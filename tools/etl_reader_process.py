"""Pin local Windows files and run the named ETL reader under a deadline."""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time

from saved_etl_comparison import DIAGNOSTIC, check, record_bytes


class WindowsFiles:
    """Keep local path components and reader images in place until publication."""

    def __init__(self):
        dll = ctypes.WinDLL("kernel32", use_last_error=True)

        def api(name, result, *args):
            fn = getattr(dll, name)
            fn.argtypes, fn.restype = args, result
            return fn

        self.create = api("CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
        self.info = api("GetFileInformationByHandleEx", w.BOOL, w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD)
        self.close = api("CloseHandle", w.BOOL, w.HANDLE)
        self.drive = api("GetDriveTypeW", w.UINT, w.LPCWSTR)
        self.final_name = api("GetFinalPathNameByHandleW", w.DWORD, w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD)
        self.open_process = api("OpenProcess", w.HANDLE, w.DWORD, w.BOOL, w.DWORD)
        self.image_name = api("QueryFullProcessImageNameW", w.BOOL, w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD))
        self.process_times = api("GetProcessTimes", w.BOOL, w.HANDLE, *(ctypes.POINTER(w.FILETIME),) * 4)
        get_system = api("GetSystemDirectoryW", w.UINT, w.LPWSTR, w.UINT)
        buf = ctypes.create_unicode_buffer(32768)
        check(0 < get_system(buf, len(buf)) < len(buf), "cannot locate Windows system directory")
        self.tracerpt = Path(buf.value) / "tracerpt.exe"

    def file_identity(self, stream):
        import msvcrt
        class FileId(ctypes.Structure):
            _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]
        handle = msvcrt.get_osfhandle(stream.fileno())
        data = FileId()
        if not self.info(handle, 18, ctypes.byref(data), ctypes.sizeof(data)):  # FileIdInfo
            raise ctypes.WinError(ctypes.get_last_error())
        name = ctypes.create_unicode_buffer(32768)
        length = self.final_name(handle, name, len(name), 0x9)  # VOLUME_NAME_GUID | FILE_NAME_OPENED
        if not 0 < length < len(name):
            raise ctypes.WinError(ctypes.get_last_error() if length == 0 else 122)
        return dict(volume_serial=f"{data.volume:016x}", file_id=bytes(data.identifier).hex(),
                    file_bytes=os.fstat(stream.fileno()).st_size,
                    opened_path_sha256=hashlib.sha256(name.value.encode("utf-16le", errors="surrogatepass")).hexdigest())

    def process_identity(self, pid, *, process_handle=None):
        handle = self.open_process(0x1000, False, pid) if process_handle is None else process_handle
        if not handle:
            return None
        try:
            times = [w.FILETIME() for _ in range(4)]
            if not self.process_times(handle, *(ctypes.byref(t) for t in times)):
                return None
            created = times[0].dwHighDateTime << 32 | times[0].dwLowDateTime
            return dict(pid=pid, process_created=str(created))
        finally:
            if process_handle is None:
                self.close(handle)

    def image_binding(self, pid, pinned, *, process_handle=None):
        import msvcrt
        buf = ctypes.create_unicode_buffer(32768)
        n = self.final_name(msvcrt.get_osfhandle(pinned.fileno()), buf, len(buf), 2)  # VOLUME_NAME_NT
        if not 0 < n < len(buf):
            return dict(status="unavailable", win32_status=ctypes.get_last_error() if not n else 122)
        expected = buf.value
        handle = self.open_process(0x1000, False, pid) if process_handle is None else process_handle
        if not handle:
            return dict(status="unavailable", win32_status=ctypes.get_last_error())
        try:
            size = w.DWORD(len(buf))
            if not self.image_name(handle, 1, buf, ctypes.byref(size)):  # PROCESS_NAME_NATIVE
                return dict(status="unavailable", win32_status=ctypes.get_last_error())
            return dict(status="matched" if expected == buf.value else "different_path", win32_status=0)
        finally:
            if process_handle is None:
                self.close(handle)

    @contextmanager
    def hold(self, path, directory=False, *, share_directory_writes=True):
        import msvcrt
        # ETL readers share directory writes. Signature verification also denies
        # directory writes while Windows reopens a path. Neither shares deletion.
        access = 0x81 if directory else 0x80000000
        flags = 0x00200000 | 0x00100000 | (0x02000000 if directory else 0)
        share = 3 if directory and share_directory_writes else 1
        handle = self.create(str(path), access, share, None, 3, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = (w.DWORD * 2)()
            if not self.info(handle, 9, info, ctypes.sizeof(info)):  # FileAttributeTagInfo
                raise ctypes.WinError(ctypes.get_last_error())
            check(not info[0] & (0x400 | 0x1000 | 0x40000 | 0x400000) and bool(info[0] & 0x10) == directory,
                  "expected a local file or directory without reparse, offline or recall attributes")
            if directory:
                yield
            else:
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
                handle = None  # The descriptor now owns the Win32 handle.
                with os.fdopen(fd, "rb") as stream:
                    yield stream
        finally:
            if handle is not None:
                self.close(handle)

    def parents(self, stack, directory, held, *, share_directory_writes=True):
        check(self.drive(directory.anchor) == 3, "use a fixed local volume")
        for parent in (*reversed(directory.parents), directory):
            if parent != Path(directory.anchor) and parent not in held:
                stack.enter_context(self.hold(parent, directory=True, share_directory_writes=share_directory_writes))
                held.add(parent)


def file_hash(stream):
    stream.seek(0)
    return hashlib.file_digest(stream, "sha256").hexdigest()


def reader_receipt(attempt):
    result = {k: attempt[k] for k in ("state", "exit_code", "os_error", "image_binding")}
    for channel in ("stdout", "stderr"):
        result[channel + "_sha256"] = attempt[channel]["original_sha256"]
        result[channel + "_bytes"] = attempt[channel]["byte_count"]
    return result


def run_reader(program, arguments, directory, timeout_ms, stdout_limit, files, pinned, *, capture_identity=False):
    with tempfile.TemporaryFile(dir=directory) as out, tempfile.TemporaryFile(dir=directory) as err:
        start = time.perf_counter_ns()
        code = error = binding = identity = None
        try:
            child = subprocess.Popen([str(program), *arguments], executable=program, cwd=directory,
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
        except OSError as exc:
            state, error = "launch_error", getattr(exc, "winerror", None) or exc.errno
        else:
            try:
                binding = files.image_binding(child.pid, pinned)
                if capture_identity:
                    identity = files.process_identity(child.pid)
                remaining = max(0, start + timeout_ms * 1_000_000 - time.perf_counter_ns())
                code = child.wait(timeout=remaining / 1_000_000_000)
                state = "exited"
            except subprocess.TimeoutExpired:
                state = "timed_out"
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
        end = time.perf_counter_ns()
        result = dict(state=state, exit_code=code, os_error=error, image_binding=binding, started_ns=str(start), ended_ns=str(end),
                      stdout=record_bytes(out, stdout_limit), stderr=record_bytes(err, DIAGNOSTIC))
        if capture_identity:
            result["process_identity"] = identity
        return result
