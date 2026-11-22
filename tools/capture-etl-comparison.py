"""Run KnLiveDbg and Windows tracerpt on one pinned saved ETL and retain both attempts."""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from saved_etl_comparison import (DIAGNOSTIC, MAX_ETL, MIB, ROLES, check, config, digest, encoded,
                                  local_path, outputs_safe, record_bytes, sha, stream_bytes, write_package, write_result)


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
        get_system = api("GetSystemDirectoryW", w.UINT, w.LPWSTR, w.UINT)
        buf = ctypes.create_unicode_buffer(32768)
        check(0 < get_system(buf, len(buf)) < len(buf), "cannot locate Windows system directory")
        self.tracerpt = Path(buf.value) / "tracerpt.exe"

    def image_binding(self, pid, pinned):
        import msvcrt
        buf = ctypes.create_unicode_buffer(32768)
        n = self.final_name(msvcrt.get_osfhandle(pinned.fileno()), buf, len(buf), 2)  # VOLUME_NAME_NT
        if not 0 < n < len(buf):
            return dict(status="unavailable", win32_status=ctypes.get_last_error() if not n else 122)
        expected = buf.value
        handle = self.open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return dict(status="unavailable", win32_status=ctypes.get_last_error())
        try:
            size = w.DWORD(len(buf))
            if not self.image_name(handle, 1, buf, ctypes.byref(size)):  # PROCESS_NAME_NATIVE
                return dict(status="unavailable", win32_status=ctypes.get_last_error())
            return dict(status="matched" if expected == buf.value else "different_path", win32_status=0)
        finally:
            self.close(handle)

    @contextmanager
    def hold(self, path, directory=False):
        import msvcrt
        # Share directory writes so children can be created and renamed, while
        # denying rename of the directory itself. Files deny writes and renames.
        access = 0x81 if directory else 0x80000000
        flags = 0x00200000 | 0x00100000 | (0x02000000 if directory else 0)
        handle = self.create(str(path), access, 3 if directory else 1, None, 3, flags, None)
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

    def parents(self, stack, directory, held):
        check(self.drive(directory.anchor) == 3, "use a fixed local volume")
        for parent in (*reversed(directory.parents), directory):
            if parent != Path(directory.anchor) and parent not in held:
                stack.enter_context(self.hold(parent, directory=True))
                held.add(parent)


def file_hash(stream):
    stream.seek(0)
    return hashlib.file_digest(stream, "sha256").hexdigest()


def run_reader(program, arguments, directory, timeout_ms, stdout_limit, files, pinned):
    with tempfile.TemporaryFile(dir=directory) as out, tempfile.TemporaryFile(dir=directory) as err:
        start = time.perf_counter_ns()
        code = error = binding = None
        try:
            child = subprocess.Popen([str(program), *arguments], executable=program, cwd=directory,
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
        except OSError as exc:
            state, error = "launch_error", getattr(exc, "winerror", None) or exc.errno
        else:
            try:
                binding = files.image_binding(child.pid, pinned)
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
        return dict(state=state, exit_code=code, os_error=error, image_binding=binding, started_ns=str(start), ended_ns=str(end),
                    stdout=record_bytes(out, stdout_limit), stderr=record_bytes(err, DIAGNOSTIC))


def acquire(args):
    check(os.name == "nt", "acquisition requires Windows")
    pin, exe_pin = digest(args.sha256), digest(args.exe_sha256)
    external_pin = digest(args.tracerpt_sha256) if args.tracerpt_sha256 is not None else None
    cfg = config(pin, args.timeout_ms)
    files = WindowsFiles()
    source, exe, output = map(local_path, (args.etl, args.exe, args.output))
    check(exe.suffix.lower() == ".exe", "expected a Windows executable image")
    programs = dict(native=exe, tracerpt=files.tracerpt)
    expected = dict(native=exe_pin, tracerpt=external_pin)
    with ExitStack() as stack:
        parents = set()
        for path in (source, *programs.values(), output):
            files.parents(stack, path.parent, parents)
        check(not os.path.lexists(output), "choose a new comparison package path")
        original = stack.enter_context(files.hold(source))
        size = os.fstat(original.fileno()).st_size
        check(0 < size <= MAX_ETL, "saved ETL must be 1 byte..512 MiB")
        binaries = {role: stack.enter_context(files.hold(programs[role])) for role in ROLES}
        identities = [os.fstat(f.fileno()) for f in (original, *binaries.values())]
        check(len({(s.st_dev, s.st_ino) for s in identities}) == len(identities), "use distinct source and reader files")
        before = {role: file_hash(stream) for role, stream in binaries.items()}
        check(all(expected[r] is None or expected[r] == before[r] for r in ROLES), "reader binary admission pin mismatch")
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=output.parent, prefix=".knbench-etl-")))
        files.parents(stack, directory, parents)
        snapshot = directory / "source.etl"
        with snapshot.open("xb") as out:
            stream_bytes(original, size, out.write)
        retained = stack.enter_context(files.hold(snapshot))
        check(file_hash(retained) == pin, "ETL admission pin mismatch")
        attempts = {role: run_reader(programs[role], cfg[role], directory, cfg["timeout_ms"],
                                     MIB if role == "native" else DIAGNOSTIC, files, binaries[role]) for role in ROLES}
        try:
            with files.hold(directory / "summary.txt") as report:
                summary = record_bytes(report, MIB)
        except FileNotFoundError:
            summary = None
        tools = {r: dict(before_sha256=before[r], after_sha256=file_hash(binaries[r]), expected_sha256=expected[r]) for r in ROLES}
        version = sys.getwindowsversion()
        manifest = dict(schema="kn.etl_reader_comparison.v1", source_sha256=pin, source_bytes=size,
                        config=cfg, config_sha256=sha(encoded(cfg)), os_build=f"{version.major}.{version.minor}.{version.build}",
                        tools=tools, attempts=attempts, summary=summary)
        package = write_package(output, manifest, retained)
    return dict(schema="kn.etl_reader_archive.v1", package_sha256=package, source_sha256=pin,
                attempts={role: attempts[role]["state"] for role in ROLES})


def main():
    if not outputs_safe(sys.argv[1:]):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for opt in ("--etl", "--sha256", "--exe", "--exe-sha256", "--output"):
        parser.add_argument(opt, required=True)
    parser.add_argument("--tracerpt-sha256", help="optional expected hash of the installed system reader")
    parser.add_argument("--timeout-ms", type=int, default=240000, help="deadline per reader, 1..600000 ms")
    args = parser.parse_args()
    try:
        receipt = acquire(args)
    except (OSError, ValueError) as exc:
        if outputs_safe(sys.argv[1:]):
            print(f"ETL acquisition failed: {exc}", file=sys.stderr)
        return 2
    if not outputs_safe(sys.argv[1:]):
        return 2
    return write_result(encoded(receipt))


if __name__ == "__main__":
    raise SystemExit(main())
