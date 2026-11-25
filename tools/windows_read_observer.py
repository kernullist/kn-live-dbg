"""Sample the launching collector through inherited files, events and a query-only process handle."""
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import file_read_scope as scope
import read_observation as evidence
from etl_reader_process import WindowsFiles
from saved_etl_comparison import local_path


TIMEOUT = 30000
SYNC = 0x100000
WORKER_ERRORS = {3: "observer requires a distinct signing key", 4: "source aliases observer key",
                 5: "cannot load the acquisition signing key", 6: "observer opened a different source",
                 7: "collector and observer identity differ", 8: "observer could not open or query a required Windows object"}


class IoStatus(ctypes.Structure):
    _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]


class Windows:
    def __init__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        native = ctypes.WinDLL("ntdll")

        def api(dll, name, result, *args):
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = result, args
            return fn

        self.duplicate = api(kernel, "DuplicateHandle", w.BOOL, w.HANDLE, w.HANDLE, w.HANDLE, ctypes.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD)
        self.create_event = api(kernel, "CreateEventW", w.HANDLE, w.LPVOID, w.BOOL, w.BOOL, w.LPCWSTR)
        self.set_event = api(kernel, "SetEvent", w.BOOL, w.HANDLE)
        self.wait = api(kernel, "WaitForMultipleObjects", w.DWORD, w.DWORD, ctypes.POINTER(w.HANDLE), w.BOOL, w.DWORD)
        self.close = api(kernel, "CloseHandle", w.BOOL, w.HANDLE)
        self.pid = api(kernel, "GetProcessId", w.DWORD, w.HANDLE)
        self.kind = api(kernel, "GetFileType", w.DWORD, w.HANDLE)
        self.counters = api(kernel, "GetProcessIoCounters", w.BOOL, w.HANDLE, w.LPVOID)
        self.query = api(native, "NtQueryInformationFile", w.DWORD, w.HANDLE, ctypes.POINTER(IoStatus), w.LPVOID, w.ULONG, ctypes.c_int)
        self.read = api(native, "NtReadFile", w.DWORD, w.HANDLE, w.HANDLE, w.LPVOID, w.LPVOID, ctypes.POINTER(IoStatus), w.LPVOID,
                        w.ULONG, ctypes.POINTER(ctypes.c_longlong), w.LPVOID)

    def event(self, owner):
        handle = self.create_event(None, False, False, None)  # Auto-reset, initially unsignalled.
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        owner.callback(self.close, handle)
        return handle

    def inherit(self, owner, handle, rights):
        copy = w.HANDLE()
        if not self.duplicate(-1, handle, -1, ctypes.byref(copy), rights, True, 0 if rights else 2):
            raise ctypes.WinError(ctypes.get_last_error())
        owner.callback(self.close, copy)
        return copy.value

    def signal(self, handle):
        if not self.set_event(handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def await_peer(self, peer, event):
        result = self.wait(2, (w.HANDLE * 2)(peer, event), False, TIMEOUT)
        if result != 1:
            raise ValueError("file observer timed out" if result == 258 else "file observer or collector stopped")

    def sample(self, file, process):
        position, io = ctypes.c_longlong(), IoStatus()
        status = self.query(file, ctypes.byref(io), ctypes.byref(position), 8, 14)  # FilePositionInformation
        if status or io.information != 8:
            raise ValueError("file cursor query failed")
        counts = (ctypes.c_ulonglong * 6)()
        if not self.counters(process, counts):
            raise ctypes.WinError(ctypes.get_last_error())
        return dict(position=position.value, read_operations=counts[0], read_bytes=counts[3])

    def reread(self, file, offset, size, parent):
        buf, at, io = ctypes.create_string_buffer(size), ctypes.c_longlong(offset), IoStatus()
        status = self.read(file, None, None, None, ctypes.byref(io), buf, size, ctypes.byref(at), None)
        if status == 0x103:  # Keep the buffer and IO_STATUS_BLOCK alive until the I/O completes.
            try:
                self.await_peer(parent, file)
            except ValueError:
                os._exit(2)  # End the observer process with its outstanding I/O.
            status = (io.status or 0) & 0xffffffff
        scope.require(io.information <= size, "invalid native repeat length")
        return status, buf.raw[:io.information]


class Session:
    def __init__(self, api, process, trigger, ack):
        self.api, self.process, self.trigger, self.ack = api, process, trigger, ack

    def checkpoint(self):
        self.api.signal(self.trigger)
        try:
            self.api.await_peer(int(self.process._handle), self.ack)
        except ValueError:
            reason = WORKER_ERRORS.get(self.process.poll())
            if reason:
                raise ValueError(reason) from None
            raise

    def finish(self, capture):
        try:
            output, _ = self.process.communicate(capture, timeout=TIMEOUT / 1000)
        except subprocess.TimeoutExpired:
            raise ValueError("file observer did not finish") from None
        scope.require(self.process.returncode == 0 and 0 < len(output) <= evidence.MAX_OBSERVER,
                      WORKER_ERRORS.get(self.process.returncode, "file observation failed"))
        controller, observed = json.loads(capture), json.loads(output)
        primary = hashlib.sha256(bytes.fromhex(controller["public_key"])).hexdigest()
        pin = hashlib.sha256(bytes.fromhex(observed["public_key"])).hexdigest()
        result = evidence.verify(output, json.loads, capture, controller["body"], primary, pin)
        return evidence.combine(capture, output), dict(observer_key_sha256=pin, observation_status=result["status"])


@contextmanager
def observe(file_handle, directory, plan):
    import msvcrt
    api = Windows()
    with ExitStack() as lifetime:
        trigger, ack = api.event(lifetime), api.event(lifetime)
        # Pass a read-only duplicate of a delete-on-close plan. The observer never
        # reopens a caller-selected plan path, and a lost collector leaves no plan to recover.
        with tempfile.TemporaryFile(dir=directory) as job, ExitStack() as inherited:
            job.write(scope.canonical(plan))
            job.flush()
            job.seek(0)
            handles = [api.inherit(inherited, -1, SYNC | 0x1000), api.inherit(inherited, file_handle, 0),
                       api.inherit(inherited, trigger, SYNC), api.inherit(inherited, ack, 2),
                       api.inherit(inherited, msvcrt.get_osfhandle(job.fileno()), SYNC | 1)]
            startup = subprocess.STARTUPINFO(lpAttributeList={"handle_list": handles})
            # Supervise the interpreter that holds the events, including in a Windows venv
            # whose python.exe is a separate process launcher.
            python = sys._base_executable if sys.prefix != sys.base_prefix else sys.executable
            env = os.environ.copy()
            if python != sys.executable:
                env["__PYVENV_LAUNCHER__"] = sys.executable
            process = subprocess.Popen([python, "-B", Path(__file__).resolve(), *map(str, handles)], env=env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       startupinfo=startup, close_fds=True)
        try:
            yield Session(api, process, trigger, ack)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdin.close()
            process.stdout.close()


def worker():
    import msvcrt
    from owned_module_benchmark import sha

    if len(sys.argv) != 6:
        return 2
    api, files = Windows(), WindowsFiles()
    parent, shared, trigger, ack, job_handle = map(int, sys.argv[1:])
    pid = api.pid(parent)
    scope.require(pid and pid == os.getppid() and api.kind(shared) == 1 and
                  all(api.kind(msvcrt.get_osfhandle(s.fileno())) == 3 for s in (sys.stdin, sys.stdout)), "unexpected observer handles")
    with ExitStack() as inputs:
        for handle in (parent, trigger, ack):
            inputs.callback(api.close, handle)
        stream = inputs.enter_context(os.fdopen(msvcrt.open_osfhandle(shared, os.O_BINARY | os.O_RDONLY), "rb"))
        held = set()
        scope.require(api.kind(job_handle) == 1, "unexpected observer plan handle")
        with os.fdopen(msvcrt.open_osfhandle(job_handle, os.O_BINARY | os.O_RDONLY), "rb") as job:
            raw = job.read((1 << 20) + 1)
            scope.require(len(raw) <= 1 << 20, "observer plan exceeds limit")
            plan = json.loads(raw)
            scope.require(type(plan) is dict and plan.keys() == {"schema", "source", "observer_key", "collector_key", "ranges",
                          "nonce", "case_id", "target"} and plan["schema"] == "kn.windows_file_read_observer_plan.v1" and
                          scope.canonical(plan) == raw and scope.context_valid(plan["case_id"], plan["target"], plan["nonce"]) and
                          scope.hex_value(plan["collector_key"], 64), "invalid observer plan")
        source, secret = local_path(plan["source"]), local_path(plan["observer_key"])
        for p in (source, secret):
            files.parents(inputs, p.parent, held)
        reference = inputs.enter_context(files.hold(source))
        with files.hold(secret) as key_file:
            scope.require(not os.path.samestat(os.fstat(reference.fileno()), os.fstat(key_file.fileno())), "source aliases observer key")
            key = scope.signing_key(key_file)
        public = key.public_key().public_bytes_raw()
        scope.require(sha(public) != plan["collector_key"], "observer requires a distinct signing key")
        identity = files.file_identity(reference)
        scope.require(files.file_identity(stream) == identity, "observer opened a different source")
        ranges = plan["ranges"]
        scope.require(type(ranges) is list and 1 <= len(ranges) <= scope.MAX_READS, "invalid observer range count")
        collector = files.process_identity(pid, process_handle=parent)
        observer = files.process_identity(os.getpid(), process_handle=-1)
        scope.require(evidence.actor(collector) and evidence.actor(observer), "missing observer process identity")
        independent = msvcrt.get_osfhandle(reference.fileno())
        repeated, rows = hashlib.sha256(), []
        last = 0
        for offset, size in ranges:
            scope.require(scope.integer(offset, last, scope.MAX_PACKAGE) and scope.integer(size, 1, min(scope.CHUNK, scope.MAX_PACKAGE-offset)),
                          "invalid observer range")
            last = offset + size
            api.await_peer(parent, trigger)
            before = api.sample(shared, parent)
            api.signal(ack)
            api.await_peer(parent, trigger)
            after = api.sample(shared, parent)
            status, data = api.reread(independent, offset, size, parent)
            repeated.update(data)
            rows.append(dict(offset=offset, requested=size, before=before, after=after, repeat_ntstatus=status, repeat_bytes=len(data)))
            api.signal(ack)
        capture = sys.stdin.buffer.read(evidence.MAX_CAPTURE + 1)
        scope.require(0 < len(capture) <= evidence.MAX_CAPTURE, "missing final collector receipt")
        envelope = json.loads(capture)
        _, witness = scope.verify(envelope, plan["collector_key"], plan["nonce"])
        scope.require(witness["case_id"] == plan["case_id"] and envelope["body"]["target_path"] == plan["target"] and
                      witness["source"] == identity == files.file_identity(reference) == files.file_identity(stream),
                      "collector and observer identity differ")
        body = dict(collector_receipt_sha256=sha(capture), source=identity, collector=collector, observer=observer,
                    observations=rows, repeat_packed_sha256=repeated.hexdigest())
        signed = scope.canonical(dict(schema=evidence.SCHEMA, body=body, public_key=public.hex(),
                                      signature=key.sign(evidence.DOMAIN + scope.canonical(body)).hex()))
        scope.require(len(signed) <= evidence.MAX_OBSERVER, "observer receipt exceeds limit")
        sys.stdout.buffer.write(signed)
        sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(worker())
    except OSError:
        raise SystemExit(8)
    except ValueError as exc:
        raise SystemExit(next((code for code, reason in WORKER_ERRORS.items() if reason == str(exc)), 2))
    except (TypeError, KeyError, RecursionError):
        raise SystemExit(2)
