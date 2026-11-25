"""Record requested ranges from a local Windows file for offline publisher comparison."""
import argparse
from contextlib import ExitStack
import ctypes
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
import time

from saved_etl_comparison import local_path, outputs_safe, write_result


def read_ranges(values, max_reads, max_offset, max_size):
    if not 1 <= len(values) <= max_reads:
        raise ValueError("too many file ranges")
    result = []
    end = 0
    for value in values:
        match = re.fullmatch(r"([0-9]{1,12})\+([0-9]{1,8})", value)
        if not match:
            raise ValueError("supply each range as decimal OFFSET+LENGTH")
        start, size = map(int, match.groups())
        if start < end or size < 1 or size > max_size or start + size > max_offset:
            raise ValueError("file ranges must be ordered, disjoint and within the read limits")
        result.append((start, size))
        end = start + size
    return result


class DiskReader:
    def __init__(self, files, stream):
        import msvcrt
        self.files, self.stream = files, stream
        self.handle = msvcrt.get_osfhandle(stream.fileno())
        dll = ctypes.WinDLL("kernel32", use_last_error=True)
        self.seek = dll.SetFilePointerEx
        self.seek.argtypes = (w.HANDLE, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), w.DWORD)
        self.seek.restype = w.BOOL
        self.read = dll.ReadFile
        self.read.argtypes = (w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID)
        self.read.restype = w.BOOL

    def identity(self):
        return self.files.file_identity(self.stream)

    def attempt(self, offset, requested, observer=None):
        actual = ctypes.c_longlong()
        ready = self.seek(self.handle, offset, ctypes.byref(actual), 0)
        status = 0 if ready else ctypes.get_last_error()
        if ready and actual.value != offset:
            raise ValueError("file pointer differs from the requested offset")
        data, count = ctypes.create_string_buffer(requested), w.DWORD()
        if observer is not None:
            observer.checkpoint()
        if ready and not self.read(self.handle, data, requested, ctypes.byref(count), None):
            status = ctypes.get_last_error()
            if not status or count.value:
                raise ValueError("unexpected unsuccessful disk read result")
        if observer is not None:
            observer.checkpoint()
        if count.value > requested:
            raise ValueError("invalid Windows transfer length")
        return "read" if ready else "seek", status, data.raw[:count.value]


def collect(args):
    from etl_reader_process import WindowsFiles
    import file_read_scope as scope

    ranges = read_ranges(args.ranges, scope.MAX_READS, scope.MAX_PACKAGE, scope.CHUNK)
    if not scope.context_valid(args.case_id, args.target_path, args.capture_nonce):
        raise ValueError("invalid case, publisher target or capture nonce")
    source, key_file, dest = map(local_path, (args.source, args.signing_key, args.output))
    files = WindowsFiles()
    with ExitStack() as inputs:
        held = set()
        for path in (source, key_file, dest):
            files.parents(inputs, path.parent, held)
        src = inputs.enter_context(files.hold(source))
        secret = inputs.enter_context(files.hold(key_file))
        if os.path.samestat(os.fstat(src.fileno()), os.fstat(secret.fileno())):
            raise ValueError("the source aliases the signing key")
        if not outputs_safe((), src) or not outputs_safe((), secret):
            raise ValueError("an output aliases a protected input")
        key = scope.signing_key(secret)
        public = key.public_key().public_bytes_raw()
        key_pin = hashlib.sha256(public).hexdigest()
        if os.path.lexists(dest):
            raise ValueError("the capture destination already exists")
        reader = DiskReader(files, src)
        identity = reader.identity()
        if not 0 <= identity["file_bytes"] <= scope.MAX_PACKAGE:
            raise ValueError("source size exceeds the file comparison limit")
        # Rename the complete pair on the same volume. An existing destination wins a race.
        with tempfile.TemporaryDirectory(prefix=".knbench-", suffix=".tmp", dir=dest.parent) as private, ExitStack() as observers:
            stage = Path(private) / "capture"
            stage.mkdir()
            observer = None
            observation_key = getattr(args, "observer_signing_key", None)
            if observation_key is not None:
                from windows_read_observer import observe
                job = dict(schema="kn.windows_file_read_observer_plan.v1", source=str(source),
                           observer_key=str(local_path(observation_key)), collector_key=key_pin, ranges=ranges,
                           nonce=args.capture_nonce, case_id=args.case_id, target=args.target_path)
                observer = observers.enter_context(observe(reader.handle, Path(private), job))
            payload = hashlib.sha256()
            attempts = []
            started, clock = time.time_ns(), time.monotonic_ns()
            with (stage / "capture.knblob").open("xb") as output:
                for offset, requested in ranges:
                    begin = time.monotonic_ns() - clock
                    operation, status, data = reader.attempt(offset, requested, observer)
                    finish = time.monotonic_ns() - clock
                    attempts.append(dict(offset=offset, requested=requested, operation=operation, win32_status=status,
                                         transferred=len(data), start_ns=begin, end_ns=finish))
                    output.write(data)
                    payload.update(data)
                output.flush()
                os.fsync(output.fileno())
            if reader.identity() != identity:
                raise ValueError("source file identity or length changed during acquisition")
            body = dict(case_id=args.case_id, target_path=args.target_path, capture_nonce=args.capture_nonce,
                        source=identity, started_unix_ns=started, attempts=attempts, packed_sha256=payload.hexdigest())
            _, witness = scope.inspect_reads(body)
            signature = key.sign(scope.DOMAIN + scope.canonical(body))
            receipt = scope.canonical(dict(schema=scope.SCHEMA, body=body, public_key=public.hex(), signature=signature.hex()))
            observed = {}
            if observer is not None:
                receipt, observed = observer.finish(receipt)
            with (stage / "scope.knreads").open("xb") as output:
                output.write(receipt)
                output.flush()
                os.fsync(output.fileno())
            os.rename(stage, dest)
    schema = "kn.benchmark_read_capture.v2" if observed else "kn.benchmark_read_capture.v1"
    return scope.canonical(dict(schema=schema, artifact_sha256=payload.hexdigest(),
                                holes_sha256=hashlib.sha256(receipt).hexdigest(), packed_bytes=witness["packed_bytes"],
                                collector_key_sha256=key_pin, **observed)) + b"\n"


def main():
    # Restrict alias checks to paths. A target name or case ID may contain characters
    # that a Windows path cannot, including in a command that redirects its report.
    args = sys.argv[1:]
    paths = []
    path_flags = ("--source", "--signing-key", "--observer-signing-key", "--output")
    for index, arg in enumerate(args):
        flag, sep, value = arg.partition("=")
        if len(flag) > 2 and flag.startswith("--") and any(option.startswith(flag) for option in path_flags):
            if sep or index + 1 < len(args):
                path = value if sep else args[index + 1]
                paths.append(path)
                if "--output".startswith(flag) and path:
                    paths.extend(os.path.join(path, name) for name in ("capture.knblob", "scope.knreads"))
    if not outputs_safe(paths):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for flag in ("source", "signing-key", "output", "case-id", "target-path", "capture-nonce"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--observer-signing-key", help="run an independent cursor, process I/O and file reread observer with a distinct Ed25519 key")
    parser.add_argument("--range", dest="ranges", action="append", required=True, metavar="OFFSET+LENGTH")
    parsed = parser.parse_args(args)
    try:
        if os.name != "nt":
            raise ValueError("acquisition requires Windows")
        result = collect(parsed)
    except (OSError, ValueError, TypeError, ImportError) as exc:
        if outputs_safe(paths):
            reason = f"Windows I/O error {getattr(exc, 'winerror', None) or exc.errno}" if isinstance(exc, OSError) else str(exc)
            print(f"file acquisition failed: {reason}", file=sys.stderr)
        return 2
    return write_result(result) if outputs_safe(paths) else 2


if __name__ == "__main__":
    raise SystemExit(main())
