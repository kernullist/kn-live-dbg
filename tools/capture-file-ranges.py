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
        class FileId(ctypes.Structure):
            _fields_ = [("volume", ctypes.c_ulonglong), ("identifier", ctypes.c_ubyte * 16)]
        data = FileId()
        if not self.files.info(self.handle, 18, ctypes.byref(data), ctypes.sizeof(data)):  # FileIdInfo
            raise ctypes.WinError(ctypes.get_last_error())
        name = ctypes.create_unicode_buffer(32768)
        length = self.files.final_name(self.handle, name, len(name), 0x9)  # VOLUME_NAME_GUID | FILE_NAME_OPENED
        if not 0 < length < len(name):
            raise ctypes.WinError(ctypes.get_last_error() if length == 0 else 122)
        return dict(volume_serial=f"{data.volume:016x}", file_id=bytes(data.identifier).hex(),
                    file_bytes=os.fstat(self.stream.fileno()).st_size,
                    opened_path_sha256=hashlib.sha256(name.value.encode("utf-16le", errors="surrogatepass")).hexdigest())

    def attempt(self, offset, requested):
        actual = ctypes.c_longlong()
        if not self.seek(self.handle, offset, ctypes.byref(actual), 0):
            return "seek", ctypes.get_last_error(), b""
        if actual.value != offset:
            raise ValueError("file pointer differs from the requested offset")
        data, count = ctypes.create_string_buffer(requested), w.DWORD()
        if not self.read(self.handle, data, requested, ctypes.byref(count), None):
            error = ctypes.get_last_error()
            if count.value or not error:
                raise ValueError("unexpected unsuccessful disk read result")
            return "read", error, b""
        return "read", 0, data.raw[:count.value]


def collect(args):
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
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
        raw_key = secret.read(8193)
        if len(raw_key) > 8192:
            raise ValueError("invalid acquisition key")
        try:
            key = load_pem_private_key(raw_key, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise ValueError("cannot load the acquisition signing key") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("an Ed25519 private key is required")
        if os.path.lexists(dest):
            raise ValueError("the capture destination already exists")
        reader = DiskReader(files, src)
        identity = reader.identity()
        if not 0 <= identity["file_bytes"] <= scope.MAX_PACKAGE:
            raise ValueError("source size exceeds the file comparison limit")
        # Rename the complete pair on the same volume. An existing destination wins a race.
        with tempfile.TemporaryDirectory(prefix=".knbench-", suffix=".tmp", dir=dest.parent) as private:
            stage = Path(private) / "capture"
            stage.mkdir()
            payload = hashlib.sha256()
            attempts = []
            started, clock = time.time_ns(), time.monotonic_ns()
            with (stage / "capture.knblob").open("xb") as output:
                for offset, requested in ranges:
                    begin = time.monotonic_ns() - clock
                    operation, status, data = reader.attempt(offset, requested)
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
            public = key.public_key().public_bytes_raw()
            signature = key.sign(scope.DOMAIN + scope.canonical(body))
            receipt = scope.canonical(dict(schema=scope.SCHEMA, body=body, public_key=public.hex(), signature=signature.hex()))
            with (stage / "scope.knreads").open("xb") as output:
                output.write(receipt)
                output.flush()
                os.fsync(output.fileno())
            os.rename(stage, dest)
    return scope.canonical(dict(schema="kn.benchmark_read_capture.v1", artifact_sha256=payload.hexdigest(),
                                holes_sha256=hashlib.sha256(receipt).hexdigest(), packed_bytes=witness["packed_bytes"],
                                collector_key_sha256=hashlib.sha256(public).hexdigest())) + b"\n"


def main():
    # Restrict alias checks to paths. A target name or case ID may contain characters
    # that a Windows path cannot, including in a command that redirects its report.
    args = sys.argv[1:]
    paths = []
    path_flags = ("--source", "--signing-key", "--output")
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
