"""Run KnLiveDbg and Windows tracerpt on one pinned saved ETL and retain both attempts."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import sys
import tempfile

from etl_reader_process import WindowsFiles, file_hash, run_reader
from saved_etl_comparison import (DIAGNOSTIC, MAX_ETL, MIB, ROLES, InputPinMismatch, check, config, digest, encoded,
                                  local_path, outputs_safe, record_bytes, registration, sha, stream_bytes, write_package, write_result)


def acquire(args, registered=None):
    check(os.name == "nt", "acquisition requires Windows")
    pin, exe_pin = digest(args.sha256), digest(args.exe_sha256)
    external_pin = digest(args.tracerpt_sha256) if args.tracerpt_sha256 is not None else None
    cfg = config(pin, args.timeout_ms, args.include_disk_io)
    if registered is not None:
        registration(registered)
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
        for role in ROLES:
            if expected[role] is not None and expected[role] != before[role]:
                raise InputPinMismatch(role, expected[role], before[role])
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=output.parent, prefix=".knbench-etl-")))
        files.parents(stack, directory, parents)
        snapshot = directory / "source.etl"
        with snapshot.open("xb") as out:
            stream_bytes(original, size, out.write)
        retained = stack.enter_context(files.hold(snapshot))
        source_hash = file_hash(retained)
        if source_hash != pin:
            raise InputPinMismatch("etl", pin, source_hash)
        attempts = {role: run_reader(programs[role], cfg[role], directory, cfg["timeout_ms"],
                                     MIB if role == "native" else DIAGNOSTIC, files, binaries[role]) for role in ROLES}
        try:
            with files.hold(directory / "summary.txt") as report:
                summary = record_bytes(report, MIB)
        except FileNotFoundError:
            summary = None
        tools = {r: dict(before_sha256=before[r], after_sha256=file_hash(binaries[r]), expected_sha256=expected[r]) for r in ROLES}
        version = sys.getwindowsversion()
        schema = "kn.etl_reader_comparison.v2" if args.include_disk_io else "kn.etl_reader_comparison.v1"
        manifest = dict(schema=schema, source_sha256=pin, source_bytes=size,
                        config=cfg, config_sha256=sha(encoded(cfg)), os_build=f"{version.major}.{version.minor}.{version.build}",
                        tools=tools, attempts=attempts, summary=summary)
        if registered is not None:
            manifest.update(schema="kn.etl_reader_comparison.v3", registration=registered)
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
    parser.add_argument("--include-disk-io", action="store_true", help="register classic DiskIo reads, writes and flushes as a third family")
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
