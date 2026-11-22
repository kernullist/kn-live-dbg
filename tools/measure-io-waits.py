"""Capture a directory I/O journal with independent thread-state samples, or replay its original bytes."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import platform
import stat
import struct
import subprocess
import sys
import tempfile
import time

from etl_reader_process import WindowsFiles, file_hash
from io_wait_sampler import observe, prepare
import io_wait_study as study
from owned_module_benchmark import check, encoded, publish_new, sha
from saved_etl_comparison import DIAGNOSTIC, digest, local_path, outputs_safe, record_bytes, write_result


def first_plan(stream, child, deadline):
    while True:
        stream.seek(0)
        line = stream.readline(4097)
        if line.endswith(b"\n") and len(line) <= 4096:
            try:
                plan = study.decode(line)
                study.IO["validate_record"](plan, 0)
                if plan["kind"] == "plan" and plan["seq"] == 0:
                    return plan, sha(line)
            except (ValueError, KeyError, TypeError, RecursionError):
                pass
            break
        if len(line) > 4096 or child.poll() is not None or time.monotonic() >= deadline:
            break
        time.sleep(0.002)
    return None, None


def acquire(args, work, files, exe, pinned, directories):
    attempt = dict(state="launch_error", exit_code=None, os_error=None, image_binding=None, process_identity=None)
    sampler = dict(plan_line_sha256=None, binding=None, samples=[], stopped="no_plan", terminal_wait=None)
    args_list = [str(exe), "--io-lifecycle", str(args.wait_ms), *map(str, directories)]
    machine = platform.machine().lower()
    prepared = prepare(machine)
    deadline = time.monotonic() + (args.wait_ms + 10000)/1000
    with (work/"journal.bin").open("x+b") as out, tempfile.TemporaryFile(dir=work) as err, ExitStack() as stack:
        try:
            child = subprocess.Popen(args_list, executable=exe, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     cwd=work, creationflags=subprocess.CREATE_NO_WINDOW)
        except OSError as exc:
            attempt["os_error"] = getattr(exc, "winerror", None) or exc.errno
        else:
            try:
                process_handle = int(child._handle)  # Original Windows process handle retained by Popen.
                attempt["image_binding"] = files.image_binding(child.pid, pinned, process_handle=process_handle)
                identity = attempt["process_identity"] = files.process_identity(child.pid, process_handle=process_handle)
                # A separate reader has its own file offset, independent of the child's stdout handle.
                with (work/"journal.bin").open("rb") as journal:
                    plan, sampler["plan_line_sha256"] = first_plan(journal, child, deadline)
                if plan:
                    if (attempt["image_binding"] == study.MATCHED and identity == dict(pid=plan["pid"], process_created=plan["process_created"]) and
                            plan["pid"] == child.pid and plan["requests"] == len(directories) and plan["wait_ms"] == args.wait_ms):
                        sampler.update(observe(child, stack, plan, args.interval_ms, args.samples, deadline, prepared))
                    else:
                        sampler["stopped"] = "producer_unbound"
                attempt.update(state="exited", exit_code=child.wait(timeout=max(0, deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                attempt["state"] = "timed_out"
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
        attempt.update(stdout=record_bytes(out, study.JOURNAL_LIMIT), stderr=record_bytes(err, DIAGNOSTIC))
    version = sys.getwindowsversion()
    host = dict(windows_version=[version.major, version.minor, version.build], pointer_bytes=struct.calcsize("P"),
                machine=machine, information_class="SystemProcessInformation", clock="GetTickCount64_ms")
    return dict(schema="kn.io_thread_wait_capture.v1", host=host, collector_sha256=args.exe_sha256.lower(), wait_ms=args.wait_ms, request_count=len(directories),
                interval_ms=args.interval_ms, sample_limit=args.samples, producer=attempt, sampler=sampler)


def capture(args):
    check(os.name == "nt", "live acquisition requires Windows")
    check(1 <= args.wait_ms <= 30000 and 1 <= args.interval_ms <= 1000 and 1 <= args.samples <= study.MAX_SAMPLES and
          1 <= len(args.directories) <= 8, "invalid acquisition bounds")
    directories = [local_path(value) for value in args.directories]
    files, held = WindowsFiles(), set()
    output, exe = local_path(args.output), local_path(args.exe)
    with ExitStack() as stack:
        files.parents(stack, output.parent, held)
        check(not os.path.lexists(output), "choose a new capture file")
        files.parents(stack, exe.parent, held)
        pinned = stack.enter_context(files.hold(exe))
        check(file_hash(pinned) == digest(args.exe_sha256.lower()), "collector SHA-256 mismatch")
        with tempfile.TemporaryDirectory(dir=output.parent, prefix=".kn-io-wait-") as tmp:
            package = acquire(args, Path(tmp), files, exe, pinned, directories)
        data = encoded(package)
        check(len(data) <= study.PACKAGE_LIMIT, "capture exceeds byte limit")
        report = study.assess(package, sha(data))
        pin = publish_new(output, lambda stream: stream.write(data))
    return dict(schema="kn.io_thread_wait_capture_receipt.v1", capture_sha256=pin, status=report["status"], coverage=report["coverage"]), int(report["status"] != "complete")


def replay(args):
    source = local_path(args.capture)
    pin = digest(args.sha256.lower())
    check(stat.S_ISREG(source.stat().st_mode), "use a regular capture")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(source, flags), "rb") as stream:
        check(stat.S_ISREG(os.fstat(stream.fileno()).st_mode) and outputs_safe(sys.argv[1:], stream), "invalid capture or output alias")
        raw = stream.read(study.PACKAGE_LIMIT+1)
    check(len(raw) <= study.PACKAGE_LIMIT and sha(raw) == pin, "capture extent or SHA-256 mismatch")
    report = study.assess(study.decode(raw), pin)
    data = encoded(report)
    if args.check_report:
        state = "matched" if digest(args.check_report.lower()) == sha(data) else "mismatch"
    else:
        output = local_path(args.output)
        with ExitStack() as stack:
            if os.name == "nt":
                WindowsFiles().parents(stack, output.parent, set())
            check(not os.path.lexists(output), "choose a new report file")
            publish_new(output, lambda stream: stream.write(data))
        state = "written"
    return dict(schema="kn.io_thread_waits_receipt.v1", capture_sha256=pin, report_sha256=sha(data), status=state,
                study_status=report["status"], coverage=report["coverage"]), int(state == "mismatch" or report["status"] != "complete")


def main():
    if not outputs_safe(sys.argv[1:]):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="verb", required=True)
    new = sub.add_parser("capture", help="launch the pinned I/O collector and sample its issuing thread", allow_abbrev=False)
    new.add_argument("--exe", required=True)
    new.add_argument("--exe-sha256", required=True)
    new.add_argument("--wait-ms", required=True, type=int)
    new.add_argument("--interval-ms", type=int, default=20)
    new.add_argument("--samples", type=int, default=256)
    new.add_argument("--output", required=True)
    new.add_argument("directories", nargs="+")
    saved = sub.add_parser("replay", help="join the private journal and retained thread-state observations", allow_abbrev=False)
    saved.add_argument("--capture", required=True)
    saved.add_argument("--sha256", required=True)
    dest = saved.add_mutually_exclusive_group(required=True)
    dest.add_argument("--output")
    dest.add_argument("--check-report")
    args = parser.parse_args()
    try:
        receipt, code = capture(args) if args.verb == "capture" else replay(args)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        if outputs_safe(sys.argv[1:]):
            print(f"I/O wait measurement failed: {exc}", file=sys.stderr)
        return 2
    return (write_result(encoded(receipt)) or code) if outputs_safe(sys.argv[1:]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
