"""Register, capture and replay a paired Windows ETW study of an owned thread handoff."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import struct
import sys
import tempfile
from uuid import uuid4
import zipfile

import etl_handoff as study
from etl_reader_process import WindowsFiles, file_hash, reader_receipt, run_reader
from owned_module_benchmark import check, decimal, encoded, fields, publish_new, sha, stored_directory, stored_extent, uint
from saved_etl_comparison import DIAGNOSTIC, MIB, digest, local_path, original, outputs_safe, process_state, write_result


LIMIT = 16 * 1024
ETL_LIMIT = 2 * MIB
MAX_PACKAGE = 72 * MIB
PLAN_MEMBER = "handoff-plan.json"
OUTCOMES = "handoff-outcomes.json"


def held_file(path, files, stack, held):
    files.parents(stack, path.parent, held)
    return stack.enter_context(files.hold(path))


def pinned_image(name, pin, files, stack, held):
    path = local_path(name)
    check(path.suffix.lower() == ".exe", "expected a Windows executable")
    stream = held_file(path, files, stack, held)
    check(file_hash(stream) == pin, "executable SHA-256 mismatch")
    return path, stream


def read_bounded(stream, bound):
    size = os.fstat(stream.fileno()).st_size
    check(0 < size <= bound, "input outside byte bounds")
    stream.seek(0)
    data = stream.read(size+1)
    check(len(data) == size, "input extent changed")
    return data


def slot_name(slot):
    return f"slot-{slot['slot']:02d}.etl"


def recorder_document(attempt):
    raw, complete = original(attempt["stdout"], LIMIT)
    check(complete, "recorder output truncated")
    value = study.DECODE(raw)
    check(type(value) is dict and value["schema"] == "kn.owned_etl_handoff.v1", "unexpected recorder output")
    study.guid(value["session_id"])
    return value


def capture_slot(cfg, slot, activity, program, binary, directory, files, stack, held):
    folder = directory / f"slot-{slot['slot']:02d}"
    folder.mkdir()
    files.parents(stack, folder, held)
    args = [".", "--handoff", activity, str(slot["seed"]), str(cfg["steps"]), str(slot["delay_ms"])]
    attempt = run_reader(program, args, folder, cfg["timeout_ms"], LIMIT, files, binary, capture_identity=True)
    record = dict(slot=slot["slot"], ticket=slot["ticket"], attempt=attempt, retention="not_located",
                  source_sha256=None, source_bytes=None)
    if attempt["state"] != "exited" or attempt["exit_code"] != 0 or attempt["image_binding"] != study.MATCHED_IMAGE:
        record["retention"] = "recorder_failed"
        return record, None
    try:
        truth = recorder_document(attempt)
        check(truth["activity_id"] == activity, "recorder activity mismatch")
        source = held_file(folder / truth["session_id"] / "capture.etl", files, stack, held)
        size = os.fstat(source.fileno()).st_size
        if not 0 < size <= ETL_LIMIT:
            record["retention"] = "size_limit"
            return record, None
        record.update(retention="retained", source_bytes=size, source_sha256=file_hash(source))
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return record, None
    return record, source


def capture(args, output, files, stack, held, directory):
    source = held_file(local_path(args.plan), files, stack, held)
    plan_raw = read_bounded(source, LIMIT)
    pin = digest(args.plan_sha256.lower())
    check(sha(plan_raw) == pin, "registered plan SHA-256 mismatch")
    cfg = study.registered(study.DECODE(plan_raw))
    program, binary = pinned_image(args.recorder, cfg["recorder_sha256"], files, stack, held)
    acquisition = str(uuid4())
    version = sys.getwindowsversion()
    environment = dict(windows_version=[version.major, version.minor, version.build], controller_pointer_bytes=struct.calcsize("P"))
    records, sources = [], {}
    for slot in cfg["slots"]:
        record, etl = capture_slot(cfg, slot, study.activity_id(acquisition, pin, slot), program, binary, directory, files, stack, held)
        records.append(record)
        if etl is not None:
            sources[slot_name(slot)] = (etl, record)
    envelope = encoded(dict(schema="kn.etl_handoff_capture.v1", plan_sha256=pin, acquisition_id=acquisition,
                            environment=environment, outcomes=records))
    check(len(envelope) <= 6*MIB, "recorder evidence exceeds package limit")

    def write(out):
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(PLAN_MEMBER, plan_raw)
            archive.writestr(OUTCOMES, envelope)
            for member, (etl, record) in sources.items():
                raw = read_bounded(etl, ETL_LIMIT)
                check(sha(raw) == record["source_sha256"], "retained ETL changed")
                archive.writestr(member, raw)

    package = publish_new(output, write)
    return dict(schema="kn.etl_handoff_capture_receipt.v1", plan_sha256=pin, package_sha256=package, acquisition_id=acquisition,
                planned_arms=len(records), retained_etls=len(sources)), int(len(sources) != len(records))


def member(archive, name, limit):
    entry = archive.getinfo(name)
    check(entry.orig_filename == name and entry.compress_type == zipfile.ZIP_STORED and entry.flag_bits == 0 and
          0 < entry.file_size == entry.compress_size <= limit, "invalid handoff package member")
    with archive.open(entry) as source:
        data = source.read(entry.file_size+1)
    check(len(data) == entry.file_size, "package member extent mismatch")
    return data


def structure(archive, source, bounds, expected_plan):
    entries = archive.infolist()
    offset, count = bounds
    names = [e.orig_filename for e in entries]
    check(len(entries) == count and names[:2] == [PLAN_MEMBER, OUTCOMES], "invalid handoff package layout")
    cursor = 0
    for entry in entries:
        cursor = stored_extent(source, entry, cursor, offset)
    check(cursor == offset, "unaccounted package contents")
    raw = member(archive, PLAN_MEMBER, LIMIT)
    check(sha(raw) == expected_plan, "package plan SHA-256 mismatch")
    cfg = study.registered(study.DECODE(raw))
    document = study.DECODE(member(archive, OUTCOMES, 6*MIB))
    fields(document, "schema plan_sha256 acquisition_id environment outcomes", "capture envelope")
    acquisition = study.guid(document["acquisition_id"])
    check(acquisition != cfg["study_id"], "acquisition reused plan identity")
    env = document["environment"]
    fields(env, "windows_version controller_pointer_bytes", "acquisition environment")
    version = env["windows_version"]
    check(type(version) is list and len(version) == 3, "invalid Windows version")
    major, _, build = (uint(part, study.UINT32) for part in version)
    check(major > 0 and build > 0 and uint(env["controller_pointer_bytes"]) in (4, 8), "invalid acquisition environment")
    outcomes = document["outcomes"]
    check(document["schema"] == "kn.etl_handoff_capture.v1" and document["plan_sha256"] == expected_plan and
          type(outcomes) is list and len(outcomes) == len(cfg["slots"]), "missing registered attempt")
    expected = [PLAN_MEMBER, OUTCOMES]
    previous = 0
    for record, slot in zip(outcomes, cfg["slots"], strict=True):
        fields(record, "slot ticket attempt retention source_sha256 source_bytes", "workload attempt")
        check(uint(record["slot"]) == slot["slot"] and record["ticket"] == slot["ticket"], "attempt outside registered order")
        attempt = record["attempt"]
        fields(attempt, "state exit_code os_error image_binding started_ns ended_ns stdout stderr process_identity", "recorder process")
        lo, hi, state, binding = process_state(attempt)
        check(0 < lo and previous <= lo, "overlapping or reordered recorder processes")
        previous = hi
        identity = attempt["process_identity"]
        if identity is not None:
            fields(identity, "pid process_created", "workload process identity")
            check(state != "launch_error" and 0 < uint(identity["pid"], study.UINT32-1) and decimal(identity["process_created"]) > 0,
                  "invalid recorder process identity")
        original(attempt["stdout"], LIMIT)
        original(attempt["stderr"], DIAGNOSTIC)
        ran = state == "exited" and attempt["exit_code"] == 0 and binding == study.MATCHED_IMAGE
        check((record["retention"] == "recorder_failed") == (not ran), "inconsistent recorder and ETL retention states")
        if record["retention"] == "retained":
            digest(record["source_sha256"])
            check(0 < uint(record["source_bytes"], ETL_LIMIT), "invalid retained ETL size")
            expected.append(slot_name(slot))
        else:
            check(record["retention"] in ("not_located", "recorder_failed", "size_limit") and
                  record["source_sha256"] is record["source_bytes"] is None, "unexpected ETL retention record")
    check(names == expected, "missing or unexpected handoff package members")
    return cfg, acquisition, env, outcomes


def observe(cfg, slot, activity, record, archive, reader, binary, directory, files):
    attempt = record["attempt"]
    result = dict(selection=slot, expected_activity_id=activity, status="unavailable", reason=record["retention"], etl_sha256=record["source_sha256"],
                  session_id=None, process=attempt["process_identity"], recorder=reader_receipt(attempt),
                  reader=None, workload=None, marker_page=None, measurement=None)
    if record["retention"] != "retained":
        return result
    name = slot_name(slot)
    raw = member(archive, name, ETL_LIMIT)
    check(len(raw) == record["source_bytes"] and sha(raw) == record["source_sha256"], "retained ETL differs from capture receipt")
    try:
        truth = recorder_document(attempt)
        result.update(session_id=truth["session_id"], workload=truth)
    except (KeyError, TypeError, ValueError, RecursionError):
        result["reason"] = "invalid_recorder_output"
        return result
    path = directory / name
    with path.open("xb") as out:
        out.write(raw)
    with files.hold(path) as source:
        check(file_hash(source) == record["source_sha256"], "replay ETL changed")
        flags = ["--etl-hard-faults", str(path), "--sha256", record["source_sha256"], "--activity-markers", "--limit", "128"]
        native = run_reader(reader, flags, directory, cfg["timeout_ms"], MIB, files, binary)
    result["reader"] = reader_receipt(native)
    if native["state"] != "exited" or native["image_binding"] != study.MATCHED_IMAGE or native["exit_code"] not in (0, 1):
        result["reason"] = "reader_unavailable"
        return result
    try:
        raw_page, complete = original(native["stdout"], MIB)
        check(complete, "reader output truncated")
        page = study.DECODE(raw_page)
        check(type(page) is dict and page["source_sha256"] == record["source_sha256"] and
              native["exit_code"] == (0 if page["status"] == "read" else 1), "unexpected reader output")
        result["marker_page"] = page
        result["measurement"] = study.measure(cfg, slot, activity, truth, result["process"], page, record["source_sha256"], len(raw))
        result.update(status="measured", reason=None)
    except study.Unqualified as exc:
        result.update(status="unqualified", reason=str(exc))
    except (KeyError, TypeError, ValueError, RecursionError):
        result.update(status="unqualified", reason="invalid_measurement_evidence")
    return result


def replay(args, output, files, stack, held, directory):
    source = held_file(local_path(args.package), files, stack, held)
    expected, plan_pin = digest(args.sha256.lower()), digest(args.plan_sha256.lower())
    check(0 < os.fstat(source.fileno()).st_size <= MAX_PACKAGE and file_hash(source) == expected, "package extent or SHA-256 mismatch")
    bounds = stored_directory(source, 2, 2+2*study.MAX_PAIRS)
    with zipfile.ZipFile(source) as archive:
        cfg, acquisition, env, outcomes = structure(archive, source, bounds, plan_pin)
        exe, binary = pinned_image(args.exe, cfg["reader_sha256"], files, stack, held)
        rows = [observe(cfg, slot, study.activity_id(acquisition, plan_pin, slot), result, archive, exe, binary, directory, files)
                for slot, result in zip(cfg["slots"], outcomes, strict=True)]
    report = study.summarize(cfg, plan_pin, expected, acquisition, env, rows)
    data = encoded(report)
    if output:
        report_pin = publish_new(output, lambda out: out.write(data))
        state = "written"
    else:
        report_pin = sha(data)
        state = "matched" if report_pin == digest(args.check_report.lower()) else "mismatch"
    receipt = dict(schema="kn.etl_handoff_study_receipt.v1", status=state, study_status=report["status"],
                   report_sha256=report_pin, plan_sha256=plan_pin, package_sha256=expected,
                   planned_pairs=report["planned_pairs"], measured_pairs=report["measured_pairs"])
    return receipt, int(state == "mismatch" or report["status"] != "complete")


def execute(args):
    check(os.name == "nt", "workload acquisition and replay require Windows")
    files = WindowsFiles()
    output = local_path(args.output) if args.output is not None else None
    parent = output.parent if output else local_path(tempfile.gettempdir())
    with ExitStack() as stack:
        held = set()
        files.parents(stack, parent, held)
        if output:
            check(not os.path.lexists(output), "choose a new private output file")
        if args.command == "plan":
            cfg = study.plan(str(uuid4()), args.pairs, args.steps, args.baseline_ms, args.candidate_ms, args.timeout_ms,
                             args.recorder_sha256.lower(), args.exe_sha256.lower())
            pin = publish_new(output, lambda out: out.write(encoded(cfg)))
            return dict(schema="kn.etl_handoff_plan_receipt.v1", plan_sha256=pin, planned_pairs=cfg["pairs"]), 0
        if args.command == "replay" and not output:
            digest(args.check_report.lower())
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=parent, prefix=".kn-handoff-")))
        files.parents(stack, directory, held)
        if args.command == "capture":
            return capture(args, output, files, stack, held, directory)
        return replay(args, output, files, stack, held, directory)


def main():
    if not outputs_safe(sys.argv[1:]):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    new = sub.add_parser("plan", help="register paired work, treatment and arm order", allow_abbrev=False)
    new.add_argument("--pairs", required=True, type=int, help="2..16 consecutive pairs")
    new.add_argument("--steps", type=int, default=20000, help="fixed iterations per thread and arm (1..1000000)")
    new.add_argument("--baseline-ms", type=int, required=True, help="baseline relative timer delay (0..1000 ms)")
    new.add_argument("--candidate-ms", type=int, required=True, help="candidate relative timer delay (0..1000 ms)")
    new.add_argument("--timeout-ms", type=int, default=15000, help="deadline per process (1..120000 ms)")
    for flag in ("--recorder-sha256", "--exe-sha256", "--output"):
        new.add_argument(flag, required=True)
    acquire = sub.add_parser("capture", help="run each planned arm in a fresh producer process", allow_abbrev=False)
    for flag in ("--plan", "--plan-sha256", "--recorder", "--output"):
        acquire.add_argument(flag, required=True)
    verify = sub.add_parser("replay", help="read original ETLs and compute paired differences", allow_abbrev=False)
    for flag in ("--package", "--sha256", "--plan-sha256", "--exe"):
        verify.add_argument(flag, required=True)
    target = verify.add_mutually_exclusive_group(required=True)
    target.add_argument("--output", help="new private report file")
    target.add_argument("--check-report", help="expected digest of exact report bytes")
    args = parser.parse_args()
    try:
        receipt, code = execute(args)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError, RecursionError) as exc:
        if outputs_safe(sys.argv[1:]):
            print(f"Handoff study failed: {exc}", file=sys.stderr)
        return 2
    if not outputs_safe(sys.argv[1:]):
        return 2
    return write_result(encoded(receipt)) or code


if __name__ == "__main__":
    raise SystemExit(main())
