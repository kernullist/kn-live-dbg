"""Compare one recorded activity in each of two SHA-256-pinned Windows ETLs."""
import argparse
from contextlib import ExitStack
from fractions import Fraction
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile
from typing import NamedTuple

from etl_reader_process import WindowsFiles, file_hash, reader_receipt, run_reader
import etl_traceprocessor
from owned_module_benchmark import check, decimal, encoded, publish_new, sha, uint
from saved_etl_comparison import MAX_ETL, MIB, digest, local_path, original, outputs_safe, write_result


DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]
MAX_RECORDS = 2_000_000
MAX_TICK = (1 << 63) - 1
NATIVE_SCHEMA = "kn.etl_hard_faults.v3"
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
FAULT_ONLY_ISSUES = {"fault_logger_conflict", "fault_family_unobserved_on_logger", "unknown_fault_tid",
                    "untimed_thread_fault", "fault_outside_thread_bracket", "fault_limit"}


class Selection(NamedTuple):
    path: Path
    pin: str
    start: int
    stop: int


class Measurement(NamedTuple):
    descriptor: dict
    duration_ns: Fraction
    fault_ns: Fraction | None


def selection(values):
    path, pin, start, stop = values
    start, stop = decimal(start), decimal(stop)
    check(0 < start < stop <= MAX_RECORDS, "use two increasing original record ordinals in 1..2000000")
    return Selection(local_path(path), digest(pin.lower()), start, stop)


def positive_tick(value):
    tick = decimal(value)
    check(0 < tick <= MAX_TICK, "expected a positive signed QPC value")
    return tick


def boundary_tick(value):
    check(type(value) is str and re.fullmatch(r"0|-?[1-9][0-9]{0,18}", value), "invalid thread boundary tick")
    number = int(value)
    check(-1 - MAX_TICK <= number <= MAX_TICK, "thread boundary outside signed QPC range")
    return number


def fault_union(page, window, start_tick, stop_tick):
    edges, faults = window["overlaps"], page["hard_faults"]
    check(uint(window["fault_limit"]) == 128 and type(edges) is list and type(faults) is list and
          len(edges) == len(faults) == uint(window["candidate_faults"], 128), "incomplete overlap witnesses")
    recorded = uint(page["decoded_hard_faults"], page["records_seen"])
    logger_faults = uint(window["decoded_faults_on_start_logger"], recorded)
    check(logger_faults > 0 and len(edges) <= logger_faults and
          all(uint(window[k]) == 0 for k in ("untimed_thread_faults", "unassigned_possible_faults",
                                             "other_logger_thread_faults", "faults_outside_thread_bracket")),
          "unqualified fault coverage")
    spans = []
    bracket = window["thread_evidence"]
    first, last = bracket["before"], bracket["after"]
    thread_start, thread_stop = boundary_tick(first["raw_timestamp"]), boundary_tick(last["raw_timestamp"])
    previous_record, previous_fault = first["record_ordinal"], 0
    for edge, fault in zip(edges, faults, strict=True):
        ordinal = uint(edge["record_ordinal"], MAX_RECORDS)
        fault_ordinal = uint(edge["fault_ordinal"], recorded)
        check(previous_record < ordinal == uint(fault["record_ordinal"]) < last["record_ordinal"] and
              previous_fault < fault_ordinal == uint(fault["fault_ordinal"]) and
              uint(fault["faulting_thread_id"]) == window["start"]["header_thread_id"] and
              uint(fault["logger_id"]) == window["start"]["logger_id"], "fault witness identity mismatch")
        previous_record, previous_fault = ordinal, fault_ordinal
        begin, end = positive_tick(fault["initial_time_raw"]), positive_tick(fault["raw_timestamp"])
        check(thread_start < begin < end < thread_stop, "fault outside thread bracket")
        lo, hi = max(start_tick, begin), min(stop_tick, end)
        check(lo < hi and (lo, hi, hi - lo) == tuple(decimal(edge[k]) for k in
              ("overlap_start_raw", "overlap_end_raw", "overlap_ticks")), "fault intersection mismatch")
        spans.append((lo, hi))
    cursor, total = start_tick, 0
    for lo, hi in sorted(spans):
        total += max(0, hi - max(cursor, lo))
        cursor = max(cursor, hi)
    check(total == decimal(window["fault_union_ticks"]), "fault union differs from original witnesses")
    return total


def project(page, query, size, exit_code):
    """Use native eligibility and verify the fields that enter the cross-recording arithmetic."""
    check(type(page) is dict and page["schema"] == NATIVE_SCHEMA, "unexpected reader schema")
    status = page["status"]
    check(type(status) is str and re.fullmatch(r"[a-z_]{1,64}", status), "invalid reader status")
    check(exit_code == (0 if status == "read" else 1), "reader exit disagrees with page")
    if status not in ("read", "partial"):
        check(page["source_sha256"] in (None, query.pin) and "activity_window" not in page, "misbound diagnostic")
        if status == "activity_record_not_observed":
            check(page["source_sha256"] == query.pin and uint(page["requested_start_record"]) == query.start and
                  uint(page["requested_stop_record"]) == query.stop, "diagnostic selector mismatch")
        return None
    check(page["source_sha256"] == query.pin and uint(page["source_bytes"]) == size and
          uint(page["after"]) == 0 and page["next_after"] is None, "source or page extent mismatch")
    check(page["provider_guid"] == "3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c" and
          (uint(page["event_id"]), uint(page["opcode"]), uint(page["version"])) == (0, 32, 2),
          "unexpected hard-fault descriptor")
    w = page["activity_window"]
    a, b = w["start"], w["stop"]
    check(uint(a["record_ordinal"]) == query.start and uint(b["record_ordinal"]) == query.stop and
          query.stop <= uint(page["records_seen"], MAX_RECORDS), "selected records differ")
    duration, union = w["window_ticks"], w["fault_union_ticks"]
    check((w["status"] == "measured") == (union is not None), "inconsistent fault qualification")
    if duration is None:
        check(union is None, "fault measurement without a window")
        return None
    check(w["status"] == "measured" or w["status"] in FAULT_ONLY_ISSUES, "window rejected by the native reader")
    check(status == "read" and page["buffer_comparison"] == "matched" and
          0 < uint(page["buffers_processed"]) == uint(page["log_header"]["buffers_written"]) and
          all(uint(page["log_header"][k]) == 0 for k in ("events_lost", "buffers_lost")) and
          uint(page["loss_marker_records"]) == uint(page["unsupported_hard_fault_records"]) == 0,
          "incomplete trace coverage")
    check(page["clock"]["kind"] == "qpc" and uint(page["clock"]["raw_type"]) == 1, "unqualified clock")
    frequency = positive_tick(page["clock"]["header_perf_frequency"])
    a_tick, b_tick = positive_tick(a["raw_timestamp"]), positive_tick(b["raw_timestamp"])
    check(b_tick - a_tick == positive_tick(duration), "duration differs from marker timestamps")
    check(uint(a["opcode"]) == 1 and uint(b["opcode"]) == 2 and uint(w["process_key_boundaries"]) >= 2 and
          uint(w["intervening_boundaries"]) == uint(w["unassigned_activity_boundaries"]) == 0, "unqualified marker boundaries")
    for key in ("provider_guid", "activity_id"):
        value = a[key]
        check(type(value) is str and GUID.fullmatch(value) and int(value.replace("-", ""), 16) > 0 and value == b[key],
              "invalid marker identity")
    for key, lower, upper in (("channel", 0, 255), ("task", 1, 65535), ("logger_id", 0, 65535),
                              ("header_process_id", 1, 0xfffffffe), ("header_thread_id", 1, 0xfffffffe)):
        check(lower <= uint(a[key], upper) == uint(b[key], upper), "marker scope mismatch")
    thread = w["thread_evidence"]
    check(thread["relation"] in ("start_end", "rundown_bracket") and
          uint(thread["paired_record_pid"]) == a["header_process_id"], "thread bracket unavailable")
    first, last = thread["before"], thread["after"]
    for bound in (first, last):
        check(uint(bound["payload_tid"]) == a["header_thread_id"] and uint(bound["payload_pid"]) == a["header_process_id"] and
              uint(bound["logger_id"]) == a["logger_id"], "thread bracket identity mismatch")
    check(uint(first["opcode"]) in (1, 3) and uint(last["opcode"]) in (2, 4) and
          0 < uint(first["record_ordinal"]) < query.start < query.stop < uint(last["record_ordinal"], page["records_seen"]) and
          boundary_tick(first["raw_timestamp"]) < a_tick < b_tick < boundary_tick(last["raw_timestamp"]),
          "activity outside thread bracket")
    descriptor = dict(provider_guid=a["provider_guid"], channel=a["channel"], task=a["task"])
    for label, marker in (("start", a), ("stop", b)):
        event_id = uint(marker["event_id"], 65535)
        # String, WPP, decoding-GUID, classic, XML and forwarded/legacy records lack the keyed marker semantics.
        check(event_id > 0 and not uint(marker["header_flags"], 65535) & (4 | 8 | 128 | 256) and
              not uint(marker["event_property"], 65535) & 7, "unkeyed event descriptor")
        descriptor[label + "_event_id"] = event_id
        descriptor[label + "_version"] = uint(marker["version"], 255)
    tick_ns = Fraction(1_000_000_000, frequency)
    fault_ns = None if union is None else fault_union(page, w, a_tick, b_tick) * tick_ns
    return Measurement(descriptor, (b_tick - a_tick) * tick_ns, fault_ns)


def observe(query, program, binary, files, stack, held, directory, timeout):
    side = dict(source_sha256=query.pin, observed_sha256=None, source_bytes=None, requested_start_record=query.start,
                requested_stop_record=query.stop, status="source_unavailable", os_error=None, reader=None, page=None)
    try:
        files.parents(stack, query.path.parent, held)
        stream = stack.enter_context(files.hold(query.path))
        size = os.fstat(stream.fileno()).st_size
        side["source_bytes"] = size
        if not 0 < size <= MAX_ETL or os.path.samestat(os.fstat(stream.fileno()), os.fstat(binary.fileno())):
            side["status"] = "source_rejected"
            return side, None
        side["observed_sha256"] = file_hash(stream)
    except (OSError, ValueError) as exc:
        side["os_error"] = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        return side, None
    if side["observed_sha256"] != query.pin:
        side["status"] = "source_pin_mismatch"
        return side, None
    arguments = ["--etl-hard-faults", str(query.path), "--sha256", query.pin, "--activity-window", str(query.start), str(query.stop)]
    attempt = run_reader(program, arguments, directory, timeout, MIB, files, binary)
    result = reader_receipt(attempt)
    side["reader"] = result
    if result["state"] != "exited" or result["image_binding"] != dict(status="matched", win32_status=0):
        side["status"] = "reader_unavailable"
        return side, None
    try:
        raw, complete = original(attempt["stdout"], MIB)
        check(complete, "reader page exceeds limit")
        page = DECODE(raw)
        measurement = project(page, query, size, result["exit_code"])
    except (KeyError, TypeError, ValueError, RecursionError):
        side["status"] = "invalid_reader_page"
        return side, None
    side.update(status=page["status"], page=page)
    return side, measurement


def rational(value):
    return None if value is None else dict(numerator=str(value.numerator), denominator=str(value.denominator))


def metric(before, after, comparable):
    delta = after - before if comparable and before is not None and after is not None else None
    percent = 100 * delta / before if delta is not None and before else None
    return dict(baseline_ns=rational(before), candidate_ns=rational(after),
                candidate_minus_baseline_ns=rational(delta), relative_change_percent=rational(percent))


def comparison(baseline, candidate):
    before_side, before = baseline
    after_side, after = candidate
    if before is None or after is None:
        status = "window_unavailable"
    elif before_side["observed_sha256"] == after_side["observed_sha256"]:
        status = "same_recording"
    elif before.descriptor != after.descriptor:
        status = "descriptor_mismatch"
    else:
        status = "duration_only" if before.fault_ns is None or after.fault_ns is None else "compared"
    paired = status in ("duration_only", "compared")
    return dict(status=status, matched_descriptor=before.descriptor if paired else None,
                activity_duration=metric(before.duration_ns if before else None, after.duration_ns if after else None, paired),
                observed_hard_fault_union=metric(before.fault_ns if before else None, after.fault_ns if after else None, paired))


def execute(args):
    check(os.name == "nt", "ETL comparison requires Windows")
    queries = [selection(values) for values in (args.baseline, args.candidate)]
    program, expected = local_path(args.exe), digest(args.exe_sha256.lower())
    check(program.suffix.lower() == ".exe" and 1 <= args.timeout_ms <= 600000, "invalid executable or reader timeout")
    output = local_path(args.output) if args.output is not None else None
    expected_report = digest(args.check_report.lower()) if args.check_report is not None else None
    parent = output.parent if output else local_path(tempfile.gettempdir())
    files = WindowsFiles()
    with ExitStack() as stack:
        held = set()
        files.parents(stack, parent, held)
        if output:
            check(output not in (program, *(query.path for query in queries)) and not os.path.lexists(output),
                  "choose a new private report path")
        files.parents(stack, program.parent, held)
        binary = stack.enter_context(files.hold(program))
        check(file_hash(binary) == expected, "reader executable SHA-256 mismatch")
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=parent, prefix=".kn-etl-activities-")))
        files.parents(stack, directory, held)
        runtime = etl_traceprocessor.admit(args.traceprocessor, directory, files, stack, held) if args.traceprocessor else None
        before, after = [observe(q, program, binary, files, stack, held, directory, args.timeout_ms) for q in queries]
        result = comparison(before, after)
        report = dict(schema="kn.etl_activity_comparison.v1", reader_sha256=expected, reader_schema=NATIVE_SCHEMA,
                      timeout_ms=args.timeout_ms, baseline=before[0], candidate=after[0], comparison=result,
                      qualification=dict(scope="two_selected_marker_windows", symbol_lookup="not_requested",
                                         equivalent_workload=None, population_regression=None, cause_of_change=None))
        sdk_status = None
        if runtime:
            sides = {role: etl_traceprocessor.verify_side(q, side, measured, runtime, directory, args.timeout_ms, files, DECODE)
                     for role, q, (side, measured) in zip(("baseline", "candidate"), queries, (before, after), strict=True)}
            sdk_status = "matched" if all(s["status"] == "matched" for s in sides.values()) else "unconfirmed"
            report.update(schema="kn.etl_activity_comparison.v2", traceprocessor=dict(status=sdk_status, **runtime[2], **sides))
        data = encoded(report)
        if output:
            report_pin = publish_new(output, lambda stream: stream.write(data))
            state = "written"
        else:
            report_pin = sha(data)
            state = "matched" if report_pin == expected_report else "mismatch"
    receipt = dict(schema="kn.etl_activity_comparison_receipt.v1", status=state, comparison_status=result["status"],
                   report_sha256=report_pin, expected_report_sha256=expected_report)
    if sdk_status is not None:
        receipt.update(schema="kn.etl_activity_comparison_receipt.v2", traceprocessor_status=sdk_status)
    return receipt, int(state == "mismatch" or result["status"] != "compared" or sdk_status == "unconfirmed")


def main():
    if not outputs_safe(sys.argv[1:]):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--exe", required=True, help="local KnLiveDbg executable")
    parser.add_argument("--exe-sha256", required=True, help="expected executable SHA-256")
    parser.add_argument("--traceprocessor", nargs=2, metavar=("ADAPTER_ZIP", "SHA256"),
                        help="independently check both pairs of marker headers with a pinned TraceProcessor adapter")
    for role in ("baseline", "candidate"):
        parser.add_argument("--" + role, required=True, nargs=4, metavar=("ETL", "SHA256", "START", "STOP"),
                            help="pinned recording and its two original record numbers")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--output", help="publish a new private JSON report")
    target.add_argument("--check-report", metavar="SHA256", help="repeat both queries and compare exact report bytes")
    parser.add_argument("--timeout-ms", type=int, default=240000, help="per-query timeout in milliseconds (1..600000)")
    args = parser.parse_args()
    try:
        receipt, code = execute(args)
    except (OSError, ValueError) as exc:
        if outputs_safe(sys.argv[1:]):
            print(f"Activity comparison failed: {exc}", file=sys.stderr)
        return 2
    if not outputs_safe(sys.argv[1:]):
        return 2
    return write_result(encoded(receipt)) or code


if __name__ == "__main__":
    raise SystemExit(main())
