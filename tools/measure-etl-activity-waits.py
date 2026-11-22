"""Account for the waits of one marked Windows thread in a saved ETL."""
import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import runpy
import sys
import tempfile

from etl_activity_waits import ActivityWaits, MAX_RECORDS, candidate
import etl_interrupt_overlap
from etl_ready_correspondence import TableBindings, correlate, key
from etl_reader_process import WindowsFiles, file_hash, reader_receipt, run_reader
import etl_traceprocessor
from owned_module_benchmark import check, decimal, encoded, publish_new, uint
from saved_etl_comparison import MAX_ETL, MIB, digest, local_path, original, outputs_safe, write_result

DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]
TRACE_FIELDS = ("source_sha256", "source_bytes", "clock", "log_header", "records_seen", "decoded_switches",
                "buffers_processed", "buffer_comparison", "loss_marker_records", "unsupported_switch_records")


def read(program, binary, flags, directory, timeout, files):
    attempt = run_reader(program, flags, directory, timeout, 2*MIB, files, binary)
    receipt = reader_receipt(attempt)
    query = dict(reader=receipt, page=None)
    if receipt["state"] == "exited" and receipt["image_binding"] == dict(status="matched", win32_status=0):
        raw, complete = original(attempt["stdout"], 2*MIB)
        if complete and raw:
            try:
                query["page"] = DECODE(raw)
            except (ValueError, RecursionError):
                pass
    return query


def sdk_query(runtime, path, pin, size, origins, directory, timeout, files, tables):
    program, binary, _ = runtime
    keys = list(dict.fromkeys(map(key, origins)))
    query = read(program, binary, [str(path), "--cpu-context", *keys], directory, timeout, files)
    matches = None
    if query["page"] is not None and query["reader"]["exit_code"] == 0:
        try:
            rows = correlate(query["page"], origins, pin, size)
            tables.check(query["page"], origins, rows)
            matches = rows
        except (KeyError, TypeError, ValueError, RecursionError):
            pass
    matched = matches is not None and all(m["status"] == "matched" for m in matches)
    return dict(status="matched" if matched else "unconfirmed", query=query, correspondence=matches)


def schedule_window(query, args, pin, size, after):
    page = query["page"]
    if page is None:
        return None, "schedule_reader_unavailable"
    check(page["schema"] == "kn.etl_switches.v4" and page["source_sha256"] == pin and
          uint(page["requested_start_record"]) == args.start and uint(page["requested_stop_record"]) == args.stop and
          uint(page["after"]) == after and uint(page["interval_page_limit"]) == args.page_size, "schedule selector mismatch")
    check(query["reader"]["exit_code"] == (0 if page["status"] == "read" else 1), "schedule exit mismatch")
    if page["status"] not in ("read", "partial"):
        return None, page["status"]
    check(uint(page["source_bytes"]) == size, "schedule size mismatch")
    window = page["activity_schedule"]
    if window["status"] != "covered":
        return None, window["status"]
    if page["status"] == "partial":
        return None, "partial_source"
    check(page["buffer_comparison"] == "matched" and 0 < uint(page["buffers_processed"]) == uint(page["log_header"]["buffers_written"]) and
          all(uint(page["log_header"][k]) == 0 for k in ("events_lost", "buffers_lost")) and
          uint(page["loss_marker_records"]) == uint(page["unsupported_switch_records"]) == 0 and
          page["clock"]["kind"] == "qpc" and uint(page["clock"]["raw_type"]) == 1 and decimal(page["clock"]["header_perf_frequency"]) > 0,
          "unqualified schedule coverage")
    count = uint(window["intersecting_intervals"], MAX_RECORDS)
    rows, following = window["intervals"], page["next_after"]
    check(type(rows) is list and len(rows) == min(args.page_size, count - after), "schedule page extent mismatch")
    end = after + len(rows)
    check((following is None and end == count) or (following is not None and uint(following) == end < count and end > after),
          "schedule cursor mismatch")
    return window, None


def origin_rows(query, selectors, common, window):
    b = query["page"]
    check(b["schema"] == "kn.etl_switches.v6" and b["requested_ready_records"] == selectors and
          {k: b[k] for k in TRACE_FIELDS} == common and b["status"] in ("read", "partial") and
          query["reader"]["exit_code"] == int(b["status"] == "partial"), "origin source or selector mismatch")
    for left, right in (("ready_records", "ready_records"), ("unsupported_ready_records", "unsupported_ready_records"),
                        ("unassigned_ready_records", "unassigned_ready_records"), ("thread_boundary_records", "thread_boundaries"),
                        ("unsupported_thread_boundaries", "unsupported_thread_boundaries")):
        check(uint(b[left]) == uint(window[right]), "inconsistent scheduler event coverage")
    rows = b["ready_origins"]
    check([r["selected_ready"]["record_ordinal"] for r in rows] == selectors, "missing or reordered ready events")
    if b["status"] == "partial":
        check(all(r["target_dispatch"]["switch_out_to_ready_ticks"] is None and r["target_dispatch"]["ready_to_switch_in_ticks"] is None
                  and r["relationship"]["readying_tid"] is None for r in rows), "attribution on a partial source")
    return dict(zip(selectors, rows, strict=True))


def interrupt_query(runtime, path, pin, size, window, frequency, running, directory, timeout, files):
    program, binary, _ = runtime
    a, b = window["start"], window["stop"]
    args = [str(path), "--interrupt-window", str(a["header_process_id"]), str(a["header_thread_id"]),
            a["raw_timestamp"], b["raw_timestamp"]]
    query = read(program, binary, args, directory, timeout, files)
    status, summary = "reader_unavailable", None
    if query["page"] is not None and query["reader"]["exit_code"] == 0:
        try:
            status, summary = etl_interrupt_overlap.correlate(query["page"], pin, size, window, frequency, running)
        except (KeyError, TypeError, ValueError, RecursionError):
            status = "inconsistent_interrupt_evidence"
    return dict(status=status, query=query, summary=summary)


def analyze(args, path, pin, size, reader, sdk, directory, files, emit):
    prefix = ["--etl-switches", str(path), "--sha256", pin]

    def native(flags):
        return read(*reader, [*prefix, *flags], directory, args.timeout_ms, files)

    after, aggregate, metadata = 0, None, None
    sdk_counts = Counter()
    tables = TableBindings() if sdk else None
    running = []
    reason = None
    while True:
        schedule = native(["--schedule-activity", str(args.start), str(args.stop), "--after", str(after), "--limit", str(args.page_size)])
        part = dict(after=after, schedule=schedule, origins=None, waits=None)
        if sdk:
            part["traceprocessor"] = None
        following = None
        try:
            window, reason = schedule_window(schedule, args, pin, size, after)
            if window is not None:
                page = schedule["page"]
                following = page["next_after"]
                common = {k: page[k] for k in TRACE_FIELDS}
                if aggregate is None:
                    metadata, aggregate = common, ActivityWaits(window)
                check(common == metadata, "schedule coverage changed")
                selectors = [uint(r["record_ordinal"], MAX_RECORDS) for item in window["intervals"] if (r := candidate(item)) is not None]
                check(selectors == sorted(set(selectors)) and all(selectors), "ready selectors out of sequence")
                origins = {}
                if selectors:
                    batch = native(["--ready-origins", ",".join(map(str, selectors))])
                    part["origins"] = batch
                    if batch["page"] is None:
                        reason = "origin_reader_unavailable"
                    else:
                        origins = origin_rows(batch, selectors, common, window)
                if reason is None:
                    part["waits"] = aggregate.account(window, origins)
                    if args.interrupt_overlap:
                        etl_interrupt_overlap.native_slices(window, running)
                    if sdk and origins:
                        result = sdk_query(sdk, path, pin, size, list(origins.values()), directory, args.timeout_ms, files, tables)
                        part["traceprocessor"] = result
                        if result["correspondence"] is None:
                            sdk_counts["unconfirmed"] += len(origins)
                        else:
                            sdk_counts.update(r["scope"] if r["status"] == "matched" else "unconfirmed" for r in result["correspondence"])
        except (KeyError, TypeError, ValueError, RecursionError):
            reason = "inconsistent_reader_evidence"
        emit((b"," if after else b"") + encoded(part).rstrip(b"\n"))
        if reason is not None or following is None:
            break
        after = following

    summary = None
    if reason is None:
        try:
            summary = aggregate.finish()
        except (KeyError, TypeError, ValueError, RecursionError):
            reason = "incomplete_activity_accounting"
    sdk_status = None
    if sdk:
        sdk_status = "unconfirmed" if reason is not None or sdk_counts["unconfirmed"] else "matched" if sdk_counts else "no_ready_records"
    result = dict(status="accounted" if summary is not None else "unavailable", reason=reason, summary=summary,
                  traceprocessor_status=sdk_status, traceprocessor_counts=dict(sorted(sdk_counts.items())) if sdk else None)
    if args.interrupt_overlap:
        overlap = dict(status="native_window_unavailable", query=None, summary=None)
        if summary is not None:
            frequency = decimal(metadata["clock"]["header_perf_frequency"])
            overlap = interrupt_query(sdk, path, pin, size, aggregate.header, frequency, running, directory, args.timeout_ms, files)
        result["interrupt_overlap"] = overlap
    return result


def execute(args):
    check(os.name == "nt" and 1 <= args.timeout_ms <= 600000 and 1 <= args.page_size <= 128, "invalid Windows reader settings")
    check(not args.interrupt_overlap or args.traceprocessor, "--interrupt-overlap requires --traceprocessor")
    args.start, args.stop = decimal(args.start), decimal(args.stop)
    check(0 < args.start < args.stop <= MAX_RECORDS, "select two increasing original ETW record numbers")
    path, program = local_path(args.etl), local_path(args.exe)
    pin, expected = digest(args.sha256.lower()), digest(args.exe_sha256.lower())
    output = local_path(args.output) if args.output is not None else None
    expected_report = digest(args.check_report.lower()) if args.check_report is not None else None
    parent = output.parent if output else local_path(tempfile.gettempdir())
    files = WindowsFiles()
    with ExitStack() as stack:
        held = set()
        for folder in (parent, path.parent, program.parent):
            files.parents(stack, folder, held)
        if output:
            check(not os.path.lexists(output), "choose a new report path")
        source, binary = (stack.enter_context(files.hold(p)) for p in (path, program))
        size = os.fstat(source.fileno()).st_size
        check(0 < size <= MAX_ETL and not os.path.samestat(os.fstat(source.fileno()), os.fstat(binary.fileno())) and
              file_hash(source) == pin and program.suffix.lower() == ".exe" and file_hash(binary) == expected, "source or reader pin mismatch")
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=parent, prefix=".kn-etl-waits-")))
        files.parents(stack, directory, held)
        sdk = etl_traceprocessor.admit(args.traceprocessor, directory, files, stack, held, cpu=True) if args.traceprocessor else None
        header = dict(schema="kn.etl_activity_waits.v1", source_sha256=pin, source_bytes=size, reader_sha256=expected,
                      requested_start_record=args.start, requested_stop_record=args.stop, interval_page_limit=args.page_size,
                      timeout_ms=args.timeout_ms, traceprocessor=sdk[2] if sdk else None,
                      qualification=dict(scope="one_marked_thread", symbol_lookup="not_requested", wait_object=None,
                                         cause_of_wait=None, application_critical_path=None))
        if args.interrupt_overlap:
            header["schema"] = "kn.etl_activity_waits.v2"
            header["traceprocessor"]["tables"].extend(etl_interrupt_overlap.TABLES)
            header["qualification"].update(interrupt_scope="exclusive_sdk_fragments_during_thread_residency",
                                           interrupt_time_basis="trace_relative_nanoseconds")
        outcome = {}

        def render(emit):
            emit(encoded(header)[:-2] + b',"pages":[')
            outcome.update(analyze(args, path, pin, size, (program, binary), sdk, directory, files, emit))
            emit(b'],"result":' + encoded(outcome).rstrip(b"\n") + b"}\n")

        if output:
            report_pin = publish_new(output, lambda stream: render(stream.write))
            result = "written"
        else:
            h = hashlib.sha256()
            render(h.update)
            report_pin = h.hexdigest()
            result = "matched" if report_pin == expected_report else "mismatch"
    receipt = dict(schema="kn.etl_activity_waits_receipt.v1", status=result, report_sha256=report_pin,
                   expected_report_sha256=expected_report, activity_waits_status=outcome["status"], traceprocessor_status=outcome["traceprocessor_status"])
    if args.interrupt_overlap:
        receipt.update(schema="kn.etl_activity_waits_receipt.v2", interrupt_overlap_status=outcome["interrupt_overlap"]["status"])
    return receipt, int(result == "mismatch" or outcome["status"] != "accounted" or outcome["traceprocessor_status"] == "unconfirmed" or
                        (args.interrupt_overlap and receipt["interrupt_overlap_status"] != "measured"))


def main():
    if not outputs_safe(sys.argv[1:]):
        return 2
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ("exe", "exe-sha256", "etl", "sha256", "start", "stop"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--traceprocessor", nargs=2, metavar=("CPU_ADAPTER_ZIP", "SHA256"))
    p.add_argument("--interrupt-overlap", action="store_true", help="measure exclusive DPC/ISR fragments during the marked thread's CPU residency")
    p.add_argument("--page-size", type=int, default=128)
    p.add_argument("--timeout-ms", type=int, default=240000)
    dest = p.add_mutually_exclusive_group(required=True)
    dest.add_argument("--output", help="write a new private evidence report")
    dest.add_argument("--check-report", help="repeat the query and verify the report SHA-256")
    args = p.parse_args()
    try:
        receipt, code = execute(args)
    except (OSError, ValueError) as exc:
        if outputs_safe(sys.argv[1:]):
            print(f"Activity wait measurement failed: {exc}", file=sys.stderr)
        return 2
    if not outputs_safe(sys.argv[1:]):
        return 2
    return write_result(encoded(receipt)) or code


if __name__ == "__main__":
    raise SystemExit(main())
