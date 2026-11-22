"""Retain independent TraceProcessor table coordinates and QPC intervals for an owned handoff."""
from collections import Counter, defaultdict
from fractions import Fraction

import etl_handoff as study
import etl_traceprocessor as sdk
from owned_module_benchmark import check, uint


PHASES = ("activity", "caller_work", "worker_span")


def native_markers(page, source_hash, size, activity_id, schema):
    check(page["schema"] == schema and page["status"] == "read" and page["source_sha256"] == source_hash and
          uint(page["source_bytes"]) == size and page["header_scope"] == "keyed_nonclassic_start_stop" and
          page["thread_filter"] is None and uint(page["after"]) == 0 and page["next_after"] is None, "incomplete native page")
    check(type(page["opcodes"]) is list and len(page["opcodes"]) == 2 and [uint(op) for op in page["opcodes"]] == [1, 2],
          "unexpected native marker filter")
    log, clock, rows = page["log_header"], page["clock"], page["markers"]
    check(uint(clock["raw_type"]) == 1 and clock["kind"] == "qpc" and study.qpc(clock["header_perf_frequency"]) and
          page["buffer_comparison"] == "matched" and 0 < uint(log["buffers_written"]) == uint(page["buffers_processed"]) and
          all(uint(n) == 0 for n in (log["events_lost"], log["buffers_lost"], page["loss_marker_records"],
                                      page["excluded_start_stop_records"])), "native source coverage unqualified")
    check(type(rows) is list and len(rows) == uint(page["matched_markers"], 128) == uint(page["decoded_activity_markers"]),
          "native marker count mismatch")
    selected = []
    previous = 0
    records = uint(page["records_seen"], 2_000_000)
    for i, marker in enumerate(rows, 1):
        event = marker["event"]
        ordinal = uint(event["record_ordinal"], records)
        check(uint(marker["marker_ordinal"]) == i and previous < ordinal, "invalid native record ordinal")
        previous = ordinal
        if study.guid(event["provider_guid"]) != study.PROVIDER or study.guid(event["activity_id"]) != activity_id:
            continue
        check(uint(event["opcode"]) in (1, 2) and study.qpc(event["raw_timestamp"]), "invalid native marker")
        for key, maximum in (("channel", 255), ("task", 65535), ("event_id", 65535), ("version", 255),
                             ("header_process_id", study.UINT32), ("header_thread_id", study.UINT32)):
            uint(event[key], maximum)
        selected.append(event)
    return selected


def header(row):
    return tuple(row[k] for k in sdk.HEADER)


def has_qpc(row):
    return row["clock_type"] == "PerformanceCounter" and not row["timestamp_partial"] and int(row["raw_timestamp"]) > 0


def link_rows(events, rows, truncated):
    exact, uncertain = defaultdict(list), defaultdict(list)
    for row in rows:
        key = header(row)
        if has_qpc(row):
            exact[key, row["raw_timestamp"]].append(row["table_row"])
        else:
            uncertain[key].append(row["table_row"])
    native_counts = Counter((header(e), e["raw_timestamp"]) for e in events)
    links, matched = [], set()
    for event in events:
        key = header(event)
        identity = key, event["raw_timestamp"]
        candidates, unknown = exact[identity], uncertain[key]
        if truncated:
            status = "row_limit"
        elif unknown:
            status = "clock_unqualified"
        elif native_counts[identity] > 1 or len(candidates) > 1:
            status = "ambiguous_rows"
        elif not candidates:
            status = "row_missing"
        else:
            status = "matched"
            matched.add(candidates[0])
        links.append(dict(record_ordinal=event["record_ordinal"], status=status,
                          matching_table_rows=candidates, unqualified_clock_rows=unknown))
    unlinked = [r["table_row"] for r in rows if r["table_row"] not in matched]
    if truncated:
        status = "row_limit"
    elif not events and not rows:
        status = "activity_unobserved"
    elif unlinked or len(matched) != len(events):
        status = "row_mismatch"
    else:
        status = "matched"
    return dict(status=status, matched_markers=len(matched), marker_links=links, unlinked_table_rows=unlinked)


def phase_intervals(rows, issue, hz, measurement, process):
    intervals = {}
    for task, phase in enumerate(PHASES, 1):
        group = [r for r in rows if r["task"] == task and r["channel"] == 0 and r["version"] == 1]
        start, stop = ([r for r in group if r["opcode"] == op and r["event_id"] == 2*(task-1)+op] for op in (1, 2))
        result = dict(start_table_row=None, stop_table_row=None, elapsed_qpc_ticks=None, elapsed_ns=None,
                      recorder_pid_matches=None, native_elapsed_matches=None)
        if issue:
            status = issue
        elif len(start) > 1 or len(stop) > 1:
            status = "ambiguous_rows"
        elif not start or not stop:
            status = "boundary_missing"
        else:
            a, b = start[0], stop[0]
            result.update(start_table_row=a["table_row"], stop_table_row=b["table_row"])
            if process:
                result["recorder_pid_matches"] = a["header_process_id"] == b["header_process_id"] == process["pid"]
            if not has_qpc(a) or not has_qpc(b):
                status = "clock_unqualified"
            elif (a["header_process_id"], a["header_thread_id"]) != (b["header_process_id"], b["header_thread_id"]):
                status = "thread_mismatch"
            elif a["header_process_id"] in (0, study.UINT32) or a["header_thread_id"] in (0, study.UINT32):
                status = "thread_unqualified"
            elif result["recorder_pid_matches"] is False:
                status = "process_mismatch"
            elif a["table_row"] >= b["table_row"] or int(a["raw_timestamp"]) > int(b["raw_timestamp"]):
                status = "order_conflict"
            else:
                elapsed = int(b["raw_timestamp"])-int(a["raw_timestamp"])
                result.update(elapsed_qpc_ticks=str(elapsed), elapsed_ns=study.rational(Fraction(elapsed*1_000_000_000, hz)),
                              native_elapsed_matches=measurement["ticks"][phase] == str(elapsed) if measurement else None)
                status = "measured"
        intervals[phase] = dict(status=status, **result)
    return intervals


def correspondence(document, arm, size, schema):
    source, activity = arm["etl_sha256"], arm["expected_activity_id"]
    rows = sdk.validate_projection(document, source, size, study.PROVIDER, activity)
    truncated = document["matched_rows"] > len(rows)
    meta = document["trace_metadata"]
    hz = int(meta["performance_counter_hz"])
    issue = None
    if meta["lost_events"] or meta["lost_buffers"]:
        issue = "sdk_loss_reported"
    elif hz <= 0 or meta["clock_type"] != "PerformanceCounter" or meta["context_clock_type"] != "PerformanceCounter" or meta["timestamp_context_partial"]:
        issue = "sdk_clock_unqualified"
    measurement = None
    same_frequency = None
    try:
        events = native_markers(arm["marker_page"], source, size, activity, schema)
    except (ValueError, KeyError, TypeError):
        events = None
    else:
        same_frequency = hz == int(arm["marker_page"]["clock"]["header_perf_frequency"])
        measurement = arm["measurement"]
    if issue or events is None:
        result = dict(status=issue or "native_page_unqualified", matched_markers=0, marker_links=None,
                      unlinked_table_rows=[r["table_row"] for r in rows])
    else:
        result = link_rows(events, rows, truncated)
    intervals = phase_intervals(rows, issue or ("row_limit" if truncated else None), hz, measurement, arm["process"])
    result.update(marker_status=result["status"], native_frequency_matches=same_frequency, phase_intervals=intervals)
    if result["status"] == "matched":
        if not same_frequency:
            result["status"] = "clock_disagreement"
        elif any(v["status"] != "measured" or v["recorder_pid_matches"] is not True or v["native_elapsed_matches"] is False for v in intervals.values()):
            result["status"] = "phase_unconfirmed"
    return result


def observe(path, arm, size, schema, runtime, directory, timeout, files):
    args = [str(path), study.PROVIDER, arm["expected_activity_id"], "--all-markers"]
    native_hash = arm["reader"]["stdout_sha256"] if arm["reader"] else None
    return sdk.read_query(args, native_hash, runtime, directory, timeout, files, study.DECODE,
                          lambda doc: correspondence(doc, arm, size, schema))


def summarize(report, runtime):
    """Compare independently timed phases in the registered pairs, preserving every missing arm."""
    arms = report["observations"]
    results = [arm["traceprocessor"] for arm in arms]
    matched = sum(r["status"] == "matched" for r in results)
    groups = {name: {phase: [] for phase in PHASES} for name in ("all", "baseline", "candidate")}
    pairs = []
    for i, pair in enumerate(report["pairs"]):
        times = {}
        for arm in arms[2*i:2*i+2]:
            evidence = arm["traceprocessor"]
            comparison = evidence["correspondence"]
            if comparison is None:
                continue
            spans = comparison["phase_intervals"]
            if all(v["status"] == "measured" and v["recorder_pid_matches"] is True for v in spans.values()):
                times[arm["selection"]["role"]] = {phase: Fraction(int(v["elapsed_ns"]["numerator"]), int(v["elapsed_ns"]["denominator"]))
                                                  for phase, v in spans.items()}
        changes = agrees = None
        if len(times) == 2:
            changes = {}
            for phase in PHASES:
                delta = times["candidate"][phase] - times["baseline"][phase]
                changes[phase] = study.rational(delta)
                groups["all"][phase].append(delta)
                groups[pair["order"][0]][phase].append(delta)
            native = pair["candidate_minus_baseline_ns"]
            if native is not None:
                agrees = all(changes[k] == native[k] for k in PHASES)
        pairs.append(dict(pair=pair["pair"], order=pair["order"], phase_change_ns=changes, native_changes_match=agrees))
    distributions = {name: {phase: study.distribution(values) for phase, values in group.items()} for name, group in groups.items()}
    confirmed = matched == len(arms) and all(pair["native_changes_match"] is not False for pair in pairs)
    return dict(status="matched" if confirmed else "unconfirmed", native_study_schema=report["schema"],
                planned_arms=len(arms), matched_arms=matched, matched_markers=sum(r["correspondence"]["matched_markers"] for r in results if r["correspondence"]),
                planned_pairs=len(pairs), measured_pairs=len(groups["all"]["activity"]), pairs=pairs, changes=distributions["all"],
                by_first_arm={k: distributions[k] for k in ("baseline", "candidate")}, **runtime)
