"""Independent ETW payload and interval checks for the owned scheduling experiment."""
from copy import deepcopy
from contextlib import ExitStack
from fractions import Fraction
from itertools import combinations, groupby
import json
from statistics import median
import subprocess
import zipfile

import etl_traceprocessor as sdk
from etl_reader_process import WindowsFiles, file_hash, run_reader
from saved_etl_comparison import MIB, original


def traceprocessor_markers(package, report, deployment, folder):
    """Re-query each scheduling task and compare every selected header and raw QPC."""
    assert report["plan"].get("observe_scheduling")
    files, matched = WindowsFiles(), 0
    with ExitStack() as stack, zipfile.ZipFile(package) as archive:
        program, binary, runtime = sdk.admit(deployment, folder, files, stack, set())
        for row in report["observations"]:
            path = folder / "sdk-source.etl"
            path.write_bytes(archive.read(f"slot-{row['selection']['slot']:02d}.etl"))
            events = [m["event"] for m in row["marker_page"]["markers"]]
            with files.hold(path) as source:
                assert file_hash(source) == row["etl_sha256"]
                table_rows = set()
                for task in (4, 5, 8, 9):
                    group = [e for e in events if e["task"] == task]
                    if not group:
                        assert task == 8 and not row["measurement"]["scheduling"]["observer"]["views"]
                        continue
                    start, stop = group[0], group[-1]
                    scope = {k: start[k] for k in ("header_process_id", "header_thread_id", "channel", "task")}
                    scope.update(begin_raw=start["raw_timestamp"], end_raw=stop["raw_timestamp"])
                    args = [str(path), start["provider_guid"], start["activity_id"], *map(str, scope.values())]
                    attempt = run_reader(program, args, folder, 60000, MIB, files, binary)
                    assert attempt["state"] == "exited" and attempt["exit_code"] == 0 and attempt["image_binding"]["status"] == "matched"
                    raw, complete = original(attempt["stdout"], MIB)
                    projection = json.loads(raw)
                    assert complete and projection["schema"] == sdk.SCHEMA and projection["table"] == runtime["table"]
                    assert projection["source_sha256"] == row["etl_sha256"] and projection["source_bytes"] == row["marker_page"]["source_bytes"]
                    assert projection["query_filter"] == scope and projection["activity_marker_rows"] == projection["provider_rows"] == len(events)
                    assert projection["scoped_marker_rows"] == projection["matched_rows"] == len(group) <= projection["row_limit"]
                    sdk.verify_modules(projection["loaded_processing_modules"], ("Events", "Processes", "Processing"))
                    previous = 0
                    for event, other in zip(group, projection["rows"], strict=True):
                        assert all(event[k] == other[k] for k in (*sdk.HEADER, "raw_timestamp"))
                        assert other["clock_type"] == "PerformanceCounter" and other["timestamp_partial"] is False
                        ordinal = other["table_row"]
                        assert previous < ordinal <= len(events) and ordinal not in table_rows
                        table_rows.add(ordinal)
                        previous = ordinal
                matched += len(table_rows)
    return matched


def minimum(windows, count):
    if not windows:
        return 0
    lengths = []
    for cuts in combinations(range(1, len(windows)), min(len(windows), count)-1):
        boundaries = (0, *cuts, len(windows))
        lengths.append(sum(max(0, windows[b-1][0]-windows[a][1]) for a, b in zip(boundaries, boundaries[1:])))
    return min(lengths)


def from_etl(oracle, path, row):
    raw = subprocess.check_output([oracle, path, "--marker-data"], timeout=60)
    source = [json.loads(line) for line in raw.splitlines()]
    markers = row["marker_page"]["markers"]
    by_record = {r["record_ordinal"]: r for r in source if r.get("record_kind") == "activity_boundary"}
    assert len(markers) == len(by_record)
    assert source[-1]["records_seen"] == row["marker_page"]["records_seen"]
    evidence = row["measurement"]["scheduling"]
    assert evidence["status"] == "measured" and evidence["scheduler_timeline"] is None
    truth = row["workload"]
    profiles, samples, expected_views = {}, [], []
    join = tuple(map(int, truth["join_call"]))
    last_start = None
    for marker in markers:
        e = by_record[marker["event"]["record_ordinal"]]
        eid = e["event_id"]
        payload = marker["handoff_payload"]
        if eid not in (8, 10, 19, 21):
            assert payload is None and e["raw"] == ""
            if eid == 18:
                last_start = e
            continue
        assert e["version"] == 2 and payload["payload_bytes"] == e["length"] and payload["payload_hex"] == e["raw"]
        blob = bytes.fromhex(e["raw"])
        w = [int.from_bytes(blob[i:i+8], "little") for i in range(0, len(blob), 8)]
        assert w[0] == 1 and len(blob) == 8*len(w)
        if eid in (8, 10):
            name = "worker_timer" if eid == 8 else "caller_join"
            result = evidence[name]
            call = tuple(map(int, truth["timer_call" if eid == 8 else "join_call"]))
            assert result["stop_record"] == e["record_ordinal"] and tuple(w[3:5]) == call
            assert len(w) == 19 and w[1] == result["enable_win32"] == 0 and w[2] == result["disable_win32"] == 0
            for word, key in ((5, "before"), (12, "after")):
                actual = result[key]
                assert list(map(int, (actual[k] for k in ("win32_status", "begin_qpc", "end_qpc", "context_switches",
                                                           "wait_reason_bitmap", "cycle_time", "retry_count")))) == w[word:word+7]
            assert 0 < w[6] <= w[7] <= call[0] <= call[1] <= w[13] <= w[14] <= int(e["raw_timestamp"])
            profiles[name] = w[15]-w[8]
            assert result["switch_delta"] == profiles[name] and int(result["cycle_delta"]) == w[17]-w[10]
            assert int(result["interval_wait_reasons"]) == w[16]
        elif eid == 19:
            assert last_start and last_start["header_thread_id"] == e["header_thread_id"] == evidence["observer"]["observer_tid"]
            assert int(last_start["raw_timestamp"]) <= w[4] <= w[5] <= int(e["raw_timestamp"])
            result = evidence["observer"]["views"][w[1]-1]
            assert (last_start["record_ordinal"], e["record_ordinal"]) == (result["start_record"], result["stop_record"])
            assert [result["view"], result["worker_before"], result["worker_after"], int(result["begin_qpc"]), int(result["end_qpc"]),
                    result["query_win32"], int(result["cycle"]), result["reported_nodes"], len(result["nodes"])] == w[1:10]
            nodes = [w[i:i+6] for i in range(10, len(w), 6)]
            assert [[n["type"], n["status"], n.get("pid", 0), n.get("tid", 0), n.get("wait_time", 0), n.get("context_switches", 0)]
                    for n in result["nodes"]] == nodes
            if (w[2:4] == [258, 258] and join[0] < w[4] and w[5] < join[1] and w[6:8] == [0, 0] and len(nodes) >= 3 and
                    nodes[0][:4] == [8, 3, truth["pid"], truth["caller_tid"]] and nodes[1][:2] == [6, 6] and
                    nodes[2][0] == 8 and nodes[2][1] in (2, 3) and nodes[2][2:4] == [truth["pid"], truth["joined_tid"]]):
                expected_views.append(e["record_ordinal"])
                samples.append((w[4]-1, w[5]+1, nodes[0][-1]))
            last_start = None
        else:
            monitor = evidence["observer"]
            assert w[1:] == [monitor["setup_win32"], monitor["open_win32"], monitor["observer_win32"], monitor["stop_reason"],
                             monitor["observer_tid"], len(monitor["views"])]
            assert monitor["stop_record"] == e["record_ordinal"]
    hz = int(truth["frequency"])
    runs = {key: list(group) for key, group in groupby(samples, lambda item: item[2])}
    from_wct = sum(max(0, group[-1][0]-group[0][1]) for key, group in runs.items() if key)
    lower = max(from_wct, minimum(samples, profiles["caller_join"]))
    assert evidence["caller_residency"]["witness_stop_records"] == expected_views
    result = {}
    for role, phase, call, minimum_ticks in (("caller_residency", "caller_join", join, lower),
                                            ("worker_residency", "worker_timer", tuple(map(int, truth["timer_call"])), 0)):
        duration = call[1]-call[0]
        upper = duration if profiles[phase] else 0
        timing = evidence[role]
        assert timing["status"] == "bounded" and [int(timing[k]) for k in ("wait_call_ticks", "off_cpu_lower_ticks", "off_cpu_upper_ticks",
               "on_cpu_lower_ticks", "on_cpu_upper_ticks")] == [duration, minimum_ticks, upper, duration-upper, duration-minimum_ticks]
        result[role] = [Fraction(t*10**9, hz) for t in (minimum_ticks, upper)]
    return result


def check_pairs(arms, report):
    summary = report["scheduling_summary"]
    assert summary["measured_pairs"] == report["planned_pairs"] and summary["unavailable_pairs"] == 0
    samples = {}
    def value(r):
        return Fraction(int(r["numerator"]), int(r["denominator"]))
    for pair in report["pairs"]:
        a, b = (arms[pair["pair"], role] for role in ("baseline", "candidate"))
        for phase in a:
            possibilities = [y-x for x in a[phase] for y in b[phase]]
            lo, hi = min(possibilities), max(possibilities)
            projected = pair["off_cpu_change_ns"][phase]
            assert (lo, hi) == (value(projected["lower"]), value(projected["upper"]))
            for group in ("all", pair["order"][0]):
                samples.setdefault((group, phase), []).append((lo, hi))
    for (group, phase), values in samples.items():
        dest = (summary["changes"] if group == "all" else summary["by_first_arm"][group])[phase]
        assert [value(dest[k]) for k in ("median_lower_ns", "median_upper_ns")] == [median(c) for c in zip(*values)]
        counts = [sum(lo > 0 for lo, hi in values), sum(hi < 0 for lo, hi in values), values.count((0, 0))]
        assert [dest[k] for k in ("longer", "shorter", "equal", "unresolved")] == [*counts, len(values)-sum(counts)]


def controls(report, assess, partition, residency):
    # Exhaust every arrangement of cuts independently of the dynamic program.
    for n in range(1, 9):
        spans = [(i*i+1, i*i+1+i%3) for i in range(n)]
        for switches in range(1, n+3):
            assert partition(spans, switches) == minimum(spans, switches)
    timed = lambda lo, hi, count, record: dict(relation="blocked_on_joined_worker", begin_qpc=str(lo), end_qpc=str(hi),
                                               stop_record=record, nodes=[dict(context_switches=count)])
    views = [timed(10, 12, 5, 1), timed(30, 34, 5, 2), timed(60, 62, 6, 3)]
    counter = lambda delta: dict(status="measured", switch_delta=delta)
    assert residency(counter(0), (1, 90), views)["status"] == "counter_witness_conflict"
    assert residency(counter(1), (1, 90), views)["status"] == "counter_witness_conflict"
    assert residency(counter(2), (1, 90), views)["status"] == "bounded"
    assert int(residency(counter(3), (1, 90), views)["off_cpu_lower_ticks"]) == 16
    assert residency(counter(3), (1, 90), [views[2], views[0]])["status"] == "counter_witness_conflict"
    row = next(r for r in report["observations"] if r["measurement"]["scheduling"]["observer"]["views"]) if any(
        r["measurement"]["scheduling"]["observer"]["views"] for r in report["observations"]) else report["observations"][0]
    original = row["marker_page"]
    def edit(event_id, index, new):
        page = deepcopy(original)
        marker = next(r for r in page["markers"] if r["event"]["event_id"] == event_id)
        payload = marker["handoff_payload"]
        data = bytearray.fromhex(payload["payload_hex"])
        data[8*index:8*(index+1)] = int(new).to_bytes(8, "little")
        payload["payload_hex"] = data.hex()
        return assess(row, page)
    for phase, eid in (("caller_join", 10), ("worker_timer", 8)):
        for pos, new in ((0, 9), (3, 1), (6, 1), (14, 2**63), (8, 2**32)):
            changed = edit(eid, pos, new)
            assert changed["status"] == "partial" and changed[phase]["status"] == "invalid_evidence"
        assert edit(eid, 2, 5)[phase]["status"] == "unavailable"
        assert edit(eid, 8, 2**32-1)[phase]["status"] == "counter_discontinuity"
    page = deepcopy(original)
    target = next(r for r in page["markers"] if r["event"]["event_id"] == 10)
    target["handoff_payload"]["payload_hex"] = None
    assert assess(row, page)["caller_join"]["status"] == "invalid_evidence"
    assert edit(21, 6, 9)["observer"]["status"] == "invalid_evidence"
    if any(r["event"]["event_id"] == 19 for r in original["markers"]):
        for pos, new in ((1, 9), (2, 17), (5, 0), (9, 17)):
            assert edit(19, pos, new)["observer"]["status"] == "invalid_evidence"
