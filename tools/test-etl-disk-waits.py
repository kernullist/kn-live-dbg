"""Compare marked-thread disk waits with independent Windows TDH records in the public TaskbarLatency ETL."""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from itertools import pairwise
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile

import etl_disk_waits as disk
from etl_traceprocessor import DISK_PROGRAM, unpack

HERE = Path(__file__).resolve().parent
WAITS = runpy.run_path(str(HERE / "test-etl-activity-waits.py"))
TDH, PIN, call, pin = (WAITS[k] for k in ("TDH", "PIN", "call", "pin"))
COMPLETIONS = {10: (12, "read"), 11: (13, "write"), 14: (15, "flush")}
POSITIVES = {(339732, 374019): (9082, 8752), (397312, 398477): (39082, 38512),
             (418372, 418976): (39668, 39345), (451991, 452304): (39349, 38509)}


def disk_records(oracle, etl):
    p = subprocess.run([oracle, etl, "--disk-requests"], capture_output=True, check=True, timeout=240)
    rows = [json.loads(line) for line in p.stdout.splitlines()]
    footer = rows.pop()
    assert (footer["records_seen"], footer["clock_type"], footer["frequency"]) == (1093447, 1, 10000000)
    pending, requests = {}, defaultdict(list)
    assert len(rows) == 241 and len({r["packet_first_ordinal"] for r in rows}) == 23
    for n, e in enumerate(rows, 1):
        assert e["disk_ordinal"] == n and 1 <= e["packet_first_ordinal"] <= n
        assert n == 1 or rows[n-2]["record_ordinal"] < e["record_ordinal"]
        k, op = e["packet_first_ordinal"], e["opcode"]
        if op in COMPLETIONS:
            a = pending.pop(k)
            assert a["opcode"] == COMPLETIONS[op][0] and a["issuing_tid"] == e["issuing_tid"]
            assert int(a["raw_timestamp"]) < int(e["raw_timestamp"])
            requests[e["issuing_tid"]].append((a, e))
        else:
            assert op in (12, 13, 15) and k not in pending
            pending[k] = e
    assert [e["record_ordinal"] for e in pending.values()] == [1091129]
    assert Counter(b["opcode"] for pairs in requests.values() for _, b in pairs) == {10: 17, 11: 95, 14: 8}
    return rows, requests


def check_native(native_pages, rows):
    exposed = [r for q in native_pages for r in q["page"]["disk_events"]]
    assert len(exposed) == len(rows)
    for n, e in zip(exposed, rows):
        TDH["source_fields"](n, e, ("record_ordinal", "raw_timestamp", "opcode", "version", "pointer_bytes", "logger_id", "cpu"))
        assert n["disk_event_ordinal"] == e["disk_ordinal"] and n["reported_issuing_tid"] == e["issuing_tid"]
        completed = e["opcode"] in COMPLETIONS
        assert n["disk_number"] == (e["disk"] if completed else None)
        assert n["high_res_response_ticks"] == (e["response_ticks"] if completed else None)
        assert n["transfer_bytes"] == (e["bytes"] if e["opcode"] in (10, 11) else None)


def check_sdk(doc, rows, requests):
    tid = doc["query_filter"]["tid"]
    keys = {e["packet_first_ordinal"] for e in rows if e["issuing_tid"] == tid}
    history = [e for e in rows if e["packet_first_ordinal"] in keys]
    assert doc["matched_events"] == len(doc["events"]) == len(history) and doc["selected_packets"] == len(keys)
    clock = doc["clock"]

    def ns(raw):
        return (int(raw)-int(clock["reference_qpc"]))*100 + int(clock["reference_ns"])

    for e, orig in zip(doc["events"], history):
        TDH["source_fields"](e, orig, tuple(k for k in e if k != "relative_ns"))
        assert int(e["relative_ns"]) == ns(orig["raw_timestamp"])
    lo, hi = (int(doc["query_filter"][k]) for k in ("start_qpc", "stop_qpc"))
    expected = {(a["packet_first_ordinal"], ns(a["raw_timestamp"]), ns(b["raw_timestamp"])): (a, b)
                for a, b in requests[tid] if max(lo, int(a["raw_timestamp"])) < min(hi, int(b["raw_timestamp"]))}
    matched = {}
    for r in doc["activities"]:
        a, b = expected.pop((r["packet_first_ordinal"], int(r["start_ns"]), int(r["stop_ns"])))
        assert r["operation"] == COMPLETIONS[b["opcode"]][1] and (r["disk"], int(r["size_bytes"])) == (b["disk"], b["bytes"])
        matched[r["table_row"]] = (a, b)
    assert not expected and len(matched) == len(doc["activities"]) == doc["matched_activities"]
    return matched


def scheduler_parts(start, stop, bounds, ready, transitions):
    tid = start["header_thread_id"]
    _, _, steps = TDH["intervals"](tid, start["record_ordinal"], int(start["raw_timestamp"]), int(stop["raw_timestamp"]),
                                   bounds[tid], transitions[tid])
    for running, a, b, lo, hi in steps:
        x, y = a["record_ordinal"], b["record_ordinal"]
        if running:
            yield lo, hi, "on_cpu", x, y, None
            continue
        points = [r for r in ready[tid] if x < r["record_ordinal"] < y]
        clocks = [int(r["raw_timestamp"]) for r in (a, *points, b)]
        valid = (all(t < u for t, u in pairwise(clocks)) and all(p["logger_id"] == a["logger_id"] and
                 p["reserved_field"] == 0 and not p["ready_flags"] & ~15 for p in points))
        dispatch = [p for p in points if not p["ready_flags"] & ~9]
        if not valid or len(dispatch) != 1 or dispatch[0] != points[-1]:
            yield lo, hi, "other_off_cpu", x, y, None
            continue
        ready_at = int(dispatch[0]["raw_timestamp"])
        pivot = max(lo, min(hi, ready_at))
        yield lo, pivot, "waiting_before_ready" if a["old_state"] == 5 else "other_off_cpu", x, y, dispatch[0]
        yield pivot, hi, "ready_to_dispatch", x, y, dispatch[0]


def check_accounting(summary, matched, parts, stop):
    actual = {r["table_row"]: r for r in summary["requests"]}
    assert actual.keys() == matched.keys() and len(actual) == len(summary["requests"])
    for row, (a, b) in matched.items():
        r = actual[row]
        assert (r["init_record"], r["complete_record"], r["init_disk_ordinal"], r["complete_disk_ordinal"]) == (
            a["record_ordinal"], b["record_ordinal"], a["disk_ordinal"], b["disk_ordinal"])
        assert (r["start_qpc"], r["stop_qpc"], r["packet_first_ordinal"], r["reported_response_ticks"]) == (
            a["raw_timestamp"], b["raw_timestamp"], a["packet_first_ordinal"], b["response_ticks"])
        assert r["operation"] == COMPLETIONS[b["opcode"]][1] and int(r["elapsed_ticks"]) == int(b["raw_timestamp"])-int(a["raw_timestamp"])
    expected, gaps, amounts = [], {}, Counter()
    spans = {row: (int(a["raw_timestamp"]), int(b["raw_timestamp"])) for row, (a, b) in matched.items()}
    for lo, hi, state, x, y, ready in parts:
        # Partition this switch interval from all endpoints afresh, without carrying an active-request set.
        cuts = sorted({lo, hi, *(t for span in spans.values() for t in span if lo < t < hi)})
        for u, v in pairwise(cuts):
            active = sorted(row for row, (a, b) in spans.items() if a <= u < v <= b)
            if active:
                expected.append((str(u), str(v), state, x, y, ready["record_ordinal"] if ready else None, active))
                amounts[state] += v-u
        if state == "waiting_before_ready" and ready and hi == int(ready["raw_timestamp"]) < int(stop["raw_timestamp"]):
            for row, (_, b) in matched.items():
                at = int(b["raw_timestamp"])
                if lo <= at <= hi and x < b["record_ordinal"] < ready["record_ordinal"] < y:
                    gaps[row] = dict(switch_out_record=x, ready_record=ready["record_ordinal"], switch_in_record=y, gap_ticks=str(hi-at))
    keys = ("start_qpc", "stop_qpc", "state", "switch_start_record", "switch_stop_record", "ready_record", "table_rows")
    assert [tuple(o[k] for k in keys) for o in summary["overlaps"]] == expected
    assert all(r["following_ready_in_wait"] == gaps.get(row) for row, r in actual.items())
    assert all(int(summary[state+"_ticks"]) == amounts[state] for state in disk.STATES)
    assert int(summary["request_union_ticks"]) == sum(amounts.values())


def controls(report):
    result = report["result"]["disk_requests"]
    doc = result["sdk_query"]["page"]
    pages = result["native_pages"]
    common = report["pages"][0]["schedule"]["page"]
    window = common["activity_schedule"]

    def prepare(edit, native_edit=None):
        changed, native = deepcopy(doc), deepcopy(pages)
        edit(changed)
        if native_edit:
            native_edit(native)
        result, timeline = disk.prepare(dict(reader={"exit_code": 0}, page=changed), lambda cursor, n: native[cursor//128], common, window)
        assert timeline is None and result["summary"] is None
        return result["status"]

    assert prepare(lambda d: d.update(events=[], activities=[], selected_packets=0, matched_activities=0, matched_events=0)) == "inconsistent_disk_evidence"
    assert prepare(lambda d: d.update(packet_limit_hit=True)) == "disk_row_limit"
    assert prepare(lambda d: d.update(unassigned_events=1)) == "disk_events_unqualified"
    assert prepare(lambda d: d["clock"].update(lost_buffers=1)) == "disk_clock_or_loss_unqualified"
    assert prepare(lambda d: d.update(disk_events=8193)) == "disk_page_limit"
    assert prepare(lambda d: d.update(activities=[], matched_activities=0)) == "disk_table_pair_unconfirmed"
    assert prepare(lambda d: d.update(activities=[*d["activities"], dict(d["activities"][0], table_row=120)],
                                      matched_activities=3)) == "ambiguous_disk_activity"
    def empty_page(pages):
        native = pages[0]["page"]
        native.update(decoded_disk_records=0, disk_events=[], next_after=None)
        for op in native["operations"]:
            op.update(initiations=0, completions=0, transfer_bytes=None if op["operation"] == "flush" else "0",
                      longest_response_ties=0, first_longest_response=None)

    assert prepare(lambda d: d.update(events=[], activities=[], disk_events=0, activity_rows=0, selected_packets=0,
                                      matched_activities=0, matched_events=0), empty_page) == "disk_events_unobserved"
    assert prepare(lambda d: None, lambda p: p[0]["page"]["operations"][0].update(initiations=0)) == "inconsistent_disk_evidence"
    for edit in (lambda d: d.update(source_sha256="0"*64), lambda d: d["clock"].update(reference_ns="1"),
                 lambda d: d["events"][0].update(relative_ns="0"), lambda d: d["query_filter"].update(tid=1)):
        assert prepare(edit) == "inconsistent_disk_evidence"
    assert prepare(lambda d: None, lambda p: p[1]["page"].update(after=0)) == "inconsistent_disk_evidence"
    assert prepare(lambda d: None, lambda p: p[0]["page"].update(provider_guid="invalid")) == "inconsistent_disk_evidence"
    table = doc["activities"][0]
    history = [e for e in doc["events"] if e["packet_first_ordinal"] == table["packet_first_ordinal"]]
    a = next(e for e in history if e["relative_ns"] == table["start_ns"])
    b = next(e for e in history if e["relative_ns"] == table["stop_ns"])
    page, offset = divmod(b["disk_ordinal"]-1, 128)
    assert prepare(lambda d: None, lambda p: p[page]["page"]["disk_events"][offset].update(high_res_response_ticks="-1")) == "inconsistent_disk_evidence"
    for rows, code in (([b], "disk_initiation_missing"), ([a], "disk_completion_missing"),
                       ([a, a, b, b], "ambiguous_disk_packet_history"), ([a, dict(b, issuing_tid=1)], "disk_issuer_lifetime_unconfirmed")):
        try:
            disk.pairs(window, {table["packet_first_ordinal"]: rows}, {})
        except disk.Unavailable as exc:
            assert str(exc) == code
        else:
            raise AssertionError(code)
    for part in (report, result["summary"], result["summary"]["requests"][0], result["summary"]["overlaps"][0],
                 result["summary"]["requests"][0]["following_ready_in_wait"], doc, doc["clock"], doc["query_filter"], table, a):
        TDH["require_private"](part)
    limit_window = dict(start={"raw_timestamp": "0"}, stop={"raw_timestamp": "5"})
    concurrent = disk.DiskTimeline([dict(table_row=i+1, start_qpc="0", stop_qpc="5") for i in range(disk.LIMIT)], limit_window)
    try:
        for i in range(5):
            concurrent.piece(i, i+1, "on_cpu", 1, 2, None)
    except disk.Unavailable as exc:
        assert str(exc) == "disk_intersection_limit" and i == 4
    else:
        raise AssertionError("exceeded the intersection limit")


def whole_source(program, etl, rows, requests, bounds, common, native):
    table_rows = set()
    accepted = []
    overlap_checked = False
    for tid, pairs in requests.items():
        before, after = bounds[tid]
        assert before["payload_pid"] == after["payload_pid"]
        edges = [int(e["raw_timestamp"]) for e in rows if e["issuing_tid"] == tid]
        lo, hi = min(edges)-1, max(edges)+1
        def query(left, right):
            return call([program, etl, str(before["payload_pid"]), str(tid), str(left), str(right)], 0)

        doc = query(lo, hi)
        matched = check_sdk(doc, rows, requests)
        assert table_rows.isdisjoint(matched)
        table_rows.update(matched)
        window = dict(start=dict(header_process_id=before["payload_pid"], header_thread_id=tid, logger_id=before["logger_id"],
                                 raw_timestamp=str(lo)), stop=dict(raw_timestamp=str(hi)), thread_evidence=dict(before=before, after=after))
        def prepare(projection):
            return disk.prepare(dict(reader={"exit_code": 0}, page=projection), lambda cursor, n: native[cursor//128], common, window)

        if tid == 24156:
            # This thread has 18 completions after final rundown and a final initiation without a completion.
            packets, _ = disk.projection(doc, common, window)
            orphan = rows[-1]
            end_window = dict(window, start=dict(window["start"], raw_timestamp=str(int(orphan["raw_timestamp"])-1)))
            try:
                disk.pairs(end_window, packets, {})
            except disk.Unavailable as exc:
                assert str(exc) == "disk_completion_missing"
            else:
                raise AssertionError("final initiation received an endpoint")
            assert prepare(doc)[0]["status"] == "disk_issuer_lifetime_unconfirmed"
            hi = int(after["raw_timestamp"])-1
            window["stop"]["raw_timestamp"] = str(hi)
            doc = query(lo, hi)
            matched = check_sdk(doc, rows, requests)
        result, timeline = prepare(doc)
        assert timeline is not None, (tid, result["status"])
        assert {r["table_row"] for r in timeline.requests} == matched.keys()
        accepted.extend(timeline.requests)
        if tid == 15792:
            # Use a QPC interval strictly inside two real concurrent requests to exercise clipping and the union.
            spans = [(int(a["raw_timestamp"]), int(b["raw_timestamp"])) for a, b in pairs]
            left, right = next((max(a, c)+1, min(b, d)-1) for i, (a, b) in enumerate(spans) for c, d in spans[i+1:]
                               if min(b, d)-max(a, c) > 2)
            window["start"]["raw_timestamp"], window["stop"]["raw_timestamp"] = str(left), str(right)
            narrow = query(left, right)
            overlapping = check_sdk(narrow, rows, requests)
            result, concurrent = prepare(narrow)
            assert len(overlapping) >= 2 and concurrent is not None
            # A single test scheduler piece isolates the duration calculation from marker eligibility.
            concurrent.piece(left, right, "on_cpu", 1, 2, None)
            summary = concurrent.finish()
            assert int(summary["request_union_ticks"]) == right-left and sum(int(r["elapsed_ticks"]) for r in summary["requests"]) > right-left
            check_accounting(summary, overlapping, [(left, right, "on_cpu", 1, 2, None)], window["stop"])
            overlap_checked = True
    assert table_rows == set(range(1, 121)) and len(accepted) == 102 and overlap_checked
    print("TDH and SDK matched 120 disk activities; 102 pairs inside recorded issuer lifetimes", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "etl", "oracle", "adapter"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--cpu-adapter", type=Path)
    args = parser.parse_args()
    exe, etl, oracle, adapter = (p.resolve(strict=True) for p in (args.exe, args.etl, args.oracle, args.adapter))
    assert pin(etl) == PIN
    rows, requests = disk_records(oracle, etl)
    _, _, groups, _ = WAITS["SCHED"]["ACTIVITY"]["read_oracle"](oracle, etl)
    markers = {r["record_ordinal"]: r for group in groups.values() for r in group}
    _, _, _, bounds, ready, transitions = TDH["tdh"](oracle, etl)
    base = [sys.executable, "-B", WAITS["CLI"], "--exe", exe, "--exe-sha256", pin(exe), "--etl", etl, "--sha256", PIN]
    sdk = ["--disk-requests", adapter, pin(adapter)]
    first = next(iter(POSITIVES))
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for a, b in dict.fromkeys((*POSITIVES, *WAITS["WINDOWS"])):
            query = [*base, "--start", str(a), "--stop", str(b)]
            out = root / f"disk-{a}.json"
            receipt = call([*query, *sdk, "--output", out], 0)
            report = json.loads(out.read_bytes())
            result = report["result"]["disk_requests"]
            assert report["schema"] == "kn.etl_activity_waits.v3" and receipt["schema"] == "kn.etl_activity_waits_receipt.v3"
            assert receipt["disk_requests_status"] == result["status"] == "measured" and pin(out) == receipt["report_sha256"]
            check_native(result["native_pages"], rows)
            matched = check_sdk(result["sdk_query"]["page"], rows, requests)
            parts = scheduler_parts(markers[a], markers[b], bounds, ready, transitions)
            check_accounting(result["summary"], matched, parts, markers[b])
            counts = tuple(int(result["summary"][k]) for k in ("request_union_ticks", "waiting_before_ready_ticks"))
            assert counts == POSITIVES.get((a, b), (0, 0))
            print(a, b, len(matched), *counts, flush=True)
            if (a, b) == first:
                TDH["require_private"](receipt)
                controls(report)
                assert call([*query, *sdk, "--check-report", pin(out)], 0)["status"] == "matched"
                assert call([*query, *sdk, "--check-report", "0"*64], 1)["status"] == "mismatch"
                assert call([*query, *sdk, "--output", out], 2) is None and pin(out) == receipt["report_sha256"]
                assert call([*query, *sdk[:2], "0"*64, "--output", root / "bad-pin.json"], 2) is None
                small = root / "small.json"
                call([*query, *sdk, "--page-size", "2", "--output", small], 0)
                assert json.loads(small.read_bytes())["result"]["disk_requests"] == result
                if args.cpu_adapter:
                    cpu = args.cpu_adapter.resolve(strict=True)
                    combined = root / "combined.json"
                    options = [*sdk, "--traceprocessor", cpu, pin(cpu), "--interrupt-overlap"]
                    receipt = call([*query, *options, "--output", combined], 0)
                    both = json.loads(combined.read_bytes())["result"]
                    assert both["disk_requests"] == result and both["interrupt_overlap"]["status"] == "measured"
                    assert receipt["traceprocessor_status"] == "matched" and call([*query, *options, "--check-report", pin(combined)], 0)["status"] == "matched"
                (root / "wpt" / "Catalog").mkdir(parents=True)
                unpack(adapter, root, disk=True)
                whole_source(root / DISK_PROGRAM, etl, rows, requests, bounds, report["pages"][0]["schedule"]["page"], result["native_pages"])

        for i, (a, b) in enumerate(((726753, 731848), (1, 2))):
            out = root / f"ineligible-{i}.json"
            receipt = call([*base, "--start", str(a), "--stop", str(b), *sdk, "--output", out], 1)
            r = json.loads(out.read_bytes())["result"]
            assert receipt["disk_requests_status"] == "native_window_unavailable" and r["disk_requests"]["summary"] is None
            if i == 0:
                assert r["reason"] == "intervening_activity_boundary"
        common = json.loads((root / f"disk-{first[0]}.json").read_bytes())["pages"][0]["schedule"]["page"]
        source = etl.read_bytes()
        header = struct.pack("<qqII", 10_000_000, int(common["log_header"]["start_filetime"]), 1, 0)
        assert source[:512].count(header) == 1
        for offset, value in ((16, 2), (20, 1)):
            data = bytearray(source)
            struct.pack_into("<I", data, source[:512].index(header)+offset, value)
            etl_copy = root / "adjusted.etl"
            etl_copy.write_bytes(data)
            flags = list(base)
            flags[flags.index("--etl")+1], flags[flags.index("--sha256")+1] = etl_copy, pin(etl_copy)
            out = root / f"limited-{offset}.json"
            receipt = call([*flags, "--start", str(first[0]), "--stop", str(first[1]), *sdk, "--output", out], 1)
            assert receipt["disk_requests_status"] == "native_window_unavailable" and json.loads(out.read_bytes())["result"]["disk_requests"]["summary"] is None


if __name__ == "__main__":
    main()
