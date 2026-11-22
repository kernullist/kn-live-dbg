"""Check activity scheduling against Windows event headers and independent TDH scheduler properties."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import runpy
import struct
import tempfile


HERE = Path(__file__).resolve().parent
ACTIVITY = runpy.run_path(str(HERE / "test-etl-activity-window.py"))
SCHED = runpy.run_path(str(HERE / "test-etl-fault-schedule.py"))
CAP = ACTIVITY["CAP"]
VERB = "--etl-switches"
TIMES = ("on_cpu_ticks", "off_cpu_ticks", "before_ready_ticks", "after_ready_ticks",
         "waiting_before_ready_ticks", "unclassified_off_cpu_ticks")


def select(path, pin, start, stop):
    return [VERB, path, "--sha256", pin, "--schedule-activity", str(start), str(stop)]


def read(exe, flags, code=0):
    raw = CAP["invoke"](exe, flags, code)
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def verify(exe, path, pin, start, stop, footer, switches, bounds, ready, transitions):
    tid = start["header_thread_id"]
    first, last = start["record_ordinal"], stop["record_ordinal"]
    flags = select(path, pin, first, last)
    lo, hi = int(start["raw_timestamp"]), int(stop["raw_timestamp"])
    evidence = SCHED["intervals"](tid, first, lo, hi, bounds[tid], transitions[tid])
    before, after, expected = evidence
    assert before["payload_pid"] == after["payload_pid"] == start["header_process_id"] == stop["header_process_id"]
    assert last < after["record_ordinal"]
    cursor, observed, first_page = 0, [], None
    while True:
        query = [*flags, "--after", str(cursor), "--limit", "7"]
        doc, digest = read(exe, query)
        assert doc["schema"] == "kn.etl_switches.v4" and doc["source_sha256"] == pin and doc["after"] == cursor
        assert (doc["requested_start_record"], doc["requested_stop_record"], doc["interval_page_limit"]) == (first, last, 7)
        assert doc["records_seen"] == footer["records_seen"] and doc["decoded_switches"] == len(switches)
        assert doc["clock"]["raw_type"] == 1 and int(doc["clock"]["header_perf_frequency"]) == footer["frequency"]
        s = doc["activity_schedule"]
        assert s["start"] == start and s["stop"] == stop and int(s["window_ticks"]) == hi-lo
        assert s["ready_records"] == sum(map(len, ready.values())) and s["thread_boundaries"] == sum(map(len, bounds.values()))
        assert s["unassigned_ready_records"] == len(ready[0]) + len(ready[2**32-1]) == 0
        assert s["intersecting_intervals"] == len(expected) and len(s["intervals"]) == min(len(expected)-cursor, 7)
        summary = {k: v for k, v in s.items() if k != "intervals"}
        if first_page is None:
            first_page = summary
            replay, _ = read(exe, [*query, "--check-page", digest])
            assert replay["status"] == "matched" and replay["source_kind"] == "context_switch" and replay["page_bytes_match"]
            assert (replay["requested_start_record"], replay["requested_stop_record"]) == (first, last)
            for piece in (doc, s, s["start"], s["thread_evidence"], doc["qualification"], replay):
                ACTIVITY["private"](piece)
        assert first_page == summary
        observed.extend(s["intervals"])
        cursor += len(s["intervals"])
        if cursor == len(expected):
            assert doc["next_after"] is None
            break
        assert doc["next_after"] == cursor
    SCHED["verify_intervals"](dict(first_page, intervals=observed), tid, evidence, ready[tid], Counter())
    portions = Counter()
    for running, left, right, a, b in expected:
        if running:
            continue
        portions["off"] += 1
        marks = [e for e in ready[tid] if left["record_ordinal"] < e["record_ordinal"] < right["record_ordinal"]]
        _, tick = SCHED["readiness"](marks, left, right)
        if tick is None:
            portions["unknown"] += b-a
            continue
        portions["splits"] += 1
        pre = max(0, min(tick, b)-a)
        portions["before"] += pre
        portions["after"] += b-a-pre
        if left["old_state"] == 5:
            portions["waiting"] += pre
    assert (s["off_cpu_intervals"], s["split_off_cpu_intervals"]) == (portions["off"], portions["splits"])
    assert tuple(int(s[k]) for k in TIMES[2:]) == tuple(portions[k] for k in ("before", "after", "waiting", "unknown"))
    assert int(s["on_cpu_ticks"]) + int(s["off_cpu_ticks"]) == hi-lo
    assert portions["before"] + portions["after"] + portions["unknown"] == int(s["off_cpu_ticks"])
    if len(observed) > 128:
        full, _ = read(exe, [*flags, "--limit", "128"])
        tail, _ = read(exe, [*flags, "--limit", "128", "--after", "128"])
        assert full["next_after"] == 128 and full["activity_schedule"]["intervals"] == observed[:128]
        assert tail["activity_schedule"]["intervals"] == observed[128:256]
        assert all({k: v for k, v in page["activity_schedule"].items() if k != "intervals"} == first_page for page in (full, tail))
    terminal, _ = read(exe, [*flags, "--after", str(cursor)])
    assert terminal["next_after"] is None and not terminal["activity_schedule"]["intervals"]
    rejected, _ = read(exe, [*flags, "--after", str(cursor+1)], 1)
    assert rejected["status"] == "cursor_out_of_range" and rejected["after"] == cursor+1
    assert (rejected["requested_start_record"], rejected["requested_stop_record"], rejected["interval_page_limit"]) == (first, last, 64)
    print(first, last, len(expected), {k: s[k] for k in TIMES})
    return flags


def controls(exe, path, flags, folder, openssl):
    doc, digest = read(exe, flags)
    x, y = map(int, flags[-2:])
    for mode in (["--thread-id", "1"], ["--intervals"], ["--capture-settings"], flags[-3:]):
        for args in ([*flags, *mode], [*flags[:4], *mode, *flags[4:]]):
            assert not CAP["invoke"](exe, args, 2)
    for pair in (["0", "1"], ["02", "3"], ["3", "3"], ["3", "2"], ["1", "2000001"], ["2"]):
        assert not CAP["invoke"](exe, [*flags[:-2], *pair], 2)
    assert not CAP["invoke"](exe, ["--etl-hard-faults", *flags[1:]], 2)
    assert read(exe, [*flags, "--check-page", "0"*64], 1)[0]["status"] == "page_mismatch"
    other, _ = read(exe, [*flags[:-2], "1", str(y)])
    assert other["activity_schedule"]["status"] == "invalid_start_marker"
    assert all(other["activity_schedule"][k] is None for k in (*TIMES, "window_ticks"))
    paged, _ = read(exe, [*flags[:-2], "1", str(y), "--after", "1"])
    assert paged["activity_schedule"]["status"] == other["activity_schedule"]["status"]
    absent, _ = read(exe, [*flags[:-2], str(x), str(doc["records_seen"]+1), "--after", "1", "--limit", "5"], 1)
    assert absent["status"] == "activity_record_not_observed" and (absent["after"], absent["interval_page_limit"]) == (1, 5)
    source = path.read_bytes()
    hdr = struct.pack("<qqII", int(doc["clock"]["header_perf_frequency"]), int(doc["log_header"]["start_filetime"]), 1, 0)
    assert source[:512].count(hdr) == 1
    pos = source[:512].index(hdr)
    sign = ACTIVITY["SIGNED"]
    signer = sign["Signer"](openssl, folder / "keys") if openssl else None
    def signed(input_path, args, page_hash, code):
        if signer:
            statement = folder / "capture.jws"
            statement.write_bytes(signer.token(sign["statement"](input_path)))
            result, _ = read(exe, [*args, "--check-page", page_hash, "--capture-statement", statement, "archive_witness", signer.point], code)
            assert result["capture_statement"]["bound_to_replayed_page"] and result["page_bytes_match"]
    signed(path, flags, digest, 0)
    for delta, fmt, value, reason in ((0, "<q", 0, "clock_unqualified"), (16, "<I", 2, "clock_unqualified"),
                                     (16, "<I", 3, "clock_unqualified"), (20, "<I", 1, "coverage_unqualified")):
        changed = bytearray(source)
        struct.pack_into(fmt, changed, pos+delta, value)
        test = folder/"header.etl"
        test.write_bytes(changed)
        query = select(test, hashlib.sha256(changed).hexdigest(), x, y)
        code = int(delta == 20)
        altered, expected = read(exe, query, code)
        s = altered["activity_schedule"]
        assert s["status"] == reason and all(s[k] is None for k in (*TIMES, "window_ticks"))
        assert altered["status"] == ("partial" if code else "read") and altered["decoded_switches"] == doc["decoded_switches"]
        if code:
            signed(test, query, expected, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("--exe", "--oracle", "--etl"):
        parser.add_argument(flag, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--window", type=int, nargs=2, action="append", required=True, metavar=("START", "STOP"))
    parser.add_argument("--no-switches", nargs=4, action="append", default=[], metavar=("ETL", "SHA256", "START", "STOP"))
    parser.add_argument("--check-controls", action="store_true")
    parser.add_argument("--openssl", type=Path)
    args = parser.parse_args()
    path = args.etl.resolve(strict=True)
    assert CAP["sha256"](path) == args.sha256.lower()
    marker_footer, _, groups, threads = ACTIVITY["read_oracle"](args.oracle, path)
    footer, _, switches, bounds, ready, transitions = SCHED["tdh"](args.oracle, path)
    assert footer["records_seen"] == marker_footer["records_seen"] and footer["frequency"] == marker_footer["frequency"]
    by_record = {r["record_ordinal"]: r for rows in groups.values() for r in rows}
    first = None
    for x, y in args.window:
        start, stop = by_record[x], by_record[y]
        assert (start["opcode"], stop["opcode"]) == (1, 2) and ACTIVITY["lifetime"](start, stop, threads)
        group = groups[tuple(start[k] for k in ("provider_guid", "activity_id", "header_process_id", "channel", "task"))]
        assert group[group.index(start)+1] == stop
        flags = verify(args.exe, path, args.sha256.lower(), start, stop, footer, switches, bounds, ready, transitions)
        if first is None:
            first = flags
    if args.check_controls:
        with tempfile.TemporaryDirectory() as folder:
            controls(args.exe, path, first, Path(folder), args.openssl)
    for name, pin, x, y in args.no_switches:
        original = Path(name).resolve(strict=True)
        assert CAP["sha256"](original) == pin.lower()
        query = select(original, pin, x, y)
        page, _ = read(args.exe, query)
        markers, _ = read(args.exe, ACTIVITY["selector"](original, pin, x, y))
        s, w = page["activity_schedule"], markers["activity_window"]
        assert page["decoded_switches"] == 0 and s["status"] == "no_switch_records"
        assert s["start"] == w["start"] and s["stop"] == w["stop"] and s["window_ticks"] == w["window_ticks"]
        assert int(s["window_ticks"]) > 0 and all(s[k] is None for k in TIMES)
    assert CAP["sha256"](path) == args.sha256.lower()


if __name__ == "__main__":
    main()
