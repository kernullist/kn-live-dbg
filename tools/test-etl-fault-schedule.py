"""Compare completed hard-fault windows with independent Windows TDH scheduler properties."""
import argparse
from collections import Counter, defaultdict
import hashlib
from itertools import pairwise
import json
from pathlib import Path
import runpy
import struct
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
CAP = runpy.run_path(str(HERE / "test-etl-capabilities.py"))
AUDIT = runpy.run_path(str(HERE / "validate-public-content.py"))
COMMAND = "--etl-hard-faults"


def require_private(row):
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        text = "log\n" + json.dumps(dict(reversed(list(row.items()))))[:-1]
        hits = AUDIT["inspect"]("part.txt", text.encode(encoding))
        assert any(h["rule"] == "private-evidence-bundle" for h in hits), tuple(row)


def tdh(oracle, path):
    p = subprocess.run([oracle, path, "--scheduler"], check=True, capture_output=True, timeout=240)
    switches, faults = [], []
    lifetimes, ready, transitions = defaultdict(list), defaultdict(list), defaultdict(list)
    last_cpu = {}
    for line in p.stdout.splitlines():
        row = json.loads(line)
        if "records_seen" in row:
            footer = row
        elif "faulting_thread_id" in row:
            faults.append(row)
        elif row["opcode"] == 36:
            switches.append(row)
            row["switch_ordinal"] = len(switches)
            cpu = row["cpu"]
            row["previous_on_cpu"] = last_cpu.get(cpu)
            last_cpu[cpu] = row["record_ordinal"]
            transitions[row["old_thread_id"]].append(("out", row))
            transitions[row["new_thread_id"]].append(("in", row))
        elif row["opcode"] == 50:
            ready[row["payload_tid"]].append(row)
        else:
            lifetimes[row["payload_tid"]].append(row)
    return footer, faults, switches, lifetimes, ready, transitions


def source_fields(actual, expected, names):
    assert all(actual[k] == expected[k] for k in names), (expected["record_ordinal"], names)


def intervals(fault, bounds, transitions):
    tid, record = fault["faulting_thread_id"], fault["record_ordinal"]
    lo, hi = int(fault["initial_time_raw"]), int(fault["raw_timestamp"])
    before = max((r for r in bounds if r["record_ordinal"] < record), key=lambda r: r["record_ordinal"])
    after = min((r for r in bounds if r["record_ordinal"] > record), key=lambda r: r["record_ordinal"])
    assert before["opcode"] in (1, 3) and after["opcode"] in (2, 4) and before["payload_pid"] == after["payload_pid"]
    assert int(before["raw_timestamp"]) < lo < hi < int(after["raw_timestamp"])
    points = [(role, e) for role, e in transitions if before["record_ordinal"] < e["record_ordinal"] < after["record_ordinal"]]
    expected = []
    for (role, start), (next_role, end) in pairwise(points):
        a, b = max(int(start["raw_timestamp"]), lo), min(int(end["raw_timestamp"]), hi)
        if a >= b:
            continue
        assert start["logger_id"] == end["logger_id"] == before["logger_id"] == after["logger_id"]
        assert role != next_role
        if role == "in":
            assert start["new_thread_id"] == end["old_thread_id"] == tid
            assert start["cpu"] == end["cpu"] and end["previous_on_cpu"] == start["record_ordinal"]
        expected.append((role == "in", start, end, a, b))
    assert expected and expected[0][3] == lo and expected[-1][4] == hi
    assert all(left[4] == right[3] for left, right in pairwise(expected))
    return before, after, expected


def verify_window(schedule, fault, bounds, transitions, ready, tally):
    before, after, expected = intervals(fault, bounds, transitions)
    pair = schedule["thread_evidence"]
    assert pair["paired_record_pid"] == before["payload_pid"]
    assert pair["relation"] == ("start_end" if (before["opcode"], after["opcode"]) == (1, 2) else "rundown_bracket")
    base = ("record_ordinal", "raw_timestamp", "logger_id")
    for name, point in (("before", before), ("after", after)):
        source_fields(pair[name], point, (*base, "payload_tid", "payload_pid", "opcode"))
    assert schedule["status"] == "covered" and schedule["intersecting_intervals"] == len(expected)
    assert len(schedule["intervals"]) == len(expected) <= schedule["interval_limit"]
    for native, (running, start, end, a, b) in zip(schedule["intervals"], expected, strict=True):
        assert (int(native["overlap_start_raw"]), int(native["overlap_end_raw"]), int(native["overlap_ticks"])) == (a, b, b - a)
        assert native["relation"] == ("running_on_cpu" if running else "off_cpu")
        for name, row, outgoing in (("start", start, not running), ("end", end, running)):
            edge = native[name]
            source_fields(edge, row, (*base, "cpu", "opcode", "version", "switch_ordinal"))
            assert edge["payload_tid"] == fault["faulting_thread_id"] and edge["kind"] == ("switch_out" if outgoing else "switch_in")
            if outgoing:
                source_fields(edge, row, ("old_state", "old_wait_reason"))
        tally["intervals"] += 1
        if running:
            assert "readiness" not in native
            continue
        r = native["readiness"]
        between = [p for p in ready if start["record_ordinal"] < p["record_ordinal"] < end["record_ordinal"]]
        assert r["ready_records"] == len(between)
        dispatchable = [p for p in between if p["ready_flags"] in (0, 1)]
        assert r["dispatchable_records"] == len(dispatchable)
        for name, point in (("first_ready", between[0] if between else None), ("last_ready", between[-1] if len(between) > 1 else None)):
            if point:
                source_fields(r[name], point, (*base, "cpu", "payload_tid", "ready_flags"))
            else:
                assert r[name] is None
        if not between:
            assert r["relation"] == "ready_unobserved" and r["before_ready_ticks"] is r["after_ready_ticks"] is None
        else:
            # The complete reference capture contains a single dispatchable witness per split.
            assert len(dispatchable) == 1 and between[-1] == dispatchable[0]
            assert all(p["logger_id"] == start["logger_id"] for p in between)
            pivot = max(a, min(b, int(dispatchable[0]["raw_timestamp"])))
            assert r["relation"] == ("waiting_ready_switch_in" if start["old_state"] == 5 else "ready_switch_in")
            assert (int(r["before_ready_ticks"]), int(r["after_ready_ticks"])) == (pivot - a, b - pivot)
        tally[r["relation"]] += 1
    for running, name in ((True, "on_cpu_ticks"), (False, "off_cpu_ticks")):
        assert int(schedule[name]) == sum(b - a for on, _, _, a, b in expected if on == running)


def controls(exe, path, pin, folder):
    call = CAP["invoke"]
    base = [COMMAND, path, "--sha256", pin]
    for opts in (["0"], ["01"], ["-1"], ["2000001"], [], ["1", "--schedule-of", "1"],
                 ["1", "--after", "0"], ["1", "--limit", "1"]):
        assert not call(exe, [*base, "--schedule-of", *opts], 2)
    for opts in (["--limit", "1"], ["--after", "0"]):
        assert not call(exe, [*base, *opts, "--schedule-of", "1"], 2)
    for command in ("--etl-profile", "--etl-switches", "--etl-disk-io"):
        assert not call(exe, [command, *base[1:], "--schedule-of", "1"], 2)
    page = json.loads(call(exe, [*base, "--schedule-of", "1"]))
    h = page["log_header"]
    raw = path.read_bytes()
    sig = struct.pack("<qqII", int(page["clock"]["header_perf_frequency"]), int(h["start_filetime"]), 1, 0)
    assert raw[:512].count(sig) == 1
    offset = raw[:512].index(sig)
    target = folder / "clock-control.etl"
    for delta, fmt, value in ((0, "q", 0), (16, "I", 2), (16, "I", 3), (20, "I", 2)):
        altered = bytearray(raw)
        struct.pack_into("<" + fmt, altered, offset + delta, value)
        target.write_bytes(altered)
        args = [COMMAND, target, "--sha256", hashlib.sha256(altered).hexdigest(), "--schedule-of"]
        loss = delta == 20
        doc = json.loads(call(exe, [*args, "1"], int(loss)))
        s = doc["fault_schedule"]
        assert s["on_cpu_ticks"] is s["off_cpu_ticks"] is None and all(i["overlap_ticks"] is None for i in s["intervals"])
        assert s["status"] == ("coverage_unqualified" if loss else "clock_unqualified")
        assert doc["decoded_hard_faults"] == page["decoded_hard_faults"]
        absent = json.loads(call(exe, [*args, str(doc["decoded_hard_faults"] + 1)], 1))
        assert absent["status"] == "fault_not_observed" and absent["source_status"] == ("partial" if loss else "read")
        require_private(absent)
    assert CAP["sha256"](path) == pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("--exe", "--oracle", "--etl"):
        parser.add_argument(flag, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--check-controls", action="store_true")
    opt = parser.parse_args()
    exe, oracle, path = (p.resolve(strict=True) for p in (opt.exe, opt.oracle, opt.etl))
    pin = opt.sha256.lower()
    assert CAP["sha256"](path) == pin
    footer, faults, switches, boundaries, ready, transitions = tdh(oracle, path)
    assert footer["clock_type"] == 1 and footer["frequency"] > 0 and faults and switches
    with tempfile.TemporaryDirectory(prefix="kn-fault-schedule-") as folder:
        total, families = CAP["windows_counts"](path, Path(folder))
        assert (total, families["hard_fault"], families["context_switch"]) == (footer["records_seen"], len(faults), len(switches))
        tally = Counter()
        for ordinal, fault in enumerate(faults, 1):
            args = [COMMAND, path, "--sha256", pin, "--schedule-of", str(ordinal)]
            raw = CAP["invoke"](exe, args)
            doc = json.loads(raw)
            assert doc["schema"] == "kn.etl_hard_faults.v2" and doc["source_sha256"] == pin and doc["status"] == "read"
            assert doc["records_seen"] == total and doc["decoded_hard_faults"] == len(faults) and doc["next_after"] is None
            assert len(doc["hard_faults"]) == 1 and doc["hard_faults"][0]["fault_ordinal"] == ordinal
            source_fields(doc["hard_faults"][0], fault, ("record_ordinal", "raw_timestamp", "initial_time_raw", "faulting_thread_id", "header_thread_id", "byte_count"))
            qualification = doc["qualification"]
            assert qualification["evidence"] == "reported_hard_fault_schedule_overlap"
            assert all(qualification[k] is None for k in ("authenticated_thread_lifetime", "wait_cause", "critical_path", "disk_request"))
            s = doc["fault_schedule"]
            assert s["requested_fault_ordinal"] == ordinal and s["decoded_switches"] == len(switches)
            assert s["thread_boundaries"] == sum(map(len, boundaries.values())) and s["ready_records"] == sum(map(len, ready.values()))
            tid = fault["faulting_thread_id"]
            verify_window(s, fault, boundaries[tid], transitions[tid], ready[tid], tally)
            if ordinal == 1:
                digest = hashlib.sha256(raw).hexdigest()
                receipt = json.loads(CAP["invoke"](exe, [*args, "--check-page", digest]))
                assert receipt["requested_fault_ordinal"] == ordinal and receipt["status"] == "matched" and receipt["page_bytes_match"]
                require_private(receipt)
                if len(faults) > 1:
                    mismatch = json.loads(CAP["invoke"](exe, [*args[:-1], "2", "--check-page", digest], 1))
                    assert mismatch["requested_fault_ordinal"] == 2 and mismatch["status"] == "page_mismatch"
                for item in (s, *s["intervals"], *(r["readiness"] for r in s["intervals"] if "readiness" in r),
                             switches[0], next(iter(ready.values()))[0], next(iter(boundaries.values()))[0]):
                    require_private(item)
        if opt.check_controls:
            controls(exe, path, pin, Path(folder))
    print(f"{len(faults)} faults matched TDH, {dict(tally)}")


if __name__ == "__main__":
    main()
