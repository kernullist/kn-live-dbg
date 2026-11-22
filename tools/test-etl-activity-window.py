"""Compare explicit activity windows to Windows event headers and TDH hard-fault properties."""
import argparse
from collections import defaultdict
import hashlib
from itertools import pairwise
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import tempfile
from uuid import UUID


HERE = Path(__file__).resolve().parent
CAP = runpy.run_path(str(HERE / "test-etl-capabilities.py"))
SIGNED = runpy.run_path(str(HERE / "test-etl-capture-statement.py"))
AUDIT = runpy.run_path(str(HERE / "validate-public-content.py"))
VERB = "--etl-hard-faults"


def read_oracle(oracle, path):
    out = subprocess.run([oracle, path, "--activities"], check=True, capture_output=True, timeout=240)
    groups, threads, faults = defaultdict(list), defaultdict(list), []
    nonclassic = 0
    for line in out.stdout.splitlines():
        row = json.loads(line)
        if "records_seen" in row:
            footer = row
        elif "initial_time_raw" in row:
            row["fault_ordinal"] = len(faults) + 1
            faults.append(row)
        elif "payload_pid" in row:
            threads[row["payload_tid"]].append(row)
        else:
            assert row.pop("record_kind") == "activity_boundary"
            nonclassic += int(not row["header_flags"] & 4)
            for name in ("provider_guid", "activity_id"):
                row[name] = str(UUID(row[name]))
            if (row["event_id"] and row["task"] and not row["header_flags"] & (4 | 128) and not row["event_property"] & 7 and
                    all(UUID(row[k]).int for k in ("provider_guid", "activity_id"))):
                groups[tuple(row[k] for k in ("provider_guid", "activity_id", "header_process_id", "channel", "task"))].append(row)
    footer["nonclassic_start_stop"] = nonclassic
    return footer, faults, groups, threads


def tick(row):
    return int(row["raw_timestamp"])


def lifetime(start, stop, threads):
    history = threads[start["header_thread_id"]]
    left = [e for e in history if e["record_ordinal"] < start["record_ordinal"]]
    right = [e for e in history if e["record_ordinal"] >= start["record_ordinal"]]
    if not left or not right:
        return None
    before, after = left[-1], right[0]
    if (before["opcode"] not in (1, 3) or after["opcode"] not in (2, 4) or stop["record_ordinal"] >= after["record_ordinal"] or
            before["payload_pid"] != after["payload_pid"] or before["payload_pid"] != start["header_process_id"] or
            not tick(before) < tick(start) < tick(stop) < tick(after) or
            any(e["logger_id"] != start["logger_id"] for e in history) or
            any((a["opcode"] % 2) == (b["opcode"] % 2) or tick(a) >= tick(b) for a, b in pairwise(history))):
        return None
    return before, after


def intersection(start, stop, faults):
    rows = []
    for f in faults:
        if f["faulting_thread_id"] != start["header_thread_id"]:
            continue
        lo = max(tick(start), int(f["initial_time_raw"]))
        hi = min(tick(stop), tick(f))
        if hi > lo:
            rows.append((f, lo, hi))
    # Sweep endpoint depth independently of fault completion or start order.
    changes = defaultdict(int)
    for _, lo, hi in rows:
        changes[lo] += 1
        changes[hi] -= 1
    covered, depth, last = 0, 0, tick(start)
    for point, delta in sorted(changes.items()):
        if depth:
            covered += point - last
        last, depth = point, depth + delta
    assert depth == 0
    return rows, covered


def private(row):
    text = "observation\n" + json.dumps(dict(reversed(list(row.items()))))[:-1]
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        assert any(hit["rule"] == "private-evidence-bundle" for hit in AUDIT["inspect"]("part.txt", text.encode(encoding)))


def selector(path, pin, start, stop):
    return [VERB, path, "--sha256", pin, "--activity-window", str(start), str(stop)]


def marker_pages(exe, path, pin, groups, footer, tid):
    ordered = sorted((e for events in groups.values() for e in events), key=lambda e: e["record_ordinal"])
    expected = [dict(marker_ordinal=i, event=row) for i, row in enumerate(ordered, 1)]
    for thread in (None, tid):
        args = [VERB, path, "--sha256", pin, "--activity-markers"]
        chosen = expected
        if thread is not None:
            args += ["--thread-id", str(thread)]
            chosen = [item for item in expected if item["event"]["header_thread_id"] == thread]
        for after in [*range(0, len(chosen), 128), len(chosen)]:
            flags = [*args, "--after", str(after), "--limit", "128"]
            raw = CAP["invoke"](exe, flags)
            page = json.loads(raw)
            assert page["schema"] == "kn.etl_activity_markers.v1" and page["status"] == "read"
            assert page["source_sha256"] == pin and page["records_seen"] == footer["records_seen"]
            assert page["decoded_activity_markers"] == len(expected) and page["excluded_start_stop_records"] == footer["nonclassic_start_stop"] - len(expected)
            assert page["thread_filter"] == thread and page["matched_markers"] == len(chosen) and page["after"] == after
            assert page["markers"] == chosen[after:after+128]
            assert page["next_after"] == (after+128 if after+128 < len(chosen) else None)
            if after == 0:
                receipt = json.loads(CAP["invoke"](exe, [*flags, "--check-page", hashlib.sha256(raw).hexdigest()]))
                assert receipt["status"] == "matched" and receipt["source_kind"] == "activity_marker" and receipt["thread_filter"] == thread
                private(page["markers"][0])
        past = json.loads(CAP["invoke"](exe, [*args, "--after", str(len(chosen)+1)], 1))
        assert past["status"] == "cursor_out_of_range"
    print(f"{len(expected)} keyed boundaries matched in source order, including the filtered thread pages")


def check_page(exe, args, code=0):
    raw = CAP["invoke"](exe, args, code)
    doc = json.loads(raw)
    assert doc["schema"] == "kn.etl_hard_faults.v3" and doc["source_sha256"] == args[3]
    assert doc["status"] == ("partial" if code else "read") and doc["next_after"] is None
    assert all(doc["qualification"][k] is None for k in ("logical_task_identity", "wait_cause", "disk_request", "critical_path"))
    return doc, hashlib.sha256(raw).hexdigest()


def compare(exe, path, pin, footer, faults, groups, threads):
    positive, zero = [], []
    for group in groups.values():
        for a, b in pairwise(group):
            if (a["opcode"], b["opcode"]) != (1, 2) or a["header_thread_id"] != b["header_thread_id"] or a["logger_id"] != b["logger_id"]:
                continue
            bracket = lifetime(a, b, threads)
            if not bracket:
                continue
            rows, covered = intersection(a, b, faults)
            case = (a, b, bracket, len(group), rows, covered)
            if rows:
                positive.append(case)
            elif len(zero) < 2:
                zero.append(case)
    assert positive and zero, "use a clean QPC capture with overlapping faults and measured empty windows"
    for a, b, (before, after), count, rows, covered in positive + zero:
        args = selector(path, pin, a["record_ordinal"], b["record_ordinal"])
        doc, digest = check_page(exe, args)
        w = doc["activity_window"]
        assert (doc["records_seen"], doc["decoded_hard_faults"]) == (footer["records_seen"], len(faults))
        assert w["start"] == a and w["stop"] == b and w["status"] == "measured"
        assert w["process_key_boundaries"] == count and w["intervening_boundaries"] == 0
        assert w["decoded_faults_on_start_logger"] > 0 and w["unassigned_activity_boundaries"] == 0
        assert int(w["window_ticks"]) == tick(b) - tick(a) and int(w["fault_union_ticks"]) == covered
        pair = w["thread_evidence"]
        assert (pair["before"]["record_ordinal"], pair["after"]["record_ordinal"]) == (before["record_ordinal"], after["record_ordinal"])
        assert pair["paired_record_pid"] == a["header_process_id"]
        assert w["candidate_faults"] == len(rows) == len(w["overlaps"]) == len(doc["hard_faults"])
        for (f, lo, hi), edge, native in zip(rows, w["overlaps"], doc["hard_faults"], strict=True):
            assert edge == dict(record_ordinal=f["record_ordinal"], fault_ordinal=f["fault_ordinal"],
                                overlap_start_raw=str(lo), overlap_end_raw=str(hi), overlap_ticks=str(hi-lo))
            assert all(f[k] == native[k] for k in ("record_ordinal", "fault_ordinal", "initial_time_raw", "raw_timestamp",
                                                    "header_thread_id", "faulting_thread_id", "byte_count", "read_offset"))
        if a == positive[0][0]:
            receipt = json.loads(CAP["invoke"](exe, [*args, "--check-page", digest]))
            assert receipt["status"] == "matched" and receipt["page_bytes_match"]
            assert (receipt["requested_start_record"], receipt["requested_stop_record"]) == (a["record_ordinal"], b["record_ordinal"])
            for part in (receipt, w, w["start"], w["stop"], doc["qualification"], *w["overlaps"]):
                private(part)
    print(f"{len(positive)} nonempty and {len(zero)} empty windows matched, {sum(len(c[4]) for c in positive)} fault intersections")
    return positive[0][:2], zero[0][:2]


def controls(exe, path, pin, folder, footer, groups, positive, zero, openssl):
    call = CAP["invoke"]
    a, b = positive
    x, y = a["record_ordinal"], b["record_ordinal"]
    base = selector(path, pin, x, y)
    doc, digest = check_page(exe, base)
    key = tuple(a[k] for k in ("provider_guid", "activity_id", "header_process_id", "channel", "task"))
    later = next(e for e in groups[key] if e["opcode"] == 2 and e["header_thread_id"] == a["header_thread_id"] and e["record_ordinal"] > y)
    bad = [(1, y, "invalid_start_marker"), (x, x + 1, "invalid_stop_marker"), (x, later["record_ordinal"], "intervening_activity_boundary")]
    other = next(e for k, g in groups.items() if k != key for e in g if e["opcode"] == 2 and e["record_ordinal"] > x)
    bad.append((x, other["record_ordinal"], "activity_key_mismatch"))
    cross = next((e for e in groups[key] if e["opcode"] == 2 and e["header_thread_id"] != a["header_thread_id"] and e["record_ordinal"] > x), None)
    if cross:
        bad.append((x, cross["record_ordinal"], "thread_scope_unqualified"))
    for start, stop, reason in bad:
        data, _ = check_page(exe, selector(path, pin, start, stop))
        window = data["activity_window"]
        assert window["status"] == reason and window["fault_union_ticks"] is window["window_ticks"] is None
    others = selector(path, pin, zero[0]["record_ordinal"], zero[1]["record_ordinal"])
    mismatch = json.loads(call(exe, [*others, "--check-page", digest], 1))
    assert mismatch["status"] == "page_mismatch" and not mismatch["page_bytes_match"]
    for args in ([*base[:4], "--activity-window", "0", "2"], [*base[:4], "--activity-window", "2", "2"],
                 [*base[:4], "--activity-window", "3", "2"], [*base[:4], "--activity-window", "01", "2"],
                 [*base[:4], "--activity-window", "1", "2000001"], base[:-1], [*base, "--after", "0"], [*base, "--limit", "1"],
                 [*base, "--schedule-of", "1"], [*base[:4], "--schedule-of", "1", *base[4:]], [*base, *base[4:]],
                 ["--etl-switches", *base[1:]], [*base, "--activity-markers"], [*base[:4], "--activity-markers", "--schedule-of", "1"],
                 [*base[:4], "--activity-markers", "--activity-markers"], [*base[:4], "--thread-id", "1"]):
        assert not call(exe, args, 2)
    missing = selector(path, pin, x, footer["records_seen"] + 1)
    for flags in ([], ["--check-page", digest]):
        absent = json.loads(call(exe, [*missing, *flags], 1))
        assert absent["status"] == "activity_record_not_observed" and absent["source_status"] == "read"
        assert absent["requested_start_record"] == x and absent["requested_stop_record"] == footer["records_seen"] + 1
    raw = path.read_bytes()
    signature = struct.pack("<qqII", int(doc["clock"]["header_perf_frequency"]), int(doc["log_header"]["start_filetime"]), 1, 0)
    assert raw[:512].count(signature) == 1
    pos = raw[:512].index(signature)
    signer = SIGNED["Signer"](openssl, folder / "private") if openssl else None

    def signed(input_path, args, page_hash, rc):
        if signer:
            statement = folder / "capture.jws"
            statement.write_bytes(signer.token(SIGNED["statement"](input_path)))
            receipt = json.loads(call(exe, [*args, "--check-page", page_hash, "--capture-statement", statement, "archive_witness", signer.point], rc))
            assert receipt["status"] == "matched" and receipt["page_bytes_match"]
            assert receipt["requested_start_record"] == x and receipt["requested_stop_record"] == y
            assert receipt["capture_statement"]["bound_to_replayed_page"] and receipt["source_status"] == ("partial" if rc else "read")
            markers = [*args[:4], "--activity-markers", "--thread-id", str(a["header_thread_id"]), "--limit", "1"]
            marker_hash = hashlib.sha256(call(exe, markers, rc)).hexdigest()
            proof = json.loads(call(exe, [*markers, "--check-page", marker_hash, "--capture-statement", statement, "archive_witness", signer.point], rc))
            assert proof["status"] == "matched" and proof["source_kind"] == "activity_marker"
            assert proof["thread_filter"] == a["header_thread_id"] and proof["capture_statement"]["bound_to_replayed_page"]

    signed(path, base, digest, 0)
    for delta, fmt, value in ((0, "q", 0), (16, "I", 2), (16, "I", 3), (20, "I", 2)):
        copy = bytearray(raw)
        struct.pack_into("<" + fmt, copy, pos + delta, value)
        local = folder / "control.etl"
        local.write_bytes(copy)
        args = selector(local, hashlib.sha256(copy).hexdigest(), x, y)
        loss = delta == 20
        changed, page_hash = check_page(exe, args, int(loss))
        w = changed["activity_window"]
        assert w["status"] == ("coverage_unqualified" if loss else "clock_unqualified")
        assert w["fault_union_ticks"] is w["window_ticks"] is w["candidate_faults"] is None
        if loss:
            signed(local, args, page_hash, 1)
            missing = json.loads(call(exe, selector(local, args[3], x, footer["records_seen"] + 1), 1))
            assert missing["status"] == "activity_record_not_observed" and missing["source_status"] == "partial"
            alias = folder / "other-name.bin"
            os.link(local, alias)
            with alias.open("ab", buffering=0) as sink:
                call(exe, args, 2, stdout=sink)
            assert CAP["sha256"](local) == args[3]
    assert CAP["sha256"](path) == pin


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "oracle", "etl"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--check-controls", action="store_true")
    p.add_argument("--openssl", type=Path, help="also check signed page replay with --check-controls")
    opt = p.parse_args()
    exe, oracle, path = (v.resolve(strict=True) for v in (opt.exe, opt.oracle, opt.etl))
    pin = opt.sha256.lower()
    assert CAP["sha256"](path) == pin
    footer, faults, groups, threads = read_oracle(oracle, path)
    assert footer["clock_type"] == 1 and footer["frequency"] > 0
    with tempfile.TemporaryDirectory(prefix="kn-activity-") as tmp:
        folder = Path(tmp)
        total, families = CAP["windows_counts"](path, folder)
        assert (total, families["hard_fault"]) == (footer["records_seen"], len(faults))
        positive, zero = compare(exe, path, pin, footer, faults, groups, threads)
        marker_pages(exe, path, pin, groups, footer, positive[0]["header_thread_id"])
        if opt.check_controls:
            controls(exe, path, pin, folder, footer, groups, positive, zero, opt.openssl)


if __name__ == "__main__":
    main()
