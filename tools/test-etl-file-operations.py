"""Corroborate enclosing FileIo generations in the public TaskbarLatency recording."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import zipfile

import etl_disk_waits
import etl_file_operations
from etl_traceprocessor import DISK_PROGRAM, FILE_RECORD_PROGRAM, unpack

HERE = Path(__file__).resolve().parent
DISK = runpy.run_path(str(HERE / "test-etl-disk-waits.py"))
WAITS, TDH, PIN, call, pin = (DISK[k] for k in ("WAITS", "TDH", "PIN", "call", "pin"))
# Source slices include records from other I/O and threads. The oracle also decodes those.
WINDOWS = {(339732, 374019): (373160, 373290), (397312, 398477): (397435, 398380),
           (418372, 418976): (418370, 418400), (451991, 452304): (452050, 452140)}
EXPECTED = {42: 114825, 46: 114826, 52: 114827, 53: 114828, 55: 114829, 56: 114851}


def compare_source(oracle, etl, span, tid, disk, result):
    p = subprocess.run([oracle, etl, "--file-window", *map(str, span)], check=True, capture_output=True, timeout=120)
    *events, footer = [json.loads(line) for line in p.stdout.splitlines()]
    assert footer["records_seen"] == 1093447 and footer["frequency"] == 10000000
    TDH["require_private"](events[0])
    original = {r["record"]: r for r in events}
    pending, files = {}, []
    for r in events:
        if r["op"] in (67, 68, 73):
            assert r["packet"] not in pending
            pending[r["packet"]] = r
        elif r["op"] == 76 and r["packet"] in pending:
            files.append((pending.pop(r["packet"]), r))
    summary = result["summary"]
    assert result["status"] == "compared" and len(disk["summary"]["requests"]) == summary["disk_requests"]
    actual = {(c["disk_table_row"], c["file_start_record"], c["file_end_record"]): c for c in summary["contexts"]}
    assert len(actual) == len(summary["contexts"])
    missing = []
    for request in disk["summary"]["requests"]:
        row = request["table_row"]
        init, done = (original[request[k]] for k in ("init_record", "complete_record"))
        assert init["tid"] == done["tid"] == tid and init["packet"] == done["packet"] != 0
        enclosing = [(a, b) for a, b in files if a["tid"] == tid and {67: 12, 68: 13, 73: 15}[a["op"]] == init["op"] and
                     a["record"] < init["record"] < done["record"] < b["record"] and a["tick"] <= init["tick"] < done["tick"] <= b["tick"]]
        if not enclosing:
            missing.append(row)
        for a, b in enclosing:
            c = actual.pop((row, a["record"], b["record"]))
            assert c["operation"] == {67: "read", 68: "write", 73: "flush"}[a["op"]]
            assert (c["disk_init_record"], c["disk_completion_record"], c["ntstatus"]) == (init["record"], done["record"], b["status"])
            assert tuple(map(int, (c["file_elapsed_ticks"], c["before_disk_ticks"], c["disk_elapsed_ticks"], c["after_disk_ticks"]))) == (
                b["tick"]-a["tick"], init["tick"]-a["tick"], done["tick"]-init["tick"], b["tick"]-done["tick"])
            for field, peer, key in (("packet_value", init, "packet"), ("file_object_value", done, "object")):
                assert c[field] == ("unreported" if not a[key] or not peer[key] else "equal" if a[key] == peer[key] else "different")
            if a["op"] == 73:
                assert all(c[k] is None for k in ("file_offset", "requested_bytes", "actual_bytes", "io_flags", "sdk_packet_flags", "synchronous_paging_flags"))
            else:
                assert (int(c["requested_bytes"]), int(c["actual_bytes"]), c["io_flags"]) == (a["size"], b["extra"], a["flags"])
                assert c["sdk_packet_flags"] == a["flags"] & 0x3fff and c["synchronous_paging_flags"] == (a["flags"] & 0x42 == 0x42)
                f = next(f for f in result["sdk_query"]["page"]["files"] if f["begin_record"] == a["record"])
                assert int(f["file_offset"]) == int(c["file_offset"]) == a["offset"]
    assert not actual and summary["disk_rows_without_file_context"] == sorted(missing)


def rejection_controls(report):
    common = report["pages"][0]["schedule"]["page"]
    d, f = (report["result"][k] for k in ("disk_requests", "file_operations"))
    window = common["activity_schedule"]
    page = f["native_pages"][0]["page"]
    for scope, key, value, expected in (
            ("file", "packet_conflict", True, "file_packet_history_unconfirmed"),
            ("file", "begin_matches", 2, "file_packet_history_unconfirmed"),
            ("file", "end_matches", 0, "file_packet_history_unconfirmed"),
            ("file", "actual_bytes", "1", "inconsistent_file_evidence"),
            ("file", "ntstatus", 1, "inconsistent_file_evidence"),
            ("sdk", "matched_links", 129, "file_context_limit"),
            ("sdk", "unplaced", 1, "file_rows_unplaced"),
            ("sdk", "operation_ends", 0, "file_operations_unobserved"),
            ("start", "io_flags", 0, "inconsistent_file_evidence"),
            ("start", "issuing_tid", 0, "inconsistent_file_evidence"),
            ("start", "raw_timestamp", "1", "inconsistent_file_evidence"),
            ("end", "packet_label", None, "inconsistent_file_evidence"),
            ("page", "status", "partial", "file_native_records_unavailable"),
            ("page", "source_sha256", "0"*64, "inconsistent_file_evidence")):
        sdk, native = deepcopy(f["sdk_query"]), deepcopy(f["native_pages"][0])
        projected, p = sdk["page"], native["page"]
        end = projected["files"][0]["end_record"]
        rows = {r["record_ordinal"]: r for r in p["operation_records"]}
        target = {"sdk": projected, "file": projected["files"][0], "start": rows[projected["files"][0]["begin_record"]],
                  "end": rows[end], "page": p}[scope]
        target[key] = value
        result = etl_file_operations.measure(lambda: sdk, lambda _: native, common, d, window)
        assert result["status"] == expected and result["summary"] is None, (key, result["status"])
    for private in (f, f["summary"], f["summary"]["contexts"][0], f["sdk_query"]["page"], f["sdk_query"]["page"]["files"][0],
                    f["sdk_query"]["page"]["files"][0]["enclosed"][0], f["sdk_query"]["page"]["disks"][0],
                    page, page["operation_records"][0], report["disk_traceprocessor"]):
        TDH["require_private"](private)


def other_operations(program, native, oracle, etl, common, disk_pages):
    _, disk_pairs = DISK["disk_records"](oracle, etl)
    bounds = TDH["tdh"](oracle, etl)[3]
    def query(command):
        return {"reader": {"exit_code": 0}, "page": call(command, 0)}

    # Choose by source ordinal, then derive the actual QPC query bounds. These are component queries without activity markers.
    for tid, first, last, span, expected, missing in (
            (11796, 86040, 86117, (86020, 86130), [(1, 1), (1, 2), (2, 1)], []),
            (15792, 87770, 87790, (87725, 87804), [(1, 6)], []),
            (38548, 810164, 810173, (810100, 810196), [], [94])):
        before, after = bounds[tid]
        events = {e["record_ordinal"]: e for pair in disk_pairs[tid] for e in pair}
        a, b = events[first]["raw_timestamp"], events[last]["raw_timestamp"]
        pid = before["payload_pid"]
        window = dict(start=dict(header_process_id=pid, header_thread_id=tid, logger_id=before["logger_id"], raw_timestamp=a),
                      stop=dict(raw_timestamp=b), thread_evidence=dict(before=before, after=after))
        args = [str(pid), str(tid), a, b]
        d, timeline = etl_disk_waits.prepare(query([program, etl, *args]), lambda n, _: disk_pages[n//128], common, window)
        assert timeline is not None, d["status"]
        d.update(status="measured", summary={"requests": timeline.requests})
        r = etl_file_operations.measure(lambda: query([program, etl, "--file-operations", *args]),
                                        lambda ns: query([native, etl, PIN, ",".join(map(str, ns))]), common, d, window)
        compare_source(oracle, etl, span, tid, d, r)
        assert sorted((x["file_table_row"], x["disk_table_row"]) for x in r["summary"]["contexts"]) == expected
        assert r["summary"]["disk_rows_without_file_context"] == missing
    for selector in ("2,1", "1,1", "0", "01", "2,"):
        assert call([native, etl, PIN, selector], 2) is None
    for selector, status in (("1", "other_event"), ("1999999", "not_observed")):
        partial = call([native, etl, PIN, selector], 1)
        assert partial["status"] == "partial" and partial["operation_records"][0]["status"] == status
    assert call([native, etl, "0"*64, "1"], 1) is None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "etl", "oracle", "adapter"):
        p.add_argument("--"+name, required=True, type=Path)
    p.add_argument("--cpu-adapter", type=Path)
    args = p.parse_args()
    exe, etl, oracle, adapter = (v.resolve(strict=True) for v in (args.exe, args.etl, args.oracle, args.adapter))
    assert pin(etl) == PIN
    base = [sys.executable, "-B", WAITS["CLI"], "--exe", exe, "--exe-sha256", pin(exe), "--etl", etl, "--sha256", PIN]
    disk = ["--disk-requests", adapter, pin(adapter)]
    opt = [*disk, "--file-operations"]
    observed = {}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for (a, b), span in WINDOWS.items():
            flags = [*base, "--start", str(a), "--stop", str(b)]
            out = root / f"files-{a}.json"
            receipt = call([*flags, *opt, "--output", out], 0)
            j = json.loads(out.read_bytes())
            d, f = (j["result"][k] for k in ("disk_requests", "file_operations"))
            common = j["pages"][0]["schedule"]["page"]
            compare_source(oracle, etl, span, common["activity_schedule"]["start"]["header_thread_id"], d, f)
            observed.update((c["disk_table_row"], c["file_table_row"]) for c in f["summary"]["contexts"])
            assert receipt["schema"] == "kn.etl_activity_waits_receipt.v4" and j["schema"] == "kn.etl_activity_waits.v4"
            assert receipt["report_sha256"] == pin(out) and receipt["file_operations_status"] == "compared"
            if (a, b) != next(iter(WINDOWS)):
                continue
            TDH["require_private"](receipt)
            rejection_controls(j)
            assert call([*flags, *opt, "--check-report", pin(out)], 0)["status"] == "matched"
            assert call([*flags, *opt, "--check-report", "0"*64], 1)["status"] == "mismatch"
            assert call([*flags, *opt, "--output", out], 2) is None and pin(out) == receipt["report_sha256"]
            for bad in (["--file-operations"], ["--disk-requests", adapter, "0"*64, "--file-operations"]):
                assert call([*flags, *bad, "--output", root/"bad.json"], 2) is None
                assert not (root/"bad.json").exists()
            small = root/"small.json"
            call([*flags, *opt, "--page-size", "2", "--output", small], 0)
            assert json.loads(small.read_bytes())["result"]["file_operations"] == f
            if args.cpu_adapter:
                cpu = args.cpu_adapter.resolve(strict=True)
                combined = root/"combined.json"
                both = call([*flags, *opt, "--traceprocessor", cpu, pin(cpu), "--interrupt-overlap", "--output", combined], 0)
                assert (both["traceprocessor_status"], both["interrupt_overlap_status"]) == ("matched", "measured")
                assert json.loads(combined.read_bytes())["result"]["file_operations"] == f
            legacy = root/"legacy.zip"
            with zipfile.ZipFile(adapter) as source, zipfile.ZipFile(legacy, "x") as dest:
                for member in source.infolist():
                    if member.filename != FILE_RECORD_PROGRAM:
                        dest.writestr(member, source.read(member))
            old = ["--disk-requests", legacy, pin(legacy)]
            before = root/"disk.json"
            call([*flags, *old, "--output", before], 0)
            legacy_report = json.loads(before.read_bytes())
            assert legacy_report["schema"] == "kn.etl_activity_waits.v3" and legacy_report["result"]["disk_requests"] == d
            assert call([*flags, *old, "--file-operations", "--output", root/"bad.json"], 2) is None
            (root/"wpt"/"Catalog").mkdir(parents=True)
            unpack(adapter, root, disk=True)
            other_operations(root/DISK_PROGRAM, root/FILE_RECORD_PROGRAM, oracle, etl, common, d["native_pages"])
        for a, b, status, code in ((87258, 87264, "no_disk_requests", 0), (726753, 731848, "disk_measurement_unavailable", 1)):
            out = root/f"control-{a}.json"
            r = call([*base, "--start", str(a), "--stop", str(b), *opt, "--output", out], code)
            f = json.loads(out.read_bytes())["result"]["file_operations"]
            assert r["file_operations_status"] == f["status"] == status and not f["native_pages"] and f["sdk_query"] is None
            assert f["summary"] == (None if code else dict(disk_requests=0, disk_rows_without_file_context=[], contexts=[]))
    assert observed == EXPECTED
    print("Six marked reads, nested writes, a flush, an unmatched flush, replay and rejection checks passed.")


if __name__ == "__main__":
    main()
