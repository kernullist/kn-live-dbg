"""Compare a pinned local Windows ETL with the system tracerpt decoder."""
import argparse
import bisect
from collections import Counter, defaultdict
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import struct
from xml.etree import ElementTree


def run(exe, etl, digest, *args, rc=0):
    result = subprocess.run([exe, "--etl-profile", etl, "--sha256", digest, *map(str, args)],
                            capture_output=True, timeout=90)
    assert result.returncode == rc, (result.returncode, result.stdout[:250], result.stderr[:250])
    if rc == 2:
        assert not result.stdout
        return None
    value = json.loads(result.stdout.decode("utf-8"))
    assert value["schema"] == ("kn.etl_profile.v2" if "--thread-evidence" in args else "kn.etl_profile.v1")
    return value


def oracle(etl, folder):
    # The XML event envelope gives an ordinal even when TDH cannot format a
    # field. In that case Windows still exports the original event payload.
    xml_path = folder / "raw.xml"
    tracerpt = Path(os.environ["SystemRoot"]) / "System32" / "tracerpt.exe"
    subprocess.run([tracerpt, etl, "-o", xml_path, "-of", "XML", "-rts", "-y"],
                   cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, timeout=240)
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    trace_ns = "{http://schemas.microsoft.com/win/2004/08/events/trace}"
    thread_guid = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"
    profile_guid = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"
    samples, threads = [], defaultdict(list)
    records = raw_threads = raw_samples = 0
    with xml_path.open("rb") as stream:
        events = ElementTree.iterparse(stream, events=("start", "end"))
        _, root = next(events)
        for action, event in events:
            if action != "end" or event.tag != ns + "Event":
                continue
            records += 1
            guid = (event.findtext(trace_ns + "ExtendedTracingInfo/" + trace_ns + "EventGuid") or "").strip("{}").lower()
            if guid in (thread_guid, profile_guid):
                system = event.find(ns + "System")
                descriptor = {x.tag.removeprefix(ns): x.text for x in system}
                opcode = int(descriptor["Opcode"])
                profile = (guid, descriptor["EventID"], opcode, descriptor["Version"]) == (profile_guid, "0", 46, "2")
                thread = guid == thread_guid and descriptor["EventID"] == "0" and 1 <= opcode <= 4 and descriptor["Version"] == "3"
                if profile or thread:
                    tick = int(system.find(ns + "TimeCreated").attrib["RawTime"])
                    values = {x.attrib["Name"]: x.text for x in event.findall(ns + "EventData/" + ns + "Data")}
                    if values:
                        if profile:
                            ip, tid, count, reserved = (int(values[key], 0) for key in
                                                        ("InstructionPointer", "ThreadId", "Count", "Reserved"))
                        else:
                            pid, tid = (int(values[key], 0) for key in ("ProcessId", "TThreadId"))
                    else:
                        raw = bytes.fromhex(event.findtext(ns + "ProcessingErrorData/" + ns + "EventPayload") or "")
                        if profile:
                            assert len(raw) in (12, 16)
                            ip = int.from_bytes(raw[:-8], "little")
                            tid, count, reserved = struct.unpack("<IHH", raw[-8:])
                            raw_samples += 1
                        else:
                            pid, tid = struct.unpack_from("<II", raw)
                            raw_threads += 1
                    if thread:
                        threads[tid].append((records, tick, opcode, pid, tid))
                    else:
                        header = system.find(ns + "Execution").attrib
                        samples.append((records, tick, int(header["ProcessorID"], 0), ip, tid, count, reserved,
                                        int(header["ProcessID"], 0), int(header["ThreadID"], 0),
                                        int(descriptor["Keywords"], 0), int(descriptor["Channel"] or "0", 0),
                                        int(descriptor["Level"], 0), int(descriptor["Task"], 0)))
            event.clear()
            root.clear()
    print(f"XML oracle used raw payloads for {raw_samples} CPU samples and {raw_threads} thread records.")
    return records, samples, threads


def compare_thread(pair, row, events, coverage, clock_ok):
    names = {1: "start", 2: "end", 3: "rundown_start", 4: "rundown_end"}
    pos = bisect.bisect_left(events, (row["record_ordinal"],))
    left, right = events[pos - 1] if pos else None, events[pos] if pos < len(events) else None

    def point(e):
        if e is None:
            return None
        ordinal, tick, opcode, pid, tid = e
        return dict(record_ordinal=ordinal, raw_timestamp=str(tick), event=names[opcode],
                    opcode=opcode, payload_pid=pid, payload_tid=tid)

    paired_pid = None
    if row["sampled_thread_id"] in (0, 0xffffffff):
        relation, left, right = "unusable_tid", None, None
    elif not events:
        relation = "no_record"
    elif not left or not right:
        relation = "one_boundary"
    elif left[2] in (2, 4) or right[2] in (1, 3):
        relation = "outside_bracket"
    elif left[3] != right[3] or left[3] in (0, 0xffffffff):
        relation = "pid_conflict"
    elif any((a[2] in (1, 3)) == (b[2] in (1, 3)) for a, b in zip(events, events[1:])):
        relation = "conflicting_transitions"
    elif (not clock_ok or any(b[1] <= a[1] for a, b in zip(events, events[1:])) or
          not left[1] < int(row["raw_timestamp"]) < right[1]):
        relation = "clock_unqualified"
    elif not coverage:
        relation = "coverage_unqualified"
    else:
        relation = "start_end" if (left[2], right[2]) == (1, 2) else "rundown_bracket"
        paired_pid = left[3]
    assert pair == dict(relation=relation, before=point(left), after=point(right), paired_record_pid=paired_pid)


def compare(report, pin, size, records, oracle_rows, after, limit, threads):
    assert report["status"] == "read" and report["source_sha256"] == pin and report["source_bytes"] == size
    assert (report["provider_guid"], report["event_id"], report["opcode"], report["version"]) == (
        "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc", 0, 46, 2)
    assert report["records_seen"] == records and report["decoded_samples"] == len(oracle_rows)
    assert report["after"] == after
    assert report["log_header"]["events_lost"] >= 0 and report["log_header"]["buffers_lost"] >= 0
    if report["buffer_comparison"] == "matched":
        assert report["buffers_processed"] == report["log_header"]["buffers_written"]
    else:
        assert report["buffer_comparison"] == "not_comparable"
    q = report["qualification"]
    assert q["evidence"] == "reported_cpu_sample" and q["verified_level"] == "unqualified"
    assert q["producer_authenticity"] == "unverified"
    assert all(q[field] is None for field in ("sampled_process_id", "thread_lifetime", "address_space",
               "vm", "vtl", "code_version", "capture_privilege", "capture_enable_flags",
               "stack_capture_policy", "sample_loss_intervals"))
    if threads is not None:
        meta = report["thread_source"]
        total = sum(map(len, threads.values()))
        assert meta["provider_guid"] == "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c" and meta["version"] == 3
        assert meta["decoded_events"] == meta["retained_events"] == total and meta["unsupported_events"] == 0
    else:
        assert "thread_source" not in report
    rows = report["samples"]
    wanted = oracle_rows[after:after + limit]
    assert len(rows) == len(wanted)
    for seq, (row, expected) in enumerate(zip(rows, wanted), after + 1):
        got = (row["record_ordinal"], int(row["raw_timestamp"]), row["cpu"], int(row["instruction_pointer"], 0),
               row["sampled_thread_id"], row["count_field"], row["reserved_field"],
               row["header_process_id"], row["header_thread_id"], int(row["event_keyword"], 0),
               row["event_channel"], row["event_level"], row["event_task"])
        assert row["sample_ordinal"] == seq and got == expected, (seq, got, expected)
        if threads is not None:
            h = report["log_header"]
            coverage = report["buffer_comparison"] == "matched" and not (h["events_lost"] or h["buffers_lost"] or report["loss_marker_records"])
            clock = report["clock"]
            clock_ok = clock["raw_type"] == 2 or (clock["raw_type"] == 1 and int(clock["header_perf_frequency"]) > 0)
            compare_thread(row["thread_evidence"], row, threads.get(row["sampled_thread_id"], []), coverage, clock_ok)
        else:
            assert "thread_evidence" not in row
        assert row["pointer_bytes"] in (4, 8)
        assert row["cpu_field"] == ("processor_index" if row["header_flags"] & 0x200 else "processor_number")
    assert report["next_after"] == (after + limit if after + limit < len(oracle_rows) else None)
    return rows


def check_directory_lease(exe, etl, pin, parent):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    # FILE_ADD_FILE makes this a write-access handle on an owned ancestor.
    handle = kernel.CreateFileW(str(parent), 2, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        assert run(exe, etl, pin, rc=1)["status"] == "source_unavailable"
    finally:
        kernel.CloseHandle(handle)


def exercise(exe, etl, pin, expected_count, folder, all_pages, short_tail, join_threads):
    size = etl.stat().st_size
    with etl.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == pin
    records, samples, threads = oracle(etl, folder)
    thread_args = ["--thread-evidence"] if join_threads else []
    assert len(samples) == expected_count, (len(samples), expected_count)
    pages = [(0, 64), (0, 1), (min(1, len(samples)), 128), (len(samples) // 2, 128),
             (max(0, len(samples) - 3), 128), (len(samples), 1)]
    if all_pages:
        pages.extend((offset, 128) for offset in range(0, len(samples), 128))
    compared = {}
    for after, limit in pages:
        # The first call exercises the defaults, subsequent calls explicit paging.
        args = [] if (after, limit) == (0, 64) else ["--limit", limit, "--after", after]
        report = run(exe, etl, pin.upper(), *thread_args, *args)
        rows = compare(report, pin, size, records, samples, after, limit, threads if join_threads else None)
        for row in rows:
            compared[row["sample_ordinal"]] = row.get("thread_evidence", {}).get("relation")
    if all_pages:
        assert len(compared) == len(samples)
    if short_tail:
        trimmed = folder / "short-tail.etl"
        shutil.copyfile(etl, trimmed)
        with trimmed.open("r+b") as output:
            output.truncate(size - 1)
        with trimmed.open("rb") as f:
            trimmed_pin = hashlib.file_digest(f, "sha256").hexdigest()
        partial = run(exe, trimmed, trimmed_pin, "--limit", 1, *thread_args, rc=1)
        assert partial["source_sha256"] == trimmed_pin and partial["status"] == "partial"
        assert partial["buffer_comparison"] == "fewer_than_declared"
        assert partial["buffers_processed"] < partial["log_header"]["buffers_written"]
        assert partial["records_seen"] < records
        if join_threads:
            assert all(r["thread_evidence"]["paired_record_pid"] is None for r in partial["samples"])
    assert run(exe, etl, pin, "--after", len(samples) + 1, rc=1)["status"] == "cursor_out_of_range"
    wrong = ("0" if pin[0] != "0" else "1") + pin[1:]
    assert run(exe, etl, wrong, *thread_args, rc=1)["status"] == "digest_mismatch"
    for args in (("--after", "-1"), ("--limit", 0), ("--limit", 129), ("--after", "01"),
                 ("--after", 1, "--after", 2), ("--limit", "1", "--limit", "2"), ("--thread-evidence", "--thread-evidence")):
        run(exe, etl, pin, *args, rc=2)
    bad = folder / "invalid.etl"
    bad.write_bytes(b"invalid test input")
    bad_pin = hashlib.sha256(bad.read_bytes()).hexdigest()
    assert run(exe, bad, bad_pin, rc=1)["status"] in ("open_trace_failed", "process_trace_failed")
    missing = folder / "missing.etl"
    assert run(exe, missing, pin, rc=1)["status"] == "source_unavailable"
    check_directory_lease(exe, etl, pin, folder)
    # The writable stdout hard link must not receive even an error report.
    hardlink = folder / "same-source.bin"
    os.link(etl, hardlink)
    with hardlink.open("ab", buffering=0) as redirected:
        result = subprocess.run([exe, "--etl-profile", etl, "--sha256", pin],
                                stdout=redirected, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode != 0 and etl.stat().st_size == size
    with etl.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == pin
    if join_threads:
        print("Thread events:", sum(map(len, threads.values())), "Sample relations:", dict(Counter(compared.values())))
    print(f"ETL profile passed. {records} events, {len(samples)} CPU samples, {len(compared)} distinct sample rows compared.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--etl", type=Path, required=True, help="Saved trace for the independent decoder")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--expect-samples", type=int, required=True)
    parser.add_argument("--thread-evidence", action="store_true", help="Compare the source-local thread records for each sample")
    parser.add_argument("--all-pages", action="store_true", help="Compare every decoded sample in 128-row pages")
    parser.add_argument("--check-short-tail", action="store_true",
                        help="For fixtures with a populated last buffer, require detection after removing its last byte")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-etl-profile-") as directory:
        folder = Path(directory)
        (folder / "source").mkdir()
        etl = folder / "source" / "input.etl"
        shutil.copyfile(args.etl, etl)
        exercise(args.exe.resolve(strict=True), etl, args.sha256.lower(), args.expect_samples, folder, args.all_pages, args.check_short_tail, args.thread_evidence)


if __name__ == "__main__":
    main()
