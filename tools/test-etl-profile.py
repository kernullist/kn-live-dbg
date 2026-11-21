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
    version = 3 if "--image-evidence" in args else (2 if "--thread-evidence" in args else 1)
    assert value["schema"] == f"kn.etl_profile.v{version}"
    return value


IMAGE_GUID = "2cb15d1d-5fc1-11d2-abe1-00a0c911f518"


class ImageOracle:
    """Use TDH's named image fields and a chronological history at each PID/base."""

    def __init__(self):
        self.by_ordinal = {}
        self.by_pid = defaultdict(lambda: defaultdict(list))

    def add(self, ordinal, tick, version, op, width, fields):
        def integer(key):
            return int(fields[key], 0)

        assert width in (4, 8)
        pid, base = integer("ProcessId"), integer("ImageBase")
        point = dict(record_ordinal=ordinal, raw_timestamp=str(tick), opcode=op, version=version,
                     pointer_bytes=width, payload_pid=pid, image_base=hex(base), image_size=hex(integer("ImageSize")),
                     preferred_base=hex(integer("DefaultBase")), image_checksum=integer("ImageChecksum"),
                     pe_timestamp=integer("TimeDateStamp"), recorded_file_name=fields["FileName"] or "",
                     signature_level=integer("SignatureLevel") if version == 3 else None,
                     signature_type=integer("SignatureType") if version == 3 else None)
        self.by_ordinal[ordinal] = point
        self.by_pid[pid][base].append(ordinal)

    def prepare(self):
        self.ranges = defaultdict(list)
        for pid, bases in self.by_pid.items():
            for base, ordinals in sorted(bases.items(), reverse=True):
                points = [self.by_ordinal[n] for n in ordinals]
                end = base + max(int(p["image_size"], 0) for p in points)
                opening = [p["opcode"] in (3, 10) for p in points]
                ticks = [int(p["raw_timestamp"]) for p in points]
                alternates = all(a != b for a, b in zip(opening, opening[1:]))
                ordered = all(a < b for a, b in zip(ticks, ticks[1:]))
                self.ranges[pid].append((base, end, ordinals, alternates, ordered))

    def expected(self, row, pid, coverage, clock_ok):
        ip = int(row["instruction_pointer"], 0)
        ordinal, tick = row["record_ordinal"], int(row["raw_timestamp"])
        candidates = []
        paired_rva = None
        for base, end, history, alternates, ordered in self.ranges.get(pid, ()):
            if not base <= ip < end:
                continue
            pos = bisect.bisect_left(history, ordinal)
            before = history[pos - 1] if pos else None
            after = history[pos] if pos < len(history) else None
            a, b = self.by_ordinal.get(before), self.by_ordinal.get(after)
            in_a = a and ip < base + int(a["image_size"], 0)
            in_b = b and ip < base + int(b["image_size"], 0)
            if not alternates:
                relation = "conflicting_transitions"
            elif not ordered:
                relation = "clock_unqualified"
            elif not (in_a or in_b):
                continue
            elif not clock_ok or (a and int(a["raw_timestamp"]) >= tick) or (b and int(b["raw_timestamp"]) <= tick):
                relation = "clock_unqualified"
            elif not ((in_a and a["opcode"] in (3, 10)) or (in_b and b["opcode"] in (2, 4))):
                continue
            elif not (a and b):
                relation = "one_boundary"
            elif any(a[k] != b[k] for k in ("image_size", "version", "pointer_bytes", "preferred_base", "image_checksum",
                                            "pe_timestamp", "signature_level", "signature_type", "recorded_file_name")):
                relation = "image_identity_conflict"
            elif not a["recorded_file_name"]:
                relation = "missing_image_name"
            elif not coverage:
                relation = "coverage_unqualified"
            else:
                relation = "load_unload" if (a["opcode"], b["opcode"]) == (10, 2) else "rundown_bracket"
                paired_rva = hex(ip - base)
            candidates.append(dict(relation=relation, before_record=before, after_record=after))
        if len(candidates) == 1:
            relation = candidates[0]["relation"]
        elif candidates:
            relation = "overlapping_ranges"
        else:
            relation = "no_recorded_range" if pid else "thread_pid_unavailable"
        return dict(relation=relation, candidate_ranges=len(candidates),
                    reported_rva=paired_rva if len(candidates) == 1 else None, witnesses=candidates[:2])


def oracle(etl, folder, want_images):
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
    images = ImageOracle() if want_images else None
    pointer_width = None
    records = raw_threads = raw_samples = 0
    with xml_path.open("rb") as stream:
        events = ElementTree.iterparse(stream, events=("start", "end"))
        _, root = next(events)
        for action, event in events:
            if action != "end" or event.tag != ns + "Event":
                continue
            records += 1
            guid = (event.findtext(trace_ns + "ExtendedTracingInfo/" + trace_ns + "EventGuid") or "").strip("{}").lower()
            if want_images and guid == "68fdd900-4a3e-11d1-84f4-0000f80464e3":
                width = event.find(ns + "EventData/" + ns + "Data[@Name='PointerSize']")
                if width is not None:
                    pointer_width = int(width.text, 0)
            if want_images and guid == IMAGE_GUID:
                system = event.find(ns + "System")
                version = int(system.findtext(ns + "Version"))
                op = int(system.findtext(ns + "Opcode"))
                if system.findtext(ns + "EventID") == "0" and version in (2, 3) and op in (2, 3, 4, 10):
                    fields = {x.attrib["Name"]: x.text for x in event.findall(ns + "EventData/" + ns + "Data")}
                    tick = int(system.find(ns + "TimeCreated").attrib["RawTime"])
                    images.add(records, tick, version, op, pointer_width, fields)
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
    if images is not None:
        images.prepare()
    return records, samples, threads, images


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
    return paired_pid


def compare(report, pin, size, records, oracle_rows, after, limit, threads, images):
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
    referenced = set()
    if images is not None:
        count = len(images.by_ordinal)
        assert report["image_source"] == dict(provider_guid=IMAGE_GUID, versions=[2, 3], decoded_events=count,
                                              retained_events=count, unsupported_events=0, retention="complete")
    else:
        assert "image_source" not in report and "image_records" not in report
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
            pid = compare_thread(row["thread_evidence"], row, threads.get(row["sampled_thread_id"], []), coverage, clock_ok)
            if images is not None:
                answer = images.expected(row, pid, coverage, clock_ok)
                assert row["image_evidence"] == answer, ("image relation", seq)
                for witness in answer["witnesses"]:
                    referenced.update(n for n in (witness["before_record"], witness["after_record"]) if n is not None)
        if images is None:
            assert "image_evidence" not in row
        if threads is None:
            assert "thread_evidence" not in row
        assert row["pointer_bytes"] in (4, 8)
        assert row["cpu_field"] == ("processor_index" if row["header_flags"] & 0x200 else "processor_number")
    if images is not None:
        assert [p["record_ordinal"] for p in report["image_records"]] == sorted(referenced)
        for point in report["image_records"]:
            expected = images.by_ordinal[point["record_ordinal"]]
            assert point == expected, ("image record", point["record_ordinal"], [k for k in expected if expected[k] != point.get(k)])
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


def exercise(exe, etl, pin, expected_count, folder, all_pages, short_tail, join_threads, join_images):
    size = etl.stat().st_size
    with etl.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == pin
    records, samples, threads, images = oracle(etl, folder, join_images)
    evidence_args = ["--image-evidence"] if join_images else (["--thread-evidence"] if join_threads else [])
    join_threads = join_threads or join_images
    assert len(samples) == expected_count, (len(samples), expected_count)
    pages = [(0, 64), (0, 1), (min(1, len(samples)), 128), (len(samples) // 2, 128),
             (max(0, len(samples) - 3), 128), (len(samples), 1)]
    if all_pages:
        pages.extend((offset, 128) for offset in range(0, len(samples), 128))
    compared, compared_images = {}, {}
    for after, limit in pages:
        # The first call exercises the defaults, subsequent calls explicit paging.
        args = [] if (after, limit) == (0, 64) else ["--limit", limit, "--after", after]
        report = run(exe, etl, pin.upper(), *evidence_args, *args)
        rows = compare(report, pin, size, records, samples, after, limit, threads if join_threads else None, images)
        for row in rows:
            if join_images:
                compared_images[row["sample_ordinal"]] = row["image_evidence"]["relation"]
            compared[row["sample_ordinal"]] = row.get("thread_evidence", {}).get("relation")
    if join_images:
        first = run(exe, etl, pin, "--image-evidence", "--limit", 4)
        for flags in (("--image-evidence", "--thread-evidence"), ("--thread-evidence", "--image-evidence")):
            assert run(exe, etl, pin, *flags, "--after", 0, "--limit", 4) == first
        for flags, evidence in (([], None), (["--thread-evidence"], threads)):
            compare(run(exe, etl, pin, *flags, "--limit", 4), pin, size, records, samples, 0, 4, evidence, None)
    if all_pages:
        assert len(compared) == len(samples)
    if short_tail:
        trimmed = folder / "short-tail.etl"
        shutil.copyfile(etl, trimmed)
        with trimmed.open("r+b") as output:
            output.truncate(size - 1)
        with trimmed.open("rb") as f:
            trimmed_pin = hashlib.file_digest(f, "sha256").hexdigest()
        partial = run(exe, trimmed, trimmed_pin, "--limit", 1, *evidence_args, rc=1)
        assert partial["source_sha256"] == trimmed_pin and partial["status"] == "partial"
        assert partial["buffer_comparison"] == "fewer_than_declared"
        assert partial["buffers_processed"] < partial["log_header"]["buffers_written"]
        assert partial["records_seen"] < records
        if join_threads:
            assert all(r["thread_evidence"]["paired_record_pid"] is None for r in partial["samples"])
        if join_images:
            assert all(r["image_evidence"]["reported_rva"] is None for r in partial["samples"])
    assert run(exe, etl, pin, "--after", len(samples) + 1, rc=1)["status"] == "cursor_out_of_range"
    wrong = ("0" if pin[0] != "0" else "1") + pin[1:]
    assert run(exe, etl, wrong, *evidence_args, rc=1)["status"] == "digest_mismatch"
    for args in (("--after", "-1"), ("--limit", 0), ("--limit", 129), ("--after", "01"),
                 ("--after", 1, "--after", 2), ("--limit", "1", "--limit", "2"), ("--thread-evidence", "--thread-evidence"),
                 ("--image-evidence", "--image-evidence")):
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
    if join_images:
        print("Image events:", len(images.by_ordinal), "Sample relations:", dict(Counter(compared_images.values())))
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
    parser.add_argument("--image-evidence", action="store_true", help="Compare same-process image ranges and their source records")
    parser.add_argument("--all-pages", action="store_true", help="Compare every decoded sample in 128-row pages")
    parser.add_argument("--check-short-tail", action="store_true",
                        help="For fixtures with a populated last buffer, require detection after removing its last byte")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-etl-profile-") as directory:
        folder = Path(directory)
        (folder / "source").mkdir()
        etl = folder / "source" / "input.etl"
        shutil.copyfile(args.etl, etl)
        exercise(args.exe.resolve(strict=True), etl, args.sha256.lower(), args.expect_samples, folder, args.all_pages, args.check_short_tail, args.thread_evidence, args.image_evidence)


if __name__ == "__main__":
    main()
