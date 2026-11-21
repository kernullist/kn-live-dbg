"""Compare a pinned local Windows ETL with the system tracerpt decoder."""
import argparse
import bisect
from collections import Counter, defaultdict
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
import tempfile
import struct
from xml.etree import ElementTree


def run(exe, etl, digest, *args, rc=0, switches=False):
    command = "--etl-switches" if switches else "--etl-profile"
    result = subprocess.run([exe, command, etl, "--sha256", digest, *map(str, args)],
                            capture_output=True, timeout=90)
    assert result.returncode == rc, (result.returncode, result.stdout[:250], result.stderr[:250])
    if rc == 2:
        assert not result.stdout
        return None
    value = json.loads(result.stdout.decode("utf-8"))
    version = 6 if "--build-evidence" in args else 5 if "--reference-image" in args else 4 if "--process-evidence" in args else 3 if "--image-evidence" in args else 2 if "--thread-evidence" in args else 1
    switch_version = 2 if "--intervals" in args or "--thread-id" in args else 1
    assert value["schema"] == (f"kn.etl_switches.v{switch_version}" if switches else f"kn.etl_profile.v{version}")
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


def switch_values(system, ns, fields, ordinal, version):
    def number(key):
        assert fields[key].isascii()
        return int(fields[key], 0)

    def signed_byte(key):
        value = number(key)
        assert -128 <= value <= 255
        return value - 256 if value >= 128 else value

    execution = system.find(ns + "Execution").attrib
    return (ordinal, int(system.find(ns + "TimeCreated").attrib["RawTime"]), int(execution["ProcessorID"], 0),
            int(execution["ProcessID"], 0), int(execution["ThreadID"], 0), int(system.findtext(ns + "Keywords"), 0),
            int(system.findtext(ns + "Channel") or "0", 0), int(system.findtext(ns + "Level"), 0),
            int(system.findtext(ns + "Task"), 0), version, number("NewThreadId"), number("OldThreadId"),
            signed_byte("NewThreadPriority"), signed_byte("OldThreadPriority"), number("PreviousCState"),
            signed_byte("SpareByte"), signed_byte("OldThreadWaitReason"), signed_byte("OldThreadWaitMode") if version == 2 else None,
            number("ThreadFlags") & 255 if version >= 3 else None, signed_byte("OldThreadState"),
            signed_byte("OldThreadWaitIdealProcessor"), number("NewThreadWaitTime"), number("Reserved"))


def oracle(etl, folder, want_images, want_switches=False, schedule=None, processes=None, builds=None):
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
    samples, threads, switches = [], defaultdict(list), []
    images = ImageOracle() if want_images else None
    pointer_width = None
    records = raw_threads = raw_samples = 0
    with xml_path.open("rb") as stream:
        # Switch fields and descriptor IDs are ASCII integers. Some tracerpt
        # exports write unrelated text in the local code page without an XML
        # encoding declaration. A single-byte parse preserves the markup and
        # every selected value. Image evidence needs the original Unicode names.
        prefix = stream.read(4)
        stream.seek(0)
        narrow_xml = b"\0" not in prefix and not prefix.startswith((b"\xff\xfe", b"\xfe\xff"))
        single_byte = narrow_xml and (want_switches or processes is not None and not want_images)
        if narrow_xml and processes is not None and want_images:
            # Keep valid UTF-8 image names. Some tracerpt builds write unrelated provider text
            # in a local code page. Refuse to verify any selected name with a replacement character.
            stream = io.TextIOWrapper(stream, encoding="utf-8-sig", errors="replace")
        parser = ElementTree.XMLParser(encoding="iso-8859-1") if single_byte else None
        events = ElementTree.iterparse(stream, events=("start", "end"), parser=parser)
        _, root = next(events)
        for action, event in events:
            if action != "end" or event.tag != ns + "Event":
                continue
            records += 1
            guid = (event.findtext(trace_ns + "ExtendedTracingInfo/" + trace_ns + "EventGuid") or "").strip("{}").lower()
            if (want_images or processes is not None) and guid == "68fdd900-4a3e-11d1-84f4-0000f80464e3":
                width = event.find(ns + "EventData/" + ns + "Data[@Name='PointerSize']")
                if width is not None:
                    pointer_width = int(width.text, 0)
            if builds is not None and guid == "b3e675d7-2554-4f18-830b-2762732560de":
                builds.add(event, ns, records, pointer_width)
            if want_images and guid == IMAGE_GUID:
                system = event.find(ns + "System")
                version = int(system.findtext(ns + "Version"))
                op = int(system.findtext(ns + "Opcode"))
                if processes is not None and op in (2, 3, 4, 10):
                    processes.image_tick(int(system.find(ns + "TimeCreated").attrib["RawTime"]))
                if system.findtext(ns + "EventID") == "0" and version in (2, 3) and op in (2, 3, 4, 10):
                    fields = {x.attrib["Name"]: x.text for x in event.findall(ns + "EventData/" + ns + "Data")}
                    tick = int(system.find(ns + "TimeCreated").attrib["RawTime"])
                    if processes is not None:
                        assert "\ufffd" not in (fields.get("FileName") or ""), ("unqualified XML image name", records)
                    images.add(records, tick, version, op, pointer_width, fields)
            if processes is not None and guid in ("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c", thread_guid, profile_guid):
                system = event.find(ns + "System")
                op = int(system.findtext(ns + "Opcode"))
                process = guid == "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c" and op in (1, 2, 3, 4, 39)
                if process or guid == thread_guid and 1 <= op <= 4 or guid == profile_guid and op == 46:
                    tick = int(system.find(ns + "TimeCreated").attrib["RawTime"])
                    processes.tick(tick)
                    if process and system.findtext(ns + "EventID") == "0":
                        fields = {x.attrib["Name"]: x.text for x in event.findall(ns + "EventData/" + ns + "Data")}
                        raw = event.findtext(ns + "ProcessingErrorData/" + ns + "EventPayload")
                        processes.add(records, tick, op, int(system.findtext(ns + "Version")), pointer_width, fields, raw)
            if want_switches and guid == thread_guid:
                system = event.find(ns + "System")
                if system.findtext(ns + "EventID") == "0" and system.findtext(ns + "Opcode") == "36":
                    version = int(system.findtext(ns + "Version"))
                    if version in (2, 3, 4):
                        fields = {x.attrib["Name"]: x.text for x in event.findall(ns + "EventData/" + ns + "Data")}
                        switches.append(switch_values(system, ns, fields, records, version))
                        if schedule is not None:
                            r = switches[-1]
                            schedule.switch(records, r[1], r[2], version, len(switches), r[10], r[11], r[19], r[16])
                elif schedule is not None and system.findtext(ns + "EventID") == "0":
                    opcode = int(system.findtext(ns + "Opcode"))
                    version = int(system.findtext(ns + "Version"))
                    if (opcode == 50 and version == 2) or (1 <= opcode <= 4 and version == 3):
                        tick = int(system.find(ns + "TimeCreated").attrib["RawTime"])
                        cpu = int(system.find(ns + "Execution").attrib["ProcessorID"], 0)
                        fields = {x.attrib["Name"]: x.text for x in event.findall(ns + "EventData/" + ns + "Data")}
                        if opcode == 50:
                            assert all(value.isascii() for value in fields.values())
                            tid, reason, increment, flags, reserved = (int(fields[k], 0) for k in
                                ("TThreadId", "AdjustReason", "AdjustIncrement", "Flag", "Reserved"))
                            def signed(v):
                                return (v + 128) % 256 - 128
                            schedule.readiness(records, tick, cpu, tid, signed(reason), signed(increment), flags & 255, signed(reserved))
                        else:
                            if fields:
                                pid, tid = (int(fields[k], 0) for k in ("ProcessId", "TThreadId"))
                            else:
                                payload = bytes.fromhex(event.findtext(ns + "ProcessingErrorData/" + ns + "EventPayload"))
                                pid, tid = struct.unpack_from("<II", payload)
                            schedule.boundary(records, tick, cpu, opcode, pid, tid)
            if not want_switches and guid in (thread_guid, profile_guid):
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
    if builds is not None:
        xml_path.unlink()
    if not want_switches:
        print(f"XML oracle used raw payloads for {raw_samples} CPU samples and {raw_threads} thread records.")
    if processes is not None:
        processes.prepare()
    if images is not None:
        images.prepare()
    return records, samples, threads, images, switches


def compare_thread(pair, row, events, coverage, clock_ok, include_logger=False):
    names = {1: "start", 2: "end", 3: "rundown_start", 4: "rundown_end"}
    pos = bisect.bisect_left(events, (row["record_ordinal"],))
    left, right = events[pos - 1] if pos else None, events[pos] if pos < len(events) else None

    def point(e):
        if e is None:
            return None
        ordinal, tick, opcode, pid, tid = e
        expected = dict(record_ordinal=ordinal, raw_timestamp=str(tick), event=names[opcode],
                        opcode=opcode, payload_pid=pid, payload_tid=tid)
        if include_logger:
            expected["logger_id"] = row["logger_id"]
        return expected

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


def compare(report, pin, size, records, oracle_rows, after, limit, threads, images, processes=None, reference=None, builds=None):
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
    if reference is not None:
        assert report["reference_image"] == reference.source
    else:
        assert "reference_image" not in report
    if builds is not None:
        builds.check_records(report, images)
    else:
        assert "build_source" not in report and "build_records" not in report and "reference_build" not in report
    referenced, process_refs = set(), set()
    if processes is not None:
        assert report["process_source"] == processes.metadata(images is not None)
    else:
        assert "process_source" not in report and "process_records" not in report
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
            pid = compare_thread(row["thread_evidence"], row, threads.get(row["sampled_thread_id"], []), coverage, clock_ok, processes is not None)
            if processes is not None:
                process_answer = processes.expected(row, clock_ok, coverage and not report["unsupported_profile_records"])
                assert row["process_evidence"] == process_answer, ("process relation", seq, row["process_evidence"]["relation"], process_answer["relation"])
                process_refs.update(n for n in (process_answer["before_record"], process_answer["after_record"]) if n is not None)
            if images is not None:
                answer = images.expected(row, pid, coverage, clock_ok)
                if processes is not None:
                    bound = processes.image_in_process(process_answer, answer, images)
                    assert row["image_process_evidence"] == bound, ("image in process", seq)
                    build = builds.expected(bound, answer, images, coverage and clock_ok) if builds is not None else None
                    assert row.get("build_evidence") == build
                    if reference is not None:
                        assert row["reference_evidence"] == reference.expected(bound, answer, images, build), ("reference", seq)
                assert row["image_evidence"] == answer, ("image relation", seq)
                for witness in answer["witnesses"]:
                    referenced.update(n for n in (witness["before_record"], witness["after_record"]) if n is not None)
        if reference is None:
            assert "reference_evidence" not in row
        if processes is None:
            assert "process_evidence" not in row
        if processes is None or images is None:
            assert "image_process_evidence" not in row
        if images is None:
            assert "image_evidence" not in row
        if threads is None:
            assert "thread_evidence" not in row
        assert row["pointer_bytes"] in (4, 8)
        assert row["cpu_field"] == ("processor_index" if row["header_flags"] & 0x200 else "processor_number")
    if processes is not None:
        assert [p["record_ordinal"] for p in report["process_records"]] == sorted(process_refs)
        # tracerpt does not export the native logger ID. These comparisons use single-logger fixtures.
        if rows:
            assert len({r["logger_id"] for r in rows}) == 1
        for actual in report["process_records"]:
            expected = dict(processes.points[actual["record_ordinal"]], logger_id=rows[0]["logger_id"])
            assert actual == expected, ("process record", actual["record_ordinal"], [k for k in expected if actual.get(k) != expected[k]])
    if images is not None:
        assert [p["record_ordinal"] for p in report["image_records"]] == sorted(referenced)
        for point in report["image_records"]:
            expected = images.by_ordinal[point["record_ordinal"]]
            if processes is not None:
                expected = dict(expected, logger_id=rows[0]["logger_id"])
            if builds is not None:
                expected = dict(expected, merge_build=builds.endpoint(expected, coverage and clock_ok))
            assert point == expected, ("image record", point["record_ordinal"], [k for k in expected if expected[k] != point.get(k)])
    assert report["next_after"] == (after + limit if after + limit < len(oracle_rows) else None)
    return rows


def check_directory_lease(exe, etl, pin, parent, switches=False, options=(), status="source_unavailable"):
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
        assert run(exe, etl, pin, *options, rc=1, switches=switches)["status"] == status
    finally:
        kernel.CloseHandle(handle)


def check_output_alias(exe, command, etl, pin, folder, options=()):
    # The writable stdout hard link must not receive even an error report.
    size = etl.stat().st_size
    hardlink = folder / "same-source.bin"
    os.link(etl, hardlink)
    with hardlink.open("ab", buffering=0) as redirected:
        result = subprocess.run([exe, command, etl, "--sha256", pin, *options],
                                stdout=redirected, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode != 0 and etl.stat().st_size == size
    with etl.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == pin


def page_cases(count, all_pages):
    pages = [(0, 64), (0, 1), (min(1, count), 128), (count // 2, 128),
             (max(0, count - 3), 128), (count, 1)]
    if all_pages:
        pages.extend((offset, 128) for offset in range(0, count, 128))
    return pages


def exercise(exe, etl, pin, expected_count, folder, all_pages, short_tail, join_threads, join_images, join_processes,
             reference_args=None, expected_windows=None, join_builds=False):
    size = etl.stat().st_size
    with etl.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == pin
    reference = None
    if reference_args is not None:
        metadata_dir = folder / "reference"
        metadata_dir.mkdir()
        original = Path(reference_args[0]).resolve(strict=True)
        local = metadata_dir / original.name
        shutil.copyfile(original, local)
        reference = run_path(str(Path(__file__).with_name("etl_reference_oracle.py")))["ReferenceOracle"](local, reference_args[1])
        join_images = join_processes = True
    builds = None
    if join_builds:
        module = run_path(str(Path(__file__).with_name("etl_build_oracle.py")))
        builds = module["BuildOracle"](reference)
        if expected_count == 0:
            module["check_reference_layouts"](exe, etl, pin, folder, run)
        join_images = join_processes = True
    processes = run_path(str(Path(__file__).with_name("etl_process_oracle.py")))["ProcessOracle"]() if join_processes else None
    records, samples, threads, images, _ = oracle(etl, folder, join_images, processes=processes, builds=builds)
    if builds is not None:
        builds.prepare(images)
    evidence_args = [f for enabled, f in ((join_processes, "--process-evidence"), (join_images, "--image-evidence"),
                                          (join_threads, "--thread-evidence")) if enabled]
    if reference is not None:
        evidence_args = ["--reference-image", reference.path, reference_args[1].upper()]
    if builds is not None:
        evidence_args = ["--build-evidence"] + (evidence_args if reference is not None else [])
        canonical = run(exe, etl, pin, *evidence_args, "--limit", 3)
        assert run(exe, etl, pin, "--process-evidence", "--image-evidence", "--thread-evidence", *evidence_args,
                   "--limit", 3, "--after", 0) == canonical
        run(exe, etl, pin, "--build-evidence", switches=True, rc=2)
    join_threads = join_threads or join_images or join_processes
    assert len(samples) == expected_count, (len(samples), expected_count)
    pages = page_cases(len(samples), all_pages)
    compared, compared_images, compared_processes, compared_bindings = {}, {}, {}, {}
    reference_rows, differing_checksums, build_rows = {}, set(), {}
    same_rsds_with_checksum_conflict = set()
    for after, limit in pages:
        # The first call exercises the defaults, subsequent calls explicit paging.
        args = [] if (after, limit) == (0, 64) else ["--limit", limit, "--after", after]
        report = run(exe, etl, pin.upper(), *evidence_args, *args)
        rows = compare(report, pin, size, records, samples, after, limit, threads if join_threads else None, images, processes, reference, builds)
        for row in rows:
            if builds is not None:
                build_rows[row["sample_ordinal"]] = row["build_evidence"]["relation"]
            if reference is not None:
                ref = row["reference_evidence"]
                reference_rows[row["sample_ordinal"]] = (ref["relation"], ref["file_location"])
                fields = ref["loader_fields"]
                if fields and fields["file_name"] and fields["image_size"] and fields["pe_timestamp"] and fields["image_checksum"] is False:
                    differing_checksums.add(row["sample_ordinal"])
                    comparison = row.get("build_evidence", {}).get("reference_comparison")
                    if comparison and all(value is True for value in comparison.values()):
                        same_rsds_with_checksum_conflict.add(row["sample_ordinal"])
            if join_processes:
                compared_processes[row["sample_ordinal"]] = row["process_evidence"]["relation"]
                if join_images:
                    compared_bindings[row["sample_ordinal"]] = row["image_process_evidence"]["relation"]
            if join_images:
                compared_images[row["sample_ordinal"]] = row["image_evidence"]["relation"]
            compared[row["sample_ordinal"]] = row.get("thread_evidence", {}).get("relation")
    if join_processes:
        # All flag orders preserve the two independent evidence requests and the selected page.
        canonical = ["--process-evidence"] + (["--image-evidence"] if join_images else [])
        first = run(exe, etl, pin, *canonical, "--limit", 4)
        for flags in (canonical[::-1], ["--thread-evidence", *canonical], [*canonical[::-1], "--thread-evidence"]):
            assert run(exe, etl, pin, "--after", 0, *flags, "--limit", 4) == first
        if join_images:
            for after, limit in ((0, 4), (len(samples) // 2, 128)):
                compare(run(exe, etl, pin, "--process-evidence", "--after", after, "--limit", limit),
                        pin, size, records, samples, after, limit, threads, None, processes)
        run(exe, etl, pin, "--process-evidence", switches=True, rc=2)
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
        partial = run(exe, trimmed, trimmed_pin, "--limit", 128 if join_processes else 1, *evidence_args, rc=1)
        assert partial["source_sha256"] == trimmed_pin and partial["status"] == "partial"
        assert partial["buffer_comparison"] == "fewer_than_declared"
        assert partial["buffers_processed"] < partial["log_header"]["buffers_written"]
        assert partial["records_seen"] < records
        if join_threads:
            assert all(r["thread_evidence"]["paired_record_pid"] is None for r in partial["samples"])
        if builds is not None:
            assert all(r["build_evidence"]["relation"] == "process_image_unavailable" for r in partial["samples"])
            assert all(p["merge_build"]["relation"] == "coverage_unqualified" for p in partial["image_records"])
        if join_images:
            assert all(r["image_evidence"]["reported_rva"] is None for r in partial["samples"])
        if join_processes:
            assert all(r["process_evidence"]["recorded_generation"] is None for r in partial["samples"])
            if reference is not None:
                assert all(r["reference_evidence"]["reference_window"] is None for r in partial["samples"])
                surviving = [n for n, (_, location) in reference_rows.items()
                             if location == "executable_file_bytes" and n <= partial["decoded_samples"]]
                if surviving:
                    checked = set()
                    for offset in sorted({(n - 1) // 128 * 128 for n in surviving}):
                        clipped = run(exe, trimmed, trimmed_pin, "--after", offset, "--limit", 128, *evidence_args, rc=1)
                        assert clipped["status"] == "partial"
                        for row in clipped["samples"]:
                            n = row["sample_ordinal"]
                            assert row["record_ordinal"] == samples[n - 1][0]
                            assert row["reference_evidence"]["reference_window"] is None
                            if reference_rows.get(n, (None, None))[1] == "executable_file_bytes":
                                checked.add(n)
                    assert checked == set(surviving)
                    print("Former reference windows withheld on the clipped trace:", len(checked))
            if join_images:
                assert all(r["image_process_evidence"]["reported_rva"] is None for r in partial["samples"])
    assert run(exe, etl, pin, *evidence_args, "--after", len(samples) + 1, rc=1)["status"] == "cursor_out_of_range"
    wrong = ("0" if pin[0] != "0" else "1") + pin[1:]
    assert run(exe, etl, wrong, *evidence_args, rc=1)["status"] == "digest_mismatch"
    for args in (("--after", "-1"), ("--limit", 0), ("--limit", 129), ("--after", "01"),
                 ("--after", 1, "--after", 2), ("--limit", "1", "--limit", "2"), ("--thread-evidence", "--thread-evidence"),
                 ("--image-evidence", "--image-evidence"), ("--process-evidence", "--process-evidence"), ("--build-evidence", "--build-evidence")):
        run(exe, etl, pin, *args, rc=2)
    bad = folder / "invalid.etl"
    bad.write_bytes(b"invalid test input")
    bad_pin = hashlib.sha256(bad.read_bytes()).hexdigest()
    assert run(exe, bad, bad_pin, rc=1)["status"] in ("open_trace_failed", "process_trace_failed")
    missing = folder / "missing.etl"
    assert run(exe, missing, pin, rc=1)["status"] == "source_unavailable"
    check_directory_lease(exe, etl, pin, folder, options=evidence_args)
    check_output_alias(exe, "--etl-profile", etl, pin, folder, options=evidence_args)
    if reference is not None:
        reference.controls(exe, etl, pin, folder, run)
        check_directory_lease(exe, etl, pin, reference.path.parent, options=evidence_args, status="reference_unavailable")
        windows = sum(location == "executable_file_bytes" for _, location in reference_rows.values())
        if expected_windows is not None:
            assert windows == expected_windows, (windows, expected_windows)
        print("Reference comparison:", dict(Counter(reference_rows.values())), "file windows:", windows)
        print("Samples with matching name, size and stamp but a different checksum:", len(differing_checksums))
        if builds is not None:
            print("Matching merge GUID, age and stamp despite a loader checksum conflict:", len(same_rsds_with_checksum_conflict))
    if builds is not None:
        print("Merge marker opcodes:", dict(Counter(m["opcode"] for m in builds.by_record.values())),
              "Sample build relations:", dict(Counter(build_rows.values())))
    if join_processes:
        print("Process source:", len(processes.points), "Defunct:", processes.defunct, "Raw process payloads:", processes.raw)
        print("Process relations:", dict(Counter(compared_processes.values())), "Image in process:", dict(Counter(compared_bindings.values())))
    if join_images:
        print("Image events:", len(images.by_ordinal), "Sample relations:", dict(Counter(compared_images.values())))
    if join_threads:
        print("Thread events:", sum(map(len, threads.values())), "Sample relations:", dict(Counter(compared.values())))
    print(f"ETL profile passed. {records} events, {len(samples)} CPU samples, {len(compared)} distinct sample rows compared.")


def complete_switch_coverage(report):
    header = report["log_header"]
    return (report["buffer_comparison"] == "matched" and not report["unsupported_switch_records"] and
            not (header["buffers_lost"] or header["events_lost"] or report["loss_marker_records"]))


def exercise_switches(exe, etl, pin, expected_count, folder, all_pages, short_tail, intervals):
    with etl.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == pin
    schedule = run_path(str(Path(__file__).with_name("etl_schedule_oracle.py")))["ScheduleOracle"]() if intervals else None
    records, _, _, _, expected = oracle(etl, folder, False, want_switches=True, schedule=schedule)
    if schedule is not None:
        schedule.prepare()
    flags = ["--intervals"] if intervals else []
    run_counts, off_counts, ready_counts = Counter(), Counter(), Counter()
    migrated = 0
    assert len(expected) == expected_count, (len(expected), expected_count)
    compared = set()
    for after, limit in page_cases(expected_count, all_pages):
        options = [] if (after, limit) == (0, 64) else ["--limit", limit, "--after", after]
        report = run(exe, etl, pin, *flags, *options, switches=True)
        assert report["status"] == "read" and report["source_sha256"] == pin and report["source_bytes"] == etl.stat().st_size
        assert (report["provider_guid"], report["event_id"], report["opcode"], report["versions"]) == (
            "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c", 0, 36, [2, 3, 4])
        assert (report["records_seen"], report["decoded_switches"], report["unsupported_switch_records"]) == (records, expected_count, 0)
        assert "samples" not in report and report["after"] == after
        assert report["next_after"] == (after + limit if after + limit < expected_count else None)
        qualification = dict(producer_authenticity="unverified", thread_lifetime=None, process_generation=None, wait_time_unit=None,
                             capture_enable_flags=None, capture_privilege=None, stack_capture_policy=None)
        if intervals:
            qualification.update(evidence="reported_scheduler_intervals", wait_object=None, wait_cause=None)
            meta = report["interval_source"]
            clock = report["clock"]
            hz = 10_000_000 if clock["raw_type"] == 2 else int(clock["header_perf_frequency"]) if clock["raw_type"] == 1 else 0
            assert meta == dict(thread_filter=None, matched_switches=expected_count, ticks_per_second=str(hz) if hz > 0 else None,
                                ready_opcode=50, ready_version=2, ready_records=schedule.ready_count, unsupported_ready_records=0,
                                boundary_version=3, thread_boundaries=schedule.boundaries, unsupported_thread_boundaries=0,
                                cpu_scope="comparable" if expected else "unobserved", cpus_with_tid_conflict=len(schedule.bad_cpus),
                                cpus_with_clock_conflict=len(schedule.bad_cpu_times), unknown_switch_tid=schedule.unknown_tid,
                                scheduler_clock_reversed=schedule.reversed_clock)
        else:
            qualification.update(evidence="reported_context_switch", wait_duration=None)
            assert "interval_source" not in report
        assert report["qualification"] == qualification
        header = report["log_header"]
        assert header["events_lost"] >= 0 and header["buffers_lost"] >= 0 and report["loss_marker_records"] >= 0
        if report["buffer_comparison"] == "matched":
            assert report["buffers_processed"] == header["buffers_written"]
        else:
            assert report["buffer_comparison"] == "not_comparable"
        rows = report["switches"]
        covered = complete_switch_coverage(report)
        assert len(rows) == len(expected[after:after + limit])
        for seq, row in enumerate(rows, after + 1):
            fields = (row["record_ordinal"], int(row["raw_timestamp"]), row["cpu"], row["header_process_id"], row["header_thread_id"],
                      int(row["event_keyword"], 0), row["event_channel"], row["event_level"], row["event_task"], row["version"],
                      row["new_thread_id"], row["old_thread_id"], row["new_priority"], row["old_priority"], row["previous_c_state"],
                      row["spare_byte"], row["old_wait_reason"], row["old_wait_mode"], row["thread_flags"], row["old_state"],
                      row["old_wait_ideal_processor"], row["new_wait_time"], row["reserved_field"])
            assert row["switch_ordinal"] == seq and fields == expected[seq - 1], ("switch field mismatch", seq,
                [i for i, pair in enumerate(zip(fields, expected[seq - 1])) if pair[0] != pair[1]])
            assert row["cpu_field"] == ("processor_index" if row["header_flags"] & 0x200 else "processor_number")
            assert row["pointer_bytes"] in (4, 8) and 0 <= row["stack_extension_items"] <= row["extended_data_items"]
            if intervals:
                assert row["match_ordinal"] == seq
                on, off, ready = schedule.compare(row, hz > 0, covered)
                if seq not in compared:
                    run_counts[on] += 1
                    off_counts[off] += 1
                    ready_counts[ready] += 1
                    if off == "off_cpu" and row["off_cpu"]["previous_thread_event"]["cpu"] != row["cpu"]:
                        migrated += 1
            else:
                assert "on_cpu" not in row and "off_cpu" not in row and "match_ordinal" not in row
            compared.add(seq)
    if intervals:
        workload_tids = Counter(r[10] for r in expected if r[10] not in (0, 0xffffffff))
        probes = {0, 0xffffffff}
        if workload_tids:
            probes.add(workload_tids.most_common(1)[0][0])
        for tid in probes:
            ordinals = [n for n, r in enumerate(expected, 1) if tid in r[10:12]]
            for after in {0, len(ordinals) // 2, max(0, len(ordinals) - 4), len(ordinals)}:
                args = ("--thread-id", tid, "--after", after, "--limit", 8)
                page = run(exe, etl, pin, *args, switches=True)
                assert page == run(exe, etl, pin, "--intervals", *args, switches=True)
                if after == 0:
                    assert page == run(exe, etl, pin, *args, "--intervals", switches=True)
                assert page["interval_source"]["thread_filter"] == tid and page["interval_source"]["matched_switches"] == len(ordinals)
                assert page["next_after"] == (after + 8 if after + 8 < len(ordinals) else None)
                assert [r["switch_ordinal"] for r in page["switches"]] == ordinals[after:after + 8]
                for match, row in enumerate(page["switches"], after + 1):
                    assert row["match_ordinal"] == match
                    schedule.compare(row, page["interval_source"]["ticks_per_second"] is not None, complete_switch_coverage(page))
            assert run(exe, etl, pin, "--thread-id", tid, "--after", len(ordinals) + 1, switches=True, rc=1)["status"] == "cursor_out_of_range"
        for args in (("--intervals", "--intervals"), ("--thread-id",), ("--thread-id", "01"), ("--thread-id", "-1"),
                     ("--thread-id", "4294967296"), ("--thread-id", 0, "--thread-id", 0)):
            run(exe, etl, pin, *args, switches=True, rc=2)
        for args in (("--intervals",), ("--thread-id", 1)):
            run(exe, etl, pin, *args, rc=2)
        print("On-CPU", dict(run_counts), "Off-CPU", dict(off_counts), "Readiness", dict(ready_counts), "Changed CPU", migrated)
    if all_pages:
        assert len(compared) == expected_count
    if short_tail:
        trimmed = folder / "short-tail.etl"
        shutil.copyfile(etl, trimmed)
        with trimmed.open("r+b") as out:
            out.truncate(etl.stat().st_size - 1)
        with trimmed.open("rb") as f:
            short_pin = hashlib.file_digest(f, "sha256").hexdigest()
        partial = run(exe, trimmed, short_pin, *flags, "--limit", 128, switches=True, rc=1)
        assert partial["status"] == "partial" and partial["buffer_comparison"] == "fewer_than_declared"
        assert partial["buffers_processed"] < partial["log_header"]["buffers_written"] and partial["records_seen"] < records
    wrong = ("0" if pin[0] != "0" else "1") + pin[1:]
    if short_tail and intervals:
        assert all(r["on_cpu"]["elapsed_ticks"] is None and r["off_cpu"]["elapsed_ticks"] is None and
                   r["off_cpu"]["readiness"]["ready_to_switch_in_ticks"] is None for r in partial["switches"])
    assert run(exe, etl, wrong, *flags, switches=True, rc=1)["status"] == "digest_mismatch"
    assert run(exe, etl, pin, *flags, "--after", expected_count + 1, switches=True, rc=1)["status"] == "cursor_out_of_range"
    assert run(exe, folder / "missing.etl", pin, *flags, switches=True, rc=1)["status"] == "source_unavailable"
    for options in (("--thread-evidence",), ("--image-evidence",), ("--limit", 0), ("--limit", 129), ("--after", "-1")):
        run(exe, etl, pin, *options, switches=True, rc=2)
    check_directory_lease(exe, etl, pin, folder, switches=True, options=flags)
    check_output_alias(exe, "--etl-switches", etl, pin, folder, options=flags)
    print(f"ETL switches passed. {records} events, {expected_count} switches, {len(compared)} distinct switch rows compared.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--etl", type=Path, required=True, help="Saved trace for the independent decoder")
    parser.add_argument("--sha256", required=True)
    counts = parser.add_mutually_exclusive_group(required=True)
    counts.add_argument("--expect-samples", type=int)
    counts.add_argument("--expect-switches", type=int, help="Check the standalone saved context-switch command")
    parser.add_argument("--thread-evidence", action="store_true", help="Compare the source-local thread records for each sample")
    parser.add_argument("--image-evidence", action="store_true", help="Compare same-process image ranges and their source records")
    parser.add_argument("--process-evidence", action="store_true", help="Check process lifetimes and optional image brackets for each sample")
    parser.add_argument("--build-evidence", action="store_true", help="Check original merge marker payloads at both image boundaries")
    parser.add_argument("--reference-image", nargs=2, metavar=("LOCAL_PE", "PE_SHA256"), help="Check an explicit PE against ETL image records and the raw file bytes")
    parser.add_argument("--expect-reference-windows", type=int, help="Require this number of distinct samples with a verified file window on --all-pages")
    parser.add_argument("--intervals", action="store_true", help="Compare CPU, off-CPU and ReadyThread boundaries for each switch")
    parser.add_argument("--all-pages", action="store_true", help="Compare every decoded sample or switch in 128-row pages")
    parser.add_argument("--check-short-tail", action="store_true",
                        help="For fixtures with a populated last buffer, require detection after removing its last byte")
    args = parser.parse_args()
    if args.expect_reference_windows is not None and (not args.reference_image or not args.all_pages or args.expect_reference_windows < 0):
        parser.error("Expected reference windows require --reference-image and --all-pages.")
    if args.intervals and args.expect_switches is None:
        parser.error("Interval checks require --expect-switches.")
    if args.expect_switches is not None and (args.thread_evidence or args.image_evidence or args.process_evidence or args.reference_image or args.build_evidence):
        parser.error("Thread, process and image joins apply to sampled profiles.")
    with tempfile.TemporaryDirectory(prefix="kn-etl-profile-") as directory:
        folder = Path(directory)
        (folder / "source").mkdir()
        etl = folder / "source" / "input.etl"
        shutil.copyfile(args.etl, etl)
        exe = args.exe.resolve(strict=True)
        if args.expect_switches is not None:
            exercise_switches(exe, etl, args.sha256.lower(), args.expect_switches, folder, args.all_pages, args.check_short_tail, args.intervals)
        else:
            exercise(exe, etl, args.sha256.lower(), args.expect_samples, folder, args.all_pages, args.check_short_tail,
                     args.thread_evidence, args.image_evidence, args.process_evidence, args.reference_image, args.expect_reference_windows, args.build_evidence)


if __name__ == "__main__":
    main()
