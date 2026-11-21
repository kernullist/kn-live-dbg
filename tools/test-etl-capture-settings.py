"""Compare saved ETL settings and their row witnesses with Windows tracerpt on single-logger fixtures."""
import argparse
import bisect
from collections import Counter
import hashlib
import io
import os
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET

PROFILE = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"
HEADER = "68fdd900-4a3e-11d1-84f4-0000f80464e3"
THREAD = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"
LOSS = "6a399ae0-4bc6-4de9-870b-3657f8947e7e"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
TRACE = "{http://schemas.microsoft.com/win/2004/08/events/trace}"
BASE = runpy.run_path(str(Path(__file__).with_name("test-etl-profile.py")))
run = BASE["run"]


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def oracle(etl, folder):
    path = folder / "events.xml"
    tracerpt = Path(os.environ["SystemRoot"]) / "System32/tracerpt.exe"
    subprocess.run([tracerpt, etl, "-o", path, "-of", "XML", "-rts", "-y"], cwd=folder, capture_output=True,
                   check=True, timeout=240)
    settings, samples, switches = [], [], []
    resolution = width = None
    number = 0
    with path.open("rb") as data:
        prefix = data.read(4)
        data.seek(0)
        stream = data if b"\0" in prefix or prefix.startswith((b"\xff\xfe", b"\xfe\xff")) else (
            io.TextIOWrapper(data, encoding="utf-8-sig", errors="replace"))
        events = ET.iterparse(stream, events=("start", "end"))
        _, root = next(events)
        for phase, e in events:
            if phase != "end" or e.tag != NS + "Event":
                continue
            number += 1
            guid = (e.findtext(TRACE + "ExtendedTracingInfo/" + TRACE + "EventGuid") or "").strip("{}").lower()
            if guid in (PROFILE, HEADER, THREAD, LOSS):
                system = e.find(NS + "System")
                op = int(system.findtext(NS + "Opcode"))
                version = int(system.findtext(NS + "Version"))
                event_id = int(system.findtext(NS + "EventID"))
                tick = int(system.find(NS + "TimeCreated").attrib["RawTime"])
                if guid == HEADER and op == 0:
                    fields = {v.attrib["Name"]: v.text for v in e.findall(NS + "EventData/" + NS + "Data")}
                    if "PointerSize" in fields:
                        width = int(fields["PointerSize"], 0)
                        resolution = int(fields["TimerResolution"], 0)
                if guid == PROFILE and op == 46 and version == 2 and event_id == 0:
                    samples.append((number, tick))
                if guid == THREAD and op == 36 and version in (2, 3, 4) and event_id == 0:
                    switches.append((number, tick))
                if (guid == HEADER and op in (5, 32) or guid == PROFILE and op in (72, 73, 74) or
                        guid == LOSS and op in (32, 33, 34)):
                    fields = {v.attrib["Name"]: v.text for v in e.findall(NS + "EventData/" + NS + "Data")}
                    raw = e.findtext(NS + "ProcessingErrorData/" + NS + "EventPayload") or e.findtext(NS + "BinaryEventData")
                    blob = bytes.fromhex(raw) if raw else b""
                    point = dict(record_ordinal=number, raw_timestamp=str(tick), opcode=op, version=version, event_id=event_id,
                                 cpu=int(system.find(NS + "Execution").attrib["ProcessorID"], 0), pointer_bytes=width,
                                 event_keyword=hex(int(system.findtext(NS + "Keywords"), 0)),
                                 event_level=int(system.findtext(NS + "Level") or "0", 0), event_task=int(system.findtext(NS + "Task") or "0", 0),
                                 event_channel=int(system.findtext(NS + "Channel") or "0", 0),
                                 payload_status="envelope_only" if guid == LOSS else "decoded")
                    if guid == HEADER:
                        assert version in (0, 1, 2)
                        values = ([int(fields[f"GroupMask{i}"], 0) for i in range(1, 9)]
                                  if fields else list(struct.unpack_from("<8I", blob)))
                        kernel = (int(fields["KernelEventVersion"], 0) if fields else struct.unpack_from("<I", blob, 32)[0]) if version == 2 else None
                        point.update(kind="group_mask", group_masks=values, kernel_event_version=kernel, payload_bytes=36 if version == 2 else 32)
                    elif guid == PROFILE:
                        assert version in (2, 3)
                        values = ([int(fields[k], 0) for k in ("Source", "NewInterval", "OldInterval")]
                                  if fields else struct.unpack_from("<3I", blob))
                        label = None
                        if version == 3:
                            if fields:
                                label = fields["SourceName"] or ""
                            else:
                                decoded = blob[12:].decode("utf-16-le")
                                assert decoded.endswith("\0") and "\0" not in decoded[:-1]
                                label = decoded[:-1]
                            assert "\ufffd" not in label
                        point.update(kind="profile_interval", profile_source=values[0], new_interval_raw=values[1],
                                     old_interval_raw=values[2], profile_source_name=label,
                                     payload_bytes=12 if label is None else 14 + len(label.encode("utf-16-le")))
                    else:
                        point.update(kind="loss_indication", payload_bytes=len(blob))
                    settings.append(point)
            e.clear()
            root.clear()
    path.unlink()
    assert width in (4, 8) and resolution is not None
    return settings, samples, switches, resolution, number


class History:
    def __init__(self, events, timer):
        self.timer = timer
        opening, closing = (73, 74) if timer else (5, 32)
        self.points = [e for e in events if (e["kind"] == "profile_interval" and e["profile_source"] == 0
                                             if timer else e["kind"] == "group_mask")]
        self.ordinals = [p["record_ordinal"] for p in self.points]
        ticks = [int(p["raw_timestamp"]) for p in self.points]
        self.ordered = all(a < b for a, b in zip(ticks, ticks[1:]))
        boundaries = [p for p in self.points if p["opcode"] in (opening, closing)]
        adjacent = list(zip(boundaries, boundaries[1:]))
        self.ambiguous = any(a["opcode"] == b["opcode"] for a, b in adjacent)
        self.pairs = [(a["record_ordinal"], b["record_ordinal"]) for a, b in adjacent
                      if a["opcode"] == opening and b["opcode"] == closing]

    def boundaries(self, span):
        return (self.points[bisect.bisect_left(self.ordinals, ordinal)] for ordinal in span)

    def at(self, n, tick, width, coverage, clock):
        pos = bisect.bisect_left(self.ordinals, n)
        a = self.points[pos - 1] if pos else None
        b = self.points[pos] if pos < len(self.points) else None
        span = next(((lo, hi) for lo, hi in self.pairs if lo < n < hi), (None, None))
        if self.ambiguous:
            span = (None, None)
        period = None
        if not coverage:
            relation = "coverage_unqualified"
        elif a is None and b is None:
            relation = "no_records"
        elif (not clock or not self.ordered or a and int(a["raw_timestamp"]) >= tick or b and int(b["raw_timestamp"]) <= tick):
            relation = "clock_unqualified"
        elif self.ambiguous:
            relation = "ambiguous_boundaries"
        elif a is None or b is None:
            relation = "one_boundary"
        elif span[0] is None:
            relation = "outside_recorded_collection"
        elif (any(p["pointer_bytes"] != width for p in (a, b, *self.boundaries(span))) or
              len({p["version"] for p in (a, b, *self.boundaries(span))}) != 1):
            relation = "setting_layout_conflict"
        elif not self.timer:
            relation = ("equal_group_snapshots" if all(a[k] == b[k] for k in ("group_masks", "kernel_event_version", "version"))
                        else "group_snapshots_differ")
        elif len({p["profile_source_name"] for p in (a, b, *self.boundaries(span))}) != 1:
            relation = "profile_source_name_conflict"
        else:
            endpoints_agree = all(p["old_interval_raw"] == p["new_interval_raw"] for p in self.boundaries(span))
            agreed_value = a["new_interval_raw"]
            if endpoints_agree and agreed_value and agreed_value == b["old_interval_raw"]:
                period = agreed_value
                relation = "recorded_timer_interval"
            else:
                relation = "interval_values_unresolved"
        result = dict(relation=relation, before_record=a and a["record_ordinal"], after_record=b and b["record_ordinal"])
        if self.timer:
            result.update(collection_start_record=span[0], collection_end_record=span[1], reported_period_100ns=period)
        return result


def check_manifest(page, points, resolution):
    manifest = page["capture_settings"]
    counts = Counter(p["kind"] for p in points)
    assert {k: v for k, v in manifest.items() if k != "records"} == dict(
        scope="saved_file_logger_records", original_session_id=None, mask_provider=HEADER, interval_provider=PROFILE,
        loss_provider=LOSS, header_timer_resolution_100ns=resolution, group_mask_records=counts["group_mask"],
        profile_interval_records=counts["profile_interval"], loss_indications=counts["loss_indication"],
        unsupported_group_masks=0, unsupported_profile_intervals=0, retained_records=len(points), retention="complete")
    assert page["loss_marker_records"] == counts["loss_indication"]
    assert page["qualification"]["capture_enable_flags"] is None and page["qualification"]["stack_capture_policy"] is None
    assert page["qualification"]["capture_privilege"] is None and page["qualification"]["producer_authenticity"] == "unverified"
    assert len(manifest["records"]) == len(points)
    for actual, expected in zip(manifest["records"], points):
        assert {k: v for k, v in actual.items() if k not in ("cpu_field", "header_flags", "logger_id")} == expected
        assert actual["cpu_field"] == ("processor_index" if actual["header_flags"] & 0x200 else "processor_number")
        assert actual["header_flags"] & 0x100 and actual["header_flags"] & 0x60 == (0x40 if expected["pointer_bytes"] == 8 else 0x20)


def compare_mode(exe, etl, pin, points, rows, resolution, total, switches, args, folder):
    histories = (History(points, False), History(points, True))
    name = "switches" if switches else "samples"
    number = "switch_ordinal" if switches else "sample_ordinal"
    outcomes = {}
    flags = ["--capture-settings"]
    for after, limit in dict.fromkeys(BASE["page_cases"](len(rows), args.all_pages)):
        page = run(exe, etl, pin, *flags, "--after", after, "--limit", limit, switches=switches)
        check_manifest(page, points, resolution)
        assert page["records_seen"] == total and page["after"] == after and page["status"] == "read"
        assert page["decoded_" + name] == len(rows)
        assert page["next_after"] == (after + limit if after + limit < len(rows) else None)
        header, clock = page["log_header"], page["clock"]
        complete = page["buffer_comparison"] == "matched" and not (header["events_lost"] or header["buffers_lost"] or page["loss_marker_records"])
        valid_clock = clock["raw_type"] == 2 or clock["raw_type"] == 1 and int(clock["header_perf_frequency"]) > 0
        expected = rows[after:after + limit]
        assert len(page[name]) == len(expected)
        # tracerpt omits logger IDs. The public fixtures for this check have one
        # logger ID on their returned rows and settings. Native tests cover collisions.
        logger_ids = {r["logger_id"] for r in page[name] + page["capture_settings"]["records"]}
        assert len(logger_ids) <= 1
        for seq, (r, (n, tick)) in enumerate(zip(page[name], expected), after + 1):
            assert (r[number], r["record_ordinal"], int(r["raw_timestamp"])) == (seq, n, tick)
            mask = histories[0].at(n, tick, r["pointer_bytes"], complete, valid_clock)
            evidence = dict(group_mask_bracket=mask)
            period = None
            if not switches:
                timer = histories[1].at(n, tick, r["pointer_bytes"], complete, valid_clock)
                evidence["timer_bracket"] = timer
                period = timer["reported_period_100ns"]
            assert r["capture_setting_evidence"] == evidence, (name, seq, evidence)
            outcomes[seq] = (mask["relation"], period)
    if args.all_pages:
        assert len(outcomes) == len(rows)
    timed = sum(period is not None for _, period in outcomes.values())
    if not switches and args.expect_timed_samples is not None:
        assert timed == args.expect_timed_samples, (timed, args.expect_timed_samples)
    combinations = [["--intervals"], ["--thread-id", 0]] if switches else [
        ["--thread-evidence"], ["--process-evidence", "--image-evidence"], ["--build-evidence"]]
    if not switches and args.reference_image:
        combinations.append(["--build-evidence", "--reference-image", args.reference_image[0], args.reference_image[1]])
    for options in [[], *combinations]:
        baseline = run(exe, etl, pin, *options, "--limit", 4, switches=switches)
        combined = run(exe, etl, pin, *options, *flags, "--limit", 4, switches=switches)
        assert run(exe, etl, pin, *flags, *options, "--limit", 4, switches=switches) == combined
        combined["schema"] = baseline["schema"]
        del combined["capture_settings"]
        for r in combined[name]:
            del r["capture_setting_evidence"]
        assert combined == baseline
    alias_dir = folder / ("switch-alias" if switches else "sample-alias")
    alias_dir.mkdir()
    BASE["check_output_alias"](exe, "--etl-switches" if switches else "--etl-profile", etl, pin, alias_dir, options=flags)
    run(exe, etl, pin, *flags, *flags, switches=switches, rc=2)
    assert run(exe, etl, "0" * 64, *flags, switches=switches, rc=1)["status"] == "digest_mismatch"
    assert run(exe, etl, pin, *flags, "--after", len(rows) + 1, switches=switches, rc=1)["status"] == "cursor_out_of_range"
    if args.check_short_tail:
        trimmed = folder / "short.etl"
        if not trimmed.exists():
            shutil.copyfile(etl, trimmed)
            with trimmed.open("r+b") as f:
                f.truncate(etl.stat().st_size - 1)
        valid = [seq for seq, (relation, period) in outcomes.items() if period or relation == "equal_group_snapshots"]
        offsets = {0, *((valid[i] - 1) // 128 * 128 for i in (0, len(valid) // 2, -1))} if valid else {0}
        survived = 0
        short_pin = digest(trimmed)
        for offset in sorted(offsets):
            clipped = run(exe, trimmed, short_pin, *flags, "--after", offset, "--limit", 128, switches=switches, rc=1)
            assert clipped["status"] == "partial" and clipped["buffer_comparison"] == "fewer_than_declared"
            for row in clipped[name]:
                evidence = row["capture_setting_evidence"]
                assert all(value["relation"] == "coverage_unqualified" for value in evidence.values())
                assert switches or evidence["timer_bracket"]["reported_period_100ns"] is None
                seq = row[number]
                same_record = 0 < seq <= len(rows) and rows[seq - 1] == (row["record_ordinal"], int(row["raw_timestamp"]))
                if same_record and seq in outcomes and (outcomes[seq][0] == "equal_group_snapshots" or outcomes[seq][1] is not None):
                    survived += 1
        if valid:
            assert survived, "clipped-page check needs a surviving, previously qualified source record"
        print(name, "previously qualified rows checked on clipped pages:", survived)
    print(name, "distinct rows:", len(outcomes), "mask relations:", dict(Counter(v[0] for v in outcomes.values())),
          "timer periods (100 ns):", dict(Counter(v[1] for v in outcomes.values() if v[1] is not None)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--etl", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--all-pages", action="store_true")
    parser.add_argument("--check-short-tail", action="store_true")
    parser.add_argument("--expect-timed-samples", type=int)
    parser.add_argument("--reference-image", nargs=2, metavar=("LOCAL_PE", "SHA256"))
    args = parser.parse_args()
    if args.expect_timed_samples is not None and (not args.all_pages or args.expect_timed_samples < 0):
        parser.error("--expect-timed-samples requires --all-pages and a nonnegative count")
    pin = args.sha256.lower()
    with tempfile.TemporaryDirectory(prefix="kn-etl-settings-") as tmp:
        folder = Path(tmp)
        etl = folder / "owned-input.etl"
        shutil.copyfile(args.etl, etl)
        assert digest(etl) == pin
        points, samples, switches, resolution, total = oracle(etl, folder)
        print("Original records:", total, "settings:", dict(Counter(p["kind"] for p in points)))
        exe = args.exe.resolve(strict=True)
        compare_mode(exe, etl, pin, points, samples, resolution, total, False, args, folder)
        compare_mode(exe, etl, pin, points, switches, resolution, total, True, args, folder)


if __name__ == "__main__":
    main()
