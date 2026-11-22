"""Check the paired activity CLI against Windows ETW/TDH on the pinned PerfView and TaskbarLatency fixtures."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
CLI = HERE / "compare-etl-activities.py"
COMPARE = runpy.run_path(str(CLI))
WINDOW = runpy.run_path(str(HERE / "test-etl-activity-window.py"))
PINS = ("50da7f725f80f88a7622b37f9826844a790cb0c4f64e351fa1f38cf24916889a",
        "18e62d477308bdc9b01ca6674cbbcbb7c350acf2bf68733ba6361976fac9538d",
        "8a59fa63479e49d68fc9bf878f1960313ce2ee179f30ee14655973a5bd7ec3d5")


def pin(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def fraction(value):
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def witness(oracle, query, side):
    path, source_pin, start, stop = query
    assert side["source_sha256"] == side["observed_sha256"] == source_pin
    page = side["page"]
    footer, faults, groups, threads = WINDOW["read_oracle"](oracle, path)
    by_record = {e["record_ordinal"]: e for group in groups.values() for e in group}
    a, b = by_record[start], by_record[stop]
    w = page["activity_window"]
    assert (w["start"], w["stop"]) == (a, b)
    left, right = WINDOW["lifetime"](a, b, threads)
    assert (w["thread_evidence"]["before"]["record_ordinal"], w["thread_evidence"]["after"]["record_ordinal"]) == (
        left["record_ordinal"], right["record_ordinal"])
    rows, covered = WINDOW["intersection"](a, b, faults)
    assert [edge["record_ordinal"] for edge in w["overlaps"]] == [f["record_ordinal"] for f, *_ in rows]
    assert int(w["fault_union_ticks"]) == covered and footer["records_seen"] == page["records_seen"]
    assert footer["clock_type"] == 1 and int(page["clock"]["header_perf_frequency"]) == footer["frequency"]
    scale = Fraction(1_000_000_000, footer["frequency"])
    return (WINDOW["tick"](b) - WINDOW["tick"](a)) * scale, covered * scale


def copy_header(query, side, folder, name, offset, fmt, value):
    path, _, a, b = query
    data = bytearray(path.read_bytes())
    page = side["page"]
    signature = struct.pack("<qqII", int(page["clock"]["header_perf_frequency"]),
                            int(page["log_header"]["start_filetime"]), 1, 0)
    head = data[:512]
    assert head.count(signature) == 1
    struct.pack_into("<" + fmt, data, head.index(signature) + offset, value)
    other = folder / name
    other.write_bytes(data)
    return other, pin(other), a, b


def projection_controls(query, side, other):
    project = COMPARE["project"]
    selection = COMPARE["Selection"](*query)
    page, size = side["page"], side["source_bytes"]
    for where, key, value in (((), "provider_guid", "wrong"), ((), "source_sha256", "0" * 64), ((), "source_bytes", size - 1),
                              ((), "decoded_hard_faults", 0),
                              (("activity_window", "start"), "record_ordinal", query[2] - 1),
                              (("activity_window", "stop"), "header_flags", 0x100),
                              (("activity_window", "stop"), "event_property", 2),
                              (("activity_window",), "window_ticks", "1"),
                              (("activity_window",), "fault_union_ticks", "1"),
                              (("log_header",), "events_lost", True)):
        changed = deepcopy(page)
        target = changed
        for member in where:
            target = target[member]
        target[key] = value
        try:
            project(changed, selection, size, 0)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted an inconsistent {key}")
    bounded = deepcopy(page)
    w = bounded["activity_window"]
    w.update(status="thread_bracket_unqualified", fault_union_ticks=None)
    try:
        project(bounded, selection, size, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("a rejected window yielded a duration")
    w.update(status="fault_family_unobserved_on_logger", decoded_faults_on_start_logger=0)
    measured = project(bounded, selection, size, 0)
    assert measured.fault_ns is None
    candidate = COMPARE["Selection"](Path("candidate.etl"), other["source_sha256"], other["requested_start_record"], other["requested_stop_record"])
    qualified = project(other["page"], candidate, other["source_bytes"], 0)
    result = COMPARE["comparison"]((side, measured), (other, qualified))
    assert result["status"] == "duration_only" and fraction(result["activity_duration"]["candidate_minus_baseline_ns"]) == 2430400
    assert result["observed_hard_fault_union"]["candidate_minus_baseline_ns"] is None
    for endpoint, key in (("start", "version"), ("stop", "version"), ("start", "event_id"), ("stop", "event_id")):
        different = deepcopy(other["page"])
        different["activity_window"][endpoint][key] += 1
        value = project(different, candidate, other["source_bytes"], 0)
        result = COMPARE["comparison"]((side, measured), (other, value))
        assert result["status"] == "descriptor_mismatch" and result["activity_duration"]["candidate_minus_baseline_ns"] is None
    extreme = deepcopy(page)
    last = (1 << 63) - 1
    w = extreme["activity_window"]
    w["thread_evidence"]["before"]["raw_timestamp"] = "-1"
    w["start"]["raw_timestamp"], w["stop"]["raw_timestamp"] = "1", str(last - 1)
    w["window_ticks"], w["thread_evidence"]["after"]["raw_timestamp"] = str(last - 2), str(last)
    extreme["clock"]["header_perf_frequency"] = "7"
    assert project(extreme, selection, size, 0).duration_ns == Fraction((last - 2) * 10**9, 7)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "oracle", "x64", "x86", "taskbar"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    paths = [p.resolve() for p in (args.x64, args.x86, args.taskbar)]
    assert tuple(map(pin, paths)) == PINS
    x64, x86, taskbar = [(p, h, a, b) for p, h, (a, b) in
                         zip(paths, PINS, ((135036, 135051), (122133, 122302), (339732, 374019)), strict=True)]
    common = [sys.executable, "-B", CLI, "--exe", args.exe.resolve(), "--exe-sha256", pin(args.exe).upper()]

    def command(a, b):
        return [*common, "--baseline", *map(str, a), "--candidate", *map(str, b)]

    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)

        def acquire(a, b, name, status, code):
            destination = folder / name
            result = subprocess.run([*command(a, b), "--output", destination], capture_output=True, timeout=240)
            assert result.returncode == code, (result.stdout, result.stderr)
            receipt = json.loads(result.stdout)
            assert receipt["status"] == "written" and receipt["report_sha256"] == pin(destination)
            report = json.loads(destination.read_bytes())
            assert receipt["comparison_status"] == report["comparison"]["status"] == status
            return report, receipt

        report, receipt = acquire(x64, x86, "pair.json", "compared", 0)
        assert all(report["qualification"][key] is None for key in ("equivalent_workload", "cause_of_change", "population_regression"))
        for role, query in (("baseline", x64), ("candidate", x86)):
            side = report[role]
            expected = witness(args.oracle, query, side)
            for key, value in zip(("activity_duration", "observed_hard_fault_union"), expected, strict=True):
                assert fraction(report["comparison"][key][role + "_ns"]) == value
            raw = subprocess.check_output([args.exe, *WINDOW["selector"](query[0], query[1], *query[2:])], timeout=180)
            assert side["reader"]["stdout_sha256"] == hashlib.sha256(raw).hexdigest() and json.loads(raw) == side["page"]
        metric = report["comparison"]["activity_duration"]
        assert fraction(metric["candidate_minus_baseline_ns"]) == 2430400 and fraction(metric["relative_change_percent"]) == Fraction(173600, 247)
        assert report["comparison"]["observed_hard_fault_union"]["relative_change_percent"] is None
        for document in (report, receipt, report["comparison"], metric, report["baseline"], report["baseline"]["reader"],
                         report["comparison"]["matched_descriptor"], report["qualification"]):
            WINDOW["private"](document)
        projection_controls(x64, report["baseline"], report["candidate"])
        for expected_pin, code, status in ((receipt["report_sha256"], 0, "matched"), ("0" * 64, 1, "mismatch")):
            r = subprocess.run([*command(x64, x86), "--check-report", expected_pin], capture_output=True, timeout=240)
            assert r.returncode == code and json.loads(r.stdout)["status"] == status
        swapped, _ = acquire(x86, x64, "swapped.json", "compared", 0)
        assert fraction(swapped["comparison"]["activity_duration"]["candidate_minus_baseline_ns"]) == -2430400
        different, _ = acquire(x64, (*x86[:2], 122089, 122123), "different.json", "descriptor_mismatch", 1)
        assert different["comparison"]["activity_duration"]["candidate_minus_baseline_ns"] is None
        alias = folder / "alias.etl"
        alias.hardlink_to(x64[0])
        same, _ = acquire(x64, (alias, *x64[1:]), "same.json", "same_recording", 1)
        assert same["comparison"]["observed_hard_fault_union"]["candidate_minus_baseline_ns"] is None
        for query, outcome in (((folder / "missing.etl", *x86[1:]), "source_unavailable"),
                               ((x86[0], x64[1], *x86[2:]), "source_pin_mismatch"),
                               ((*x86[:3], 2_000_000), "activity_record_not_observed")):
            failed, _ = acquire(x64, query, outcome + ".json", "window_unavailable", 1)
            assert failed["candidate"]["status"] == outcome and failed["baseline"]["status"] == "read"
            assert fraction(failed["comparison"]["activity_duration"]["baseline_ns"]) == 345800
            assert failed["comparison"]["activity_duration"]["candidate_ns"] is None
        loss = copy_header(x86, report["candidate"], folder, "loss.etl", 20, "I", 1)
        partial, partial_receipt = acquire(x64, loss, "partial.json", "window_unavailable", 1)
        assert partial["candidate"]["status"] == "partial" and partial["candidate"]["page"]["activity_window"]["status"] == "coverage_unqualified"
        r = subprocess.run([*command(x64, loss), "--check-report", partial_receipt["report_sha256"]], capture_output=True, timeout=240)
        assert r.returncode == 1 and json.loads(r.stdout)["status"] == "matched"
        base, _ = acquire(taskbar, x64, "taskbar.json", "descriptor_mismatch", 1)
        assert witness(args.oracle, taskbar, base["baseline"]) == (116214900, 1292600)
        shifted = copy_header(taskbar, base["baseline"], folder, "frequency.etl", 0, "q", 7_000_003)
        scaled, _ = acquire(taskbar, shifted, "scaled.json", "compared", 0)
        expected = witness(args.oracle, shifted, scaled["candidate"])
        for key, after, before in zip(("activity_duration", "observed_hard_fault_union"), expected, (116214900, 1292600), strict=True):
            row = scaled["comparison"][key]
            assert fraction(row["candidate_ns"]) == after and fraction(row["candidate_minus_baseline_ns"]) == after - before
        with alias.open("ab") as sink:
            r = subprocess.run([*command(x64, x86), "--help"], stdout=sink, stderr=sink, timeout=30)
        assert r.returncode == 2 and pin(x64[0]) == x64[1]
        original = (folder / "pair.json").read_bytes()
        invalid = [*command(x64, x86), "--output", folder / "pair.json"]
        assert subprocess.run(invalid, capture_output=True, timeout=30).returncode == 2 and (folder / "pair.json").read_bytes() == original
        other_pin = command(x64, x86)
        other_pin[other_pin.index("--exe-sha256") + 1] = "0" * 64
        rejected = folder / "rejected.json"
        assert subprocess.run([*other_pin, "--output", rejected], capture_output=True, timeout=30).returncode == 2 and not rejected.exists()
        failed_reader = folder / "invalid.exe"
        failed_reader.write_bytes(b"invalid executable")
        launch = command(x64, x86)
        launch[launch.index("--exe") + 1] = failed_reader
        launch[launch.index("--exe-sha256") + 1] = pin(failed_reader)
        timed = [*command(taskbar, x86), "--timeout-ms", "1"]
        for invocation, state in ((launch, "launch_error"), (timed, "timed_out")):
            dest = folder / (state + ".json")
            r = subprocess.run([*invocation, "--output", dest], capture_output=True, timeout=60)
            assert r.returncode == 1 and json.loads(r.stdout)["comparison_status"] == "window_unavailable"
            side = json.loads(dest.read_bytes())["baseline"]
            assert side["status"] == "reader_unavailable" and side["reader"]["state"] == state and side["page"] is None
        race = [*command(x64, x86), "--output", folder / "race.json"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            runs = [pool.submit(subprocess.run, race, capture_output=True, timeout=240) for _ in range(2)]
            assert sorted(r.result().returncode for r in runs) == [0, 2]
        assert pin(folder / "race.json") == receipt["report_sha256"] and not list(folder.glob(".kn*"))
    print("Cross-recording durations, fault unions, independent TDH witnesses, exact replay and failure controls passed.")


if __name__ == "__main__":
    main()
