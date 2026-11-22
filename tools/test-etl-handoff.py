"""Check a pinned handoff study against an independent Windows event reader and exercise partial studies."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import statistics
import subprocess
import sys
import tempfile
import zipfile

import etl_handoff as study


HERE = Path(__file__).resolve().parent
CLI = HERE / "measure-etl-handoff.py"
WINDOW = runpy.run_path(str(HERE / "test-etl-activity-window.py"))


def pin(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def invoke(args, code, **kwargs):
    r = subprocess.run([sys.executable, "-B", CLI, *args], capture_output=True, timeout=240, **kwargs)
    assert r.returncode == code, (r.returncode, r.stdout[:500], r.stderr[:500])
    return json.loads(r.stdout) if r.stdout else None


def sweep(left, right):
    changes = sorted([(p, d) for (lo, hi) in (left, right) for p, d in ((lo, 1), (hi, -1))])
    depth = covered = 0
    last = changes[0][0]
    for tick, change in changes:
        if depth == 2:
            covered += tick - last
        depth += change
        last = tick
    return covered


def independent(package, report, oracle, folder):
    cfg = report["plan"]
    by_pair = {}
    with zipfile.ZipFile(package) as archive:
        for row in report["observations"]:
            slot, truth = row["selection"], row["workload"]
            path = folder / "sample.etl"
            path.write_bytes(archive.read(f"slot-{slot['slot']:02d}.etl"))
            assert pin(path) == row["etl_sha256"]
            footer, _, groups, _ = WINDOW["read_oracle"](oracle, path)
            events = sorted((e for group in groups.values() for e in group), key=lambda e: e["record_ordinal"])
            assert [r["event"] for r in row["marker_page"]["markers"]] == events
            assert len(events) == 10 and footer["records_seen"] == row["marker_page"]["records_seen"]
            assert footer["clock_type"] == 1 and footer["frequency"] == int(truth["frequency"])
            t = {e["event_id"]: int(e["raw_timestamp"]) for e in events}
            join, timer = (tuple(map(int, truth[k])) for k in ("join_call", "timer_call"))
            expected = {"activity": t[2]-t[1], "caller_work": t[4]-t[3], "worker_span": t[6]-t[5],
                        "join_call": join[1]-join[0], "timer_call": timer[1]-timer[0],
                        "join_timer_overlap": sweep(join, timer), "work_window_overlap": sweep((t[3], t[4]), (t[5], t[7]))}
            assert {k: int(v) for k, v in row["measurement"]["ticks"].items()} == expected
            assert expected["join_timer_overlap"] <= min(expected["join_call"], expected["timer_call"])
            for seed, name in ((slot["seed"], "caller_result"), (slot["seed"] ^ 0x9e3779b9, "worker_result")):
                for _ in range(cfg["steps"]):
                    seed = (1664525*seed + 1013904223) % 2**32
                assert seed == truth[name]
            by_pair.setdefault(slot["pair"], {})[slot["role"]] = {k: Fraction(v*10**9, footer["frequency"]) for k, v in expected.items()}
    def value(r):
        return Fraction(int(r["numerator"]), int(r["denominator"]))
    for name, distribution in report["changes"].items():
        differences = [p["candidate"][name]-p["baseline"][name] for p in by_pair.values()]
        assert differences == [value(p["candidate_minus_baseline_ns"][name]) for p in report["pairs"]]
        assert (min(differences), statistics.median(differences), max(differences)) == tuple(
            value(distribution[key]) for key in ("minimum_ns", "median_ns", "maximum_ns"))
        assert distribution["longer"] == sum(d > 0 for d in differences) and distribution["equal"] == differences.count(0)
        for role, group in report["by_first_arm"].items():
            subset = [d for p, d in zip(report["pairs"], differences, strict=True) if p["order"][0] == role]
            assert len(subset) == group["planned_pairs"] == group["measured_pairs"]
            assert value(group["changes"][name]["median_ns"]) == statistics.median(subset)
    assert report["planned_pairs"] == report["measured_pairs"] == len(by_pair) and report["status"] == "complete"
    return sum(len(r["marker_page"]["markers"]) for r in report["observations"])


def semantic_controls(report):
    row = report["observations"][0]
    cfg, slot, truth, page = report["plan"], row["selection"], row["workload"], row["marker_page"]
    def assess(t, p, process):
        return study.measure(cfg, slot, row["expected_activity_id"], t, process, p, row["etl_sha256"], page["source_bytes"])
    for key, replacement, reason in (("caller_result", truth["caller_result"] ^ 1, "workload_mismatch"),
                                     ("delay_ms", truth["delay_ms"]+1, "workload_mismatch"),
                                     ("joined_tid", truth["caller_tid"], "process_or_worker_generation_unqualified"),
                                     ("join_call", ["1", "2"], "wait_outside_recorded_dependency"),
                                     ("timer_call", ["2", "1"], "inverted_call_bracket")):
        try:
            assess(dict(truth, **{key: replacement}), page, row["process"])
        except study.Unqualified as e:
            assert str(e) == reason
        else:
            raise AssertionError("accepted inconsistent " + key)
    for where, key, replacement, reason in (
            (["clock"], "header_perf_frequency", "0", "clock_unqualified"),
            (["log_header"], "events_lost", 1, "private_capture_coverage_unqualified"),
            (["markers", 0, "event"], "raw_timestamp", "1", "marker_outside_producer_write"),
            (["markers", 0, "event"], "header_thread_id", 0, "marker_identity_mismatch"),
            (["markers", 0, "event"], "logger_id", 65535, "logger_mismatch"),
            ([], "matched_markers", 9, "incomplete_marker_set")):
        p = deepcopy(page)
        target = p
        for member in where:
            target = target[member]
        target[key] = replacement
        try:
            assess(truth, p, row["process"])
        except study.Unqualified as e:
            assert str(e) == reason
        else:
            raise AssertionError("accepted inconsistent " + key)
    for a, b, expected in (((1, 4), (4, 9), 0), ((0, 10), (2, 6), 4), ((7, 10), (3, 12), 3)):
        assert study.overlap(a, b) == sweep(a, b) == expected
    for field in ("process", "session_id", "etl_sha256"):
        observations = deepcopy(report["observations"])
        identity = observations[0][field]
        observations[1][field] = dict(reversed(list(identity.items()))) if field == "process" else identity
        result = study.summarize(cfg, report["plan_sha256"], report["package_sha256"], report["acquisition_id"],
                                 report["acquisition_environment"], observations)
        assert result["measured_pairs"] == cfg["pairs"]-1
        assert all(r["reason"] == "reused_"+field and r["measurement"] is None for r in observations[:2])


def archive_controls(args, folder, replay, report):
    def repack(target, mutate):
        with zipfile.ZipFile(args.package) as archive:
            parts = {name: archive.read(name) for name in archive.namelist()}
        document = json.loads(parts["handoff-outcomes.json"])
        mutate(parts, document["outcomes"])
        parts["handoff-outcomes.json"] = study.encoded(document)
        with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_STORED) as archive:
            for name, raw in parts.items():
                archive.writestr(name, raw)
        flags = list(replay)
        flags[flags.index("--package")+1], flags[flags.index("--sha256")+1] = target, pin(target)
        return flags

    def lost(parts, outcomes):
        parts.pop("slot-01.etl")
        outcomes[0].update(retention="not_located", source_bytes=None, source_sha256=None)

    limited = repack(folder/"partial.zip", lost)
    output = folder/"partial.json"
    receipt = invoke([*limited, "--output", output], 1)
    result = json.loads(output.read_bytes())
    assert result["measured_pairs"] == report["planned_pairs"]-1 and result["unavailable_pairs"] == 1
    assert result["observations"][0]["reason"] == "not_located" and result["observations"][1]["measurement"] is not None
    assert result["pairs"][0]["candidate_minus_baseline_ns"] is None
    assert invoke([*limited, "--check-report", receipt["report_sha256"]], 1)["status"] == "matched"
    def reversed_order(_parts, outcomes):
        outcomes[0], outcomes[1] = outcomes[1], outcomes[0]
    def bad_binding(_parts, outcomes):
        outcomes[0]["attempt"]["image_binding"]["win32_status"] = False
    def extra(parts, _outcomes):
        parts["unexpected.txt"] = b"extra"
    def changed_etl(parts, _outcomes):
        raw = parts["slot-01.etl"]
        parts["slot-01.etl"] = raw[:-1] + bytes([raw[-1] ^ 1])
    target = folder/"rejected.json"
    for mutate in (reversed_order, bad_binding, extra, changed_etl):
        flags = repack(folder/(mutate.__name__+".zip"), mutate)
        assert invoke([*flags, "--output", target], 2) is None and not target.exists()
    wrong_pin = "0"*64
    for option in ("--sha256", "--plan-sha256"):
        flags = list(replay)
        flags[flags.index(option)+1] = wrong_pin
        assert invoke([*flags, "--output", target], 2) is None and not target.exists()
    assert invoke([*replay, "--check-report", wrong_pin], 1)["status"] == "mismatch"
    source = folder/"sink.zip"
    shutil.copyfile(args.package, source)
    alias = folder/"sink-alias.zip"
    alias.hardlink_to(source)
    with alias.open("ab") as stream:
        result = subprocess.run([sys.executable, "-B", CLI, "--help", "--package", source], stdout=stream, stderr=stream, timeout=30)
    assert result.returncode == 2 and pin(source) == args.sha256
    race = [sys.executable, "-B", CLI, *replay, "--output", folder/"race.json"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(subprocess.run, race, capture_output=True, timeout=240) for _ in range(2)]
        assert sorted(p.result().returncode for p in pending) == [0, 2]
    assert pin(folder/"race.json") == pin(folder/"report.json") and not list(folder.glob(".kn*"))


def acquisition_controls(args, folder):
    def register(label, image):
        path = folder/(label+"-plan.json")
        receipt = invoke(["plan", "--pairs", "2", "--baseline-ms", "0", "--candidate-ms", "0", "--steps", "29",
                          "--recorder-sha256", pin(image), "--exe-sha256", pin(args.exe), "--output", path], 0)
        assert receipt["plan_sha256"] == pin(path)
        return path

    def acquire(label, image, plan, code):
        archive = folder/(label+".zip")
        receipt = invoke(["capture", "--recorder", image, "--plan", plan, "--plan-sha256", pin(plan), "--output", archive], code)
        assert receipt["package_sha256"] == pin(archive) and receipt["planned_arms"] == 4
        return archive

    def assess(label, archive, plan, code):
        path = folder/(label+"-report.json")
        invoke(["replay", "--package", archive, "--sha256", pin(archive), "--plan-sha256", pin(plan),
                "--exe", args.exe, "--output", path], code)
        return json.loads(path.read_bytes())

    plan = register("repeat", args.recorder)
    first, again = (acquire(label, args.recorder, plan, 0) for label in ("first", "again"))
    a, b = (assess(label, archive, plan, 0) for label, archive in (("first", first), ("again", again)))
    assert a["acquisition_id"] != b["acquisition_id"] and a["plan"] == b["plan"]
    assert {r["expected_activity_id"] for r in a["observations"]}.isdisjoint(r["expected_activity_id"] for r in b["observations"])
    mixed = folder/"mixed.zip"
    with zipfile.ZipFile(first) as original, zipfile.ZipFile(mixed, "x", compression=zipfile.ZIP_STORED) as output:
        for name in original.namelist():
            raw = original.read(name)
            if name == "handoff-outcomes.json":
                doc = json.loads(raw)
                doc["acquisition_id"] = b["acquisition_id"]
                raw = study.encoded(doc)
            output.writestr(name, raw)
    rejected = assess("mixed", mixed, plan, 1)
    assert rejected["measured_pairs"] == 0 and all(r["reason"] == "workload_identity_mismatch" for r in rejected["observations"])
    invalid = folder/"invalid.exe"
    invalid.write_bytes(b"invalid Windows executable")
    bad_plan = register("launch", invalid)
    refused = folder/"wrong-recorder.zip"
    assert invoke(["capture", "--recorder", args.recorder, "--plan", bad_plan, "--plan-sha256", pin(bad_plan), "--output", refused], 2) is None
    assert not refused.exists()
    failed = assess("launch", acquire("launch", invalid, bad_plan, 1), bad_plan, 1)
    assert failed["planned_pairs"] == failed["unavailable_pairs"] == 2 and failed["measured_pairs"] == 0
    assert all(r["recorder"]["state"] == "launch_error" and r["measurement"] is None for r in failed["observations"])
    assert all(v["median_ns"] is None for v in failed["changes"].values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("--exe", "--oracle", "--package"):
        parser.add_argument(flag, required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--recorder", type=Path, help="include new same-plan acquisitions and actual failed launches")
    parser.add_argument("--check-controls", action="store_true")
    args = parser.parse_args()
    replay = ["replay", "--package", args.package, "--sha256", args.sha256, "--plan-sha256", args.plan_sha256, "--exe", args.exe]
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        output = folder/"report.json"
        receipt = invoke([*replay, "--output", output], 0)
        assert receipt["report_sha256"] == pin(output) and invoke([*replay, "--check-report", pin(output)], 0)["status"] == "matched"
        report = json.loads(output.read_bytes())
        markers = independent(args.package, report, args.oracle, folder)
        row = report["observations"][0]
        for part in (receipt, report["plan"], report["plan"]["slots"][0], row, row["workload"], row["measurement"],
                     row["measurement"]["ticks"], row["process"], report["pairs"][0], report["changes"]["activity"],
                     report["qualification"], report["acquisition_environment"], next(iter(report["by_first_arm"].values()))):
            WINDOW["private"](part)
        assert WINDOW["AUDIT"]["inspect"]("renamed.bin", args.package.read_bytes()[:100])[0]["rule"] == "private-benchmark-package"
        if args.check_controls:
            semantic_controls(report)
            archive_controls(args, folder, replay, report)
        if args.recorder:
            acquisition_controls(args, folder)
        print(f'{report["measured_pairs"]} pairs and {markers} original markers matched the independent Windows reader and interval calculations.')


if __name__ == "__main__":
    main()
