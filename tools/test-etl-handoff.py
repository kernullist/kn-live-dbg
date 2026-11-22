"""Check a pinned handoff study against an independent Windows event reader and exercise partial studies."""
import argparse
import base64
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


def fraction(value):
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def independent_path(events, truth, measurement):
    path = measurement["join_path"]
    source = {e["event_id"]: e for e in events}
    start, arrival, stop = (int(source[i]["raw_timestamp"]) for i in (1, 9, 2))
    join_start, returned = map(int, truth["join_call"])
    ids = (1, 2, 9, 6, 10)
    assert [source[i]["record_ordinal"] for i in ids] == [path[k] for k in (
        "activity_start_record", "activity_stop_record", "caller_arrival_record", "worker_stop_record", "join_stop_record")]
    assert (arrival, join_start, returned) == tuple(int(path[k]) for k in ("caller_arrival_qpc", "join_call_start_qpc", "join_return_qpc"))
    lower, upper = [start, int(truth["write_brackets"][5][1])-1], [returned]
    results = []
    for i, entry in enumerate(truth.get("join_probes", [])):
        first, pending, signaled = ((11, 12, 16), (13, 14, 17))[i]
        assert (pending in source) != (signaled in source)
        stop_id = signaled if signaled in source else pending
        lo, hi = map(int, entry["call"])
        left, right = (source[k] for k in (first, stop_id))
        assert int(left["raw_timestamp"]) <= lo <= hi <= int(right["raw_timestamp"])
        if i == 0:
            assert right["record_ordinal"] < source[9]["record_ordinal"]
        else:
            assert source[9]["record_ordinal"] < left["record_ordinal"]
        code = 0 if stop_id == signaled else 258
        assert entry["wait_result"] == code
        results.append(code)
        assert path["probes"][i] == dict(start_record=left["record_ordinal"], result_record=right["record_ordinal"],
                                         wait_result=code, call_start_qpc=str(lo), call_end_qpc=str(hi))
        (upper if code == 0 else lower).append(hi if code == 0 else lo)
    assert len(results) == len(path["probes"])
    a, b = max(lower), min(upper)
    assert a <= b and (a, b) == (int(path["worker_signal_earliest_qpc"]), int(path["worker_signal_latest_qpc"]))
    who = "unresolved"
    if b < arrival or results[:1] == [0]:
        who = "caller"
    if a > arrival or results[1:] == [258]:
        who = "worker"
    assert path["last_prerequisite"] == who
    phases = ("start_to_caller", "exposed_worker", "join_return_delay", "return_to_stop")
    samples = {k: [] for k in phases}
    for signal, key in ((a, "at_earliest_signal"), (b, "at_latest_signal")):
        marks = sorted({start, signal, arrival, returned, stop})
        parts = dict.fromkeys(phases, 0)
        for left, right in zip(marks, marks[1:]):
            band = 0 if right <= arrival else 1 if right <= signal else 2 if right <= returned else 3
            parts[phases[band]] += right - left
        assert {k + "_ticks": str(v) for k, v in parts.items()} == path[key]
        assert sum(parts.values()) == int(measurement["ticks"]["activity"])
        for phase in phases:
            samples[phase].append(parts[phase])
    t0, t1 = map(int, truth["timer_call"])
    timer_widths = [sweep((arrival, max(arrival, b)), (t0+d, t1+d)) for d in (-1, 0, 1) if t1+d <= b]
    timer = path["worker_timer_after_arrival_ticks"]
    assert (min(timer_widths), max(timer_widths)) == (int(timer["lower"]), int(timer["upper"]))
    samples["worker_timer_after_arrival"] = timer_widths
    samples["worker_after_join_call_start"] = [sweep((start, s), (join_start, returned)) for s in (a, b)]
    assert samples["worker_after_join_call_start"] == [int(path["worker_after_join_call_start_ticks"][k]) for k in ("lower", "upper")]
    hz = int(truth["frequency"])
    return who, {k: [Fraction(t*10**9, hz) for t in v] for k, v in samples.items()}


def independent_differences(report, arms):
    counts = {role: dict(caller=0, worker=0, unresolved=0, unavailable=0) for role in ("baseline", "candidate")}
    groups = {}
    for pair in report["pairs"]:
        baseline, candidate = (arms[pair["pair"], r] for r in counts)
        counts["baseline"][baseline[0]] += 1
        counts["candidate"][candidate[0]] += 1
        for phase, values in candidate[1].items():
            alternatives = [v-b for v in values for b in baseline[1][phase]]
            low, high = min(alternatives), max(alternatives)
            change = pair["join_path_change_ns"][phase]
            assert (fraction(change["lower"]), fraction(change["upper"])) == (low, high)
            for group in ("all", pair["order"][0]):
                groups.setdefault((group, phase), []).append((low, high))
    summary = report["join_path_summary"]
    assert counts == summary["last_prerequisites"]
    for (group, phase), values in groups.items():
        dest = (summary["changes"] if group == "all" else summary["by_first_arm"][group])[phase]
        assert dest["pairs"] == len(values)
        assert [fraction(dest[k]) for k in ("median_lower_ns", "median_upper_ns")] == [statistics.median(col) for col in zip(*values)]
        expected = [sum(lo > 0 for lo, hi in values), sum(hi < 0 for lo, hi in values), values.count((0, 0))]
        assert [dest[k] for k in ("longer", "shorter", "equal", "unresolved")] == [*expected, len(values)-sum(expected)]


def independent(package, report, oracle, folder):
    cfg = report["plan"]
    by_pair, paths = {}, {}
    with zipfile.ZipFile(package) as archive:
        for row in report["observations"]:
            slot, truth = row["selection"], row["workload"]
            path = folder / "sample.etl"
            path.write_bytes(archive.read(f"slot-{slot['slot']:02d}.etl"))
            assert pin(path) == row["etl_sha256"]
            footer, _, groups, _ = WINDOW["read_oracle"](oracle, path)
            events = sorted((e for group in groups.values() for e in group), key=lambda e: e["record_ordinal"])
            assert [r["event"] for r in row["marker_page"]["markers"]] == events
            assert len(events) == (14 if "caller_delay_ms" in cfg else 10) and footer["records_seen"] == row["marker_page"]["records_seen"]
            assert footer["clock_type"] == 1 and footer["frequency"] == int(truth["frequency"])
            t = {e["event_id"]: int(e["raw_timestamp"]) for e in events}
            join, timer = (tuple(map(int, truth[k])) for k in ("join_call", "timer_call"))
            expected = {"activity": t[2]-t[1], "caller_work": t[4]-t[3], "worker_span": t[6]-t[5],
                        "join_call": join[1]-join[0], "timer_call": timer[1]-timer[0],
                        "join_timer_overlap": sweep(join, timer), "work_window_overlap": sweep((t[3], t[4]), (t[5], t[7]))}
            if "caller_delay_ms" in cfg:
                delay = truth["caller_delay_call"]
                if cfg["caller_delay_ms"]:
                    lo, hi = map(int, delay)
                    assert t[4] <= lo <= hi <= t[11]
                    expected["caller_delay_call"] = hi-lo
                else:
                    assert delay is None
                    expected["caller_delay_call"] = 0
            assert {k: int(v) for k, v in row["measurement"]["ticks"].items()} == expected
            assert expected["join_timer_overlap"] <= min(expected["join_call"], expected["timer_call"])
            for seed, name in ((slot["seed"], "caller_result"), (slot["seed"] ^ 0x9e3779b9, "worker_result")):
                for _ in range(cfg["steps"]):
                    seed = (1664525*seed + 1013904223) % 2**32
                assert seed == truth[name]
            by_pair.setdefault(slot["pair"], {})[slot["role"]] = {k: Fraction(v*10**9, footer["frequency"]) for k, v in expected.items()}
            if report["schema"] == "kn.etl_handoff_study.v2":
                paths[slot["pair"], slot["role"]] = independent_path(events, truth, row["measurement"])
    if paths:
        independent_differences(report, paths)
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


def join_controls(report):
    ticks = {1: 10, 9: 30, 2: 60}
    records = {n: n for n in (1, 9, 2, 6, 10)}
    def probes(first, second):
        return [dict(wait_result=code, call_start_qpc=str(lo), call_end_qpc=str(hi))
                for code, lo, hi in ((first, 24, 26), (second, 34, 36))]
    # Enumerate every feasible integer signal tick and cross-thread timer-end reading.
    for before, after in ((0, 0), (258, 0), (258, 258)):
        for worker_end in (24, 30, 31, 35):
            signals = [s for s in range(10, 51) if s >= worker_end-1 and
                       (s <= 26 if before == 0 else s >= 24) and (s <= 36 if after == 0 else s >= 34)]
            try:
                path = study.bound_join(ticks, records, worker_end, (40, 50), (20, worker_end), probes(before, after))
            except study.Unqualified:
                assert not signals
                continue
            assert signals and (int(path["worker_signal_earliest_qpc"]), int(path["worker_signal_latest_qpc"])) == (min(signals), max(signals))
            who = "worker" if min(signals) > 30 else "caller" if max(signals) < 30 else "unresolved"
            assert path["last_prerequisite"] == who
            tails = [len(range(30, s)) for s in signals]
            assert (min(tails), max(tails)) == tuple(int(path[k]["exposed_worker_ticks"]) for k in ("at_earliest_signal", "at_latest_signal"))
            calls = [len(range(40, s)) for s in signals]
            assert (min(calls), max(calls)) == tuple(int(path["worker_after_join_call_start_ticks"][k]) for k in ("lower", "upper"))
            timers = [len(set(range(30, s)) & set(range(20+d, worker_end+d))) for s in signals
                      for d in (-1, 0, 1) if worker_end+d <= s]
            assert (min(timers), max(timers)) == tuple(int(path["worker_timer_after_arrival_ticks"][k]) for k in ("lower", "upper"))
    try:
        study.bound_join(ticks, records, 24, (40, 50), (10, 20), probes(0, 258))
        raise AssertionError("accepted a nonsignaled thread after a signaled observation")
    except study.Unqualified as error:
        assert str(error) == "thread_signal_reversed"
    if "caller_delay_ms" not in report["plan"]:
        return
    row = report["observations"][0]
    def reject(truth, page, expected):
        try:
            study.measure(report["plan"], row["selection"], row["expected_activity_id"], truth, row["process"], page,
                          row["etl_sha256"], row["marker_page"]["source_bytes"])
        except study.Unqualified as error:
            assert str(error) == expected, error
        else:
            raise AssertionError("accepted " + expected)
    truth, page = row["workload"], row["marker_page"]
    changed = deepcopy(truth)
    changed["join_probes"][0]["wait_result"] ^= 258
    reject(changed, page, "probe_result_disagrees_with_etl")
    altered_page = deepcopy(page)
    result_record = row["measurement"]["join_path"]["probes"][0]["result_record"]
    event = next(r["event"] for r in altered_page["markers"] if r["event"]["record_ordinal"] == result_record)
    event["event_id"] = 16 if event["event_id"] == 12 else 12
    reject(truth, altered_page, "probe_result_disagrees_with_etl")
    changed = deepcopy(truth)
    changed["join_probes"][0]["call"] = changed["join_call"]
    reject(changed, page, "probe_outside_markers")
    reject(dict(truth, caller_delay_ms=(truth["caller_delay_ms"]+1) % 1001), page, "workload_mismatch")
    reject(dict(truth, schema="kn.owned_etl_handoff.v1"), page, "workload_identity_mismatch")
    bad_delay = "caller_delay_outside_markers" if truth["caller_delay_ms"] else "unexpected_caller_delay"
    reject(dict(truth, caller_delay_call=truth["join_call"]), page, bad_delay)


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
    if "join_path_summary" in report:
        assert result["pairs"][0]["join_path_change_ns"] is None
        summary = result["join_path_summary"]
        assert summary["last_prerequisites"][result["observations"][0]["selection"]["role"]]["unavailable"] == 1
        assert summary["changes"]["exposed_worker"]["pairs"] == result["measured_pairs"]
    assert invoke([*limited, "--check-report", receipt["report_sha256"]], 1)["status"] == "matched"
    if "caller_delay_ms" in report["plan"]:
        def change_probe(_parts, outcomes):
            captured = outcomes[0]["attempt"]["stdout"]
            raw = json.loads(base64.b64decode(captured["base64"], validate=True))
            raw["join_probes"][0]["wait_result"] ^= 258
            changed = study.encoded(raw)
            digest = hashlib.sha256(changed).hexdigest()
            captured.update(byte_count=len(changed), original_sha256=digest, retained_sha256=digest,
                            base64=base64.b64encode(changed).decode("ascii"))
        altered = repack(folder/"changed-probe.zip", change_probe)
        output = folder/"changed-probe.json"
        mismatch = invoke([*altered, "--output", output], 1)
        partial = json.loads(output.read_bytes())
        assert partial["observations"][0]["reason"] == "probe_result_disagrees_with_etl"
        assert partial["measured_pairs"] == report["planned_pairs"]-1 and partial["pairs"][0]["join_path_change_ns"] is None
        assert invoke([*altered, "--check-report", mismatch["report_sha256"]], 1)["status"] == "matched"
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
    parser.add_argument("--join-path", action="store_true", help="check optional join analysis of a legacy archive")
    args = parser.parse_args()
    replay = ["replay", "--package", args.package, "--sha256", args.sha256, "--plan-sha256", args.plan_sha256, "--exe", args.exe]
    if args.join_path:
        replay.append("--join-path")
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
            if "join_path_summary" in report:
                join_controls(report)
            archive_controls(args, folder, replay, report)
        if "join_path_summary" in report:
            path = row["measurement"]["join_path"]
            for part in (path, path["at_latest_signal"], *path["probes"], *row["workload"].get("join_probes", []),
                         report["join_path_summary"], report["join_path_summary"]["changes"],
                         report["join_path_summary"]["changes"]["exposed_worker"], report["join_path_summary"]["last_prerequisites"]["baseline"]):
                WINDOW["private"](part)
        if args.recorder:
            acquisition_controls(args, folder)
        print(f'{report["measured_pairs"]} pairs and {markers} original markers matched the independent Windows reader and interval calculations.')


if __name__ == "__main__":
    main()
