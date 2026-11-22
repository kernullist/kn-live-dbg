"""Check timer bounds from independent Windows ETW rows and feasible ordered transitions."""
from fractions import Fraction
from itertools import combinations_with_replacement, product
from statistics import median

from etl_handoff_timer import phase_bounds


PHASES = ("before_timer_set", "timer_pending", "after_timer_signal")


def feasible(arrival, arm, signal, worker, points):
    choices = [[p for p in points if lo <= p <= hi] for lo, hi in (arm, signal, worker)]
    values = [((a, t), (max(arrival, a)-arrival, max(arrival, t)-max(arrival, a), max(arrival, w)-max(arrival, t)))
              for a, t, w in product(*choices) if a <= t <= w]
    if values:
        transitions, widths = zip(*values)
        return [tuple((min(col), max(col)) for col in zip(*rows)) for rows in (transitions, widths)]
    return None


def compare(result, expected):
    for interval, name in zip(expected[0], ("timer_set", "timer_signal"), strict=True):
        assert interval == tuple(int(result[name+"_"+k+"_qpc"]) for k in ("earliest", "latest"))
    for interval, phase in zip(expected[1], PHASES, strict=True):
        assert interval == tuple(int(result[phase+"_ticks"][k]) for k in ("lower", "upper"))


def small_clocks():
    ticks = range(4)
    windows = list(combinations_with_replacement(ticks, 2))
    for a, t, w, j in product(windows, windows, windows, ticks):
        expected = feasible(j, a, t, w, ticks)
        if expected:
            compare(phase_bounds(j, a, t, w), expected)
        else:
            try:
                phase_bounds(j, a, t, w)
            except ValueError:
                continue
            raise AssertionError("accepted impossible timer order")


def from_etl(events, row):
    truth, result = row["workload"], row["measurement"]["timer_path"]
    def time(e):
        return int(e["raw_timestamp"])
    marks = {e["event_id"]: e for e in events}
    obs = [e for e in events if e["task"] == 11]
    groups = list(zip(obs[::2], obs[1::2], strict=True))
    assert len(groups) == truth["timer_probe_count"] == len(result["probes"])
    assert 2 <= len(groups) <= 40 and result["status"] == "bounded"
    assert truth["timer_observer_tid"] == result["timer_observer_tid"] and truth["timer_observer_tid"] not in (truth["caller_tid"], truth["joined_tid"])
    for i, ((start, stop), probe) in enumerate(zip(groups, result["probes"], strict=True)):
        signaled = i == len(groups)-1
        assert start["event_id"] == 24 and stop["event_id"] == (26 if signaled else 25)
        assert (start["opcode"], stop["opcode"]) == (1, 2) and all(e["header_thread_id"] == truth["timer_observer_tid"] for e in (start, stop))
        assert probe == dict(start_record=start["record_ordinal"], result_record=stop["record_ordinal"], wait_result=0 if signaled else 258,
                             marker_start_qpc=start["raw_timestamp"], marker_stop_qpc=stop["raw_timestamp"])
    assert all(marks[k]["header_thread_id"] == truth["joined_tid"] and marks[k]["task"] == 10 for k in (22, 23))
    assert [marks[k]["record_ordinal"] for k in (22, 23)] == [result[k] for k in ("timer_set_start_record", "timer_set_stop_record")]
    # Each phase is linear between neighboring event endpoints; extrema occur at endpoints or at a tie.
    j = time(marks[9])
    a = (max(time(marks[1]), time(marks[22])-1), time(marks[23])+1)
    t = (time(groups[-2][0])-1, min(time(groups[-1][1]), int(truth["timer_call"][1]))+1)
    lower = [time(marks[1]), int(truth["write_brackets"][5][1])-1]
    upper = [int(truth["join_call"][1])]
    for probe in truth["join_probes"]:
        if probe["wait_result"] == 258:
            lower.append(int(probe["call"][0]))
        else:
            upper.append(int(probe["call"][1]))
    w = max(lower), min(upper)
    expected = feasible(j, a, t, w, sorted(set((j, *a, *t, *w))))
    compare(result, expected)
    return {phase: tuple(Fraction(v*10**9, int(truth["frequency"])) for v in width) for phase, width in zip(PHASES, expected[1], strict=True)}


def pairs(report, results):
    def value(r):
        return Fraction(int(r["numerator"]), int(r["denominator"]))
    summary = report["timer_path_summary"]
    assert summary["measured_pairs"] == report["planned_pairs"] and summary["unavailable_pairs"] == 0
    for phase in PHASES:
        groups = {k: [] for k in ("all", "baseline", "candidate")}
        for pair in report["pairs"]:
            base, cand = (results[pair["pair"], role][phase] for role in ("baseline", "candidate"))
            diffs = [v-b for v in cand for b in base]
            interval = min(diffs), max(diffs)
            assert tuple(value(pair["timer_path_change_ns"][phase][k]) for k in ("lower", "upper")) == interval
            for group in ("all", pair["order"][0]):
                groups[group].append(interval)
        for group, intervals in groups.items():
            stats = (summary["changes"] if group == "all" else summary["by_first_arm"][group])[phase]
            assert [value(stats[k]) for k in ("median_lower_ns", "median_upper_ns")] == [median(col) for col in zip(*intervals)]
            counts = [sum(lo > 0 for lo, hi in intervals), sum(hi < 0 for lo, hi in intervals), intervals.count((0, 0))]
            assert [stats[k] for k in ("longer", "shorter", "equal", "unresolved")] == [*counts, len(intervals)-sum(counts)]


def evidence_controls(report, measure):
    from copy import deepcopy
    row = report["observations"][0]
    original = row["measurement"]
    plan, truth, page = report["plan"], row["workload"], row["marker_page"]

    def check(workload, source, reason):
        changed = measure(plan, row["selection"], row["expected_activity_id"], workload, row["process"],
                          source, row["etl_sha256"], page["source_bytes"])
        assert changed["timer_path"] == dict(status="unqualified", reason=reason)
        assert changed["join_path"] == original["join_path"] and changed["ticks"] == original["ticks"]
        if plan["observe_scheduling"]:
            assert changed["scheduling"] == original["scheduling"]

    check(dict(truth, timer_observer_tid=truth["caller_tid"]), page, "invalid_timer_observer")
    check(dict(truth, timer_probe_count=1), page, "invalid_timer_observer")
    check(dict(truth, timer_probe_count=41), page, "invalid unsigned integer")
    count = truth["timer_probe_count"]
    check(dict(truth, timer_probe_count=count-1 if count > 2 else 3), page, "incomplete_timer_markers")
    for event, field, value, why in (
            (25, "event_id", 26, "invalid_timer_probe_sequence"),
            (23, "header_thread_id", truth["timer_observer_tid"], "timer_descriptor_mismatch"),
            (24, "version", True, "invalid unsigned integer"),
            (22, "raw_timestamp", "1", "timer_set_outside_worker_phase"),
            (24, "raw_timestamp", str(2**63-1), "timer_probe_order_mismatch")):
        modified = deepcopy(page)
        next(m["event"] for m in modified["markers"] if m["event"]["event_id"] == event)[field] = value
        check(truth, modified, why)
