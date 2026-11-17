"""Independent cooperative-stage invariants and actual owned-queue integration."""
import argparse
import json
from pathlib import Path
import subprocess

STAGES = ["execution_references", "layout", "live_events", "ti_events", "iotrace",
          "pipeline_events", "captured_regions", "watched_references", "image_sweeps"]


class Oracle:
    def __init__(self):
        self.checks = 0

    def check(self, condition, why):
        self.checks += 1
        if not condition:
            raise AssertionError(why)

    def histogram(self, actual, values):
        values = sorted(values)
        percentile = values[(len(values) * 95 + 99) // 100 - 1] if values else 0
        self.check(actual == {"samples": str(len(values)), "max_ms": str(max(values, default=0)),
                              "p95_upper_ms": str((1 << percentile.bit_length()) - 1)},
                   "histogram agrees with independent ordered observations")


def run_json(exe, *arguments):
    result = subprocess.run([str(exe.resolve()), *arguments], capture_output=True, text=True,
                            encoding="utf-8", timeout=120)
    if result.returncode:
        raise AssertionError(f"fixture exit {result.returncode}: {result.stderr}")
    return json.loads(result.stdout)


def report(oracle, data):
    oracle.check(data["schema"] == "kn.analysis_scheduling.v1" and data["policy"] == "persistent_stage_rotation.v1",
                 "actual scheduler schema and policy")
    oracle.check(data["turn_budget_ms"] == "250" and data["maximum_slice_ms"] == "100", "policy allowances")
    oracle.check(data["target_freshness_success_reported"] is False and data["hard_deadline_enforced"] is False and
                 data["shutdown_drain_included"] is False and data["snapshot_atomic_across_queues"] is False,
                 "bounded service is not target freshness, atomic acquisition, shutdown or a hard deadline")
    oracle.check([s["stage"] for s in data["stages"]] == STAGES, "fixed stage inventory")


def deterministic(oracle, data):
    oracle.check(data["schema"] == "kn.analysis_scheduler_fixtures.v1" and data["synthetic_clock"] is True,
                 "synthetic clock corpus remains explicit")
    names = {s["name"] for s in data["scenarios"]}
    oracle.check(names == {"fixed", "growing", "churn", "blocked", "not_due", "slow", "fault", "stop", "reentrant",
                           "backward", "last_stage_overrun", "depletion"}, "complete adversarial scenario inventory")
    for scenario in data["scenarios"]:
        name = scenario["name"]
        services, failures, gaps = ([[] for _ in STAGES] for _ in range(3))
        dispatches, returned, faults, overruns, deferrals = ([0] * 9 for _ in range(5))
        previous, last_return = ([None] * 9 for _ in range(2))
        turns, exhausted, stopped, turn_overruns = [], 0, 0, 0
        cursor, last_opportunity = 0, [None] * 9
        ordinal = 0
        for turn_index, turn in enumerate(scenario["turns"]):
            oracle.check(turn["before"]["next_stage"] == STAGES[cursor], f"{name}: cursor survives boundary")
            ready = turn["ready"]
            selected = set()
            for index, item in enumerate(turn["trace"]):
                stage, start, end, allowance = (item[k] for k in ("stage", "begin", "end", "allowance"))
                oracle.check(ready[stage] and stage not in selected, f"{name}: ready and at most once per boundary")
                earlier = [(cursor + offset) % 9 for offset in range((stage - cursor) % 9)]
                oracle.check(all(not ready[i] or i in selected for i in earlier), f"{name}: no ready waiter bypassed")
                oracle.check(0 <= start - turn["begin"] < 250 and allowance == min(100, 250 - (start - turn["begin"])),
                             f"{name}: no dispatch past budget and no fresh budget per stage")
                selected.add(stage)
                cursor = (stage + 1) % 9
                ordinal += 1
                if name in ("fixed", "growing", "slow", "fault", "stop", "reentrant", "last_stage_overrun"):
                    if last_opportunity[stage] is not None:
                        oracle.check(ordinal - last_opportunity[stage] <= 9, f"{name}: finite service under continuous arrivals")
                    last_opportunity[stage] = ordinal
                dispatches[stage] += 1
                if previous[stage] is not None and start >= previous[stage]:
                    gaps[stage].append(start - previous[stage])
                previous[stage] = start
                fault = turn["threw"] and index == len(turn["trace"]) - 1
                faults[stage] += fault
                returned[stage] += not fault
                if end >= start:
                    (failures if fault else services)[stage].append(end - start)
                    overruns[stage] += end - start > allowance
                    if not fault:
                        last_return[stage] = end
                else:
                    oracle.check(name == "backward" and turn_index == 0 and len(turn["trace"]) == 1,
                                 "invalid clock halts the turn and emits no wrapped duration")
            if turn["end"] >= turn["begin"]:
                turns.append(turn["end"] - turn["begin"])
                turn_overruns += turn["end"] - turn["begin"] > 250
            if name == "stop":
                stopped += 1
                oracle.check(len(turn["trace"]) == 1, "stop interrupts subsequent stages")
            elif not turn["threw"] and turn["end"] - turn["begin"] >= 250 and len(selected) < 9:
                exhausted += 1
                for i in range(9):
                    deferrals[i] += ready[i] and i not in selected
            oracle.check(turn["threw"] == (name == "fault" and turn_index == 0), "only injected fault propagates")
        final = scenario["final"]
        report(oracle, final)
        oracle.check(final["active_stage"] is None and final["active_allowance_ms"] == "0" and
                     final["active_service_ms"] is None, "return, fault and invalid clock release active state")
        oracle.check(int(final["turns"]) == 36 and int(final["exhausted_turns"]) == exhausted and
                     int(final["stopped_turns"]) == stopped and int(final["turn_overruns"]) == turn_overruns,
                     f"{name}: turn accounting including last-stage overrun")
        oracle.check(int(final["invalid_clocks"]) == (name == "backward") and
                     int(final["reentrant_calls"]) == (name == "reentrant"), "invalid clock and recursive entry diagnostics")
        oracle.histogram(final["turn_service"], turns)
        for i, stage in enumerate(final["stages"]):
            oracle.check([int(stage[k]) for k in ("dispatches", "returned", "faults", "overruns", "budget_deferrals")] ==
                         [dispatches[i], returned[i], faults[i], overruns[i], deferrals[i]], f"{name}: exact stage accounting")
            oracle.check(stage["last_dispatch_ms"] == (str(previous[i]) if previous[i] is not None else None) and
                         stage["last_return_ms"] == (str(last_return[i]) if last_return[i] is not None else None),
                         "failed/invalid-clock callbacks do not invent successful return timestamps")
            for key, values in (("service", services[i]), ("failed_service", failures[i]), ("dispatch_gap", gaps[i])):
                oracle.histogram(stage[key], values)
            if name in ("fixed", "growing", "blocked", "slow"):
                oracle.check(stage["backlog_since_ms"] == "0" and stage["backlog_age_ms"] == str(scenario["turns"][-1]["end"]),
                             "continuous backlog and source blockage never reset original observation age")
        oracle.check(all(n > 0 for n in dispatches), f"{name}: every rejoining stage eventually dispatched")


def integration(oracle, data):
    oracle.check(data["schema"] == "kn.analysis_scheduler_test.v1" and data["passed"] is True and data["checks"] == 15,
                 "owned production dispatcher controls pass")
    oracle.check(data["driver_loaded"] is False and data["native_byte_reads"] is False, "no native-driver coverage invented")
    normal = data["normal"]
    report(oracle, normal)
    oracle.check(normal["active_stage"] is None and int(normal["turns"]) >= 4, "owned event pressure needs multiple bounded turns")
    for i in (0, 7, 8):
        stage = normal["stages"][i]
        oracle.check(stage["pending"] == "1" and stage["dependency"] == "live_binding_absent" and stage["dispatches"] == "0",
                     "actual source gate leaves work unconsumed")
    for i in (1, 2, 3, 5, 6):
        stage = normal["stages"][i]
        oracle.check(stage["pending"] == "0" and int(stage["dispatches"]) >= 1 and stage["faults"] == "0",
                     "actual independent stages drain admitted work")
    pipeline = data["pipeline"]
    report(oracle, pipeline)
    oracle.check(pipeline["active_stage"] == "pipeline_events" and int(pipeline["active_allowance_ms"]) > 0,
                 "coverage diagnostics capture the real active publication stage")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-exe", type=Path)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error("provide --core-exe or --exe")
    oracle = Oracle()
    if args.core_exe:
        deterministic(oracle, run_json(args.core_exe, "--analysis-scheduling-json"))
    if args.exe:
        integration(oracle, run_json(args.exe, "--self-test", "analysis-scheduler"))
    print(f"Analysis scheduling oracle: {oracle.checks} checks passed")


if __name__ == "__main__":
    main()
