"""Independent discovery-cycle, request, failure and real worker-gate controls."""
import argparse
from collections import deque
import json
from pathlib import Path
import subprocess

GROUPS = ["runtime", "hidden", "mapper", "kernel_pages", "user", "inline", "threads", "channels", "kernel_images", "page_candidates"]
FIRST = [0, 1, 2, 14, 16, 21, 22, 23, 24, 25]
COUNT = [1, 1, 12, 2, 5, 1, 1, 1, 1, 1]
DELAY = [0, 1000, 1000, 2000, 1500, 2000, 2000, 0, 0, 0]
PHASES = ["runtime_provider", "hidden_processes", "mapper_remnants", "pool_images", "unbacked_drivers", "module_inventory",
          "image_integrity", "driver_tamper", "hook_callbacks", "callback_lifecycle", "platform_evidence", "hook_input",
          "graphics_dispatch", "graphics_references", "cpu_integrity", "orphan_pages", "user_prune", "user_logging",
          "user_hostility", "user_handles", "user_capabilities", "inline_patches", "kernel_threads", "communication",
          "kernel_images", "page_candidates"]


class Oracle:
    def __init__(self):
        self.checks = 0

    def check(self, ok, why):
        self.checks += 1
        if not ok:
            raise AssertionError(why)

    def histogram(self, actual, values):
        ordered = sorted(values)
        p95 = ordered[(len(ordered) * 95 + 99) // 100 - 1] if ordered else 0
        self.check(actual == {"samples": str(len(values)), "max_ms": str(max(values, default=0)),
                              "p95_upper_ms": str((1 << p95.bit_length()) - 1)}, "independent ordered-sample histogram")


def run_json(exe, *args):
    result = subprocess.run([str(exe.resolve()), *args], capture_output=True, text=True, encoding="utf-8", timeout=120)
    if result.returncode:
        raise AssertionError(f"fixture exit {result.returncode}: {result.stderr}")
    return json.loads(result.stdout)


def contract(o, report):
    o.check(report["schema"] == "kn.discovery_scheduling.v1" and report["policy"] == "persistent_group_and_phase_rotation.v1",
            "discovery schema and policy")
    o.check(report["turn_budget_ms"] == "250" and report["debt_scope"] == "scheduled_discovery_cycle_due", "cooperative scope")
    o.check(all(report[k] is False for k in ("target_success_reported", "hard_deadline_enforced", "individual_scanner_preemption",
                                            "shutdown_drain_included")) and report["interleaved_analysis_in_turn_service"] is True,
            "no successful-target, preemption, shutdown or hard-deadline inference")
    o.check([g["group"] for g in report["groups"]] == GROUPS and [p["phase"] for p in report["phases"]] == PHASES,
            "complete production phase inventory")


def deterministic(o, data):
    names = {"fixed", "flood", "churn", "blocked", "slow", "head_fault", "midcycle_request", "yield_fault", "stop",
             "reentrant", "backward_between", "backward_inside", "last_phase_overrun", "depletion", "cancel"}
    o.check(data["schema"] == "kn.discovery_scheduler_fixtures.v1" and data["synthetic_clock"] is True and
            {s["name"] for s in data["scenarios"]} == names, "explicit complete synthetic corpus")
    for scenario in data["scenarios"]:
        name = scenario["name"]
        groups = [dict(due=None, request=None, next=0, active=False, fault=False, invalid=False, started=0, returned=0,
                       faulted=0, invalid_cycles=0, requests=0, coalesced=0, consumed=0, deferrals=0,
                       wait=[], service=[], failed=[], due_return=[], due_fault=[]) for _ in GROUPS]
        phases = [dict(attempts=0, returned=0, faults=0, cancelled=0, overruns=0, last=None, last_return=None, service=[], failed=[], cancelled_service=[], gap=[])
                  for _ in PHASES]
        ring = deque(range(10))
        last_clock = None
        turn_service, exhausted, overrun, stopped, invalid, yield_faults = [], 0, 0, 0, 0, 0
        cancelled_turns = 0

        def request(items):
            for i, due in items:
                g = groups[i]
                g["requests"] += 1
                if g["request"] is not None:
                    g["coalesced"] += 1
                    due = min(due, g["request"])
                g["request"] = due

        def due(g):
            return min(g["due"], g["request"]) if g["request"] is not None else g["due"]

        def ready(i, time, completed, enabled):
            g = groups[i]
            return i not in completed and enabled[i] and (g["active"] or time >= due(g))

        for index, turn in enumerate(scenario["turns"]):
            request(turn["requests"])
            begin, now, enabled = turn["begin"], turn["begin"], turn["enabled"]
            expected_enabled = [(index + i) % 5 < 3 if name == "churn" else False if name == "blocked" and i == 2 and index < 12
                                else i == 2 if name == "midcycle_request" else True for i in range(10)]
            o.check(enabled == expected_enabled, "actual configured binding changes")
            if last_clock is not None and begin < last_clock:
                invalid += 1
                o.check(not turn["trace"] and turn["end"] == begin and not turn["threw"], "backward inter-turn clock cannot advance a partial cycle")
                continue
            last_clock = begin
            if groups[0]["due"] is None:
                for i, g in enumerate(groups):
                    g["due"] = begin + DELAY[i]
            completed, valid = set(), True
            interval = 4000 if name == "flood" else 100000 if name in ("midcycle_request", "last_phase_overrun", "depletion") else 0
            for position, call in enumerate(turn["trace"]):
                selected = next((i for i in ring if ready(i, now, completed, enabled)), None)
                group, phase = call["group"], call["phase"]
                o.check(selected == group and now == call["begin"] and now - begin < 250,
                        f"{name}: ready group rotation and shared budget")
                while ring[0] != group:
                    ring.rotate(-1)
                ring.rotate(-1)
                g, p = groups[group], phases[phase]
                first = not g["active"]
                o.check(phase == FIRST[group] + g["next"] and call["first"] == (g["next"] == 0), "partial cycle preserves phase order after wait or failure")
                if first:
                    g.update(active=True, fault=False, invalid=False, cycle_due=due(g), cycle_start=now)
                    g["started"] += 1
                    g["wait"].append(now - g["cycle_due"])
                    if g["request"] is not None and g["request"] <= now:
                        g["request"] = None
                        g["consumed"] += 1
                request(call["requests"])
                g["next"] += 1
                p["attempts"] += 1
                if p["last"] is not None and now >= p["last"]:
                    p["gap"].append(now - p["last"])
                p["last"] = now
                fault = call["fault"]
                cancelled = call["cancelled"]
                o.check(fault == (name == "head_fault" and phase == 2), "only injected scanner faults")
                o.check(cancelled == (name == "cancel" and index == 0), "only injected pre-entry cancellation")
                p["faults"] += fault
                p["cancelled"] += cancelled
                p["returned"] += not fault and not cancelled
                g["fault"] |= fault
                end = call["end"]
                if end < last_clock:
                    invalid += 1
                    valid = False
                    g["invalid"] = True
                else:
                    last_clock = end
                    p["cancelled_service" if cancelled else "failed" if fault else "service"].append(end - now)
                    p["overruns"] += end - now > 250 - (now - begin)
                    if not fault and not cancelled:
                        p["last_return"] = end
                if cancelled:
                    g["next"] -= 1
                    cancelled_turns += 1
                    now = end
                    o.check(position == len(turn["trace"]) - 1 and g["active"], "cancelled entry preserves its pending phase and cycle debt")
                    break
                if g["next"] == COUNT[group]:
                    completed.add(group)
                    g.update(active=False, next=0, due=(end if valid else now) + interval)
                    g["faulted" if g["fault"] else "returned"] += 1
                    if g["invalid"]:
                        g["invalid_cycles"] += 1
                    else:
                        g["failed" if g["fault"] else "service"].append(end - g["cycle_start"])
                        g["due_fault" if g["fault"] else "due_return"].append(end - g["cycle_due"])
                now = end
                if fault or not valid:
                    o.check(position == len(turn["trace"]) - 1, "fault/clock reversal ends this turn after cursor advancement")
                    break
                if name == "yield_fault" and index == 0:
                    yield_faults += 1
                    o.check(position == len(turn["trace"]) - 1, "analysis yield fault preserves completed scanner work")
                    break
                if name == "flood":
                    now += 50
                    last_clock = now
            o.check(now == turn["end"], "analysis yield time is charged to the enclosing turn")
            o.check(turn["threw"] == (any(c["fault"] for c in turn["trace"]) or name == "yield_fault" and index == 0), "failure propagation")
            if valid:
                turn_service.append(now - begin)
                overrun += now - begin > 250
                last_clock = now
                if not turn["threw"] and len(turn["trace"]) < 26 and not any(c["cancelled"] for c in turn["trace"]):
                    if name == "stop" and turn["trace"]:
                        stopped += 1
                        o.check(len(turn["trace"]) == 1, "stop preserves remaining phases")
                    elif now - begin >= 250:
                        exhausted += 1
                        for i, g in enumerate(groups):
                            g["deferrals"] += ready(i, now, completed, enabled)
                    else:
                        o.check(not any(ready(i, now, completed, enabled) for i in range(10)), "no unaccounted eligible scanner skipped")
        final, snapshot = scenario["final"], scenario["snapshot_ms"]
        contract(o, final)
        o.check(final["active_phase"] is None and final["active_service_ms"] is None and final["next_group"] == GROUPS[ring[0]], "active state released and cursor retained")
        o.check([int(final[k]) for k in ("turns", "exhausted_turns", "overrunning_turns", "stopped_turns", "invalid_clocks", "analysis_yield_faults", "reentrant_calls")] ==
                [160, exhausted, overrun, stopped, invalid, yield_faults, int(name == "reentrant")], f"{name}: actual turn outcomes")
        o.histogram(final["turn_service"], turn_service)
        o.check(int(final["cancelled_turns"]) == cancelled_turns, "pre-entry cancellations are separate from completed and stopped turns")
        o.check(int(final["requests"]) == sum(g["requests"] for g in groups), "all request admissions counted")
        for i, (actual, g) in enumerate(zip(final["groups"], groups)):
            for key, model in (("requests", "requests"), ("coalesced_requests", "coalesced"), ("consumed_request_batches", "consumed"),
                               ("started_cycles", "started"), ("returned_cycles", "returned"), ("faulted_cycles", "faulted"),
                               ("cycles_without_valid_clock", "invalid_cycles"), ("budget_deferrals", "deferrals")):
                o.check(int(actual[key]) == g[model], f"{name}: group {i} {key}")
            pending = g["cycle_due"] if g["active"] else due(g)
            o.check(actual["cycle_active"] == g["active"] and actual["next_phase"] == PHASES[FIRST[i] + g["next"]] and
                    int(actual["remaining_phases"]) == COUNT[i] - g["next"], "retained phase cursor")
            o.check(actual["request_due_ms"] == (str(g["request"]) if g["request"] is not None else None) and int(actual["periodic_due_ms"]) == g["due"],
                    "coalescing retains earliest request and does not overwrite periodic cadence")
            o.check(actual["pending_since_ms"] == (str(pending) if g["active"] or snapshot >= pending else None) and
                    actual["pending_age_ms"] == (str(snapshot - pending) if snapshot >= pending else None), "original cycle debt survives partial service")
            for key, model in (("due_to_first_dispatch", "wait"), ("cycle_service", "service"), ("failed_cycle_service", "failed"),
                               ("due_to_returned_cycle", "due_return"), ("due_to_faulted_cycle", "due_fault")):
                o.histogram(actual[key], g[model])
        for actual, p in zip(final["phases"], phases):
            o.check(all(int(actual[k]) == p[k] for k in ("attempts", "returned", "faults", "cancelled", "overruns")), "exact scanner outcomes")
            o.check(actual["last_attempt_ms"] == (str(p["last"]) if p["last"] is not None else None) and
                    actual["last_return_ms"] == (str(p["last_return"]) if p["last_return"] is not None else None), "return clocks exclude fault and invalid clock")
            for key, model in (("service", "service"), ("failed_service", "failed"), ("cancelled_service", "cancelled_service"), ("attempt_gap", "gap")):
                o.histogram(actual[key], p[model])
        if name == "midcycle_request":
            o.check(groups[2]["returned"] == 2 and groups[2]["consumed"] == 2 and groups[2]["request"] is None,
                    "request admitted during active cycle causes a distinct later cycle")
        elif name in ("last_phase_overrun", "depletion"):
            o.check(all(p["attempts"] == 1 for p in phases), "each scanner executes exactly once in a single requested cycle")
        else:
            o.check(all(p["attempts"] > 0 for p in phases), f"{name}: long tails and all independent scanners receive service")
        if name == "head_fault":
            o.check(groups[2]["faulted"] > 0 and phases[13]["returned"] > 0, "repeated failing head cannot starve its own group tail")


def integration(o, data):
    o.check(data["schema"] == "kn.discovery_scheduler_test.v1" and data["passed"] is True and data["checks"] == 13,
            "actual worker controls passed")
    o.check(data["driver_loaded"] is False and data["native_scans_executed"] is False, "binding-gate scope only")
    for key in ("pending", "stopped", "pipeline"):
        contract(o, data[key])
        o.check(all(p["attempts"] == "0" for p in data[key]["phases"]), "actual absent-binding gate prevents every native discovery dispatch")
    stopped = data["stopped"]
    o.check(int(stopped["turns"]) >= 2 and stopped["active_phase"] is None, "observed worker completed and joined")
    o.check(all(stopped["groups"][i]["request_due_ms"] is not None for i in (2, 3, 4)), "unserved mapper/page/user requests survive worker stop")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-exe", type=Path)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error("provide --core-exe or --exe")
    oracle = Oracle()
    if args.core_exe:
        deterministic(oracle, run_json(args.core_exe, "--discovery-scheduling-json"))
    if args.exe:
        integration(oracle, run_json(args.exe, "--self-test", "discovery-scheduler"))
    print(f"Discovery scheduling oracle: {oracle.checks} checks passed")


if __name__ == "__main__":
    main()
