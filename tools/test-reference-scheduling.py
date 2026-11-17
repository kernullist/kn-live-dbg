"""Independent queue/debt model plus owned-process checks of the production drain."""
import argparse
from collections import Counter, OrderedDict, deque
import json
import math
from pathlib import Path
import subprocess


class Oracle:
    def __init__(self):
        self.checks = 0

    def check(self, condition, message):
        self.checks += 1
        if not condition:
            raise AssertionError(message)

    def equal(self, actual, expected, message):
        self.check(actual == expected, f"{message}: {actual!r} != {expected!r}")


def key(work):
    return tuple(work[field] for field in ("pid", "create_time", "role", "target", "slot"))


def histogram(values):
    ordered = sorted((1 << value.bit_length()) - 1 if value else 0 for value in values)
    return {"samples": str(len(values)), "max_ms": str(max(values, default=0)), **{
        f"p{percent}_upper_ms": str(ordered[math.ceil(len(ordered) * percent / 100) - 1] if ordered else 0)
        for percent in (50, 95, 99)}}


class Model:
    """Two levels of rotating deques; independent of the C++ ticket ordering."""
    def __init__(self, oracle):
        self.oracle = oracle
        self.subjects = OrderedDict()
        self.history = {}
        self.deferred = OrderedDict()
        self.counts = Counter()
        self.stats = {name: {"outcomes": Counter(), "queue_wait": [], "success_service": [], "failed_service": []}
                      for name in ("normal", "shutdown")}

    def pending(self):
        return [work for roles in self.subjects.values() for items in roles.values() for work in items]

    def admit(self, work):
        scope, now = key(work), work["ms"]
        previous = self.history.get(scope)
        if previous is not None:
            self.oracle.check(now >= previous["last_seen_ms"], "fixture clocks are monotonic per key")
            previous["last_seen_ms"] = now
            previous["rediscoveries"] += 1
            if previous["pending_since_ms"] is not None:
                self.counts["duplicates"] += 1
                return "already_pending"
            attempt = previous["last_attempt_ms"]
            if attempt is not None and now - attempt < 10000:
                self.counts["cooldowns"] += 1
                return "attempt_cooldown"
        pending = self.pending()
        subject = scope[:2]
        subject_items = [item for item in pending if key(item)[:2] == subject]
        reason = None
        if len(pending) >= 1024:
            reason = "global_limit"
        elif len(subject_items) >= 64:
            reason = "subject_limit"
        elif sum(item["role"] == work["role"] for item in subject_items) >= 16:
            reason = "subject_role_limit"
        elif sum(item["role"] == work["role"] for item in pending) >= 256:
            reason = "role_limit"
        if reason:
            self.counts["deferred_attempts"] += 1
            receipt_key = scope + (reason,)
            if receipt_key in self.deferred:
                self.deferred[receipt_key]["last_ms"] = now
                self.deferred[receipt_key]["attempts"] += 1
            elif len(self.deferred) < 128:
                self.deferred[receipt_key] = dict(first_ms=now, last_ms=now, attempts=1)
            else:
                self.counts["omitted_deferred_attempts"] += 1
            return reason
        if previous is None:
            previous = self.history[scope] = dict(first_seen_ms=now, last_seen_ms=now,
                pending_since_ms=None, last_attempt_ms=None, last_success_ms=None,
                outcome="not_attempted", rediscoveries=0)
        previous["pending_since_ms"] = now
        self.subjects.setdefault(subject, OrderedDict()).setdefault(work["role"], deque()).append(work.copy())
        self.counts["admitted"] += 1
        return "queued"

    def pop(self, operation):
        subject, roles = self.subjects.popitem(last=False)
        role, items = roles.popitem(last=False)
        original = items.popleft()
        if items:
            roles[role] = items
        if roles:
            self.subjects[subject] = roles
        self.oracle.equal(key(operation), key(original), "admitted subject and role receive their next turn")
        first = original["ms"]
        self.oracle.equal((operation["original_ms"], operation["original_at"], operation["anchor"], operation["peb"]),
                          (first, first + 100000, first & 255, first + 9000), "rediscovery preserves original work")
        now, ended = operation["ms"], operation["end"]
        started = first <= now <= first + 30000
        self.oracle.equal(operation["started"], started, "expiry is checked before qualification")
        record = self.history[key(original)]
        record["pending_since_ms"] = None
        if started:
            record["last_attempt_ms"] = now
        else:
            self.oracle.equal(operation["outcome"], "expired", "expired work cannot report success")
        outcome = record["outcome"] = operation["outcome"]
        if outcome == "observed":
            record["last_success_ms"] = ended
        stats = self.stats["shutdown" if operation["shutdown"] else "normal"]
        stats["outcomes"][outcome] += 1
        stats["queue_wait"].append(now - first)
        if outcome not in ("expired", "cancelled"):
            stats["success_service" if outcome == "observed" else "failed_service"].append(ended - now)

    def snapshot(self, report):
        oracle = self.oracle
        check_contract(oracle, report)
        now = int(report["snapshot_ms"])
        pending = self.pending()
        oldest = min((item["ms"] for item in pending), default=None)
        oracle.equal(report["pending"], str(len(pending)), "pending denominator")
        oracle.equal(report["oldest_pending_ms"], str(oldest) if oldest is not None else None, "oldest pending is independent of next fair turn")
        oracle.equal(report["oldest_wait_ms"], str(now - oldest if oldest is not None else 0), "old pending age survives rediscovery")
        oracle.equal(report["expired_pending"], str(sum(now - item["ms"] > 30000 for item in pending)), "expiry risk denominator")
        for name in ("admitted", "duplicates", "cooldowns", "deferred_attempts", "omitted_deferred_attempts"):
            oracle.equal(report[name], str(self.counts[name]), name)
        oracle.equal(report["history_resident"], str(len(self.history)), "resident debt denominator")
        oracle.equal(report["history_evicted"], "0", "fixture history below bound")
        debt = max((now - (row["last_success_ms"] if row["last_success_ms"] is not None else row["first_seen_ms"])
                    for row in self.history.values()), default=0)
        oracle.equal(report["max_resident_observation_debt_ms"], str(debt), "failure cannot renew successful observation")
        ordered = sorted(sorted(self.history), key=lambda scope: (
            self.history[scope]["pending_since_ms"] is None,
            self.history[scope]["pending_since_ms"] if self.history[scope]["pending_since_ms"] is not None else self.history[scope]["last_seen_ms"]))
        oracle.equal(report["scopes_omitted"], str(max(0, len(ordered) - 64)), "bounded scope omission denominator")
        oracle.equal(len(report["scopes"]), min(64, len(ordered)), "bounded history details")
        for scope, actual in zip(ordered[:64], report["scopes"]):
            oracle.equal(key({name: int(value) if name != "role" else value for name, value in actual.items()
                              if name in ("pid", "create_time", "role", "target", "slot")}), scope, "history scope")
            for name, value in self.history[scope].items():
                oracle.equal(actual[name], str(value) if isinstance(value, int) else value, "history " + name)
        oracle.equal(len(report["deferred_scopes"]), len(self.deferred), "bounded deferred details")
        for (scope, expected), actual in zip(self.deferred.items(), report["deferred_scopes"]):
            oracle.equal(tuple(int(actual[field]) if field != "role" else actual[field]
                               for field in ("pid", "create_time", "role", "target", "slot")) + (actual["reason"],), scope, "deferred exact scope")
            for name, value in expected.items():
                oracle.equal(actual[name], str(value), "deferred " + name)
        for lane, stats in self.stats.items():
            for outcome, value in report[lane]["outcomes"].items():
                oracle.equal(value, str(stats["outcomes"][outcome]), lane + " outcome " + outcome)
            for field in ("queue_wait", "success_service", "failed_service"):
                oracle.equal(report[lane][field], histogram(stats[field]), lane + " " + field)


def check_contract(oracle, report):
    oracle.check(report["schema"] == "kn.reference_scheduling.v1" and report["scope"] == "execution_reference_queue" and
                 report["clock_domain"] == "GetTickCount64_ms" and report["debt_scope"] == "resident_admitted_keys", "bounded debt scope")
    oracle.equal([report[name] for name in ("capacity", "subject_capacity", "subject_role_capacity", "role_capacity")],
                 ["1024", "64", "16", "256"], "admission policy")
    oracle.check(not report["hard_deadline_enforced"] and not report["deferred_rediscovery_guaranteed"] and
                 not report["shutdown_in_normal_samples"], "no unmeasured guarantees")
    oracle.check(report["success_scope"] == "consistent_bounded_static_check_not_execution_or_full_path" and
                 report["percentiles"] == "log2_bucket_upper_bounds", "bounded success and percentile semantics")


def run_core(oracle, exe):
    process = subprocess.run([str(exe), "--reference-scheduling-json"], capture_output=True,
                             text=True, encoding="utf-8", check=True, timeout=60)
    data = json.loads(process.stdout)
    oracle.equal(data["schema"], "kn.reference_scheduler_fixtures.v1", "core fixtures")
    oracle.equal(len(data["scenarios"]), 3, "fixed, growing and expired/churn cohorts")
    for scenario in data["scenarios"]:
        model = Model(oracle)
        for operation in scenario["operations"]:
            if operation["op"] == "admit":
                oracle.equal(operation["result"], model.admit(operation), "admission result")
            elif operation["op"] == "pop":
                model.pop(operation)
            elif operation["op"] == "snapshot":
                model.snapshot(operation["report"])
            else:
                raise AssertionError("unknown fixture operation")


def run_product(oracle, exe):
    process = subprocess.run([str(exe), "--self-test", "reference-scheduler"], capture_output=True,
                             text=True, encoding="utf-8", timeout=60)
    oracle.check(process.returncode == 0, f"owned reference integration: {process.stderr}")
    data = json.loads(process.stdout)
    oracle.check(data["schema"] == "kn.reference_scheduler_test.v1" and data["passed"] and
                 not data["driver_loaded"] and data["corpus"] == "owned_process_and_absent_device", "native fixture scope")
    for name in ("pipeline", "shutdown", "admission"):
        check_contract(oracle, data[name])
    normal = data["pipeline"]
    oracle.equal(normal["pending"], "0", "production drain completes eight candidates")
    expected = Counter(observed=1, read_unavailable=2, changed_or_unreadable=2,
                       identity_unavailable=1, mapping_unavailable=1, partial_path=1)
    for name, value in normal["normal"]["outcomes"].items():
        oracle.equal(value, str(expected[name]), "actual native outcome " + name)
    oracle.equal(normal["normal"]["success_service"]["samples"], "1", "one successful static check")
    oracle.equal(normal["normal"]["failed_service"]["samples"], "7", "seven unavailable or partial checks")
    for row in normal["scopes"]:
        oracle.check(row["last_attempt_ms"] is not None and row["pending_since_ms"] is None, "actual qualification attempted")
        oracle.equal(row["last_success_ms"] is not None, row["role"] == "owned_stable", "only successful check renews debt")
    shutdown = data["shutdown"]
    oracle.equal(shutdown["normal"]["queue_wait"]["samples"], "0", "stop prevents normal dispatch")
    oracle.equal(shutdown["shutdown"]["success_service"]["samples"], "1", "shutdown completion stays separate")
    admission = data["admission"]
    oracle.equal((admission["admitted"], admission["pending"], admission["deferred_attempts"], admission["duplicates"]),
                 ("17", "15", "24", "1"), "actual admission counters")
    quiet = next(row for row in admission["scopes"] if row["role"] == "owned_quiet")
    oracle.check(quiet["last_success_ms"] is not None, "quiet rule gets the second turn despite flood")
    invalid = subprocess.run([str(exe), "--self-test", "reference-scheduler", "extra"],
                             capture_output=True, text=True, encoding="utf-8", timeout=30)
    oracle.check(invalid.returncode == 2 and not invalid.stdout.strip() and "usage:" in invalid.stderr, "strict self-test grammar")
    help_result = subprocess.run([str(exe), "--help"], capture_output=True, text=True, encoding="utf-8", check=True, timeout=30)
    oracle.check("reference-scheduler" in help_result.stdout, "help names the owned check")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-exe", type=Path)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error("at least one executable is required")
    oracle = Oracle()
    if args.core_exe:
        run_core(oracle, args.core_exe.resolve())
    if args.exe:
        run_product(oracle, args.exe.resolve())
    print(f"reference scheduling oracle passed: {oracle.checks} checks; bounded admitted work; no driver")


if __name__ == "__main__":
    main()
