"""Independent layout collection/verification scheduling and owned native controls."""
import argparse
from collections import deque, OrderedDict
import json
from pathlib import Path
import subprocess


class Oracle:
    def __init__(self):
        self.checks = 0

    def check(self, condition, message):
        self.checks += 1
        if not condition:
            raise AssertionError(message)


def run_json(exe, *arguments):
    result = subprocess.run([str(exe), *arguments], capture_output=True, text=True, encoding="utf-8", timeout=90)
    if result.returncode:
        raise AssertionError(f"fixture exit {result.returncode}: {result.stderr}")
    return json.loads(result.stdout)


def collection(oracle, scenarios):
    for scenario in scenarios:
        ring, due, deadlines = deque(), {}, {}
        slots = loans = 0
        for op in scenario["operations"]:
            pid = op["pid"]
            if op["op"] == "add":
                oracle.check(pid not in due, "new discovery joins once")
                ring.append(pid)
                due[pid] = op["due"]
                deadlines[pid] = slots + (len(ring) * 4 + 2) // 3 + 2
            elif op["op"] == "remove":
                ring.remove(pid)
                del due[pid], deadlines[pid]
            else:
                oracle.check(op["op"] == "select" and bool(ring), "known nonempty collection selection")
                oldest = min(ring, key=due.__getitem__)
                if slots % 4 == 3 and oldest != ring[0]:
                    expected = oldest
                    loans += 1
                else:
                    expected = ring.popleft()
                    ring.append(expected)
                slots += 1
                oracle.check(pid == expected and op["loans"] == loans, f'{scenario["name"]}: collection order and loan count')
                oracle.check(all(slots <= deadline for deadline in deadlines.values()), "later discoveries cannot extend an existing waiter's bound")
                deadlines[pid] = slots + (len(ring) * 4 + 2) // 3 + 2


def verification(oracle, scenarios):
    for scenario in scenarios:
        ring, owners, next_class, history = deque(), {}, {}, OrderedDict()
        slots = 0
        for op in scenario["operations"]:
            if op["op"] == "admit":
                subject = (op["pid"], op["generation"])
                lane = op["lane"]
                key = (*subject, lane, op["base"])
                record = history.get(key)
                pending = sum(len(q) for lanes in owners.values() for q in lanes)
                lane_count = sum(len(lanes[lane]) for lanes in owners.values())
                own = owners.get(subject, ((), ()))
                if record and op["observed"] < record["last_seen"]:
                    expected = "invalid_input_or_clock"
                elif record and record["pending"]:
                    expected = ("expired_original_pending" if op["observed"] > record["observed"] and
                                op["now"] - record["observed"] > 30000 else "already_pending")
                    record["last_seen"] = op["observed"]
                    record["rediscoveries"] += 1
                elif pending >= 160:
                    expected = "global_limit"
                elif lane_count >= 128:
                    expected = "class_limit"
                elif sum(map(len, own)) >= 16:
                    expected = "subject_limit"
                elif len(own[lane]) >= 8:
                    expected = "subject_class_limit"
                else:
                    expected = "queued"
                    if record is None and len(history) == 512:
                        disposable = next(k for k, value in history.items() if not value["pending"])
                        del history[disposable]
                    history[key] = {"pending": True, "observed": op["observed"], "queued": op["now"],
                                    "last_seen": op["observed"], "rediscoveries": 0}
                    if subject not in owners:
                        owners[subject] = [deque(), deque()]
                        next_class[subject] = 0
                        ring.append(subject)
                    owners[subject][lane].append(key)
                oracle.check(op["result"] == expected, f'{scenario["name"]}: exact admission reason')
            elif not ring:
                oracle.check(op["op"] == "empty", "empty work does not consume rotation")
            else:
                oracle.check(op["op"] == "pop", "admitted work must be selected")
                ready_heads = [(subject, history[q[0]]["observed"]) for subject in ring for q in owners[subject] if q]
                oldest = min(ready_heads, key=lambda pair: pair[1])[0]
                loan = slots % 4 == 3 and oldest != ring[0]
                if loan:
                    subject = oldest
                    lane = min((i for i in (0, 1) if owners[subject][i]),
                               key=lambda i: history[owners[subject][i][0]]["observed"])
                else:
                    subject = ring.popleft()
                    ring.append(subject)
                    lane = next_class[subject]
                    if not owners[subject][lane]:
                        lane = 1 - lane
                    next_class[subject] = 1 - lane
                slots += 1
                key = owners[subject][lane].popleft()
                expected = history[key]
                oracle.check((op["pid"], op["generation"], op["lane"], op["base"]) == key, "subject/class rotation and FIFO head")
                for field in ("observed", "queued", "last_seen", "rediscoveries"):
                    oracle.check(op[field] == expected[field], "rediscovery retains original observation and queue clocks")
                expected["pending"] = False
                if not any(owners[subject]):
                    ring.remove(subject)
                    del owners[subject], next_class[subject]


def product(oracle, exe):
    data = run_json(exe, "--self-test", "layout-scheduler")
    oracle.check(data["schema"] == "kn.layout_scheduler_test.v1" and data["passed"] and
                 not data["driver_loaded"] and not data["native_byte_reads"], "owned mapping-only scope")
    pending, normal, retry, shutdown = (data[key] for key in ("pending", "normal", "retry", "shutdown"))
    for report in (pending, normal, retry, shutdown):
        oracle.check(report["schema"] == "kn.layout_verification_scheduling.v1" and not report["hard_deadline_enforced"] and
                     not report["shutdown_in_normal_samples"], "bounded verification contract")
    oracle.check(pending["pending"] == "4" and pending["refused"] == "1" and pending["rediscovered"] == "0" and normal["pending"] == shutdown["pending"] == "0" and
                 normal["in_flight"] == shutdown["in_flight"] == "0", "actual admitted and final drained state")
    samples = normal["normal"]
    oracle.check(samples["attempts"] == "4" and samples["qualified_mappings"] == "2" and samples["invalid_clocks"] == "0", "actual qualified mappings")
    oracle.check(samples["outcomes"] == {"mapping_revalidated": "2", "mapping_or_identity_unavailable": "1", "expired": "1", "fault": "0"},
                 "expired original and stale identity are failed attempts")
    oracle.check(samples["admission_to_qualification"]["samples"] == samples["observation_to_qualification"]["samples"] == "2" and
                 samples["complete_service"]["samples"] == samples["incomplete_service"]["samples"] == "2", "outcome-specific timing samples")
    expired = [row for row in normal["records"] if row["outcome"] == "expired"]
    oracle.check(len(expired) == 1 and expired[0]["last_mapping_success_ms"] is None and
                 int(expired[0]["original_observed_ms"]) < int(expired[0]["last_seen_ms"]) and expired[0]["rediscoveries"] == "1",
                 "new discovery cannot rejuvenate queued original")
    oracle.check(normal["deferred_resident"] == "1" and normal["deferred"][0]["reason"] == "expired_original_pending" and
                 retry["deferred_resident"] == "0" and retry["normal"]["attempts"] == "5" and retry["normal"]["qualified_mappings"] == "3",
                 "source-held new observation retries after original is accounted for")
    oracle.check(normal["shutdown"]["attempts"] == "0" and shutdown["normal"] == retry["normal"] and
                 shutdown["shutdown"]["attempts"] == shutdown["shutdown"]["qualified_mappings"] == "1", "actual shutdown population separate")
    source = data["collection"]
    oracle.check(source["schema"] == "kn.layout_collection_scheduling.v1" and source["completed"] == "1" and
                 not source["hard_deadline_enforced"] and not source["shutdown_observation_performed"], "actual collection completion contract")
    oracle.check(source["resident"] == "1" and source["discovery_to_first_sweep"]["samples"] == source["due_to_sweep"]["samples"] == "1" and
                 len(source["records"]) == 1 and source["records"][0]["last_completed_sweep_ms"] is not None, "owned process collection latency")
    invalid = subprocess.run([str(exe), "--self-test", "layout-scheduler", "extra"], capture_output=True, text=True, encoding="utf-8", timeout=30)
    oracle.check(invalid.returncode == 2 and not invalid.stdout.strip() and "usage:" in invalid.stderr, "strict public CLI grammar")
    help_result = subprocess.run([str(exe), "--help"], capture_output=True, text=True, encoding="utf-8", timeout=30)
    oracle.check(help_result.returncode == 0 and "layout-scheduler" in help_result.stdout, "owned test discoverable in help")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-exe", type=Path)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error("one executable is required")
    oracle = Oracle()
    if args.core_exe:
        data = run_json(args.core_exe.resolve(), "--scheduling-json")
        oracle.check(data["schema"] == "kn.layout_scheduling_fixture.v1", "controlled scheduling fixture")
        collection(oracle, data["collection"])
        verification(oracle, data["verification"])
    if args.exe:
        product(oracle, args.exe.resolve())
    print(f"layout scheduling oracle passed: {oracle.checks} checks; metadata qualification scope; no driver")


if __name__ == "__main__":
    main()
