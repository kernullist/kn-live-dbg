"""Independent family rotation and actual publication timing checks."""
import argparse
from collections import deque
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


def core(oracle, exe):
    data = run_json(exe, "--publication-scheduling-json")
    oracle.check(data["schema"] == "kn.publication_picker_test.v1", "fixture schema")
    for scenario in data["scenarios"]:
        queues = [deque() for _ in range(4)]
        ring = deque(range(4))
        slots = 0
        loans = 0
        for op in scenario["operations"]:
            family = op["family"]
            if op["op"] == "push":
                admitted = len(queues[family]) < 12
                oracle.check(op["admitted"] == admitted, "bounded fixture admission")
                if admitted:
                    queues[family].append(op["now"])
            elif op["op"] == "clear":
                queues[family].clear()
            else:
                oracle.check(op["op"] == "select", "known operation")
                ready = [candidate for candidate in ring if queues[candidate]]
                if not ready:
                    expected = 4
                else:
                    expected = ready[0]
                    oldest = min(ready, key=lambda candidate: queues[candidate][0])
                    if slots % 4 == 3 and oldest != expected:
                        expected = oldest
                        loans += 1
                    else:
                        while ring[0] != expected:
                            ring.rotate(-1)
                        ring.rotate(-1)
                    queues[expected].popleft()
                    slots += 1
                oracle.check(family == expected and op["loans"] == loans,
                             f'{scenario["name"]}: bounded old-family loan must preserve ordinary cursor')


def contract(oracle, report):
    oracle.check(report["schema"] == "kn.publication_scheduling.v1" and report["scope"] == "capture_writer_admitted_work",
                 "admitted writer scope")
    oracle.check(not report["hard_deadline_enforced"] and not report["shutdown_in_normal_samples"] and
                 not report["snapshot_atomic_across_queues"], "accounting limits explicit")
    oracle.check(report["active_family"] is None and all(row["pending"] == "0" for row in report["families"]),
                 "post-join pending/in-flight state is empty")
    return {row["family"]: row for row in report["families"]}


def product(oracle, exe):
    data = run_json(exe, "--self-test", "publication-scheduler")
    oracle.check(data["schema"] == "kn.publication_writer_test.v1" and data["passed"] and not data["driver_loaded"],
                 "owned writer fixture succeeds without driver")
    normal = contract(oracle, data["normal"])
    failed = contract(oracle, data["shutdown"])
    for family, row in normal.items():
        wanted = 2 if family == "captured_page" else 1
        count = row["normal"]
        oracle.check(int(count["attempts"]) == wanted and int(count["complete"]) == wanted and
                     count["failed"] == count["partial"] == "0" and count["invalid_clocks"] == "0", "actual complete family counts")
        oracle.check(int(count["file_publications"]) == wanted and
                     int(count["journal_commits"]) == (1 if family in ("image_reads", "irp_capture") else 0),
                     "file-only family cannot invent a collection commit")
        oracle.check(row["shutdown"]["attempts"] == "0", "normal writer stopped only after observed completion")
        known = 0 if family == "irp_capture" else 1
        oracle.check(int(count["acquisition_end_to_file"]["samples"]) == known and
                     int(count["acquisition_start_to_file"]["samples"]) == known and
                     int(count["unknown_acquisition_origins"]) == wanted - known,
                     "live caller window only; opaque/historical origin remains unknown")
    partial = failed["image_reads"]["shutdown"]
    oracle.check(partial["partial"] == partial["file_publications"] == "1" and partial["journal_commits"] == partial["complete"] == "0",
                 "physical file survives failed journal membership")
    page = failed["captured_page"]["shutdown"]
    oracle.check(page["failed"] == "1" and page["file_publications"] == "0" and failed["captured_page"]["normal"]["attempts"] == "0",
                 "failed shutdown does not improve normal publication timing")
    oracle.check(len(data["receipts"]) == 5, "one completion receipt per actual job")
    for receipt in data["receipts"]:
        oracle.check(receipt["schema"] == "kn.publication_timing.v1" and receipt["clock_domain"] == "GetTickCount64_ms" and
                     receipt["complete"] and not receipt["shutdown"], "qualified receipt scope")
        start, end, queued = (int(receipt[key]) for key in ("service_start_ms", "service_end_ms", "queued_ms"))
        oracle.check(queued <= start <= int(receipt["file_ms"]) <= end, "actual file milestone lies inside service")
        if receipt["journal_ms"] is not None:
            oracle.check(int(receipt["file_ms"]) <= int(receipt["journal_ms"]) <= end, "journal follows original file")
        if receipt["acquisition_start_ms"] is not None:
            first, last = int(receipt["acquisition_start_ms"]), int(receipt["acquisition_end_ms"])
            oracle.check(first <= last <= queued, "explicit acquisition window precedes admission")
    invalid = subprocess.run([str(exe), "--self-test", "publication-scheduler", "extra"],
                             capture_output=True, text=True, encoding="utf-8", timeout=30)
    oracle.check(invalid.returncode == 2 and not invalid.stdout.strip() and "usage:" in invalid.stderr, "strict CLI grammar")
    help_result = subprocess.run([str(exe), "--help"], capture_output=True, text=True, encoding="utf-8", timeout=30)
    oracle.check(help_result.returncode == 0 and "publication-scheduler" in help_result.stdout, "help exposes owned test")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-exe", type=Path)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error("one executable is required")
    oracle = Oracle()
    if args.core_exe:
        core(oracle, args.core_exe.resolve())
    if args.exe:
        product(oracle, args.exe.resolve())
    print(f"publication scheduling oracle passed: {oracle.checks} checks; qualified collector clock; no driver")


if __name__ == "__main__":
    main()
