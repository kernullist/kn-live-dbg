"""Independent dispatch model and asynchronous reference-preparation contracts."""
import argparse
from collections import deque
import json
from pathlib import Path
import subprocess


class Oracle:
    checks = 0

    def check(self, value, reason):
        self.checks += 1
        if not value:
            raise AssertionError(reason)


def run(exe, *arguments):
    result = subprocess.run([str(exe.resolve()), *arguments], capture_output=True, text=True, encoding="utf-8", timeout=90)
    if result.returncode:
        raise AssertionError(f"fixture exit {result.returncode}: {result.stderr}")
    return json.loads(result.stdout)


def contract(check, report):
    check(report["schema"] == "kn.image_reference_preparation.v1" and
          report["success_scope"] == "metadata_prepared_not_live_image_verified", "preparation cannot qualify live bytes")
    check(not report["hard_deadline_enforced"] and not report["native_io_cancellation_guaranteed"] and
          not report["shutdown_in_normal_samples"] and not report["hard_process_memory_bound"], "bounded cancellation and allocation claims")
    check(int(report["resident"]) == sum(int(report[k]) for k in ("running", "ready", "queued")) <= 64 and
          int(report["running"]) <= 2 and int(report["running"]) + int(report["ready"]) <= 4, "all retained owner populations bounded")
    for phase in ("normal", "shutdown"):
        t = report[phase]
        check(int(t["attempts"]) == sum(int(t[k]) for k in ("prepared", "failed", "cancelled")), "every completed attempt classified")
        check(t["prepared_service"]["samples"] == t["prepared"] and t["failed_service"]["samples"] == t["failed"] and
              t["cancelled_service"]["samples"] == t["cancelled"], "outcome-specific service denominators")
    check(report["invalid_clocks"] == report["worker_faults"] == "0", "no silent dispatch/clock faults")


def core(check, exe):
    data = run(exe, "--json")
    check(data["schema"] == "kn.image_preparation_core.v1" and data["passed"], "actual queue/worker fixture")
    ring, queues = deque(), {}
    turns, loans = data["initial_turns"], 0
    for work in data["admissions"]:
        pid = work["pid"]
        if pid not in queues:
            queues[pid] = deque()
            ring.append(pid)
        queues[pid].append(work)
    for actual in data["dispatch"]:
        oldest = min(ring, key=lambda pid: queues[pid][0]["queued"])
        if turns % 4 == 3 and oldest != ring[0]:
            pid = oldest
            loans += 1
        else:
            pid = ring.popleft()
            ring.append(pid)
        expected = queues[pid].popleft()
        check(actual == {"pid": pid, "base": expected["base"]}, "independent subject rotation, bounded loan and FIFO")
        turns += 1
        if not queues[pid]:
            del queues[pid]
            ring.remove(pid)
    check(not queues and int(data["fixed"]["debt_loans"]) == loans, "all admitted scopes serviced exactly once")
    for name in ("fixed", "capacity", "result_bound", "native"):
        contract(check, data[name])
    check(data["capacity"]["cancelled_queued"] == "62" and data["capacity"]["shutdown"]["cancelled"] == "2", "observed queue/worker shutdown overlap")
    check(data["native"]["normal"]["prepared"] == data["native"]["applied"] == "1", "owned file follows actual native parser")


def product(check, exe):
    data = run(exe, "--self-test", "image-preparation")
    check(data["schema"] == "kn.image_preparation_test.v1" and data["passed"] and not data["driver_loaded"], "actual monitor integration")
    for name in ("pending", "completed", "before_stop", "stopped"):
        contract(check, data[name])
    check(data["pending"]["running"] == data["pending"]["ready"] == "1", "another subject prepared while first worker held")
    done = data["completed"]
    check(done["normal"]["prepared"] == "3" and done["normal"]["failed"] == "2" and done["stale_completions"] == "1", "failure and stale episode remain separate")
    check(data["before_stop"]["queued"] == "6" and data["before_stop"]["running"] == "2" and
          data["stopped"]["resident"] == "0" and data["stopped"]["shutdown"]["cancelled"] == "2", "actual Stop joins and accounts for all owners")
    invalid = subprocess.run([str(exe.resolve()), "--self-test", "image-preparation", "extra"], capture_output=True, timeout=30)
    check(invalid.returncode == 2 and not invalid.stdout.strip(), "strict public CLI grammar")
    help_result = subprocess.run([str(exe.resolve()), "--help"], capture_output=True, timeout=30)
    check(help_result.returncode == 0 and b"image-preparation" in help_result.stdout, "self-test discoverable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-exe", type=Path)
    parser.add_argument("--exe", type=Path)
    args = parser.parse_args()
    if not args.core_exe and not args.exe:
        parser.error("at least one executable is required")
    oracle = Oracle()
    if args.core_exe:
        core(oracle.check, args.core_exe)
    if args.exe:
        product(oracle.check, args.exe)
    print(f"reference preparation oracle passed: {oracle.checks} checks; owned metadata and controlled scheduling; no driver")


if __name__ == "__main__":
    main()
