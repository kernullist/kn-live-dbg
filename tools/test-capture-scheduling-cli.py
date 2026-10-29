"""Check the driver-free owned capture worker fixture and its timing DTO."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    exe = args.exe.resolve()
    checks = 0

    def check(value, name):
        nonlocal checks
        assert value, name
        checks += 1

    result = subprocess.run([str(exe), "--self-test", "capture-scheduler"],
                            capture_output=True, text=True, encoding="utf-8", timeout=30)
    check(result.returncode == 0, "owned capture integration succeeds")
    report = json.loads(result.stdout)
    check(report["schema"] == "kn.capture_scheduler_test.v1" and report["passed"] and
          report["corpus"] == "owned_process_and_absent_device" and not report["driver_loaded"], "test scope remains explicit")
    normal, shutdown = report["normal"], report["shutdown"]
    for state in (normal, shutdown):
        check(state["schema"] == "kn.capture_scheduling.v1" and state["clock_domain"] == "GetTickCount64_ms" and
              state["percentiles"] == "log2_bucket_upper_bounds", "units and quantile approximation are explicit")
        check(not state["shutdown_in_normal_samples"] and not state["hard_deadline_enforced"], "no unmeasured deadline guarantee")
        check(state["saturation_scope"] == "first_and_continuation_request_queues", "admission saturation is not whole-pipeline coverage")
        check(state["first_urgency_ms"] == "250" and state["continued_urgency_ms"] == "1000" and
              state["first_burst_limit"] == "8", "distinct scheduling classes preserve the burst bound")
        for field in ("first_queue_wait", "continued_queue_wait", "first_attempt_age", "page_service"):
            histogram = {key: int(value) for key, value in state[field].items()}
            check(histogram["p50_upper_ms"] <= histogram["p95_upper_ms"] <= histogram["p99_upper_ms"] and
                  (histogram["samples"] != 0 or all(value == 0 for value in histogram.values())), "latency counters remain coherent")
    check(normal["first_queue_wait"]["samples"] == "2" and normal["continued_queue_wait"]["samples"] == "5" and
          normal["first_attempt_age"]["samples"] == "2" and normal["page_service"]["samples"] == "7",
          "queue turns and page attempts use distinct denominators")
    check(normal["failed_attempts"] == "2" and normal["invalid_clocks"] == "0" and
          normal["shutdown_dispatches"] == normal["shutdown_attempts"] == "0", "protected pages count as failed attempts")
    check(shutdown["shutdown_dispatches"] == shutdown["shutdown_attempts"] == "1" and
          shutdown["first_queue_wait"]["samples"] == shutdown["page_service"]["samples"] == "0",
          "shutdown-only work cannot improve normal percentile reports")
    invalid = subprocess.run([str(exe), "--self-test", "capture-scheduler", "extra"],
                             capture_output=True, text=True, encoding="utf-8", timeout=30)
    check(invalid.returncode == 2 and not invalid.stdout.strip() and "usage:" in invalid.stderr, "strict self-test grammar")
    help_result = subprocess.run([str(exe), "--help"], capture_output=True, text=True, encoding="utf-8", timeout=30)
    check(help_result.returncode == 0 and "capture-scheduler" in help_result.stdout, "public help exposes the owned test")
    print(f"capture scheduling CLI passed: {checks} checks; owned process only; no driver")


if __name__ == "__main__":
    main()
