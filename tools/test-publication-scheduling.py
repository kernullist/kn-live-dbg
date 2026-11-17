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
    cases = {row["name"]: row["report"] for row in data["collections"]}
    expected = {"complete": "complete", "partial_job": "partial", "failed": "failed", "unknown": "complete",
                "rejected": "partial", "pending": "incomplete", "open": "incomplete", "closing": "incomplete",
                "empty": "empty", "invalid_acquisition": "complete", "invalid_closure": "incomplete",
                "late_admission": "incomplete", "duplicate_closure": "incomplete", "sweep_loss": "partial",
                "irp_unavailable": "partial", "optional_irp": "complete", "journal_only": "partial", "failed_closure": "partial", "auxiliary_only": "partial"}
    oracle.check(set(cases) == set(expected), "all collection boundary controls emitted")
    for name, report in cases.items():
        collection_contract(oracle, report)
        oracle.check(report["publication_outcome"] == expected[name], f"{name}: scoped collection outcome")
        oracle.check(report["writer_end_ms"] == (None if name in ("open", "closing") else "100"),
                     f"{name}: missing/duplicate closure never invents or renews original end")
        if name in ("partial_job", "rejected", "sweep_loss", "irp_unavailable"):
            oracle.check(report["closure_outcome"] == "complete" and report["acquisition_to_successful_close_ms"] is None,
                         "closed journal cannot erase publication failures, drops or auxiliary gaps")
    report = cases["complete"]
    oracle.check(report["first_known_acquisition_ms"] == "0" and report["last_known_acquisition_ms"] == "20" and
                 report["acquisition_to_successful_close_ms"] == "100" and report["known_acquisition_jobs"] == "2",
                 "earliest original acquisition survives out-of-order dispatch; zero is not missing")
    oracle.check(report["normal_attempts"] == report["shutdown_attempts"] == "1", "shutdown population stays explicit")
    for name in ("unknown", "empty", "invalid_acquisition"):
        oracle.check(not cases[name]["all_acquisitions_known"] and cases[name]["acquisition_to_successful_close_ms"] is None and
                     cases[name]["first_known_acquisition_ms"] is None, "no fabricated acquisition interval")
    oracle.check(cases["invalid_acquisition"]["invalid_clocks"] == "1" and cases["invalid_closure"]["protocol_errors"] == "1",
                 "malformed clocks cannot underflow or become valid closure latency")
    oracle.check(cases["optional_irp"]["phases"][2]["outcome"] == "not_applicable" and
                 cases["optional_irp"]["phases"][2]["journal_ms"] is None, "absent IRP is not a successful ledger commit")
    for name in ("journal_only", "failed_closure", "auxiliary_only"):
        oracle.check(cases[name]["closure_outcome"] == "failed" and cases[name]["publication_outcome"] == "partial",
                     "previous files or journal members do not invent partially successful closure")


def collection_contract(oracle, report):
    oracle.check(report["schema"] == "kn.collection_timing.v1" and report["scope"] == "capture_writer_session" and
                 report["clock_domain"] == "GetTickCount64_ms", "collection identity and clock scope")
    oracle.check(not report["timing_journal_member"] and not report["source_coverage_evaluated"] and
                 not report["captured_page_ledger"] and not report["hard_deadline_enforced"] and
                 not report["snapshot_atomic_with_producer_queues"], "runtime diagnostic does not expand durable/source coverage")
    oracle.check([p["phase"] for p in report["phases"]] == ["sweep_flush", "evidence_ledger", "irp_ledger", "image_journal"],
                 "original closure dependencies remain ordered")


def product_collection(oracle, data):
    report = data["collection"]
    for key in ("collection", "open_collection", "failed_collection", "empty_collection", "closed_with_failure", "no_files_collection", "auxiliary_collection"):
        collection_contract(oracle, data[key])
    oracle.check(data["recovered_closed"] and report["final"] and report["publication_outcome"] == report["closure_outcome"] == "complete",
                 "post-join collection agrees with actual offline journal recovery")
    oracle.check(report["attempts"] == report["admitted"] == report["complete_jobs"] == "5" and
                 report["known_acquisition_jobs"] == "3" and not report["all_acquisitions_known"] and
                 report["acquisition_to_successful_close_ms"] is None, "mixed origins retain explicit denominator")
    oracle.check(data["open_collection"]["publication_outcome"] == "incomplete" and not data["open_collection"]["final"] and
                 data["open_collection"]["writer_end_ms"] is None, "completed jobs do not close live collection")
    oracle.check(data["failed_collection"]["publication_outcome"] == "partial" and
                 data["failed_collection"]["phases"][3]["file_ms"] is not None and
                 data["failed_collection"]["phases"][3]["journal_ms"] is None, "failed closure preserves file-only milestone")
    oracle.check(data["empty_collection"]["publication_outcome"] == "empty" and
                 data["empty_collection"]["acquisition_to_successful_close_ms"] is None, "empty does not count as an acquisition success")
    oracle.check(data["closed_with_failure"]["publication_outcome"] == "partial" and
                 data["closed_with_failure"]["closure_outcome"] == "complete" and
                 data["closed_with_failure"]["complete_jobs"] == "0", "actual failed page survives successful journal closure accounting")
    oracle.check(data["no_files_collection"]["publication_outcome"] == data["no_files_collection"]["closure_outcome"] == "failed" and
                 data["no_files_collection"]["final"], "final no-files failure stays distinct from incomplete collection")
    oracle.check(data["auxiliary_collection"]["publication_outcome"] == "partial" and
                 data["auxiliary_collection"]["closure_outcome"] == "failed" and
                 int(data["auxiliary_collection"]["auxiliary_publication_successes"]) >= 1,
                 "actual retained reference survives failed primary publication and closure")
    receipts = data["receipts"]
    origins = [r for r in receipts if r["acquisition_start_ms"] is not None]
    first = min(int(r["acquisition_start_ms"]) for r in origins)
    last = max(int(r["acquisition_end_ms"]) for r in origins)
    oracle.check(int(report["first_known_acquisition_ms"]) == first and int(report["last_known_acquisition_ms"]) == last and
                 int(report["known_subset_start_to_writer_end_ms"]) == int(report["writer_end_ms"]) - first,
                 "collection spans derive from actual local per-job receipts")
    previous = max(int(r["service_end_ms"]) for r in receipts)
    for phase in report["phases"]:
        start, end = int(phase["start_ms"]), int(phase["end_ms"])
        oracle.check(previous <= start <= end and int(phase["service_ms"]) == end - start, "closure follows drained work in dependency order")
        previous = end
        for field in ("file_ms", "journal_ms"):
            if phase[field] is not None:
                oracle.check(start <= int(phase[field]) <= end, "actual closure milestone lies inside its own service")
        if phase["journal_ms"] is not None:
            oracle.check(int(phase["file_ms"]) <= int(phase["journal_ms"]), "closure journal follows its ledger file")
    oracle.check(previous <= int(report["writer_end_ms"]), "writer finished only after final closure")


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
    product_collection(oracle, data)
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
