"""Check production image scheduling against a small independent rotation model."""
import argparse
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


def contract(check, report):
    check(report["schema"] == "kn.image_scheduling.v1" and
          report["scope"] == "resident_image_work_entries", "resident scheduling scope")
    check(not report["hard_deadline_enforced"] and report["minimum_page_and_final_fences_may_overrun"] and
          not report["shutdown_in_normal_samples"] and not report["parser_attempt_is_native_read"] and
          not report["deferred_rediscovery_guaranteed"], "qualified accounting limits")
    check(report["cooperative_turn_budget_ms"] == "25" and report["reference_retry_ms"] == "30000" and
          report["debt_priority_ordinary_stride"] == "4", "budget and retry contract")
    rows = report["details"]
    check(len(rows) <= 64 and len(rows) + int(report["details_omitted"]) == int(report["resident"]), "bounded detail denominator")
    now = int(report["snapshot_ms"])
    for row in rows:
        observation = row["observation"]
        origin = observation["last_gap_free_traversal_ms"] or observation["first_seen_ms"]
        expected = str(now - int(origin)) if origin is not None and int(origin) <= now else None
        check(observation["observation_debt_ms"] == expected, "debt uses qualified traversal or original discovery")
        check(row["remaining_pages"] is not None if row["reference_loaded"] else row["remaining_pages"] is None,
              "unavailable inventory is not zero remaining pages")


def model(check, scenario):
    # Fixtures deliberately use a single watched/repeat class. The established
    # watch/background, first/repeat and bulk/tail gates have production tests.
    # This independent model checks the new bounded debt loan within that class.
    entries = {}
    cursor = (0, 0)
    turns = 0
    served = set()
    for operation in scenario["operations"]:
        identifier = operation["id"]
        now = operation["now"]
        if operation["op"] == "put":
            entries[identifier] = dict(subject=(100 + identifier % 3, operation["generation"]),
                                       first=now, debt=now, last=0, success=None)
            continue
        check(operation["op"] == "select", "known model operation")
        if turns % 4 == 3:
            expected = min(entries, key=lambda key: (entries[key]["debt"], entries[key]["last"], key))
        else:
            subjects = sorted({entry["subject"] for entry in entries.values()})
            selected_subject = next((subject for subject in subjects if subject > cursor), subjects[0])
            cursor = selected_subject
            expected = min((key for key in entries if entries[key]["subject"] == cursor),
                           key=lambda key: (entries[key]["last"], key))
            served.add(cursor[0])
        check(identifier == expected, f'{scenario["name"]}: selector diverged at turn {turns}')
        entry = entries[expected]
        entry["last"] = now
        if expected:
            entry["debt"] = entry["success"] = now
        turns += 1
    check(turns == 96 and len(served) == 3, "ordinary rotation continues under permanent old failure")
    report = scenario["report"]
    contract(check, report)
    check(report["debt_priority_turns"] == "24" and int(report["resident"]) == len(entries), "bounded debt loan count")
    check(int(report["max_resident_observation_debt_ms"]) == 100096 - min(entry["debt"] for entry in entries.values()),
          "failure cannot renew observation debt")
    for row in report["details"]:
        identifier = (int(row["base"]) - 0x10000) // 4096
        entry = entries[identifier]
        observation = row["observation"]
        check(int(observation["first_seen_ms"]) == entry["first"] and int(row["create_time"]) == entry["subject"][1],
              "delete/reuse preserves new entry identity")
        check(observation["last_gap_free_traversal_ms"] == (str(entry["success"]) if entry["success"] is not None else None),
              "successful observations alone renew traversal")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    args = parser.parse_args()
    exe = args.exe.resolve()
    oracle = Oracle()
    check = oracle.check
    run = subprocess.run([str(exe), "--self-test", "image-scheduler"], capture_output=True,
                         text=True, encoding="utf-8", timeout=90)
    check(run.returncode == 0, f"owned fixture failed: {run.stderr}")
    data = json.loads(run.stdout)
    check(data["schema"] == "kn.image_scheduler_test.v1" and data["passed"] and not data["driver_loaded"] and
          data["corpus"] == "owned_files_synthetic_target_and_time", "bounded fixture corpus")
    for report in (data["pipeline"], data["cancelled"], data["unavailable"], data["bounded"]):
        contract(check, report)
    report = data["pipeline"]
    normal = report["normal"]
    check(normal["successful_turn"]["samples"] == "6" and normal["failed_turn"]["samples"] == "1" and
          normal["deferred_turn"]["samples"] == "1", "actual success, gap and cooldown outcomes separated")
    check(report["shutdown"]["successful_turn"]["samples"] == "0" and report["shutdown"]["failed_turn"]["samples"] == "1" and
          report["pending"] == "0", "cancelled shutdown remains separate after normal recovery")
    cancelled = data["cancelled"]["details"][0]
    check(data["cancelled"]["pending"] == "1" and cancelled["remaining_pages"] == "2" and
          cancelled["observation"]["last_gap_free_episode"] != cancelled["retention_episode"], "cancelled partial cursor cannot qualify replaced reference")
    for name in ("discovery_to_first_parser_attempt", "discovery_to_first_exact_read", "discovery_to_first_traversal",
                 "discovery_to_first_gap_free_traversal"):
        check(normal[name]["samples"] == "1", "one milestone per resident key: " + name)
    for name in ("reference_open_retention", "identity_secondary_qualification", "page_comparison", "final_identity_content_checks"):
        check(normal[name]["samples"] == "7", "seven entered verifier stages: " + name)
    check(normal["reference_lookup"]["samples"] == "16" and normal["invalid_clocks"] == "0",
          "each explicit preparation readiness check and actual observation performs a lookup")
    row = report["details"][0]
    check(row["observation"]["last_gap_free_episode"] == row["retention_episode"] and row["remaining_pages"] == "0",
          "replaced reference qualifies only its own completed episode")
    missing = data["unavailable"]["details"][0]["observation"]
    check(missing["pending_since_ms"] == missing["first_seen_ms"] and missing["last_successful_slice_ms"] is None and
          missing["first_parser_attempt_ms"] is None and missing["last_attempt_ms"] is not None, "failed metadata is attempted, not read or successful")
    check(data["bounded"]["details_omitted"] == "6", "long scope and capacity omissions explicit")
    check(all(item["content_preparation"] is None for item in data["bounded"]["details"]),
          "unattempted content has no invented completion and preserves exact-scope capacity")
    check(cancelled["content_preparation"]["cancelled"] and row["content_preparation"]["active_id"] is None and
          row["content_preparation"]["success_episode"] == row["retention_episode"],
          "content cancellation and current successful preparation remain separate")
    for scenario in data["scenarios"]:
        model(check, scenario)
    invalid = subprocess.run([str(exe), "--self-test", "image-scheduler", "extra"], capture_output=True,
                             text=True, encoding="utf-8", timeout=30)
    check(invalid.returncode == 2 and not invalid.stdout.strip() and "usage:" in invalid.stderr, "strict self-test grammar")
    help_result = subprocess.run([str(exe), "--help"], capture_output=True, text=True, encoding="utf-8", timeout=30)
    check(help_result.returncode == 0 and "image-scheduler" in help_result.stdout, "documented owned test entry")
    print(f"image scheduling oracle passed: {oracle.checks} checks; actual collector and fixed/growing/delete-reuse models; no driver")


if __name__ == "__main__":
    main()
