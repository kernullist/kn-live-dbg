"""Check synthetic cross-view reports with an independent JSON oracle."""
import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    run = subprocess.run([str(args.exe.resolve()), "--json"], check=True,
                         capture_output=True, text=True, timeout=30)
    data = json.loads(run.stdout)
    assert data["schema"] == "kn-live-dbg.hidden-process.v1"
    assert data["policy"] == "lifetime-cross-view-v2"
    assert data["membership_scope"] == "discovery"
    assert data["consistency"] == "live_non_atomic"
    assert data["api_dependency"] == "shared_process_list"
    assert data["actor_attributed"] is False
    assert data["inventory_complete"] is True and data["coverage_complete"] is False
    assert data["suspicious"] == 1 and data["unverified"] == 3
    assert data["ignored"] == 3 and data["reconciled"] == 1
    assert data["ignored_auxiliary"] == 1 and data["ignored_terminating"] == 1
    assert data["ignored_race"] == 0
    assert data["warnings"] == ['synthetic "warning"\nwith newline']
    records = data["records"]
    assert len(records) == 7
    assert [r["state"] for r in records] == [
        "cross_view_discrepancy", "unverified", "unverified", "terminating",
        "reconciled", "auxiliary", "unverified"]
    assert [r["reason"] for r in records] == [
        "cid_only", "lifecycle_unavailable", "identity_changed", "terminating",
        "reconciled", "auxiliary", "qualification_budget"]
    assert records[1]["qualification"]["after"]["exit_time"] is None
    assert records[2]["qualification"]["stable_lifetime"] is False
    assert records[2]["has_exit_time"] is False
    assert records[6]["qualification"]["after"]["active_threads"] is None
    assert records[4]["kernel"] is False
    assert records[4]["qualification"]["kernel"] is True
    assert records[0]["eprocess"] == records[0]["qualification"]["after"]["eprocess"]
    assert records[0]["eprocess_scope"] == "qualification"
    assert records[0]["discovery_eprocess"] == "0x0"
    assert records[2]["eprocess_scope"] == "discovery"
    assert records[0]["image_scope"] == "discovery_pid_hint"
    for r in records:
        q = r["qualification"]
        if r["suspicious"]:
            assert q["stable_lifetime"] and q["kernel_complete"] and q["spi_complete"] and q["toolhelp_complete"]
            assert q["before"]["pid"] == q["after"]["pid"] == r["pid"]
            assert q["before"]["eprocess"] == q["after"]["eprocess"]
            assert q["before"]["create_time"] == q["after"]["create_time"]
            assert q["before"]["exit_time"] == q["after"]["exit_time"] == "0x0"
            assert q["before"]["active_threads"] > 0 and q["after"]["active_threads"] > 0
            assert q["before"]["state_transition"] is False and q["after"]["state_transition"] is False
        assert not (r["unverified"] and r["suspicious"])
    print("hidden-process JSON oracle passed: 7 retained dispositions and scoped requirements")
    run = subprocess.run([str(args.exe.resolve()), "--schedule-json"], check=True,
                         capture_output=True, text=True, timeout=30)
    rounds = json.loads(run.stdout)
    assert len(rounds) == 3
    ever_visited = set()
    for index, report in enumerate(rounds):
        scheduling = report["scheduling"]
        assert scheduling["policy"] == "fair-fresh-batch-v1"
        assert scheduling["candidates"] == len(report["records"]) == 257
        assert scheduling["attempted"] == scheduling["completed_boundaries"] == 128
        assert scheduling["deferred"] == report["unverified"] == 129
        assert scheduling["attempted"] + scheduling["deferred"] == scheduling["candidates"]
        assert scheduling["source_epoch"] == 1
        assert scheduling["success_revisit_measured"] is False
        assert scheduling["wait_scope"] == "discovered_pid_scheduling_hint"
        assert scheduling["started_ms"] <= report["comparison_started_ms"]
        assert report["comparison_finished_ms"] <= scheduling["finished_ms"]
        assert scheduling["max_serviced_wait_ms"] >= (5000 if index else 0)
        visited = set()
        for record in report["records"]:
            q = record["qualification"]
            assert not q["cancelled"] and not q["source_changed"]
            if q["attempted"]:
                visited.add(record["pid"])
                assert q["stable_lifetime"] and record["suspicious"]
                assert q["before"]["pid"] == q["after"]["pid"] == record["pid"]
                assert q["before"]["create_time"] == q["after"]["create_time"]
                assert q["before"]["eprocess"] == q["after"]["eprocess"]
            else:
                assert q["before"]["identity_valid"] is False
                assert q["after"]["identity_valid"] is False
                assert record["unverified"] and record["reason"] == "qualification_budget"
        assert len(visited) == 128
        assert len(ever_visited | visited) == min((index + 1) * 128, 257)
        ever_visited |= visited
    assert ever_visited == set(range(100, 357))
    print("hidden-process scheduling JSON oracle passed: all 257 candidates, 3 fresh batches")


if __name__ == "__main__":
    main()
