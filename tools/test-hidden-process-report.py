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


if __name__ == "__main__":
    main()
