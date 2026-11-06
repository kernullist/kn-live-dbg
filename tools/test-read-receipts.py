"""Independent denominator, byte, status and provenance assertions for the recorder."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    run = subprocess.run([args.exe], capture_output=True, text=True, encoding="utf-8", timeout=60)
    print(run.stderr, end="")
    assert run.returncode == 0, "recorder control harness failed"
    records = [json.loads(line) for line in run.stdout.splitlines()]
    sets = {entry["operation_id"]: entry for entry in records}
    assert len(sets) == 13 and len(records) == 14
    for entry in records:
        assert entry["schema"] == "kn.read_set.v1"
        assert entry["consistency"] == "ordered_attempts_not_atomic_snapshot"
        assert entry["execution_observed"] is entry["mapping_lifetime_bound"] is entry["collector_authenticated"] is False
        reads = entry["reads"]
        assert int(entry["attempts"]) == len(reads) + int(entry["unrecorded_attempts"])
        assert int(entry["receipts_saved"]) == len(reads)
        assert int(entry["charged_source_calls"]) == sum(read["source_invoked"] for read in reads)
        assert int(entry["charged_source_calls"]) <= int(entry["budget"]["maximum_source_calls"])
        assert int(entry["charged_requested_bytes"]) <= int(entry["budget"]["maximum_bytes"])
        assert int(entry["stored_spans"]) <= int(entry["budget"]["maximum_stored_spans"])
        assert int(entry["stored_spans"]) + int(entry["reserved_span_slots"]) <= int(entry["budget"]["maximum_stored_spans"])
        if entry["pending_receipts"] == "0":
            assert entry["reserved_span_slots"] == "0"
        assert [int(read["sequence"]) for read in reads] == sorted({int(read["sequence"]) for read in reads})
        stored = 0
        for receipt in reads:
            assert int(receipt["address"]) >= 0 and int(receipt["requested_bytes"]) > 0
            if not receipt["completed"]:
                assert receipt["read"] is None
                continue
            read = receipt["read"]
            assert read["operation_id"] == entry["operation_id"] and read["read_receipt_id"] == receipt["sequence"]
            assert read["address"] == receipt["address"] and read["requested_bytes"] == int(receipt["requested_bytes"])
            assert int(read["started_tick"]) <= int(read["ended_tick"])
            for span in read["spans"]:
                data = bytes.fromhex(span["bytes_hex"])
                assert len(data) == (span["requested_bytes"] if span["state"] == "complete" else 0)
                stored += len(data)
        assert int(entry["stored_valid_bytes_with_repeats"]) == stored
    assert [r["read"]["status"] for r in sets["admission"]["reads"]] == [
        "complete", "identity_changed", "budget_deferred", "unsupported", "unsupported", "policy_denied", "cancelled"]
    fallback = sets["partial-and-fallback"]["reads"]
    assert fallback[0]["read"]["native_status"] == 0x8000000D
    assert fallback[0]["read"]["spans"][0]["bytes_hex"] == "41" * 16
    assert fallback[1]["read"]["status"] == "policy_denied" and not fallback[1]["source_invoked"]
    assert fallback[2]["fallback"] == {"from_receipt": "1", "reason": "explicit_alternate_source",
                                      "permission_requested": True, "permitted": True}
    assert fallback[2]["read"]["source_id"] != fallback[0]["read"]["source_id"]
    assert fallback[2]["read"]["spans"][0]["bytes_hex"] == "51" * 32
    assert sets["shared-budget"]["charged_requested_bytes"] == "64"
    assert sets["span-budget"]["stored_spans"] == "8"
    capacity = sets["receipt-capacity"]
    assert capacity["recording_complete"] is False and capacity["unrecorded_attempts"] == "1"
    abandoned = sets["abandoned"]
    assert abandoned["recording_complete"] is False and abandoned["abandoned_receipts"] == "1"
    assert sets["concurrent"]["recording_complete"] is True
    pending = next(entry for entry in records if entry["pending_receipts"] == "1")
    assert pending["operation_id"] == "concurrent" and pending["recording_complete"] is False
    assert pending["reads"][0]["read"] is None and pending["reads"][0]["requested_bytes"] == "32"
    assert sets["cancel-during-read"]["reads"][0]["read"]["status"] == "complete"
    assert sets["cancel-during-read"]["reads"][0]["read"]["cancellation_observed"] is True
    assert all(r["read"]["native_status"] == 299 for key in ("malformed", "source-replaced") for r in sets[key]["reads"])
    owned = sets["owned-process"]
    assert owned["recording_complete"] is True
    assert owned["stored_valid_bytes_with_repeats"] == str(64 + 4096)
    assert owned["reads"][0]["read"]["spans"][0]["bytes_hex"] == "5a" * 64
    assert owned["reads"][-1]["read"]["native_status_domain"] == "win32"
    assert owned["reads"][-1]["read"]["native_status"] != 0
    print(f"Read receipt JSON oracle passed: {len(sets)} bounded operations, {len(records)} snapshots")


if __name__ == "__main__":
    main()
