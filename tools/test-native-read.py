"""Independent JSON assertions for raw native read status and compatibility."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    run = subprocess.run([args.exe], capture_output=True, text=True, encoding="utf-8", timeout=60)
    print(run.stderr, end="")
    assert run.returncode == 0, "native read controls failed"
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(rows) == 14
    reads = {}
    for row in rows:
        assert row["schema"] == "kn.read_set.v1" and row["recording_complete"] is True
        assert row["attempts"] == row["receipts_saved"] == "1"
        read = row["reads"][0]["read"]
        assert read["source_epoch"] == "42" and read["requested_bytes"] == 32
        assert read["collector_authenticated"] is False
        reads[row["operation_id"]] = read
        assert read["transport_status_domain"] == "win32"
    for name in ("kernel", "process", "physical"):
        read = reads[name]
        assert read["status"] == "complete" and read["native_status_domain"] == "ntstatus"
        assert read["native_status"] == read["transport_status"] == 0
        assert read["transport_succeeded"] is read["backend_copy_attempted"] is True
        assert read["native_read_kind"] == {"kernel": 1, "process": 2, "physical": 3}[name]
        assert read["transferred_bytes"] == 32 and read["driver_abi"] == 17
        assert read["spans"][0]["bytes_hex"] == "5a" * 32
        assert read["identity_revalidated"] is (name == "process")
    partial = reads["partial"]
    assert partial["status"] == "partial" and partial["native_status"] == 0x8000000D
    assert partial["transport_status"] == 0 and partial["transferred_bytes"] == 7
    assert [(s["requested_bytes"], s["state"], s["bytes_hex"]) for s in partial["spans"]] == [
        (7, "complete", "5a" * 7), (25, "read_failed", "")]
    failed = reads["failed"]
    assert failed["status"] == "read_failed" and failed["native_status"] == 0xC0000005
    assert failed["transferred_bytes"] == 0 and failed["transport_status"] == 0
    for name, state, status in (("identity-mismatch", "identity_changed", 0xC0000225), ("policy-denied", "policy_denied", 0xC0000022)):
        read = reads[name]
        assert read["status"] == state and read["native_status"] == status
        assert read["transport_succeeded"] is True and read["backend_copy_attempted"] is False
        assert read["transferred_bytes"] == 0 and read["identity_revalidated"] is False
    for name, count, status in (("short-success", 4, 0), ("full-error", 32, 0xC0000005)):
        read = reads[name]
        assert read["status"] == "read_failed" and read["transferred_bytes"] == count
        assert read["native_status"] == status and read["validation_reason"] == "native_status_length_mismatch"
        assert all(not span["bytes_hex"] for span in read["spans"])
    transport = reads["transport-failed"]
    assert transport["native_status_domain"] == "win32" and transport["native_status"] == 1
    assert transport["transport_status"] == 1 and transport["transferred_bytes"] is None
    assert transport["transport_succeeded"] is False and transport["backend_copy_attempted"] is None
    for name in ("legacy-kernel", "legacy-process", "legacy-physical"):
        read = reads[name]
        assert read["backend_contract"] == "abi17_legacy_raw_ntstatus_unavailable"
        assert read["native_status_domain"] == "unavailable" and read["native_status"] is None
        assert read["transport_status"] == 0
        assert read["transferred_bytes"] == (32 if name == "legacy-process" else 5)
    assert reads["legacy-failed"]["transferred_bytes"] is None
    assert reads["legacy-failed"]["native_status_domain"] == "win32"
    assert reads["legacy-failed"]["native_status"] == 299
    print(f"Native read JSON oracle passed: {len(rows)} status/source observations")


if __name__ == "__main__":
    main()
