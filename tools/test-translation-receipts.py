"""Independent oracle for paging receipts and their physical read denominators."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    run = subprocess.run([args.exe], capture_output=True, encoding="utf-8", timeout=60)
    print(run.stderr, end="")
    assert run.returncode == 0
    rows = {row["name"]: row for row in map(json.loads, run.stdout.splitlines())}
    assert len(rows) == 13
    for name, row in rows.items():
        t, reads = row["translation"], row["read_set"]
        assert t["schema"] == "kn.translation_receipt.v1"
        assert reads["recording_complete"] and len(t["entries"]) == len(reads["reads"])
        assert not t["cpu_access_verified"] and not t["mapping_lifetime_bound"] and not t["collector_authenticated"]
        for index, (entry, saved) in enumerate(zip(t["entries"], reads["reads"]), 1):
            assert entry["read"] == saved["read"]
            assert entry["read"]["read_receipt_id"] == str(index)
            assert saved["address_domain"] == entry["read"]["address_domain"] == "physical"
            assert entry["read"]["virtual_address_bits"] is None
        if name.startswith("la"):
            bits, leaf = int(name[2:4]), int(name[-1])
            levels = 5 if bits == 57 else 4
            va = 0x0012123456789ABC if bits == 57 else 0x0000123456789ABC
            page_bytes = {1: 4096, 2: 2**21, 3: 2**30}[leaf]
            base = {1: 0x9000, 2: 0x400000, 3: 0x80000000}[leaf]
            assert t["status"] == "complete" and t["root_revalidated"] and t["entries_revalidated"]
            assert int(t["physical_address"]) == base + va % page_bytes
            assert int(t["page_bytes"]) == page_bytes and int(t["pfn"]) == (base + va % page_bytes) // 4096
            assert t["paging_permissions_known"]
            assert t["paging_write_allowed"] is t["paging_user_allowed"] is t["paging_execute_allowed"] is False
            assert int(reads["charged_requested_bytes"]) == 16 * (levels - leaf + 1)
            first = t["entries"][:levels - leaf + 1]
            rechecks = t["entries"][levels - leaf + 1:]
            for i, (entry, check) in enumerate(zip(first, rechecks)):
                level = levels - i
                assert entry["level"] == check["level"] == level
                expected = 0x1000 + i * 4096 + ((va >> (12 + 9 * (level - 1))) & 511) * 8
                assert int(entry["entry_address"]) == int(check["entry_address"]) == expected
                assert entry["entry_value"] == check["entry_value"]
                assert entry["phase"] == "walk" and check["phase"] == "recheck"
        else:
            assert not t["paging_permissions_known"] and t["paging_execute_allowed"] is None
            if name != "unknown-architecture":
                assert t["physical_address"] is t["pfn"] is t["page_bytes"] is None
    assert rows["partial-entry"]["translation"]["entries"][-1]["read"]["native_status"] == 0x8000000D
    assert rows["partial-entry"]["translation"]["entries"][-1]["entry_value"] is None
    assert rows["not-present"]["translation"]["status"] == "not_present"
    assert rows["root-changed"]["translation"]["status"] == "identity_changed"
    assert rows["entry-changed"]["translation"]["status"] == "conflict"
    assert rows["budget-deferred"]["read_set"]["charged_requested_bytes"] == "40"
    assert rows["deadline"]["read_set"]["reads"][0]["read"]["operation_deadline_exceeded"]
    print(f"Translation JSON oracle passed: {len(rows)} observations")


if __name__ == "__main__":
    main()
