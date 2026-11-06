"""Independent checks of raw attempts and parser selection, without a target."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    run = subprocess.run([args.exe], capture_output=True, text=True, encoding="utf-8", timeout=60)
    print(run.stderr, end="")
    assert run.returncode == 0, "routing controls failed"
    sets = [json.loads(line) for line in run.stdout.splitlines()]
    indexed = {entry["attempts"]["operation_id"]: entry for entry in sets}
    assert len(indexed) == len(sets) == 31
    for entry in sets:
        assert entry["schema"] == "kn.routed_reads.v1"
        assert not any(entry[key] for key in ("reference_preserved", "image_verification_replayed",
                                             "collector_authenticated", "atomic_snapshot"))
        operation = entry["attempts"]
        reads = {int(read["sequence"]): read for read in operation["reads"]}
        assert int(operation["attempts"]) == len(reads) + int(operation["unrecorded_attempts"])
        assert int(operation["charged_source_calls"]) == sum(read["source_invoked"] for read in reads.values())
        assert int(operation["charged_requested_bytes"]) <= int(operation["budget"]["maximum_bytes"])
        used = []
        for call in entry["parser_reads"]:
            first, last = int(call["primary_receipt"]), int(call["returned_receipt"])
            if first:
                assert first in reads
                used.append(first)
            if last and last != first:
                assert last in reads and last > first
                used.append(last)
                link = reads[last]["fallback"]
                assert int(link["from_receipt"]) == first and link["permitted"]
                assert reads[first]["source_id_at_admission"] != reads[last]["source_id_at_admission"]
            for number in {first, last} - {0}:
                read = reads[number]
                assert read["address"] == call["address"] and read["requested_bytes"] == call["length"]
            if call["accepted"]:
                read = reads[last]["read"]
                assert read["status"] == "complete" and not read["cancellation_observed"]
                assert not read["operation_deadline_exceeded"]
                assert call["before_guard"] in ("passed", "not_requested")
                assert call["after_guard"] in ("passed", "not_requested")
                data = b"".join(bytes.fromhex(span["bytes_hex"]) for span in read["spans"])
                assert data == b"Q" * int(call["length"])
        assert used == sorted(set(used))
    selected = indexed["partial-fallback"]
    assert selected["parser_reads"][0]["returned_receipt"] == "2"
    raw = selected["attempts"]["reads"][0]["read"]
    assert raw["native_status_domain"] == "ntstatus" and raw["native_status"] == 0x8000000D
    assert raw["spans"][0]["bytes_hex"] == "41" * 16
    for key in ("guard-1", "guard-2", "guard-3"):
        assert indexed[key]["attempts"]["reads"][0]["read"]["status"] == "complete"
        assert not indexed[key]["parser_reads"][0]["accepted"]
    assert indexed["parser-capacity"]["unrecorded_parser_calls"] == "1"
    for key in ("guard-not-started-0", "guard-not-started-1"):
        assert not indexed[key]["attempts"]["reads"]
        assert indexed[key]["parser_reads"][0]["before_guard"] == "not_run"
    assert indexed["shared-budget-2"]["attempts"]["unrecorded_attempts"] == "1"
    assert indexed["abandoned"]["attempts"]["reads"][0]["abandoned"]
    print(f"Read routing JSON oracle passed: {len(sets)} operation snapshots")


if __name__ == "__main__":
    main()
