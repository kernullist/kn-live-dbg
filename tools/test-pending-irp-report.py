"""Check the real IRP parser's snapshot report with an independent JSON oracle."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    args = parser.parse_args()
    run = subprocess.run([str(args.exe.resolve()), "--json"], capture_output=True,
                         text=True, check=True, timeout=90)
    rows = json.loads(run.stdout)
    assert len(rows) == 6
    for row in rows:
        assert row["schema"] == "kn.irp_observation.v1"
        assert row["state"] == "RequestObserved" and row["outcome"] == "UnknownOutcome"
        assert row["transitions"] == []
        for key in ("atomic", "referenced_lifetime", "execution_observed", "actor_attributed",
                    "deadlock_established", "global_inventory"):
            assert row[key] is False, key
        assert row["process_create_time"] is None
        assert row["identity_scope"] == row["graph"]["id_scope"] == "single_observation"
        assert row["started_tick_ms"] == "100" and row["finished_tick_ms"] == "110"
        nodes = {node["id"]: node for node in row["graph"]["nodes"]}
        assert len(nodes) == len(row["graph"]["nodes"])
        for edge in row["graph"]["edges"]:
            assert edge["from"] in nodes and edge["to"] in nodes
            assert edge["kind"] in {"thread_list_member_observed", "stack_location_observed", "pointer_reference_observed"}
        for node in nodes.values():
            if node["kind"].endswith("_pointer"):
                assert node["object_validated"] is False
                assert int(node["address"]) >= 0xFFFF800000000000
    assert rows[0]["cancel_flag"] is False and not rows[0]["stacks"][0]["completion_registered"]
    assert rows[1]["cancel_flag"] is True and rows[1]["pending_returned"] is True
    assert rows[1]["io_status"] == 0 and rows[1]["outcome"] != "Completed"
    assert rows[2]["stacks"][0]["file"] == str(0x1234)
    assert not any(n["kind"] == "file_pointer" for n in rows[2]["graph"]["nodes"])
    assert all(rows[3][key] is None for key in ("cancel_flag", "pending_returned", "io_status"))
    assert rows[3]["stacks"][0]["device"] is None and rows[3]["stacks"][0]["file"] is None
    assert rows[4]["stacks"] == [] and rows[4]["outcome"] == "UnknownOutcome"
    assert rows[5]["stacks_total"] == 65 and rows[5]["stacks_truncated"] and len(rows[5]["stacks"]) == 64
    print("pending IRP JSON oracle passed: six reports, resolved edges, unknown outcomes and bounded export")


if __name__ == "__main__":
    main()
