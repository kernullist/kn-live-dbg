"""Independent JSON contract checks over the actual C++ ledger serializer."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    args = parser.parse_args()
    run = subprocess.run([args.exe], capture_output=True, text=True, encoding="utf-8", timeout=60)
    print(run.stderr, end="")
    assert run.returncode == 0, run.stdout
    rows = [json.loads(line) for line in run.stdout.splitlines()]
    expected = [
        (1, "queued", False, False, "10", None, None),
        (1, "cancelled_before_execution", False, True, "10", None, "20"),
        (2, "running", True, False, "30", "31", None),
        (2, "unknown_outcome", True, False, "30", "31", None),
        (2, "succeeded", True, True, "30", "31", "40"),
        (3, "failed", True, True, "50", "51", "60"),
        (4, "unknown_outcome", True, True, "70", "71", "80"),
    ]
    assert len(rows) == len(expected)
    for row, (identity, state, dispatched, finished, queued, started, ended) in zip(rows, expected):
        assert row["schema"] == "kn.mcp_operation.v1"
        assert row["operation_id"] == f"{identity:032x}"
        assert row["state"] == state
        assert row["engine_dispatched"] is dispatched and row["operation_finished"] is finished
        assert row["engine_finished"] is (dispatched and finished)
        assert (row["queued_tick_ms"], row["started_tick_ms"], row["finished_tick_ms"]) == (queued, started, ended)
        assert row["clock"] == "collector_boot_tick_ms" and row["capacity"] == 256
        assert row["retention"] == "bounded_server_lifetime"
        for field in ("result_payload_retained", "effects_verified", "rollback_performed", "automatic_retry"):
            assert row[field] is False
    print(f"mcp operation JSON oracle: {len(rows)} state records passed")


if __name__ == "__main__":
    main()
