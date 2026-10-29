"""Independent JSON assertions for owned Win32 process-memory observations."""
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
    assert [row["status"] for row in rows] == ["policy_denied", "complete", "cancelled", "unsupported", "read_failed", "identity_changed"]
    for index, row in enumerate(rows):
        assert row["schema"] == "kn.observation_read.v1" and row["collector_authenticated"] is False
        assert row["consistency"] == "handle_bound_single_read"
        assert row["identity_revalidated"] is (index in (1, 4))
        assert row["side_effects_possible"] is (index in (1, 4))
        assert row["cancellation_observed"] is (index == 2)
        if index in (1, 4):
            assert row["native_status_domain"] == "win32" and isinstance(row["native_status"], int)
        else:
            assert row["native_status"] is None
    assert rows[1]["native_status"] == 0 and rows[4]["native_status"] != 0
    assert rows[1]["spans"][0]["bytes_hex"] == "5a" * 64
    assert rows[4]["spans"][0]["bytes_hex"] == ""
    print(f"process source JSON oracle: {len(rows)} observations passed")


if __name__ == "__main__":
    main()
