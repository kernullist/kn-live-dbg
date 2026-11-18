"""Check exported control receipts against the scripted calls and a real pipe rejection."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def receipt(lines, prefix):
    matches = [json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix)]
    assert len(matches) == 1, f"expected one {prefix} row"
    row = matches[0]
    evidence = row["evidence"]
    assert row["source"] == "observer" and row["domain"] == "observer_action"
    assert row["entity"] == "driver:KnLiveDbg/timeline" and "targetPid" not in row
    assert row["risk"] == "info" and row["confidence"] == "controller_reported"
    assert evidence["schema"] == "kn.observer_action.v1" and evidence["ingest_origin"] == "local_controller"
    assert evidence["actor"] == "controller" and evidence["effect_verified"] == "false"
    assert row["pid"] > 0 and int(evidence["controller_create_time"]) > 0
    assert int(evidence["requested_utc_filetime"]) > 0 and int(evidence["returned_utc_filetime"]) == row["timestampFileTime"]
    assert int(evidence["device_epoch"]) > 0
    return row, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    exe = parser.parse_args().exe.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="kn-callback-receipt-") as directory:
        run = subprocess.run([exe, "--self-test", "callback-ownership"], cwd=directory, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, encoding="utf-8", errors="replace", timeout=60)
        if run.returncode:
            raise RuntimeError(run.stdout[-1600:])
        assert not list(Path(directory).iterdir()), "test artifacts remain"
    lines = run.stdout.splitlines()
    assert lines.count("[callback.activation.fixture] rejected_states=13 fresh_starts=2 stale_stops=0") == 1
    assert lines.count("[callback.activation.overlap] connections=2 starts=1 reuses=1 receipts=1") == 1
    assert lines.count("[callback.activation.native] status_failed=1 start_receipts=0") == 1
    failed, detail = receipt(lines, "[callback.fixture.receipt] ")
    assert failed["action"] == "timeline.callbacks.start" and detail["outcome"] == "failed"
    assert detail["possible_observer_effect"] == "initialize_or_reset_ring_and_register_callbacks"
    assert detail["win32_status"] == "0" and detail["status_domain"] == "ntstatus" and detail["status"] == "0xc0000022"
    assert detail["request_action"] == "1" and int(detail["request_id"]) > 0 and detail["requested_capacity"] == "128"
    assert detail["before_flags"] == "0xe" and detail["after_flags"] == "0x2" and detail["callback_calls"] == "8"
    expected = [("thread", "unregister", "0x0"), ("process", "unregister", "0x0"), ("image", "unregister", "0x0"),
                ("process", "register", "0x0"), ("image", "register", "0x0"), ("thread", "register", "0xc0000022"),
                ("process", "unregister", "0x80000011"), ("image", "unregister", "0x0")]
    actual = [tuple(detail[f"call.{i}.{field}"] for field in ("callback", "request", "ntstatus")) for i in range(1, 9)]
    assert actual == expected and "call.9.callback" not in detail
    for i in range(1, 9):
        requested = 133000000000000000 + (i - 1) * 10
        assert int(detail[f"call.{i}.requested_utc_filetime"]) == requested
        assert int(detail[f"call.{i}.returned_utc_filetime"]) == requested + 5
    native, error = receipt(lines, "[callback.native.receipt] ")
    assert native["pid"] == failed["pid"] and native["action"] == "timeline.ring.clear" and error["outcome"] == "transport_failed"
    assert error["status_domain"] == "win32" and error["status"] == error["win32_status"] and int(error["status"]) != 0
    assert error["request_action"] == "3" and error["returned_bytes"] == "0"
    assert not {"before_flags", "after_flags", "callback_calls", "request_id", "call.1.ntstatus"}.intersection(error)
    assert run.stdout.count("Live callback control calls=1 retained=1") == 2
    print(f"Callback control receipts passed: 8 ordered DDI calls, original and rollback errors, "
          f"native Win32 {error['status']}, repeated CLI ingest, no test files")


if __name__ == "__main__":
    main()
