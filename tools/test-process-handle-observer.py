"""Check the controller's process-handle timeline against its Windows process identity."""

import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import re
import subprocess
import tempfile


def run_child(exe, arguments, directory):
    get_times = ctypes.WinDLL("kernel32", use_last_error=True).GetProcessTimes
    get_times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    get_times.restype = wintypes.BOOL
    with subprocess.Popen([exe, *arguments], cwd=directory, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, encoding="utf-8", errors="replace") as child:
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not get_times(int(child._handle), *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            output, errors = child.communicate(timeout=60)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        if child.returncode:
            raise RuntimeError(f"{arguments}: exit {child.returncode}. {errors[-1200:]}")
        return output, child.pid, created


def evidence(rows, calls, pid, created):
    assert [row["action"] for row in rows] == ["process.handle." + call for call in calls]
    for index, row in enumerate(rows, start=1):
        assert row["eventId"] == index and row["pid"] == pid and "targetPid" not in row
        assert (row["source"], row["domain"], row["entity"]) == ("observer", "observer_action", "process_handle:controller")
        assert (row["risk"], row["confidence"]) == ("info", "controller_reported")
        fields = row["evidence"]
        assert fields["schema"] == "kn.observer_action.v1" and fields["ingest_origin"] == "local_controller"
        assert fields["actor"] == "controller" and fields["effect_verified"] == "false"
        assert fields["sequence"] == str(index) and fields["controller_create_time"] == str(created)
        assert fields["status_domain"] == "win32" and (fields["status"] == "0") == (fields["outcome"] == "succeeded")
        assert int(fields["requested_utc_filetime"]) > 0 and int(fields["returned_utc_filetime"]) == row["timestampFileTime"]
        assert fields["possible_observer_effect"] and not {"raw_handle", "handle_value", "granted_access"}.intersection(fields)
        if row["action"] == "process.handle.open":
            assert fields["inherit_handle"] == "false" and "duplicate_options" not in fields
        elif row["action"] == "process.handle.duplicate":
            assert fields["inherit_handle"] == "false" and fields["access_mode"] == "same_as_source"
            assert fields["duplicate_options"] == "0x2" and "requested_access" not in fields
        else:
            assert not {"inherit_handle", "duplicate_options", "requested_access"}.intersection(fields)
    return [row["evidence"] for row in rows]


def check_denied_open(exe, policy_exe, directory):
    child = subprocess.run([policy_exe, "--deny-self-probe", exe], cwd=directory, stdin=subprocess.DEVNULL,
                           capture_output=True, encoding="utf-8", timeout=50)
    if child.returncode:
        raise RuntimeError(f"Denied self-probe fixture exit {child.returncode}. {child.stderr[-400:]}")
    identity = re.fullmatch(r"child pid=(\d+) created=(\d+) exit=1\s*", child.stderr)
    assert identity
    pid, created = map(int, identity.groups())
    probe = json.loads(child.stdout)["probe"]
    assert probe["process_id"] == pid and int(probe["process_create_time"]) == created
    assert probe["process_handle_attempted"] and probe["observer_actions"] == ["owned_process_handle_attempt"]
    assert not probe["process_source_opened"] and not probe["process_read_attempted"] and not probe["sample_bytes_matched"]
    assert probe["process_read"] is None and probe["process_read_set"] is None
    assert probe["process_handles_acquired"] == probe["process_handles_closed"] == 0 and probe["probe_handles_closed"]
    assert not probe["native_probe_attempted"] and probe["native_close_succeeded"] is None
    timeline = probe["process_handle_timeline"]
    assert timeline["count"] == timeline["totalStored"] == 1
    row, = evidence(timeline["events"], ["open"], pid, created)
    assert row["requested_pid"] == str(pid) and row["requested_create_time"] == str(created)
    assert row["outcome"] == "failed" and row["status"] == "5" and row["requested_access"] == "0x1010"
    assert not {"acquisition_id", "observed_pid", "observed_create_time", "identity_win32_status"}.intersection(row)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--policy-exe", type=Path, help="also check denied memory-read access with a standard Windows token")
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="kn-handle-observer-") as directory:
        raw, pid, created = run_child(exe, ["--mode", "observe", "--capabilities", "--probe", "--allow-residency"], directory)
        probe = json.loads(raw)["probe"]
        assert probe["process_id"] == pid and int(probe["process_create_time"]) == created
        assert probe["process_handles_acquired"] == probe["process_handles_closed"] == 2 and probe["probe_handles_closed"] is True
        assert probe["native_close_win32_status"] is None and probe["native_close_succeeded"] is None
        assert probe["observer_actions"] == ["owned_process_handle_and_read"]
        assert bytes.fromhex(probe["process_read"]["spans"][0]["bytes_hex"]) == bytes(range(0x51, 0x71))
        assert probe["process_read_set"]["reads"][0]["read"] == probe["process_read"]
        timeline = probe["process_handle_timeline"]
        assert timeline["schema"] == "kn-live-dbg.timeline.v1" and timeline["count"] == timeline["totalStored"] == 4
        assert timeline["newestFirst"] is False
        fields = evidence(timeline["events"], ["open", "duplicate", "close", "close"], pid, created)
        assert fields[0]["requested_access"] == "0x1010"
        assert [r["handle_site"] for r in fields] == ["owned_capability_probe", "observation_source", "observation_source", "owned_capability_probe"]
        assert [r["acquisition_id"] for r in fields] == ["1", "2", "2", "1"]
        assert [r.get("parent_acquisition_id") for r in fields] == [None, "1", "1", None]
        for row in fields:
            assert row["observed_pid"] == row["requested_pid"] == str(pid)
            assert row["observed_create_time"] == row["requested_create_time"] == str(created)
            assert row["identity_observed_at"] == "acquisition" and row["identity_win32_status"] == row["status"] == "0"

        output, pid, created = run_child(exe, ["--self-test", "process-handle-observer"], directory)
        def records(prefix):
            return [json.loads(line[len(prefix):]) for line in output.splitlines() if line.startswith(prefix)]
        mismatch = evidence(records("[handle.pid-mismatch] "), ["duplicate", "close"], pid, created)
        for row in mismatch:
            assert row["requested_pid"] != str(pid) and row["observed_pid"] == str(pid)
            assert row["requested_create_time"] == str(created) and "observed_create_time" not in row
            assert row["status"] == row["identity_win32_status"] == "0"
        calls = ["open", "duplicate", "open", "duplicate", "close", "close", "duplicate", "close", "open", "close"]
        fields = evidence(records("[handle.fixture] "), calls, pid, created)
        assert [r.get("acquisition_id") for r in fields] == [None, None, "3", "4", "4", "3", "7", "7", "9", "9"]
        assert fields[0]["requested_pid"] == "0" and fields[0]["status"] == "87" and fields[1]["status"] != "0"
        assert all("observed_pid" not in r and "identity_win32_status" not in r for r in fields[:2])
        assert fields[2]["requested_access"] == fields[8]["requested_access"] == "0x1000"
        for row in fields[3:5]:
            assert row["parent_acquisition_id"] == "3" and row["requested_create_time"] == str(created + 1)
            assert row["observed_create_time"] == str(created) and row["observed_pid"] == str(pid)
        for row in fields[6:8]:
            assert row["outcome"] == "succeeded" and row["identity_win32_status"] != "0"
            assert "observed_pid" not in row and "observed_create_time" not in row
        assert fields[9]["outcome"] == "failed" and fields[9]["status"] != "0"
        fields = evidence(records("[handle.native.timeline] "), ["open", "close"], pid, created)
        assert fields[0]["requested_access"] == "0x1000" and all(r["handle_site"] == "identity_lookup" for r in fields)
        assert all(r["observed_create_time"] == str(created) and r["requested_pid"] == str(pid) and "requested_create_time" not in r for r in fields)
        assert output.count("Process handle calls=2 retained=2") == 2
        assert "source_records=2 added=2" in output and "source_records=0 added=0" in output
        assert "[handle.ownership] calls=10 acquired=4 successful_closes=3 fixture_cleanup=passed concurrent_calls=168 retained=64" in output
        if args.policy_exe:
            check_denied_open(exe, args.policy_exe.resolve(strict=True), directory)
            print("Verified Windows access denial (5), one failed open, zero duplicates, reads or closes.")
        assert not list(Path(directory).iterdir()), "test files remain"
    print("Verified 4 probe calls, 10 ownership fixture calls, 2 mismatched-PID calls, 2 CLI rows and 168 concurrent calls.")


if __name__ == "__main__":
    main()
