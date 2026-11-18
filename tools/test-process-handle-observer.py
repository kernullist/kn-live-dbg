"""Check the controller's process-handle timeline against its Windows process identity."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import _winapi


def creation_time(handle):
    get_times = ctypes.WinDLL("kernel32", use_last_error=True).GetProcessTimes
    get_times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    get_times.restype = wintypes.BOOL
    times = [wintypes.FILETIME() for _ in range(4)]
    if not get_times(handle, *(ctypes.byref(t) for t in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def run_child(exe, arguments, directory, reference=None):
    startup = None
    if reference is not None:
        startup = subprocess.STARTUPINFO()
        startup.lpAttributeList = {"handle_list": [reference]}
        os.set_handle_inheritable(reference, True)
    try:
        child = subprocess.Popen([exe, *arguments], cwd=directory, startupinfo=startup, close_fds=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 encoding="utf-8", errors="replace")
    finally:
        if reference is not None:
            os.set_handle_inheritable(reference, False)
    with child:
        try:
            created = creation_time(int(child._handle))
            output, errors = child.communicate(timeout=60)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        if child.returncode:
            label = arguments[:2] if reference is not None else arguments
            raise RuntimeError(f"{label}: exit {child.returncode}. {errors[-1200:]}")
        return output, child.pid, created


def evidence(rows, calls, pid, created, first_sequence=1):
    assert [row["action"] for row in rows] == ["process.handle." + call for call in calls]
    for index, row in enumerate(rows, start=1):
        assert row["eventId"] == index and row["pid"] == pid and "targetPid" not in row
        assert (row["source"], row["domain"], row["entity"]) == ("observer", "observer_action", "process_handle:controller")
        assert (row["risk"], row["confidence"]) == ("info", "controller_reported")
        fields = row["evidence"]
        assert row["summary"] == row["action"] + " " + fields["outcome"]
        assert fields["schema"] == "kn.observer_action.v1" and fields["ingest_origin"] == "local_controller"
        assert fields["actor"] == "controller" and fields["effect_verified"] == "false"
        assert fields["sequence"] == str(first_sequence + index - 1) and fields["controller_create_time"] == str(created)
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


def process_open_status(pid, mask):
    open_process = ctypes.WinDLL("kernel32", use_last_error=True).OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    handle = open_process(mask, False, pid)
    if not handle:
        return ctypes.get_last_error()
    _winapi.CloseHandle(handle)
    return 0


def package_path_available(handle):
    kernel = ctypes.WinDLL("kernel32")
    name = kernel.GetPackageFullName
    path = kernel.GetPackagePathByFullName
    output = [ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR]
    name.argtypes = [wintypes.HANDLE, *output]
    path.argtypes = [wintypes.LPCWSTR, *output]
    def read(query, subject):
        length = wintypes.DWORD()
        if query(subject, ctypes.byref(length), None) != 122 or not 0 < length.value <= 32768:
            return ""
        buffer = ctypes.create_unicode_buffer(length.value)
        return buffer.value if query(subject, ctypes.byref(length), buffer) == 0 else ""
    package = read(name, handle)
    return bool(package and read(path, package))


def deny_child_access(child, mask):
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = wintypes.LPVOID
    convert = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(wintypes.DWORD))
    apply_dacl = security.SetKernelObjectSecurity
    apply_dacl.argtypes = (wintypes.HANDLE, wintypes.DWORD, pointer)
    release = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
    release.argtypes = (pointer,)
    release.restype = pointer
    descriptor = pointer()
    if not convert(f"D:P(D;;{mask:#x};;;WD)(A;;GA;;;OW)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not apply_dacl(int(child._handle), 4, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        release(descriptor)


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [("base", wintypes.LPVOID), ("allocation", wintypes.LPVOID),
                ("allocation_protect", wintypes.DWORD), ("partition", wintypes.WORD),
                ("size", ctypes.c_size_t), ("state", wintypes.DWORD),
                ("protect", wintypes.DWORD), ("type", wintypes.DWORD)]


def guard_mapping(handle, address):
    if address > ctypes.c_size_t(-1).value:
        raise ValueError("The supervisor needs a 64-bit Python to query this test page.")
    query = ctypes.WinDLL("kernel32", use_last_error=True).VirtualQueryEx
    query.argtypes = (wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MemoryBasicInformation), ctypes.c_size_t)
    query.restype = ctypes.c_size_t
    row = MemoryBasicInformation()
    if query(handle, address, ctypes.byref(row), ctypes.sizeof(row)) != ctypes.sizeof(row):
        raise ctypes.WinError(ctypes.get_last_error())
    assert row.base == row.allocation == address and row.state == 0x1000 and row.type == 0x20000
    return (row.size, row.protect)


def check_layout_collection(exe, directory, deny):
    query, full = 0x400, 0x410
    expected_status = {0: (0, 0), 0x10: (5, 0), query: (5, 5)}
    with subprocess.Popen([exe, "--self-test", "layout-handle-observer"], cwd=directory, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8") as child, ThreadPoolExecutor(1) as reader:
        def line():
            return reader.submit(child.stdout.readline).result(timeout=30).strip()
        def send(command):
            child.stdin.write(command + "\n")
            child.stdin.flush()
        try:
            ready = re.fullmatch(r"\[layout\.guard\] (\d+)", line())
            assert ready, "missing owned guard mapping"
            address = int(ready[1])
            handle = int(child._handle)
            created = creation_time(handle)
            if deny:
                deny_child_access(child, deny)
            statuses = tuple(process_open_status(child.pid, mask) for mask in (full, query))
            assert statuses == expected_status[deny]
            before = guard_mapping(handle, address)
            assert before[1] == 0x104
            send("collect")
            end = re.fullmatch(r"\[layout\.collect\] completed=(\d+) failed=(\d+) rows=(\d+) status=(\w+)", line())
            assert end and guard_mapping(handle, address) == before
            send("clear")
            assert line() == "[layout.control] cleared"
            assert guard_mapping(handle, address) == (before[0], 0x04)
            output, errors = child.communicate("finish\n", timeout=30)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=15)
        assert child.returncode == 0, errors[-400:]
        pid = child.pid
    completed, failed, stored = map(int, end.groups()[:3])
    assert completed == int(0 in statuses) and failed == 1 - completed
    assert (stored > 0) == bool(completed)
    assert end[4] == ("initial_observation" if completed else "process_query_unavailable")
    steps = [(full, statuses[0])]
    if statuses[0]:
        steps.append((query, statuses[1]))
    calls = ["open"] * len(steps) + (["close"] if completed else [])
    rows = [json.loads(s.removeprefix("[layout.handle] ")) for s in output.splitlines() if s.startswith("[layout.handle] ")]
    turns, remainder = divmod(len(rows), len(calls))
    assert turns > 0 and not remainder and (completed or turns == 1)
    events = evidence(rows, calls * turns, pid, created)
    for turn in range(turns):
        batch = events[turn * len(calls):(turn + 1) * len(calls)]
        for field in batch:
            assert field["handle_site"] == "layout_collection" and field["requested_pid"] == str(pid)
            assert field.get("requested_create_time") == (str(created) if turn else None)
        for row, (mask, status) in zip(batch, steps):
            assert row["requested_access"] == hex(mask) and row["status"] == str(status)
            if status:
                assert not {"acquisition_id", "observed_pid", "observed_create_time", "identity_win32_status"}.intersection(row)
        if completed:
            acquired, released = batch[-2:]
            assert acquired["sequence"] == acquired["acquisition_id"] == released["acquisition_id"]
            for row in (acquired, released):
                assert row["status"] == row["identity_win32_status"] == "0" and row["observed_pid"] == str(pid)
                assert row["observed_create_time"] == str(created) and row["identity_observed_at"] == "acquisition"
    print(f"Layout collection: deny={deny:#x}, turns={turns}, calls={len(rows)}, guard retained and clear control observed.")


def check_layout_verification(exe, directory):
    output, pid, created = run_child(exe, ["--self-test", "layout-scheduler"], directory)
    diagnostic = json.loads(output)
    normal = diagnostic["normal"]["normal"]
    assert diagnostic["passed"] and normal["attempts"] == "4" and normal["qualified_mappings"] == "2"
    assert normal["outcomes"]["expired"] == normal["outcomes"]["mapping_or_identity_unavailable"] == "1"
    timeline = diagnostic["verification_handle_timeline"]
    assert timeline["count"] == timeline["totalStored"] == 6
    rows = evidence(timeline["events"], ["open", "close"] * 3, pid, created)
    assert sorted(int(row["requested_create_time"]) for row in rows[::2]) == [created - 1, created, created]
    for opened, closed in zip(rows[::2], rows[1::2]):
        assert opened["requested_access"] == "0x410" and opened["sequence"] == opened["acquisition_id"] == closed["acquisition_id"]
        assert closed["requested_create_time"] == opened["requested_create_time"]
        for row in (opened, closed):
            assert row["handle_site"] == "layout_verification" and row["requested_pid"] == row["observed_pid"] == str(pid)
            assert row["observed_create_time"] == str(created) and row["status"] == row["identity_win32_status"] == "0"
    print("Verified 4 dispatched layout candidates, 3 opens and closes, 1 expired before open and 1 generation mismatch.")


def collector_rows(output):
    prefix = "[collector.handle] "
    return [json.loads(line[len(prefix):]) for line in output.splitlines() if line.startswith(prefix)]


def check_collector_retention(exe, directory, target, reference):
    output, actor, actor_created = run_child(exe, ["--self-test", "collector-handle-observer", str(reference), "retention"],
                                             directory, reference=reference)
    rows = evidence(collector_rows(output), ["open", "close"] * 32, actor, actor_created, first_sequence=17)
    created = creation_time(int(target._handle))
    for opened, closed in zip(rows[::2], rows[1::2]):
        assert opened["acquisition_id"] == closed["acquisition_id"] == opened["sequence"]
        for row in (opened, closed):
            assert row["handle_site"] == "ti_image_lookup" and row["status"] == row["identity_win32_status"] == "0"
            assert row["requested_pid"] == row["observed_pid"] == str(target.pid) and row["observed_create_time"] == str(created)
    assert actor != target.pid and output.count("16 process handle observer actions evicted before ingest") == 1
    assert output.count("Process handle calls=80 retained=64") == 2
    assert "source_records=64 added=64" in output and "source_records=0 added=0" in output
    print("Verified 40 TI name lookups, 80 calls, 64 retained rows and 16 evictions reported once.")


def check_collector_run(exe, directory, target, reference, phase):
    pid, created = target.pid, creation_time(int(target._handle))
    limited, synchronized = 0x1000, 0x101000
    statuses = {mask: process_open_status(pid, mask) for mask in (limited, synchronized)}
    if phase == "live":
        assert statuses == {limited: 0, synchronized: 0}
    elif phase == "deny_synchronize":
        assert statuses == {limited: 0, synchronized: 5}
    elif phase == "deny_query":
        assert statuses == {limited: 5, synchronized: 5}
    alive = target.poll() is None
    assert alive == (phase != "exited")
    output, actor, actor_created = run_child(exe, ["--self-test", "collector-handle-observer", str(reference)],
                                            directory, reference=reference)
    assert pid != actor
    def printed(prefix):
        return [dict(item.split("=", 1) for item in line[len(prefix):].split())
                for line in output.splitlines() if line.startswith(prefix)]
    rows = collector_rows(output)
    requests = [("ti_image_lookup", synchronized, 0)] * 2 + [("kmon_user_inventory", limited, 0)]
    for expected in (created, created + 1, 0):
        requests.append(("hunt_public_details", limited, expected))
        if expected:
            requests.append(("hunt_package_identity", synchronized, expected))
    calls = []
    for _, mask, _ in requests:
        calls.append("open")
        if not statuses[mask]:
            calls.append("close")
    details = iter(evidence(rows, calls, actor, actor_created))
    for site, mask, requested in requests:
        opened = next(details)
        assert opened["requested_access"] == hex(mask) and int(opened["status"]) == statuses[mask]
        pair = [opened]
        if statuses[mask]:
            assert not {"acquisition_id", "observed_pid", "observed_create_time", "identity_win32_status"}.intersection(opened)
        else:
            close = next(details)
            assert close["acquisition_id"] == opened["acquisition_id"] == opened["sequence"] and close["status"] == "0"
            pair.append(close)
            for row in pair:
                assert row["observed_pid"] == str(pid) and row["observed_create_time"] == str(created)
                assert row["identity_observed_at"] == "acquisition" and row["identity_win32_status"] == "0"
        for row in pair:
            assert row["requested_pid"] == str(pid) and row["handle_site"] == site
            assert row.get("requested_create_time") == (str(requested) if requested else None)
    assert output.count(f"Process handle calls={len(rows)} retained={len(rows)}") == 2
    assert f"source_records={len(rows)} added={len(rows)}" in output and "source_records=0 added=0" in output
    ti_image = str(int(alive and not statuses[synchronized]))
    assert printed("[collector.ti] ") == [{"image": ti_image, "matches": ti_image}] * 2
    inventory, = printed("[collector.inventory] ")
    assert int(inventory["created"]) == (0 if statuses[limited] else created)
    assert int(inventory["pinned"]) == int(not statuses[limited]) and inventory["matches"] == inventory["image"]
    if alive:
        assert int(inventory["image"]) == int(not statuses[limited])
    hunt = printed("[collector.hunt] ")
    assert [int(r["requested"]) for r in hunt] == [created, created + 1, 0]
    lookup_session = ctypes.WinDLL("kernel32", use_last_error=True).ProcessIdToSessionId
    lookup_session.argtypes = (wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    session = wintypes.DWORD()
    session_known = bool(lookup_session(pid, ctypes.byref(session)))
    has_package = alive and package_path_available(reference)
    for row in hunt:
        stale = int(row["requested"]) == created + 1
        assert int(row["changed"]) == int(not statuses[limited] and (not alive or stale))
        qualified = alive and not stale and not statuses[limited]
        assert row["matches"] == row["image"] and int(row["image"]) == int(qualified)
        assert int(row["session_queries"]) == int(row["pinned_at_session"]) == int(qualified), "session lookup outside qualified handle lifetime"
        assert int(row["session_known"]) == int(qualified and session_known)
        if row["session_known"] == "1":
            assert int(row["session"]) == session.value
        assert row["package"] == row["package_path"]
        assert int(row["package"]) == int(has_package and not statuses[synchronized] and int(row["requested"]) == created)
    print(f"Collector {phase}: {len(requests)} opens, {calls.count('close')} closes, package metadata present={has_package}.")


def check_collectors(exe, directory, denied_cases):
    # The child waits on its parent's pipe. The retained creation handle keeps
    # its process object identifiable after the child has exited.
    for restrict in ([False, True] if denied_cases else [False]):
        with subprocess.Popen([sys.executable, "-I", "-B", "-c", "import sys; sys.stdin.buffer.read(1)"],
                              cwd=directory, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as target:
            owner = _winapi.GetCurrentProcess()
            reference = _winapi.DuplicateHandle(owner, int(target._handle), owner, 0x101000, False, 0)
            try:
                if restrict:
                    deny_child_access(target, 0x100000)
                    check_collector_run(exe, directory, target, reference, "deny_synchronize")
                    deny_child_access(target, 0x1000)
                    check_collector_run(exe, directory, target, reference, "deny_query")
                else:
                    check_collector_run(exe, directory, target, reference, "live")
                    check_collector_retention(exe, directory, target, reference)
                    target.stdin.close()
                    assert target.wait(timeout=15) == 0
                    check_collector_run(exe, directory, target, reference, "exited")
            finally:
                _winapi.CloseHandle(reference)
                target.stdin.close()
                try:
                    target.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    target.kill()
                    target.wait(timeout=15)
                    raise


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
        check_collectors(exe, directory, denied_cases=bool(args.policy_exe))
        for deny in (0, 0x10, 0x400):
            check_layout_collection(exe, directory, deny)
        check_layout_verification(exe, directory)
        assert not list(Path(directory).iterdir()), "test files remain"
    print("Verified 4 probe calls, 10 ownership fixture calls, 2 mismatched-PID calls, 2 CLI rows and 168 concurrent calls.")


if __name__ == "__main__":
    main()
