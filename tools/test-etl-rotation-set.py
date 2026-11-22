"""Verify a signed rotation inventory against three distinct saved ETL files or an owned live rotation."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).parent
SIGNED = runpy.run_path(str(HERE / "test-etl-capture-statement.py"))
CAP = runpy.run_path(str(HERE / "test-etl-capabilities.py"))
SCHEMA = "kn.etl_rotation_inventory.v1"
HEADER = {"alg": "ES256", "typ": SCHEMA + "+jws"}


def pin(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def supplied(pair):
    path = Path(pair[0]).resolve(strict=True)
    assert pin(path) == pair[1].lower()
    return path


def owned(recorder, folder):
    root = folder / "owned-rotation"
    root.mkdir()
    try:
        record = json.loads(SIGNED["run"]([recorder, root, "--rotate"]))
    except BaseException:
        # A named ETW logger can survive a recorder timeout. Only recover this launch's started session.
        for receipt in root.glob("*/controller.knetlowner"):
            SIGNED["run"]([recorder, receipt.parent, "--recover-rotation"])
        raise
    assert record["system_trace_enable_flags"] == 0 and record["increments"] == 2 and record["stop_win32"] == 0
    assert record["cleanup_query_win32"] == 4201  # ERROR_WMI_INSTANCE_NOT_FOUND
    directory = root / record["session_id"]
    files = [directory / f"part-{i}.etl" for i in (1, 2, 3)]
    assert set(directory.iterdir()) == {*files, directory / "controller.knetlowner"}
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    for i, path in enumerate(files, 1):
        xml = folder / "marker.xml"
        SIGNED["run"]([Path(os.environ["SystemRoot"]) / "System32/tracerpt.exe", path, "-o", xml, "-of", "XML", "-rts", "-y"], cwd=folder)
        events = ET.parse(xml).findall(".//" + ns + "Event")
        matches = [e for e in events if record["provider_id"] in SIGNED["provider_guids"](e)]
        assert len(matches) == i
        assert all(f"KnLiveDbg rotation member {i}" in "".join(e.itertext()) for e in matches)
    return files, record["session_id"], dict(win32_status=0, final_ordinal=3, events_lost=record["events_lost"],
                                             log_buffers_lost=record["log_buffers_lost"])


def check_publication_leases(command, paths):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    peek = kernel.PeekNamedPipe
    peek.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]

    def write_open(path):
        handle = create(str(path), 0x40000000, 7, None, 3, 0, None)  # GENERIC_WRITE, all sharing, OPEN_EXISTING
        if handle == ctypes.c_void_p(-1).value:
            return ctypes.get_last_error()
        assert close(handle)
        return 0

    assert all(write_open(path) == 0 for path in paths)
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        try:
            pipe = msvcrt.get_osfhandle(proc.stdout.fileno())
            available = wintypes.DWORD()
            deadline = time.monotonic() + 60
            while not available.value:
                assert proc.poll() is None and time.monotonic() < deadline
                assert peek(pipe, None, 0, None, ctypes.byref(available), None)
                if not available.value:
                    time.sleep(.01)
            assert proc.poll() is None, "the report must exceed the unread pipe buffer"
            assert all(write_open(path) == 32 for path in paths)  # ERROR_SHARING_VIOLATION
            raw, _ = proc.communicate(timeout=60)
            assert proc.returncode == 1 and json.loads(raw)["verified_members"] == 1
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=60)
    assert all(write_open(path) == 0 for path in paths)


def check(exe, openssl, folder, files, sequential, session, stop):
    signer = SIGNED["Signer"](openssl, folder / "signer")
    other = SIGNED["Signer"](openssl, folder / "other")
    token = folder / "inventory.knetlset"
    inspect = SIGNED["AUDIT"]["inspect"]
    rows = [dict(ordinal=i, etl_bytes=str(p.stat().st_size), etl_sha256=pin(p)) for i, p in enumerate(files, 1)]
    assert len({r["etl_sha256"] for r in rows}) == 3
    claims = dict(schema=SCHEMA, role="capture_controller", session_id=session, stop=stop, members=rows)
    bindings = [(i, files[i-1]) for i in (3, 1, 2)]

    def sign(value, header=HEADER):
        token.write_bytes(signer.token(value, header) + b"\r\n")

    def argv(paths=bindings, role="capture_controller", key=None, digest=None):
        return [exe, "--etl-rotation-set", token, "--sha256", digest or pin(token), "--authority", role,
                key or signer.point, *(str(v) for i, path in paths for v in ("--member", i, path))]

    def verify(status, rc=1, **options):
        report = json.loads(SIGNED["run"](argv(**options), rc))
        assert report["schema"] == "kn.etl_rotation_set.v1" and report["status"] == status, report["status"]
        assert report["session_membership_independently_verified"] is report["cross_member_timing_checked"] is report["lossless_session_verified"] is False
        return report

    def rejected(status, signature, **options):
        report = verify(status, **options)
        assert report["signature_verified"] is signature and report["inventory_authenticated"] is False
        for name in ("signed_role", "controller_stop", "session_id", "members", "closed_controller_inventory_verified", "verified_members"):
            assert report[name] is None

    sign(claims)
    complete = verify("closed_controller_inventory", 0)
    assert complete["controller_stop"] == stop and complete["session_id"] == session
    assert complete["verified_members"] == 3 and complete["contiguous_inventory_verified"] is complete["closed_controller_inventory_verified"] is True
    assert complete["signature_verified"] is complete["inventory_authenticated"] is True
    for i, row in enumerate(complete["members"], 1):
        assert row["ordinal"] == i and row["status"] == "verified" and row["supplied"] is True
        assert row["observed_bytes"] == row["expected_bytes"] == files[i-1].stat().st_size and row["open_win32_error"] is None
        probe = row["probe"]
        assert probe["source_sha256"] == row["expected_sha256"] == rows[i-1]["etl_sha256"] and probe["source_revalidated"] is True
        total, _ = CAP["windows_counts"](files[i-1], folder)
        summary = (folder / "summary.txt").read_bytes().decode("latin1")
        buffers = int(re.search(r"(?m)^Total Buffers +Processed +(\d+)", summary)[1])
        c = probe["coverage"]
        assert (c["records_seen"], c["buffers_processed"], c["buffer_comparison"]) == (total, buffers, "not_comparable")
        assert probe["rotation_member"]["session_complete"] is None and probe["status"] == "partial"
    for value in (complete, complete["members"][0], claims, rows[0], stop):
        assert inspect("renamed.txt", json.dumps(value).encode())
        nested = json.dumps({"exported": {"record": value}}, separators=(",", ":")).encode()
        assert inspect("renamed.txt", nested) and inspect("renamed.txt", nested[:-3])
    for part in (token.read_bytes(), *token.read_bytes().strip().split(b".")[:2]):
        assert inspect("renamed.txt", part)
    assert complete == verify("closed_controller_inventory", 0, paths=list(reversed(bindings)))
    page_args = [exe, "--etl-profile", files[0], "--sha256", rows[0]["etl_sha256"], "--limit", "1"]
    page_pin = hashlib.sha256(SIGNED["run"](page_args, 1)).hexdigest()
    single = json.loads(SIGNED["run"]([*page_args, "--check-page", page_pin, "--capture-statement",
                                       token, "capture_controller", signer.point], 1))
    assert single["status"] == "capture_statement_rejected" and single["capture_statement"]["status"] == "invalid_jws"

    missing = verify("incomplete_set", paths=bindings[:-1])
    assert [r["status"] for r in missing["members"]] == ["verified", "not_supplied", "verified"]
    assert missing["verified_members"] == 2 and missing["closed_controller_inventory_verified"] is False
    absent = verify("incomplete_set", paths=[(1, folder / "absent.etl")])
    assert absent["members"][0]["status"] == "source_unavailable" and absent["members"][0]["open_win32_error"] == 2
    output = folder / "partial.json"
    with output.open("wb") as sink:
        result = subprocess.run(argv(paths=[(1, folder / "missing-dir" / "absent.etl")]), stdout=sink, stderr=subprocess.PIPE, timeout=60)
    missing_dir = json.loads(output.read_bytes())["members"][0]
    assert result.returncode == 1 and missing_dir["status"] == "source_unavailable" and missing_dir["open_win32_error"] in (2, 3)
    absent_inventory = argv()
    absent_inventory[2] = folder / "missing-inventory.knetlset"
    unavailable = json.loads(SIGNED["run"](absent_inventory, 1))
    assert unavailable["status"] == "inventory_unavailable" and unavailable["inventory_open_win32_error"] == 2
    junction, target = folder / "junction", folder / "target"
    target.mkdir()
    shell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    SIGNED["run"]([shell, "-NoProfile", "-NonInteractive", "-Command",
                   "[void](New-Item -ItemType Junction -Path $env:KN_ETL_TEST_JUNCTION -Target $env:KN_ETL_TEST_TARGET -ErrorAction Stop)"],
                  env=dict(os.environ, KN_ETL_TEST_JUNCTION=str(junction), KN_ETL_TEST_TARGET=str(target)))
    try:
        with output.open("wb") as sink:
            result = subprocess.run(argv(paths=[(1, junction / "absent.etl")]), stdout=sink, stderr=subprocess.PIPE, timeout=60)
        assert result.returncode == 2 and output.stat().st_size == 0
    finally:
        junction.rmdir()
    swapped = verify("incomplete_set", paths=[(1, files[1]), (2, files[0]), (3, files[2])])
    assert swapped["verified_members"] == 1 and all(r["status"] in ("size_mismatch", "digest_mismatch") for r in swapped["members"][:2])
    extra = verify("incomplete_set", paths=[*bindings, (4, sequential)])
    assert extra["members"][-1]["status"] == "unexpected_input" and extra["closed_controller_inventory_verified"] is False
    changed = folder / "substitute.etl"
    shutil.copyfile(files[0], changed)
    with changed.open("r+b") as stream:
        first = stream.read(1)[0]
        stream.seek(0)
        stream.write(bytes([first ^ 1]))
    mismatch = verify("incomplete_set", paths=[(1, changed)])["members"][0]
    assert mismatch["status"] == "digest_mismatch" and mismatch["probe"]["source_sha256"] == pin(changed)
    sign(dict(claims, members=[rows[0], rows[2]], stop=dict(stop, final_ordinal=5)))
    gap = verify("incomplete_set", paths=[(1, files[0]), (3, files[2])])
    assert [r["status"] for r in gap["members"]] == ["verified", "not_in_inventory", "verified", "not_in_inventory", "not_in_inventory"]
    sign(dict(claims, members=[dict(rows[0], etl_bytes=str(sequential.stat().st_size), etl_sha256=pin(sequential))]))
    assert verify("incomplete_set", paths=[(1, sequential)])["members"][0]["status"] == "not_rotating"

    sign(dict(claims, members=[]))
    empty = verify("incomplete_set", paths=[])
    assert empty["signature_verified"] and [r["status"] for r in empty["members"]] == ["not_in_inventory"] * 3
    assert empty["verified_members"] == 0 and empty["closed_controller_inventory_verified"] is False
    sign(dict(claims, members=[dict(rows[0], etl_bytes=str(512 << 20)), rows[1]]))
    assert verify("incomplete_set", paths=[])["inventory_authenticated"] is True

    sign(dict(claims, stop=None))
    assert verify("ordered_members_verified", 0)["closed_controller_inventory_verified"] is None
    failed_stop = dict(win32_status=5, final_ordinal=None, events_lost=None, log_buffers_lost=None)
    sign(dict(claims, stop=failed_stop))
    failed = verify("controller_stop_failed")
    assert failed["contiguous_inventory_verified"] is True and failed["controller_stop"] == failed_stop
    archive = dict(claims, role="archive_witness", session_id=None, stop=None)
    sign(archive)
    witness = verify("ordered_members_verified", 0, role="archive_witness")
    assert witness["signed_role"] == "archive_witness" and witness["closed_controller_inventory_verified"] is None
    rejected("signer_role_mismatch", True)
    sign(claims)
    rejected("signature_rejected", False, key=other.point)
    rejected("inventory_digest_mismatch", None, digest="0"*64)
    raw = token.read_bytes().strip().split(b".")
    raw[2] = (b"B" if raw[2][:1] == b"A" else b"A") + raw[2][1:]
    token.write_bytes(b".".join(raw))
    rejected("signature_rejected", False)
    sign(claims, SIGNED["HEADER"])
    rejected("invalid_jws", None)

    invalid = [dict(archive, stop=stop), dict(claims, session_id=None), dict(claims, members=[], stop=None),
               dict(claims, stop=dict(stop, final_ordinal=2)), dict(claims, stop=dict(failed_stop, events_lost=0)),
               dict(claims, stop=dict(stop, events_lost=-1)), dict(claims, stop=dict(stop, final_ordinal=True)),
               dict(claims, members=rows[::-1]), dict(claims, members=[rows[0], rows[0]]),
               dict(claims, members=[rows[0], dict(rows[0], ordinal=2)]),
               dict(claims, members=[dict(rows[0], ordinal=33)]), dict(claims, members=[dict(rows[0], etl_bytes="0")]),
               dict(claims, members=[dict(rows[0], etl_bytes=str((512 << 20) + 1))]), dict(claims, extra=True)]
    for value in invalid:
        sign(value)
        rejected("invalid_claims", True)
    compact = SIGNED["compact"](claims)
    sign(compact.replace(b'"role":', b'"role":"archive_witness","role":', 1))
    rejected("invalid_claims", True)
    long_rows = [dict(ordinal=i, etl_bytes="1", etl_sha256=hashlib.sha256(str(i).encode()).hexdigest()) for i in range(1, 33)]
    long_claims = dict(claims, members=long_rows, stop=dict(stop, final_ordinal=32))
    sign(json.dumps(long_claims, indent=8).encode())
    assert len(verify("incomplete_set", paths=[])["members"]) == 32
    payload = token.read_bytes().split(b".")[1]
    assert len(payload) > 5460 and inspect("detached.txt", payload)
    # Wait for an actual pending output write, then request writable opens on the same files.
    readable = folder / "owned-first.etl"
    shutil.copyfile(files[0], readable)
    sign(dict(long_claims, members=[rows[0], *long_rows[1:]]))
    check_publication_leases(argv(paths=[(1, readable)]), (token, readable))
    with readable.open("r+b"):
        busy = verify("incomplete_set", paths=[(1, readable)])
        assert busy["members"][0]["status"] == "source_unavailable" and busy["members"][0]["open_win32_error"] == 32
        assert busy["verified_members"] == 0

    sign(claims)
    for tail in (["--member", "1", files[0]], ["--bad", changed], ["--member", "0", files[0]], ["--member", "33", files[0]]):
        assert not SIGNED["run"]([*argv(), *tail], 2)
    for target in (token, changed):
        original = pin(target)
        alias = folder / "output-alias"
        os.link(target, alias)
        try:
            for sink, tail in (("stdout", []), ("stderr", ["--bad"])):
                with alias.open("ab") as stream:
                    result = subprocess.run([*argv(paths=[(1, changed)]), *tail], **{sink: stream}, timeout=60)
                assert result.returncode == 2 and pin(target) == original
            with alias.open("ab") as stream:
                result = subprocess.run([exe, "--mode", "offline", *argv(paths=[(1, changed)])[1:]], stdout=stream, timeout=60)
            assert result.returncode == 5 and pin(target) == original
        finally:
            alias.unlink()
    assert [r["etl_sha256"] for r in rows] == [pin(p) for p in files]
    print("Verified signed order, missing members, stop and loss claims, source pins, signer boundaries and output aliases.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--openssl", type=Path, required=True)
    p.add_argument("--sequential", nargs=2, metavar=("FILE", "SHA256"), required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--etl", nargs=2, action="append", metavar=("FILE", "SHA256"), help="repeat for three distinct rotating files")
    group.add_argument("--recorder", type=Path, help="owned ETW recorder built from etl-statement-capture.cpp")
    a = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-rotation-set-") as temp:
        folder = Path(temp)
        if a.recorder:
            files, session, stop = owned(a.recorder.resolve(strict=True), folder)
        else:
            if len(a.etl) != 3:
                p.error("pass exactly three --etl FILE SHA256 pairs")
            files = [supplied(pair) for pair in a.etl]
            session = str(uuid.uuid4())
            stop = dict(win32_status=0, final_ordinal=3, events_lost=4, log_buffers_lost=1)
        check(a.exe.resolve(strict=True), a.openssl.resolve(strict=True), folder, files, supplied(a.sequential), session, stop)


if __name__ == "__main__":
    main()
