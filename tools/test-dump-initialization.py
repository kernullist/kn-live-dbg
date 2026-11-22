"""Compare initialization receipts with the known byte layout of the owned dump-source fixtures."""
import argparse
import hashlib
import json
import msvcrt
import os
from pathlib import Path
from runpy import run_path
import shutil
import struct
import subprocess
import tempfile


HEADER = 8192
PAGE = 4096
HEADER_READ = (None, "dump_header", None, 0, HEADER)


def arguments(path, address=0x100000, length=8):
    return ["--offline", "!kmon", "dump-read", path, format(address, "x"), str(length)]


def invoke(exe, args, code, **streams):
    result = subprocess.run([exe, *args], **{"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, **streams}, timeout=30)
    assert result.returncode == code, (args[2:3], result.returncode, code, (result.stderr or b"")[:160])
    return result


def check_report(exe, path, address, code, decision):
    result = invoke(exe, [*arguments(path, address), "/init-receipts", "/json"], code)
    assert not result.stderr
    report = json.loads(result.stdout)
    assert report["schema"] == "kn.dump_read.v2" and report["initialization_reads_included"] is True
    assert report["collector_authenticated"] is False
    init = report["initialization"]
    assert init["schema"] == "kn.dump_initialization.v1" and init["decision"] == decision
    rows = init["reads"]
    assert init["max_reads"] == 45 and init["max_requested_bytes"] == 8544 and init["recording_complete"] is True
    assert init["attempts"] == len(rows) <= init["max_reads"]
    assert sum(r["requested_bytes"] for r in rows) == init["charged_requested_bytes"] <= init["max_requested_bytes"]
    assert init["clock_domain"] == "collector_GetTickCount64" and init["qualification_win32_error"] is None
    if init["source_id"] is None:
        assert not rows and not init["probe_reads"] and init["source_bytes"] is None and init["operation_id"] is None
    else:
        assert init["operation_id"] == init["source_id"] + ":initialization"
        assert int(init["source_bytes"]) == path.stat().st_size and init["open_win32_status"] == 0
        with path.open("rb") as source:
            previous = 0
            for sequence, row in enumerate(rows, 1):
                assert row["sequence"] == sequence and previous <= row["started_ms"] <= row["finished_ms"]
                previous = row["finished_ms"]
                assert row["identity_failure_win32_status"] is None
                if row["state"] == "complete":
                    size = row["requested_bytes"]
                    source.seek(int(row["file_offset"]))
                    original = source.read(size)
                    assert len(original) == size == row["hash_input_bytes"] == row["transferred_bytes"]
                    assert hashlib.sha256(original).hexdigest() == row["sha256"]
                    assert row["read_win32_status"] == row["seek_win32_status"] == 0
                else:
                    assert row["state"] == "not_captured" and row["hash_input_bytes"] == 0
                    assert row["sha256"] is row["transferred_bytes"] is row["read_win32_status"] is row["seek_win32_status"] is None
    claimed = []
    for probe in init["probe_reads"]:
        assert probe["source_id"] == init["source_id"] + ":probe" + str(probe["candidate_levels"])
        assert sum(s["requested_bytes"] for s in probe["spans"]) == probe["requested_bytes"]
        assert probe["parser_accepted"] == (probe["state"] == "complete")
        first, count = probe["first_file_sequence"], probe["file_read_count"]
        assert count > 0 and 2 <= first <= len(rows) - count + 1
        for row in rows[first-1:first-1+count]:
            assert (row["purpose"], row["candidate_levels"]) == (probe["purpose"], probe["candidate_levels"])
            claimed.append(row["sequence"])
    assert claimed == list(range(2, len(rows) + 1))
    nested = report["requested_range"]
    if init["selected_levels"]:
        assert nested["schema"] == "kn.dump_read.v1" and nested["initialization_reads_included"] is False
        assert nested["read"]["source_id"] == init["source_id"] and report["status"] == nested["read"]["status"]
        assert init["final_identity_matched"] is True and init["final_identity_win32_status"] == 0 and report["error"] is None
    else:
        assert nested is None and report["status"] == "unavailable" and report["error"]
        assert init["final_identity_matched"] is init["final_identity_win32_status"] is None
    return init


def address_for(levels):
    return 0xff01000000100000 if levels == 5 else 0xffff800000100000


def expected_fixture(levels, split=False, hole=False):
    # Fixture() writes the test tables at consecutive file pages, followed by
    # its data run. This layout is fixed by the fixture writer.
    base = address_for(levels)
    head = base + (4088 if split else 0)
    rows = [HEADER_READ]
    for purpose, start, remaining in (("list_head", head, 16), ("first_backlink", head + 8, 8),
                                      ("last_forward_link", head, 8)):
        while remaining:
            size = min(remaining, PAGE - start % PAGE)
            for page_number in range(levels):
                slot = (start >> (12 + 9 * (levels - 1 - page_number))) & 511
                offset = page_number * PAGE + 8 * slot
                rows.append((levels, purpose, PAGE + offset, HEADER + offset, 8))
            delta = start - base
            offset = None if hole and delta >= PAGE else HEADER + 5 * PAGE + delta
            rows.append((levels, purpose, 0x9000 + delta, offset, size))
            start += size
            remaining -= size
        if hole:
            break
    if levels == 4:
        # The sparse virtual reader examines each page portion even when its root entry is absent.
        for _ in range(2 if split else 1):
            rows.append((5, "list_head", PAGE + 511 * 8, HEADER + 511 * 8, 8))
    return rows


def location(row):
    physical, offset = row["physical_address"], row["file_offset"]
    return (row["candidate_levels"], row["purpose"], None if physical is None else int(physical),
            None if offset is None else int(offset), row["requested_bytes"])


def test_fixtures(exe, fixtures):
    for levels in (4, 5):
        for fixture, split, hole, decision, code in (
                ("probed", False, False, "unique_probe", 0),
                ("contradictory", False, False, "context_depth_conflict", 1),
                ("split-head", True, False, "unique_probe", 0),
                ("split-hole", True, True, "depth_unavailable", 1)):
            address = address_for(levels) + (4088 if split else 0)
            init = check_report(exe, fixtures / f"{fixture}-{levels}.dmp", address, code, decision)
            assert [location(row) for row in init["reads"]] == expected_fixture(levels, split, hole), (fixture, levels)
            own, alternate = ("four_level_probe", "five_level_probe") if levels == 4 else ("five_level_probe", "four_level_probe")
            assert init[own] == ("list_read_incomplete" if hole else "matched")
            assert init[alternate] == ("list_read_incomplete" if levels == 4 else "list_range_rejected")
            assert init["selected_levels"] == (None if code else levels)
            assert init["context_levels"] == (9 - levels if fixture == "contradictory" else None)
            checks = [r for r in init["probe_reads"] if r["candidate_levels"] == levels]
            assert [r["purpose"] for r in checks] == (["list_head"] if hole else ["list_head", "first_backlink", "last_forward_link"])
            assert checks[0]["state"] == ("partial" if hole else "complete")
            assert checks[0]["spans"] == ([dict(state="complete", requested_bytes=8),
                                          dict(state="not_captured" if hole else "complete", requested_bytes=8)]
                                         if split else [dict(state="complete", requested_bytes=16)])
            if levels == 4:
                assert init["probe_reads"][-1]["state"] == "not_present"
        path = fixtures / f"la{48 if levels == 4 else 57}-leaf1.dmp"
        for address, code in ((0x100000 if levels == 4 else 0x0010000000100000, 0), (0x800000000000, 1)):
            init = check_report(exe, path, address, code, "context_depth")
            assert init["selected_levels"] == init["context_levels"] == levels and not init["probe_reads"]
            assert list(map(location, init["reads"])) == [HEADER_READ]
    ambiguous = check_report(exe, fixtures / "ambiguous.dmp", 0x100000, 1, "depth_ambiguous")
    assert ambiguous["four_level_probe"] == ambiguous["five_level_probe"] == "matched"
    assert len(ambiguous["probe_reads"]) == 6 and len(ambiguous["reads"]) == 34
    maximum = check_report(exe, fixtures / "split-ambiguous.dmp", 0x100000, 1, "depth_ambiguous")
    assert len(maximum["reads"]) == maximum["max_reads"] and maximum["charged_requested_bytes"] == maximum["max_requested_bytes"]
    decisions = ("unsupported_header", "unsupported_header", "overlapping_runs", "run_page_count_mismatch",
                 "invalid_or_truncated_run", "depth_unavailable", "unsupported_header", "invalid_or_truncated_run",
                 "invalid_or_truncated_run", "unsupported_header", "unsupported_header", "context_root_conflict", "unsupported_header")
    for n, decision in enumerate(decisions):
        init = check_report(exe, fixtures / f"invalid-{n}.dmp", 0x100000, 1, decision)
        assert list(map(location, init["reads"])) == [HEADER_READ]
    return ambiguous


def test_link_decisions(exe, fixtures, folder):
    data_offset = HEADER + 5 * PAGE
    head = address_for(4)
    original = (fixtures / "probed-4.dmp").read_bytes()
    path = folder / "list-neighbors.dmp"
    purposes = ["list_head", "first_backlink", "last_forward_link"]
    for reason, first, back, forward, count in (
            ("link_range_rejected", 0, head, head, 1),
            ("first_backlink_mismatch", head + 32, head + 8, head, 2),
            ("last_forward_link_mismatch", head + 32, head, head + 8, 3),
            ("matched", head + 32, head, head, 3)):
        data = bytearray(original)
        struct.pack_into("<QQ", data, data_offset, first, head + 64)
        struct.pack_into("<Q", data, data_offset + 40, back)
        struct.pack_into("<Q", data, data_offset + 64, forward)
        path.write_bytes(data)
        matched = reason == "matched"
        init = check_report(exe, path, head, 0 if matched else 1, "unique_probe" if matched else "depth_unavailable")
        assert init["four_level_probe"] == reason
        checks = [row for row in init["probe_reads"] if row["candidate_levels"] == 4]
        assert [row["purpose"] for row in checks] == purposes[:count]
        assert all(row["parser_accepted"] for row in checks)
        assert [int(row["virtual_address"]) for row in checks] == [head, head + 40, head + 64][:count]


def test_outputs(exe, fixtures, folder):
    path = folder / "owned input.dmp"
    path.write_bytes(b"short header")
    short = check_report(exe, path, 0x100000, 1, "header_read_incomplete")
    assert list(map(location, short["reads"])) == [HEADER_READ]
    missing = check_report(exe, folder / "missing.dmp", 0x100000, 1, "file_open_failed")
    assert missing["open_win32_status"] == 2 and missing["source_id"] is None
    policy = check_report(exe, Path(r"\\.\NUL"), 0x100000, 1, "path_rejected")
    assert policy["open_win32_status"] is None
    device = check_report(exe, Path("NUL"), 0x100000, 1, "not_disk_file")
    assert device["open_win32_status"] == 0
    shutil.copyfile(fixtures / "la48-leaf1.dmp", path)
    original = path.read_bytes()
    alias = folder / "alias.dat"
    os.link(path, alias)
    args = arguments(path)
    with path.open("ab", buffering=0):
        denied = check_report(exe, path, 0x100000, 1, "file_open_failed")
        assert denied["open_win32_status"] == 32 and denied["source_id"] is None
    for flags in (["/receipts", "/init-receipts"], ["/init-receipts", "/init-receipts"], ["/init-receipts", "/bad"]):
        assert b"usage" in invoke(exe, [*args, *flags], 2).stderr
    for restricted, code in ((["--mode", "offline", *args, "/init-receipts"], 5),
                             ([*args, "/init-receipts", "--mode", "offline"], 2)):
        decision = json.loads(invoke(exe, restricted, code).stdout)
        assert decision["schema"] == "kn.launch_authority.v1"
        assert decision["status"] == ("blocked_by_policy" if code == 5 else "invalid_request")
    for command, stream, code in (([*args, "/init-receipts"], "stdout", 2), ([*args, "/init-receipts", "/bad"], "stderr", 2),
                                  (["--mode", "offline", *args, "/init-receipts"], "stdout", 5),
                                  ([*args, "/init-receipts", "--mode", "offline"], "stdout", 2)):
        with alias.open("ab", buffering=0) as output:
            invoke(exe, command, code, **{stream: output})
        assert path.read_bytes() == original
    # Windows permits the second read handle to open. Only the locked file
    # bytes fail, so the reported error must originate from ReadFile.
    with path.open("rb", buffering=0) as locked:
        msvcrt.locking(locked.fileno(), msvcrt.LK_NBLCK, HEADER)
        try:
            raw = json.loads(invoke(exe, [*args, "/init-receipts"], 1).stdout)["initialization"]
        finally:
            locked.seek(0)
            msvcrt.locking(locked.fileno(), msvcrt.LK_UNLCK, HEADER)
    assert raw["open_win32_status"] == 0 and raw["decision"] == "header_read_incomplete"
    only, = raw["reads"]
    assert only["state"] == "read_failed" and only["seek_win32_status"] == 0 and only["read_win32_status"] == 33
    assert only["transferred_bytes"] == only["hash_input_bytes"] == 0 and only["sha256"] is None

    probe_path = folder / "locked list data.dmp"
    shutil.copyfile(fixtures / "probed-4.dmp", probe_path)
    with probe_path.open("rb", buffering=0) as locked:
        locked.seek(HEADER + 5 * PAGE)
        msvcrt.locking(locked.fileno(), msvcrt.LK_NBLCK, 16)
        try:
            raw = json.loads(invoke(exe, [*arguments(probe_path, address_for(4)), "/init-receipts"], 1).stdout)["initialization"]
        finally:
            locked.seek(HEADER + 5 * PAGE)
            msvcrt.locking(locked.fileno(), msvcrt.LK_UNLCK, 16)
    head, alternate = raw["probe_reads"]
    assert raw["decision"] == "depth_unavailable" and (head["state"], alternate["state"]) == ("read_failed", "not_present")
    failed = raw["reads"][head["first_file_sequence"] + head["file_read_count"] - 2]
    assert failed["state"] == "read_failed" and failed["read_win32_status"] == 33 and failed["sha256"] is None

    sink = folder / "report.json"
    with sink.open("wb") as output:
        invoke(exe, [*args, "/json", "/init-receipts"], 0, stdout=output)
    assert json.loads(sink.read_bytes())["schema"] == "kn.dump_read.v2"
    before = sink.read_bytes()
    with sink.open("rb") as readonly:
        invoke(exe, [*args, "/init-receipts"], 3, stdout=readonly)
    assert sink.read_bytes() == before and path.read_bytes() == original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    exe, fixtures = args.executable.resolve(strict=True), args.fixtures.resolve(strict=True)
    ambiguous = test_fixtures(exe, fixtures)
    scan = run_path(str(Path(__file__).with_name("validate-public-content.py")))["inspect"]
    for obj in (ambiguous, *ambiguous["reads"], *ambiguous["probe_reads"]):
        assert scan("private-export.log", ("report\n" + json.dumps(obj)).encode("utf-8"))
    with tempfile.TemporaryDirectory(prefix="kn-dump-init-") as temp:
        test_link_decisions(exe, fixtures, Path(temp))
        test_outputs(exe, fixtures, Path(temp))
    print("Dump initialization passed: source ranges, original payload digests, sparse probes, rejection decisions, output and privacy")


if __name__ == "__main__":
    main()
