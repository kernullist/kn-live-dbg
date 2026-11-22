"""Verify the standalone saved-dump capability report on owned synthetic full dumps."""
import argparse
from contextlib import contextmanager
import ctypes
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
ZERO = "0" * 64


def sha(data):
    return hashlib.sha256(data).hexdigest()


def header_pin(path):
    with path.open("rb") as stream:
        return sha(stream.read(HEADER))


def arguments(path, pin):
    return ["--capabilities", "--probe-dump", str(path), "--header-sha256", pin]


@contextmanager
def locked(path, offset, length):
    with path.open("rb", buffering=0) as stream:
        stream.seek(offset)
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, length)
        try:
            yield
        finally:
            stream.seek(offset)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, length)


class Harness:
    def __init__(self, exe):
        self.exe = exe
        self.calls = 0
        self.compiled = json.loads(self.run(["--capabilities"]).stdout)
        self.private = run_path(str(Path(__file__).with_name("validate-public-content.py")))["inspect"]

    def run(self, args, code=0, **streams):
        result = subprocess.run([self.exe, *args], timeout=30, **{"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, **streams})
        assert result.returncode == code, (args[1:3], result.returncode, code, (result.stderr or b"")[:300])
        self.calls += 1
        return result

    def report(self, path, status, *flags, pin=None):
        pin = header_pin(path) if pin is None else pin
        result = self.run([*arguments(path, pin), *flags], int(status != "read"))
        assert not result.stderr and b"bytes_hex" not in result.stdout
        report = json.loads(result.stdout)
        assert report["schema"] == self.compiled["schema"] and report["scope"] == "saved_dump_probe"
        assert report["target_probed"] is False and report["inventory_complete"] is False
        assert report["target"] == self.compiled["target"] and report["commands"] == self.compiled["commands"]
        sample = None
        for row, static in zip(report["capabilities"], self.compiled["capabilities"], strict=True):
            for field in ("domain", "operation", "backend", "implementation", "address_contract", "requirements", "limits", "validation"):
                assert row[field] == static[field], field
            assert row["validation"] == "not_performed_for_target_environment" and row["probe_stages"]["environment_regression"] == "not_performed"
            if (row["domain"], row["operation"], row["backend"]) == ("memory", "read_virtual", "dump"):
                assert sample is None and row["availability_scope"] == "supplied_dump_virtual_range"
                sample = row
            else:
                assert row["availability"] == row["availability_scope"] == "not_probed"
                assert row["probe_stages"] == static["probe_stages"] and "range_evidence" not in row
        probe = report["probe"]
        assert sample is not None and probe["status"] == status, (probe["status"], status)
        assert probe["schema"] == "kn.dump_capability_probe.v1" and probe["expected_header_sha256"] == pin.lower()
        assert probe["digest_scope"] == "first_8192_bytes" and probe["producer_authenticity"] == "unverified"
        init = probe["initialization"]
        assert sample["availability"] == ("available" if status == "read" else "partial" if init["selected_levels"] else "unavailable")
        assert init["attempts"] <= init["max_reads"] and init["charged_requested_bytes"] <= init["max_requested_bytes"]
        return probe, sample


def check_ranges(h, fixtures):
    for levels, bits, base, head in ((4, 48, 0x100000, 0xffff800000100000), (5, 57, 0x0010000000100000, 0xff01000000100000)):
        for leaf in (1, 2, 3):
            file = fixtures / f"la{bits}-leaf{leaf}.dmp"
            length = PAGE if leaf == 1 else 8
            expected = sha(b"B" * length)
            p, row = h.report(file, "read", "--range", hex(base), str(length), "--expect-sha256", expected.upper(), pin=header_pin(file).upper())
            r = row["range_evidence"]
            assert p["sample_digest_comparison"] == "matched" and p["sample_identity_revalidated"] is True and p["sample_identity_win32_status"] == 0
            assert (p["requested_virtual_address"], p["requested_bytes"]) == (str(base), length)
            assert row["probe_stages"]["layout_qualified"] == row["probe_stages"]["sample_read"] == "passed"
            assert row["probe_stages"]["semantic_validation"] == "not_probed" and p["initialization"]["selected_levels"] == levels
            assert r["range_state"] == "complete" and r["sample_sha256"] == expected and r["virtual_address_bits"] == bits
            assert r["spans"] == [dict(range_offset=0, requested_bytes=length, captured_bytes=length, state="complete", span_sha256=expected)]
            assert r["translations"] == [dict(range_offset=0, requested_bytes=length, translation_state="complete",
                                              translation_reason="architecture_context_incomplete", entries_revalidated=True)]
            assert r["translation_count"] == 1 and r["charged_physical_reads"] == 2 * (levels - leaf + 1) + 1
            assert r["charged_physical_bytes"] == 16 * (levels - leaf + 1) + length and not r["incomplete_physical_reads"]
            assert r["physical_recording_complete"] and r["unrecorded_attempts"] == 0
            p, row = h.report(file, "partial", "--range", f"{base + PAGE - 8:x}", "16", "--expect-sha256", ZERO)
            r = row["range_evidence"]
            assert r["translation_count"] == 2 and r["captured_bytes"] == r["unobserved_bytes"] == 8
            assert [s["range_offset"] for s in r["spans"]] == [0, 8]
            assert [s["state"] for s in r["spans"]] == ["complete", "not_captured"]
            assert [s["span_sha256"] for s in r["spans"]] == [sha(b"B" * 8), None] and r["sample_sha256"] is None
            assert p["sample_digest_comparison"] == "not_compared" and row["probe_stages"]["sample_read"] == "partial"
            assert r["incomplete_physical_reads"][-1]["win32_status"] is None
        for prefix, offset, pages in (("probed", 0, 1), ("split-head", PAGE - 8, 2)):
            file = fixtures / f"{prefix}-{levels}.dmp"
            expected = sha(struct.pack("<QQ", head + offset, head + offset))
            p, row = h.report(file, "read", "--expect-sha256", expected)
            r = row["range_evidence"]
            assert p["range_selection"] == "header_module_list_head" and p["requested_virtual_address"] is None
            assert r["virtual_address"] == str(head + offset) and r["translation_count"] == pages and r["sample_sha256"] == expected
            assert p["sample_digest_comparison"] == "matched" and row["probe_stages"]["semantic_validation"] == "passed"
            assert p["initialization"]["decision"] == "unique_probe"
            for export in (p, row, r, *r["spans"], *r["translations"]):
                assert h.private("detached.log", ("log\n" + json.dumps([export])[:-1]).encode())
            p, row = h.report(file, "read", "--range", hex(head + offset), "16")
            assert row["range_evidence"]["sample_sha256"] == expected and row["probe_stages"]["semantic_validation"] == "not_probed"
            assert p["sample_digest_comparison"] == "not_requested"
    file = fixtures / "la48-leaf1.dmp"
    p, row = h.report(file, "default_range_unavailable")
    assert row["range_evidence"] is None and p["sample_identity_revalidated"] is None
    p, row = h.report(file, "unsupported", "--range", "0x800000000000", "1")
    assert row["range_evidence"]["charged_physical_reads"] == 0 and row["probe_stages"]["sample_read"] == "not_probed"
    assert row["range_evidence"]["spans"] == [] and row["range_evidence"]["unobserved_bytes"] == 1
    p, row = h.report(fixtures / "not-present.dmp", "not_present", "--range", "101000", "8")
    assert row["range_evidence"]["translations"][0]["translation_reason"] == "page_table_entry_not_present"
    assert row["range_evidence"]["spans"][0]["state"] == "not_present" and row["probe_stages"]["sample_read"] == "failed"


def check_source_and_control(h, fixtures, folder):
    file = folder / "owned dump with spaces.dmp"
    shutil.copyfile(fixtures / "probed-4.dmp", file)
    pin = header_pin(file)
    p, row = h.report(file, "header_digest_mismatch", pin=ZERO)
    assert p["header_sha256"] == pin and len(p["initialization"]["reads"]) == 1 and not p["initialization"]["probe_reads"]
    assert row["range_evidence"] is None and row["probe_stages"]["layout_qualified"] == "not_probed"
    for name, decision in (("ambiguous", "depth_ambiguous"), ("contradictory-4", "context_depth_conflict"),
                           ("invalid-0", "unsupported_header"), ("invalid-4", "invalid_or_truncated_run"),
                           ("split-hole-5", "depth_unavailable")):
        p, row = h.report(fixtures / f"{name}.dmp", decision)
        assert row["range_evidence"] is None and row["probe_stages"]["layout_qualified"] == "failed"
    p, row = h.report(folder / "missing.dmp", "file_open_failed", pin=ZERO)
    assert p["initialization"]["open_win32_status"] == 2 and not p["initialization"]["reads"]
    assert row["probe_stages"]["source_opened"] == "failed" and p["header_sha256"] is None
    p, row = h.report(r"\\.\NUL", "path_rejected", pin=ZERO)
    assert p["initialization"]["open_win32_status"] is None and row["probe_stages"]["source_opened"] == "not_probed"

    # Supply independent context and an invalid link in the saved list. The
    # same 16 bytes can still be read and compared by an explicit range.
    original = file.read_bytes()
    head = 0xffff800000100000
    pos = original[:HEADER].index(struct.pack("<Q", head))
    data = bytearray(original)
    data[:HEADER] = (fixtures / "la48-leaf1.dmp").read_bytes()[:HEADER]
    struct.pack_into("<Q", data, pos, head)
    data[HEADER + 5 * PAGE:HEADER + 5 * PAGE + 16] = bytes(16)
    file.write_bytes(data)
    p, row = h.report(file, "list_control_unqualified", "--expect-sha256", sha(bytes(16)))
    assert p["initialization"]["four_level_probe"] == "link_range_rejected" and p["sample_digest_comparison"] == "matched"
    assert row["probe_stages"]["sample_read"] == "passed" and row["probe_stages"]["semantic_validation"] == "failed"
    p, row = h.report(file, "read", "--range", hex(head), "16", "--expect-sha256", sha(bytes(16)))
    assert row["probe_stages"]["semantic_validation"] == "not_probed"
    current_pin = header_pin(file)
    data[-PAGE + 1] = 7
    file.write_bytes(data)
    p, row = h.report(file, "sample_digest_mismatch", "--range", hex(head), "16", "--expect-sha256", sha(bytes(16)), pin=current_pin)
    assert p["header_sha256"] == current_pin and p["sample_digest_comparison"] == "mismatched"
    assert row["probe_stages"]["sample_read"] == "passed" and row["range_evidence"]["sample_sha256"] == sha(data[-PAGE:-PAGE + 16])
    struct.pack_into("<QQ", data, HEADER + 5 * PAGE, head + PAGE, head)
    file.write_bytes(data)
    p, row = h.report(file, "list_control_unqualified", pin=current_pin)
    assert p["initialization"]["four_level_probe"] == "first_backlink_incomplete"
    assert row["probe_stages"]["sample_read"] == "passed" and row["probe_stages"]["semantic_validation"] == "inconclusive"
    file.write_bytes(b"short")
    p, row = h.report(file, "header_read_incomplete", pin=pin)
    assert p["header_sha256"] is None and not p["initialization"]["probe_reads"] and row["range_evidence"] is None

    shutil.copyfile(fixtures / "la48-leaf1.dmp", file)
    pin = header_pin(file)
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    attrs = api.GetFileAttributesW(str(file))
    assert attrs != -1 and api.SetFileAttributesW(str(file), attrs | 0x1000)  # FILE_ATTRIBUTE_OFFLINE
    try:
        p, row = h.report(file, "data_recall_required", pin=pin)
        assert p["initialization"]["open_win32_status"] == 0 and not p["initialization"]["reads"]
        assert row["probe_stages"]["layout_qualified"] == "not_probed"
    finally:
        assert api.SetFileAttributesW(str(file), attrs)
    with file.open("ab", buffering=0):
        p, _ = h.report(file, "file_open_failed", pin=pin)
        assert p["initialization"]["open_win32_status"] == 32
    with locked(file, 0, HEADER):
        p, _ = h.report(file, "header_read_incomplete", pin=pin)
        assert p["initialization"]["reads"][0]["read_win32_status"] == 33 and p["header_sha256"] is None
    with locked(file, HEADER + 5 * PAGE, 8):
        p, row = h.report(file, "read_failed", "--range", "100000", "8", "--expect-sha256", ZERO, pin=pin)
        r = row["range_evidence"]
        assert r["spans"][0]["state"] == "read_failed" and r["sample_sha256"] is None and p["sample_digest_comparison"] == "not_compared"
        assert r["incomplete_physical_reads"] == [dict(physical_read_sequence=9, state="read_failed", native_status_domain="win32",
                                                       win32_status=33, transferred_bytes=0)]
    return file


def check_outputs(h, file, folder):
    original = file.read_bytes()
    args = arguments(file, header_pin(file))
    for rest in (["--range", "0x", "8"], ["--range", "-1", "8"], ["--range", "0x10000000000000000", "8"],
                 ["--range", "1", "0"], ["--range", "1", "4097"], ["--range", "1", "+8"], ["--range", "1", "08"],
                 ["--range", "1", "8", "--range", "2", "8"], ["--expect-sha256", "g" * 64], ["--probe"],
                 ["--probe-etl", str(file)], ["--probe-dump", str(file)]):
        result = h.run([*args, *rest], 2)
        assert not result.stdout and b"usage" in result.stderr
    for bad in (args[:3], [*args[:-1], ZERO[1:]], ["--capabilities", "--probe-dump", "--probe-etl", "--header-sha256", ZERO]):
        assert b"usage" in h.run(bad, 2).stderr
    # A directory junction is available without symbolic-link privileges.
    real = folder / "real directory"
    real.mkdir()
    child = real / "input.dmp"
    child.write_bytes(original)
    junction = folder / "junction"
    subprocess.run(["cmd", "/d", "/c", "mklink", "/j", str(junction), str(real)], check=True, capture_output=True, timeout=30)
    try:
        p, r = h.report(junction / child.name, "path_rejected", pin=header_pin(file))
        assert not p["initialization"]["reads"] and r["range_evidence"] is None
    finally:
        junction.rmdir()
    alias = folder / "alias.log"
    os.link(file, alias)
    ok = [*args, "--range", "100000", "8"]
    other = folder / "other.dmp"
    other.write_bytes(b"other")
    for command, stream, code in ((ok, "stdout", 2), ([*ok, "--invalid"], "stderr", 2),
                                  ([*arguments(other, ZERO), "--probe-etl", str(file)], "stderr", 2),
                                  (["--capabilities", "--probe-etl", str(other), "--probe-dump", str(file)], "stderr", 2),
                                  (["--mode", "offline", *ok], "stdout", 5), ([*ok, "--mode", "observe"], "stdout", 2)):
        with alias.open("ab", buffering=0) as sink:
            h.run(command, code, **{stream: sink})
        assert file.read_bytes() == original
    result = h.run(["--mode", "observe", *ok], 5)
    assert json.loads(result.stdout)["status"] == "blocked_by_policy"
    sink = folder / "ordinary report.json"
    with sink.open("wb") as output:
        h.run(ok, stdout=output)
    exported = sink.read_bytes()
    assert h.private("renamed.data", exported)
    matrix = run_path(str(Path(__file__).with_name("generate-support-matrix.py")))
    try:
        matrix["render"](json.loads(exported))
    except ValueError:
        pass
    else:
        raise AssertionError("range-specific capability entered the compiled matrix")
    with sink.open("rb") as readonly:
        h.run(ok, 2, stdout=readonly)
    assert sink.read_bytes() == exported and file.read_bytes() == original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    args = parser.parse_args()
    h = Harness(args.exe.resolve(strict=True))
    fixtures = args.fixtures.resolve(strict=True)
    check_ranges(h, fixtures)
    with tempfile.TemporaryDirectory(prefix="kn-saved-dump-cap-") as tmp:
        folder = Path(tmp)
        file = check_source_and_control(h, fixtures, folder)
        check_outputs(h, file, folder)
    print(f"Saved dump capability checks passed across {h.calls} CLI launches on synthetic full dumps")


if __name__ == "__main__":
    main()
