"""Exercise only owned synthetic dumps through the public offline entry point."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    checks = 0
    skipped = 0

    def read(path, address, length, expected, receipts=False):
        nonlocal checks
        result = subprocess.run([str(args.executable.resolve()), "--offline", "!kmon", "dump-read",
                                 str(path), format(address, "x"), str(length), "/json"] + (["/receipts"] if receipts else []),
                                capture_output=True, timeout=30,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == expected and not result.stderr
        assert b"preflight checks" not in result.stdout
        data = json.loads(result.stdout.decode("utf-8-sig"))
        assert data["schema"] == ("kn.dump_read.v1" if receipts else "kn.observation_read.v1") and not data["collector_authenticated"]
        checks += 3
        return data

    for bits in (48, 57):
        base = 0x0010000000100000 if bits == 57 else 0x100000
        for leaf in (1, 2, 3):
            path = args.fixtures / f"la{bits}-leaf{leaf}.dmp"
            complete = read(path, base + 0x234, 8, 0)
            assert complete["status"] == "complete" and complete["virtual_address_bits"] == bits
            assert not complete["side_effects_possible"] and complete["consistency"] == "offline_dump"
            assert complete["spans"] == [{"address": str(base + 0x234), "requested_bytes": 8,
                                          "state": "complete", "bytes_hex": "42" * 8}]
            partial = read(path, base + 0xff8, 16, 1)
            assert partial["status"] == "partial" and len(partial["spans"]) == 2
            assert partial["spans"][0]["bytes_hex"] == "42" * 8
            assert partial["spans"][1]["state"] == "not_captured" and partial["spans"][1]["bytes_hex"] == ""
            checks += 6
            receipt = read(path, base + 0x234, 8, 0, receipts=True)
            assert receipt["read"]["spans"] == complete["spans"]
            assert not receipt["initialization_reads_included"]
            translation = receipt["translations"][0]
            walk_levels = (5 if bits == 57 else 4) - leaf + 1
            assert translation["status"] == "complete" and len(translation["entries"]) == 2 * walk_levels
            assert translation["paging_execute_allowed"] is None and translation["root"]["physical_address_bits"] is None
            assert translation["root"]["nx_enabled"] is None and not translation["cpu_access_verified"]
            physical = receipt["physical_read_set"]
            assert receipt["read"]["operation_id"] == physical["operation_id"]
            assert physical["recording_complete"] and int(physical["charged_requested_bytes"]) == 16 * walk_levels + 8
            assert int(physical["charged_source_calls"]) == 2 * walk_levels + 1
            assert all(r["read"]["native_status_domain"] == "win32" and r["read"]["native_status"] == 0
                       and r["read"]["address_domain"] == "physical" and r["read"]["backend_copy_attempted"]
                       for r in physical["reads"])
            for entry, saved in zip(translation["entries"], physical["reads"]):
                assert entry["read"] == saved["read"]
            partial_receipt = read(path, base + 0xff8, 16, 1, receipts=True)
            assert partial_receipt["read"]["spans"] == partial["spans"]
            assert len(partial_receipt["translations"]) == 2
            assert partial_receipt["physical_read_set"]["reads"][-1]["read"]["status"] == "not_captured"
            checks += 12
    nonpresent = read(args.fixtures / "not-present.dmp", 0x101000, 8, 1)
    assert nonpresent["status"] == "not_present" and nonpresent["spans"][0]["bytes_hex"] == ""
    hole = read(args.fixtures / "la48-leaf1.dmp", 0x800000000000, 8, 1)
    assert hole["status"] == "unsupported" and hole["spans"] == []
    checks += 2
    receipt = read(args.fixtures / "not-present.dmp", 0x101000, 8, 1, receipts=True)
    assert receipt["read"]["status"] == receipt["translations"][0]["status"] == "not_present"
    receipt = read(args.fixtures / "la48-leaf1.dmp", 0x800000000000, 8, 1, receipts=True)
    assert receipt["read"]["status"] == "unsupported" and receipt["translations"] == []
    assert receipt["physical_read_set"]["attempts"] == "0"
    checks += 3
    for name in ("invalid-0.dmp", "invalid-4.dmp", "ambiguous.dmp", "contradictory-4.dmp", "missing.dmp"):
        unavailable = read(args.fixtures / name, 0x100000, 8, 1)
        assert unavailable["status"] == "unavailable" and unavailable["spans"] == []
        checks += 1
        if name == "missing.dmp":
            unavailable_receipt = read(args.fixtures / name, 0x100000, 8, 1, receipts=True)
            assert unavailable_receipt["status"] == "unavailable" and "physical_read_set" not in unavailable_receipt
            checks += 1
    for length in (0, 4097):
        result = subprocess.run([str(args.executable.resolve()), "--offline", "!kmon", "dump-read",
                                 str(args.fixtures / "missing.dmp"), "100000", str(length), "/json"],
                                capture_output=True, timeout=30)
        assert result.returncode == 2 and b"usage" in result.stderr and not result.stdout
        checks += 1
    for flags in (("/receipts", "/receipts"), ("/json", "/json"), ("/receipts", "/unknown")):
        result = subprocess.run([str(args.executable.resolve()), "--offline", "!kmon", "dump-read",
                                 str(args.fixtures / "missing.dmp"), "100000", "8", *flags],
                                capture_output=True, timeout=30)
        assert result.returncode == 2 and b"usage" in result.stderr and not result.stdout
        checks += 1
    with tempfile.TemporaryDirectory(prefix="kmon-dump-link-") as folder:
        sink = Path(folder) / "readonly-output.txt"
        sink.write_text("unchanged", encoding="utf-8")
        with sink.open("rb") as stdout:
            failed_output = subprocess.run([str(args.executable.resolve()), "--offline", "!kmon", "dump-read",
                                            str(args.fixtures / "la48-leaf1.dmp"), "100000", "8", "/receipts"],
                                           stdout=stdout, stderr=subprocess.PIPE, timeout=30)
        assert failed_output.returncode != 0 and sink.read_text(encoding="utf-8") == "unchanged"
        checks += 1
        link = Path(folder) / "alias.dmp"
        try:
            os.symlink((args.fixtures / "la48-leaf1.dmp").resolve(), link)
        except OSError as error:
            if getattr(error, "winerror", None) != 1314:
                raise
            skipped += 1
        else:
            linked = read(link, 0x100000, 8, 1)
            assert linked["status"] == "unavailable", "final reparse point must not be followed"
            checks += 1
    print(json.dumps({"checks_passed": checks, "symlink_checks_skipped": skipped,
                      "corpus": "synthetic", "driver_loaded": False}))


if __name__ == "__main__":
    main()
