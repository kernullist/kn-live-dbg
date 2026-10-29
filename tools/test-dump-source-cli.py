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

    def read(path, address, length, expected):
        nonlocal checks
        result = subprocess.run([str(args.executable.resolve()), "--offline", "!kmon", "dump-read",
                                 str(path), format(address, "x"), str(length), "/json"],
                                capture_output=True, timeout=30,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == expected and not result.stderr
        assert b"preflight checks" not in result.stdout
        data = json.loads(result.stdout.decode("utf-8-sig"))
        assert data["schema"] == "kn.observation_read.v1" and not data["collector_authenticated"]
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
    nonpresent = read(args.fixtures / "not-present.dmp", 0x101000, 8, 1)
    assert nonpresent["status"] == "not_present" and nonpresent["spans"][0]["bytes_hex"] == ""
    hole = read(args.fixtures / "la48-leaf1.dmp", 0x800000000000, 8, 1)
    assert hole["status"] == "unsupported" and hole["spans"] == []
    checks += 2
    for name in ("invalid-0.dmp", "invalid-4.dmp", "ambiguous.dmp", "contradictory-4.dmp", "missing.dmp"):
        unavailable = read(args.fixtures / name, 0x100000, 8, 1)
        assert unavailable["status"] == "unavailable" and unavailable["spans"] == []
        checks += 1
    for length in (0, 4097):
        result = subprocess.run([str(args.executable.resolve()), "--offline", "!kmon", "dump-read",
                                 str(args.fixtures / "missing.dmp"), "100000", str(length), "/json"],
                                capture_output=True, timeout=30)
        assert result.returncode == 2 and b"usage" in result.stderr and not result.stdout
        checks += 1
    with tempfile.TemporaryDirectory(prefix="kmon-dump-link-") as folder:
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
