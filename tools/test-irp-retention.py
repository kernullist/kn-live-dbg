"""Independent bounded IRP priority accounting and concurrent admission oracle."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    process = subprocess.run([str(args.exe.resolve())], capture_output=True, text=True, encoding="utf-8", timeout=60)
    print(process.stderr.strip())
    assert process.returncode == 0, "compiled resource controls"
    rows = [json.loads(line) for line in process.stdout.splitlines() if line.startswith("{")]
    assert len(rows) == 2
    concurrent, accounting = rows[0]["concurrent"], rows[1]["accounting"]
    checks = 0

    def check(ok):
        nonlocal checks
        checks += 1
        assert ok, f"independent IRP retention invariant {checks}"

    for report in (concurrent, accounting):
        check(report["schema"] == "kn.irp_retention.v1" and report["policy"] == "kn.irp_retention_partition.v1")
        check(report["scope"] == "recording_session" and report["first_retained_requires_reference_and_journal"] is True)
        for flag in ("disk_space_reserved", "cross_session_dedup_established", "maliciousness_established", "referenced_lifetime"):
            check(report[flag] is False)
        check(int(report["tracked_keys"]) <= int(report["key_limit"]) == 8192)
        for i, lane in enumerate(report["classes"]):
            number = lambda key: int(lane[key])
            check(lane["class"] == ("first_observed_state", "observation_gap", "repeat_or_empty")[i])
            check(number("slot_limit") == (2, 1, 1)[i] and number("memory_limit") == 80 * 1024 * 1024)
            check(number("capture_bytes_limit") == (64, 32, 32)[i] * 1024 * 1024 and number("reference_bytes_limit") == 64 * 1024 * 1024)
            check(number("attempted") == sum(number(k) for k in ("admitted", "slot_denied", "memory_denied", "key_denied", "preparation_denied", "unavailable", "invalid")))
            check(number("admitted") == number("finished") + number("abandoned") + number("in_flight"))
            check(number("complete") <= number("finished") and number("peak") <= number("slot_limit"))
            check(number("in_flight") == number("held_bytes") == 0)
            for stream in ("capture", "reference"):
                check(number(stream + "_bytes") <= number(stream + "_bytes_limit"))
    for lane in concurrent["classes"]:
        check(int(lane["attempted"]) == 3000)
        check(all(lane[key] == "0" for key in ("abandoned", "memory_denied", "key_denied", "unavailable", "invalid")))
    expected = [dict(attempted=3, admitted=2, memory_denied=1, finished=1, complete=1, abandoned=1, capture_bytes=17, reference_bytes=64*1024*1024),
                dict(attempted=4, admitted=1, slot_denied=1, unavailable=1, invalid=1, finished=1, complete=1, abandoned=0, capture_bytes=0, reference_bytes=0),
                dict(attempted=3, admitted=2, slot_denied=1, finished=2, complete=1, abandoned=0, capture_bytes=32*1024*1024, reference_bytes=0)]
    for lane, truth in zip(accounting["classes"], expected):
        for key, value in truth.items():
            check(int(lane[key]) == value)
    check(accounting["tracked_keys"] == "1" and concurrent["tracked_keys"] == "0")
    print(f"[irp.retention.oracle] checks={checks} concurrent_attempts=9000 children_remaining=0")


if __name__ == "__main__":
    main()
