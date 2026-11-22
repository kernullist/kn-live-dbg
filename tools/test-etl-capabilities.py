"""Compare saved ETL capability rows against Windows tracerpt and the native readers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from runpy import run_path
import shutil
import struct
import subprocess
import tempfile


FAMILIES = (
    ("hard_fault", "--etl-hard-faults", "hard_faults", "decoded_hard_faults", "unsupported_hard_fault_records",
     "3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c", r"(?:HardFault|32)", "2"),
    ("disk_io", "--etl-disk-io", "disk_events", "decoded_disk_records", "unsupported_disk_records",
     "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c", r"(?:Read|Write|ReadInit|WriteInit|FlushBuffers|FlushInit|1[0-5])", "[23]"),
    ("cpu_profile", "--etl-profile", "samples", "decoded_samples", "unsupported_profile_records",
     "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc", r"(?:SampleProf|46)", "2"),
    ("context_switch", "--etl-switches", "switches", "decoded_switches", "unsupported_switch_records",
     "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c", r"(?:CSwitch|36)", "[234]"),
)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def invoke(exe, args, code=0, **streams):
    result = subprocess.run([exe, *args], **{"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, **streams}, timeout=90)
    assert result.returncode == code, (args[:2], result.returncode, code, (result.stderr or b"")[:300])
    return result.stdout


def probe_args(path, pin):
    return ["--capabilities", "--probe-etl", path, "--sha256", pin]


def report(exe, path, pin, code):
    data = json.loads(invoke(exe, probe_args(path, pin), code))
    assert data["schema"] == "kn.capabilities.v1" and data["scope"] == "saved_etl_probe"
    assert data["target_probed"] is False and data["target"]["validation"] == "not_performed"
    assert data["inventory_complete"] is False
    rows = {}
    for row in data["capabilities"]:
        assert row["validation"] == "not_performed_for_target_environment"
        stages = row["probe_stages"]
        assert stages["environment_regression"] == "not_performed" and stages["semantic_validation"] == "not_probed"
        expected_domain = {"disk_io": "io", "hard_fault": "memory"}.get(row["operation"], "execution")
        if (row["domain"], row["backend"]) == (expected_domain, "etl") and row["operation"] in {f[0] for f in FAMILIES}:
            assert row["availability_scope"] == "supplied_etl_record_family" and row["operation"] not in rows
            rows[row["operation"]] = row
        else:
            assert row["availability"] == row["availability_scope"] == "not_probed" and "record_evidence" not in row
            assert stages["source_opened"] == stages["layout_qualified"] == stages["sample_read"] == "not_probed"
    assert len(rows) == len(FAMILIES)
    probe = data["probe"]
    assert probe["expected_sha256"] == pin.lower() and probe["schema"] == "kn.etl_capability_probe.v1"
    assert probe["producer_authenticity"] == "unverified" and "process_id" not in probe
    return data, probe, rows


def windows_counts(path, folder):
    summary = folder / "summary.txt"
    tracerpt = Path(os.environ["SystemRoot"]) / "System32" / "tracerpt.exe"
    subprocess.run([tracerpt, path, "-of", "CSV", "-o", "NUL", "-summary", summary, "-y"],
                   cwd=folder, check=True, capture_output=True, timeout=240)
    # Only ASCII descriptor names, GUIDs and integer totals enter the comparison.
    text = summary.read_bytes().decode("latin1")
    total = int(re.search(r"(?m)^Total Events +Processed +(\d+)", text)[1])
    counts = {}
    for op, _, _, _, _, guid, opcode, version in FAMILIES:
        pattern = rf"(?im)^\|\s*(\d+) +[^\r\n|]*? +{opcode} +{version} +\{{{guid}\}}\|"
        counts[op] = sum(int(n) for n in re.findall(pattern, text))
    return total, counts


def first_payload(operation, row):
    if operation == "cpu_profile":
        return (int(row["instruction_pointer"], 16).to_bytes(row["pointer_bytes"], "little") +
                struct.pack("<IHH", row["sampled_thread_id"], row["count_field"], row["reserved_field"]))
    mode_or_flags = row["old_wait_mode"] if row["version"] == 2 else row["thread_flags"]
    return struct.pack("<IIbbBbbBbbII", row["new_thread_id"], row["old_thread_id"], row["new_priority"],
                       row["old_priority"], row["previous_c_state"], row["spare_byte"], row["old_wait_reason"],
                       mode_or_flags & 255, row["old_state"], row["old_wait_ideal_processor"],
                       row["new_wait_time"], row["reserved_field"])


def check_scan(exe, path, pin, code, oracle=None):
    data, probe, rows = report(exe, path, pin, code)
    assert probe["status"] == ("read" if code == 0 else "partial")
    assert probe["source_sha256"] == pin.lower() and probe["source_bytes"] == path.stat().st_size
    assert probe["trace_opened"] is True and probe["source_revalidated"] is True and probe["win32_status"] == 0
    coverage = probe["coverage"]
    if oracle:
        assert coverage["records_seen"] == oracle[0]
    for op, command, key, decoded, unsupported, *_ in FAMILIES:
        page = json.loads(invoke(exe, [command, path, "--sha256", pin, "--limit", "1"], code))
        for name in ("records_seen", "buffer_comparison", "buffers_processed", "loss_marker_records"):
            assert coverage[name] == page[name]
        for name in ("buffers_written", "events_lost", "buffers_lost"):
            assert coverage[name] == page["log_header"][name]
        row = rows[op]
        evidence = row["record_evidence"]
        assert evidence["decoded"] == page[decoded] and evidence["unsupported"] == page[unsupported] == 0
        if oracle:
            assert evidence["decoded"] == oracle[1][op]
        assert evidence["first_decoded_record"] == (page[key][0]["record_ordinal"] if page[key] else None)
        if op == "hard_fault" and page[key]:
            # The named-property TDH oracle also reconstructs and hashes the private pointer fields.
            assert evidence["first_payload_bytes"] == 24 + 2 * page[key][0]["pointer_bytes"]
            assert re.fullmatch(r"[0-9a-f]{64}", evidence["first_payload_sha256"])
        elif op == "disk_io" and page[key]:
            # Disk pages omit pointer values. The XML disk oracle checks the hash from the full named fields.
            first = page[key][0]
            width = first["pointer_bytes"]
            size = {10: 32+2*width, 11: 32+2*width, 14: 16+width}.get(first["opcode"], width)
            assert evidence["first_payload_bytes"] == size + (4 if first["version"] == 3 else 0)
            assert re.fullmatch(r"[0-9a-f]{64}", evidence["first_payload_sha256"])
        else:
            payload = first_payload(op, page[key][0]) if page[key] else None
            assert evidence["first_payload_bytes"] == (len(payload) if payload else None)
            assert evidence["first_payload_sha256"] == (hashlib.sha256(payload).hexdigest() if payload else None)
        assert evidence["observation"] == ("decoded_records" if page[key] else "no_matching_records_observed")
        assert row["availability"] == ("available" if page[key] and code == 0 else "partial")
        stages = row["probe_stages"]
        assert stages["source_opened"] == "passed"
        assert stages["sample_read"] == stages["layout_qualified"] == ("passed" if page[key] else "not_probed")
    return data


def check_failures(exe, folder, source, pin):
    invalid = folder / "owned input.etl"
    invalid.write_bytes(b"owned non-ETL control\n" * 64)
    invalid_pin = sha256(invalid)
    missing = folder / "missing.etl"
    wrong = ("0" if pin[0] != "0" else "1") + pin[1:]
    for path, expected, reason, actual in ((source, wrong, "digest_mismatch", pin),
                                          (invalid, invalid_pin, "open_trace_failed", invalid_pin),
                                          (missing, pin, "source_unavailable", None)):
        _, probe, rows = report(exe, path, expected, 1)
        assert probe["status"] == reason and probe["source_sha256"] == actual
        assert probe["source_revalidated"] is None and probe["trace_opened"] is False and probe["coverage"] is None
        assert (probe["win32_status"] not in (None, 0)) == (reason == "open_trace_failed")
        for row in rows.values():
            assert row["availability"] == "unavailable" and row["record_evidence"] is None
            assert row["probe_stages"]["source_opened"] == ("passed" if actual else "failed")
            assert row["probe_stages"]["layout_qualified"] == row["probe_stages"]["sample_read"] == "not_probed"
    owned = folder / "owned valid trace.etl"
    shutil.copyfile(source, owned)
    command = probe_args(owned, pin)
    output = folder / "report.json"
    with output.open("wb") as destination:
        invoke(exe, command, stdout=destination)
    assert json.loads(output.read_bytes())["probe"]["source_sha256"] == pin
    for args in (command[:-1], command + ["--probe"], [*command[:-1], "x" * 64], ["--capabilities", "--probe-etl"]):
        assert not invoke(exe, args, 2)
    alias = folder / "redirect.bin"
    os.link(owned, alias)
    for args, channel, code in ((command, "stdout", 2), (command[:-1], "stderr", 2),
                                (["--capabilities", "--probe", *command[1:]], "stderr", 2),
                                ([*probe_args(invalid, invalid_pin), "--probe-etl", owned], "stderr", 2),
                                (["--mode", "offline", *command], "stdout", 5),
                                ([*command, "--mode", "offline"], "stdout", 2)):
        with alias.open("ab", buffering=0) as stream:
            invoke(exe, args, code, **{channel: stream})
        assert sha256(owned) == pin
    for mode in ("observe", "offline"):
        denial = json.loads(invoke(exe, ["--mode", mode, *command], 5))
        assert denial["status"] == "blocked_by_policy"
    with invalid.open("rb") as readonly:
        invoke(exe, probe_args(source, pin), 2, stdout=readonly)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--etl", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--check-short-tail", action="store_true")
    args = parser.parse_args()
    exe, path = args.exe.resolve(strict=True), args.etl.resolve(strict=True)
    pin = sha256(path)
    assert pin == args.sha256.lower()
    with tempfile.TemporaryDirectory(prefix="kn-saved-etl-cap-") as temp:
        folder = Path(temp)
        expected = windows_counts(path, folder)
        data = check_scan(exe, path, pin.upper(), 0, expected)
        audit = run_path(str(Path(__file__).with_name("validate-public-content.py")))["inspect"]
        for value in (data, data["probe"], *(row["record_evidence"] for row in data["capabilities"] if "record_evidence" in row)):
            assert audit("private-export.log", json.dumps(value).encode("utf-8"))
        matrix = run_path(str(Path(__file__).with_name("generate-support-matrix.py")))
        try:
            matrix["render"](data)
        except ValueError:
            pass
        else:
            raise AssertionError("artifact-specific availability entered the compiled support matrix")
        if args.check_short_tail:
            clipped = folder / "clipped.etl"
            shutil.copyfile(path, clipped)
            with clipped.open("r+b") as stream:
                stream.truncate(path.stat().st_size - 1)
            report_clipped = check_scan(exe, clipped, sha256(clipped), 1)
            assert report_clipped["probe"]["coverage"]["buffer_comparison"] == "fewer_than_declared"
        check_failures(exe, folder, path, pin)
        assert sha256(path) == pin
        print(f"ETL capability rows matched tracerpt on {expected[0]} records: {expected[1]}; short tail={args.check_short_tail}")


if __name__ == "__main__":
    main()
