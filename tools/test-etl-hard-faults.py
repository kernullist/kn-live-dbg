"""Check each page and its file-wide totals against Windows TDH properties and tracerpt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
CAP = runpy.run_path(str(HERE / "test-etl-capabilities.py"))
AUDIT = runpy.run_path(str(HERE / "validate-public-content.py"))
COMMAND = "--etl-hard-faults"


def tdh_rows(oracle, path):
    result = subprocess.run([oracle, path], capture_output=True, check=True, timeout=120)
    lines = result.stdout.splitlines()
    footer = json.loads(lines.pop())
    clock, frequency = footer["clock_type"], footer["frequency"]
    assert len(lines) == footer["decoded_hard_faults"] and not result.stderr
    assert any(f["rule"] == "private-evidence-bundle" for f in AUDIT["inspect"]("tdh.log", result.stdout))
    rows, first_hash = [], None
    for i, line in enumerate(lines, 1):
        row = json.loads(line)
        if i == 1:
            first_hash = row.pop("first_payload_sha256")
        assert row["pointer_bytes"] in (4, 8)
        start, end = int(row["initial_time_raw"]), int(row["raw_timestamp"])
        if start >= 2**63:
            start -= 2**64
        status = ("qpc_unavailable" if clock != 1 or frequency <= 0 else
                  "nonpositive_start" if start <= 0 else "end_precedes_start" if end < start else "ordered_qpc")
        row.update(fault_ordinal=i, initial_time_raw=str(start), timing_status=status,
                   elapsed_qpc_ticks=str(end - start) if status == "ordered_qpc" else None)
        rows.append(row)
    return footer["records_seen"], clock, frequency, rows, first_hash


def same_row(actual, expected):
    assert {key: actual[key] for key in expected} == expected, ("TDH row mismatch", expected["record_ordinal"])
    assert actual["cpu_field"] in ("processor_number", "processor_index")
    assert not {"file_object", "virtual_address", "disk_number", "process_generation"} & actual.keys()


def compare(exe, oracle, path, pin, directory, partial):
    assert CAP["sha256"](path) == pin
    records, clock, frequency, expected, first_hash = tdh_rows(oracle, path)
    summary_records, families = CAP["windows_counts"](path, directory)
    assert (records, len(expected)) == (summary_records, families["hard_fault"])
    rc = int(partial)
    base = [COMMAND, path, "--sha256", pin]
    _, _, capabilities = CAP["report"](exe, path, pin, rc)
    evidence = capabilities["hard_fault"]["record_evidence"]
    assert evidence["decoded"] == len(expected) and evidence["unsupported"] == 0
    assert evidence["first_payload_sha256"] == first_hash
    assert evidence["first_decoded_record"] == (expected[0]["record_ordinal"] if expected else None)
    assert evidence["first_payload_bytes"] == (24 + 2 * expected[0]["pointer_bytes"] if expected else None)
    measured = [r for r in expected if r["elapsed_qpc_ticks"] is not None]
    maximum = max((int(r["elapsed_qpc_ticks"]) for r in measured), default=None)
    longest = [r for r in measured if int(r["elapsed_qpc_ticks"]) == maximum]
    total = sum(r["byte_count"] for r in expected)
    # Nonuniform pages plus a cursor at end exercise both traversal and aggregate stability.
    for after, limit in [(0, 1), *((n, 128) for n in range(0, len(expected), 128)), (len(expected), 1)]:
        args = [*base, "--after", str(after), "--limit", str(limit)]
        raw = CAP["invoke"](exe, args, rc)
        d = json.loads(raw)
        assert (d["schema"], d["status"], d["source_sha256"]) == ("kn.etl_hard_faults.v1", "partial" if partial else "read", pin)
        assert (d["provider_guid"], d["opcode"], d["version"], d["event_id"]) == ("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c", 32, 2, 0)
        assert d["source_bytes"] == path.stat().st_size and (d["records_seen"], d["decoded_hard_faults"]) == (records, len(expected))
        assert d["unsupported_hard_fault_records"] == 0 and d["after"] == after
        assert (d["clock"]["raw_type"], int(d["clock"]["header_perf_frequency"])) == (clock, frequency)
        q = d["qualification"]
        assert q["producer_authenticity"] == "unverified" and all(q[k] is None for k in ("thread_lifetime", "file_identity", "disk_request", "critical_path"))
        summary = d["fault_summary"]
        assert (int(summary["read_bytes"]), summary["timed_faults"], summary["untimed_faults"], summary["longest_fault_ties"]) == (
            total, len(measured), len(expected) - len(measured), len(longest))
        if longest:
            same_row(summary["first_longest_fault"], longest[0])
        else:
            assert summary["first_longest_fault"] is None
        for row, witness in zip(d["hard_faults"], expected[after:after + limit], strict=True):
            same_row(row, witness)
        assert d["next_after"] == (after + limit if after + limit < len(expected) else None)
        if after == 0 and limit == 1:
            assert any(f["rule"] == "private-evidence-bundle" for f in AUDIT["inspect"]("private.log", raw))
            page_pin = hashlib.sha256(raw).hexdigest()
            for supplied, code, status in ((page_pin, rc, "matched"), ("0" * 64, 1, "page_mismatch")):
                proof = json.loads(CAP["invoke"](exe, [*args, "--check-page", supplied], code))
                assert (proof["status"], proof["source_kind"], proof["replayed_page_sha256"]) == (status, "hard_fault", page_pin)
                assert proof["source_status"] == d["status"] and proof["page_bytes_match"] is (supplied == page_pin)
    assert json.loads(CAP["invoke"](exe, [COMMAND, path, "--sha256", "0" * 64], 1))["status"] == "digest_mismatch"
    if not partial:
        assert json.loads(CAP["invoke"](exe, [*base, "--after", str(len(expected) + 1)], 1))["status"] == "cursor_out_of_range"
    assert CAP["sha256"](path) == pin
    print(f"{records} records, {len(expected)} hard faults, {len(measured)} timed, {total} bytes, longest {maximum} ticks")


def rejected_inputs(exe, directory):
    import _winapi

    path = directory / "owned input.etl"
    path.write_bytes(b"hard fault output ownership control")
    pin = CAP["sha256"](path)
    alias = directory / "other name.bin"
    os.link(path, alias)
    args = [COMMAND, path, "--sha256", pin]
    locked = _winapi.CreateFile(str(path), 0x80000000, 0, 0, 3, 0, 0)
    try:
        error = json.loads(CAP["invoke"](exe, args, 1))
        assert error["status"] == "source_unavailable" and error["win32_status"] == 32
    finally:
        _winapi.CloseHandle(locked)
    target, junction = directory / "ordinary", directory / "junction"
    target.mkdir()
    os.link(path, target / "input.etl")
    _winapi.CreateJunction(str(target), str(junction))
    try:
        indirect = [COMMAND, junction / "input.etl", "--sha256", pin]
        rejected = json.loads(CAP["invoke"](exe, indirect, 1))
        assert rejected["status"] == "source_unavailable" and rejected["win32_status"] is None
        with alias.open("ab", buffering=0) as sink:
            CAP["invoke"](exe, indirect, 2, stdout=sink)
        assert CAP["sha256"](path) == pin
    finally:
        junction.rmdir()
    for command in (COMMAND, "--etl-profile", "--etl-switches", "--etl-disk-io"):
        for missing in (directory / "absent.etl", directory / "absent directory" / "trace.etl"):
            argv = [command, missing, "--sha256", pin]
            plain = CAP["invoke"](exe, argv, 1)
            doc = json.loads(plain)
            assert doc["status"] == "source_unavailable" and doc["win32_status"] in (2, 3)
            with (directory / "failure.json").open("wb") as out:
                CAP["invoke"](exe, argv, 1, stdout=out)
            assert (directory / "failure.json").read_bytes() == plain
    for flags in (["--capture-settings"], ["--thread-id", "1"], ["--limit", "0"], ["--clr-evidence"]):
        assert not CAP["invoke"](exe, [*args, *flags], 2)
    for args, sink, rc in ((args, "stdout", 2), ([COMMAND, "--bad", path], "stderr", 2),
                           (["--mode", "offline", *args], "stdout", 5), ([*args, "--mode", "observe"], "stdout", 2)):
        with alias.open("ab", buffering=0) as stream:
            CAP["invoke"](exe, args, rc, **{sink: stream})
        assert CAP["sha256"](path) == pin


def header_controls(exe, original, original_pin, directory):
    # Locate this fixture's clock and loss fields using the independently named ETW header values.
    def page(path, pin, code):
        return json.loads(CAP["invoke"](exe, [COMMAND, path, "--sha256", pin, "--limit", "128"], code))
    baseline = page(original, original_pin, 0)
    clock, header = baseline["clock"], baseline["log_header"]
    assert clock["raw_type"] == 1 and baseline["fault_summary"]["timed_faults"] > 0 and header["buffers_lost"] == 0
    data = original.read_bytes()
    signature = struct.pack("<qqII", int(clock["header_perf_frequency"]), int(header["start_filetime"]), 1, 0)
    first = data[:512]
    assert first.count(signature) == 1
    offset = first.index(signature)
    for name, delta, fmt, value in (("system", 16, "I", 2), ("cycle", 16, "I", 3),
                                    ("no frequency", 0, "q", 0), ("lost buffers", 20, "I", 2)):
        changed = bytearray(data)
        struct.pack_into("<" + fmt, changed, offset + delta, value)
        path = directory / (name + ".etl")
        path.write_bytes(changed)
        loss = name == "lost buffers"
        d = page(path, hashlib.sha256(changed).hexdigest(), int(loss))
        summary = d["fault_summary"]
        assert d["decoded_hard_faults"] == baseline["decoded_hard_faults"]
        assert summary["read_bytes"] == baseline["fault_summary"]["read_bytes"]
        if loss:
            assert d["status"] == "partial" and d["log_header"]["buffers_lost"] == value
            assert summary == baseline["fault_summary"] and d["hard_faults"] == baseline["hard_faults"]
        else:
            assert d["clock"]["raw_type"] == (value if delta == 16 else 1)
            if delta == 0:
                assert d["clock"]["header_perf_frequency"] == "0"
            assert summary["timed_faults"] == summary["longest_fault_ties"] == 0
            assert summary["untimed_faults"] == d["decoded_hard_faults"] and summary["first_longest_fault"] is None
            assert all(r["timing_status"] == "qpc_unavailable" and r["elapsed_qpc_ticks"] is None for r in d["hard_faults"])
    assert CAP["sha256"](original) == original_pin


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("--exe", "--oracle", "--etl"):
        parser.add_argument(name, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--check-header-controls", action="store_true", help="use a complete QPC trace with timed faults")
    opt = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-hard-fault-") as temp:
        folder = Path(temp)
        binary = opt.exe.resolve(strict=True)
        path, pin = opt.etl.resolve(strict=True), opt.sha256.lower()
        compare(binary, opt.oracle.resolve(strict=True), path, pin, folder, opt.partial)
        rejected_inputs(binary, folder)
        if opt.check_header_controls:
            header_controls(binary, path, pin, folder)
