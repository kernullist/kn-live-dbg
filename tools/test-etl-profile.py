"""Compare a pinned local Windows ETL with the system tracerpt decoder."""
import argparse
import csv
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(exe, etl, digest, *args, rc=0):
    result = subprocess.run([exe, "--etl-profile", etl, "--sha256", digest, *map(str, args)],
                            capture_output=True, timeout=90)
    assert result.returncode == rc, (result.returncode, result.stdout[:250], result.stderr[:250])
    if rc == 2:
        assert not result.stdout
        return None
    value = json.loads(result.stdout.decode("utf-8"))
    assert value["schema"] == "kn.etl_profile.v1"
    return value


def oracle(etl, folder):
    csv_path = folder / "raw.csv"
    tracerpt = Path(os.environ["SystemRoot"]) / "System32" / "tracerpt.exe"
    subprocess.run([tracerpt, etl, "-o", csv_path, "-of", "CSV", "-rts", "-y"],
                   cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, timeout=180)
    samples = []
    records = 0
    # The compared columns are ASCII numbers and MOF event names. Preserve
    # every CSV record, including unrelated provider payloads in the local ACP.
    with csv_path.open(encoding="latin-1", newline="") as f:
        rows = csv.reader(f, skipinitialspace=True)
        header = [name.strip() for name in next(rows)]
        assert header[0] == "Event Name" and header[16] == "Clock-Time" and header[19] == "User Data"
        for records, fields in enumerate(rows, 1):
            if fields[:4] != ["PerfInfo", "SampleProf", "0", "2"] or fields[6] != "46":
                continue
            assert len(fields) == 23
            samples.append((records, *(int(fields[i], 0) for i in
                                (16, 11, 19, 20, 21, 22, 9, 10, 8, 4, 5, 7))))
    return records, samples


def compare(report, pin, size, records, oracle_rows, after, limit):
    assert report["status"] == "read" and report["source_sha256"] == pin and report["source_bytes"] == size
    assert (report["provider_guid"], report["event_id"], report["opcode"], report["version"]) == (
        "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc", 0, 46, 2)
    assert report["records_seen"] == records and report["decoded_samples"] == len(oracle_rows)
    assert report["after"] == after
    assert report["log_header"]["events_lost"] >= 0 and report["log_header"]["buffers_lost"] >= 0
    if report["buffer_comparison"] == "matched":
        assert report["buffers_processed"] == report["log_header"]["buffers_written"]
    else:
        assert report["buffer_comparison"] == "not_comparable"
    q = report["qualification"]
    assert q["evidence"] == "reported_cpu_sample" and q["verified_level"] == "unqualified"
    assert q["producer_authenticity"] == "unverified"
    assert all(q[field] is None for field in ("sampled_process_id", "thread_lifetime", "address_space",
               "vm", "vtl", "code_version", "capture_privilege", "capture_enable_flags",
               "stack_capture_policy", "sample_loss_intervals"))
    rows = report["samples"]
    wanted = oracle_rows[after:after + limit]
    assert len(rows) == len(wanted)
    for seq, (row, expected) in enumerate(zip(rows, wanted), after + 1):
        got = (row["record_ordinal"], int(row["raw_timestamp"]), row["cpu"], int(row["instruction_pointer"], 0),
               row["sampled_thread_id"], row["count_field"], row["reserved_field"],
               row["header_process_id"], row["header_thread_id"], int(row["event_keyword"], 0),
               row["event_channel"], row["event_level"], row["event_task"])
        assert row["sample_ordinal"] == seq and got == expected, (seq, got, expected)
        assert row["pointer_bytes"] in (4, 8)
        assert row["cpu_field"] == ("processor_index" if row["header_flags"] & 0x200 else "processor_number")
    assert report["next_after"] == (after + limit if after + limit < len(oracle_rows) else None)
    return len(rows)


def check_directory_lease(exe, etl, pin, parent):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    # FILE_ADD_FILE makes this a write-access handle on an owned ancestor.
    handle = kernel.CreateFileW(str(parent), 2, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        assert run(exe, etl, pin, rc=1)["status"] == "source_unavailable"
    finally:
        kernel.CloseHandle(handle)


def exercise(exe, etl, pin, expected_count, folder, all_pages, short_tail):
    size = etl.stat().st_size
    with etl.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == pin
    records, samples = oracle(etl, folder)
    assert len(samples) == expected_count, (len(samples), expected_count)
    pages = [(0, 64), (0, 1), (min(1, len(samples)), 128), (len(samples) // 2, 128),
             (max(0, len(samples) - 3), 128), (len(samples), 1)]
    if all_pages:
        pages.extend((offset, 128) for offset in range(0, len(samples), 128))
    compared = set()
    for after, limit in pages:
        # The first call exercises the defaults, subsequent calls explicit paging.
        args = [] if (after, limit) == (0, 64) else ["--limit", limit, "--after", after]
        report = run(exe, etl, pin.upper(), *args)
        count = compare(report, pin, size, records, samples, after, limit)
        compared.update(range(after + 1, after + 1 + count))
    if all_pages:
        assert len(compared) == len(samples)
    if short_tail:
        trimmed = folder / "short-tail.etl"
        shutil.copyfile(etl, trimmed)
        with trimmed.open("r+b") as output:
            output.truncate(size - 1)
        with trimmed.open("rb") as f:
            trimmed_pin = hashlib.file_digest(f, "sha256").hexdigest()
        partial = run(exe, trimmed, trimmed_pin, "--limit", 1, rc=1)
        assert partial["source_sha256"] == trimmed_pin and partial["status"] == "partial"
        assert partial["buffer_comparison"] == "fewer_than_declared"
        assert partial["buffers_processed"] < partial["log_header"]["buffers_written"]
        assert partial["records_seen"] < records
    assert run(exe, etl, pin, "--after", len(samples) + 1, rc=1)["status"] == "cursor_out_of_range"
    wrong = ("0" if pin[0] != "0" else "1") + pin[1:]
    assert run(exe, etl, wrong, rc=1)["status"] == "digest_mismatch"
    for args in (("--after", "-1"), ("--limit", 0), ("--limit", 129), ("--after", "01"),
                 ("--after", 1, "--after", 2), ("--limit", "1", "--limit", "2")):
        run(exe, etl, pin, *args, rc=2)
    bad = folder / "invalid.etl"
    bad.write_bytes(b"invalid test input")
    bad_pin = hashlib.sha256(bad.read_bytes()).hexdigest()
    assert run(exe, bad, bad_pin, rc=1)["status"] in ("open_trace_failed", "process_trace_failed")
    missing = folder / "missing.etl"
    assert run(exe, missing, pin, rc=1)["status"] == "source_unavailable"
    check_directory_lease(exe, etl, pin, folder)
    # The writable stdout hard link must not receive even an error report.
    hardlink = folder / "same-source.bin"
    os.link(etl, hardlink)
    with hardlink.open("ab", buffering=0) as redirected:
        result = subprocess.run([exe, "--etl-profile", etl, "--sha256", pin],
                                stdout=redirected, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode != 0 and etl.stat().st_size == size
    with etl.open("rb") as f:
        assert hashlib.file_digest(f, "sha256").hexdigest() == pin
    print(f"ETL profile passed. {records} events, {len(samples)} CPU samples, {len(compared)} distinct sample rows compared.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--etl", type=Path, required=True, help="Saved trace for the independent decoder")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--expect-samples", type=int, required=True)
    parser.add_argument("--all-pages", action="store_true", help="Compare every decoded sample in 128-row pages")
    parser.add_argument("--check-short-tail", action="store_true",
                        help="For fixtures with a populated last buffer, require detection after removing its last byte")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-etl-profile-") as directory:
        folder = Path(directory)
        (folder / "source").mkdir()
        etl = folder / "source" / "input.etl"
        shutil.copyfile(args.etl, etl)
        exercise(args.exe.resolve(strict=True), etl, args.sha256.lower(), args.expect_samples, folder, args.all_pages, args.check_short_tail)


if __name__ == "__main__":
    main()
