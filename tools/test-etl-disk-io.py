"""Compare saved disk I/O pages with Windows tracerpt XML or its compact CSV export."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
from runpy import run_path
import subprocess
import tempfile


BASE = run_path(str(Path(__file__).with_name("test-etl-profile.py")))
DISK = "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"
TRACE = "68fdd900-4a3e-11d1-84f4-0000f80464e3"
TYPES = {10: ("read", "completion"), 11: ("write", "completion"), 12: ("read", "initiation"),
         13: ("write", "initiation"), 14: ("flush", "completion"), 15: ("flush", "initiation")}


class DiskOracle:
    def __init__(self):
        self.events = []
        self.frequency = None
        self.unsupported = 0
        self.first_payload_digests = {}

    def observe_xml(self, event, ns, guid, record):
        if guid not in (TRACE, DISK):
            return
        system = event.find(ns + "System")
        opcode = int(system.findtext(ns + "Opcode"))
        if guid == TRACE and opcode != 0 or guid == DISK and opcode not in TYPES:
            return
        fields = {x.attrib["Name"]: x.text for x in event.findall(ns + "EventData/" + ns + "Data")}
        if guid == TRACE:
            if "PerfFreq" in fields and self.frequency is None:
                self.frequency = int(fields["PerfFreq"], 0)
            return
        version = int(system.findtext(ns + "Version"))
        self.observe(record, opcode, version, int(system.findtext(ns + "EventID")),
                     system.find(ns + "TimeCreated").attrib["RawTime"],
                     int(system.find(ns + "Execution").attrib["ProcessorID"], 0), fields)

    def observe(self, record, opcode, version, event_id, timestamp, cpu, fields):
        if event_id != 0 or version not in (2, 3):
            self.unsupported += 1
            return
        name, phase = TYPES[opcode]
        complete = phase == "completion"
        if not self.events:
            # TDH returns the MOF fields in wire order. Some ETLs mix envelope widths.
            for width in (4, 8):
                sizes = ([4, 4, 4, 4, 8, width, width, 8] if opcode in (10, 11) else
                         [4, 4, 8, width] if opcode == 14 else [width])
                if version == 3:
                    sizes.append(4)
                buf = bytearray()
                for value, size in zip(fields.values(), sizes, strict=True):
                    number = int(value, 0)
                    if not -(1 << (size*8-1)) <= number < (1 << (size*8)):
                        break
                    buf.extend(number.to_bytes(size, "little", signed=number < 0))
                else:
                    self.first_payload_digests[len(buf)] = hashlib.sha256(buf).hexdigest()
            assert self.first_payload_digests
        self.events.append(dict(disk_event_ordinal=len(self.events)+1, record_ordinal=record,
            raw_timestamp=timestamp, opcode=opcode, version=version, cpu=cpu, operation=name, phase=phase,
            reported_issuing_tid=int(fields["IssuingThreadId"], 0) if version == 3 else None,
            disk_number=int(fields["DiskNumber"], 0) if complete else None,
            transfer_bytes=int(fields["TransferSize"], 0) if complete and name != "flush" else None,
            high_res_response_ticks=str(int(fields["HighResResponseTime"], 0)) if complete else None))

    @staticmethod
    def compare_row(row, expected):
        assert {key: row[key] for key in expected} == expected, ("disk event mismatch", expected["record_ordinal"])
        assert set(row) - set(expected) == {"pointer_bytes", "cpu_field", "logger_id"}
        assert row["pointer_bytes"] in (4, 8) and row["cpu_field"] in ("processor_index", "processor_number")

    def compare(self, page, records, digest, after, limit):
        assert (page["schema"], page["source_sha256"], page["provider_guid"]) == ("kn.etl_disk_io.v1", digest, DISK)
        assert page["records_seen"] == records and page["decoded_disk_records"] == len(self.events)
        assert page["unsupported_disk_records"] == self.unsupported and page["after"] == after
        assert page["qualification"]["request_generation"] is None and page["qualification"]["device_service_time"] is None
        assert page["response_ticks_per_second"] == (str(self.frequency) if self.frequency and self.frequency > 0 else None)
        expected = self.events[after:after+limit]
        assert len(expected) == len(page["disk_events"])
        for row, witness in zip(page["disk_events"], expected):
            self.compare_row(row, witness)
        assert page["next_after"] == (after+limit if after+limit < len(self.events) else None)
        assert [s["operation"] for s in page["operations"]] == ["read", "write", "flush"]
        for summary in page["operations"]:
            family = [r for r in self.events if r["operation"] == summary["operation"]]
            completed = [r for r in family if r["phase"] == "completion"]
            assert summary["completions"] == len(completed) and summary["initiations"] == len(family)-len(completed)
            size = None if summary["operation"] == "flush" else str(sum(r["transfer_bytes"] for r in completed))
            assert summary["transfer_bytes"] == size
            longest = max((int(r["high_res_response_ticks"]) for r in completed), default=None)
            ties = [r for r in completed if int(r["high_res_response_ticks"]) == longest]
            assert summary["longest_response_ties"] == len(ties)
            if ties:
                self.compare_row(summary["first_longest_response"], ties[0])
            else:
                assert summary["first_longest_response"] is None


def read_csv(path, truth):
    # tracerpt CSV has a common envelope followed by the ordered MOF fields.
    # Project only ASCII numeric fields. Other providers can contain local-code-page text.
    names = {10: "Read", 11: "Write", 12: "ReadInit", 13: "WriteInit", 14: "FlushBuffers", 15: "FlushInit"}
    transfer = ["DiskNumber", "IrpFlags", "TransferSize", "Reserved", "ByteOffset", "FileObject", "Irp", "HighResResponseTime"]
    flush = ["DiskNumber", "IrpFlags", "HighResResponseTime", "Irp"]
    records = 0
    with path.open(encoding="latin1", newline="") as stream:
        rows = csv.reader(stream, skipinitialspace=True)
        header = [name.strip() for name in next(rows)]
        assert header[:4] == ["Event Name", "Type", "Event ID", "Version"] and header[16] == "Clock-Time"
        for records, row in enumerate(rows, 1):
            if row[0].strip() == "EventTrace" and row[1].strip() == "Header" and truth.frequency is None:
                truth.frequency = int(row[19+16], 0)
            if row[0].strip() != "DiskIo":
                continue
            opcode, version = int(row[6], 0), int(row[3], 0)
            if opcode not in TYPES:
                continue
            assert row[1].strip() in (names[opcode], str(opcode))
            keys = transfer if opcode in (10, 11) else flush if opcode == 14 else ["Irp"]
            keys = keys + (["IssuingThreadId"] if version == 3 else [])
            fields = dict(zip(keys, row[19:], strict=True)) if version in (2, 3) else {}
            truth.observe(records, opcode, version, int(row[2], 0), str(int(row[16], 0)), int(row[11], 0), fields)
    return records


def csv_oracle(etl, directory, truth):
    csv_path = directory / "raw.csv"
    tracerpt = Path(os.environ["SystemRoot"]) / "System32" / "tracerpt.exe"
    subprocess.run([tracerpt, etl, "-of", "CSV", "-en", "ANSI", "-rts", "-o", csv_path, "-y"],
                   cwd=directory, capture_output=True, check=True, timeout=240)
    records = read_csv(csv_path, truth)
    csv_path.unlink()
    # CSV identifies the family by name. The independent summary counts the exact GUID and versions.
    cap = run_path(str(Path(__file__).with_name("test-etl-capabilities.py")))
    total, families = cap["windows_counts"](etl, directory)
    assert records == total and len(truth.events) == families["disk_io"]
    return records


def check_probe(exe, etl, pin, truth):
    report = json.loads(subprocess.check_output([exe, "--capabilities", "--probe-etl", etl, "--sha256", pin], timeout=90))
    assert report["target_probed"] is False
    matches = [r for r in report["capabilities"] if (r["domain"], r["operation"], r["backend"]) == ("io", "disk_io", "etl")]
    assert len(matches) == 1
    evidence = matches[0]["record_evidence"]
    assert evidence["decoded"] == len(truth.events) and evidence["unsupported"] == truth.unsupported
    if truth.events:
        assert evidence["first_decoded_record"] == truth.events[0]["record_ordinal"]
        assert truth.first_payload_digests[evidence["first_payload_bytes"]] == evidence["first_payload_sha256"]
    else:
        assert all(evidence[k] is None for k in ("first_decoded_record", "first_payload_bytes", "first_payload_sha256"))


def check_aliases(exe, directory):
    source = directory / "owned evidence.etl"
    alias = directory / "alias.bin"
    data = b"private test input for redirection"
    source.write_bytes(data)
    os.link(source, alias)
    pin = hashlib.sha256(data).hexdigest()
    for stream, args in (("stdout", [source, "--sha256", pin]), ("stderr", [source, "--bad"]),
                         ("stderr", ["--bad", source, "--sha256", pin]),
                         ("stderr", ["--bad", "--capture-statement", source])):
        with alias.open("ab", buffering=0) as sink:
            io = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, stream: sink}
            proc = subprocess.run([exe, "--etl-disk-io", *args], **io, timeout=30)
        assert proc.returncode == 2 and source.read_bytes() == data
    # Restricted modes do not open paths. A disk-backed denial preserves all named inputs.
    for selector in ("--etl-disk-io", "--etl-switches", "--etl-profile"):
        for mode in ("observe", "offline"):
            args = ["--mode", mode, selector, source, "--sha256", pin]
            denied = subprocess.run([exe, *args], capture_output=True, timeout=30)
            assert denied.returncode == 5 and json.loads(denied.stdout)["status"] == "blocked_by_policy"
            for command, code in ((args, 5), ([selector, source, "--mode", mode], 2),
                                  ([source, "--mode", mode, selector], 2)):
                with alias.open("ab", buffering=0) as sink:
                    denied = subprocess.run([exe, *command], stdout=sink, stderr=subprocess.PIPE, timeout=30)
                assert denied.returncode == code and source.read_bytes() == data
    with (directory / "usage.txt").open("w+b") as sink:
        proc = subprocess.run([exe, "--etl-disk-io", "--bad", source], stderr=sink, stdout=subprocess.PIPE, timeout=30)
        sink.seek(0)
        assert proc.returncode == 2 and not proc.stdout and b"--etl-disk-io" in sink.read()


def run(exe, etl, digest, *options, code=0):
    cmd = [exe, "--etl-disk-io", etl, "--sha256", digest, *map(str, options)]
    proc = subprocess.run(cmd, capture_output=True, timeout=90)
    assert proc.returncode == code, (proc.returncode, proc.stdout[:220], proc.stderr[:220])
    if code == 2:
        assert not proc.stdout
    return proc.stdout


def verify(exe, etl, pin, directory, all_pages, short_tail, use_csv):
    with etl.open("rb") as src:
        assert hashlib.file_digest(src, "sha256").hexdigest() == pin
    truth = DiskOracle()
    if use_csv:
        records = csv_oracle(etl, directory, truth)
    else:
        records, *_ = BASE["oracle"](etl, directory, False, want_switches=True, disk=truth)
        (directory / "raw.xml").unlink()
    check_probe(exe, etl, pin, truth)
    pages = BASE["page_cases"](len(truth.events), all_pages)
    for after, limit in dict.fromkeys(pages):
        raw = run(exe, etl, pin, "--after", after, "--limit", limit)
        page = json.loads(raw)
        assert page["status"] == "read"
        truth.compare(page, records, pin, after, limit)
    page_hash = hashlib.sha256(raw).hexdigest()
    receipt = json.loads(run(exe, etl, pin, "--after", after, "--limit", limit, "--check-page", page_hash))
    assert receipt["status"] == "matched" and receipt["source_kind"] == "disk_io" and receipt["page_bytes_match"]
    changed = json.loads(run(exe, etl, pin, "--after", after, "--limit", limit, "--check-page", "0"*64, code=1))
    assert changed["status"] == "page_mismatch" and not changed["page_bytes_match"]
    assert json.loads(run(exe, etl, "0"*64, code=1))["status"] == "digest_mismatch"
    assert json.loads(run(exe, etl, pin, "--after", len(truth.events)+1, code=1))["status"] == "cursor_out_of_range"
    for options in [("--intervals",), ("--thread-id", "4"), ("--reference-image", str(etl), pin), ("--capture-settings",), ("--limit", "0")]:
        run(exe, etl, pin, *options, code=2)
    check_aliases(exe, directory)
    if short_tail:
        short = directory / "short.etl"
        data = etl.read_bytes()[:-1]
        short.write_bytes(data)
        partial = json.loads(run(exe, short, hashlib.sha256(data).hexdigest(), code=1))
        assert partial["status"] == "partial" and partial["buffer_comparison"] == "fewer_than_declared"
        assert partial["buffers_processed"] < partial["log_header"]["buffers_written"]
    print(json.dumps(dict(records=records, decoded=len(truth.events), header_frequency=truth.frequency,
        operations=[{k: s[k] for k in ("operation", "initiations", "completions", "transfer_bytes", "longest_response_ties")}
                    for s in page["operations"]], pages=len(dict.fromkeys(pages)))))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--etl", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--csv", action="store_true", help="use the smaller Windows CSV export and its GUID summary")
    parser.add_argument("--all-pages", action="store_true")
    parser.add_argument("--short-tail", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-disk-oracle-") as folder:
        verify(args.exe.resolve(strict=True), args.etl.resolve(strict=True), args.sha256, Path(folder), args.all_pages, args.short_tail, args.csv)
