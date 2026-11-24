"""Exercise saved EVTX stop comparisons. A local archive supplies real Windows event records."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import tempfile
import unittest


triage = runpy.run_path(str(Path(__file__).with_name("test-crash-diagnosis.py")))["triage"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_rows(path):
    # Get-WinEvent decodes the original provider properties independently of the product XML parser.
    command = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$rows = @(Get-WinEvent -Path $env:KN_REBOOT_TEST_INPUT -Oldest -MaxEvents 129 | ForEach-Object {
    $xml = ([xml]$_.ToXml()).Event
    $tuple = $null
    if ($_.ProviderName -ceq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 -and $_.Version -in (2..10)) {
        $tuple = @($_.Properties[0..4] | ForEach-Object { [string][uint64]$_.Value })
    }
    [pscustomobject]@{record=[string]$_.RecordId; id=$_.Id; version=$_.Version; tuple=$tuple; time=$xml.System.TimeCreated.SystemTime}
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, timeout=40, env=dict(os.environ, KN_REBOOT_TEST_INPUT=str(path)))
    if result.returncode:
        raise RuntimeError("Windows could not read the supplied test archive")
    rows = json.loads(result.stdout)
    if len(rows) > 128:
        raise ValueError("use a test export with at most 128 records")
    for row in rows:
        if row["tuple"] is not None:
            row["tuple"] = [int(x) for x in row["tuple"]]
    return rows


class RebootComparison(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="kn-reboot-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.dump = self.root / "owned.dmp"
        self.log = self.root / "saved \u0394.evtx"
        self.dump.write_bytes(triage())
        self.log.write_bytes(ARCHIVE_BYTES if ARCHIVE_BYTES else b"owned nonarchive")

    def row(self, kind):
        for row in ROWS:
            values = row["tuple"]
            if (kind == "nonzero" and values and values[0]) or (kind == "zero" and values and not values[0]) or (kind == "other" and values is None):
                return row
        self.skipTest("supplied archive has no " + kind + " control")

    def command(self, record="1", pin=None, before=()):
        return [EXE, "--crash-diagnose", self.dump, "--sha256", sha(self.dump.read_bytes()), *before,
                "--reboot-log", self.log, "--log-sha256", pin or sha(self.log.read_bytes()), "--record-id", str(record)]

    def observe(self, *args, **kwargs):
        c = subprocess.run(self.command(*args, **kwargs), capture_output=True, timeout=25)
        self.assertEqual((c.returncode, c.stderr), (0, b""))
        report = json.loads(c.stdout)
        self.assertEqual(report["schema"], "kn.crash_diagnosis.v3")
        self.assertFalse(report["assessment"]["host_crash_verified"])
        self.assertIsNone(report["assessment"]["attributed_cause"])
        event = report["reboot_event"]
        self.assertEqual(event["schema"], "kn.reboot_event_comparison.v1")
        self.assertFalse(event["source_authenticated"])
        self.assertFalse(event["same_host_boot_verified"])
        hypothesis = next(h for h in report["assessment"]["hypotheses"] if h["candidate"] == "same_recorded_stop_at_restart")
        for link in hypothesis["support"] + hypothesis["contrary"] + hypothesis["missing"]:
            item = report
            for field in link.strip("/").split("/"):
                item = item[field]
        return event, hypothesis, report

    def make_dump(self, values, attributes=0):
        raw = triage(code=values[0], attributes=attributes)
        struct.pack_into("<4Q", raw, 0x40, *values[1:])
        self.dump.write_bytes(raw)

    def test_installed_kernel_power_templates(self):
        command = r"""
$ErrorActionPreference = 'Stop'
$p = Get-WinEvent -ListProvider 'Microsoft-Windows-Kernel-Power'
$rows = @($p.Events | Where-Object Id -eq 41 | ForEach-Object {
    $names = @()
    if ($_.Template) {
        $names = @(([xml]$_.Template).template.data | Where-Object { $_.name -match '^Bugcheck(Code|Parameter[1-4])$' } |
                   ForEach-Object { $_.name + '/' + $_.inType })
    }
    [pscustomobject]@{version=$_.Version; fields=$names}
})
ConvertTo-Json -InputObject $rows -Depth 4 -Compress
"""
        c = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                           capture_output=True, check=True, timeout=30)
        known = [r for r in json.loads(c.stdout) if r["version"] <= 10]
        self.assertTrue(any(row["version"] >= 2 for row in known))
        for row in known:
            expected = ["BugcheckCode/win:UInt32"] if row["version"] else []
            if row["version"] >= 2:
                expected += [f"BugcheckParameter{i}/win:Pointer" for i in range(1, 5)]
            self.assertCountEqual(row["fields"], expected)

    def test_windows_rows_and_each_conflicting_field(self):
        row = self.row("nonzero")
        for candidate in ROWS:
            values = candidate["tuple"]
            if not values or not values[0]:
                continue
            self.make_dump(values)
            event, h, _ = self.observe(candidate["record"])
            self.assertEqual(event["status"], "matching_stop_tuple")
            self.assertIs(event["same_stop_tuple"], True)
            self.assertIs(event["same_stop_code"], True)
            self.assertEqual(event["bugcheck_code_decimal"], values[0])
            self.assertTrue(event["bugcheck"] == {"code": hex(values[0]), "parameters": [hex(n) for n in values[1:]]})
            self.assertEqual(event["event"]["version"], candidate["version"])
            self.assertTrue(event["event"]["system_time_utc"] == candidate["time"])
            self.assertTrue(event["requested_record_id"] == event["event"]["event_record_id"] == candidate["record"])
            self.assertTrue(event["log_sha256"] == sha(ARCHIVE_BYTES) and event["log_bytes"] == len(ARCHIVE_BYTES))
            self.assertTrue(h["support"] and not h["contrary"] and not h["missing"])
        for i in range(5):
            values = row["tuple"].copy()
            values[i] ^= 2 if values[i] == 1 else 1
            self.make_dump(values)
            event, h, _ = self.observe(row["record"])
            self.assertEqual(event["status"], "different_stop_tuple")
            self.assertIs(event["same_stop_tuple"], False)
            self.assertIs(event["same_stop_code"], i != 0)
            self.assertTrue(h["contrary"] and not h["support"] and not h["missing"])
        self.assertTrue(self.log.read_bytes() == ARCHIVE_BYTES)

    def test_zero_event_wrong_provider_and_missing_record(self):
        if not ROWS:
            self.skipTest("no original archive supplied")
        for kind, expected in (("zero", "event_stop_code_unavailable"), ("other", "different_event_source")):
            with self.subTest(kind=kind):
                event, h, _ = self.observe(self.row(kind)["record"])
                self.assertEqual(event["status"], expected)
                self.assertIsNone(event["same_stop_tuple"])
                self.assertTrue(h["missing"] and not h["contrary"])
        present = {int(row["record"]) for row in ROWS}
        unissued = next(i for i in range(1, len(present) + 2) if i not in present)
        event, _, _ = self.observe(unissued)
        self.assertEqual(event["status"], "record_not_found")
        self.assertEqual(event["win32_error"], 259)

    def test_unqualified_dump_and_optional_whea(self):
        row = self.row("nonzero")
        for attrs in (0x10, 0x20, 0x80000000):
            self.make_dump(row["tuple"], attrs)
            event, h, report = self.observe(row["record"], before=("--whea",))
            self.assertEqual(event["status"], "dump_stop_unqualified")
            self.assertIsNone(event["same_stop_tuple"])
            self.assertTrue(event["bugcheck"] and h["missing"])
            self.assertIn("whea_record", report)
        values = row["tuple"].copy()
        values[0] = 0
        self.make_dump(values)
        self.assertEqual(self.observe(row["record"])[0]["status"], "dump_stop_unqualified")
        self.make_dump(row["tuple"])
        before = ("--whea", "--event-xml", self.root / "missing.xml", "--event-sha256", "a" * 64)
        event, _, report = self.observe(row["record"], before=before)
        self.assertIs(event["same_stop_tuple"], True)
        self.assertEqual(report["whea_event"]["status"], "event_source_unavailable")

    def test_pin_archive_signature_and_query_failure(self):
        for data, status in ((b"owned text", "unsupported_event_archive"), (b"ElfFile\0" + bytes(512), "event_query_failed")):
            self.log.write_bytes(data)
            event, _, _ = self.observe()
            self.assertEqual(event["status"], status)
            self.assertIsNone(event["same_stop_tuple"])
            self.assertTrue(event["log_sha256"] == sha(data))
            self.assertEqual(event["win32_error"] is not None, status == "event_query_failed")
        self.assertEqual(self.observe(pin="1" * 64)[0]["status"], "event_digest_mismatch")
        with self.log.open("wb") as output:
            output.truncate((256 << 20) + 1)
        self.assertEqual(self.observe(pin="1" * 64)[0]["status"], "event_source_unavailable")
        self.log.unlink()
        self.assertEqual(self.observe(pin="1" * 64)[0]["status"], "event_source_unavailable")

    def test_writers_junction_and_io_aliases(self):
        import _winapi
        before = self.log.read_bytes()
        with self.log.open("ab"):
            self.assertEqual(self.observe()[0]["status"], "event_source_unavailable")
        for path in (self.log, self.dump):
            alias = self.root / "alias"
            os.link(path, alias)
            original = path.read_bytes()
            for stream, options in (("stdout", self.command()), ("stderr", self.command("0"))):
                with alias.open("ab") as sink:
                    c = subprocess.run(options, **{stream: sink}, timeout=20)
                self.assertEqual(c.returncode, 2)
                self.assertTrue(path.read_bytes() == original)
            alias.unlink()
        parent = self.root / "original"
        parent.mkdir()
        moved = parent / self.log.name
        self.log.rename(moved)
        junction = self.root / "junction"
        _winapi.CreateJunction(str(parent), str(junction))
        try:
            self.log = junction / moved.name
            self.assertEqual(self.observe()[0]["status"], "event_source_unavailable")
        finally:
            junction.rmdir()
        self.assertTrue(moved.read_bytes() == before)

    def test_invalid_record_and_option_order(self):
        base = self.command()
        for cmd in [self.command(record) for record in ("0", "-1", "0x10", "1 or 1", "18446744073709551616", "")] + [
                base[:-1], base + base[-6:], base + ["--whea"], base[:-4] + ["--record-id", "1"], base[:-3] + ["bad", "--record-id", "1"]]:
            c = subprocess.run(cmd, capture_output=True, timeout=10)
            self.assertEqual((c.returncode, c.stdout), (2, b""))
            self.assertIn(b"--reboot-log", c.stderr)

    def test_option_spelling_in_an_operand_is_a_filename(self):
        original = self.dump.read_bytes()
        for name in ("--event-xml", "--reboot-log"):
            (self.root / name).write_bytes(original)
            destination = self.root / "--sha256"
            with destination.open("wb") as output:
                result = subprocess.run([EXE, "--crash-diagnose", name, "--sha256", sha(original)],
                                        cwd=self.root, stdout=output, stderr=subprocess.PIPE, timeout=25)
            self.assertEqual((result.returncode, result.stderr), (0, b""))
            self.assertEqual(json.loads(destination.read_bytes())["schema"], "kn.crash_diagnosis.v1")
            self.assertTrue((self.root / name).read_bytes() == original)
        self.log.replace(self.root / "--event-xml")
        self.log = self.root / "--event-xml"
        args = self.command()
        args[args.index("--reboot-log") + 1] = self.log.name
        destination = self.root / "--log-sha256"
        with destination.open("wb") as output:
            result = subprocess.run(args, cwd=self.root, stdout=output, stderr=subprocess.PIPE, timeout=25)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(json.loads(destination.read_bytes())["schema"], "kn.crash_diagnosis.v3")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--archive", type=Path, help="private, small EVTX with nonzero/zero Event 41 and a different provider")
    args = parser.parse_args()
    EXE = args.exe.resolve()
    ARCHIVE_BYTES, ROWS = None, []
    if args.archive:
        with args.archive.open("rb") as source:
            ARCHIVE_BYTES = source.read((8 << 20) + 1)
        if len(ARCHIVE_BYTES) > 8 << 20:
            parser.error("use a test export up to 8 MiB")
        with tempfile.TemporaryDirectory(prefix="kn-reboot-oracle-") as directory:
            snapshot = Path(directory) / "original.evtx"
            snapshot.write_bytes(ARCHIVE_BYTES)
            ROWS = read_rows(snapshot)
    unittest.main(argv=[__file__])
