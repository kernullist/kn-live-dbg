"""Compare an owned saved dump with separate Windows Event XML inputs through the native CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

W = runpy.run_path(str(Path(__file__).with_name("test-whea-record.py")))
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NAME = "Microsoft-Windows-WHEA-Logger"
GUID = "{c26c4f3c-3f66-4e99-8f8a-39405cfed220}"
STAMP = "2026-02-25T03:24:16.1234567Z"
ET.register_namespace("", NS)


def tag(name):
    return "{" + NS + "}" + name


def event(raw, *, name=NAME, guid=GUID, event_id=18, version=0, channel="System", length=None, stamp=STAMP):
    root = ET.Element(tag("Event"))
    system = ET.SubElement(root, tag("System"))
    ET.SubElement(system, tag("Provider"), Name=name, Guid=guid)
    ET.SubElement(system, tag("EventID")).text = str(event_id)
    ET.SubElement(system, tag("Version")).text = str(version)
    ET.SubElement(system, tag("TimeCreated"), SystemTime=stamp)
    ET.SubElement(system, tag("EventRecordID")).text = str(2**63 + 15)
    ET.SubElement(system, tag("Channel")).text = channel
    ET.SubElement(system, tag("Computer")).text = "Owned-Fixture"
    body = ET.SubElement(root, tag("EventData"))
    ET.SubElement(body, tag("Data"), Name="Length").text = str(len(raw) if length is None else length)
    ET.SubElement(body, tag("Data"), Name="RawData").text = raw.hex().upper()
    return root


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Comparison(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="kn-whevt-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.dump = self.root / "kernel \u0394.dmp"
        self.xml = self.root / "event \u0394.xml"
        self.raw = W["record"](W["sample"]())
        self.binary = W["small_dump"](self.raw)
        self.dump.write_bytes(self.binary)

    def args(self, pin=None):
        return [EXE, "--crash-diagnose", self.dump, "--sha256", sha(self.dump.read_bytes()), "--whea",
                "--event-xml", self.xml, "--event-sha256", pin or sha(self.xml.read_bytes())]

    def observe(self, value, pin=None):
        data = value if isinstance(value, bytes) else ET.tostring(value, encoding="utf-8", xml_declaration=True)
        self.xml.write_bytes(data)
        c = subprocess.run(self.args(pin), capture_output=True, timeout=30)
        self.assertEqual(c.returncode, 0, c.stderr[:200])
        self.assertEqual(c.stderr, b"")
        d = json.loads(c.stdout)
        r = d["whea_event"]
        self.assertEqual((d["schema"], r["schema"]), ("kn.crash_diagnosis.v2", "kn.whea_event_comparison.v1"))
        self.assertIsNone(d["assessment"]["attributed_cause"])
        self.assertFalse(d["assessment"]["host_crash_verified"])
        self.assertFalse(r["source_authenticated"])
        h = next(h for h in d["assessment"]["hypotheses"] if h["candidate"] == "same_whea_record_bytes_in_event_export")
        same = r["same_payload_bytes"]
        self.assertEqual(h["state"], "unresolved" if same is None else "supported_by_payloads" if same else "different_payloads")
        self.assertEqual((bool(h["support"]), bool(h["contrary"]), bool(h["missing"])), (same is True, same is False, same is None))
        self.assertEqual("/whea_record/status" in h["missing"], d["whea_record"]["status"] != "linked")
        self.assertEqual("/whea_event/status" in h["missing"], r["payload_sha256"] is None)
        for pointer in h["support"] + h["contrary"] + h["missing"]:
            value = d
            for part in pointer[1:].split("/"):
                value = value[part]
            self.assertIsNotNone(value)
        if r["xml_sha256"]:
            self.assertEqual((r["xml_sha256"], r["xml_bytes"]), (sha(data), len(data)))
        return r, c.stdout

    def test_complete_artifacts_and_template_versions(self):
        root = event(self.raw)
        r, first = self.observe(root)
        self.assertEqual(self.observe(root)[1], first)
        self.assertEqual(r["status"], "matching_payload_bytes")
        self.assertEqual((r["payload_sha256"], r["dump_record_sha256"], r["payload_bytes"]),
                         (sha(self.raw), sha(self.raw), len(self.raw)))
        self.assertEqual(r["event"], {"provider": NAME, "channel": "System", "event_id": 18, "version": 0,
                                      "event_record_id": str(2**63 + 15), "system_time_utc": STAMP})
        self.assertNotIn(b"Owned-Fixture", first)
        for i in (1, 2, 3, 16, 29, 40, 47):
            self.assertEqual(self.observe(event(self.raw, event_id=i))[0]["status"], "matching_payload_bytes")
        for i, v in ((0, 0), (15, 0), (30, 0), (48, 0), (18, 1)):
            self.assertEqual(self.observe(event(self.raw, event_id=i, version=v))[0]["status"], "unsupported_event_template")

    def test_disagreement_missing_and_pins(self):
        changed = bytearray(self.raw)
        changed[-1] ^= 1  # only padding differs
        r, _ = self.observe(event(changed))
        self.assertEqual((r["status"], r["payload_sha256"]), ("different_payload_bytes", sha(changed)))
        self.assertEqual(r["dump_record_sha256"], sha(self.raw))
        self.dump.write_bytes(W["small_dump"](self.raw, captured=80))
        r, _ = self.observe(event(self.raw))
        self.assertEqual(r["status"], "dump_record_unavailable")
        self.assertEqual(r["payload_sha256"], sha(self.raw))
        self.assertIsNone(r["dump_record_sha256"])
        r, _ = self.observe(event(self.raw), pin="0" * 64)
        self.assertEqual(r["status"], "event_digest_mismatch")
        self.assertIsNone(r["event"])
        self.xml.unlink()
        c = subprocess.run(self.args("a" * 64), capture_output=True, timeout=30, check=True)
        self.assertEqual(json.loads(c.stdout)["whea_event"]["status"], "event_source_unavailable")

    def test_identity_namespace_and_duplicates(self):
        for kwargs in ({"name": "Another-Provider"}, {"guid": "{00000000-0000-0000-0000-000000000001}"},
                       {"channel": "Application"}):
            self.assertEqual(self.observe(event(self.raw, **kwargs))[0]["status"], "different_event_source")
        for stamp in ("2025-02-29T03:24:16Z", "2026-02-25T99:24:16Z", "malformed"):
            self.assertEqual(self.observe(event(self.raw, stamp=stamp))[0]["status"], "event_metadata_incomplete")
        for which in ("System", "EventData", "Provider", "TimeCreated", "EventID", "EventRecordID", "RawData", "Length"):
            root = event(self.raw)
            system, data = list(root)
            if which in ("System", "EventData"):
                root.append(root.find(tag(which)))
            elif which in ("RawData", "Length"):
                data.append(next(e for e in data if e.get("Name") == which))
            else:
                system.append(system.find(tag(which)))
            self.assertEqual(self.observe(root)[0]["status"], "ambiguous_event_fields", which)
        root = event(self.raw)
        nested = root.find(tag("EventData"))
        other = ET.SubElement(nested, tag("Other"))
        other.append(nested[1])
        nested.remove(nested[1])
        self.assertEqual(self.observe(root)[0]["status"], "event_payload_missing")
        root = event(self.raw)
        raw = root.find(tag("EventData"))[1]
        raw.tag = "{urn:unrelated}Data"
        self.assertEqual(self.observe(root)[0]["status"], "event_payload_missing")
        self.assertEqual(self.observe(b"<Event/>")[0]["status"], "unsupported_event_document")
        root = event(self.raw)
        ET.SubElement(root, tag("UserData"))
        self.assertEqual(self.observe(root)[0]["status"], "ambiguous_event_fields")
        root = event(self.raw)
        system = root[0]
        root.remove(system)
        root.append(system)
        self.assertEqual(self.observe(root)[0]["status"], "unsupported_event_document")

    def test_payload_and_document_limits(self):
        root = event(self.raw)
        raw = root.find(tag("EventData"))[1]
        for value in ("4z", "4"):
            raw.text = value
            self.assertEqual(self.observe(root)[0]["status"], "invalid_payload_hex")
        raw.text = self.raw.hex()
        ET.SubElement(raw, tag("Injected")).text = "00"
        self.assertEqual(self.observe(root)[0]["status"], "nested_event_value")
        for length in (0, len(self.raw) - 1, "x", 2**64):
            r, _ = self.observe(event(self.raw, length=length))
            self.assertEqual(r["status"], "event_length_mismatch")
            self.assertEqual(r["payload_bytes"], len(self.raw))
            self.assertEqual(r["declared_payload_bytes"], length if isinstance(length, int) and length <= 0xffffffff else None)
            self.assertIsNone(r["payload_sha256"])
        self.assertEqual(self.observe(event(bytes(2**20 + 1)))[0]["status"], "event_payload_limit")
        for data in (b"<", ET.tostring(event(self.raw)) + b"<extra/>",
                     b'<!DOCTYPE Event [<!ENTITY e "text">]>' + ET.tostring(event(self.raw))):
            self.assertEqual(self.observe(data)[0]["status"], "malformed_event_xml")
        root = event(self.raw)
        extra = ET.SubElement(root, tag("RenderingInfo"))
        for _ in range(4097):
            ET.SubElement(extra, tag("Unused"))
        self.assertEqual(self.observe(root)[0]["status"], "event_node_limit")
        root = event(self.raw)
        child = root
        for _ in range(40):
            child = ET.SubElement(child, tag("Unused"))
        self.assertEqual(self.observe(root)[0]["status"], "malformed_event_xml")
        self.assertEqual(self.observe(b" " * (8 * 2**20 + 1))[0]["status"], "event_source_unavailable")

    def test_maximum_cper_in_a_utf16_export(self):
        extra = 2**20 - len(W["record"]([(W["OPAQUE"], b"x", 1)]))
        raw = W["record"]([(W["OPAQUE"], bytes(extra + 1), 1)])
        self.dump.write_bytes(W["small_dump"](raw))
        xml = ET.tostring(event(raw), encoding="utf-16")
        r, _ = self.observe(xml)
        self.assertEqual(r["status"], "matching_payload_bytes")
        self.assertEqual((r["declared_payload_bytes"], r["payload_bytes"], r["payload_sha256"]), (2**20, 2**20, sha(raw)))

    def test_encodings_prefixes_and_split_values(self):
        root = event(self.raw, guid=GUID.upper())
        canonical = ET.tostring(root, encoding="unicode")
        encoded = self.raw.hex().upper()
        split = canonical.replace(encoded, encoded[:7] + "<![CDATA[" + encoded[7:25] + "]]>\n " + encoded[25:])
        for enc in ("utf-8-sig", "utf-16", "utf-16-be"):
            data = split.encode(enc)
            if enc == "utf-16-be":
                data = b"\xfe\xff" + data
            r, _ = self.observe(data)
            self.assertEqual((r["status"], r["payload_sha256"]), ("matching_payload_bytes", sha(self.raw)))
        ET.register_namespace("ev", NS)
        try:
            self.assertEqual(self.observe(root)[0]["status"], "matching_payload_bytes")
        finally:
            ET.register_namespace("", NS)

    def test_external_entity_and_wrong_source_payload(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.setblocking(False)
            url = "http://127.0.0.1:" + str(listener.getsockname()[1]) + "/event.dtd"
            data = ('<!DOCTYPE Event SYSTEM "' + url + '">').encode() + ET.tostring(event(self.raw))
            self.assertEqual(self.observe(data)[0]["status"], "malformed_event_xml")
            with self.assertRaises(BlockingIOError):
                listener.accept()
        root = event(self.raw, name="Other")
        root.find(tag("EventData"))[1].text = "not-hex"
        self.assertEqual(self.observe(root)[0]["status"], "different_event_source")

    def test_aliases_and_cli_shape(self):
        self.xml.write_bytes(ET.tostring(event(self.raw)))
        args = self.args()
        for p in (self.dump, self.xml):
            alias = self.root / ("same-" + p.name)
            os.link(p, alias)
            original = p.read_bytes()
            for stream, arguments in (("stdout", args), ("stderr", args[:-1] + ["bad"])):
                with alias.open("ab") as sink:
                    ret = subprocess.run(arguments, **{stream: sink}, timeout=30)
                self.assertEqual(ret.returncode, 2)
                self.assertEqual(p.read_bytes(), original)
        for cmd in (args[:-1], args + ["extra"], args[:5] + args[6:]):
            c = subprocess.run(cmd, capture_output=True, timeout=15)
            self.assertEqual(c.returncode, 2)
            self.assertIn(b"usage", c.stderr)

    def test_event_writer_junction_and_separate_output(self):
        import _winapi
        self.xml.write_bytes(ET.tostring(event(self.raw)))
        with self.xml.open("ab"):
            c = subprocess.run(self.args(), capture_output=True, check=True, timeout=30)
            self.assertEqual(json.loads(c.stdout)["whea_event"]["status"], "event_source_unavailable")
        owned = self.root / "owned"
        owned.mkdir()
        target = owned / "event.xml"
        self.xml.rename(target)
        junction = self.root / "alias"
        _winapi.CreateJunction(str(owned), str(junction))
        try:
            self.xml = junction / "event.xml"
            c = subprocess.run(self.args(), capture_output=True, check=True, timeout=30)
            self.assertEqual(json.loads(c.stdout)["whea_event"]["status"], "event_source_unavailable")
        finally:
            junction.rmdir()
        self.xml = self.root / "missing.xml"
        output = self.root / "output.txt"
        with output.open("wb") as sink:
            result = subprocess.run(self.args("0" * 64), stdout=sink, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(output.read_bytes())["whea_event"]["status"], "event_source_unavailable")

    def test_installed_provider_and_native_event_export(self):
        if not POWERSHELL:
            self.skipTest("Windows PowerShell not supplied")
        command = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$p=Get-WinEvent -ListProvider 'Microsoft-Windows-WHEA-Logger'
$ids=@($p.Events | Where-Object { $_.Version -eq 0 -and $_.Template -match 'name="RawData" inType="win:Binary"' -and $_.Template -match 'name="Length" inType="win:UInt32"' } | ForEach-Object Id)
$e=Get-WinEvent -LogName System -MaxEvents 128 | Where-Object { $_.ProviderId -and $_.ProviderName -ne $p.Name } | Select-Object -First 1
if(-not $e) { throw 'No unrelated System event available' }
[Console]::Write((@{guid=$p.Id.ToString('B');ids=$ids;xml=$e.ToXml()} | ConvertTo-Json -Compress))
"""
        p = subprocess.run([POWERSHELL, "-NoProfile", "-Command", command], capture_output=True, timeout=30, check=True)
        native = json.loads(p.stdout)
        self.assertEqual(native["guid"].lower(), GUID)
        self.assertTrue(set([1, 2, 3, *range(16, 30), *range(40, 48)]) <= set(native["ids"]))
        r, _ = self.observe(native["xml"].encode("utf-8"))
        self.assertEqual(r["status"], "different_event_source")
        self.assertIsNone(r["payload_sha256"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--powershell", help="Windows PowerShell for provider metadata and a real System event")
    args = parser.parse_args()
    EXE = str(args.exe.resolve())
    POWERSHELL = args.powershell
    unittest.main(argv=["test-whea-event"], verbosity=2)
