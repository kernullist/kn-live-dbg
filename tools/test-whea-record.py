"""Exercise the stop-linked WHEA route on owned AMD64 small dumps, with an optional independent SDK byte comparison."""
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
from uuid import UUID

TRIAGE = runpy.run_path(str(Path(__file__).with_name("test-crash-diagnosis.py")))
MEMORY = UUID("a5bc1114-6f64-4ede-b863-3e83ed7c83b1")
PROCESSOR = UUID("9876ccad-47b4-4bdb-b65e-16f193c4f3db")
PCIE = UUID("d995e954-bbc1-430f-ad91-b44dcb3c6f35")
MCA = UUID("8a1e1d01-42f9-4557-9c33-565e5cc3f7e8")
OPAQUE = UUID(int=123)
SP = TRIAGE["SP"] + 0x600
DELTA = 0x1f0
ADDRESS = SP + DELTA  # sixteen bytes before a page boundary
MCI = 0xb400000012340005


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(sections, severity=1, flags=0):
    """Descriptor order, payload order, padding and unused capacity deliberately differ."""
    table_end = 128 + 72 * len(sections)
    data = bytearray(table_end + 13)
    for i in reversed(range(len(sections))):
        kind, body, section_severity = sections[i]
        desc = 128 + i * 72
        struct.pack_into("<IIHBBI", data, desc, len(data), len(body), 0x300, 0, 0, int(i == 0))
        data[desc + 16:desc + 32] = kind.bytes_le
        struct.pack_into("<I", data, desc + 48, section_severity)
        data.extend(body)
        data.extend(b"\xc5" * 5)
    struct.pack_into("<4sHIHIII", data, 0, b"CPER", 0x210, 0xffffffff, len(sections), severity, 0, len(data))
    struct.pack_into("<QQI", data, 88, 0, 12345, flags)
    return data


def small_dump(payload, *, code=0x124, attrs=0, source=5, address=ADDRESS, halves=(0, 0), captured=None):
    b = TRIAGE["triage"](code, attrs)
    start = 0x8000
    content = payload if captured is None else payload[:captured]
    if start + DELTA + len(content) + 4 > len(b):
        b.extend(bytes(start + DELTA + len(content) + 4 - len(b)))
        struct.pack_into("<II", b, 0x2004, len(b), len(b) - 4)
        struct.pack_into("<Q", b, 0xfa0, len(b))
        b[-4:] = b"TRGD"
    struct.pack_into("<4Q", b, 0x40, source, address, *halves)
    struct.pack_into("<Q", b, 0x348 + 0x98, SP)
    struct.pack_into("<Q", b, 0x2048, SP)
    struct.pack_into("<II", b, 0x2028, start, DELTA + len(content))
    b[start:start + 16] = b[0x5000:0x5010]
    b[start + DELTA:start + DELTA + len(content)] = content
    return b


def sample():
    memory = bytearray(73)
    struct.pack_into("<Q", memory, 0, (1 << 14) | 2)
    struct.pack_into("<QQ", memory, 16, 0x12340, 0xfeed)
    memory[72] = 3
    proc = bytearray(192)
    struct.pack_into("<Q", proc, 0, (1 << 8) | 4)
    proc[10] = 4
    struct.pack_into("<Q", proc, 152, 0x62)
    pci = bytearray(208)
    struct.pack_into("<QI", pci, 0, 9, 4)
    struct.pack_into("<HHII", pci, 24, 0xfffe, 0xabcd, 2 << 24, (6 << 24) | (11 << 8) | 3)
    # Looks like an address. An opaque payload must never add a debugger read.
    opaque = struct.pack("<Q", ADDRESS + 0x4000)
    return [(MEMORY, memory, 1), (PROCESSOR, proc, 2), (PCIE, pci, 0), (OPAQUE, opaque, 3)]


def mca(version=2, status=MCI, extra=()):
    data = bytearray({2: 272, 3: 292, 4: 1192}.get(version, 8))
    struct.pack_into("<II", data, 0, version, 2)
    if version not in (2, 3, 4):
        return data
    struct.pack_into("<I", data, 16, 8)
    struct.pack_into("<IQQQ", data, 36, 4, status, 0x1234, 0x4321)
    if version == 4:
        struct.pack_into("<I", data, 292, len(extra))
        for i, value in enumerate(extra):
            struct.pack_into("<I", data, 296 + 4 * i, i + 5)
            struct.pack_into("<Q", data, 424 + 8 * i, value)
    return data


class Whea(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="kn-whea-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "saved kernel \u0394.dmp"

    def invoke(self, binary, pin=None, exit_code=0):
        self.path.write_bytes(binary)
        c = subprocess.run([EXE, "--crash-diagnose", str(self.path), "--sha256", pin or sha(binary), "--whea"],
                           capture_output=True, timeout=30)
        self.assertEqual(c.returncode, exit_code, c.stdout[:220])
        self.assertEqual(c.stderr, b"")
        doc = json.loads(c.stdout)
        self.assertEqual(doc["schema"], "kn.crash_diagnosis.v2")
        return doc

    def observed(self, payload, **kwargs):
        b = small_dump(payload, **kwargs)
        doc = self.invoke(b)
        self.assertEqual(doc["dump_sha256"], sha(b))
        self.assertEqual(doc["header"]["bugcheck"], doc["dbgeng"]["bugcheck"])
        self.assertFalse(doc["source_authenticated"])
        self.assertIsNone(doc["assessment"]["attributed_cause"])
        r = doc["whea_record"]
        used = 0
        for call in r["reads"]:
            self.assertEqual(call["offset"], used)
            self.assertLessEqual(call["requested"], 4096 - ((kwargs.get("address", ADDRESS) + used) % 4096))
            if call["hr"] == "0x0":
                self.assertLessEqual(call["returned"], call["requested"])
                used += call["returned"]
        self.assertEqual(r["captured_bytes"], used)
        self.assertEqual(r["captured_sha256"], sha(payload[:used]) if used else None)
        h = next(x for x in doc["assessment"]["hypotheses"] if x["candidate"] == "fatal_error_reported_at_stop")
        for pointer in h["support"] + h["contrary"] + h["missing"]:
            at = doc
            for key in pointer[1:].split("/"):
                at = at[int(key)] if isinstance(at, list) else at[key]
            self.assertIsNotNone(at)
        if r["status"] != "linked":
            self.assertIsNone(r["sections"])
            self.assertEqual(h["state"], "unresolved")
        return r, h

    def test_linked_source_and_valid_fields(self):
        sections = sample()
        raw = record(sections)
        r, h = self.observed(raw)
        self.assertEqual(r["status"], "linked")
        self.assertEqual(r["captured_bytes"], len(raw))
        self.assertEqual(r["reads"][0]["requested"], 16)
        self.assertEqual(h["state"], "supported_by_record")
        self.assertEqual(r["qualifiers"], [])
        self.assertEqual(r["header"]["record_id"], hex(12345))
        self.assertIsNone(r["header"]["platform"])
        self.assertIsNone(r["header"]["timestamp_raw"])
        for i, (s, (kind, body, sev)) in enumerate(zip(r["sections"], sections, strict=True)):
            self.assertEqual(UUID(s["type_guid"]), kind)
            self.assertEqual(s["severity"], sev)
            self.assertEqual(s["offset"], struct.unpack_from("<I", raw, 128 + i * 72)[0])
            self.assertEqual(s["sha256"], sha(body))
            self.assertEqual(s["length"], len(body))
        mem, cpu, pci, opaque = r["sections"]
        self.assertEqual(mem["fields"]["physical_address"], "0x12340")
        self.assertEqual(mem["fields"]["error_type"], 3)
        self.assertIsNone(mem["fields"]["physical_address_mask"])
        self.assertEqual(cpu["fields"]["processor_id"], "0x62")
        self.assertEqual(cpu["fields"]["error_type"], 4)
        self.assertIsNone(cpu["fields"]["instruction_pointer"])
        self.assertEqual(pci["fields"]["device"], dict(vendor="0xfffe", device_id="0xabcd", segment=11,
                                                        primary_bus=6, device=3, function=2))
        self.assertEqual(opaque["decode"], "opaque")
        self.assertIsNone(opaque["fields"])
        self.assertEqual(self.observed(raw), (r, h))

    def test_bad_headers_and_descriptors(self):
        entries = [(OPAQUE, bytes(8), 1), (MEMORY, bytes(80), 2)]
        for offset, fmt, value, status in (
                (0, "I", 0, "invalid_signature"), (6, "I", 0, "invalid_signature"),
                (4, "H", 0x0310, "unsupported_header_revision"), (10, "H", 0, "invalid_header_extent"),
                (20, "I", 127, "invalid_header_extent"), (20, "I", 1 + 2**20, "record_budget_exceeded"),
                (136, "H", 0x400, "unsupported_descriptor_revision"), (128, "I", 16, "invalid_section_extent"),
                (132, "I", 0, "invalid_section_extent"), (128, "I", 0xffffffff, "invalid_section_extent"),
                (132, "I", 0xffffffff, "invalid_section_extent")):
            with self.subTest(offset=offset, value=value):
                data = record(entries)
                struct.pack_into("<" + fmt, data, offset, value)
                self.assertEqual(self.observed(data)[0]["status"], status)
        data = record(entries)
        struct.pack_into("<I", data, 128, struct.unpack_from("<I", data, 200)[0] + 3)
        self.assertEqual(self.observed(data)[0]["status"], "overlapping_sections")
        for count, expected in [(128, "linked"), (129, "record_budget_exceeded")]:
            data = record([(OPAQUE, b"x", 1)] * count)
            self.assertEqual(self.observed(data)[0]["status"], expected)

    def test_record_length_at_budget(self):
        extra = 2**20 - len(record([(OPAQUE, b"x", 1)]))
        raw = record([(OPAQUE, bytes(extra + 1), 1)])
        r, _ = self.observed(raw)
        self.assertEqual(r["status"], "linked")
        self.assertEqual(r["captured_bytes"], 2**20)
        self.assertLessEqual(len(r["reads"]), 512)

    def test_missing_capture_and_partial_header_or_body(self):
        data = record(sample())
        for available in (0, 9, 16, 83, 128, len(data) - 13):
            with self.subTest(available=available):
                r, _ = self.observed(data, captured=available)
                self.assertEqual(r["status"], "incomplete_read")
                self.assertEqual(r["captured_bytes"], available)
                self.assertIs(r["header"] is None, available < 128)

    def test_only_qualified_stored_stop_can_read(self):
        data = record(sample())
        for kwargs, status in [({"code": 0x9f}, "different_stop_code"),
                               ({"attrs": 0x10}, "unqualified_dump_attributes"),
                               ({"attrs": 0x20}, "unqualified_dump_attributes"),
                               ({"attrs": 0x80000000}, "unqualified_dump_attributes"),
                               ({"source": 9}, "unsupported_amd64_error_source"),
                               ({"source": 0x11}, "unsupported_amd64_error_source"),
                               ({"source": 0x100}, "unsupported_amd64_error_source"),
                               ({"address": 0}, "invalid_record_address"), ({"address": 0x1000}, "invalid_record_address"),
                               ({"address": 2**64 - 4}, "address_overflow")]:
            with self.subTest(kwargs=kwargs):
                r, _ = self.observed(data, **kwargs)
                self.assertEqual((r["status"], r["reads"]), (status, []))
        invalid = self.invoke(small_dump(data), pin="0" * 64, exit_code=1)
        self.assertEqual(invalid, {"schema": "kn.crash_diagnosis.v2", "status": "digest_mismatch", "attributed_cause": None})

    def test_unavailable_stop_and_output_protection(self):
        raw = small_dump(record(sample()))
        header_only = bytearray(raw)
        struct.pack_into("<I", header_only, 0xf98, 1)
        doc = self.invoke(header_only, exit_code=1)
        self.assertEqual(doc["whea_record"]["status"], "stop_tuple_unavailable")
        self.assertEqual(doc["whea_record"]["reads"], [])
        physical = raw[:8192] + bytes(4096)
        struct.pack_into("<Q", physical, 0x10, 4096)
        struct.pack_into("<I4xQQQ", physical, 0x88, 1, 1, 1, 1)
        struct.pack_into("<I", physical, 0xf98, 1)
        struct.pack_into("<Q", physical, 0xfa0, len(physical))
        doc = self.invoke(physical)
        self.assertEqual(doc["whea_record"]["status"], "initial_stop_unavailable")
        self.assertEqual(doc["whea_record"]["reads"], [])
        self.path.write_bytes(raw)
        alias = self.root / "same input.bin"
        os.link(self.path, alias)
        for pin, stream in [(sha(raw), "stdout"), ("x", "stderr")]:
            with alias.open("ab") as sink:
                result = subprocess.run([EXE, "--crash-diagnose", str(self.path), "--sha256", pin, "--whea"],
                                        **{stream: sink}, timeout=15)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(self.path.read_bytes(), raw)
        for extra in (["--whea", "--whea"], ["--whea", "0x1000"], ["--other"]):
            c = subprocess.run([EXE, "--crash-diagnose", str(self.path), "--sha256", sha(raw), *extra],
                               capture_output=True, timeout=15)
            self.assertEqual(c.returncode, 2)
            self.assertEqual(c.stdout, b"")
            self.assertIn(b"usage", c.stderr)

    def test_qualifying_flags_and_alternative_severity(self):
        for flag, src, why in [(1, 5, "recovery"), (2, 5, "previous_error"), (4, 5, "simulated"),
                               (8, 5, "device_driver_source"), (0, 16, "device_driver_source"),
                               (0x40, 5, "sections_truncated"), (1 << 31, 5, "unrecognized_flags"),
                               (0, 2, "corrected_stop_source"), (0, 7, "boot_error_source")]:
            r, h = self.observed(record(sample(), flags=flag), source=src)
            self.assertIn(why, r["qualifiers"])
            self.assertEqual(h["state"], "qualified_record")
        for hs, ss, expected in [(1, 2, "qualified_record"), (2, 1, "qualified_record"),
                                 (4, 2, "qualified_record"), (1, 99, "qualified_record"),
                                 (2, 0, "qualified_record"), (3, 2, "qualified_record"),
                                 (2, 2, "different_record_severity"), (0, 0, "different_record_severity")]:
            r, h = self.observed(record([(OPAQUE, b"x", ss)], severity=hs))
            self.assertEqual(h["state"], expected)
            self.assertFalse(h["support"])
            self.assertTrue(h["contrary"] or h["missing"])
        for kind, body in [(MEMORY, bytes(72)), (MEMORY, struct.pack("<Q", 1 << 16) + bytes(65)),
                           (PCIE, bytes(207)), (PROCESSOR, bytes(191))]:
            r, h = self.observed(record([(kind, body, 1)]))
            self.assertFalse(h["contrary"])
            self.assertTrue(h["missing"])
            self.assertEqual(r["sections"][0]["decode"], "body_too_short")
            self.assertEqual(h["state"], "qualified_record")

    def test_machine_check_status_across_banks(self):
        halves = (MCI >> 32, MCI & 0xffffffff)
        for version in (2, 3, 4):
            body = mca(version, extra=(MCI ^ 1,) if version == 4 else ())
            r, h = self.observed(record([(MCA, body, 1)]), source=0, halves=halves)
            self.assertEqual(r["stop_mci_status"], hex(MCI))
            f = r["sections"][0]["fields"]
            self.assertEqual((f["version"], f["processor_number"]), (version, 8))
            bank = f["banks"][0]
            self.assertTrue(bank["matches_stop_status"])
            self.assertTrue(bank["uncorrected"])
            self.assertEqual((bank["mca_error_code"], bank["model_error_code"]), ("0x5", "0x1234"))
            self.assertEqual(bank["address"], "0x1234")
            self.assertIsNone(bank["misc"])
            self.assertEqual(h["state"], "supported_by_record")
        body = mca(4, MCI ^ 1, (MCI,))
        r, _ = self.observed(record([(MCA, body, 1)]), source=0, halves=halves)
        self.assertEqual([s["matches_stop_status"] for s in r["sections"][0]["fields"]["banks"]], [False, True])
        r, h = self.observed(record([(MCA, mca(2, MCI ^ 2), 1)]), source=0, halves=halves)
        self.assertIn("recorded_mca_statuses_differ", r["qualifiers"])
        self.assertEqual(h["state"], "qualified_record")
        r, _ = self.observed(record([(MCA, mca(2, 0), 1)]), source=0, halves=halves)
        self.assertIn("valid_mca_bank_unavailable", r["qualifiers"])
        self.assertIsNone(r["sections"][0]["fields"]["banks"][0]["matches_stop_status"])
        r, _ = self.observed(record([(MCA, mca(), 1)]), source=0, halves=(1 << 32, 5))
        self.assertIn("non_dword_stop_status_parts", r["qualifiers"])
        self.assertIsNone(r["stop_mci_status"])
        self.assertIsNone(self.observed(record([(MCA, mca(), 1)]))[0]["sections"][0]["fields"]["banks"][0]["matches_stop_status"])
        recovered = MCI & ~(1 << 61)
        r, h = self.observed(record([(MCA, mca(2, recovered), 1)]), source=0, halves=(recovered >> 32, recovered & 0xffffffff))
        self.assertIn("matching_bank_uncorrected_bit_clear", r["qualifiers"])
        self.assertEqual(h["state"], "qualified_record")
        self.assertTrue(h["contrary"])
        counts = mca(4)
        struct.pack_into("<I", counts, 292, 33)
        for body, decode in [(mca(99), "unsupported_mca_version"), (mca(4)[:-1], "body_too_short"), (counts, "invalid_mca_counts")]:
            r, h = self.observed(record([(MCA, body, 1)]), source=0, halves=halves)
            self.assertEqual(r["sections"][0]["decode"], decode)
            self.assertIsNone(r["sections"][0]["fields"])
            self.assertEqual(h["state"], "qualified_record")

    def test_sdk_debugger_recovers_original_bytes(self):
        if not KD:
            self.skipTest("Windows SDK kd.exe not supplied")
        data = record(sample() + [(MCA, mca(4, extra=(MCI ^ 1,)), 1)])
        r, _ = self.observed(data)
        symbols = self.root / "empty"
        symbols.mkdir()
        env = dict(os.environ, _NT_SYMBOL_PATH=str(symbols), _NT_EXECUTABLE_IMAGE_PATH=str(symbols))
        cmd = f".bugcheck;.writemem cper-bytes.bin {ADDRESS:x} L{len(data):x};q"
        c = subprocess.run([KD, "-sins", "-noshell", "-y", str(symbols), "-i", str(symbols), "-z", str(self.path),
                            "-c", cmd], cwd=self.root, env=env, capture_output=True, timeout=30)
        self.assertEqual(c.returncode, 0)
        self.assertIn("Bugcheck code 00000124", c.stdout.decode(errors="replace"))
        original = (self.root / "cper-bytes.bin").read_bytes()
        self.assertEqual(original, data)
        self.assertEqual(sha(original), r["captured_sha256"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--kd", type=Path)
    args = parser.parse_args()
    EXE = str(args.exe.resolve())
    KD = str(args.kd.resolve()) if args.kd else None
    unittest.main(argv=["test-whea-record"], verbosity=2)
