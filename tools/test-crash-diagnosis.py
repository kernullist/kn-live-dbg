"""Compare the offline crash route with owned dump bytes and, optionally, the Windows SDK debugger."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import tempfile
import unittest

IP = 0xfffff80000004200
SP = 0xffff800000010800
KERNEL = 0xfffff80000100000
DRIVER = IP - 0x200
PARAMETERS = (4, 0xffff8000a1b2c3d4, 0x8123456789abcdef, 0xfedcba9876543210)


def triage(code=0x124, attributes=0, ret=None, frames=2):
    """Two named module ranges and a bounded saved stack, without any executable images."""
    b = bytearray(0x20000)

    def put(offset, fmt, *values):
        struct.pack_into("<" + fmt, b, offset, *values)

    b[:8] = b"PAGEDU64"
    put(8, "II", 15, 26100)
    put(0x30, "III", 0x8664, 1, code)
    put(0x40, "4Q", *PARAMETERS)
    put(0xf98, "I", 4)
    put(0xfa0, "Q", len(b))
    put(0x1050, "I", attributes)
    put(0x348 + 0x30, "I", 0x100003)
    put(0x348 + 0x98, "Q", SP)
    put(0x348 + 0xf8, "Q", IP)
    put(0x348 + 0x38, "H", 0x10)
    put(0x348 + 0x42, "H", 0x18)
    put(0x348 + 0x44, "I", 0x202)
    put(0x2000, "18I", 0, len(b), len(b) - 4, 0x348, 0xf00, 0, 0, 0x2400, 0x3400,
        0x4000, 0x5000, 0x800, 0x6000, 2, 0x7000, 256, 0, 0xffffffff)
    put(0x2000 + 72, "Q", SP)
    for i, (base, name) in enumerate(((KERNEL, "ntoskrnl.exe"), (DRIVER, "FixtureProvider.sys"))):
        entry, name_at = 0x6000 + i * 0x90, 0x7000 + i * 96
        encoded = name.encode("utf-16-le")
        put(name_at, "I", len(name))
        b[name_at + 4:name_at + 4 + len(encoded)] = encoded
        put(entry, "I", name_at)
        put(entry + 8 + 0x30, "QQI", base, base + 0x200, 0x4000)
    for i in range(frames - 1):
        put(0x5000 + i * 8, "Q", ret if ret is not None else KERNEL + 0x1200 + i * 16)
    b[-4:] = b"TRGD"
    return b


class Diagnosis(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kn-crash-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "owned kernel \u0394.dmp"
        self.path.write_bytes(triage())

    def invoke(self, path=None, pin=None, expected=0, env=None):
        path = self.path if path is None else path
        pin = hashlib.sha256(path.read_bytes()).hexdigest() if pin is None else pin
        c = subprocess.run([EXE, "--crash-diagnose", str(path), "--sha256", pin],
                           capture_output=True, env=env, timeout=25)
        self.assertEqual(c.returncode, expected, c.stdout[:180])
        self.assertEqual(c.stderr, b"")
        doc = json.loads(c.stdout)
        self.assertEqual(doc["schema"], "kn.crash_diagnosis.v1")
        if "dump_sha256" in doc:
            self.assertEqual(doc["dump_sha256"], pin.lower())
            self.assertEqual(doc["bytes"], path.stat().st_size)
            self.assertFalse(doc["source_authenticated"])
            self.assertFalse(doc["assessment"]["host_crash_verified"])
            self.assertIsNone(doc["assessment"]["attributed_cause"])
            self.assertEqual(doc["assessment"]["unwind_quality"], "unverified")
            for h in doc["assessment"]["hypotheses"]:
                self.assertTrue(h["next"])
                for pointer in h["support"] + h["contrary"]:
                    at = doc
                    for field in pointer[1:].split("/"):
                        at = at[int(field)] if isinstance(at, list) else at[field]
                    self.assertIsNotNone(at)
        return doc, c.stdout

    def test_windows_triage_and_replay(self):
        doc, original = self.invoke()
        self.assertEqual(self.invoke(pin=doc["dump_sha256"].upper())[1], original)
        self.assertEqual(doc["status"], "matched_stop_data")
        expected = {"code": "0x124", "parameters": [hex(i) for i in PARAMETERS]}
        self.assertEqual(doc["header"]["bugcheck"], expected)
        self.assertEqual(doc["dbgeng"]["bugcheck"], expected)
        self.assertTrue(doc["dbgeng"]["initial_stop"])
        self.assertTrue(doc["assessment"]["header_context_matches_stack_top"])
        frames = doc["dbgeng"]["frames"]
        self.assertEqual([(f["ip"], f["sp"]) for f in frames],
                         [(hex(IP), hex(SP)), (hex(KERNEL + 0x1200), hex(SP + 8))])
        self.assertEqual([f["module"]["range"]["base"] for f in frames], [hex(DRIVER), hex(KERNEL)])
        self.assertEqual(frames[0]["module"]["range"]["name"], "FixtureProvider")
        self.assertEqual([h["state"] for h in doc["assessment"]["hypotheses"]],
                         ["supported_by_stop_tuple", "mapped_frame_observed", "unresolved"])
        self.path.rename(self.root / "retired.dmp")

    def test_live_offline_reserved_or_zero_code(self):
        for mask, live, offline in ((0x10, True, False), (0x20, False, True), (0x80000000, None, None)):
            self.path.write_bytes(triage(attributes=mask))
            doc, _ = self.invoke()
            self.assertEqual(doc["header"]["attribute_bits"], hex(mask))
            self.assertIs(doc["header"]["live_dump"], live)
            self.assertIs(doc["header"]["offline_generated"], offline)
            self.assertEqual(doc["assessment"]["hypotheses"][0]["state"], "code_recorded_only")
        for code in (0, 0x9f):
            self.path.write_bytes(triage(code=code))
            doc, _ = self.invoke()
            h = doc["assessment"]["hypotheses"][0]
            self.assertEqual(h["state"], "different_stop_code" if code else "unresolved")
            self.assertEqual(bool(h["contrary"]), bool(code))

    def test_unavailable_initial_stop(self):
        data = triage()[:8192] + bytes(4096)
        struct.pack_into("<Q", data, 0x10, 4096)
        struct.pack_into("<I4xQQQ", data, 0x88, 1, 1, 1, 1)
        struct.pack_into("<I", data, 0xf98, 1)
        struct.pack_into("<Q", data, 0xfa0, len(data))
        self.path.write_bytes(data)
        doc, _ = self.invoke()
        self.assertEqual(doc["header"]["bugcheck"], doc["dbgeng"]["bugcheck"])
        self.assertFalse(doc["dbgeng"]["initial_stop"])
        self.assertNotEqual(doc["dbgeng"]["calls"]["wait_event"], "0x0")
        self.assertIsNone(doc["dbgeng"]["frames"])
        self.assertIsNone(doc["assessment"]["header_context_matches_stack_top"])
        self.assertEqual(doc["assessment"]["hypotheses"][0]["state"], "code_recorded_only")

    def test_module_bounds_and_frame_limit(self):
        self.path.write_bytes(triage(ret=DRIVER + 0x4000))
        doc, _ = self.invoke()
        self.assertIsNone(doc["dbgeng"]["frames"][1]["module"]["range"])
        self.path.write_bytes(triage(frames=40))
        doc, _ = self.invoke()
        frames = doc["dbgeng"]["frames"]
        self.assertTrue(doc["dbgeng"]["frame_limit_reached"])
        self.assertEqual(len(frames), 32)
        self.assertEqual(frames[-1]["sp"], hex(SP + 31 * 8))
        self.assertEqual(frames[-1]["ip"], hex(KERNEL + 0x1200 + 30 * 16))

    def test_admission_and_terminal_errors(self):
        for path, pin, status in ((self.path, "0" * 64, "digest_mismatch"),
                                  (self.root / "missing.dmp", "0" * 64, "source_unavailable"),
                                  (self.root, "0" * 64, "source_unavailable")):
            doc, _ = self.invoke(path, pin, 1)
            self.assertEqual(doc["status"], status)
            self.assertNotIn("dbgeng", doc)
        # An accepted header with an inconsistent physical run table cannot be opened by the engine.
        malformed = triage()
        struct.pack_into("<I", malformed, 0xf98, 1)
        self.path.write_bytes(malformed)
        header, _ = self.invoke(expected=1)
        self.assertEqual(header["status"], "header_only")
        self.assertIsNone(header["dbgeng"]["bugcheck"])
        self.assertIsNotNone(header["header"]["bugcheck"])
        for data in (b"PAGEDU64", b"MDMP" + bytes(8192), bytes(8192)):
            self.path.write_bytes(data)
            self.assertEqual(self.invoke(expected=1)[0]["status"], "unsupported_header")
        for args in ([], [str(self.path), "--sha256", "g" * 64], [str(self.path), "--hash", "0" * 64]):
            c = subprocess.run([EXE, "--crash-diagnose", *args], capture_output=True, timeout=15)
            self.assertEqual(c.returncode, 2)
            self.assertEqual(c.stdout, b"")
            self.assertIn(b"usage", c.stderr)

    def test_changed_file_and_missing_header_context(self):
        original, _ = self.invoke()
        replacement = self.root / "replacement.dmp"
        replacement.write_bytes(triage(code=0x9f))
        os.replace(replacement, self.path)
        self.assertEqual(self.invoke(pin=original["dump_sha256"], expected=1)[0]["status"], "digest_mismatch")
        self.assertEqual(self.invoke()[0]["dbgeng"]["bugcheck"]["code"], "0x9f")
        data = triage()
        struct.pack_into("<I", data, 0x348 + 0x30, 0x100000)
        self.path.write_bytes(data)
        doc, _ = self.invoke()
        self.assertIsNone(doc["header"]["control_context"])
        self.assertIsNone(doc["assessment"]["header_context_matches_stack_top"])
        self.assertEqual(doc["assessment"]["hypotheses"][1]["state"], "unresolved")

    def test_reparse_parent(self):
        import _winapi
        source = self.root / "source"
        source.mkdir()
        target = source / "owned.dmp"
        self.path.rename(target)
        junction = self.root / "alias"
        _winapi.CreateJunction(str(source), str(junction))
        try:
            doc, _ = self.invoke(junction / target.name, expected=1)
            self.assertEqual(doc["status"], "source_unavailable")
            self.assertNotIn("dbgeng", doc)
        finally:
            junction.rmdir()

    def test_shared_writer_and_output_failure(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        pin = hashlib.sha256(self.path.read_bytes()).hexdigest()
        writer = kernel.CreateFileW(str(self.path), 0x40000000, 7, None, 3, 0, None)
        self.assertNotEqual(writer, ctypes.c_void_p(-1).value)
        try:
            self.assertEqual(self.invoke(pin=pin, expected=1)[0]["status"], "source_unavailable")
        finally:
            self.assertTrue(kernel.CloseHandle(writer))
        self.assertEqual(self.invoke()[0]["status"], "matched_stop_data")
        with self.path.open("rb") as sink:
            c = subprocess.run([EXE, "--crash-diagnose", str(self.path), "--sha256", pin],
                               stdout=sink, stderr=subprocess.PIPE, timeout=25)
        self.assertEqual(c.returncode, 2)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), pin)

    def test_aliased_writable_output_preserves_source(self):
        pin = hashlib.sha256(self.path.read_bytes()).hexdigest()
        alias = self.root / "other-name"
        os.link(self.path, alias)
        for name in (self.path, alias):
            with name.open("ab") as sink:
                valid = subprocess.run([EXE, "--crash-diagnose", str(self.path), "--sha256", pin],
                                       stdout=sink, stderr=subprocess.PIPE, timeout=15)
                invalid = subprocess.run([EXE, "--crash-diagnose", str(self.path), "--sha256", "x"],
                                         stderr=sink, stdout=subprocess.PIPE, timeout=15)
            self.assertEqual((valid.returncode, invalid.returncode), (2, 2))
            self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), pin)
        # A separate report file can still receive the error for a missing input.
        output = self.root / "report"
        with output.open("wb") as sink:
            c = subprocess.run([EXE, "--crash-diagnose", str(self.root / "missing"), "--sha256", pin],
                               stdout=sink, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(c.returncode, 1)
        self.assertEqual(json.loads(output.read_bytes())["status"], "source_unavailable")

    def test_ambient_symbol_server(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.setblocking(False)
            remote = "srv*http://127.0.0.1:" + str(listener.getsockname()[1])
            env = dict(os.environ, _NT_SYMBOL_PATH=remote, _NT_ALT_SYMBOL_PATH=remote, _NT_EXECUTABLE_IMAGE_PATH=remote)
            self.assertEqual(self.invoke(env=env)[0]["assessment"]["hypotheses"][1]["state"], "mapped_frame_observed")
            with self.assertRaises(BlockingIOError):
                listener.accept()

    def test_sdk_kd_comparison(self):
        if not KD:
            self.skipTest("Windows SDK kd.exe not supplied")
        folder = self.root / "empty"
        folder.mkdir()
        env = dict(os.environ, _NT_SYMBOL_PATH=str(folder), _NT_EXECUTABLE_IMAGE_PATH=str(folder))
        c = subprocess.run([KD, "-sins", "-noshell", "-y", str(folder), "-i", str(folder), "-z", str(self.path),
                            "-c", ".bugcheck;lm;k 4;q"], cwd=folder, env=env, capture_output=True, timeout=30)
        self.assertEqual(c.returncode, 0)
        output = (c.stdout + c.stderr).decode("utf-8", "replace").replace(chr(96), "")
        code = int(re.search(r"(?im)^Bugcheck code ([0-9a-f]+)", output).group(1), 16)
        params = re.search(r"(?im)^Arguments((?:[ \t]+[0-9a-f]+){4})", output).group(1).split()
        doc, _ = self.invoke()
        self.assertEqual(doc["dbgeng"]["bugcheck"], {"code": hex(code), "parameters": [hex(int(p, 16)) for p in params]})
        for f in doc["dbgeng"]["frames"]:
            m = f["module"]["range"]
            pattern = rf"(?im)^{int(m['base'],16):016x}\s+{int(m['base'],16)+m['size']:016x}\s+{re.escape(m['name'])}\b"
            self.assertRegex(output, pattern)
            self.assertRegex(output, rf"(?im)^[0-9a-f]+\s+{int(f['sp'],16):016x}\s+{int(f['return'],16):016x}\b")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--kd", type=Path, help="Windows SDK x64 kd.exe for a separate debugger session")
    args = parser.parse_args()
    EXE = str(args.exe.resolve())
    KD = str(args.kd.resolve()) if args.kd else None
    unittest.main(argv=["test-crash-diagnosis"], verbosity=2)
