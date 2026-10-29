"""Regression tests for publication checks; all secret-shaped data is synthetic."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("public_content", Path(__file__).with_name("validate-public-content.py"))
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class PublicContentTests(unittest.TestCase):
    def test_private_files(self):
        for name in (".env", ".env.production", "sub/.env.backup", "signing.pfx",
                     "capture.DMP", "auth.json", "mcp-endpoint.json", "sub/id_ed25519",
                     ".build/trace.json", "sub/.kn-live-dbg/session.json", "run.log",
                     "capture.KNCASE", "capture.kncase.pending-123", "session.knledger", "session.knledger.pending-123",
                     "manifest.KNINDEX", "chunk.knchunk", "manifest.knindex.pending-123", "chunk.knchunk.pending-123"):
            with self.subTest(name=name):
                self.assertTrue(AUDIT.inspect(name, b"empty"))

    def test_safe_examples(self):
        text = b"KNLIVEDBG_OPENROUTER_API_KEY=sk-or-replace-me\nAPI_KEY=sk-replace-me\n"
        self.assertEqual(AUDIT.inspect(".env.example", text), [])
        self.assertEqual(AUDIT.inspect("notes.md", b"sha256=" + b"a1" * 32), [])

    def test_renamed_evidence_stays_private(self):
        for schema in ("kmon.bundle.v1", "kmon.evidence.v1", "kmon.evidence_session.v1",
                       "kn.evidence_inventory.v1", "kn.evidence_inventory_chunk.v1", "kn.observation_read.v1"):
            data = json.dumps({"schema": schema, "payload": {"bytes_hex": "c3"}})
            for encoding in ("utf-8", "utf-16"):
                self.assertIn("private-evidence-bundle",
                              {f["rule"] for f in AUDIT.inspect("renamed.json", data.encode(encoding))})

    def test_real_shaped_secrets_are_not_reported_verbatim(self):
        samples = ["gh" + "p_" + "A" * 36, "sk-" + "proj-" + "B" * 50,
                   "-----BEGIN " + "PRIVATE KEY-----",
                   "API_KEY=" + "not-a-placeholder",
                   "export SERVICE_ACCESS_TOKEN=" + "arbitrary-value",
                   "https://" + "user:password" + "@example.invalid",
                   "https://example.invalid?" + "sig=" + "c" * 40,
                   "<RSAKeyValue>\n" + "<D>example</D></RSAKeyValue>"]
        for sample in samples:
            with self.subTest(kind=samples.index(sample)):
                findings = AUDIT.inspect("sample.txt", sample.encode())
                self.assertTrue(findings)
                self.assertNotIn(sample, json.dumps(findings))

    def test_utf16_and_binary_strings(self):
        secret = "gh" + "p_" + "A" * 36
        for data in (secret.encode("utf-16"), b"MZ\0\1" + secret.encode(),
                     b"MZ\0\1" + secret.encode("utf-16-le")):
            self.assertTrue(AUDIT.inspect("sample.bin", data))

    def test_filename_findings_are_redacted(self):
        secret = "gh" + "p_" + "A" * 36
        findings = AUDIT.inspect(secret + ".txt", b"empty")
        self.assertTrue(findings)
        self.assertNotIn(secret, json.dumps(findings))

    def test_profile_paths_and_test_controls(self):
        base = "C:" + "\\Users\\"
        self.assertTrue(AUDIT.inspect("notes.md", (base + "private-account\\source.cpp").encode()))
        for user in ("Public", "test", "a", "O'Brien", "O''Brien"):
            self.assertFalse(AUDIT.inspect("test.cpp", (base + user + "\\test.cpp").encode()))

    def test_private_symbols_opt_in_is_not_a_secret_bypass(self):
        data = ("C:" + "\\Users\\private-account\\source.cpp").encode()
        self.assertTrue(AUDIT.inspect("sample.pdb", data))
        self.assertFalse(AUDIT.inspect("sample.pdb", data, True))
        self.assertTrue(AUDIT.inspect("sample.cpp", data, True))
        self.assertTrue(AUDIT.inspect("sample.pdb", ("gh" + "p_" + "A" * 36).encode(), True))

    def test_exact_index_and_untracked_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            (root / "tracked.txt").write_text("staged")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True, capture_output=True)
            (root / "tracked.txt").write_text("working")
            (root / "untracked.txt").write_text("new")
            self.assertEqual(dict(AUDIT.inputs(root, True, False)), {"tracked.txt": b"staged"})
            self.assertEqual(dict(AUDIT.inputs(root, False, False)),
                             {"tracked.txt": b"working", "untracked.txt": b"new"})
            (root / "tracked.txt").unlink()
            self.assertEqual(dict(AUDIT.inputs(root, False, False)), {"untracked.txt": b"new"})

    def test_tree_mode_checks_ignored_files_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env.local").write_text("synthetic")
            result = subprocess.run([sys.executable, str(Path(AUDIT.__file__)),
                                     "--tree", "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("synthetic", result.stdout)
            self.assertEqual(json.loads(result.stdout)["files"], 1)
            missing = subprocess.run([sys.executable, str(Path(AUDIT.__file__)),
                                      "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)
            empty = root / "empty"
            empty.mkdir()
            for candidate in (empty, root / "missing"):
                result = subprocess.run([sys.executable, str(Path(AUDIT.__file__)),
                                         "--tree", "--root", str(candidate)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
