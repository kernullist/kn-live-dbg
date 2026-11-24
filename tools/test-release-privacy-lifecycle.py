"""Check the Windows packaging fixture lifecycle in disposable checkouts."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from textwrap import indent
import unittest
from zipfile import ZipFile


TOOLS = Path(__file__).resolve().parent
SHELL = "powershell.exe"
SCRIPT = "validate-release-privacy.ps1"
PREFIX = "release-privacy-selftest-"


@unittest.skipUnless(sys.platform == "win32", "requires Windows PowerShell packaging APIs")
class FixtureLifecycleTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.checkout = Path(scratch.name) / "test checkout"
        self.tools = self.checkout / "tools"
        self.tools.mkdir(parents=True)
        self.build = self.checkout / ".build"
        for name in (SCRIPT, "release.ps1", "validate-public-content.py"):
            shutil.copyfile(TOOLS / name, self.tools / name)

    def shell(self, *args, **environment):
        return subprocess.run(
            [SHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", *args],
            cwd=self.checkout, env=os.environ | environment, capture_output=True,
            text=True, errors="replace", timeout=90,
        )

    def suite(self, *args):
        return self.shell("-File", str(self.tools / SCRIPT), "-PythonExecutable", sys.executable, *args)

    def check_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"Release privacy checks passed: [1-9]\d*")

    def at_final_scan(self, control):
        # Only the temporary checkout gets this observation point. Every prior
        # scan, copy, certificate check and ZIP write still runs normally.
        validator = self.tools / "validate-public-content.py"
        validator.rename(self.tools / "original.py")
        validator.write_text(
            "from pathlib import Path\nimport runpy, sys, time\n"
            "if '--tree' in sys.argv:\n"
            "    tree = Path(sys.argv[sys.argv.index('--root') + 1])\n"
            "    if tree.name == 'content-control' and (tree.parent / 'fixture.zip').is_file():\n"
            "        controls = Path(__file__).parent\n"
            + indent(control, "        ") + "\n"
            "globals().update(runpy.run_path(str(Path(__file__).with_name('original.py')), run_name=__name__))\n",
            encoding="utf-8",
        )

    def test_clean_checkout(self):
        self.check_success(self.suite())
        self.assertEqual(list(self.build.iterdir()), [])

    def test_overlapping_default_and_retained_runs(self):
        previous = self.build / (PREFIX + "1" * 32)
        previous.mkdir(parents=True)
        receipt = previous / "inspection.json"
        receipt.write_bytes(b"previous inspection")
        self.at_final_scan(
            "(controls / (tree.parent.name + '.ready')).touch()\n"
            "deadline = time.monotonic() + 40\n"
            "while len(list(controls.glob('*.ready'))) != 2:\n"
            "    if time.monotonic() >= deadline: raise SystemExit(3)\n"
            "    time.sleep(0.05)"
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            default = pool.submit(self.suite)
            retained = pool.submit(self.suite, "-KeepFixtures")
            self.check_success(default.result())
            result = retained.result()
        self.check_success(result)
        self.assertEqual(receipt.read_bytes(), b"previous inspection")
        kept, = set(self.build.iterdir()) - {previous}
        self.assertIn(kept.name, result.stdout)
        self.assertEqual(len(list(self.tools.glob("*.ready"))), 2)
        self.assertTrue((self.tools / (kept.name + ".ready")).is_file())
        package = kept / "package"
        with ZipFile(kept / "fixture.zip") as archive:
            files = {file.relative_to(package).as_posix(): file.read_bytes()
                     for file in package.rglob("*") if file.is_file()}
            self.assertEqual(sorted(archive.namelist()), sorted(files))
            for name, data in files.items():
                self.assertEqual(archive.read(name), data)
        control = json.loads((kept / "inspection.json").read_bytes())
        self.assertEqual([row["rule"] for row in control["findings"]], ["provider-token"])
        self.assertFalse((kept / "source" / "private-container.cer").exists())

    def test_validation_error_removes_partial_work(self):
        self.at_final_scan("(controls / 'reached').touch()\nraise SystemExit(2)")
        result = self.suite()
        self.assertTrue((self.tools / "reached").is_file(), result.stderr)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Final inspection missed private content", result.stderr)
        self.assertNotIn("checks passed", result.stdout)
        self.assertEqual(list(self.build.iterdir()), [])

    def test_keep_fixtures_after_validation_error(self):
        self.at_final_scan("raise SystemExit(2)")
        result = self.suite("-KeepFixtures")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Final inspection missed private content", result.stderr)
        root, = self.build.iterdir()
        self.assertIn(root.name, result.stdout)
        self.assertTrue((root / "fixture.zip").is_file())
        self.assertFalse((root / ".fixture-owner").exists())
        self.assertFalse((root / "source/private-container.cer").exists())

    def test_unregistered_file_survives_cleanup(self):
        self.at_final_scan("(tree.parent / 'source' / 'docs' / 'other.txt').write_bytes(b'keep')")
        result = self.suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("checks passed", result.stdout)
        root, = self.build.iterdir()
        self.assertEqual((root / "source/docs/other.txt").read_bytes(), b"keep")
        self.assertFalse((root / "fixture.zip").exists())

    def test_existing_output_is_never_adopted(self):
        self.at_final_scan("(tree.parent / 'fixture-validator.py').write_bytes(b'keep')")
        result = self.suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Fixture output already exists", result.stderr)
        root, = self.build.iterdir()
        self.assertEqual((root / "fixture-validator.py").read_bytes(), b"keep")

    def test_cleanup_error_preserves_validation_error(self):
        self.at_final_scan("(tree.parent / 'other.txt').write_bytes(b'keep')\nraise SystemExit(2)")
        result = self.suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Final inspection missed private content", result.stderr)
        self.assertIn("fixture cleanup failed", result.stdout + result.stderr)
        root, = self.build.iterdir()
        self.assertEqual((root / "other.txt").read_bytes(), b"keep")
        self.assertFalse((root / ".fixture-owner").exists())

    def test_linked_build_directory(self):
        sibling = self.checkout.parent / "other work"
        sibling.mkdir()
        sentinel = sibling / "existing.txt"
        sentinel.write_bytes(b"keep")
        linked = self.shell("-Command", "$ErrorActionPreference='Stop'\n"
                            "New-Item -ItemType Junction -Path $env:FIXTURE_LINK -Target $env:FIXTURE_TARGET | Out-Null",
                            FIXTURE_LINK=str(self.build), FIXTURE_TARGET=str(sibling))
        self.assertEqual(linked.returncode, 0, linked.stderr)
        self.addCleanup(self.build.rmdir)
        result = self.suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reparse point", result.stderr)
        self.assertEqual(list(sibling.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"keep")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--powershell", default=SHELL)
    args, remaining = parser.parse_known_args()
    SHELL = args.powershell
    unittest.main(argv=[sys.argv[0], *remaining])
