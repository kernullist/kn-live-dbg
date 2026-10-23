"""Counterexamples for the offline gate; synthetic records do not test KMON."""
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("vctip_audit", pathlib.Path(__file__).with_name("validate-kmon-vctip.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class CoverageGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.run = self.root / "run"
        self.run.mkdir()
        self.reference = r"C:\Windows\System.Data.dll"
        self.mapped = r"\Device\HarddiskVolume3\Windows\System.Data.dll"
        self.before = {"pid": 42, "creation_filetime": 12345, "file_sha256": "reference",
                       "preferred_base": 0x10000000, "process_image": r"C:\tools\vctip.exe",
                       "reference": self.reference, "views": []}
        self.events = []
        for base, secondary in ((0x70000, True), (0x70000000, False)):
            self.before["views"].append({"base": base, "name": self.mapped, "header_base": 0x70000000,
                "secondary": secondary, "sections": [{"rva": 4096, "size": 4, "executable": True,
                "observed_sha256": audit.sha(b"test"), "expected_sha256": audit.sha(b"test"), "different_bytes": 0}]})
            self.events.append({"pid": 42, "kind": "coverage.image", "image": self.reference, "summary": "cycle_complete",
                "evidence": {"image_base": str(base), "process_create_time": "12345", "relocation_base": str(0x70000000),
                "relocation_basis": "independent_sec_image_no_execute" if secondary else "mapping_base",
                "compared_bytes": "4", "requested_bytes": "4", "failed_bytes": "0", "skipped_bytes": "0", "remaining_pages": "0"}})
        self.after = copy.deepcopy(self.before)
        for name in ("before", "after"):
            folder = self.root / name
            folder.mkdir()
            for view in self.before["views"]:
                for role in ("expected", "observed"):
                    (folder / f'{view["base"]:x}-1000-{role}.bin').write_bytes(b"test")
        self.validation = {k: True for k in ("passed", "all_process_scope_verified", "queue_health_passed",
            "completed_work_passed", "fresh_layouts_passed", "layout_name_accounting_passed", "same_boot")}
        self.validation.update(binary_sha256="binary", observed_processes=[{"pid": 42, "creation_filetime": "12345"}])

    def check(self, passed=False):
        (self.root / "before/snapshot.json").write_text(json.dumps(self.before))
        (self.root / "after/snapshot.json").write_text(json.dumps(self.after))
        (self.run / "validation.json").write_text(json.dumps(self.validation))
        (self.run / "kmon-events.test.jsonl").write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in self.events))
        args = types.SimpleNamespace(run=self.run, before=self.root / "before/snapshot.json", after=self.root / "after/snapshot.json")
        with contextlib.redirect_stdout(io.StringIO()):
            if passed:
                audit.audit(args)
                self.assertTrue(audit.load(self.run / "vctip-validation.json")["passed"])
            else:
                with self.assertRaises(ValueError):
                    audit.audit(args)

    def test_complete_pair(self):
        self.check(True)

    def test_controls_pass_but_target_absent(self):
        self.events.clear()
        self.check()

    def test_only_loader_complete(self):
        self.events.pop(0)
        self.check()

    def test_wrong_generation(self):
        self.events[0]["evidence"]["process_create_time"] = "12346"
        self.check()

    def test_wrong_relocation_basis(self):
        self.events[0]["evidence"]["relocation_basis"] = "mapping_base"
        self.check()

    def test_wrong_relocation_address(self):
        self.events[0]["evidence"]["relocation_base"] = str(0x70000)
        self.check()

    def test_same_basename_other_file(self):
        self.events[0]["image"] = r"C:\elsewhere\System.Data.dll"
        self.check()

    def test_mutation_is_not_exempted(self):
        change = copy.deepcopy(self.events[0])
        change["kind"] = "finding.code_modified"
        self.events.append(change)
        self.check()

    def test_incomplete_range(self):
        self.events[0]["evidence"].update(compared_bytes="3", skipped_bytes="1")
        self.check()

    def test_replaced_view(self):
        self.after["views"][0]["base"] += 65536
        self.check()

    def test_empty_views(self):
        self.before["views"] = []
        self.after["views"] = []
        self.check()

    def test_empty_executable_ranges(self):
        for report in (self.before, self.after):
            report["views"][0]["sections"] = []
        self.check()

    def test_corrupt_snapshot_bytes(self):
        (self.root / "before/70000-1000-observed.bin").write_bytes(b"fail")
        self.check()

    def test_wrong_scope(self):
        self.validation["all_process_scope_verified"] = False
        self.check()

    def test_queue_loss(self):
        self.validation["queue_health_passed"] = False
        self.check()


if __name__ == "__main__":
    unittest.main()
