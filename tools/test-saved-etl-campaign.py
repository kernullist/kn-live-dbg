"""Check registered ETL acquisition, evidence survival and planned-family denominators."""
import argparse
import base64
import copy
import errno
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

import saved_etl_campaign as campaign
import saved_etl_comparison as pair


HERE = Path(__file__).resolve().parent
FIXTURE = runpy.run_path(str(HERE / "test-saved-etl-comparison.py"))
EVALUATOR = FIXTURE["EVALUATOR"]
PIN = FIXTURE["PIN"]


def call(script, *args, **streams):
    return subprocess.run([sys.executable, "-B", str(HERE / script), *map(str, args)],
                          **{"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, **streams}, timeout=300)


def evaluate(snapshot, pin, plan_pin):
    return campaign.evaluate(snapshot, pin, plan_pin, EVALUATOR["decode_document"], EVALUATOR["ratio"])


def fixture_package(root, plan, plan_pin, slot, *, change=None, finish=True):
    admission = campaign.reserve(root, plan, plan_pin, slot)
    reg = admission["registration"]
    m = FIXTURE["manifest"](include_disk_io=plan["include_disk_io"])
    m.update(schema="kn.etl_reader_comparison.v3", registration=copy.deepcopy(reg))
    start = int(admission["tick_ns"])
    for i, role in enumerate(pair.ROLES):
        m["attempts"][role].update(started_ns=str(start+1+3*i), ended_ns=str(start+2+3*i))
    if change:
        change(m)
    path = campaign.package_path(root, reg["ticket"])
    package_pin = pair.write_package(path, m, io.BytesIO(FIXTURE["SOURCE"]))
    end = dict(schema=campaign.OUTCOME, admission_sha256=pair.sha(pair.encoded(admission)),
               tick_ns=str(start+8), outcome="published", package_sha256=package_pin, error=None)
    if finish:
        pair.publish_new(campaign.receipt_path(root, reg["ticket"], "ended"), lambda f: f.write(pair.encoded(end)))
    return path, package_pin


class CampaignTests(unittest.TestCase):
    def make(self, count, disk=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve() / "campaign"
        receipt = campaign.create(root, [PIN]*count, PIN, PIN, 3000, disk)
        return root, json.loads((root / campaign.PLAN_FILE).read_bytes()), receipt["plan_sha256"]

    def snapshot(self, root, plan_pin, name="campaign.knruns"):
        path = root / name
        result = campaign.freeze(root, plan_pin, path)
        self.assertEqual(result["snapshot_sha256"], pair.sha(path.read_bytes()))
        return path, result["snapshot_sha256"]

    def test_failed_plan_publication_can_retry_without_reusing_existing_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "campaign"
            with patch.object(campaign, "publish_new", side_effect=OSError("plan write failed")):
                with self.assertRaises(OSError):
                    campaign.create(root, [PIN], PIN, PIN, 3000, False)
            self.assertFalse(root.exists())
            first = campaign.create(root, [PIN], PIN, PIN, 3000, False)
            with self.assertRaises(FileExistsError):
                campaign.create(root, [PIN], PIN, PIN, 3000, True)
            self.assertEqual(pair.sha((root / campaign.PLAN_FILE).read_bytes()), first["plan_sha256"])

    @unittest.skipUnless(os.name == "nt", "Windows handle sharing")
    def test_plan_and_admission_held_until_terminal_publication(self):
        root, plan, pin = self.make(1)
        def check_handles(args, registration):
            for path in (root / campaign.PLAN_FILE, campaign.receipt_path(root, registration["ticket"], "admitted")):
                with self.assertRaises(PermissionError) as denied:
                    with path.open("r+b"):
                        pass
                self.assertEqual(denied.exception.errno, errno.EACCES)
            raise ValueError("test admission lifetime")
        with patch.dict(campaign.capture_tool(), acquire=check_handles):
            captured = campaign.run_slot(root, pin, 1, "source.etl", "reader.exe")
        self.assertEqual(captured["result"]["outcome"], "acquisition_rejected")
        self.assertEqual(captured["registration"]["ticket"], plan["tickets"][0])
        for path in (root / campaign.PLAN_FILE, campaign.receipt_path(root, plan["tickets"][0], "admitted")):
            with path.open("r+b"):
                pass
        snap, sp = self.snapshot(root, pin)
        self.assertEqual(evaluate(snap, sp, pin)["acquisition_counts"]["acquisition_rejected"], 1)

    def test_planned_denominators_and_unacknowledged_package(self):
        root, plan, pin = self.make(3, True)
        fixture_package(root, plan, pin, 1)
        fixture_package(root, plan, pin, 2, finish=False)
        snap, sp = self.snapshot(root, pin)
        r = evaluate(snap, sp, pin)
        self.assertEqual(r["distinct_source_hashes"], 1)
        self.assertEqual([a["acquisition"] for a in r["attempts"]], ["published", "unresolved", "unadmitted"])
        self.assertEqual([a["evidence"] for a in r["attempts"]], ["verified", "no_publication_receipt", "no_publication_receipt"])
        self.assertEqual(r["agreement_per_planned_family"], EVALUATOR["ratio"](2, 9))
        self.assertEqual(r["agreement_per_comparable_family"], EVALUATOR["ratio"](2, 2))
        self.assertEqual(r["families"]["disk_io"]["verdicts"]["native_family_unavailable"], 1)
        self.assertTrue(r["campaign_plan_checked"])
        self.assertFalse(r["attempts"][0]["pair"]["campaign_plan_checked"])
        cmd = ["--etl-reader-campaign", snap, "--sha256", sp, "--plan-sha256", pin, "--study-sha256", PIN]
        rejected = call("evaluate-corpus.py", *cmd)
        self.assertEqual((rejected.returncode, rejected.stdout), (2, b""))
        with self.assertRaises(FileExistsError):
            campaign.reserve(root, plan, pin, 2)
        with self.assertRaises(FileExistsError):
            self.snapshot(root, pin)
        with self.assertRaises(ValueError):
            campaign.freeze(root, pin, campaign.receipt_path(root, plan["tickets"][2], "ended"))

    def test_evidence_dispositions_and_registration_binding(self):
        root, plan, pin = self.make(7)
        first, _ = fixture_package(root, plan, pin, 1)
        first.unlink()
        second, _ = fixture_package(root, plan, pin, 2)
        raw = bytearray(second.read_bytes())
        raw[-1] ^= 1
        second.write_bytes(raw)
        third, _ = fixture_package(root, plan, pin, 3)
        third.write_bytes(b"invalid frame")
        fixture_package(root, plan, pin, 4, change=lambda m: m["registration"].update(slot=6))
        def wrong_tool(m):
            m["tools"]["native"].update(expected_sha256="1"*64, before_sha256="1"*64, after_sha256="1"*64)
        fixture_package(root, plan, pin, 5, change=wrong_tool)
        def wrong_scope(m):
            m["config"] = pair.config(PIN, 2999)
            m["config_sha256"] = pair.sha(pair.encoded(m["config"]))
        fixture_package(root, plan, pin, 6, change=wrong_scope)
        fixture_package(root, plan, pin, 7, change=lambda m: m["attempts"]["native"].update(started_ns="0"))
        snap, sp = self.snapshot(root, pin)
        r = evaluate(snap, sp, pin)
        self.assertEqual(r["acquisition_counts"]["published"], 7)
        self.assertEqual([a["evidence"] for a in r["attempts"]],
                         ["missing", "pin_mismatch", "invalid_package", *(["binding_mismatch"]*4)])
        self.assertEqual(r["verified_packages_per_published"], EVALUATOR["ratio"](0, 7))
        self.assertEqual(r["agreement_per_planned_family"], EVALUATOR["ratio"](0, 14))
        self.assertEqual(r["agreement_per_comparable_family"], EVALUATOR["ratio"](0, 0))
        self.assertEqual(r["reader_statuses"]["tracerpt"], {"no_verified_pair": 7})

    def test_immutable_competing_admissions_and_consistent_snapshot(self):
        root, plan, pin = self.make(2)
        start = Barrier(2)
        def reserve():
            start.wait(timeout=10)
            try:
                campaign.reserve(root, plan, pin, 2)
                return True
            except FileExistsError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(reserve) for _ in range(2)]
            self.assertEqual(sorted(job.result() for job in jobs), [False, True])
        original = campaign.observe_receipt
        triggered = False
        def interleave(path, open_file):
            nonlocal triggered
            if not triggered and path == campaign.receipt_path(root, plan["tickets"][1], "admitted"):
                triggered = True
                fixture_package(root, plan, pin, 1)
            return original(path, open_file)
        with patch.object(campaign, "observe_receipt", interleave):
            snap, sp = self.snapshot(root, pin)
        self.assertTrue(triggered)
        self.assertEqual([a["acquisition"] for a in evaluate(snap, sp, pin)["attempts"]], ["published", "unresolved"])

    def test_unusable_receipts_retain_other_slots_and_bound_original_bytes(self):
        root, plan, pin = self.make(4)
        fixture_package(root, plan, pin, 1)
        campaign.reserve(root, plan, pin, 2)
        too_big = b"a" * (campaign.MAX_RECEIPT + 1)
        campaign.receipt_path(root, plan["tickets"][1], "ended").write_bytes(too_big)
        campaign.receipt_path(root, plan["tickets"][2], "admitted").write_bytes(b"broken JSON")
        fixture_package(root, plan, pin, 4)
        campaign.receipt_path(root, plan["tickets"][3], "admitted").unlink()
        snap, sp = self.snapshot(root, pin)
        r = evaluate(snap, sp, pin)
        self.assertEqual([v["acquisition"] for v in r["attempts"]], ["published"] + ["unusable_receipts"]*3)
        self.assertIsNotNone(r["attempts"][1]["admitted"])
        self.assertIsNone(r["attempts"][3]["admitted"])
        self.assertEqual(r["agreement_per_planned_family"], EVALUATOR["ratio"](2, 8))
        self.assertEqual(r["evidence_counts"]["unusable_receipts"], 3)
        obs = r["attempts"][1]["receipt_observations"]["ended"]
        self.assertEqual((obs["file_bytes"], obs["prefix_sha256"]), (len(too_big), pair.sha(too_big[:-1])))
        self.assertNotIn("prefix", obs)
        packed = json.loads(snap.read_bytes())
        packed["attempts"][1] = dict(reversed(packed["attempts"][1].items()))
        self.assertEqual(campaign.validate_snapshot(packed, pin)[1][1], "unusable_receipts")
        packed["attempts"][1]["unusable_receipts"]["ended"]["prefix_sha256"] = "0"*64
        with self.assertRaises(ValueError):
            campaign.validate_snapshot(packed, pin)

    def test_full_cohort_with_oversized_receipts_still_fits_snapshot(self):
        count = pair.MAX_REGISTERED_SLOTS
        root, plan, pin = self.make(count, True)
        raw = b"x" * (campaign.MAX_RECEIPT + 1)
        for ticket in plan["tickets"]:
            for phase in ("admitted", "ended"):
                campaign.receipt_path(root, ticket, phase).write_bytes(raw)
        snap, sp = self.snapshot(root, pin)
        self.assertLessEqual(snap.stat().st_size, campaign.MAX_SNAPSHOT)
        report = evaluate(snap, sp, pin)
        self.assertEqual(report["evidence_counts"]["unusable_receipts"], count)
        self.assertEqual(report["agreement_per_planned_family"], EVALUATOR["ratio"](0, 3*count))

    def test_mismatch_preserves_registered_and_observed_hashes(self):
        root, plan, pin = self.make(1)
        admission = campaign.reserve(root, plan, pin, 1)
        error = dict(domain="admission", code=None, role="etl", expected_sha256=PIN, observed_sha256="0"*64)
        end = dict(schema=campaign.OUTCOME, admission_sha256=pair.sha(pair.encoded(admission)), tick_ns=admission["tick_ns"],
                   outcome="pin_mismatch", package_sha256=None, error=error)
        row = dict(slot=1, admitted=admission, ended=end)
        self.assertEqual(campaign.validate_row(plan, pin, 1, row), "pin_mismatch")
        for edit in (dict(expected_sha256="1"*64), dict(observed_sha256=PIN), dict(observed_sha256="invalid")):
            changed = copy.deepcopy(row)
            changed["ended"]["error"].update(edit)
            with self.assertRaises(ValueError):
                campaign.validate_row(plan, pin, 1, changed)

    def test_snapshot_pin_slot_order_chain_and_errors(self):
        root, plan, pin = self.make(2)
        admission = campaign.reserve(root, plan, pin, 1)
        diagnostic = pair.record_bytes(io.BytesIO(b"x"*450), campaign.ERROR_PREFIX)
        end = dict(schema=campaign.OUTCOME, admission_sha256=pair.sha(pair.encoded(admission)), tick_ns=admission["tick_ns"],
                   outcome="acquisition_rejected", package_sha256=None,
                   error=dict(domain="validation", code=None, role=None, diagnostic=diagnostic))
        path = campaign.receipt_path(root, plan["tickets"][0], "ended")
        path.write_bytes(pair.encoded(end))
        snap, sp = self.snapshot(root, pin)
        r = evaluate(snap, sp, pin)
        self.assertEqual(r["attempts"][0]["ended"]["error"]["diagnostic"]["byte_count"], 450)
        self.assertEqual(r["agreement_per_comparable_family"]["value"], None)
        for bad_snapshot, bad_plan in (("0"*64, pin), (sp, "0"*64)):
            with self.assertRaises(ValueError):
                evaluate(snap, bad_snapshot, bad_plan)
        blob = json.loads(snap.read_bytes())
        for mutate in (lambda v: v["attempts"].reverse(), lambda v: v["attempts"].pop(),
                       lambda v: v["attempts"][0]["ended"].update(admission_sha256="0"*64),
                       lambda v: v["attempts"][0]["ended"].update(tick_ns="0"),
                       lambda v: v["attempts"][0]["ended"]["error"]["diagnostic"].update(retained_sha256="0"*64),
                       lambda v: v["plan"].update(timeout_ms=1)):
            bad = copy.deepcopy(blob)
            mutate(bad)
            raw = pair.encoded(bad)
            changed = root / "mutated.knruns"
            changed.write_bytes(raw)
            with self.assertRaises(ValueError):
                evaluate(changed, pair.sha(raw), pin)
        with self.assertRaises(ValueError):
            campaign.create(root.parent / "too-many", [PIN]*33, PIN, PIN, 3000, True)
        with self.assertRaises(ValueError):
            campaign.reserve(root, plan, pin, 3)

    def test_aliases_private_outputs_and_portable_replay(self):
        root, plan, pin = self.make(1)
        package, _ = fixture_package(root, plan, pin, 1)
        snap, sp = self.snapshot(root, pin)
        command = ["--etl-reader-campaign", snap, "--sha256", sp, "--plan-sha256", pin]
        alias = root.parent / "redirect.bin"
        for source in (root / campaign.PLAN_FILE, snap, package, campaign.receipt_path(root, plan["tickets"][0], "admitted")):
            original = source.read_bytes()
            os.link(source, alias)
            for stream, script, args in (
                ("stdout", "evaluate-corpus.py", command),
                ("stderr", "evaluate-corpus.py", [*command, "--bad"]),
                ("stderr", "saved_etl_campaign.py", ["snapshot", "--directory", root, "--bad"]),
                ("stdout", "saved_etl_campaign.py", ["snapshot", "--directory", root, "--plan-sha256", pin,
                                                     "--out", root/"another.knruns"])):
                with alias.open("ab", buffering=0) as sink:
                    proc = call(script, *args, **{stream: sink})
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(source.read_bytes(), original)
                self.assertFalse((root/"another.knruns").exists())
            alias.unlink()
        moved = root.parent / "portable"
        moved.mkdir()
        os.link(package, moved/package.name)
        os.link(snap, moved/"portable.data")
        cmd = list(command)
        cmd[1] = moved/"portable.data"
        with (moved/"report.json").open("wb") as out:
            p = call("evaluate-corpus.py", *cmd, stdout=out)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads((moved/"report.json").read_bytes())
        self.assertEqual(r["agreement_per_planned_family"], EVALUATOR["ratio"](2, 2))
        self.assertFalse((moved / campaign.PLAN_FILE).exists())


class StudyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name).resolve()
        self.file = self.folder / "corpus.json"
        self.root = self.folder / "campaign"
        def case(key, source, family, group, split):
            return dict(id=key, artifact_sha256=source, family=family, independence_group=group, partition=split,
                        layer="independent_comparison", task="saved_etl_descriptor_counts", unit="case",
                        holes_sha256=campaign.EMPTY_HOLES, truth="unknown", truth_ref_sha256=None)
        self.corpus = dict(schema="kn.benchmark_corpus.v1", corpus_id="study", cohort_id="test",
                           environment=dict(target_id="reader", snapshot_id="test", os_build=None, architecture="unknown",
                                            hvci=None, vbs=None, verifier=None),
                           cases=[case("dev", PIN, "controls", "control-recording", "development"),
                                  case("variant", "1"*64, "controls", "control-recording", "development"),
                                  case("held", "2"*64, "separate", "separate-recording", "heldout"),
                                  case("unused", "3"*64, "unused", "unused-recording", "development")])

    def register(self, ids):
        raw = json.dumps(self.corpus, indent=2).encode("utf-8") + b"\r\n"
        self.file.write_bytes(raw)
        study_pin = pair.sha(raw)
        binding, sources = campaign.load_study(self.file, study_pin, ids)
        pin = campaign.create(self.root, sources, PIN, PIN, 3000, False, study=binding)["plan_sha256"]
        return json.loads((self.root / campaign.PLAN_FILE).read_bytes()), pin, study_pin

    def test_binding_and_denominators_survive_loss_of_corpus_file(self):
        self.corpus["cases"][0].update(truth="positive", truth_ref_sha256="4"*64)
        plan, pin, cp = self.register(["dev", "variant", "dev", "held", "held"])
        fixture_package(self.root, plan, pin, 1)
        admission = campaign.reserve(self.root, plan, pin, 4)
        end = dict(schema=campaign.OUTCOME, admission_sha256=pair.sha(pair.encoded(admission)), tick_ns=admission["tick_ns"],
                   outcome="pin_mismatch", package_sha256=None, error=dict(domain="admission", role="etl", code=None,
                   expected_sha256="2"*64, observed_sha256=PIN))
        campaign.receipt_path(self.root, plan["tickets"][3], "ended").write_bytes(pair.encoded(end))
        self.file.unlink()
        frozen = self.root / "frozen.knruns"
        sp = campaign.freeze(self.root, pin, frozen)["snapshot_sha256"]
        cmd = ["--etl-reader-campaign", frozen, "--plan-sha256", pin, "--sha256", sp]
        good = call("evaluate-corpus.py", *cmd, "--study-sha256", cp)
        self.assertEqual(good.returncode, 0, good.stderr)
        r = json.loads(good.stdout)
        self.assertEqual(r["schema"], campaign.STUDY_EVALUATION)
        self.assertNotIn("agreement_per_planned_family", r)
        self.assertEqual(r["corpus_sha256"], cp)
        self.assertFalse(r["partition_assignments_authenticated"])
        self.assertFalse(r["ground_truth_authenticated"])
        self.assertNotIn("precision_known_truth", r)
        dev, held = r["partitions"]["development"], r["partitions"]["heldout"]
        self.assertEqual((dev["planned_slots"], dev["distinct_cases"], dev["unselected_corpus_cases"]), (3, 2, 1))
        self.assertEqual(dev["by_independence_group"]["control-recording"]["slots"], [1, 2, 3])
        self.assertEqual(dev["by_sample_family"]["controls"]["distinct_source_hashes"], 2)
        self.assertEqual(dev["selected_cases_per_eligible"], EVALUATOR["ratio"](2, 3))
        self.assertEqual(dev["unselected_eligible_case_ids"], ["unused"])
        self.assertEqual(dev["agreement_per_planned_group"], EVALUATOR["ratio"](0, 1))
        self.assertEqual(dev["agreement_per_comparable_group"], EVALUATOR["ratio"](0, 0))
        self.assertEqual(dev["agreement_per_planned_family"], EVALUATOR["ratio"](2, 6))
        self.assertEqual(dev["agreement_per_comparable_family"], EVALUATOR["ratio"](2, 2))
        self.assertEqual(held["declared_independence_groups"], 1)
        self.assertEqual(held["agreement_per_planned_family"], EVALUATOR["ratio"](0, 4))
        self.assertEqual(held["agreement_per_comparable_family"], EVALUATOR["ratio"](0, 0))
        self.assertEqual(held["cross_partition_input_mismatches"], 1)
        self.assertEqual(r["attempts"][3]["supplied_source_partition"], "development")
        bad = call("evaluate-corpus.py", *cmd, "--study-sha256", "0"*64)
        self.assertEqual((bad.returncode, bad.stdout), (2, b""))

    def test_checks_whole_registry_and_selected_scope_before_creating_plan(self):
        for key in ("artifact_sha256", "family", "independence_group"):
            bad = copy.deepcopy(self.corpus)
            bad["cases"][3][key] = bad["cases"][2][key]
            raw = pair.encoded(bad)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "leakage"):
                campaign.select_cases(raw, pair.sha(raw), ["dev"])
        bad = copy.deepcopy(self.corpus)
        bad["cases"][3]["artifact_sha256"] = PIN
        raw = pair.encoded(bad)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            campaign.select_cases(raw, pair.sha(raw), ["dev"])
        for key, value in (("layer", "synthetic"), ("unit", "event"), ("task", "other"), ("holes_sha256", "0"*64)):
            bad = copy.deepcopy(self.corpus)
            bad["cases"][0][key] = value
            raw = pair.encoded(bad)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "scope"):
                campaign.select_cases(raw, pair.sha(raw), ["dev"])
        raw = pair.encoded(self.corpus)
        self.file.write_bytes(raw)
        cp = pair.sha(raw)
        cmd = ["create", "--directory", self.root, "--study-corpus", self.file, "--exe-sha256", PIN, "--tracerpt-sha256", PIN]
        for opts in ([], ["--study-sha256", "0"*64], ["--study-sha256", cp, "--case-id", "absent"],
                     ["--study-sha256", cp, "--source-sha256", PIN]):
            proc = call("saved_etl_campaign.py", *cmd, *opts)
            self.assertEqual((proc.returncode, proc.stdout), (2, b""))
            self.assertFalse(self.root.exists())
        alias = self.folder / "diagnostic.bin"
        os.link(self.file, alias)
        with alias.open("ab", buffering=0) as sink:
            proc = call("saved_etl_campaign.py", *cmd, "--unknown", stderr=sink)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(self.file.read_bytes(), raw)
        leaked = copy.deepcopy(self.corpus)
        leaked["cases"][3]["independence_group"] = leaked["cases"][2]["independence_group"]
        self.file.write_bytes(pair.encoded(leaked))
        proc = call("saved_etl_campaign.py", *cmd, "--study-sha256", pair.sha(self.file.read_bytes()), "--case-id", "dev")
        self.assertEqual((proc.returncode, proc.stdout), (2, b""))
        self.assertIn(b"leakage", proc.stderr)
        self.assertFalse(self.root.exists())
        self.file.write_bytes(raw)
        proc = call("saved_etl_campaign.py", *cmd, "--study-sha256", cp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        plan = json.loads((self.root / campaign.PLAN_FILE).read_bytes())
        self.assertEqual(plan["study"]["case_ids"], ["dev", "variant", "held", "unused"])

    def test_group_cannot_select_the_best_repeat(self):
        plan, pin, _ = self.register(["dev", "dev"])
        fixture_package(self.root, plan, pin, 1)
        def disagree(manifest):
            doc = FIXTURE["native"]()
            doc["capabilities"][0]["record_evidence"]["decoded"] = 1
            manifest["attempts"]["native"]["stdout"] = FIXTURE["retained"](pair.encoded(doc))
        fixture_package(self.root, plan, pin, 2, change=disagree)
        path = self.root / "frozen.knruns"
        sp = campaign.freeze(self.root, pin, path)["snapshot_sha256"]
        panel = evaluate(path, sp, pin)["partitions"]["development"]
        self.assertEqual(panel["agreement_per_planned_family"], EVALUATOR["ratio"](3, 4))
        self.assertEqual(panel["agreement_per_planned_group"], EVALUATOR["ratio"](0, 1))
        self.assertEqual(panel["agreement_per_comparable_group"], EVALUATOR["ratio"](0, 1))

    def test_repinned_study_cannot_relabel_a_previous_reader_pair(self):
        plan, pin, cp = self.register(["dev"])
        fixture_package(self.root, plan, pin, 1)
        path = self.root / "first.knruns"
        original = campaign.freeze(self.root, pin, path)["snapshot_sha256"]
        self.assertEqual(evaluate(path, original, pin)["partitions"]["heldout"]["planned_slots"], 0)
        frozen = json.loads(path.read_bytes())
        new_plan = frozen["plan"]
        for case in self.corpus["cases"][:2]:
            case["partition"] = "heldout"
        raw_corpus = pair.encoded(self.corpus)
        new_plan["study"].update(corpus_sha256=pair.sha(raw_corpus), corpus_base64=base64.b64encode(raw_corpus).decode("ascii"))
        new_pin = pair.sha(pair.encoded(new_plan))
        frozen["plan_sha256"] = new_pin
        row = frozen["attempts"][0]
        row["admitted"]["registration"]["plan_sha256"] = new_pin
        row["ended"]["admission_sha256"] = pair.sha(pair.encoded(row["admitted"]))
        changed = self.root / "changed.knruns"
        raw = pair.encoded(frozen)
        changed.write_bytes(raw)
        r = evaluate(changed, pair.sha(raw), new_pin)
        self.assertEqual(r["attempts"][0]["evidence"], "binding_mismatch")
        self.assertEqual(r["partitions"]["heldout"]["agreement_per_planned_family"], EVALUATOR["ratio"](0, 2))
        self.assertNotEqual(r["corpus_sha256"], cp)
        for edit in ("sources", "corpus", "selection", "schema"):
            variant = copy.deepcopy(new_plan)
            if edit == "sources":
                variant["sources"][0] = "7"*64
            elif edit == "corpus":
                variant["study"]["corpus_base64"] += "="
            elif edit == "selection":
                variant["study"]["case_ids"] = None
            else:
                variant["schema"] = campaign.PLAN
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                campaign.validate_plan(variant, pair.sha(pair.encoded(variant)))

    def test_full_corpus_extent_and_empty_heldout_scope(self):
        raw = pair.encoded(self.corpus).ljust(campaign.CORPUS["MAX_BYTES"], b" ")
        self.file.write_bytes(raw)
        cp = pair.sha(raw)
        binding, sources = campaign.load_study(self.file, cp, ["dev"]*pair.MAX_REGISTERED_SLOTS)
        pin = campaign.create(self.root, sources, PIN, PIN, 3000, True, study=binding)["plan_sha256"]
        plan = json.loads((self.root / campaign.PLAN_FILE).read_bytes())
        oversized = b"x"*(campaign.MAX_RECEIPT+1)
        for ticket in plan["tickets"]:
            for phase in ("admitted", "ended"):
                campaign.receipt_path(self.root, ticket, phase).write_bytes(oversized)
        frozen = self.root / "upper.knruns"
        sp = campaign.freeze(self.root, pin, frozen)["snapshot_sha256"]
        self.assertLessEqual(frozen.stat().st_size, campaign.MAX_STUDY_SNAPSHOT)
        r = evaluate(frozen, sp, pin)
        dev, held = r["partitions"]["development"], r["partitions"]["heldout"]
        self.assertEqual(dev["evidence_counts"]["unusable_receipts"], 32)
        self.assertEqual(dev["agreement_per_planned_family"], EVALUATOR["ratio"](0, 96))
        self.assertEqual(held["agreement_per_planned_family"], EVALUATOR["ratio"](0, 0))
        with self.file.open("ab") as f:
            f.write(b" ")
        with self.assertRaises(ValueError):
            campaign.load_study(self.file, cp, ["dev"])


def live(args):
    """Use real Windows readers and exit an owned supervisor between package and outcome publication."""
    exe, etl = args.exe.resolve(strict=True), args.etl.resolve(strict=True)
    tracerpt = Path(os.environ["SystemRoot"]) / "System32" / "tracerpt.exe"
    with tracerpt.open("rb") as source:
        system_pin = hashlib.file_digest(source, "sha256").hexdigest()
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder).resolve() / "registered"
        creation = call("saved_etl_campaign.py", "create", "--directory", root,
                        "--exe-sha256", args.exe_sha256, "--tracerpt-sha256", system_pin, "--include-disk-io",
                        *[arg for _ in range(5) for arg in ("--source-sha256", args.sha256)])
        assert creation.returncode == 0, creation.stderr
        pin = json.loads(creation.stdout)["plan_sha256"]
        def run(slot, src):
            return call("saved_etl_campaign.py", "run", "--directory", root, "--plan-sha256", pin,
                        "--slot", slot, "--etl", src, "--exe", exe)
        wrong = root.parent / "changed.etl"
        wrong.write_bytes(b"wrong input")
        for slot, src, state in ((1, etl, "published"), (2, root.parent/"missing.etl", "os_error"), (3, wrong, "pin_mismatch")):
            proc = run(slot, src)
            assert proc.returncode == (0 if state == "published" else 1), proc.stderr
            result = json.loads(proc.stdout)["result"]
            assert result["outcome"] == state
            if state == "os_error":
                assert result["error"] == dict(domain="win32", code=2, role=None)
            if state == "pin_mismatch":
                assert result["error"] == dict(domain="admission", code=None, role="etl", expected_sha256=args.sha256,
                                               observed_sha256=pair.sha(wrong.read_bytes()))
        child = """from pathlib import Path
import os,sys
sys.path.insert(0,sys.argv[1])
import saved_etl_campaign as c
tool = c.capture_tool()
actual = tool["acquire"]
def leave(args, reg):
    receipt = actual(args, reg)
    assert Path(args.output).is_file() and receipt["package_sha256"]
    os._exit(77)
tool["acquire"] = leave
c.run_slot(Path(sys.argv[2]), sys.argv[3], 4, sys.argv[4], sys.argv[5])
"""
        lost = subprocess.run([sys.executable, "-B", "-c", child, HERE, root, pin, etl, exe], capture_output=True, timeout=300)
        assert lost.returncode == 77, lost.stderr
        assert run(4, etl).returncode == 2
        path = root / "frozen.knruns"
        snap = call("saved_etl_campaign.py", "snapshot", "--directory", root, "--plan-sha256", pin, "--out", path)
        assert snap.returncode == 0, snap.stderr
        report = call("evaluate-corpus.py", "--etl-reader-campaign", path, "--plan-sha256", pin,
                      "--sha256", json.loads(snap.stdout)["snapshot_sha256"])
        assert report.returncode == 0, report.stderr
        rows = json.loads(report.stdout)
        assert [r["acquisition"] for r in rows["attempts"]] == ["published", "os_error", "pin_mismatch", "unresolved", "unadmitted"]
        assert rows["evidence_counts"]["verified"] == 1 and rows["agreement_per_planned_family"]["denominator"] == 15
        assert rows["attempts"][0]["pair"]["families"]["disk_io"]["native"]["decoded"] == args.expected_disk
        for role, actual in (("native", args.exe_sha256), ("tracerpt", system_pin)):
            changed = root.parent / (role + "-pin-control")
            pins = dict(native=args.exe_sha256, tracerpt=system_pin)
            pins[role] = "0"*64
            changed_pin = campaign.create(changed, [args.sha256], pins["native"], pins["tracerpt"], 3000, False)["plan_sha256"]
            failed = campaign.run_slot(changed, changed_pin, 1, etl, exe)["result"]
            assert failed["outcome"] == "pin_mismatch"
            assert failed["error"] == dict(domain="admission", code=None, role=role, expected_sha256="0"*64, observed_sha256=actual)
        bad_exe = root.parent / "bad-reader.exe"
        bad_exe.write_bytes(b"invalid executable image for the launch control")
        try:
            subprocess.run([str(bad_exe)], capture_output=True, timeout=10)
        except OSError as exc:
            launch_code = exc.winerror
        else:
            raise AssertionError("invalid executable unexpectedly launched")
        assert launch_code > 0
        failed = root.parent / "launch-control"
        failed_pin = campaign.create(failed, [args.sha256], pair.sha(bad_exe.read_bytes()), system_pin, 240000, False)["plan_sha256"]
        result = campaign.run_slot(failed, failed_pin, 1, etl, bad_exe)
        assert result["result"]["outcome"] == "published"
        frozen = failed / "launch.knruns"
        failed_snap = campaign.freeze(failed, failed_pin, frozen)["snapshot_sha256"]
        report = evaluate(frozen, failed_snap, failed_pin)
        readers = report["attempts"][0]["pair"]["readers"]
        assert (readers["native"]["status"], readers["native"]["os_error"]) == ("launch_error", launch_code)
        assert readers["tracerpt"]["status"] == "observed"
        assert report["observed_readers_per_planned"] == EVALUATOR["ratio"](1, 2)
        assert report["agreement_per_planned_family"] == EVALUATOR["ratio"](0, 2)
        assert report["agreement_per_comparable_family"] == EVALUATOR["ratio"](0, 0)
        print(f"Verified registered Windows reader pairs, source errors, native launch error {launch_code}, "
              "unacknowledged package and unused slot.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        unittest.main()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        for flag in ("--exe", "--etl"):
            parser.add_argument(flag, type=Path, required=True)
        for flag in ("--sha256", "--exe-sha256"):
            parser.add_argument(flag, required=True)
        parser.add_argument("--expected-disk", type=int, required=True)
        live(parser.parse_args())
