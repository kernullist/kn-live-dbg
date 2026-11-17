"""Check independent replay and altered copies of an actual owned Windows workload."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

import owned_module_benchmark as package


TOOLS = Path(__file__).resolve().parent
EVALUATE = TOOLS / "evaluate-corpus.py"
RUNNER = TOOLS / "test-user-module-workload.py"
SPEC = importlib.util.spec_from_file_location("corpus_evaluator", EVALUATE)
evaluator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluator)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")


class ReplayTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="kn-owned-replay-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.manifest, self.parts = package.read_bundle(self.evidence, self.pin, evaluator.decode_document)
        with self.evidence.open("rb") as stream:
            self.raw = stream.read(package.MAX_PACKAGE + 1)
        self.assertLessEqual(len(self.raw), package.MAX_PACKAGE)
        self.assertEqual(sha(self.raw), self.pin)
        self.copy = self.root / "mutated.knbench"

    def repack(self, parts, *, bind=True, compression=zipfile.ZIP_STORED):
        manifest = dict(self.manifest)
        if bind:
            manifest["artifacts"] = {name: sha(raw) for name, raw in parts.items()}
        with zipfile.ZipFile(self.copy, "w", compression=compression) as archive:
            archive.writestr(package.MANIFEST, json_bytes(manifest))
            for name, raw in parts.items():
                archive.writestr(name, raw)
        return sha(self.copy.read_bytes())

    def changed_world(self, world, *, journal=None, replies=None):
        parts = dict(self.parts)
        if journal:
            truth = json.loads(parts["truth.json"])
            journal(truth["worlds"][package.WORLDS.index(world)])
            parts["truth.json"] = json_bytes(truth)
        if replies:
            name = world + ".jsonl"
            records = [json.loads(line) for line in parts[name].splitlines()]
            replies(records)
            parts[name] = b"".join(map(json_bytes, records))
        return self.repack(parts)

    def reject(self, pin, reason):
        with self.assertRaisesRegex(ValueError, reason):
            evaluator.evaluate_owned(self.copy, pin)

    def test_known_cohorts_and_raw_pointers(self):
        report = evaluator.evaluate_owned(self.evidence, self.pin)
        self.assertEqual(report["artifacts"], {k: sha(v) for k, v in self.parts.items()})
        self.assertTrue(report["artifacts_opened"] and report["owner_loss_witnesses_reconciled"])
        self.assertTrue(report["acquisition_target_probed"])
        self.assertFalse(report["target_probed"])
        self.assertFalse(report["ground_truth_authenticated"] or report["independent_detection_validation"])
        self.assertIsNone(report["overall_ranking"])
        truth = json.loads(self.parts["truth.json"])
        for i, scope in enumerate(report["scopes"]):
            name = package.WORLDS[i]
            self.assertEqual(scope["workload"], name)
            events = truth["worlds"][i]["events"]
            lines = [json.loads(x)["payload"] for x in self.parts[name + ".jsonl"].splitlines()]
            expected = {n for n, event in enumerate(events, 1) if event["kind"] == "ready" and event["member"]}
            self.assertEqual({r["truth_event"] for r in scope["cases"]}, expected)
            total, positive = ((12, 12), (22, 20))[i]
            metrics = scope["metrics"]
            self.assertEqual((len(scope["cases"]), scope["censuses"], scope["out_of_scope_controls"]), (total, 16, 1))
            self.assertEqual(metrics["end_to_end_recall"], dict(numerator=positive, denominator=total, value=positive / total))
            self.assertEqual(metrics["observable_scope_recall"], dict(numerator=positive, denominator=positive, value=1))
            self.assertEqual(metrics["false_positive_rate_observable"], dict(numerator=0, denominator=0, value=None))
            self.assertEqual(metrics["declared_independence_groups"], 1)
            self.assertTrue(metrics["correlated_variants_present"])
            self.assertEqual((metrics["outcomes"]["missing"], metrics["outcomes"]["unavailable"]), (i, i))
            self.assertEqual((metrics["reported_latency_us"]["unknown"], scope["job_active_after_cleanup"]), (i, 0))
            for row in scope["cases"]:
                witness = events[row["truth_event"] - 1]
                visits = [(n, v) for n, v in enumerate(lines, 1) if v.get("key") == witness["child"]]
                hits = [(n, v) for n, v in visits if v["complete"] and v["terminal"] == 18 and v["rows"] > 0 and
                        v["before"] == v["after"] == witness["parent"][1] and v["base"] == witness["base"]]
                self.assertEqual(row["attempts"], len(visits))
                self.assertEqual(row["first_qualified_reply"], hits[0][0] if hits else None)
                receipt = hits[0][0] if hits else visits[-1][0] if visits else None
                self.assertEqual((row["outcome_reply"], row["elapsed_reply"]), (receipt, receipt))
                end = hits[0][1]["last_success"] if hits else visits[-1][1]["end"] if visits else None
                self.assertEqual(row["elapsed_us"], None if end is None else str((end - witness["ready"]) * 1000))
                if not hits:
                    boundary = "after_selection_before_dispatch" if visits else "before_first_census"
                    self.assertEqual(row["exit_boundary"], boundary)
            if self.live:
                live = self.live["worlds"][i]["summary"]
                self.assertEqual((metrics["cases"], metrics["true_positives"], scope["attempts"]),
                                 (live["ready"], live["ever_observed"], live["visits"]))

    def test_archive_members_crc_bounds_and_pins(self):
        self.copy.write_bytes(self.raw)
        self.reject("0" * 64, "SHA-256 mismatch")
        self.reject("A" * 64, "lowercase")
        for raw in (self.raw[:-1], self.raw + b"x", self.raw[:-22] + b"X" * 22, b"PK"):
            self.copy.write_bytes(raw)
            self.reject(sha(raw), "invalid package")
        parts = dict(self.parts, **{"collector.bin": b"changed"})
        self.reject(self.repack(parts, bind=False), "artifact hash")
        parts.pop("collector.bin")
        self.reject(self.repack(parts), "directory")
        self.reject(self.repack(dict(parts, **{"../collector.bin": b"x"})), "membership")
        self.reject(self.repack(self.parts, compression=zipfile.ZIP_DEFLATED), "unsupported")
        with zipfile.ZipFile(io.BytesIO(self.raw)) as archive:
            member = archive.getinfo("collector.bin")
            offset = member.header_offset + 30 + len(member.filename) + len(member.extra)
        altered = bytearray(self.raw)
        altered[offset] ^= 1
        self.copy.write_bytes(altered)
        self.reject(sha(altered), "checksum")
        altered = bytearray(self.raw)
        altered[member.header_offset + 6] |= 1
        self.copy.write_bytes(altered)
        self.reject(sha(altered), "local member header")

    def test_publication_is_exclusive_and_cleans_failed_writes(self):
        with patch.object(package.os, "fsync", side_effect=OSError("injected flush failure")), self.assertRaises(OSError):
            package.write_bundle(self.copy, self.manifest, self.parts)
        self.assertEqual(list(self.root.iterdir()), [])
        pin = package.write_bundle(self.copy, self.manifest, self.parts)
        with self.assertRaises(FileExistsError):
            package.write_bundle(self.copy, self.manifest, self.parts)
        self.assertEqual(sha(self.copy.read_bytes()), pin)
        self.assertEqual(list(self.root.iterdir()), [self.copy])
        raced = self.root / "race.knbench"
        both_flushed = threading.Barrier(2, timeout=15)
        flush = os.fsync
        def synchronize(fd):
            flush(fd)
            both_flushed.wait()
        def publish():
            try:
                return package.write_bundle(raced, self.manifest, self.parts)
            except FileExistsError:
                return None
        with patch.object(os, "fsync", side_effect=synchronize), ThreadPoolExecutor(max_workers=2) as pool:
            writers = [pool.submit(publish) for _ in range(2)]
            pins = [writer.result() for writer in writers]
        self.assertCountEqual(pins, [None, sha(raced.read_bytes())])
        self.assertCountEqual(self.root.iterdir(), [self.copy, raced])

    def test_truth_binding_chronology_and_cleanup(self):
        def first_ready(world):
            return next(e for e in world["events"] if e["kind"] == "ready" and e["member"])
        for change, reason in (
            (lambda w: first_ready(w).update(parent=w["collector"]), "child image"),
            (lambda w: first_ready(w).update(image_file_id=w["collector_file_id"]), "child image"),
            (lambda w: first_ready(w).update(member=False), "admission"),
            (lambda w: first_ready(w).update(confirmed=0), "chronology"),
            (lambda w: first_ready(w).update(role="growth"), "incomplete workload"),
            (lambda w: w["events"].remove(first_ready(w)), "census crossed"),
            (lambda w: w["events"].pop(), "final job accounting"),
            (lambda w: w.update(job_active_after_cleanup=1), "final job accounting"),
        ):
            self.reject(self.changed_world("fixed", journal=change), reason)
        truth = json.loads(self.parts["truth.json"])
        truth["owner_loss"]["peers"]["target"]["after"] = 258
        self.reject(self.repack(dict(self.parts, **{"truth.json": json_bytes(truth)})), "interruption witness")
        self.reject(self.repack(dict(self.parts, **{"fixed.jsonl": self.parts["changing.jsonl"]})), "timing|generation")

    def test_dispatch_order_fences_and_terminal_ledger(self):
        def first(records, kind):
            return next(r["payload"] for r in records if r["payload"]["kind"] == kind)
        for change, reason in (
            (lambda r: first(r, "dispatch").update(after="0"), "contradicts"),
            (lambda r: first(r, "dispatch").update(base=0), "contradicts"),
            (lambda r: first(r, "dispatch").update(rows=0), "enumeration"),
            (lambda r: first(r, "dispatch").update(terminal=0), "enumeration"),
            (lambda r: first(r, "dispatch").update(end=0), "timing"),
            (lambda r: first(r, "dispatch").update(last_success=0), "observation time"),
            (lambda r: first(r, "inventory")["selected"].reverse(), "dispatch identity"),
            (lambda r: first(r, "inventory")["members"].append([9, "1"]), "census crossed"),
            (lambda r: first(r, "finish")["ledger"].update(attempts="0"), "source counts"),
            (lambda r: r.pop(), "missing observer reply"),
            (lambda r: r.append(r[-1]), "transcript"),
            (lambda r: first(r, "finish")["ledger"]["failed_service"].update(samples="999"), "service or reservation"),
            (lambda r: first(r, "finish")["ledger"]["scopes"][0].update(last_success_ms="1"), "retained generation contradicts"),
        ):
            self.reject(self.changed_world("fixed", replies=change), reason)
        def false_success(records):
            visit = first(records, "dispatch")
            self.assertNotEqual(visit["result"], "observed")
            visit.update(before=visit["key"][1], after=visit["key"][1], result="observed", complete=True, rows=1, terminal=18)
        self.reject(self.changed_world("changing", replies=false_success), "contradicts")
        self.reject(self.changed_world("changing", replies=lambda r: first(r, "dispatch").update(last_success=0)), "changed the last success")

    def test_failed_attempts_remain_in_truth_denominator(self):
        def lose_one_generation(records):
            visits = [r["payload"] for r in records if r["payload"]["kind"] == "dispatch"]
            key = visits[0]["key"]
            counts = Counter()
            for visit in visits:
                if visit["key"] == key:
                    visit.update(result="incomplete", before=key[1], after=key[1], base=0, rows=0, complete=False,
                                 terminal=6, win32_error=6, last_success=None)
                counts[visit["result"]] += 1
            ledger = records[-1]["payload"]["ledger"]
            ledger["outcomes"].update({name: str(counts[name]) for name in ledger["outcomes"]})
            ledger["observed_service"]["samples"] = str(counts["observed"])
            ledger["failed_service"]["samples"] = str(counts["incomplete"])
            ledger["first_observation_wait"]["samples"] = str(int(ledger["first_observation_wait"]["samples"]) - 1)
            ledger["successful_revisit"]["samples"] = str(counts["observed"] - int(ledger["first_observation_wait"]["samples"]))
            scope = next(s for s in ledger["scopes"] if [int(s["key"]["pid"]), s["key"]["generation"]] == key)
            scope.update(last_success_ms=None, failure_class="incomplete", win32_error="6")
        pin = self.changed_world("fixed", replies=lose_one_generation)
        metrics = evaluator.evaluate_owned(self.copy, pin)["scopes"][0]["metrics"]
        self.assertEqual((metrics["outcomes"]["positive"], metrics["outcomes"]["error"]), (11, 1))
        self.assertEqual((metrics["end_to_end_recall"]["denominator"], metrics["observable_scope_recall"]["denominator"]), (12, 11))
        self.assertEqual(metrics["reported_latency_us"]["known"], 12)

    @unittest.skipUnless(os.name == "nt", "Windows file sharing and process pipes")
    def test_live_file_lease_and_trailing_original_output(self):
        spec = importlib.util.spec_from_file_location("owned_workload", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        local = self.root / "input.bin"
        local.write_bytes(b"original")
        with runner.leased_file(local) as (stream, identity):
            self.assertEqual(stream.read(), b"original")
            self.assertEqual(len(identity), 48)
            with self.assertRaises(PermissionError), local.open("r+b"):
                self.fail("writer acquired an exclusive input")
            with self.assertRaises(PermissionError):
                local.rename(self.root / "moved")
        local.write_bytes(b"released")
        output = bytearray()
        wire = json_bytes(dict(schema=runner.SCHEMA, payload=dict(kind="ready")))
        child = "import sys; sys.stdout.buffer.write(" + repr(wire + b"unexpected tail\n") + "); sys.stdout.flush()"
        peer = runner.Peer([sys.executable, "-c", child], transcript=output)
        self.addCleanup(peer.close)
        peer.receive("ready")
        self.assertEqual(peer.close(), 0)
        self.assertEqual(output, wire + b"unexpected tail\n")

    def test_public_cli_is_deterministic_and_rejects_ambiguous_inputs(self):
        cmd = [sys.executable, str(EVALUATE), "--owned-module-run", str(self.evidence)]
        outputs = [subprocess.run(cmd + ["--sha256", self.pin], capture_output=True, timeout=30, check=True).stdout for _ in range(2)]
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(json.loads(outputs[0])["package_sha256"], self.pin)
        for extra in ([], ["--sha256", "0" * 64], ["--sha256", self.pin, "--results", "unused"], ["--corpus", "unused"]):
            run = subprocess.run(cmd + extra, capture_output=True, timeout=30)
            self.assertEqual((run.returncode, run.stdout), (2, b""))
            self.assertNotIn(b"Traceback", run.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--core-exe", type=Path, help="acquire new owned Windows evidence with this local core")
    mode.add_argument("--owned-module-run", type=Path, help="test a previously acquired baseline offline")
    parser.add_argument("--sha256")
    args = parser.parse_args()
    if bool(args.owned_module_run) != bool(args.sha256):
        parser.error("--owned-module-run requires its original --sha256")
    ReplayTests.live = None
    with tempfile.TemporaryDirectory(prefix="kn-owned-acquisition-") as directory:
        if args.core_exe:
            ReplayTests.evidence = Path(directory) / "capture.knbench"
            exe = args.core_exe.resolve(strict=True)
            run = subprocess.run([sys.executable, str(RUNNER), "--core-exe", str(exe), "--benchmark-out", str(ReplayTests.evidence)],
                                 capture_output=True, timeout=240, check=True)
            report = json.loads(run.stdout)
            ReplayTests.live, ReplayTests.pin = report, report["benchmark_sha256"]
            with zipfile.ZipFile(ReplayTests.evidence) as archive:
                for name, path in (("collector.bin", exe), ("target.bin", Path(sys.executable)), ("controller.py", RUNNER)):
                    if archive.read(name) != path.read_bytes():
                        raise ValueError("retained bytes differ from the acquired input")
        else:
            ReplayTests.evidence, ReplayTests.pin = args.owned_module_run, args.sha256
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReplayTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
