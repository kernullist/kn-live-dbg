"""Check independent replay and altered copies of an actual owned Windows workload."""
import argparse
from collections import Counter, defaultdict
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


class PackageTests(unittest.TestCase):
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


class ReplayTests(PackageTests):
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


class PairedCostTests(PackageTests):
    def test_raw_pairs_and_totals(self):
        report = evaluator.evaluate_owned(self.evidence, self.pin)
        fixed, changing = report["scopes"]
        self.assertNotIn("paired_costs", changing)
        cost = fixed["paired_costs"]
        truth = json.loads(self.parts["truth.json"])["worlds"][0]
        wires = [json.loads(line) for line in self.parts["fixed.jsonl"].splitlines()]
        hz = int(self.manifest["qpc_hz"])
        self.assertEqual(cost["collector"], truth["collector"])
        self.assertEqual((cost["interval_clock"], int(cost["frequency_hz"])), ("windows_query_performance_counter", hz))
        requests = [(i, e) for i, e in enumerate(truth["events"], 1) if "arms" in e]
        self.assertEqual(len(requests), len(cost["receipts"]))
        self.assertEqual(len(wires), 2 + 2 * len(requests))
        totals, first = defaultdict(list), Counter()
        counts = Counter()
        for n, ((index, event), link) in enumerate(zip(requests, cost["receipts"])):
            kind = event["kind"]
            order = [arm["mode"] for arm in event["arms"]]
            lead = (int(self.manifest["run_id"][-1], 16) + counts[kind] + int(kind == "dispatch")) % 2
            self.assertEqual(order, ["observe", "idle"] if lead else ["idle", "observe"])
            counts[kind] += 1
            first[kind] += lead
            self.assertEqual((link["kind"], link["truth_event"]), (kind, index))
            pair = {}
            for offset, arm in enumerate(event["arms"]):
                mode = arm["mode"]
                physical = 2 + n * 2 + offset
                self.assertEqual(link["source_reply" if mode == "observe" else "idle_reply"], physical)
                wire = wires[physical - 1]
                self.assertEqual(wire["payload"]["kind"], kind if mode == "observe" else "idle")
                before, after = arm["before"], arm["after"]
                self.assertEqual(before["process"], truth["collector"])
                self.assertEqual(after["process"], truth["collector"])
                start, end = int(before["end_qpc"]), int(after["begin_qpc"])
                native = wire["qpc"]
                self.assertEqual(native["process"], truth["collector"])
                self.assertEqual(int(native["hz"]), hz)
                self.assertLessEqual(start - 1, int(native["begin"]))
                self.assertLessEqual(int(native["end"]), end + 1)
                metrics = {k: int(after[k]) - int(before[k]) for k in ("user_100ns", "kernel_100ns")}
                metrics["roundtrip_ns"] = (end - start) * 10**9 // hz
                metrics["native_service_ns"] = (int(native["end"]) - int(native["begin"])) * 10**9 // hz
                if before["io"] is not None and after["io"] is not None:
                    metrics.update({k: int(after["io"][k]) - int(before["io"][k]) for k in before["io"]})
                if before["working_set_bytes"] is not None and after["working_set_bytes"] is not None:
                    metrics["working_set_change_bytes"] = int(after["working_set_bytes"]) - int(before["working_set_bytes"])
                pair[mode] = metrics
            for k in pair["observe"].keys() & pair["idle"].keys():
                totals[kind, k].append((pair["observe"][k], pair["idle"][k]))
        self.assertEqual((counts["inventory"], counts["dispatch"]), (16, fixed["attempts"]))
        for kind, group in cost["operations"].items():
            self.assertEqual((group["pairs"], group["observe_first"], group["idle_first"]),
                             (counts[kind], first[kind], counts[kind] - first[kind]))
            for k, metric in group["metrics"].items():
                samples = totals[kind, k]
                obs, idle = (sum(x[i] for x in samples) for i in (0, 1))
                self.assertEqual(metric, dict(paired=len(samples), unavailable_pairs=counts[kind]-len(samples),
                                              observed_total=str(obs) if samples else None, idle_total=str(idle) if samples else None,
                                              observed_minus_idle=str(obs-idle) if samples else None))
        for row in fixed["cases"]:
            for k in ("first_qualified_reply", "outcome_reply", "elapsed_reply"):
                if row[k] is not None:
                    native = wires[row[k] - 1]["payload"]
                    self.assertEqual((native["kind"], native["key"]), ("dispatch", truth["events"][row["truth_event"] - 1]["child"]))

    def test_unavailable_counters_and_signed_deltas(self):
        def alter(world):
            for e in world["events"]:
                if "arms" not in e:
                    continue
                for arm in e["arms"]:
                    if arm["mode"] == "idle":
                        arm["before"].update(io=None, io_error=0)
                    for edge in ("before", "after"):
                        arm[edge].update(memory_error=None, working_set_bytes="4096")
                    if arm["mode"] == "observe":
                        arm["after"]["working_set_bytes"] = "0"
            first_inventory = next(e for e in world["events"] if e["kind"] == "inventory")
            idle = next(arm for arm in first_inventory["arms"] if arm["mode"] == "idle")
            idle["after"].update(memory_error=5, working_set_bytes=None)
        pin = self.changed_world("fixed", journal=alter)
        cost = evaluator.evaluate_owned(self.copy, pin)["scopes"][0]["paired_costs"]
        for kind, group in cost["operations"].items():
            n, metrics = group["pairs"], group["metrics"]
            for key in ("read_operations", "write_operations", "other_operations", "read_bytes", "written_bytes", "other_bytes"):
                self.assertEqual(metrics[key], dict(paired=0, unavailable_pairs=n, observed_total=None, idle_total=None, observed_minus_idle=None))
            missing = int(kind == "inventory")
            delta = metrics["working_set_change_bytes"]
            self.assertEqual((delta["paired"], delta["unavailable_pairs"]), (n - missing, missing))
            self.assertEqual(delta["observed_minus_idle"], str(-4096 * (n - missing)))
            self.assertEqual(metrics["roundtrip_ns"]["paired"], n)

    def test_counter_and_clock_contradictions(self):
        def journal(change):
            return lambda world: change(next(e for e in world["events"] if "arms" in e))
        for change, reason in (
            (lambda e: e.pop("arms"), "fields"),
            (lambda e: e["arms"].pop(), "incomplete pair"),
            (lambda e: e["arms"].reverse(), "arm differs"),
            (lambda e: e["arms"][0]["before"].update(process=[100, "1"]), "different generation"),
            (lambda e: e["arms"][0]["after"].update(io_error=5, io={}), "failed I/O query"),
            (lambda e: e["arms"][0]["before"].update(memory_error=5, working_set_bytes="0"), "failed memory query"),
            (lambda e: e["arms"][0]["before"].update(user_100ns=str(2**64-1)), "regressed"),
            (lambda e: e["arms"][0]["before"].update(end_qpc="0"), "nonmonotonic performance"),
            (lambda e: e.update(start=True), "unsigned integer"),
        ):
            with self.subTest(reason=reason):
                self.reject(self.changed_world("fixed", journal=journal(change)), reason)

        def rescale(world):
            for e in world["events"]:
                for arm in e.get("arms", []):
                    for edge in ("before", "after"):
                        for k in ("begin_qpc", "end_qpc"):
                            arm[edge][k] = str(int(arm[edge][k]) * 10)
        self.reject(self.changed_world("fixed", journal=rescale), "outside supervisor")

        def remove_idle_before_inventory(wires):
            for i, (wire, following) in enumerate(zip(wires, wires[1:])):
                if wire["payload"]["kind"] == "idle" and following["payload"]["kind"] == "inventory":
                    del wires[i]
                    return
            self.fail("counterbalanced transcript had no idle-then-inventory pair")

        for change, reason in (
            (lambda wires: wires[1]["qpc"].update(process=[100, "1"]), "different collector"),
            (lambda wires: wires[1]["qpc"].update(hz="0"), "frequencies differ"),
            (lambda wires: wires[1]["qpc"].update(end="0"), "outside supervisor"),
            (lambda wires: wires[1].pop("qpc"), "observer envelope"),
            (remove_idle_before_inventory, "observer reply"),
        ):
            with self.subTest(reason=reason):
                self.reject(self.changed_world("fixed", replies=change), reason)


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
        suite = unittest.TestSuite()
        if args.core_exe:
            exe = args.core_exe.resolve(strict=True)
            for tests, flags in ((ReplayTests, []), (PairedCostTests, ["--paired-costs"])):
                tests.evidence = Path(directory) / (tests.__name__ + ".knbench")
                run = subprocess.run([sys.executable, str(RUNNER), "--core-exe", str(exe), "--benchmark-out", str(tests.evidence), *flags],
                                     capture_output=True, timeout=240, check=True)
                tests.live = json.loads(run.stdout)
                tests.pin = tests.live["benchmark_sha256"]
                with zipfile.ZipFile(tests.evidence) as archive:
                    for name, path in (("collector.bin", exe), ("target.bin", Path(sys.executable)), ("controller.py", RUNNER)):
                        if archive.read(name) != path.read_bytes():
                            raise ValueError("retained bytes differ from the acquired input")
                suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(tests))
        else:
            manifest, _ = package.read_bundle(args.owned_module_run, args.sha256, evaluator.decode_document)
            tests = PairedCostTests if manifest["schema"] == package.PAIRED_SCHEMA else ReplayTests
            tests.evidence, tests.pin = args.owned_module_run, args.sha256
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(tests))
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
