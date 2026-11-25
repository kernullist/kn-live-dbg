"""Synthetic controls for imported benchmark declarations, not detection samples."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("evaluate-corpus.py")
SPEC = importlib.util.spec_from_file_location("corpus_evaluator", SCRIPT)
EVALUATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVALUATOR)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def fixture():
    corpus = {
        "schema": "kn.benchmark_corpus.v1", "corpus_id": "synthetic-corpus", "cohort_id": "fixed-cohort",
        "environment": {"target_id": "synthetic", "snapshot_id": "synthetic-snapshot", "os_build": None,
                        "architecture": "unknown", "hvci": None, "vbs": None, "verifier": None},
        "cases": [],
    }
    results = {
        "schema": "kn.benchmark_results.v1", "corpus_sha256": "", "run_id": "synthetic-run",
        "tool": {"name": "synthetic-assessor", "version": "1", "binary_sha256": sha("no-real-binary"),
                 "config_sha256": sha("fixture-policy")}, "assessments": [],
    }
    # Hand-calculated oracle: P=7, observed P=4, TP=2, FP=1, observed N=3.
    controls = [("positive", item) for item in ("positive", "positive", "negative", "abstain", "unavailable", "error", "missing")]
    controls += [("negative", item) for item in ("positive", "negative", "abstain", "unavailable", "missing")]
    controls += [("unknown", "positive"), ("unknown", "negative")]
    for index, (truth, outcome) in enumerate(controls):
        identity = f"case-{index}"
        case = {
            "id": identity, "family": "synthetic-family", "independence_group": f"group-{max(index, 1)}",
            "partition": "heldout", "layer": "synthetic", "task": "image-range-mismatch", "unit": "case",
            "artifact_sha256": sha(identity), "holes_sha256": sha("no-holes"), "truth": truth,
            "truth_ref_sha256": sha("synthetic-truth-" + identity) if truth != "unknown" else None,
        }
        corpus["cases"].append(case)
        if outcome != "missing":
            results["assessments"].append({
                "case_id": identity, "artifact_sha256": case["artifact_sha256"],
                "holes_sha256": case["holes_sha256"], "outcome": outcome,
                "evidence_sha256": sha("synthetic-evidence-" + identity), "elapsed_us": index * 10,
            })
    bind(corpus, results)
    return corpus, results


def bind(corpus, results):
    results["corpus_sha256"] = hashlib.sha256(encode(corpus)).hexdigest()


def evaluate(corpus, results):
    return EVALUATOR.evaluate(corpus, hashlib.sha256(encode(corpus)).hexdigest(), results,
                              hashlib.sha256(encode(results)).hexdigest())


def write_fixture(directory, corpus, results):
    (directory / "corpus.json").write_bytes(encode(corpus))
    (directory / "results.json").write_bytes(encode(results))


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.corpus, self.results = fixture()

    def reject(self):
        bind(self.corpus, self.results)
        with self.assertRaises(EVALUATOR.InvalidCorpus):
            evaluate(self.corpus, self.results)

    def test_known_denominators_and_unknown_truth(self):
        report = evaluate(self.corpus, self.results)
        self.assertFalse(report["independent_detection_validation"])
        self.assertFalse(report["target_probed"])
        self.assertFalse(report["artifacts_opened"])
        self.assertIsNone(report["overall_ranking"])
        row = report["scopes"][0]["metrics"]
        self.assertEqual(row["truth"], {"positive": 7, "negative": 5, "unknown": 2})
        self.assertEqual(row["outcomes"], {"positive": 4, "negative": 3, "abstain": 2, "unavailable": 2, "error": 1, "missing": 2})
        for name, numerator, denominator in (("end_to_end_recall", 2, 7), ("observable_scope_recall", 2, 4),
                                              ("precision_known_truth", 2, 3), ("false_positive_rate_observable", 1, 3)):
            self.assertEqual(row[name], {"numerator": numerator, "denominator": denominator, "value": numerator / denominator})
        self.assertEqual(row["positive_truth_not_detected"], 5)
        self.assertEqual(row["positive_predictions_with_unknown_truth"], 1)
        self.assertEqual(row["declared_independence_groups"], 13)
        self.assertTrue(row["correlated_variants_present"])
        self.assertIsNone(row["uncertainty_interval"])
        self.assertEqual((row["reported_latency_us"]["known"], row["reported_latency_us"]["unknown"]), (12, 2))
        self.assertEqual((row["reported_latency_us"]["p50"], row["reported_latency_us"]["p95"]), ("50", "130"))

    def test_missing_results_stay_in_denominator(self):
        self.results["assessments"] = []
        metrics = evaluate(self.corpus, self.results)["scopes"][0]["metrics"]
        self.assertEqual(metrics["end_to_end_recall"], {"numerator": 0, "denominator": 7, "value": 0.0})
        self.assertEqual(metrics["outcomes"]["missing"], 14)
        self.assertIsNone(metrics["observable_scope_recall"]["value"])
        self.assertIsNone(metrics["precision_known_truth"]["value"])
        self.assertIsNone(metrics["reported_latency_us"]["p99"])

    def test_scopes_and_layers_never_merge(self):
        for index, case in enumerate(self.corpus["cases"]):
            case["family"] = f"family-{index}"
            case["independence_group"] = f"group-{index}"
        for key, value in (("layer", "owned_fixture"), ("task", "process-cross-view"), ("unit", "page"), ("partition", "development")):
            self.corpus["cases"][0][key] = value
            bind(self.corpus, self.results)
            report = evaluate(self.corpus, self.results)
            self.assertEqual(len(report["scopes"]), 2)
            self.assertEqual(sorted(row["metrics"]["cases"] for row in report["scopes"]), [1, 13])

    def test_family_counts_and_order_invariance(self):
        self.corpus["cases"][0]["family"] = "second-family"
        bind(self.corpus, self.results)
        expected = evaluate(self.corpus, self.results)["scopes"]
        self.corpus["cases"].reverse()
        self.results["assessments"].reverse()
        bind(self.corpus, self.results)
        self.assertEqual(evaluate(self.corpus, self.results)["scopes"], expected)
        self.assertEqual(len(expected[0]["families"]), 2)

    def test_partition_leakage(self):
        original = copy.deepcopy(self.corpus)
        for field in ("family", "independence_group", "artifact_sha256"):
            with self.subTest(field=field):
                self.corpus = copy.deepcopy(original)
                first, second = self.corpus["cases"][:2]
                first.update(partition="development", family="development-family", independence_group="development-group")
                first[field] = second[field]
                self.reject()

    def test_registered_publisher_file_and_acquisition_layout(self):
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"] = corpus["cases"][:2]
        first, second = corpus["cases"]
        first.update(task="publisher-target-bytes-match", unit="case", publisher_file_sha256=sha("reference"), artifact_layout="packed")
        with self.assertRaises(EVALUATOR.InvalidCorpus):
            EVALUATOR.validate_corpus(corpus)
        corpus["schema"] = "kn.benchmark_corpus.v2"
        self.assertEqual(len(EVALUATOR.validate_corpus(corpus)), 2)
        for change in (dict(artifact_layout="other"), dict(publisher_file_sha256=None), dict(unit="page"), dict(task="other")):
            with self.subTest(change=change), self.assertRaises(EVALUATOR.InvalidCorpus):
                EVALUATOR.validate_corpus(dict(corpus, cases=[{**first, **change}]))
        for omitted in ("publisher_file_sha256", "artifact_layout"):
            with self.assertRaises(EVALUATOR.InvalidCorpus):
                EVALUATOR.validate_corpus(dict(corpus, cases=[{k:v for k,v in first.items() if k != omitted}]))
        first.update(partition="development", family="dev", independence_group="dev")
        second.update(partition="heldout", artifact_sha256=first["publisher_file_sha256"])
        for order in ([first, second], [second, first]):
            with self.assertRaisesRegex(EVALUATOR.InvalidCorpus, "leakage"):
                EVALUATOR.validate_corpus(dict(corpus, cases=order))

    def test_duplicate_and_unknown_cases(self):
        self.corpus["cases"].append(copy.deepcopy(self.corpus["cases"][0]))
        self.reject()
        self.corpus, self.results = fixture()
        self.results["assessments"].append(copy.deepcopy(self.results["assessments"][0]))
        self.reject()
        self.results["assessments"][-1]["case_id"] = "unknown-case"
        self.reject()

    def test_exact_corpus_and_scope_identity(self):
        self.results["corpus_sha256"] = "0" * 64
        with self.assertRaises(EVALUATOR.InvalidCorpus):
            evaluate(self.corpus, self.results)
        for field in ("artifact_sha256", "holes_sha256"):
            self.corpus, self.results = fixture()
            self.results["assessments"][0][field] = "0" * 64
            self.reject()

    def test_closed_members_and_required_truth(self):
        for where in ("root", "environment", "case", "tool", "assessment"):
            with self.subTest(where=where):
                self.corpus, self.results = fixture()
                obj = {"root": self.corpus, "environment": self.corpus["environment"], "case": self.corpus["cases"][0],
                       "tool": self.results["tool"], "assessment": self.results["assessments"][0]}[where]
                obj["unexpected"] = True
                self.reject()
        self.corpus, self.results = fixture()
        self.corpus["cases"][0]["truth_ref_sha256"] = None
        self.reject()
        self.corpus, self.results = fixture()
        self.results["assessments"][0]["evidence_sha256"] = None
        self.reject()

    def test_scalar_types_bounds_and_surrogates(self):
        for value in (-1, True, 1.5, 1 << 64, "1"):
            with self.subTest(elapsed=value):
                self.corpus, self.results = fixture()
                self.results["assessments"][0]["elapsed_us"] = value
                self.reject()
        for key, value in (("layer", []), ("truth", "malicious"), ("id", "\ud800"), ("family", "a" * 129),
                           ("artifact_sha256", "F" * 64), ("unit", "assertion")):
            self.corpus, self.results = fixture()
            self.corpus["cases"][0][key] = value
            with self.assertRaises(EVALUATOR.InvalidCorpus):
                EVALUATOR.validate_corpus(self.corpus)
        self.corpus, self.results = fixture()
        self.corpus["environment"]["hvci"] = 1
        self.reject()
        self.corpus["cases"] = []
        self.reject()
        self.corpus["cases"] = [fixture()[0]["cases"][0]] * (EVALUATOR.MAX_CASES + 1)
        self.reject()

    def test_large_latency_and_failed_attempts(self):
        self.results["assessments"][0]["elapsed_us"] = (1 << 64) - 1
        self.results["assessments"][0]["outcome"] = "error"
        row = evaluate(self.corpus, self.results)["scopes"][0]["metrics"]["reported_latency_us"]
        self.assertEqual(row["max"], "18446744073709551615")
        self.assertEqual(row["p99"], row["max"])

    def test_collection_and_scope_boundaries(self):
        template = self.corpus["cases"][0]
        self.corpus["cases"] = []
        self.results["assessments"] = []
        for index in range(EVALUATOR.MAX_CASES):
            case = copy.deepcopy(template)
            case["id"] = f"bounded-case-{index}"
            self.corpus["cases"].append(case)
        bind(self.corpus, self.results)
        row = evaluate(self.corpus, self.results)["scopes"][0]["metrics"]
        self.assertEqual(row["cases"], 4096)
        self.assertEqual(row["outcomes"]["missing"], 4096)
        self.assertEqual(row["declared_independence_groups"], 1)
        for index, case in enumerate(self.corpus["cases"]):
            case["task"] = f"scope-{index % 512}"
        bind(self.corpus, self.results)
        self.assertEqual(len(evaluate(self.corpus, self.results)["scopes"]), 512)
        self.corpus["cases"][-1]["task"] = "scope-over-limit"
        self.reject()

    def test_strict_json_and_size_limits(self):
        with tempfile.TemporaryDirectory(prefix="kn-corpus-") as directory:
            path = Path(directory) / "input.json"
            for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xef\xbb\xbf{}', b'\xff',
                         b'{} trailing', b'1e500', b'[' * 1500 + b'0' + b']' * 1500):
                path.write_bytes(data)
                with self.assertRaises((ValueError, RecursionError)):
                    EVALUATOR.read_document(path)
            depth = EVALUATOR.MAX_JSON_DEPTH
            value = ('["\\]' * depth)
            data = b'[' * depth + json.dumps(value).encode() + b']' * depth
            self.assertIsInstance(EVALUATOR.decode_document(data), list)
            with self.assertRaises(EVALUATOR.InvalidCorpus):
                EVALUATOR.decode_document(b'[' + data + b']')
            data = b'{}' + b' ' * (EVALUATOR.MAX_BYTES - 2)
            path.write_bytes(data)
            self.assertEqual(EVALUATOR.read_document(path)[0], {})
            path.write_bytes(data + b' ')
            with self.assertRaises(EVALUATOR.InvalidCorpus):
                EVALUATOR.read_document(path)

    def test_public_cli_and_failure_stdout(self):
        with tempfile.TemporaryDirectory(prefix="kn-corpus-") as directory:
            root = Path(directory)
            write_fixture(root, self.corpus, self.results)
            command = [sys.executable, str(SCRIPT), "--corpus", str(root / "corpus.json"), "--results", str(root / "results.json")]
            result = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), evaluate(self.corpus, self.results))
            (root / "corpus.json").write_bytes((root / "corpus.json").read_bytes() + b' ')
            result = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'different corpus bytes', result.stderr)
            (root / "results.json").unlink()
            result = subprocess.run(command, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b'')


class RetainedCorpusTests(unittest.TestCase):
    def test_writer_member_ceiling_by_corpus_version(self):
        import retained_corpus as archive
        destination = self.root / "oversized.knbench"
        for extended, count in ((False, 16387), (True, 20483)):
            with self.assertRaisesRegex(ValueError, "too many original inputs"):
                archive.seal(destination, b"plan", b"results", [self.root / "unused"] * count, set(),
                             with_publisher_files=extended)
        self.assertFalse(destination.exists())

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="kn-corpus-originals-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.corpus, self.results = fixture()
        self.inputs = {}

        def original(data):
            pin = hashlib.sha256(data).hexdigest()
            path = self.root / (pin + ".bin")
            path.write_bytes(data)
            self.inputs[pin] = path
            return pin

        for case in self.corpus["cases"]:
            key = case["id"]
            original(key.encode())
            case["holes_sha256"] = original(b"")
            if case["truth_ref_sha256"]:
                original(("synthetic-truth-" + key).encode())
        for assessment in self.results["assessments"]:
            assessment["holes_sha256"] = hashlib.sha256(b"").hexdigest()
            original(("synthetic-evidence-" + assessment["case_id"]).encode())
        original(b"no-real-binary")
        self.results["tool"]["config_sha256"] = original(bytes(range(256)) * 4100)
        bind(self.corpus, self.results)
        write_fixture(self.root, self.corpus, self.results)
        self.plan = self.results["corpus_sha256"]
        self.archive = self.root / "data.knbench"

    def pack(self, paths):
        args = ["--corpus", self.root / "corpus.json", "--results", self.root / "results.json",
                "--write-archive", self.archive, "--plan-sha256", self.plan]
        for path in paths:
            args.extend(("--original", path))
        return args

    def replay(self, plan=None):
        pin = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        return ["--archive-corpus", self.archive, "--sha256", pin, "--plan-sha256", self.plan if plan is None else plan]

    def cli(self, args, expected=0):
        p = subprocess.run([sys.executable, "-B", SCRIPT, *args], capture_output=True, timeout=30)
        self.assertEqual(p.returncode, expected, p.stderr[:500])
        if expected:
            self.assertEqual(p.stdout, b"")
            self.assertNotIn(b"Traceback", p.stderr)
            return p
        self.assertFalse(p.stderr)
        return json.loads(p.stdout)

    def test_retained_bytes_and_legacy_scores_after_source_removal(self):
        sources = list(self.inputs.values())
        receipt = self.cli(self.pack([*sources, sources[0]]))
        self.assertEqual(receipt["retained_objects"], len(sources))
        self.assertEqual(receipt["package_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        raw = self.archive.read_bytes()
        magic, cs, rs, count = struct.unpack_from("<8sIII", raw)
        self.assertEqual((magic, count), (b"KNCORP1\0", len(sources)))
        offset = 20
        self.assertEqual(raw[offset:offset+cs], encode(self.corpus))
        offset += cs
        self.assertEqual(raw[offset:offset+rs], encode(self.results))
        offset += rs
        seen = set()
        for _ in range(count):
            key, n = struct.unpack_from("<32sQ", raw, offset)
            offset += 40
            self.assertEqual(raw[offset:offset+n], self.inputs[key.hex()].read_bytes())
            seen.add(key.hex())
            offset += n
        self.assertEqual((seen, offset), (set(self.inputs), len(raw)))
        for path in [*sources, self.root / "corpus.json", self.root / "results.json"]:
            path.unlink()
        report = self.cli(self.replay())
        self.assertEqual(report["scopes"], evaluate(self.corpus, self.results)["scopes"])
        self.assertEqual(report["coverage"]["missing_sha256"], [])
        self.assertEqual(report["assessments_with_originals_per_planned_case"]["numerator"], 12)
        self.assertEqual(report["assessments_with_originals_per_planned_case"]["denominator"], 14)
        self.assertEqual(report["coverage"]["case_originals"]["truth_ref_sha256"]["not_referenced"], 2)
        self.assertFalse(report["ground_truth_authenticated"] or report["outcomes_independently_replayed"])

    def test_missing_originals_keep_declared_truth_and_outcomes(self):
        cases = self.corpus["cases"]
        absent = {cases[0]["artifact_sha256"], cases[1]["truth_ref_sha256"], self.results["assessments"][2]["evidence_sha256"]}
        self.cli(self.pack([p for k, p in self.inputs.items() if k not in absent]))
        report = self.cli(self.replay())
        scope = report["scopes"][0]["metrics"]
        self.assertEqual((scope["end_to_end_recall"]["numerator"], scope["end_to_end_recall"]["denominator"]), (0, 7))
        self.assertEqual(scope["outcomes"]["missing"], 5)
        self.assertEqual(report["coverage"]["missing_sha256"], sorted(absent))
        for row, role, original in zip(report["coverage"]["cases"], ("artifact_sha256", "truth_ref_sha256", "evidence_sha256"),
                                       ("positive", "positive", "negative")):
            self.assertEqual(row["original_status"][role], "missing")
            self.assertEqual(row["declared_outcome"], original)
            self.assertFalse(row["assessment_with_originals"])

    def test_empty_retention_and_missing_tool(self):
        self.cli(self.pack([]))
        report = self.cli(self.replay())
        scope = report["scopes"][0]["metrics"]
        self.assertEqual((scope["cases"], scope["outcomes"]["missing"]), (14, 14))
        self.assertIsNone(scope["observable_scope_recall"]["value"])
        self.assertEqual(report["coverage"]["tool_originals"]["binary_sha256"], "missing")
        self.archive.unlink()
        missing = self.results["tool"]["config_sha256"]
        self.cli(self.pack([p for pin, p in self.inputs.items() if pin != missing]))
        report = self.cli(self.replay())
        self.assertEqual(report["assessments_with_originals_per_submitted"]["numerator"], 0)
        self.assertEqual(report["coverage"]["missing_sha256"], [missing])

    def test_original_recovery_validates_whole_archive_and_preserves_files(self):
        case = self.corpus["cases"][0]
        key, empty = case["artifact_sha256"], case["holes_sha256"]
        config = self.results["tool"]["config_sha256"]
        originals = {pin: self.inputs[pin].read_bytes() for pin in (key, empty, config)}
        self.cli(self.pack([self.inputs[pin] for pin in originals]))
        for pin, data in originals.items():
            self.inputs[pin].unlink()
            target = self.root / (pin + ".recovered")
            flags = [*self.replay(), "--get-original", pin, "--destination", target]
            record = self.cli(flags)
            self.assertEqual((record["original_sha256"], record["original_bytes"], target.read_bytes()), (pin, len(data), data))
            self.cli(flags, 2)
            self.assertEqual(target.read_bytes(), data)
        target = self.root / "not-published"
        self.cli([*self.replay(), "--get-original", case["truth_ref_sha256"], "--destination", target], 2)
        self.assertFalse(target.exists())
        self.archive.write_bytes(self.archive.read_bytes()[:-1])
        self.cli([*self.replay(), "--get-original", key, "--destination", target], 2)
        self.assertFalse(target.exists())
        self.assertEqual(list(self.root.glob(".knbench-*.tmp")), [])

    def test_changed_member_during_recovery_is_not_published(self):
        import retained_corpus as archive
        key = self.results["tool"]["config_sha256"]
        receipt = self.cli(self.pack([self.inputs[key]]))
        destination = self.root / "recovered.bin"
        with archive.regular_file(self.archive) as source:
            _, _, members = archive.read(source, receipt["package_sha256"], self.plan)
            start, size = members[key]
            with self.archive.open("r+b", buffering=0) as changed:
                changed.seek(start + size // 2)
                byte = changed.read(1)
                changed.seek(-1, os.SEEK_CUR)
                changed.write(bytes([byte[0] ^ 1]))
            with self.assertRaisesRegex(ValueError, "changed during recovery"):
                archive.restore(source, destination, key, members[key])
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".knbench-*.tmp")), [])

    def test_resealed_corruption_and_plan_binding(self):
        one = next(iter(self.inputs.values()))
        self.cli(self.pack([one]))
        pristine = self.archive.read_bytes()
        _, cs, rs, n = struct.unpack_from("<8sIII", pristine)
        offset = 20 + cs + rs
        row = pristine[offset:]
        self.cli(self.replay("0" * 64), 2)
        flags = self.replay()
        flags[3] = "0" * 64
        self.cli(flags, 2)
        bad_obj = b"outside the admitted case"
        for raw in (pristine[:-1], pristine + b"x", pristine[:-1] + bytes([pristine[-1] ^ 1]),
                    pristine[:offset+32] + struct.pack("<Q", (1 << 64) - 1) + row[40:],
                    pristine[:16] + struct.pack("<I", n + 1) + pristine[20:] + row,
                    pristine[:offset] + struct.pack("<32sQ", hashlib.sha256(bad_obj).digest(), len(bad_obj)) + bad_obj):
            with self.subTest(size=len(raw)):
                self.archive.write_bytes(raw)
                self.cli(self.replay(), 2)
        self.archive.unlink()
        alien = self.root / "unrelated.bin"
        alien.write_bytes(bad_obj)
        self.cli(self.pack([one, alien]), 2)
        self.assertFalse(self.archive.exists())
        self.assertEqual(list(self.root.glob(".knbench-*.tmp")), [])

    def test_publication_race_and_output_aliases(self):
        source = next(iter(self.inputs.values()))
        command = [sys.executable, "-B", SCRIPT, *self.pack([source])]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as a, \
                subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as b:
            outputs = [p.communicate(timeout=30) for p in (a, b)]
            self.assertEqual(sorted((a.returncode, b.returncode)), [0, 2])
            self.assertEqual(sum(bool(out) for out, _ in outputs), 1)
        self.cli(self.replay())
        original = self.archive.read_bytes()
        alias = self.root / "alias"
        os.link(self.archive, alias)
        for flags in (self.replay(), ["--archive-co=" + str(self.archive), "--bogus"], self.pack([source])):
            for channel in ("stdout", "stderr"):
                with alias.open("ab") as sink:
                    streams = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, channel: sink}
                    p = subprocess.run([sys.executable, "-B", SCRIPT, *flags], **streams, timeout=30)
                self.assertEqual(p.returncode, 2)
                self.assertEqual(original, self.archive.read_bytes())
        self.assertEqual(list(self.root.glob(".knbench-*.tmp")), [])

    def test_original_file_list_and_early_diagnostic_alias(self):
        folder = self.root / "selected originals"
        folder.mkdir()
        pin = self.corpus["cases"][0]["artifact_sha256"]
        source = folder / "case one.bin"
        source.write_bytes(self.inputs[pin].read_bytes())
        filelist = folder / "originals.json"
        filelist.write_bytes(encode(dict(schema="kn.benchmark_original_files.v1", original_files=[source.name, source.name])))
        extra = ["--file-list", filelist]
        self.assertEqual(self.cli([*self.pack([]), *extra])["retained_objects"], 1)
        self.assertNotIn(pin, self.cli(self.replay())["coverage"]["missing_sha256"])
        alias = folder / "alias"
        os.link(source, alias)
        for flags in (["--help", *extra], ["--bogus", "--fi=" + str(filelist)], [*self.pack([]), *extra]):
            with alias.open("ab") as sink:
                p = subprocess.run([sys.executable, "-B", SCRIPT, *flags], stdout=sink, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual((p.returncode, source.read_bytes()), (2, self.inputs[pin].read_bytes()))
        self.archive.unlink()
        filelist.write_bytes(encode(dict(schema="kn.benchmark_original_files.v1", original_files=[source.name, 0])))
        self.cli([*self.pack([]), *extra], 2)
        self.assertFalse(self.archive.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example-directory", type=Path)
    arguments = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    if arguments.example_directory is not None:
        arguments.example_directory.mkdir(parents=True, exist_ok=False)
        write_fixture(arguments.example_directory, *fixture())
        print(f"Synthetic declarations written to {arguments.example_directory}")
