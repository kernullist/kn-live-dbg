"""Synthetic controls for imported benchmark declarations, not detection samples."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
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
                         b'{} trailing', b'[' * 1500 + b'0' + b']' * 1500):
                path.write_bytes(data)
                with self.assertRaises((ValueError, RecursionError)):
                    EVALUATOR.read_document(path)
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example-directory", type=Path)
    arguments = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CorpusTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    if arguments.example_directory is not None:
        arguments.example_directory.mkdir(parents=True, exist_ok=False)
        write_fixture(arguments.example_directory, *fixture())
        print(f"Synthetic declarations written to {arguments.example_directory}")
