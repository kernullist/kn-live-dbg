"""Evaluate declared case-level outcomes without running collectors or target code."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import sys


MAX_BYTES = 8 * 1024 * 1024
MAX_CASES = 4096
LAYERS = {"synthetic", "owned_fixture", "authorized_sample", "independent_comparison"}
OUTCOMES = ("positive", "negative", "abstain", "unavailable", "error", "missing")


class InvalidCorpus(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidCorpus(message)


def members(value, keys, where):
    require(type(value) is dict and set(value) == set(keys.split()), f"invalid members: {where}")


def identifier(value, where):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None,
            f"invalid identifier: {where}")


def digest(value, where, nullable=False):
    if nullable and value is None:
        return
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"invalid hash: {where}")


def choice(value, choices, where):
    require(type(value) is str and value in choices, f"invalid value: {where}")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def read_document(path):
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "input exceeds 8 MiB")
    # Reject nonstandard constants and preserve exact-byte corpus identity.
    def invalid_constant(_value):
        raise InvalidCorpus("non-finite JSON constant")
    parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=invalid_constant)
    return parsed, hashlib.sha256(raw).hexdigest()


def validate_corpus(corpus):
    members(corpus, "schema corpus_id cohort_id environment cases", "corpus")
    require(corpus["schema"] == "kn.benchmark_corpus.v1", "unsupported corpus schema")
    identifier(corpus["corpus_id"], "corpus_id")
    identifier(corpus["cohort_id"], "cohort_id")
    env = corpus["environment"]
    members(env, "target_id snapshot_id os_build architecture hvci vbs verifier", "environment")
    identifier(env["target_id"], "target_id")
    identifier(env["snapshot_id"], "snapshot_id")
    if env["os_build"] is not None:
        identifier(env["os_build"], "os_build")
    choice(env["architecture"], {"amd64", "arm64", "x86", "unknown"}, "architecture")
    for key in ("hvci", "vbs", "verifier"):
        require(env[key] is None or type(env[key]) is bool, f"invalid environment flag: {key}")
    cases = corpus["cases"]
    require(type(cases) is list and 1 <= len(cases) <= MAX_CASES, "corpus requires 1..4096 cases")
    by_id = {}
    partition_bindings = {}
    for case in cases:
        members(case, "id family independence_group partition layer task unit artifact_sha256 holes_sha256 truth truth_ref_sha256", "case")
        for key in ("id", "family", "independence_group", "task"):
            identifier(case[key], key)
        choice(case["partition"], {"development", "heldout"}, "partition")
        choice(case["layer"], LAYERS, "layer")
        choice(case["unit"], {"case", "entity", "page", "event", "claim"}, "unit")
        choice(case["truth"], {"positive", "negative", "unknown"}, "truth")
        digest(case["artifact_sha256"], "artifact_sha256")
        digest(case["holes_sha256"], "holes_sha256")
        digest(case["truth_ref_sha256"], "truth_ref_sha256", nullable=case["truth"] == "unknown")
        require(case["id"] not in by_id, "duplicate case id")
        by_id[case["id"]] = case
        for key in ("family", "independence_group", "artifact_sha256"):
            binding = (key, case[key])
            previous = partition_bindings.setdefault(binding, case["partition"])
            require(previous == case["partition"], f"development/heldout leakage: {key}")
    return by_id


def validate_results(results, corpus_hash, cases):
    members(results, "schema corpus_sha256 run_id tool assessments", "results")
    require(results["schema"] == "kn.benchmark_results.v1", "unsupported results schema")
    require(results["corpus_sha256"] == corpus_hash, "results refer to different corpus bytes")
    identifier(results["run_id"], "run_id")
    tool = results["tool"]
    members(tool, "name version binary_sha256 config_sha256", "tool")
    identifier(tool["name"], "tool.name")
    identifier(tool["version"], "tool.version")
    digest(tool["binary_sha256"], "tool.binary_sha256")
    digest(tool["config_sha256"], "tool.config_sha256")
    assessments = results["assessments"]
    require(type(assessments) is list and len(assessments) <= MAX_CASES, "too many assessments")
    by_id = {}
    for row in assessments:
        members(row, "case_id artifact_sha256 holes_sha256 outcome evidence_sha256 elapsed_us", "assessment")
        identifier(row["case_id"], "case_id")
        require(row["case_id"] in cases, "assessment refers to unknown case")
        require(row["case_id"] not in by_id, "duplicate assessment; keep repeated runs separate")
        case = cases[row["case_id"]]
        for key in ("artifact_sha256", "holes_sha256"):
            require(row[key] == case[key], f"assessment scope mismatch: {key}")
        choice(row["outcome"], set(OUTCOMES) - {"missing"}, "outcome")
        digest(row["evidence_sha256"], "evidence_sha256", nullable=row["outcome"] in {"unavailable", "error"})
        elapsed = row["elapsed_us"]
        require(elapsed is None or type(elapsed) is int and 0 <= elapsed <= (1 << 64) - 1, "invalid elapsed_us")
        by_id[row["case_id"]] = row
    return by_id


def ratio(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def summarize(cases, assessments):
    truth = Counter()
    outcomes = Counter()
    observed_truth = Counter()
    tp = fp = tn = unknown_predictions = 0
    elapsed = []
    for case in cases:
        row = assessments.get(case["id"])
        outcome = row["outcome"] if row is not None else "missing"
        truth[case["truth"]] += 1
        outcomes[outcome] += 1
        if outcome in {"positive", "negative", "abstain"}:
            observed_truth[case["truth"]] += 1
        if outcome == "positive":
            tp += case["truth"] == "positive"
            fp += case["truth"] == "negative"
            unknown_predictions += case["truth"] == "unknown"
        tn += outcome == "negative" and case["truth"] == "negative"
        if row is not None and row["elapsed_us"] is not None:
            elapsed.append(row["elapsed_us"])
    elapsed.sort()
    groups = {case["independence_group"] for case in cases}
    return {
        "cases": len(cases),
        "families": len({case["family"] for case in cases}),
        "declared_independence_groups": len(groups),
        "correlated_variants_present": len(groups) < len(cases),
        "truth": {key: truth[key] for key in ("positive", "negative", "unknown")},
        "outcomes": {key: outcomes[key] for key in OUTCOMES},
        "true_positives": tp, "false_positives": fp, "true_negatives": tn,
        "positive_truth_not_detected": truth["positive"] - tp,
        "positive_predictions_with_unknown_truth": unknown_predictions,
        "end_to_end_recall": ratio(tp, truth["positive"]),
        "observable_scope_recall": ratio(tp, observed_truth["positive"]),
        "precision_known_truth": ratio(tp, tp + fp),
        "false_positive_rate_observable": ratio(fp, observed_truth["negative"]),
        "uncertainty_interval": None,
        "uncertainty_reason": "declared_groups_and_imported_assessments_are_not_independently_validated_samples",
        "reported_latency_us": {
            "known": len(elapsed), "unknown": len(cases) - len(elapsed),
            "includes_failed_attempts": True,
            "quantile_method": "nearest_rank",
            "p50": str(elapsed[math.ceil(len(elapsed) * 0.50) - 1]) if elapsed else None,
            "p95": str(elapsed[math.ceil(len(elapsed) * 0.95) - 1]) if elapsed else None,
            "p99": str(elapsed[math.ceil(len(elapsed) * 0.99) - 1]) if elapsed else None,
            "max": str(elapsed[-1]) if elapsed else None,
        },
    }


def evaluate(corpus, corpus_hash, results, results_hash):
    cases = validate_corpus(corpus)
    assessments = validate_results(results, corpus_hash, cases)
    cohorts = defaultdict(list)
    families = defaultdict(list)
    for case in cases.values():
        key = tuple(case[field] for field in ("layer", "partition", "task", "unit"))
        cohorts[key].append(case)
        families[key + (case["family"],)].append(case)
    require(len(cohorts) <= 512, "too many comparison scopes")
    scopes = []
    for key, selected in sorted(cohorts.items()):
        scope = dict(zip(("layer", "partition", "task", "unit"), key))
        scope["metrics"] = summarize(selected, assessments)
        scope["families"] = [
            {"family": family, "metrics": summarize(families[key + (family,)], assessments)}
            for family in sorted({case["family"] for case in selected})
        ]
        scopes.append(scope)
    return {
        "schema": "kn.benchmark_report.v1", "corpus_id": corpus["corpus_id"],
        "cohort_id": corpus["cohort_id"], "run_id": results["run_id"],
        "corpus_sha256": corpus_hash, "results_sha256": results_hash,
        "environment": corpus["environment"], "tool": results["tool"],
        "assessment_basis": "imported_declarations", "artifacts_opened": False,
        "ground_truth_authenticated": False, "target_probed": False,
        "overall_ranking": None, "independent_detection_validation": False,
        "scopes": scopes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    try:
        corpus, corpus_hash = read_document(args.corpus)
        results, results_hash = read_document(args.results)
        report = evaluate(corpus, corpus_hash, results, results_hash)
        raw = (json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
        require(len(raw) <= 16 * 1024 * 1024, "report exceeds 16 MiB")
    except (OSError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        print(f"corpus evaluation failed: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
