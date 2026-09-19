"""Validate owned-fixture evidence without promoting it to competitive proof."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate(report):
    if report.get("schema") != "kmon.hunting.validation.v1":
        raise ValueError("unsupported evidence schema")
    for field in ("competitive_ranking_supported", "independent_analyst_audit", "live_kernel_channels_tested"):
        if report.get(field) is not False:
            raise ValueError("owned-fixture profile cannot establish " + field)
    if type(report.get("real_cheat_samples")) is not int or report["real_cheat_samples"] != 0:
        raise ValueError("owned fixtures cannot be counted as real cheat samples")
    for field in ("fixture_sha256", "replay_sha256", "synthetic_replay_sha256"):
        digest = report.get(field, "")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid evidence digest: " + field)
    runs = report.get("runs")
    if not isinstance(runs, list) or len(runs) != 4:
        raise ValueError("four labeled owned fixtures are required")
    truths = {
        "clean": "clean_image",
        "modified": "one_byte_executable_data_section_change",
        "text": "one_byte_text_function_change",
        "jit": "benign_private_rx",
    }
    seen = set()
    for run in runs:
        mode = run.get("mode")
        if mode not in truths or mode in seen or run.get("ground_truth") != truths[mode]:
            raise ValueError("missing, repeated or mislabeled fixture")
        seen.add(mode)
        probe = run.get("kmon_component", {})
        pages = probe.get("modified_pages")
        if run.get("malicious_sample") is not False or probe.get("complete") is not True:
            raise ValueError("fixture classification or scan coverage is invalid")
        if probe.get("scope") != "main_image_executable_pages" or type(pages) is not int or pages < 0:
            raise ValueError("invalid component scope or modified-page count")
        if (pages > 0) != (mode in ("modified", "text")):
            raise ValueError("fixture result does not match ground truth")
        if report.get("baseline_version") != "not_run":
            if report.get("baseline_sha256") != "9f3ff2884a2c61006cd0a92b7572a815b8dc17012be7747a6abd6ca07c503a3b":
                raise ValueError("baseline release digest mismatch")
            scan = run.get("baseline", {}).get("scan_report", {})
            if scan.get("scanner_version") != "0.4.1.1" or scan.get("scanned", {}).get("errors") != 0:
                raise ValueError("baseline failed or used an unexpected version")
    return {
        "component_evidence": "validated",
        "competitive_ranking_supported": False,
        "missing": ["real_cheat_corpus", "live_kernel_channel_trials", "long_running_normal_host_controls",
                    "matched_full_tool_benchmarks", "independent_analyst_audit"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--require-competitive", action="store_true")
    args = parser.parse_args()
    try:
        if args.report.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("report exceeds 4 MiB")
        with args.report.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("report exceeds 4 MiB")
        report = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)
        if not isinstance(report, dict):
            raise ValueError("report must be an object")
        result = validate(report)
        result["report_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, sort_keys=True))
        return 3 if args.require_competitive else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
        print("[kmon.evidence] invalid: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
