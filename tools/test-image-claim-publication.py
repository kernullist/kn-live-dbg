"""Independent publication binding, exact-policy and interrupted-root controls."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from image_claim_oracle import check_original_claim, check_report, unpack_recipe


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def seal(value, field):
    value[field] = hashlib.sha256(canonical(value["payload"])).hexdigest()
    return canonical(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    runs = 0

    def replay(case, expected="replayed", current=False, original_status=None):
        nonlocal runs
        command = [str(args.exe.resolve())] + (["--offline", "!kmon", "replay-image"] if args.product else ["--report"])
        before = {p.name: p.read_bytes() for p in case.iterdir() if p.is_file()}
        result = subprocess.run(command + [str(case.resolve())] + (["/current"] if current else []),
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        report = json.loads(result.stdout)
        assert report["status"] == expected, (case.name, report["status"], expected, result.stderr)
        assert result.returncode == (0 if expected in {"replayed", "reanalyzed"} else 1)
        assert before == {p.name: p.read_bytes() for p in case.iterdir() if p.is_file()}, "replay preserves every original"
        original = report["original_claim_replay"]
        if original_status:
            assert original["status"] == original_status, (case.name, original)
        if expected in {"replayed", "reanalyzed"}:
            document = json.loads(before["recipe.knverify"])
            recipe = unpack_recipe(document)
            check_original_claim(document, report)
            check_report(recipe, before[recipe["payload"]["reference_sha256"] + ".knblob"], report)
        else:
            assert not original["original_claim_policy_reproduced"] and not original["assessment_matches_current_report"]
            assert report["claim_assessment"] is None and report["proof"] is None
        runs += 1
        return report

    for name in ("clean", "modified", "max-differences", "observed", "observed-modified", "observed-no-consent",
                 "observed-budget", "unstable", "sparse", "wrong-pdb", "alias", "header-changed"):
        case = args.fixtures / name
        original = json.loads((case / "recipe.knverify").read_bytes())
        assert original["schema"] == "kn.image_claim_publication.v1", "new capture must publish original claims"
        replay(case, original_status="reproduced")
        replay(case, "reanalyzed", True, "not_requested")

    with tempfile.TemporaryDirectory(prefix="claim-publication-", dir=args.fixtures) as temporary:
        root = Path(temporary)
        baseline = json.loads((args.fixtures / "modified" / "recipe.knverify").read_bytes())
        for mutation in ("verdict", "ranges", "ledger", "extra_claim", "registry", "policy", "foreign_recipe",
                         "foreign_reference", "inner_digest", "missing_report", "extra_root", "oversized_report", "bad_digest"):
            case = root / mutation
            shutil.copytree(args.fixtures / "modified", case)
            document = copy.deepcopy(baseline)
            report = document["payload"]["recorded_claim"]
            expected = "recorded_claim_assessment_mismatch"
            original_status = "assessment_mismatch"
            can_reanalyze = True
            if mutation == "verdict":
                report["claims"][1]["status"] = "unfulfilled"
            elif mutation == "ranges":
                report["claims"][1]["supported_ranges"] = []
            elif mutation == "ledger":
                report["ledgers"]["trust"]["collector_authenticated"] = True
            elif mutation == "extra_claim":
                report["claims"].append({"claim": "unverified_imported_claim", "status": "supported"})
            elif mutation in {"registry", "policy"}:
                report[mutation] = "unknown.policy.v999"
                expected, original_status = "recorded_claim_policy_unavailable", "policy_unavailable"
            else:
                expected, original_status, can_reanalyze = "recipe_unavailable_or_corrupt", "publication_unavailable_or_corrupt", False
                if mutation == "foreign_recipe":
                    report["capture_sha256"] = "0" * 64
                elif mutation == "foreign_reference":
                    report["reference_sha256"] = "0" * 64
                elif mutation == "inner_digest":
                    document["payload"]["recipe"]["recipe_sha256"] = "0" * 64
                elif mutation == "missing_report":
                    del document["payload"]["recorded_claim"]
                elif mutation == "extra_root":
                    document["ignored"] = "not-permitted"
                elif mutation == "oversized_report":
                    report["padding"] = "x" * (256 * 1024)
            encoded = seal(document, "publication_sha256")
            if mutation == "bad_digest":
                document["publication_sha256"] = "0" * 64
                encoded = canonical(document)
            (case / "recipe.knverify").write_bytes(encoded)
            replay(case, expected, original_status=original_status)
            replay(case, "reanalyzed" if can_reanalyze else expected, True,
                   "not_requested" if can_reanalyze else original_status)
        for version, source in ((1, "modified"), (2, "observed-modified")):
            case = root / f"legacy-v{version}"
            shutil.copytree(args.fixtures / source, case)
            document = unpack_recipe(json.loads((case / "recipe.knverify").read_bytes()))
            assert document["schema"] == f"kn.image_recipe.v{version}"
            (case / "recipe.knverify").write_bytes(canonical(document))
            replay(case, original_status="not_recorded")
            replay(case, "reanalyzed", True, "not_recorded")
        case = root / "interrupted"
        shutil.copytree(args.fixtures / "modified", case)
        final = case / "recipe.knverify"
        saved = final.read_bytes()
        final.rename(case / "recipe.knverify.pending-owned-control")
        replay(case, "recipe_unavailable_or_corrupt")
        for length in (1, len(saved) // 2, len(saved) - 1):
            final.write_bytes(saved[:length])
            replay(case, "recipe_unavailable_or_corrupt")
        final.write_bytes(saved)
        blob = case / (baseline["payload"]["recipe"]["payload"]["reference_sha256"] + ".knblob")
        blob.unlink()
        replay(case, "reference_missing_or_unreadable")
    print(f"Image claim publication passed: {runs} replay controls; product={args.product}; exact roots, legacy, policy and interrupted publication")


if __name__ == "__main__":
    main()
