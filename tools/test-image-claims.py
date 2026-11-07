"""Check direct image claims against original owned fixtures in both replay modes."""
import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from image_claim_oracle import check_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    states, runs = Counter(), 0

    def run(case, current=False, expected="replayed"):
        nonlocal runs
        recipe_path = case / "recipe.knverify"
        before = recipe_path.read_bytes()
        recipe = json.loads(before)
        command = [str(args.exe.resolve())] + (["--offline", "!kmon", "replay-image"] if args.product else ["--report"])
        result = subprocess.run(command + [str(case.resolve())] + (["/current"] if current else []),
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        document = json.loads(result.stdout)
        assert document["status"] == expected, (case.name, current, document["status"], expected)
        assert result.returncode == (0 if expected in ("replayed", "reanalyzed") else 1), result.stderr
        assert recipe_path.read_bytes() == before, "claim evaluation cannot rewrite its original input"
        if expected in ("replayed", "reanalyzed"):
            blob = (case / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes()
            states.update(check_report(recipe, blob, document))
        else:
            assert document["claim_assessment"] is None and document["proof"] is None
        runs += 1
        return document

    for name in ("clean", "modified", "max-differences", "observed", "observed-modified", "observed-no-consent",
                 "observed-budget", "unstable", "sparse", "wrong-pdb", "alias", "header-changed"):
        for current in (False, True):
            result = run(args.fixtures / name, current, "reanalyzed" if current else "replayed")
            if name == "max-differences":
                assert len(result["claim_assessment"]["claims"][1]["supported_ranges"]) == 2048
    run(args.fixtures / "no-confirmation", expected="recorded_read_set_mismatch")
    missing = run(args.fixtures / "no-confirmation", True, "reanalyzed")
    assert all(claim["status"] == "unfulfilled" for claim in missing["claim_assessment"]["claims"])
    with tempfile.TemporaryDirectory(prefix="claim-mutations-", dir=args.fixtures) as temporary:
        case = Path(temporary) / "case"
        shutil.copytree(args.fixtures / "modified", case)
        manifest = case / "recipe.knverify"
        original = json.loads(manifest.read_bytes())
        for mutation in ("policy", "normalization", "recorded_result", "claim_injection"):
            document = copy.deepcopy(original)
            if mutation == "policy":
                document["payload"]["policy"] = "unknown-recorded-policy"
            elif mutation == "claim_injection":
                document["payload"]["claim_assessment"] = {"status": "supported", "collector_authenticated": True}
            else:
                document["payload"][mutation] = {}
            payload = json.dumps(document["payload"], ensure_ascii=False, separators=(",", ":"))
            document["recipe_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
            manifest.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":")), encoding="utf-8", newline="")
            expected = {"policy": "original_policy_unavailable", "normalization": "normalization_mismatch",
                        "recorded_result": "recorded_result_mismatch", "claim_injection": "recipe_unavailable_or_corrupt"}[mutation]
            run(case, expected=expected)
            run(case, True, "recipe_unavailable_or_corrupt" if mutation == "claim_injection" else "reanalyzed")
    assert set(states) == {"supported", "contradicted", "unfulfilled"}, states
    print(f"image claims passed: {runs} replay controls; states={dict(states)}; independent PE/read/pointer/seven-ledger oracle")


if __name__ == "__main__":
    main()
