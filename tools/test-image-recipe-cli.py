"""Validate saved reference replay through the public offline CLI using owned fixtures."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    exe, fixtures = args.exe.resolve(), args.fixtures.resolve()
    checks = 0

    def check(ok, name):
        nonlocal checks
        assert ok, name
        checks += 1

    def run(*arguments, exit_code=0):
        result = subprocess.run([str(exe), "--offline", "!kmon", *map(str, arguments)],
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        check(result.returncode == exit_code, f"exit status for {arguments[0]}")
        if exit_code == 2:
            check(not result.stdout.strip() and "usage:" in result.stderr, "invalid grammar produces no DTO")
            return None
        return json.loads(result.stdout)

    def encode(document):
        payload = json.dumps(document["payload"], ensure_ascii=False, separators=(",", ":"))
        document["recipe_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
        return json.dumps(document, ensure_ascii=False, separators=(",", ":"))

    with tempfile.TemporaryDirectory(prefix="recipe-cli-", dir=fixtures) as temporary:
        root = Path(temporary)
        case = root / "case"
        image, dump = fixtures / "owned-image.exe", fixtures / "owned.dmp"
        result = run("verify-image", image, dump, "180000000", "2000", "4096", case, "/json")
        check(result["status"] == "recorded" and result["result"]["ownership"] == "owned_verified",
              "qualified full dump source can record a normalized comparison")
        manifest = case / "recipe.knverify"
        original = manifest.read_bytes()
        recipe = json.loads(original)
        check(encode(copy.deepcopy(recipe)).encode() == original, "independent Python canonical digest matches")
        blob = case / (recipe["payload"]["reference_sha256"] + ".knblob")
        artifact = blob.read_bytes()
        check(artifact == image.read_bytes() and hashlib.sha256(artifact).hexdigest() == result["reference_sha256"],
              "content-addressed artifact contains the complete original file")
        replay = run("replay-image", case, "/json")
        check(replay["status"] == "replayed" and replay["mode"] == "original_policy" and
              replay["result"] == replay["recorded_result"] == result["result"] and
              replay["recorded_policy"] == replay["current_policy"] == recipe["payload"]["policy"], "fresh-process exact replay")
        current = run("replay-image", case, "/current", "/json")
        check(current["mode"] == "current_reanalysis" and current["status"] == "reanalyzed" and
              not current["collector_authenticated"] and not current["execution_observed"], "reanalysis is distinct from new observation")
        run("verify-image", image, dump, "180000000", "2000", "4096", case, exit_code=1)
        check(manifest.read_bytes() == original, "existing case cannot be overwritten")
        for arguments in (("verify-image",), ("replay-image",), ("replay-image", case, "/unknown"),
                          ("replay-image", case, "/current", "/current"), ("replay-image", case, "/json", "/json"),
                          ("verify-image", image, dump, "0", "0", "0", root / "bad"),
                          ("verify-image", image, dump, "180000000", "100000000", "8", root / "bad"),
                          ("verify-image", image, dump, "180000000", "2000", "4097", root / "bad")):
            run(*arguments, exit_code=2)

        def publish(document):
            manifest.write_text(encode(document), encoding="utf-8", newline="")

        for mutation, status in (("policy", "original_policy_unavailable"), ("normalization", "normalization_mismatch"),
                                 ("result", "recorded_result_mismatch"), ("read_order", "recorded_read_set_mismatch"),
                                 ("missing_bytes", "recipe_unavailable_or_corrupt"), ("source", "recipe_unavailable_or_corrupt"),
                                 ("over_budget", "recipe_unavailable_or_corrupt"), ("noncanonical_base", "recipe_unavailable_or_corrupt"),
                                 ("claimed_trust", "recipe_unavailable_or_corrupt")):
            changed = copy.deepcopy(recipe)
            payload = changed["payload"]
            if mutation == "policy":
                payload["policy"] = "unknown_original_policy"
            elif mutation == "normalization":
                payload["normalization"] = {}
            elif mutation == "result":
                payload["recorded_result"] = {}
            elif mutation == "read_order":
                payload["reads"] = payload["reads"][1:]
            elif mutation == "missing_bytes":
                payload["reads"][0]["spans"][0]["bytes"] = ""
            elif mutation == "source":
                payload["reads"][0]["source_id"] = "different-source"
            elif mutation == "over_budget":
                payload["reads"] = payload["reads"] * 65
            elif mutation == "noncanonical_base":
                payload["image_base"] = str(0x0000800000000000)
            else:
                payload["collector_authenticated"] = True
            publish(changed)
            check(run("replay-image", case, exit_code=1)["status"] == status, "recomputed digest does not override validation")
            if mutation == "policy":
                current = run("replay-image", case, "/current")
                check(current["status"] == "reanalyzed" and current["recorded_policy"] == "unknown_original_policy" and
                      current["current_policy"] != current["recorded_policy"], "current policy must be selected explicitly")
        for malformed in (original + b" ", original[:-1], b"{}", b"not json", b"x" * (2 * 1024 * 1024 + 1)):
            manifest.write_bytes(malformed)
            check(run("replay-image", case, exit_code=1)["status"] == "recipe_unavailable_or_corrupt", "malformed input is unavailable")
        manifest.write_bytes(original)
        blob.write_bytes(artifact[:500] + bytes([artifact[500] ^ 1]) + artifact[501:])
        check(run("replay-image", case, exit_code=1)["status"] == "reference_corrupt", "reference corruption cannot reuse original success")
        moved = root / "temporarily-moved.knblob"
        blob.rename(moved)
        check(run("replay-image", case, exit_code=1)["status"] == "reference_missing_or_unreadable", "missing exact reference is explicit")
        moved.rename(blob)
        blob.write_bytes(artifact)
        check(run("replay-image", case)["status"] == "replayed", "restored exact artifact restores replay")
        check(run("replay-image", root / "absent", exit_code=1)["status"] == "recipe_unavailable_or_corrupt",
              "absent final manifest is incomplete publication")
        excluded = root / "excluded"
        excluded_result = run("verify-image", image, dump, "180000000", "1000", "4096", excluded)
        check(excluded_result["result"]["ownership"] == "owned_unverified" and
              excluded_result["result"]["skipped_bytes"] == "8" and excluded_result["result"]["compared_bytes"] == "4088",
              "loader exclusions cannot become completely verified bytes")
        check(run("replay-image", excluded)["result"] == excluded_result["result"], "exclusions survive replay exactly")
        sparse = root / "sparse"
        shutil.copytree(fixtures / "sparse", sparse)
        sparse_manifest = sparse / "recipe.knverify"
        sparse_recipe = json.loads(sparse_manifest.read_bytes())
        for field in ("source_id", "consistency"):
            changed = copy.deepcopy(sparse_recipe)
            partial = [read for read in changed["payload"]["reads"] if read["state"] == "partial"]
            check(bool(partial), "partial provenance control contains retained sparse bytes")
            for read in partial:
                read[field] = "different-source-contract"
            sparse_manifest.write_text(encode(changed), encoding="utf-8", newline="")
            for options in ((), ("/current",)):
                check(run("replay-image", sparse, *options, exit_code=1)["status"] == "recipe_unavailable_or_corrupt",
                      "partial retained bytes require matching source and consistency in either replay mode")
        check(not list(root.rglob("*.pending-*")), "normal success and failure paths leave no temporary publications")
    print(f"image recipe CLI passed: {checks} checks; no live target")


if __name__ == "__main__":
    main()
