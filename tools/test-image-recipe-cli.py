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
        proof = replay["proof"]
        check(proof["schema"] == "kn.image_proof.v1" and proof["input_consistent"] and
              proof["recipe_sha256"] == recipe["recipe_sha256"], "proof binds the exact replayed recipe")
        claims = {claim["name"]: claim for claim in proof["claims"]}
        match, difference = (claims["recorded_range_matches_reference_policy"],
                             claims["recorded_range_differs_reference_policy"])
        check(match["status"] == "supported" and difference["status"] == "contradicted" and
              not match["unfulfilled_requirements"] and difference["contradicts"], "claim-specific support and contradiction")
        check(match["ranges"] == [{"address": str(0x180002000), "length": "4096"}], "claim is confined to the requested range")
        ledgers = proof["ledgers"]
        check(set(ledgers) == {"discovery", "address", "temporal", "semantic", "persistence", "replay", "trust"},
              "all seven coverage dimensions remain separate")
        address = ledgers["address"]
        check(address["status"] == "complete" and int(address["requested_bytes"]) ==
              sum(int(address[key]) for key in ("compared_bytes", "failed_bytes", "skipped_bytes", "unvisited_bytes")),
              "comparison byte accounting is conserved")
        reads = recipe["payload"]["reads"]
        persisted = sum(len(bytes.fromhex(span["bytes"])) for read in reads for span in read["spans"])
        check(int(ledgers["persistence"]["retained_read_bytes_including_repeats"]) == persisted and
              int(ledgers["persistence"]["requested_read_bytes"]) == sum(int(read["length"]) for read in reads) and
              ledgers["persistence"]["unique_target_bytes_retained"] == "4096", "independent persisted-byte denominator")
        check(ledgers["temporal"]["intervals"] == [
            {"read_index": str(index), "started_tick": read["started_tick"], "ended_tick": read["ended_tick"]}
            for index, read in enumerate(reads)] and not ledgers["temporal"]["continuous_observation"] and
              not ledgers["temporal"]["target_time_available"], "collector read intervals are not target execution time")
        for reference in proof["evidence_refs"]:
            prefix, index = reference.rsplit(":", 1)
            check(prefix == "recipe:" + recipe["recipe_sha256"] + "#read" and int(index) < len(reads),
                  "every claim read reference resolves to the retained recipe")
        check(not ledgers["trust"]["collector_authenticated"] and not ledgers["trust"]["approved_distribution"] and
              {"execution", "writer_identity", "maliciousness", "whole_image_integrity"} <= set(proof["not_proven"]),
              "byte comparison does not establish stronger claims")
        current = run("replay-image", case, "/current", "/json")
        check(current["mode"] == "current_reanalysis" and current["status"] == "reanalyzed" and
              not current["collector_authenticated"] and not current["execution_observed"], "reanalysis is distinct from new observation")
        check(current["proof"]["ledgers"]["replay"]["status"] == "current_policy_reanalysis",
              "proof distinguishes current reanalysis from original result reproduction")
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
            rejected = run("replay-image", case, exit_code=1)
            check(rejected["status"] == status, "recomputed digest does not override validation")
            check(rejected["proof"] is None, "failed replay cannot expose a retained success proof")
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
        excluded_replay = run("replay-image", excluded)
        check(excluded_replay["result"] == excluded_result["result"], "exclusions survive replay exactly")
        check(excluded_replay["proof"]["ledgers"]["address"]["status"] == "partial" and
              excluded_replay["proof"]["ledgers"]["address"]["skipped_bytes"] == "8" and
              all(claim["status"] == "not_established" and claim["unfulfilled_requirements"] and
                  claim["next_best_observation"] for claim in excluded_replay["proof"]["claims"]),
              "equal excluded bytes cannot establish a full match or difference")
        changed_replay = run("replay-image", fixtures / "modified")
        changed_proof = changed_replay["proof"]
        check(changed_proof["claims"][1]["status"] == "supported" and changed_proof["claims"][0]["status"] == "contradicted" and
              changed_proof["claims"][1]["ranges"] == [{"address": str(0x180001150), "length": "1"}] and
              len(changed_proof["evidence_refs"]) == 2, "stable differences have exact byte scope and two retained reads")
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
