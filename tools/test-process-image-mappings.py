"""Independent v3 native mapping, replay, claim, approval and archive controls."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from image_claim_oracle import check_original_claim, check_report, unpack_recipe

SPEC = importlib.util.spec_from_file_location("approval_inputs", Path(__file__).with_name("test-image-authorized-changes.py"))
INPUTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUTS)
encoded, sha = INPUTS.encoded, INPUTS.sha


def seal(recipe):
    recipe["recipe_sha256"] = sha(encoded(recipe["payload"]))
    return encoded(recipe)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    fixtures, exe = args.fixtures.resolve(), args.exe.resolve()
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, str(message)[:1400]
        checks += 1

    def run(action, *values, code=0):
        commands = {"report": "replay-image", "init-store": "init-store", "assess": "assess-image",
                    "archive": "journal-image", "archive-approval": "journal-image-approval",
                    "replay-approval": "replay-image-approval"}
        head = [exe, "--offline", "!kmon", commands[action]] if args.product else [exe, "--" + action]
        result = subprocess.run(list(map(str, [*head, *values])), capture_output=True, text=True, encoding="utf-8", timeout=90)
        check(result.returncode == code, (action, result.returncode, code, result.stdout[:700], result.stderr[-300:]))
        return json.loads(result.stdout)

    def verify(case, current=False, expected=None):
        report = run("report", case, *(["/current"] if current else []), code=1 if expected else 0)
        check(report["status"] == (expected or ("reanalyzed" if current else "replayed")), report["status"])
        if expected:
            check(report["claim_assessment"] is None and report["proof"] is None, "rejected evidence exposes no claim")
            return report
        document = json.loads((case / "recipe.knverify" if case.is_dir() else case).read_bytes())
        recipe = unpack_recipe(document)
        reference = (case / (recipe["payload"]["reference_sha256"] + ".knblob") if case.is_dir() else
                     case.parent.parent / "image-references" / (recipe["payload"]["reference_sha256"] + ".knblob"))
        check_original_claim(document, report)
        check_report(recipe, reference.read_bytes(), report)
        check(report["result"] == recipe["payload"]["recorded_result"] or current, "exact original mapping result")
        return report

    names = ("stable", "modified", "modified-conflict", "protect", "final", "free", "remap", "aba", "neighbor", "exited", "cancel", "cross")
    for name in names:
        case = fixtures / ("mapping-" + name)
        original, current = verify(case), verify(case, True)
        check(original["result"] == current["result"], "current policy keeps retained query fences")
        mapping = original["result"]["mapping"]
        check(not mapping["native_image_mapping_observed"] and not mapping["aba_excluded"], "buffer is not a native image or a lifetime proof")
        if name in ("aba", "neighbor"):
            check(mapping["status"] == "consistent_observations", "unobserved ABA and unqueried region changes are not observed conflicts")
        if name == "exited":
            check(int(mapping["failed_observations"]) == int(mapping["observations"]) and int(mapping["queries"]) > 0,
                  "exited process address-space queries retain native errors")
        if name == "cancel":
            check(mapping["queries"] == "0", "cancelled observation issues no query")

    with tempfile.TemporaryDirectory(prefix="mapping-controls-", dir=fixtures) as temporary:
        root = Path(temporary).resolve()
        assert root.is_relative_to(fixtures)
        case = root / "mutations"
        shutil.copytree(fixtures / "mapping-stable", case)
        original_publication = json.loads((case / "recipe.knverify").read_bytes())
        baseline = unpack_recipe(original_publication)
        for mutation in ("old_policy", "missing_mapping_requirement", "wrong_mapping_pointer"):
            publication = copy.deepcopy(original_publication)
            report = publication["payload"]["recorded_claim"]
            if mutation == "old_policy":
                report["policy"] = "kn.image_claim_policy.direct.v1"
            elif mutation == "missing_mapping_requirement":
                report["policies"][0]["requirements"].pop(-2)
            else:
                fact = next(row for row in report["claims"][0]["supports"] if row["requirement"] == "observed_mapping_consistent")
                fact["evidence"]["json_pointer"] = "/payload/read_set"
            publication["publication_sha256"] = sha(encoded(publication["payload"]))
            (case / "recipe.knverify").write_bytes(encoded(publication))
            verify(case, expected="recorded_claim_policy_unavailable" if mutation == "old_policy" else "recorded_claim_assessment_mismatch")
            verify(case, True)
        mutations = [
            lambda m: m.__setitem__("schema", "kn.process_image_mappings.v2"),
            lambda m: m.__setitem__("policy", "future"),
            lambda m: m.__setitem__("clock_domain", "target_clock"),
            lambda m: m.__setitem__("query_contract", "win32_virtualqueryex.x86.v1"),
            lambda m: m.__setitem__("extra", False),
            lambda m: m["reads"].pop(),
            lambda m: m["final"].pop(),
            lambda m: m["final"].append(m["final"][0]),
            lambda m: m["final"].reverse(),
            lambda m: m["reads"][0]["before"].__setitem__("source_id", "foreign-process"),
            lambda m: m["reads"][0]["after"].__setitem__("address", "0"),
            lambda m: m["reads"][0]["before"].__setitem__("length", "4097"),
            lambda m: m["reads"][0]["before"].__setitem__("ended_tick", "18446744073709551615"),
            lambda m: m["reads"][0]["after"].__setitem__("started_tick", "0"),
            lambda m: m["final"][0].__setitem__("started_tick", "0"),
            lambda m: m["final"][-1].__setitem__("ended_tick", "18446744073709551615"),
            lambda m: m["reads"][0]["before"].__setitem__("identity_revalidated", False),
            lambda m: m["reads"][0]["before"].__setitem__("status", "unknown"),
            lambda m: m["reads"][0]["before"]["queries"].clear(),
            lambda m: m["reads"][0]["before"]["queries"].extend(m["reads"][0]["before"]["queries"] * 2),
        ]
        for field, value in (("address", "0"), ("returned_bytes", "47"), ("returned_bytes", 48),
                             ("native_status", "0"), ("region_bytes", "0"), ("region_base", "18446744073709551615"),
                             ("allocation_base", "18446744073709551615"), ("state", "0"), ("type", "0"),
                             ("protect", None), ("extra", True)):
            mutations.append(lambda m, k=field, v=value: m["reads"][0]["before"]["queries"][0].__setitem__(k, v))
        for mutate in mutations:
            corrupted = copy.deepcopy(baseline)
            mutate(corrupted["payload"]["mapping_set"])
            (case / "recipe.knverify").write_bytes(seal(corrupted))
            verify(case, expected="recipe_unavailable_or_corrupt")
            verify(case, True, "recipe_unavailable_or_corrupt")

        # Retained contradictory observations may be structurally valid, but
        # the old success result must no longer reproduce or authorize bytes.
        for status in ("query_failed", "identity_changed", "unsupported", "cancelled", "malformed_result", "conflict"):
            changed = copy.deepcopy(baseline)
            record = changed["payload"]["mapping_set"]["reads"][0]["after"]
            if status == "conflict":
                record["queries"][0]["protect"] = str(0x02)
            elif status in ("query_failed", "malformed_result"):
                q = record["queries"][0]
                q.update({k: None for k in q if k != "address"})
                q.update(returned_bytes="0" if status == "query_failed" else "47", native_status="5" if status == "query_failed" else None)
                record["status"] = status
            else:
                record.update(status=status, identity_revalidated=status == "cancelled", queries=[])
            (case / "recipe.knverify").write_bytes(seal(changed))
            verify(case, expected="recorded_result_mismatch")
            checked = verify(case, True)
            check(not checked["result"]["reference_qualified"], "valid failure observations withhold reference qualification")

        # A real two-region observation supplies the first successful prefix.
        cross = fixtures / "mapping-cross"
        changed = unpack_recipe(json.loads((cross / "recipe.knverify").read_bytes()))
        pair = next(row for row in changed["payload"]["mapping_set"]["reads"] if len(row["after"]["queries"]) == 2)
        q = pair["after"]["queries"][1]
        q.update({k: None for k in q if k != "address"})
        q.update(returned_bytes="0", native_status="5")
        pair["after"]["status"] = "query_failed"
        (case / "recipe.knverify").write_bytes(seal(changed))
        verify(case, expected="recorded_result_mismatch")
        partial = verify(case, True)["result"]["mapping"]
        check(0 < int(partial["observed_query_bytes"]) < int(partial["requested_query_bytes"]), "partial native query cover is not complete")

        store = root / "private"
        check(run("init-store", store, *(["/acl-only"] if args.product else []))["status"] == "ready", "private archive")
        (case / "recipe.knverify").write_bytes(encoded(baseline))
        bare = run("archive", case, store, "100")
        check(bare["status"] == "archived" and bare["closed"], "journal accepts a bare v3 recipe with no invented original claim")
        retained_bare = store / bare["capture_path"]
        check(retained_bare.read_bytes() == encoded(baseline), "bare recipe query bytes retained exactly")
        verify(retained_bare)
        for index, name in enumerate(names[:-1], 1):
            source = root / ("source-" + name)
            shutil.copytree(fixtures / ("mapping-" + name), source)
            original = (source / "recipe.knverify").read_bytes()
            recipe = unpack_recipe(json.loads(original))
            blob = (source / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes()
            manifest, _, _ = INPUTS.material(recipe, blob, int(recipe["payload"]["rva"]) + 0x150)
            change, policy = root / "change.knchange", root / "policy.knapproval"
            change.write_bytes(encoded(manifest))
            policy.write_bytes(encoded(INPUTS.policy_for(manifest)))
            anchor = sha(policy.read_bytes())
            when = int(recipe["payload"]["captured_filetime"]) + 1
            assessed = run("assess", source, change, policy, anchor, *([] if args.product else [when]))
            check(assessed["status"] == "assessed" and assessed["authorized_changed_bytes"] == ("1" if name == "modified" else "0"),
                  "exact policy cannot authorize bytes across mapping failure or conflict")
            check_report(recipe, blob, assessed["replay"])
            archived = run("archive-approval", source, change, policy, anchor, store, str(index), *([] if args.product else [when]))
            check(archived["closed"] and archived["committed"], "mapping inputs retained with exact original approval")
            approval = store / archived["approval_path"]
            publication = json.loads(approval.read_bytes())["payload"]
            capture = store / f'image-captures/capture-{index}-{publication["capture_sha256"]}.kncapture'
            check(capture.read_bytes() == original, "archived mapping and query records are byte exact")
            # Remove only this owned copied source and policy input files.
            for path in source.iterdir():
                assert path.is_file() and path.resolve().is_relative_to(root)
                path.unlink()
            source.rmdir()
            change.unlink()
            policy.unlink()
            verify(capture)
            for current in (False, True):
                report = run("replay-approval", approval, anchor, *(["/current"] if current else []))
                check(report["status"] == ("reanalyzed" if current else "reproduced"), "managed approval survives source deletion")
                check(report["assessment"]["authorized_changed_bytes"] == ("1" if name == "modified" else "0"), "mapping gate survives archive replay")
                check_report(recipe, blob, report["assessment"]["replay"])
                if not current:
                    check(report["assessment"] == report["recorded_assessment"], "exact original approval assessment reproduced")
    print(f"[image.mapping.oracle] passed={checks} cases={len(names)} original_queries=true archive_replay=true")


if __name__ == "__main__":
    main()
