"""Independent temporal sweep membership, byte totals and tamper oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import uuid

from image_scope_claim_oracle import check_scope_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    executable = str(args.exe.resolve())
    root = args.fixtures.resolve()
    checks = 0

    def check(value, label):
        nonlocal checks
        checks += 1
        assert value, label

    def replay(path, success=True, current=False):
        command = ([executable, "--offline", "!kmon", "replay-image", str(path), "/json"] +
                   (["/current"] if current else [])) if args.cli else [executable, "--replay", str(path)]
        run = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30)
        check(run.returncode == (0 if success else 1), "replay exit")
        result = json.loads(run.stdout)
        check(result["schema"] == "kn.image_sweep_replay.v1", "distinct sweep schema")
        check(("recipe_sha256" not in result) and "manifest_sha256" in result, "manifest identity is not mislabeled as recipe")
        check((result["status"] == "replayed") == success, "replay status")
        if not success:
            check(result["proof"] is None, "contradictory or missing inputs have no proof")
            check(result["claim_assessment"] is None, "failed sweep replay cannot authorize current claims")
        else:
            manifest = json.loads(path.read_bytes())
            collection = manifest["payload"]["sweep"]["collection_id"]
            folder = path.parent.parent
            recipes, blobs = [], []
            for member in manifest["payload"]["slices"]:
                recipe = json.loads((folder / "image-reads" / f"reads-{collection}-{member['read_set_id']}.knslice").read_bytes())
                recipes.append(recipe)
                blobs.append((folder / "image-references" / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes())
            check_scope_report(manifest, recipes, blobs, result)
        return result

    def envelope_hash(path, key):
        text = path.read_text(encoding="utf-8")
        value = json.loads(text)
        payload = text.split(',"payload":', 1)[1][:-1]
        check(hashlib.sha256(payload.encode()).hexdigest() == value[key], "independent canonical payload digest")
        return value

    expected = {
        "sweep_clean": (8192, 0, 0, 0, True, True),
        "sweep_modified": (8192, 0, 1, 0, True, False),
        "sweep_excluded": (8184, 8, 0, 0, False, False),
        "sweep_gap": (4096, 0, 0, 4096, False, False),
        "sweep_interrupted": (4096, 0, 0, 4096, False, False),
        "sweep_secondary": (8192, 0, 0, 0, True, True),
    }
    for name, counts in expected.items():
        folder = root / name
        path = folder / "image-sweeps" / "sweep-7-1.knsweep"
        envelope = envelope_hash(path, "manifest_sha256")
        p = envelope["payload"]
        check(not (folder / "original.exe").exists(), "original file gone before replay")
        check(int(p["missing_entries"]) == int(p["observed_slices"]) - len(p["slices"]), "loss denominator")
        check(int(p["observed_elapsed_ms"]) == int(p["last_ended_tick"]) - int(p["sweep"]["started_tick"]), "observed duration")
        check(not p["atomic_snapshot"] and not p["complete_replay_established"], "publication itself makes no replay claim")
        previous_ordinal = 0
        previous_end = int(p["sweep"]["started_tick"])
        ranges = set()
        references = set()
        for row in p["slices"]:
            check(int(row["ordinal"]) > previous_ordinal and int(row["started_tick"]) >= previous_end, "ordered temporal membership")
            previous_ordinal, previous_end = int(row["ordinal"]), int(row["ended_tick"])
            artifact_name = f"reads-7-{row['read_set_id']}"
            leaf = envelope_hash(folder / "image-reads" / (artifact_name + ".knslice"), "recipe_sha256")
            raw = envelope_hash(folder / "image-reads" / (artifact_name + ".knreads"), "payload_sha256")
            check(leaf["recipe_sha256"] == row["recipe_sha256"] and raw["payload_sha256"] == row["raw_payload_sha256"], "manifest binds both published artifacts")
            check(leaf["payload"]["target_reads"] == raw["payload"]["reads"], "original selected reads agree")
            check(row["reference_sha256"] == leaf["payload"]["reference_sha256"], "exact reference membership")
            references.add(row["reference_sha256"])
            for index in range(int(row["start_range"]), int(row["start_range"]) + int(row["range_count"])):
                check(index not in ranges, "no duplicated range denominator")
                ranges.add(index)
        check(len(references) == 1 and len(list((folder / "image-references").glob("*.knblob"))) == 1, "one shared reference blob")
        result = replay(path)
        proof = result["proof"]
        observed = tuple(int(proof[k]) for k in ("compared_bytes", "excluded_bytes", "changed_bytes", "unobserved_bytes"))
        check(observed == counts[:4], "independent byte totals")
        check(proof["whole_sweep_complete"] == counts[4], "whole-sweep gate")
        check(proof["executable_ranges_match_retained_reference"] == counts[5], "clean match requires all executable comparison bytes")
        check(int(proof["matching_bytes"]) == counts[0] - counts[2], "matching and differing bytes remain separate")
        check(int(proof["unreadable_bytes"]) == 0 and int(proof["requested_bytes"]) == len(ranges) * 4096, "executed ranges independent count")
        check(not proof["atomic_snapshot"] and not proof["collector_authenticated"] and not proof["execution_observed"], "scope limits")
        if name == "sweep_secondary":
            check(all(row["policy"] == "kn.executable_slice.secondary.v1" for row in proof["recipe_evidence"]), "original secondary policies retained across slices")
        if args.cli:
            unavailable = replay(path, False, True)
            check(unavailable["status"] == "sweep_current_reanalysis_unavailable", "no silent current-policy alias")

    for name, expected_states in {
        "sweep_raw_lost": ["supported", "contradicted"],
        "sweep_unstable": ["unfulfilled", "unfulfilled"],
        "sweep_modified_interrupted": ["contradicted", "supported"],
        "sweep_modified_gap": ["contradicted", "supported"],
        "sweep_partial_modified": ["contradicted", "supported"],
    }.items():
        result = replay(root / name / "image-sweeps" / "sweep-7-1.knsweep")
        check([claim["status"] for claim in result["claim_assessment"]["claims"]] == expected_states,
              "local stable differences survive omitted slices, unknown tails and other failed comparisons")
        if name == "sweep_raw_lost":
            check(result["claim_assessment"]["ledgers"]["persistence"]["raw_publication_failures"] == "2" and
                  not result["proof"]["whole_sweep_complete"], "retained recipe proof cannot hide raw publication loss")
    source = root / "sweep_clean"
    for mutation in ("schedule", "duplicate", "target", "missing_recipe", "missing_raw", "corrupt_reference",
                     "raw_identity", "contradictory_terminal", "contradictory_time", "inconsistent", "path_escape"):
        destination = root / ("sweep-negative-" + uuid.uuid4().hex)
        check(destination.resolve().is_relative_to(root), "owned negative fixture path")
        shutil.copytree(source, destination)
        manifest = destination / "image-sweeps" / "sweep-7-1.knsweep"
        document = json.loads(manifest.read_text(encoding="utf-8"))
        p = document["payload"]
        if mutation == "schedule":
            p["sweep"]["total_ranges"], p["sweep"]["expected_bytes"] = "3", "12288"
        elif mutation == "duplicate":
            p["slices"][1]["read_set_id"] = p["slices"][0]["read_set_id"]
        elif mutation == "target":
            p["sweep"]["target_id"] += ":other"
        elif mutation == "missing_recipe":
            (destination / "image-reads" / "reads-7-1.knslice").unlink()
        elif mutation == "missing_raw":
            (destination / "image-reads" / "reads-7-1.knreads").unlink()
        elif mutation == "corrupt_reference":
            blob = next((destination / "image-references").glob("*.knblob"))
            data = bytearray(blob.read_bytes()); data[-1] ^= 1; blob.write_bytes(data)
        elif mutation == "raw_identity":
            raw_path = destination / "image-reads" / "reads-7-1.knreads"
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            raw["payload"]["pid"] = "99"
            payload = json.dumps(raw["payload"], ensure_ascii=False, separators=(",", ":"))
            raw["payload_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
            p["slices"][0]["raw_payload_sha256"] = raw["payload_sha256"]
            raw_path.write_text(json.dumps(raw, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        elif mutation == "contradictory_terminal":
            p["slices"][-1]["terminal"] = False
            p["slices"][-1]["traversal_complete"] = False
        elif mutation == "contradictory_time":
            p["last_ended_tick"] = str(int(p["last_ended_tick"]) + 1)
            p["observed_elapsed_ms"] = str(int(p["observed_elapsed_ms"]) + 1)
        elif mutation == "inconsistent":
            p["inconsistent"] = True
        else:
            p["sweep"]["collection_id"], p["sweep"]["sweep_id"] = "../outside", "../outside-1"
        payload = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
        document["manifest_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
        manifest.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        replay(manifest, False)
    print(f"Image sweep oracle passed: {checks} checks; cases={len(expected) + 5}; cli={args.cli}")


if __name__ == "__main__":
    main()
