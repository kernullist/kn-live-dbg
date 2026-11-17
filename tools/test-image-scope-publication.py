"""Original slice/sweep claim roots, byte oracles, journal membership and interruption."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading

from image_scope_claim_oracle import check_scope_report

SCHEMA = "kn.image_scope_claim_publication.v1"
SLICES = ("clean", "modified", "unstable", "unreadable", "guard", "identity", "continuation",
          "secondary", "secondary_verified", "secondary_modified", "secondary_unstable")
SWEEPS = ("sweep_clean", "sweep_modified", "sweep_excluded", "sweep_gap", "sweep_interrupted",
          "sweep_secondary", "sweep_unstable", "sweep_raw_lost", "sweep_modified_interrupted",
          "sweep_modified_gap", "sweep_partial_modified")


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def seal(value):
    value["publication_sha256"] = sha(encoded(value["payload"]))
    return encoded(value)


def inner(value):
    return value["payload"]["artifact"] if value["schema"] == SCHEMA else value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--publisher", type=Path)
    parser.add_argument("--journal-exe", type=Path)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    exe = str(args.exe.resolve())
    root = args.fixtures.resolve() / "scope-claim-publications"
    checks = 0

    def check(ok, label):
        nonlocal checks
        checks += 1
        assert ok, label

    def invoke(command, expected=0):
        result = subprocess.run(list(map(str, command)), capture_output=True, encoding="utf-8", timeout=60)
        check(result.returncode == expected, (command[:2], result.returncode, result.stdout[-300:], result.stderr[-500:]))
        return result

    def target(folder):
        return folder / ("image-sweeps/sweep-7-1.knsweep" if folder.name.startswith("sweep_") else "image-reads/slice.knslice")

    if args.publisher:
        root.mkdir()  # Unique parent harness run; never replace previous evidence.
        for name in SLICES + SWEEPS:
            case = root / name
            shutil.copytree(args.fixtures / name, case)
            paths = ([case / "image-reads/slice.knslice"] if name in SLICES else
                     sorted((case / "image-reads").glob("reads-7-*.knslice")) + [target(case)])
            for path in paths:
                legacy = path.with_suffix(path.suffix + ".legacy")
                check(path.resolve().is_relative_to(root), "owned publication destination")
                path.rename(legacy)
                invoke([args.publisher, "--publish", legacy, path])
                before = path.read_bytes()
                invoke([args.publisher, "--publish", legacy, path], 1)
                check(path.read_bytes() == before, "collision preserves exact first publication")

    def replay(path, expected="replayed", legacy=False):
        command = [exe, "--offline", "!kmon", "replay-image", path, "/json"] if args.cli else [exe, "--replay", path]
        before = path.read_bytes() if path.exists() else None
        result = json.loads(invoke(command, 0 if expected == "replayed" else 1).stdout)
        check(result["status"] == expected, (path, result["status"], expected))
        check((path.read_bytes() if path.exists() else None) == before, "replay leaves original root unchanged")
        original = result["original_claim_replay"]
        check(not original["journal_membership_checked"] and not original["collector_authenticated"], "reproduction is not collection authentication")
        if expected != "replayed":
            check(result["proof"] is None and result["claim_assessment"] is None and
                  not original["original_claim_policy_reproduced"], "failure cannot emit proof or reproduced claims")
            return result
        document = json.loads(before)
        artifact = inner(document)
        field = "manifest_sha256" if artifact["schema"] == "kn.image_sweep.v1" else "recipe_sha256"
        check(artifact[field] == sha(encoded(artifact["payload"])), "unchanged inner digest")
        if legacy:
            check(original["status"] == "not_recorded", "legacy import never invents original claim")
        else:
            stored = document["payload"]["recorded_claim"]
            check(document["schema"] == SCHEMA and document["publication_sha256"] == sha(encoded(document["payload"])), "outer binding")
            check(original["status"] == "reproduced" and original["original_claim_policy_reproduced"] and
                  original["assessment_matches_current_report"], "complete original report reproduced")
            check(original["publication_sha256"] == document["publication_sha256"] and
                  original["recorded_assessment_sha256"] == sha(encoded(stored)), "replay identifies exact recorded publication and report")
            check(stored == result["claim_assessment"], "all original claims witnesses policies and seven ledgers agree")
        folder = path.parent.parent
        recipes = [artifact]
        if field == "manifest_sha256":
            collection = artifact["payload"]["sweep"]["collection_id"]
            recipes = [inner(json.loads((folder / "image-reads" / f"reads-{collection}-{row['read_set_id']}.knslice").read_bytes()))
                       for row in artifact["payload"]["slices"]]
        blobs = [(folder / "image-references" / (p["payload"]["reference_sha256"] + ".knblob")).read_bytes() for p in recipes]
        check_scope_report(artifact, recipes, blobs, result)  # Independent PE/DIR64/read-receipt oracle.
        return result

    for name in SLICES + SWEEPS:
        path = target(root / name)
        replay(path)
        # These were captured before this new schema existed, in the same harness run.
        replay(target(args.fixtures / name), legacy=True)
        if name in SWEEPS:
            command = [exe, "--offline", "!kmon", "graph", path, "/json"] if args.cli else [exe, "--graph", path, "8", "128", "", "", "1000"]
            check(json.loads(invoke(command).stdout)["graph_status"] == "materialized", "graph consumes verified publication")

    with tempfile.TemporaryDirectory(prefix="scope-publication-controls-", dir=args.fixtures) as temporary:
        scratch = Path(temporary)
        for name in ("modified", "sweep_modified"):
            for mutation in ("verdict", "witness", "ledger", "extra_claim", "registry", "policy", "foreign_capture",
                             "foreign_reference", "wrong_scope", "inner_digest", "outer_digest", "missing_report",
                             "extra_root", "oversized_report", "truncated", "pending_only", "legacy", "missing_reference"):
                case = scratch / mutation / name
                shutil.copytree(root / name, case)
                path = target(case)
                document = json.loads(path.read_bytes())
                report = document["payload"]["recorded_claim"]
                expected = "recorded_claim_assessment_mismatch"
                if mutation == "verdict": report["claims"][1]["status"] = "unfulfilled"
                elif mutation == "witness": report["stable_difference_witness"] = None
                elif mutation == "ledger": report["ledgers"]["trust"]["collector_authenticated"] = True
                elif mutation == "extra_claim": report["claims"].append({"claim": "unverified", "status": "supported"})
                elif mutation in {"registry", "policy"}:
                    report[mutation] = "unknown.v999"
                    expected = "recorded_claim_policy_unavailable"
                else:
                    expected = "manifest_unavailable_or_corrupt" if name.startswith("sweep_") else "recipe_unavailable_or_corrupt"
                    if mutation == "foreign_capture": report["capture_sha256"] = "0" * 64
                    elif mutation == "foreign_reference": report["reference_sha256"] = "0" * 64
                    elif mutation == "wrong_scope": report["scope"] = "whole_host"
                    elif mutation == "inner_digest":
                        artifact = document["payload"]["artifact"]
                        artifact["manifest_sha256" if name.startswith("sweep_") else "recipe_sha256"] = "0" * 64
                    elif mutation == "missing_report": del document["payload"]["recorded_claim"]
                    elif mutation == "extra_root": document["unbound"] = True
                    elif mutation == "oversized_report": report["padding"] = "x" * (2 * 1024 * 1024)
                data = seal(document)
                if mutation == "outer_digest": data = data.replace(document["publication_sha256"].encode(), b"0" * 64, 1)
                if mutation == "truncated": data = data[:len(data) // 2]
                if mutation == "legacy": data, expected = encoded(inner(document)), "replayed"
                if mutation == "missing_reference":
                    for blob in (case / "image-references").glob("*.knblob"): blob.unlink()
                    expected = "sweep_reference_or_schedule_mismatch" if name.startswith("sweep_") else "reference_missing_or_unreadable"
                path.write_bytes(data)
                if mutation == "pending_only": path.rename(path.with_suffix(".pending"))
                replay(path, expected, legacy=mutation == "legacy")

        # A child's altered report, even with recomputed checksums, invalidates its parent replay.
        case = scratch / "child" / "sweep_modified"
        shutil.copytree(root / "sweep_modified", case)
        child = next((case / "image-reads").glob("*.knslice"))
        document = json.loads(child.read_bytes())
        document["payload"]["recorded_claim"]["policy"] = "unknown.v999"
        child.write_bytes(seal(document))
        replay(target(case), "slice_policy_replay_failed")

        if args.journal_exe:
            journal = str(args.journal_exe.resolve())

            def recover(case, good=True):
                command = [exe, "--offline", "!kmon", "journal", case / "collections/7"] if args.cli else [journal, "--recover", case / "collections/7"]
                result = json.loads(invoke(command, 0 if good else 1).stdout)
                check(not result["replay_established"] and not result["target_coverage_established"], "journal membership never implies replay")
                return result

            def oracle(case, result):
                collection = case / "collections/7"
                session = (collection / "session.knsession").read_bytes()
                check(json.loads(session)["payload"]["policy"] == "kn.image_claim_irp_collection_journal.v3", "versioned journal admission")
                previous, members, sweeps = sha(session), set(), []
                for i in range(1, int(result["committed_segments"]) + 1):
                    raw = (collection / "journal-segments" / f"{i:020}.knjseg").read_bytes()
                    envelope = json.loads(raw)
                    row = envelope["payload"]
                    check(envelope["payload_sha256"] == sha(encoded(row)) and row["previous_sha256"] == previous, "independent physical journal chain")
                    transaction = row["transaction"]
                    check(all(p in members for p in transaction["requires"]), "dependencies precede commit")
                    for member in transaction["members"]:
                        data = (case / member["path"]).read_bytes()
                        check(sha(data) == member["sha256"] and len(data) == int(member["bytes"]), "physical bytes include whole original claim")
                        members.add(member["path"])
                        if member["path"].endswith(".knsweep"): sweeps.append(member["path"])
                    previous = sha(raw)
                check(result["head_sha256"] == previous and result["committed_sweep_paths"] == sweeps, "exact accepted sweep roots")

            for stage, segments, closed in (("scope_files", 0, False), ("scope_reads", 2, False),
                                             ("scope_sweep", 3, False), ("scope_closed", 4, True)):
                case = scratch / stage / "sweep_modified"
                shutil.copytree(root / "sweep_modified", case)
                actor = subprocess.Popen([journal, "--commit-published", str(case), stage, "3"], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
                observed = queue.Queue()
                thread = threading.Thread(target=lambda: observed.put(actor.stdout.readline()), daemon=True)
                thread.start()
                try:
                    check(observed.get(timeout=60).strip() == "[journal.stage] " + stage, "observed publication boundary before kill")
                finally:
                    actor.kill()
                    actor.communicate(timeout=30)
                    thread.join(timeout=5)
                result = recover(case)
                check(int(result["committed_segments"]) == segments and result["closed"] == closed, "interrupted verified prefix and closure")
                oracle(case, result)
                replay(target(case))  # Original report reproduction alone does not commit the orphan root.
                if closed:
                    member = next((case / "image-reads").glob("*.knslice"))
                    original = member.read_bytes()
                    document = json.loads(original)
                    document["payload"]["recorded_claim"]["ledgers"]["trust"]["collector_authenticated"] = True
                    member.write_bytes(seal(document))
                    check(recover(case, False)["issue"] == "member_hash_or_size_mismatch", "rehashed claim substitution rejected by journal")
                    member.write_bytes(original)
                    oracle(case, recover(case))
            for version in ("1", "2"):
                case = scratch / ("legacy-policy-" + version) / "sweep_modified"
                shutil.copytree(root / "sweep_modified", case)
                invoke([journal, "--commit-published", case, "", version], 1)
                check(recover(case)["committed_segments"] == "0", "legacy policies cannot silently admit new claims")

    print(f"[image.scope.publication] checks={checks} cases={len(SLICES) + len(SWEEPS)} journal={bool(args.journal_exe)} fixtures={root}")


if __name__ == "__main__":
    main()
