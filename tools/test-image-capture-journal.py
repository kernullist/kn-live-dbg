"""Direct capture archival: independent hashes, original claims, restart and GC boundaries."""
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

from image_claim_oracle import check_original_claim, check_report, unpack_recipe


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def seal(value, field="payload_sha256"):
    value[field] = sha(encoded(value["payload"]))
    return encoded(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path, required=True, help="image harness with observed interruption hooks")
    parser.add_argument("--journal-exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    exe, producer, journal = map(lambda p: p.resolve(), (args.exe, args.producer, args.journal_exe))
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, message
        checks += 1

    def invoke(command, code=0):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, encoding="utf-8", timeout=60)
        check(result.returncode == code, f"exit {result.returncode}, expected {code}: {result.stdout[:300]} ... {result.stdout[-500:]} {result.stderr[-300:]}")
        if code == 2:
            check(not result.stdout and "usage:" in result.stderr, "grammar fails without evidence publication")
            return None
        return json.loads(result.stdout)

    def init(root):
        command = [exe, "--offline", "!kmon", "init-store", root, "/acl-only"] if args.cli else [producer, "--init-store", root]
        check(invoke(command)["status"] == "ready", "explicit owned ACL-only private store")

    def archive(case, root, identifier="7", code=0):
        command = [exe, "--offline", "!kmon", "journal-image"] if args.cli else [exe, "--archive"]
        result = invoke([*command, case, root, identifier], code)
        for key in ("source_directory_privacy_changed", "semantic_replay_established", "collector_authenticated", "power_loss_durability_established"):
            check(result[key] is False, "archive does not overstate " + key)
        return result

    def recover(root, index=False, code=0):
        command = [exe, "--offline", "!kmon", "journal", root / "collections/7"] if args.cli else [journal, "--recover", root / "collections/7"]
        result = invoke(command + (["/index" if args.cli else "--index"] if index else []), code)
        check(not result["replay_established"] and not result["target_coverage_established"], "verified membership is not replay")
        return result

    def inventory(root, code=0):
        command = [exe, "--offline", "!kmon", "store", root, "/artifacts"] if args.cli else [journal, "--store", root]
        result = invoke(command, code)
        if code == 0:
            check(result["artifacts_sha256"] == sha(encoded(result["artifacts"])), "independent physical inventory receipt")
        return result

    def replay(path, document, reference, expected="replayed"):
        command = [exe, "--offline", "!kmon", "replay-image", path] if args.cli else [exe, "--report", path]
        report = invoke(command, 0 if expected == "replayed" else 1)
        check(report["status"] == expected, "managed replay status")
        if expected == "replayed":
            check_original_claim(document, report)
            check_report(unpack_recipe(document), reference, report)
            checks_before = report["original_claim_replay"]
            check(not checks_before["journal_membership_checked"], "claim reproduction never invents a journal check")
        else:
            check(report["claim_assessment"] is None, "failed original policy cannot publish claims")
        return report

    def files(root):
        return {p.relative_to(root).as_posix(): sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}

    def oracle(root, result):
        collection = root / "collections/7"
        session = (collection / "session.knsession").read_bytes()
        doc = json.loads(session)
        check(sha(encoded(doc["payload"])) == doc["payload_sha256"], "session payload hash")
        check(doc["payload"]["policy"] == "kn.direct_image_collection_journal.v1", "explicit direct collection policy")
        previous, members, logical, captures = sha(session), {}, 0, []
        for number in range(1, int(result["committed_segments"]) + 1):
            raw = (collection / "journal-segments" / f"{number:020}.knjseg").read_bytes()
            doc = json.loads(raw)
            row = doc["payload"]
            check(encoded(doc) == raw and doc["payload_sha256"] == sha(encoded(row)), "independent canonical segment")
            check(row["sequence"] == str(number) and row["previous_sha256"] == previous, "exact physical hash chain")
            transaction = row["transaction"]
            check(transaction["requires"] == sorted(members) if number == 2 else not transaction["requires"], "closure binds both original members")
            check(transaction["kind"] == ("image_capture" if number == 1 else "closure"), "direct transaction order")
            for member in transaction["members"]:
                raw_member = (root / member["path"]).read_bytes()
                check(sha(raw_member) == member["sha256"] and str(len(raw_member)) == member["bytes"], "exact retained member bytes")
                members[member["path"]] = member
                logical += len(raw_member)
                if member["path"].endswith(".kncapture"):
                    captures.append(member["path"])
                    check(transaction["id"] == member["sha256"], "transaction binds physical capture digest")
            previous = sha(raw)
        check(result["head_sha256"] == previous and result["unique_paths"] == str(len(members)) and
              result["logical_bytes"] == str(logical), "independent journal denominators")
        check(result["committed_direct_capture_paths"] == captures and result["committed_sweep_paths"] == [], "direct roots separate from sweeps")

    with tempfile.TemporaryDirectory(prefix="capture-journal-", dir=args.fixtures) as temporary:
        sandbox = Path(temporary)
        source = args.fixtures / "observed-modified"
        publication = json.loads((source / "recipe.knverify").read_bytes())
        recipe = unpack_recipe(publication)
        reference = (source / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes()
        loose = sandbox / "loose-direct"
        init(loose)
        ref = "image-references/" + sha(reference) + ".knblob"
        (loose / ref).parent.mkdir(exist_ok=True)
        (loose / ref).write_bytes(reference)
        (loose / "image-captures").mkdir(exist_ok=True)
        parents = {}
        for i, document in enumerate((recipe, publication), 1):
            raw = encoded(document)
            path = f"image-captures/capture-{i}-{sha(raw)}.kncapture"
            (loose / path).write_bytes(raw)
            parents[path] = sha(raw)
        rows = {r["artifact"]["path"]: r for r in inventory(loose)["artifacts"]}
        expected = [dict(path=p, sha256=h, expected_sha256=sha(reference), digest_basis="file_bytes", input_matched=True)
                    for p, h in sorted(parents.items())]
        check(rows[ref]["retention"] == "uncommitted_image_input_protected" and
              rows[ref]["uncommitted_image_referrers"] == expected and all(rows[p]["image_catalog"] == "resolved" for p in parents),
              "bare and claim-wrapped direct captures independently protect the same original")
        loose_policy = sandbox / "loose-direct.gc-policy"
        loose_policy.write_bytes(encoded(dict(schema="kn.evidence_gc_policy.v1", policy="kn.gc_explicit_uncommitted.v1",
            reason="owned direct image input", minimum_age_seconds="0", byte_limit="67108864", members=[rows[ref]["artifact"]])))
        command = [exe, "--offline", "!kmon", "gc", loose, loose_policy, "/apply", "1"] if args.cli else [journal, "--gc", loose, loose_policy, "1"]
        denied = invoke(command, 1)
        check(denied["entries"][0]["issue"] == "uncommitted_image_input_protected" and denied["deleted_this_call"] == "0" and
              not (loose / "retention/1/operation.kngc").exists() and (loose / ref).read_bytes() == reference,
              "direct PE deletion denied before intent")
        for path in parents:
            replay(loose / path, json.loads((loose / path).read_bytes()), reference)
        store = sandbox / "private 한글"
        init(store)
        for index, name in enumerate(("clean", "modified", "observed", "observed-modified", "unstable", "sparse", "observed-budget"), 7):
            case = sandbox / name
            shutil.copytree(args.fixtures / name, case)
            original = files(case)
            document = json.loads((case / "recipe.knverify").read_bytes())
            retained = (case / (unpack_recipe(document)["payload"]["reference_sha256"] + ".knblob")).read_bytes()
            result = archive(case, store, str(index))
            check(result["status"] == "archived" and result["closed"] and result["indexed"] and result["capture_committed"], "complete archive")
            check(result["capture_created"] and result["reference_created"] == (index == 7), "shared reference deduplicated across captures")
            managed = store / result["capture_path"]
            check(managed.read_bytes() == (case / "recipe.knverify").read_bytes() and files(case) == original, "exact root copy and unchanged original")
            ledger = json.loads((store / f"image-captures/session-{index}.kncaptureledger").read_bytes())
            check(ledger["archived_captures"] == "1" and ledger["logical_referenced_bytes"] == str(managed.stat().st_size + len(retained)) and
                  ledger["capture_sha256"] == sha(managed.read_bytes()) and ledger["reference_sha256"] == sha(retained), "independent final archival denominator and original hashes")
            check(ledger["denominator_scope"] == "one_archived_capture" and not ledger["original_live_attempts_known"], "archive ledger does not reconstruct live attempts")
            snapshot = files(store)
            retry = archive(case, store, str(index))
            check(not retry["capture_created"] and not retry["reference_created"] and files(store) == snapshot, "idempotent closed retry")
            shutil.rmtree(case)  # Owned temporary case only; replay must survive its removal.
            replay(managed, document, retained)
        result = recover(store, True)
        check(result["closed"] and result["committed_segments"] == "2", "one capture and one closure")
        oracle(store, result)
        before = files(store)
        refused = archive(source, store, "7", 1)
        check(refused["issue"] == "collection_contains_different_capture" and files(store) == before, "different input cannot append or create orphans in closed collection")
        report = inventory(store)
        check(report["closed_collections"] == "7" and len(report["artifacts"]) == 15 and report["unattributed_files"] == "0", "cross-collection exact path deduplication")

        for version, name in (("v1", "modified"), ("v2", "observed-modified")):
            case = sandbox / ("legacy-" + version)
            shutil.copytree(args.fixtures / name, case)
            legacy = unpack_recipe(json.loads((case / "recipe.knverify").read_bytes()))
            (case / "recipe.knverify").write_bytes(encoded(legacy))
            result = archive(case, store, "21" if version == "v1" else "22")
            check(not result["original_claim_recorded"], "legacy recipe does not invent original claims")
            replay(store / result["capture_path"], legacy, reference)

        # Archival validates the retained structure/hash; independent replay tests the assertion.
        forged = sandbox / "forged"
        shutil.copytree(source, forged)
        altered = copy.deepcopy(publication)
        altered["payload"]["recorded_claim"]["claims"][1]["status"] = "unfulfilled"
        (forged / "recipe.knverify").write_bytes(seal(altered, "publication_sha256"))
        # The publication format's exact field names are enforced by its parser.
        forged_result = archive(forged, store, "23")
        replay(store / forged_result["capture_path"], altered, reference, "recorded_claim_assessment_mismatch")
        if args.cli:
            minimized = sandbox / "forged-disclosure"
            denied = invoke([exe, "--offline", "!kmon", "redact-image", store / forged_result["capture_path"], minimized, "/acl-only"], 1)
            check(denied["status"] == "denied" and not minimized.exists(), "archival does not bypass original-claim reproduction before redaction")

        for fault in ("missing-reference", "bad-reference", "bad-root", "bad-publication", "oversized-root", "writer-held"):
            case = sandbox / fault
            shutil.copytree(source, case)
            root = sandbox / (fault + "-store")
            init(root)
            blob = case / (recipe["payload"]["reference_sha256"] + ".knblob")
            lock = None
            try:
                if fault == "missing-reference": blob.unlink()
                elif fault == "bad-reference": blob.write_bytes(b"owned corrupt reference")
                elif fault == "bad-root": (case / "recipe.knverify").write_bytes(b"{}")
                elif fault == "bad-publication": (case / "recipe.knverify").write_bytes(b'{"schema":"kn.image_claim_publication.v1"}')
                elif fault == "oversized-root": (case / "recipe.knverify").write_bytes(b" " * (4 * 1024 * 1024 + 1))
                else: lock = (case / "recipe.knverify").open("r+b")
                snapshot = files(root)
                rejected = archive(case, root, code=1)
                check(rejected["status"] == "unavailable" and files(root) == snapshot, "invalid source cannot begin a journal")
                if fault == "bad-publication": check(not rejected["original_claim_recorded"], "a schema label alone cannot claim original-report retention")
            finally:
                if lock: lock.close()
        unprotected = sandbox / "not-private"
        unprotected.mkdir()
        check(archive(source, unprotected, code=1)["issue"] == "private_store_unavailable" and not list(unprotected.iterdir()), "private policy required before writes")
        weak = sandbox / "weak-reference"
        init(weak)
        blob = weak / ("image-references/" + sha(reference) + ".knblob")
        blob.parent.mkdir()
        blob.write_bytes(reference)
        changed_acl = subprocess.run(["icacls", str(blob), "/grant", "*S-1-1-0:(R)"], capture_output=True, timeout=30)
        check(changed_acl.returncode == 0, "owned reference receives explicit public read ACE")
        denied = archive(source, weak, code=1)
        check(denied["issue"] == "reference_publication_or_verification_failed" and not denied["capture_committed"] and
              blob.read_bytes() == reference, "exact bytes do not bypass private file admission")

        stages = {"session": 0, "reference": 0, "capture": 0, "capture_commit": 1, "ledger": 1, "closed": 2}
        for stage, count in stages.items():
            root = sandbox / ("interrupt-" + stage)
            init(root)
            actor = subprocess.Popen([str(producer), "--archive", str(source), str(root), "7", stage], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            observed = queue.Queue()
            reader = threading.Thread(target=lambda: observed.put(actor.stdout.readline()), daemon=True)
            reader.start()
            try:
                check(observed.get(timeout=60).strip() == "[capture.stage] " + stage and actor.poll() is None, "kill only after observed publication boundary")
                inventory(root, 1)
                archive(source, root, code=1)
                if stage == "reference":
                    try:
                        (root / "image-captures").rename(root / "unexpected-capture-move")
                        raise AssertionError("an empty capture directory must be pinned before publication")
                    except PermissionError:
                        check(True, "output directory denies rename before its first file")
                if stage in ("capture", "capture_commit", "ledger", "closed"):
                    path = next((root / "image-captures").glob("*.kncapture"))
                    try:
                        with path.open("r+b"):
                            raise AssertionError("publisher must exclude writes to retained files")
                    except PermissionError:
                        check(True, "published capture pinned through commit")
                actor.kill()
                actor.communicate(timeout=10)
            finally:
                if actor.poll() is None:
                    actor.kill()
                    actor.communicate(timeout=10)
                reader.join(timeout=2)
            recovered = recover(root, True)
            check(recovered["committed_segments"] == str(count) and recovered["closed"] == (stage == "closed"), "only complete committed prefix survives")
            oracle(root, recovered)
            unfinished = inventory(root, 0 if stage == "closed" else 1)
            check(unfinished["membership_complete"] == (stage == "closed"), "open collection protects unattributed evidence")
            rows = unfinished["artifacts"]
            if stage == "ledger":
                ledger = next(row for row in rows if row["artifact"]["path"].endswith(".kncaptureledger"))
                check(ledger["retention"] == "failure_ledger_protected", "uncommitted final ledger remains protected")
            resumed = archive(source, root)
            check(resumed["closed"] and resumed["indexed"], "exact retry closes interrupted archive")
            replay(root / resumed["capture_path"], publication, reference)

        baseline = sandbox / "interrupt-closed"
        for fault in ("managed-missing-reference", "managed-corrupt-reference", "managed-corrupt-root"):
            root = sandbox / fault
            shutil.copytree(baseline, root)
            managed = next((root / "image-captures").glob("*.kncapture"))
            retained = root / ("image-references/" + sha(reference) + ".knblob")
            if fault == "managed-missing-reference": retained.unlink()
            elif fault == "managed-corrupt-reference": retained.write_bytes(b"owned corrupted reference")
            else: managed.write_bytes(b"{}")
            replay(managed, publication, reference, {"managed-missing-reference": "reference_missing_or_unreadable",
                   "managed-corrupt-reference": "reference_corrupt", "managed-corrupt-root": "recipe_unavailable_or_corrupt"}[fault])
        for fault in ("reference", "capture", "ledger", "index"):
            root = sandbox / ("collision-" + fault)
            init(root)
            if fault == "reference":
                relative = "image-references/" + sha(reference) + ".knblob"
            elif fault == "capture":
                relative = "image-captures/capture-7-" + sha((source / "recipe.knverify").read_bytes()) + ".kncapture"
            elif fault == "ledger": relative = "image-captures/session-7.kncaptureledger"
            else:
                segment = (baseline / "collections/7/journal-segments/00000000000000000001.knjseg").read_bytes()
                relative = "collections/7/indexes/chunks/" + sha(segment) + ".knjindex"
            collision = root / relative
            collision.parent.mkdir(parents=True, exist_ok=True)
            collision.write_bytes(b"owned collision sentinel")
            result = archive(source, root, code=1)
            check(collision.read_bytes() == b"owned collision sentinel" and result["status"] == "incomplete", "collisions never replace existing files")
            check(result["capture_committed"] == (fault in ("ledger", "index")) and not result["closed"] and not result["indexed"], "partial archive status preserves exact commit boundary")
            archive(source, root, code=1)
            collision.unlink()  # Only this test's known sentinel; no deletion in the publisher.
            check(archive(source, root)["closed"], "explicitly resolving owned collision permits exact retry")

        for fault in ("policy-v1", "policy-v2", "policy-v3", "policy-v4", "missing-dependency", "wrong-kind", "wrong-root-id", "corrupt-member", "wrong-reference"):
            root = sandbox / fault
            shutil.copytree(baseline, root)
            collection = root / "collections/7"
            if fault.startswith("policy-"):
                policy = {"policy-v1": "kn.image_collection_journal.v1", "policy-v2": "kn.image_irp_collection_journal.v2",
                          "policy-v3": "kn.image_claim_irp_collection_journal.v3", "policy-v4": "kn.image_irp_claim_collection_journal.v4"}[fault]
                session_path = collection / "session.knsession"
                session = json.loads(session_path.read_bytes())
                session["payload"]["policy"] = policy
                session_path.write_bytes(seal(session))
            previous = sha((collection / "session.knsession").read_bytes())
            for number, path in enumerate(sorted((collection / "journal-segments").glob("*.knjseg")), 1):
                doc = json.loads(path.read_bytes())
                doc["payload"]["previous_sha256"] = previous
                transaction = doc["payload"]["transaction"]
                if number == 1 and fault == "wrong-reference":
                    ref = next(m for m in transaction["members"] if m["schema"] == "raw.bytes")
                    original_ref = ref["path"]
                    replacement = b"owned replacement".ljust(int(ref["bytes"]), b"!")
                    alternate = f"image-references/{sha(replacement)}.knblob"
                    (root / alternate).write_bytes(replacement)
                    ref.update(path=alternate, sha256=sha(replacement), bytes=str(len(replacement)))
                    transaction["members"].sort(key=lambda m: m["path"])
                if number == 2 and fault == "wrong-reference":
                    transaction["requires"] = sorted(alternate if p == original_ref else p for p in transaction["requires"])
                if number == 1 and fault == "wrong-kind": transaction["kind"] = "image_reads"
                if number == 1 and fault == "wrong-root-id": transaction["id"] = "0" * 64
                if number == 2 and fault == "missing-dependency": transaction["requires"].pop()
                path.write_bytes(seal(doc))
                previous = sha(path.read_bytes())
            if fault == "corrupt-member": next((root / "image-captures").glob("*.kncapture")).write_bytes(b"{}")
            recovered = recover(root, code=1)
            if fault == "wrong-reference":
                check(recovered["issue"] == "image_reference_not_committed", "unrelated but correctly hashed PE cannot replace recipe input")
            check(not recovered["closed"] and recovered["committed_segments"] == ("1" if fault == "missing-dependency" else "0"), "rehashed invalid policy/transaction cannot establish membership")

        orphan = store / ("image-captures/capture-99-" + sha(encoded(recipe)) + ".kncapture")
        orphan.write_bytes(encoded(recipe))
        orphan_ledger = store / "image-captures/session-99.kncaptureledger"
        orphan_ledger.write_bytes((store / "image-captures/session-7.kncaptureledger").read_bytes())
        rows = inventory(store)["artifacts"]
        committed_root = next((store / "image-captures").glob("capture-7-*.kncapture"))
        for selected, eligible in ((orphan, True), (orphan_ledger, False), (committed_root, False)):
            row = next(r for r in rows if r["artifact"]["path"] == selected.relative_to(store).as_posix())
            check(row["verified"] and row["retention"] == ("uncommitted_requires_policy" if eligible else
                  "failure_ledger_protected" if selected == orphan_ledger else "committed_original_protected"), "direct artifacts retain conservative GC classification")
            policy = sandbox / (selected.name + ".policy")
            policy.write_bytes(encoded({"schema": "kn.evidence_gc_policy.v1", "policy": "kn.gc_explicit_uncommitted.v1",
                "reason": "owned direct-capture GC control", "minimum_age_seconds": "0", "byte_limit": "67108864", "members": [row["artifact"]]}))
            command = [exe, "--offline", "!kmon", "gc", store, policy] if args.cli else [journal, "--gc", store, policy, "-"]
            result = invoke(command, 0 if eligible else 1)
            expected = "planned" if eligible else "unavailable" if selected == orphan_ledger else "denied"
            check(result["status"] == expected and selected.exists(), f"GC preflight preserves selected evidence: {result}")
            if eligible:
                command = [exe, "--offline", "!kmon", "gc", store, policy, "/apply", "99"] if args.cli else [journal, "--gc", store, policy, "99"]
                check(invoke(command)["status"] == "completed" and not selected.exists(), "explicit owned orphan removal uses durable GC path")

        if args.cli:
            encrypted = sandbox / "encrypted-store"
            protection = invoke([exe, "--offline", "!kmon", "init-store", encrypted])
            check(protection["status"] == "ready" and protection["efs_required"], "default private store requires EFS")
            secured = archive(source, encrypted)
            check(secured["closed"] and all(path.stat().st_file_attributes & 0x4000 for path in encrypted.rglob("*") if path.is_file()),
                  "all published originals and journal files inherit EFS")
            check(invoke([exe, "--offline", "!kmon", "privacy", encrypted, "/audit"])["status"] == "ready", "private admission survives full EFS output audit")
            for tail in ([], [source, store], [source, store, "01"], [source, store, "7", "/json", "/json"], [source, store, "7", "/unknown"]):
                invoke([exe, "--offline", "!kmon", "journal-image", *tail], 2)
            sink = sandbox / "read-only-output"
            sink.write_bytes(b"owned sentinel")
            with sink.open("rb") as output:
                attempt = subprocess.run(list(map(str, [exe, "--offline", "!kmon", "journal-image", source, store, "30"])),
                                         stdout=output, stderr=subprocess.PIPE, timeout=60)
            check(attempt.returncode == 3 and sink.read_bytes() == b"owned sentinel", "stdout delivery failure is reported after preserving committed files")
    print(f"[image.capture.journal] checks={checks} interrupted_stages=6 children_remaining=0 mode={'cli' if args.cli else 'harness'}")


if __name__ == "__main__":
    main()
