"""Pinned historical approval collection: exact originals, replay, interruption and retention."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import queue
import shutil
import stat
import subprocess
import tempfile
import threading

from approval_retention_oracle import check_uncommitted_approvals
from image_claim_oracle import check_original_claim, check_report, unpack_recipe

SPEC = importlib.util.spec_from_file_location("approval_inputs", Path(__file__).with_name("test-image-authorized-changes.py"))
INPUTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INPUTS)
encoded, sha = INPUTS.encoded, INPUTS.sha


def seal(document, field="payload_sha256"):
    document[field] = sha(encoded(document["payload"]))
    return encoded(document)


def is_junction(path):
    return path.lstat().st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--journal-exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    exe, producer, journal, fixtures = map(lambda p: p.resolve(), (args.exe, args.producer, args.journal_exe, args.fixtures))
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, str(message)[:1800]
        checks += 1

    def invoke(command, code=0):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, encoding="utf-8", timeout=90)
        check(result.returncode == code, f"exit={result.returncode} expected={code}: {result.stdout[:1000]} {result.stderr[-300:]}")
        if code == 2:
            check(not result.stdout and "usage:" in result.stderr, "grammar rejected before publication")
            return None
        return json.loads(result.stdout)

    def init(root, efs=False):
        command = [exe, "--offline", "!kmon", "init-store", root] + ([] if efs else ["/acl-only"]) if args.cli else [producer, "--init-store", root]
        check(invoke(command)["status"] == "ready", "owned private store initialized")

    def archive(inputs, root, identifier="7", code=0, actor=None, when=0):
        case, change, policy, anchor = inputs
        command = [exe, "--offline", "!kmon", "journal-image-approval"] if args.cli and actor is None else [actor or exe, "--archive-approval"]
        tail = [] if args.cli and actor is None else [when]
        result = invoke([*command, case, change, policy, anchor, root, identifier, *tail], code)
        check(all(not result[key] for key in ("source_privacy_changed", "current_approval_established", "collector_authenticated", "power_loss_durability_established")), "archive preserves trust limits")
        return result

    def replay(path, anchor, current=False, code=0, issue=None):
        command = [exe, "--offline", "!kmon", "replay-image-approval"] if args.cli else [exe, "--replay-approval"]
        result = invoke([*command, path, anchor] + (["/current"] if current else []), code)
        check(not result["journal_membership_checked"] and not result["collector_authenticated"] and not result["execution_observed"], "replay does not invent membership or authentication")
        if issue is not None:
            check(result["issue"] == issue and not result["original_assessment_reproduced"], result["issue"])
        if code == 0:
            check(result["status"] == ("reanalyzed" if current else "reproduced") and result["original_assessment_reproduced"] == (not current), result["status"])
            if not current:
                check(result["assessment"] == result["recorded_assessment"], "original report exactly reproduced")
            pub = json.loads(path.read_bytes())["payload"]
            store = path.parent.parent
            capture = store / f'image-captures/capture-{pub["collection_id"]}-{pub["capture_sha256"]}.kncapture'
            original = json.loads(capture.read_bytes())
            raw = (store / f'image-references/{pub["reference_sha256"]}.knblob').read_bytes()
            check_original_claim(original, result["assessment"]["replay"])
            check_report(unpack_recipe(original), raw, result["assessment"]["replay"])
        return result

    def recover(root, code=0, identifier="7"):
        command = [exe, "--offline", "!kmon", "journal", root / "collections" / identifier, "/index"] if args.cli else [journal, "--recover", root / "collections" / identifier, "--index"]
        result = invoke(command, code)
        check(not result["replay_established"], "membership independent of semantic replay")
        return result

    def inventory(root, code=0):
        command = [exe, "--offline", "!kmon", "store", root, "/artifacts"] if args.cli else [journal, "--store", root]
        result = invoke(command, code)
        if code == 0:
            check(result["artifacts_sha256"] == sha(encoded(result["artifacts"])), "independent inventory hash")
        return result

    def files(root):
        return {p.relative_to(root).as_posix(): sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}

    def oracle(root, result, identifier="7"):
        collection = root / "collections" / identifier
        raw = (collection / "session.knsession").read_bytes()
        session = json.loads(raw)
        check(session["payload"]["policy"] == "kn.approved_image_collection_journal.v1" and session["payload_sha256"] == sha(encoded(session["payload"])), "dedicated canonical approval policy")
        previous, members, approvals, captures = sha(raw), {}, [], []
        for index in range(1, int(result["committed_segments"]) + 1):
            raw = (collection / "journal-segments" / f"{index:020}.knjseg").read_bytes()
            segment = json.loads(raw)
            tx = segment["payload"]["transaction"]
            check(encoded(segment) == raw and segment["payload_sha256"] == sha(encoded(segment["payload"])), "canonical journal hash")
            check(segment["payload"]["previous_sha256"] == previous and segment["payload"]["sequence"] == str(index), "physical hash chain")
            check(tx["kind"] == ("image_approval" if index == 1 else "closure") and len(tx["members"]) == (5 if index == 1 else 1), "five-member assessment then closure")
            check(tx["requires"] == (sorted(members) if index == 2 else []), "closure requires all five prior originals")
            for member in tx["members"]:
                raw_member = (root / member["path"]).read_bytes()
                check(sha(raw_member) == member["sha256"] and len(raw_member) == int(member["bytes"]), "exact original member hash and length")
                members[member["path"]] = member
                if member["path"].endswith(".kncapture"):
                    captures.append(member["path"])
                if member["schema"] == "kn.image_approval_publication.v1":
                    approvals.append(member["path"])
                    check(tx["id"] == member["sha256"], "transaction ID is physical assessment root hash")
                    publication = json.loads(raw_member)
                    check(publication["publication_sha256"] == sha(encoded(publication["payload"])), "original report payload checksum")
            previous = sha(raw)
        check(result["head_sha256"] == previous and result["unique_paths"] == str(len(members)), "final prefix identity and member count")
        check(result["logical_bytes"] == str(sum(int(m["bytes"]) for m in members.values())), "logical bytes count all originals")
        check(result["committed_approval_paths"] == approvals and result["committed_direct_capture_paths"] == captures, "typed committed roots")

    with tempfile.TemporaryDirectory(prefix="approval-journal-", dir=fixtures) as temporary:
        sandbox = Path(temporary).resolve()
        assert sandbox.is_relative_to(fixtures)

        def remove_owned(path):
            assert path.resolve().is_relative_to(sandbox) and path.resolve() != sandbox
            shutil.rmtree(path)

        def prepare(name, prefix, expire=False):
            directory = sandbox / prefix
            directory.mkdir()
            case = directory / "source"
            shutil.copytree(fixtures / name, case)
            document = json.loads((case / "recipe.knverify").read_bytes())
            recipe = unpack_recipe(document)
            raw = (case / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes()
            manifest, _, _ = INPUTS.material(recipe, raw, int(recipe["payload"]["rva"]) + 0x150)
            when = int(recipe["payload"]["captured_filetime"]) + 10
            if expire:
                manifest["not_after_filetime"] = str(when + 10)
            policy = INPUTS.policy_for(manifest)
            if expire:
                policy["not_after_filetime"] = str(when + 10)
            changes, approved = directory / "변경.knchange", directory / "승인.knapproval"
            changes.write_bytes(encoded(manifest))
            approved.write_bytes(encoded(policy))
            return (case, changes, approved, sha(approved.read_bytes())), document, raw, when

        inputs, original, original_ref, _ = prepare("observed-modified", "baseline-inputs")
        store = sandbox / "private 한글"
        init(store)
        baseline = archive(inputs, store)
        check(baseline["committed"] and baseline["closed"] and baseline["indexed"] and not baseline["historical_root_reused"], "new collection closed")
        root_path = store / baseline["approval_path"]
        pub = json.loads(root_path.read_bytes())["payload"]
        check(pub["policy_sha256"] == inputs[3] and pub["capture_sha256"] == sha((inputs[0] / "recipe.knverify").read_bytes()), "physical inputs bound to original result")
        snapshot = files(store)
        check(archive(inputs, store)["historical_root_reused"] and files(store) == snapshot, "closed retry preserves original time and exact bytes")
        oracle(store, recover(store))
        replay(root_path, inputs[3])
        now = replay(root_path, inputs[3], current=True)
        check(now["assessment"]["clock_basis"] == "host_wall_clock" and now["recorded_assessment"]["clock_basis"] == "caller_supplied_time", "historical and current clock roles distinct")
        replay(root_path, "0" * 64, code=1, issue="recorded_policy_anchor_mismatch")
        check(archive(inputs, store, "8")["closed"], "shared approval inputs support another collection")
        check_uncommitted_approvals(store, root_path, sandbox, init=init, inventory=inventory, invoke=invoke,
                                   check=check, journal=journal, product=exe if args.cli else None)
        catalog = inventory(store)["artifacts"]
        for suffix in (".knapproval", ".knchange", ".knblob"):
            row = next(row for row in catalog if row["artifact"]["path"].endswith(suffix))
            check(int(row["journal_references"]) == 2 and row["collections"] == ["7", "8"] and row["retention"] ==
                  ("committed_reference_protected" if suffix == ".knblob" else "committed_original_protected"),
                  "shared originals retained by both collections")

        alternate, _, _, _ = prepare("modified", "alternate-inputs")
        before = files(store)
        rejected = archive(alternate, store, code=1)
        check(rejected["issue"] == "existing_approval_root_conflict" and not rejected["committed"] and not rejected["closed"] and files(store) == before,
              "closed collection cannot replace its historical input binding")
        replacement_policy = inputs[2].parent / "replacement.knapproval"
        replacement_policy.write_bytes(encoded({**json.loads(inputs[2].read_bytes()), "policy_id": "new-owned-approval"}))
        rejected = archive((inputs[0], inputs[1], replacement_policy, sha(replacement_policy.read_bytes())), store, code=1)
        check(rejected["issue"] == "existing_approval_root_conflict" and not rejected["committed"] and not rejected["closed"] and files(store) == before,
              "a different caller-pinned policy cannot inherit historical commit or closure")
        # Change only the caller's directory alias after all original inputs
        # have been opened. The assessment must still describe those originals.
        alias = sandbox / "source-junction"

        def point_alias(target):
            assert alias.parent.resolve() == sandbox and target.resolve().is_relative_to(sandbox)
            if alias.exists():
                assert is_junction(alias) and alias.resolve().is_relative_to(sandbox)
                os.rmdir(alias)  # Remove only this owned reparse entry, never its target.
            env = dict(os.environ, KN_APPROVAL_TEST_LINK=str(alias), KN_APPROVAL_TEST_TARGET=str(target))
            result = subprocess.run(["powershell", "-NoProfile", "-Command",
                                     "New-Item -ItemType Junction -Path $env:KN_APPROVAL_TEST_LINK -Target $env:KN_APPROVAL_TEST_TARGET | Out-Null"],
                                    env=env, capture_output=True, timeout=30)
            check(result.returncode == 0 and is_junction(alias) and alias.resolve() == target.resolve(), "owned source junction points to observed target")

        point_alias(inputs[0])
        root = sandbox / "switched-alias"
        init(root)
        actor = subprocess.Popen(list(map(str, [producer, "--archive-approval", alias, *inputs[1:], root, "7", "0", "session"])),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        observed = queue.Queue()
        reader = threading.Thread(target=lambda: observed.put(actor.stdout.readline()), daemon=True)
        reader.start()
        try:
            check(json.loads(observed.get(timeout=60))["stage"] == "session" and actor.poll() is None, "source acquisition precedes alias switch")
            point_alias(alternate[0])
            output, errors = actor.communicate("continue\n", timeout=90)
            check(actor.returncode == 0 and not errors, "archive completes from already opened originals")
            result = json.loads(output)
            check(result["closed"] and (root / result["capture_path"]).read_bytes() == (inputs[0] / "recipe.knverify").read_bytes(),
                  "alias switch cannot replace archived capture bytes")
            replay(root / result["approval_path"], inputs[3])
        finally:
            if actor.poll() is None:
                actor.kill()
                actor.communicate(timeout=10)
            reader.join(timeout=2)
            if alias.exists():
                assert is_junction(alias) and alias.resolve().is_relative_to(sandbox)
                os.rmdir(alias)
        for fault in ("anchor", "oversized-policy", "oversized-manifest", "capture-writer", "reference-writer", "policy-writer", "manifest-writer"):
            selected, doc, raw, _ = prepare("observed-modified", "bad-input-" + fault)
            root = sandbox / ("bad-input-store-" + fault)
            init(root)
            selected = list(selected)
            lock = None
            try:
                if fault == "anchor": selected[3] = "0" * 64
                elif fault == "oversized-policy":
                    selected[2].write_bytes(b" " * (64 * 1024 + 1))
                    selected[3] = sha(selected[2].read_bytes())
                elif fault == "oversized-manifest": selected[1].write_bytes(b" " * (64 * 1024 + 1))
                else:
                    path = {"capture-writer": selected[0] / "recipe.knverify", "reference-writer": selected[0] / (sha(raw) + ".knblob"),
                            "policy-writer": selected[2], "manifest-writer": selected[1]}[fault]
                    lock = path.open("r+b")
                before = files(root)
                denied = archive(selected, root, code=1)
                check(denied["status"] == "unavailable" and not denied["committed"] and files(root) == before,
                      "unavailable or unpinned source cannot start a journal")
            finally:
                if lock: lock.close()
        unprotected = sandbox / "not-private"
        unprotected.mkdir()
        check(archive(inputs, unprotected, code=1)["issue"] == "private_store_unavailable" and not list(unprotected.iterdir()),
              "uninitialized private store cannot receive originals")
        for kind, relative, data in (("policy", f"image-approvals/policy-{inputs[3]}.knapproval", inputs[2].read_bytes()),
                                     ("manifest", f'image-approvals/changes-{baseline["manifest_sha256"]}.knchange', inputs[1].read_bytes()),
                                     ("approval", baseline["approval_path"], root_path.read_bytes())):
            root = sandbox / ("weak-" + kind)
            init(root)
            selected = root / relative
            selected.parent.mkdir(parents=True)
            selected.write_bytes(data)
            result = subprocess.run(["icacls", str(selected), "/grant", "*S-1-1-0:(R)"], capture_output=True, timeout=30)
            check(result.returncode == 0, "owned output receives explicit public read ACE")
            rejected = archive(inputs, root, code=1)
            check(rejected["issue"] == kind + "_publication_failed" and not rejected["committed"] and selected.read_bytes() == data,
                  "matching hashes cannot bypass private admission")

        for identifier, name in enumerate(("clean", "modified", "observed", "unstable", "sparse", "observed-budget"), 20):
            selected, doc, raw, _ = prepare(name, "input-" + name)
            before = files(selected[0].parent)
            result = archive(selected, store, str(identifier))
            check(result["closed"] and files(selected[0].parent) == before, "archive retains successful/incomplete assessments without mutating source")
            remove_owned(selected[0].parent)
            replay(store / result["approval_path"], selected[3])

        for identifier, name in ((31, "modified"), (32, "observed-modified")):
            selected, document, _, _ = prepare(name, "legacy-input-" + name)
            (selected[0] / "recipe.knverify").write_bytes(encoded(unpack_recipe(document)))
            result = archive(selected, store, str(identifier))
            remove_owned(selected[0].parent)
            retained = replay(store / result["approval_path"], selected[3])
            check(retained["assessment"]["replay"]["original_claim_replay"]["status"] == "not_recorded",
                  "bare v1/v2 archival does not invent an original claim")

        expired, _, _, when = prepare("observed-modified", "expired-inputs", expire=True)
        historical = sandbox / "historical"
        init(historical)
        archived = archive(expired, historical, actor=producer, when=when)
        recorded = historical / archived["approval_path"]
        saved = recorded.read_bytes()
        reused_inputs = (historical / archived["capture_path"], historical / f'image-approvals/changes-{archived["manifest_sha256"]}.knchange',
                         historical / f'image-approvals/policy-{expired[3]}.knapproval', expired[3])
        remove_owned(expired[0].parent)
        replay(recorded, expired[3])
        denied = replay(recorded, expired[3], current=True, code=1, issue="current_assessment_unavailable")
        check(denied["assessment"]["issue"] == "approval_not_valid_at_evaluation", "expired approval never becomes current through historical replay")
        check(archive(reused_inputs, historical)["historical_root_reused"] and recorded.read_bytes() == saved, "expired historical archival retry preserves original report")

        stages = {"session": 0, "reference": 0, "capture": 0, "policy": 0, "manifest": 0, "approval": 0, "approval_commit": 1, "ledger": 1, "closed": 2}
        for stage, committed in stages.items():
            root = sandbox / ("interrupt-" + stage)
            init(root)
            command = [producer, "--archive-approval", *inputs, root, "7", "0", stage]
            actor = subprocess.Popen(list(map(str, command)), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            observed = queue.Queue()
            reader = threading.Thread(target=lambda: observed.put(actor.stdout.readline()), daemon=True)
            reader.start()
            saved_root = None
            try:
                line = observed.get(timeout=60)
                check(json.loads(line).get("stage") == stage and actor.poll() is None, "termination follows an observed publication boundary")
                archive(inputs, root, code=1)
                inventory(root, code=1)
                if stage == "reference":
                    destination = root / "moved-approvals"
                    check(destination.resolve().is_relative_to(sandbox), "owned rename target")
                    try:
                        (root / "image-approvals").rename(destination)
                        raise AssertionError("empty approval folder must be pinned")
                    except PermissionError:
                        check(True, "empty approval output folder is pinned")
                if stage in ("approval", "approval_commit", "ledger", "closed"):
                    selected = root / "image-approvals/assessment-7.knapprovalcase"
                    saved_root = selected.read_bytes()
                    try:
                        with selected.open("r+b"):
                            raise AssertionError("approval root must deny writes through commit")
                    except PermissionError:
                        check(True, "approval root write exclusion")
                if stage == "approval":
                    for selected in (inputs[0] / "recipe.knverify", inputs[0] / (baseline["reference_sha256"] + ".knblob"), inputs[1], inputs[2]):
                        try:
                            with selected.open("r+b"):
                                raise AssertionError("source must remain pinned through publication")
                        except PermissionError:
                            check(True, "original input write exclusion through journal commit")
                actor.kill()
                actor.communicate(timeout=10)
            finally:
                if actor.poll() is None:
                    actor.kill()
                    actor.communicate(timeout=10)
                reader.join(timeout=2)
            recovered = recover(root)
            check(recovered["committed_segments"] == str(committed) and recovered["closed"] == (stage == "closed"), "only complete journal transactions survive")
            oracle(root, recovered)
            before = inventory(root, code=0 if stage == "closed" else 1)
            if stage == "ledger":
                row = next(row for row in before["artifacts"] if row["artifact"]["path"].endswith(".knapprovalledger"))
                check(row["retention"] == "failure_ledger_protected", "uncommitted final ledger protected")
            resumed = archive(inputs, root)
            check(resumed["closed"] and resumed["indexed"], "exact retry finishes interrupted collection")
            if saved_root:
                check((root / resumed["approval_path"]).read_bytes() == saved_root, "retry cannot replace original assessment time/report")
            replay(root / resumed["approval_path"], inputs[3])

        for fault in ("reference", "capture", "policy", "manifest", "approval", "ledger"):
            root = sandbox / ("collision-" + fault)
            init(root)
            relative = {"reference": f'image-references/{baseline["reference_sha256"]}.knblob', "capture": baseline["capture_path"],
                        "policy": f'image-approvals/policy-{inputs[3]}.knapproval', "manifest": f'image-approvals/changes-{baseline["manifest_sha256"]}.knchange',
                        "approval": baseline["approval_path"], "ledger": "image-approvals/session-7.knapprovalledger"}[fault]
            selected = root / relative
            selected.parent.mkdir(parents=True, exist_ok=True)
            selected.write_bytes(b"owned collision sentinel")
            denied = archive(inputs, root, code=1)
            check(selected.read_bytes() == b"owned collision sentinel" and denied["committed"] == (fault == "ledger"), "collision preserved with correct commit boundary")
            selected.unlink()
            check(archive(inputs, root)["closed"], "explicit owned collision removal permits retry")

        baseline_store = sandbox / "interrupt-closed"
        root = sandbox / "index-collision"
        init(root)
        selected = root / baseline["approval_path"]
        selected.parent.mkdir()
        selected.write_bytes((baseline_store / baseline["approval_path"]).read_bytes())
        original_approval = selected.read_bytes()
        segment = (baseline_store / "collections/7/journal-segments/00000000000000000001.knjseg").read_bytes()
        collision = root / f"collections/7/indexes/chunks/{sha(segment)}.knjindex"
        collision.parent.mkdir(parents=True)
        collision.write_bytes(b"owned index collision")
        denied = archive(inputs, root, code=1)
        check(denied["committed"] and not denied["closed"] and not denied["indexed"] and denied["issue"] == "derived_index_collision" and
              collision.read_bytes() == b"owned index collision", "derived-index failure preserves committed originals and exact boundary")
        archive(inputs, root, code=1)
        collision.unlink()
        check(archive(inputs, root)["closed"] and selected.read_bytes() == original_approval, "explicit owned index repair cannot change original assessment")
        for fault in ("checksum", "extra-field", "whitespace", "oversized", "time", "path"):
            root = sandbox / ("bad-root-" + fault)
            shutil.copytree(baseline_store, root)
            selected = root / baseline["approval_path"]
            document = json.loads(selected.read_bytes())
            if fault == "checksum": document["publication_sha256"] = "0" * 64
            elif fault == "extra-field": document["unexpected"] = True
            elif fault == "time": document["payload"]["evaluation_filetime"] = "0"
            elif fault == "path": document["payload"]["collection_id"] = "../7"
            raw = b" " * (4 * 1024 * 1024 + 1) if fault == "oversized" else encoded(document) + (b" " if fault == "whitespace" else b"")
            selected.write_bytes(raw)
            replay(selected, inputs[3], code=1, issue="approval_root_unavailable_or_corrupt")
        for field, issue in (("policy_sha256", "approval_inputs_missing_or_corrupt"), ("manifest_sha256", "approval_inputs_missing_or_corrupt"),
                             ("reference_sha256", "capture_or_reference_missing_or_corrupt"), ("capture_sha256", "capture_or_reference_missing_or_corrupt")):
            root = sandbox / ("missing-" + field)
            shutil.copytree(baseline_store, root)
            victim = {"policy_sha256": f'image-approvals/policy-{inputs[3]}.knapproval', "manifest_sha256": f'image-approvals/changes-{baseline["manifest_sha256"]}.knchange',
                      "reference_sha256": f'image-references/{baseline["reference_sha256"]}.knblob', "capture_sha256": baseline["capture_path"]}[field]
            (root / victim).unlink()
            replay(root / baseline["approval_path"], inputs[3], code=1, issue=issue)
            check(recover(root, code=1)["committed_segments"] == "0", "missing original invalidates membership")

        old_policies = ["kn.image_collection_journal.v1", "kn.image_irp_collection_journal.v2", "kn.image_claim_irp_collection_journal.v3",
                        "kn.image_irp_claim_collection_journal.v4", "kn.direct_image_collection_journal.v1"]
        binding_fields = ("capture_sha256", "reference_sha256", "policy_sha256", "manifest_sha256")
        for fault in [*range(5), "dependency", "kind", "root-id", "member", "forged-report", *binding_fields, "catalog-seal", "collection-id"]:
            root = sandbox / ("tamper-" + str(fault))
            shutil.copytree(baseline_store, root)
            collection = root / "collections/7"
            session_path = collection / "session.knsession"
            if isinstance(fault, int):
                document = json.loads(session_path.read_bytes())
                document["payload"]["policy"] = old_policies[fault]
                session_path.write_bytes(seal(document))
            changed_root = fault in (*binding_fields, "catalog-seal", "collection-id", "forged-report")
            if changed_root:
                selected = root / baseline["approval_path"]
                document = json.loads(selected.read_bytes())
                if fault in binding_fields:
                    document["payload"][fault] = "0" * 64
                    if fault != "capture_sha256":
                        document["payload"]["assessment"][fault] = "0" * 64
                    if fault == "policy_sha256":
                        document["payload"]["assessment"]["policy_anchor_sha256"] = "0" * 64
                elif fault == "collection-id":
                    document["payload"]["collection_id"] = "99"
                elif fault == "forged-report":
                    document["payload"]["assessment"]["decision"] = "no_observed_change"
                selected.write_bytes(seal(document, "publication_sha256"))
                if fault == "catalog-seal":
                    document["publication_sha256"] = "0" * 64
                    selected.write_bytes(encoded(document))
                if fault == "forged-report":
                    replay(selected, inputs[3], code=1, issue="recorded_assessment_mismatch")
            previous = sha(session_path.read_bytes())
            for index, path in enumerate(sorted((collection / "journal-segments").glob("*.knjseg")), 1):
                document = json.loads(path.read_bytes())
                document["payload"]["previous_sha256"] = previous
                tx = document["payload"]["transaction"]
                if index == 1:
                    if fault == "kind": tx["kind"] = "image_capture"
                    if fault == "root-id": tx["id"] = "0" * 64
                    if fault == "member": tx["members"].pop()
                    if changed_root:
                        changed = next(m for m in tx["members"] if m["path"].endswith(".knapprovalcase"))
                        raw = (root / changed["path"]).read_bytes()
                        changed["sha256"], changed["bytes"] = sha(raw), str(len(raw))
                        tx["id"] = sha(raw)
                if index == 2 and fault == "dependency": tx["requires"].pop()
                path.write_bytes(seal(document))
                previous = sha(path.read_bytes())
            result = recover(root, code=0 if fault == "forged-report" else 1)
            if fault == "forged-report":
                check(result["closed"] and not result["replay_established"], "rehashing membership cannot authenticate a false assessment")
            else:
                if fault in binding_fields:
                    check(result["issue"] == "approval_input_not_committed", "declared hash selects a different physical member")
                if fault in ("catalog-seal", "collection-id"):
                    check(result["issue"] == "approval_catalog_invalid", "approval catalog requires its original seal and collection")
                check(not result["closed"] and result["committed_segments"] == ("1" if fault == "dependency" else "0"), "old policy or invalid transaction fails closed")

        # Shared approval inputs have no collection ID, but exact orphan policy
        # and membership still govern deletion. Final ledgers remain protected.
        orphan_raw = encoded({**json.loads(inputs[2].read_bytes()), "policy_id": "owned-orphan"})
        orphan = store / f"image-approvals/policy-{sha(orphan_raw)}.knapproval"
        orphan.write_bytes(orphan_raw)
        ledger = store / "image-approvals/session-99.knapprovalledger"
        ledger.write_bytes((store / "image-approvals/session-7.knapprovalledger").read_bytes())
        catalog = inventory(store)["artifacts"]
        for selected, eligible in ((orphan, True), (ledger, False), (root_path, False)):
            row = next(row for row in catalog if row["artifact"]["path"] == selected.relative_to(store).as_posix())
            check(row["verified"] and row["retention"] == ("uncommitted_requires_policy" if eligible else "failure_ledger_protected" if selected == ledger else "committed_original_protected"), "approval artifact retention class")
            policy_path = sandbox / (selected.name + ".gc-policy")
            policy_path.write_bytes(encoded({"schema": "kn.evidence_gc_policy.v1", "policy": "kn.gc_explicit_uncommitted.v1",
                "reason": "owned approval GC control", "minimum_age_seconds": "0", "byte_limit": "67108864", "members": [row["artifact"]]}))
            command = [exe, "--offline", "!kmon", "gc", store, policy_path] if args.cli else [journal, "--gc", store, policy_path, "-"]
            planned = invoke(command, 0 if eligible else 1)
            check(planned["status"] == ("planned" if eligible else "unavailable" if selected == ledger else "denied") and selected.exists(), "GC preflight preserves originals")
            if eligible:
                command = [exe, "--offline", "!kmon", "gc", store, policy_path, "/apply", "99"] if args.cli else [journal, "--gc", store, policy_path, "99"]
                check(invoke(command)["status"] == "completed" and not selected.exists(), "explicit orphan approval removal uses durable GC path")
        if args.cli:
            efs_store = sandbox / "efs-store"
            init(efs_store, efs=True)
            check(archive(inputs, efs_store)["closed"], "default EFS admission covers all approval members")
            check(invoke([exe, "--offline", "!kmon", "privacy", efs_store, "/audit"])["status"] == "ready", "all outputs admitted to private store")
            command = [exe, "--offline", "!kmon", "replay-image-approval", root_path, inputs[3]]
            for tail in (["/current", "/current"], ["/json", "/json"], ["/bad"]):
                invoke([*command, *tail], 2)
            actor = subprocess.Popen(list(map(str, command)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                actor.stdout.close()
                actor.wait(timeout=60)
                check(actor.returncode == 3, "replay stdout delivery failure")
            finally:
                if actor.poll() is None:
                    actor.kill()
                    actor.wait(timeout=10)
                actor.stderr.close()
    print(f"[image.approval.journal] checks={checks} mode={'product' if args.cli else 'harness'} boundaries=9 original_inputs_verified=true")


if __name__ == "__main__":
    main()
