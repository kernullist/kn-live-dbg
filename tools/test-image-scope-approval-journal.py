"""Scoped approval archives: original dependency closure, historical replay and retention."""
import argparse
import hashlib
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
from image_claim_oracle import normalized_pe
from image_scope_claim_oracle import check_scope_report, derive_slice


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def seal(document, key="payload_sha256"):
    document[key] = sha(encoded(document["payload"]))
    return encoded(document)


def inner(document):
    return document["payload"]["artifact"] if document["schema"] == "kn.image_scope_claim_publication.v1" else document


def original_inputs(path):
    raw = path.read_bytes()
    document = inner(json.loads(raw))
    root, p = path.parent.parent, document["payload"]
    sweep = document["schema"] == "kn.image_sweep.v1"
    inputs = {"root.knsweep" if sweep else "root.knslice": raw}
    recipes = []
    if sweep:
        for row in p["slices"]:
            name = f"image-reads/reads-{p['sweep']['collection_id']}-{row['read_set_id']}"
            inputs[name + ".knslice"] = (root / (name + ".knslice")).read_bytes()
            recipes.append(inner(json.loads(inputs[name + ".knslice"])))
            if row["raw_written"]:
                inputs[name + ".knreads"] = (root / (name + ".knreads")).read_bytes()
    else:
        recipes = [document]
    reference = (root / f"image-references/{recipes[0]['payload']['reference_sha256']}.knblob").read_bytes()
    return inputs, document, recipes, reference


def manifest_for(document, recipes, reference, rva, size):
    before, after = bytearray(size), bytearray(size)
    for recipe in recipes:
        p = recipe["payload"]
        derive_slice(recipe, reference)
        for page in p["recorded_result"]:
            comparison = page["comparison"]
            start, count = int(comparison["rva"]), int(comparison["requested_bytes"])
            expected = normalized_pe(reference, int(p["slice"]["relocation_base"]), start, count)
            observed = expected
            reads = p["target_reads"]
            for call in reads["parser_reads"]:
                if call["accepted"] and int(call["address"]) == int(p["image_base"]) + start and int(call["length"]) == count:
                    receipt = reads["attempts"]["reads"][int(call["returned_receipt"]) - 1]["read"]
                    if receipt["status"] == "complete":
                        observed = b"".join(bytes.fromhex(span["bytes_hex"]) for span in receipt["spans"])
                        break
            for address in range(max(start, rva), min(start + count, rva + size)):
                before[address - rva], after[address - rva] = expected[address - start], observed[address - start]
    if before == after:
        after[0] ^= 1  # Proposed change, independently checked as unapplied or unobservable.
    return dict(schema="kn.authorized_image_changes.v1", image_sha256=sha(reference), issuer="owned-scope-issuer",
                policy_epoch="7", not_before_filetime="1", not_after_filetime="18446744073709551615",
                comparison_policy=document["payload"].get("policy", "kn.executable_sweep.temporal.v1"),
                hash_basis="non_fixup_compared_bytes.v1", changes=[dict(rva=str(rva), length=str(size),
                before_sha256=sha(before), after_sha256=sha(after))])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "producer", "journal-exe", "fixtures"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    exe, producer, journal, fixtures = (p.resolve() for p in (args.exe, args.producer, args.journal_exe, args.fixtures))
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, str(message)[:1800]
        checks += 1

    def invoke(command, code=0):
        result = subprocess.run(list(map(str, command)), capture_output=True, encoding="utf-8", timeout=90)
        check(result.returncode == code, (result.returncode, code, result.stdout[:1600], result.stderr[-300:]))
        return json.loads(result.stdout)

    def init(root, efs=False):
        command = [exe, "--offline", "!kmon", "init-store", root] + ([] if efs else ["/acl-only"]) if args.cli else [producer, "--init-store", root]
        check(invoke(command)["status"] == "ready", "private store initialized")

    def archive(inputs, root, identifier="7", code=0, actor=None, when=0):
        command = [exe, "--offline", "!kmon", "journal-image-approval"] if args.cli and actor is None else [actor or exe, "--archive-scope-approval"]
        tail = [] if args.cli and actor is None else [when]
        result = invoke([*command, *inputs, root, identifier, *tail], code)
        check(result["schema"] == "kn.image_scope_approval_collection.v1" and all(not result[key] for key in
              ("source_privacy_changed", "current_approval_established", "collector_authenticated", "atomic_snapshot", "power_loss_durability_established")), result)
        return result

    def replay(path, anchor, code=0, current=False, issue=None):
        command = [exe, "--offline", "!kmon", "replay-image-approval"] if args.cli else [exe, "--replay-scope-approval"]
        result = invoke([*command, path, anchor] + (["/current"] if current else []), code)
        check(result["schema"] == "kn.image_scope_approval_replay.v1" and all(not result[key] for key in
              ("journal_membership_checked", "collector_authenticated", "execution_observed", "atomic_snapshot")), result)
        if issue:
            check(result["issue"] == issue, result)
        if code == 0:
            check(result["policy_anchor_matched"] and result["original_assessment_reproduced"] == (not current), result)
            if not current:
                check(result["recorded_assessment"] == result["assessment"], "exact historical report")
            store = path.parent.parent
            payload = json.loads(path.read_bytes())["payload"]
            catalog = {e["logical_path"]: (store / f"image-scope-inputs/{e['sha256']}.knscopeblob").read_bytes() for e in payload["inputs"]}
            original = inner(json.loads(catalog["root.knsweep" if payload["scope_kind"] == "sweep" else "root.knslice"]))
            recipes = [inner(json.loads(raw)) for name, raw in catalog.items() if name.endswith(".knslice")]
            reference = (store / f"image-references/{payload['reference_sha256']}.knblob").read_bytes()
            check_scope_report(original, recipes, [reference] * len(recipes), result["assessment"]["replay"])
            changed = sum(derive_slice(recipe, reference)["difference_bytes"] for recipe in recipes)
            assessment = result["assessment"]
            check(int(assessment["observed_changed_bytes"]) == changed == int(assessment["authorized_changed_bytes"]) +
                  int(assessment["unexplained_changed_bytes"]), "original PE/returned receipt change denominator")
        return result

    def recover(root, code=0, identifier="7", index=True):
        command = [exe, "--offline", "!kmon", "journal", root / "collections" / identifier] + (["/index"] if index else []) if args.cli else \
                  [journal, "--recover", root / "collections" / identifier] + (["--index"] if index else [])
        result = invoke(command, code)
        check(not result["replay_established"], "membership does not claim semantic replay")
        return result

    def inventory(root, code=0):
        command = [exe, "--offline", "!kmon", "store", root, "/artifacts"] if args.cli else [journal, "--store", root]
        result = invoke(command, code)
        if code == 0:
            check(result["artifacts_sha256"] == sha(encoded(result["artifacts"])), "independent inventory hash")
        return result

    def files(root):
        return {p.relative_to(root).as_posix(): sha(p.read_bytes()) for p in root.rglob("*") if p.is_file()}

    def oracle(root, recovery, identifier="7"):
        collection = root / "collections" / identifier
        raw = (collection / "session.knsession").read_bytes()
        session = json.loads(raw)
        check(session["payload"]["policy"] == "kn.approved_image_scope_collection_journal.v1" and
              session["payload_sha256"] == sha(encoded(session["payload"])), "dedicated canonical scope approval policy")
        previous, members, approvals = sha(raw), {}, []
        for index in range(1, int(recovery["committed_segments"]) + 1):
            raw = (collection / "journal-segments" / f"{index:020}.knjseg").read_bytes()
            segment = json.loads(raw)
            tx = segment["payload"]["transaction"]
            check(encoded(segment) == raw and segment["payload_sha256"] == sha(encoded(segment["payload"])), "canonical journal hash")
            check(segment["payload"]["previous_sha256"] == previous and segment["payload"]["sequence"] == str(index), "physical hash chain")
            check(tx["kind"] == ("image_scope_approval" if index == 1 else "closure"), "scope approval then closure")
            check(tx["requires"] == (sorted(members) if index == 2 else []), "closure requires every committed original")
            for member in tx["members"]:
                raw_member = (root / member["path"]).read_bytes()
                check(sha(raw_member) == member["sha256"] and len(raw_member) == int(member["bytes"]), "physical member identity")
                members[member["path"]] = member
                if member["path"].endswith(".knscopeapproval"):
                    approvals.append(member["path"])
                    publication = json.loads(raw_member)
                    p = publication["payload"]
                    check(tx["id"] == member["sha256"] and publication["publication_sha256"] == sha(encoded(p)), "exact approval root")
                    required = {member["path"], f"image-references/{p['reference_sha256']}.knblob",
                                f"image-approvals/policy-{p['policy_sha256']}.knapproval", f"image-approvals/changes-{p['manifest_sha256']}.knchange"}
                    for entry in p["inputs"]:
                        key = f"image-scope-inputs/{entry['sha256']}.knscopeblob"
                        selected = next(m for m in tx["members"] if m["path"] == key)
                        check(selected["bytes"] == entry["bytes"] and selected["schema"] == entry["schema"], "catalog describes each original member")
                        required.add(key)
                    check(required == {m["path"] for m in tx["members"]}, "exact catalog dependency closure")
            previous = sha(raw)
        check(recovery["head_sha256"] == previous and recovery["unique_paths"] == str(len(members)), "final prefix identity and member count")
        check(recovery["logical_bytes"] == str(sum(int(m["bytes"]) for m in members.values())), "physical member byte denominator")
        check(recovery["committed_approval_paths"] == approvals and not recovery["committed_direct_capture_paths"] and
              not recovery["committed_sweep_paths"], "CAS sweep requires the archived logical map")

    with tempfile.TemporaryDirectory(prefix="scope-journal-", dir=fixtures) as temporary:
        sandbox = Path(temporary).resolve()
        check(sandbox.is_relative_to(fixtures), "owned temporary root")

        def remove_owned(path):
            resolved = path.resolve()
            check(resolved.is_relative_to(sandbox) and resolved != sandbox, "owned deletion target")
            shutil.rmtree(path)

        def prepare(name, prefix, rva=0x1050, size=1, expire=False):
            directory = sandbox / prefix
            directory.mkdir()
            source = directory / "source"
            shutil.copytree(fixtures / name, source)
            path = source / ("image-sweeps/sweep-7-1.knsweep" if Path(name).name.startswith("sweep_") else "image-reads/slice.knslice")
            catalog, document, recipes, reference = original_inputs(path)
            manifest = manifest_for(document, recipes, reference, rva, size)
            when = max(int(r["payload"]["captured_filetime"]) for r in recipes) + 100
            if expire:
                manifest["not_after_filetime"] = str(when + 100)
            policy = dict(schema="kn.image_approval_policy.v1", policy_id="owned-scope-policy", policy_epoch="7",
                          not_before_filetime="1", not_after_filetime=manifest["not_after_filetime"], approvals=[dict(
                          image_sha256=manifest["image_sha256"], issuer=manifest["issuer"], manifest_sha256=sha(encoded(manifest)))])
            change, approved = directory / "변경.knchange", directory / "승인.knapproval"
            change.write_bytes(encoded(manifest))
            approved.write_bytes(encoded(policy))
            return (path, change, approved, sha(approved.read_bytes())), catalog, when

        inputs, originals, _ = prepare("sweep_boundary_modified", "baseline-inputs", 0x1fff, 2)
        store = sandbox / "private 한글"
        init(store)
        baseline = archive(inputs, store)
        check(baseline["committed"] and baseline["closed"] and baseline["indexed"] and not baseline["historical_root_reused"], baseline)
        root_path = store / baseline["approval_path"]
        publication = json.loads(root_path.read_bytes())["payload"]
        check(publication["root_sha256"] == sha(inputs[0].read_bytes()) and len(publication["inputs"]) == len(originals), "all original inputs bound")
        for entry in publication["inputs"]:
            check((store / f"image-scope-inputs/{entry['sha256']}.knscopeblob").read_bytes() == originals[entry["logical_path"]], "original bytes preserved")
        check(int(baseline["logical_input_bytes"]) == sum(map(len, originals.values())) and int(baseline["unique_input_files"]) == len({sha(b) for b in originals.values()}), "logical and physical counts")
        snapshot = files(store)
        check(archive(inputs, store)["historical_root_reused"] and files(store) == snapshot, "closed retry immutable")
        oracle(store, recover(store))
        archive(inputs, store, "8")
        check_uncommitted_approvals(store, root_path, sandbox, init=init, inventory=inventory, invoke=invoke,
                                   check=check, journal=journal, product=exe if args.cli else None)
        rows = inventory(store)["artifacts"]
        for entry in publication["inputs"]:
            row = next(r for r in rows if r["artifact"]["path"] == f"image-scope-inputs/{entry['sha256']}.knscopeblob")
            check(row["journal_references"] == "2" and row["collections"] == ["7", "8"] and
                  row["retention"] == "committed_original_protected", "shared original referenced by both collections")
        result = replay(root_path, inputs[3])
        check(result["assessment"]["authorized_changed_bytes"] == "2" and result["assessment"]["rules"][0]["spans_recipe_observations"], "two receipts authorize two bytes without atomicity")
        replay(root_path, inputs[3], current=True)
        replay(root_path, "0" * 64, code=1, issue="recorded_policy_anchor_mismatch")

        cases = {"clean": (0x1050, "not_applied", 0), "modified": (0x1050, "authorized", 1),
                 "secondary_modified": (0x1050, "authorized", 1), "continuation": (0x2050, "not_applied", 0),
                 "unstable": (0x1050, "not_fully_compared", 0), "unreadable": (0x1050, "outside_observed_ranges", 0),
                 "sweep_clean": (0x1050, "not_applied", 0), "sweep_modified_gap": (0x2050, "authorized", 1),
                 "sweep_modified_interrupted": (0x1050, "authorized", 1), "sweep_unstable": (0x1050, "not_fully_compared", 0),
                 "sweep_secondary": (0x1050, "not_applied", 0), "sweep_raw_lost": (0x1050, "not_applied", 0)}
        references = {publication["reference_sha256"]}
        for wrapped in (False, True):
            for offset, (name, (rva, state, count)) in enumerate(cases.items()):
                selected = ("scope-claim-publications/" if wrapped else "") + name
                material, catalog, _ = prepare(selected, ("wrapped-" if wrapped else "bare-") + name, rva)
                source_before = files(material[0].parent.parent)
                identifier = str(100 + offset + 100 * wrapped)
                archived = archive(material, store, identifier)
                references.add(archived["reference_sha256"])
                root = store / archived["approval_path"]
                assessed = replay(root, material[3])["assessment"]
                check(assessed["rules"][0]["state"] == state and assessed["authorized_changed_bytes"] == str(count), assessed)
                check(source_before == files(material[0].parent.parent), "source privacy and bytes unchanged")
                check(len(json.loads(root.read_bytes())["payload"]["inputs"]) == len(catalog), "declared raw loss never invented")
                oracle(store, recover(store, identifier=identifier), identifier)
                remove_owned(material[0].parent.parent)
                material[1].unlink()
                material[2].unlink()
                replay(root, material[3])
        check({p.stem for p in (store / "image-references").glob("*.knblob")} == references,
              "exactly one reference per distinct PE content across all source collection names")

        managed = (root_path, store / f"image-approvals/changes-{publication['manifest_sha256']}.knchange",
                   store / f"image-approvals/policy-{inputs[3]}.knapproval", inputs[3])
        snapshot = files(store)
        check(archive(managed, store)["historical_root_reused"] and files(store) == snapshot, "managed exact retry")
        clone = sandbox / "clone"
        init(clone)
        cloned = archive(managed, clone)
        replay(clone / cloned["approval_path"], inputs[3])
        alternate, _, _ = prepare("modified", "alternate-inputs")
        conflict = archive(alternate, store, code=1)
        check(conflict["issue"] == "existing_approval_root_conflict" and not conflict["committed"] and not conflict["closed"], "other input cannot borrow closed flags")
        replacement = inputs[2].parent / "replacement.knapproval"
        replacement.write_bytes(encoded({**json.loads(inputs[2].read_bytes()), "policy_id": "owned-replacement"}))
        snapshot = files(store)
        conflict = archive((inputs[0], inputs[1], replacement, sha(replacement.read_bytes())), store, code=1)
        check(conflict["issue"] == "existing_approval_root_conflict" and not conflict["committed"] and not conflict["closed"] and
              files(store) == snapshot, "new pinned policy cannot replace closed history")

        alias = sandbox / "source-junction"

        def remove_alias():
            check(alias.parent.resolve() == sandbox and alias.lstat().st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT and
                  alias.resolve().is_relative_to(sandbox), "owned junction entry")
            os.rmdir(alias)

        def point_alias(target):
            check(target.resolve().is_relative_to(sandbox), "owned junction target")
            if alias.exists():
                remove_alias()
            environment = dict(os.environ, KN_SCOPE_LINK=str(alias), KN_SCOPE_TARGET=str(target))
            result = subprocess.run(["powershell", "-NoProfile", "-Command",
                "New-Item -ItemType Junction -Path $env:KN_SCOPE_LINK -Target $env:KN_SCOPE_TARGET | Out-Null"],
                env=environment, capture_output=True, timeout=30)
            check(result.returncode == 0 and alias.resolve() == target.resolve(), "junction established")

        # Acquire the complete original set, then replace only the caller's alias.
        # The other target is a different valid sweep with identical logical names.
        switched, _, _ = prepare("sweep_modified", "junction-alternate")
        point_alias(inputs[0].parent.parent)
        alias_input = alias / "image-sweeps/sweep-7-1.knsweep"
        root = sandbox / "switched-alias"
        init(root)
        actor = subprocess.Popen(list(map(str, [producer, "--archive-scope-approval", alias_input, *inputs[1:], root, "7", "0", "source"])),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        observed = queue.Queue()
        reader = threading.Thread(target=lambda: observed.put(actor.stdout.readline()), daemon=True)
        reader.start()
        try:
            check(json.loads(observed.get(timeout=60))["stage"] == "source" and actor.poll() is None and
                  not (root / "collections/7").exists(), "complete source acquisition before journal mutation")
            point_alias(switched[0].parent.parent)
            output, errors = actor.communicate("continue\n", timeout=90)
            check(actor.returncode == 0 and not errors, "archive uses concrete opened originals")
            archived = json.loads(output)
            check(archived["root_sha256"] == baseline["root_sha256"], "alias switch cannot select replacement root")
            replay(root / archived["approval_path"], inputs[3])
        finally:
            if actor.poll() is None:
                actor.kill()
                actor.communicate(timeout=10)
            reader.join(timeout=2)
            if alias.exists():
                remove_alias()

        for fault in ("anchor", "oversized-policy", "oversized-manifest", "root-writer", "child-writer", "raw-writer", "reference-writer", "policy-writer", "manifest-writer"):
            root = sandbox / ("denied-source-" + fault)
            init(root)
            selected = list(inputs)
            lock = None
            try:
                if fault == "anchor": selected[3] = "0" * 64
                elif fault.startswith("oversized"):
                    at = 2 if fault.endswith("policy") else 1
                    selected[at] = sandbox / (fault + ".json")
                    selected[at].write_bytes(b" " * 65537)
                    if at == 2: selected[3] = sha(selected[at].read_bytes())
                else:
                    original_root = inputs[0].parent.parent
                    path = {"root-writer": inputs[0], "policy-writer": inputs[2], "manifest-writer": inputs[1],
                        "reference-writer": original_root / f"image-references/{publication['reference_sha256']}.knblob",
                        "child-writer": original_root / next(n for n in originals if n.endswith(".knslice")),
                        "raw-writer": original_root / next(n for n in originals if n.endswith(".knreads"))}[fault]
                    lock = path.open("r+b")
                snapshot = files(root)
                denied = archive(selected, root, code=1)
                check(denied["status"] == "unavailable" and not denied["committed"] and files(root) == snapshot,
                      "unleased or oversized inputs cannot start a journal")
            finally:
                if lock: lock.close()
        root = sandbox / "uninitialized"
        root.mkdir()
        check(archive(inputs, root, code=1)["issue"] == "private_store_unavailable" and not list(root.iterdir()), "private admission required")
        for kind, relative, data in (("scope_input", f"image-scope-inputs/{publication['root_sha256']}.knscopeblob", inputs[0].read_bytes()),
                ("policy", f"image-approvals/policy-{inputs[3]}.knapproval", inputs[2].read_bytes()),
                ("approval", baseline["approval_path"], root_path.read_bytes())):
            root = sandbox / ("weak-" + kind)
            init(root)
            selected = root / relative
            selected.parent.mkdir(parents=True)
            selected.write_bytes(data)
            result = subprocess.run(["icacls", str(selected), "/grant", "*S-1-1-0:(R)"], capture_output=True, timeout=30)
            check(result.returncode == 0, "owned public-read ACE installed")
            denied = archive(inputs, root, code=1)
            check(denied["issue"] == kind + "_publication_failed" and not denied["committed"] and selected.read_bytes() == data,
                  "matching hash cannot bypass private output admission")

        expired, _, when = prepare("sweep_boundary_modified", "expired-inputs", 0x1fff, 2, expire=True)
        expired_store = sandbox / "expired"
        init(expired_store)
        archived = archive(expired, expired_store, actor=producer, when=when)
        expired_root = expired_store / archived["approval_path"]
        original_time = expired_root.read_bytes()
        replay(expired_root, expired[3])
        replay(expired_root, expired[3], code=1, current=True, issue="current_assessment_unavailable")
        check(archive(expired, expired_store)["historical_root_reused"] and expired_root.read_bytes() == original_time, "expired exact retry remains historical")
        fresh_store = sandbox / "expired-fresh"
        init(fresh_store)
        check(not archive(expired, fresh_store, code=1)["committed"], "expired policy cannot establish a new assessment")
        expired_publication = json.loads(expired_root.read_bytes())["payload"]
        retained = (expired_root, expired_store / f"image-approvals/changes-{expired_publication['manifest_sha256']}.knchange",
                    expired_store / f"image-approvals/policy-{expired[3]}.knapproval", expired[3])
        remove_owned(expired[0].parent.parent.parent)
        check(archive(retained, expired_store)["historical_root_reused"] and expired_root.read_bytes() == original_time,
              "expired managed retry after original source and policy deletion")
        replay(expired_root, expired[3])

        stages = {"session": 0, "input-1": 0, "input-3": 0, "input-5": 0, "reference": 0,
                  "policy": 0, "manifest": 0, "approval": 0, "approval_commit": 1, "ledger": 1, "closed": 2}
        for stage, committed in stages.items():
            root = sandbox / ("interrupt-" + stage)
            init(root)
            actor = subprocess.Popen(list(map(str, [producer, "--archive-scope-approval", *inputs, root, "7", "0", stage])),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            observed = queue.Queue()
            reader = threading.Thread(target=lambda: observed.put(actor.stdout.readline()), daemon=True)
            reader.start()
            saved_root = None
            try:
                check(json.loads(observed.get(timeout=60)).get("stage") == stage and actor.poll() is None, "observed publication boundary")
                archive(inputs, root, code=1)
                inventory(root, code=1)
                if stage in ("approval", "approval_commit", "ledger", "closed"):
                    selected = root / baseline["approval_path"]
                    saved_root = selected.read_bytes()
                    try:
                        with selected.open("r+b"):
                            raise AssertionError("approval write unexpectedly permitted")
                    except PermissionError:
                        check(True, "approval root pinned through closure")
                if stage == "approval":
                    source_root = inputs[0].parent.parent
                    for selected in [inputs[0], inputs[1], inputs[2], source_root / f"image-references/{publication['reference_sha256']}.knblob",
                                     *[source_root / name for name in originals if name.startswith("image-reads/")]]:
                        try:
                            with selected.open("r+b"):
                                raise AssertionError("source write unexpectedly permitted")
                        except PermissionError:
                            check(True, "every acquired original remains leased")
                    for directory in ("image-approvals", "image-scope-inputs", "image-references"):
                        try:
                            (root / directory).rename(root / (directory + "-moved"))
                            raise AssertionError("output directory rename unexpectedly permitted")
                        except PermissionError:
                            check(True, "output directories pinned")
                actor.kill()
                actor.communicate(timeout=10)
            finally:
                if actor.poll() is None:
                    actor.kill()
                    actor.communicate(timeout=10)
                reader.join(timeout=2)
            recovered = recover(root)
            check(recovered["committed_segments"] == str(committed) and recovered["closed"] == (stage == "closed"), "complete prefix only")
            oracle(root, recovered)
            if stage == "ledger":
                rows = inventory(root, code=1)["artifacts"]
                check(next(r for r in rows if r["artifact"]["path"].endswith(".knscopeledger"))["retention"] == "failure_ledger_protected", "uncommitted final ledger protected")
            resumed = archive(inputs, root)
            check(resumed["closed"] and resumed["indexed"], "interrupted retry closes")
            if saved_root:
                check((root / baseline["approval_path"]).read_bytes() == saved_root, "retry preserves original evaluation")
            replay(root / baseline["approval_path"], inputs[3])
            if stage != "closed":
                remove_owned(root)

        baseline_store = sandbox / "interrupt-closed"
        base_root = baseline_store / baseline["approval_path"]
        for fault in ("input", "reference", "policy", "manifest", "approval", "ledger"):
            root = sandbox / ("collision-" + fault)
            init(root)
            relative = {"input": f"image-scope-inputs/{publication['root_sha256']}.knscopeblob",
                        "reference": f"image-references/{publication['reference_sha256']}.knblob",
                        "policy": f"image-approvals/policy-{inputs[3]}.knapproval",
                        "manifest": f"image-approvals/changes-{publication['manifest_sha256']}.knchange",
                        "approval": baseline["approval_path"], "ledger": "image-approvals/scope-session-7.knscopeledger"}[fault]
            selected = root / relative
            selected.parent.mkdir(parents=True)
            selected.write_bytes(b"owned collision sentinel")
            denied = archive(inputs, root, code=1)
            check(selected.read_bytes() == b"owned collision sentinel" and denied["committed"] == (fault == "ledger"), "collision and commit boundary preserved")
            selected.unlink()
            check(archive(inputs, root)["closed"], "explicit owned collision removal permits retry")
        root = sandbox / "index-collision"
        init(root)
        selected = root / baseline["approval_path"]
        selected.parent.mkdir()
        selected.write_bytes(base_root.read_bytes())
        segment = (baseline_store / "collections/7/journal-segments/00000000000000000001.knjseg").read_bytes()
        collision = root / f"collections/7/indexes/chunks/{sha(segment)}.knjindex"
        collision.parent.mkdir(parents=True)
        collision.write_bytes(b"owned index collision")
        denied = archive(inputs, root, code=1)
        check(denied["committed"] and not denied["closed"] and not denied["indexed"] and denied["issue"] == "derived_index_collision" and
              collision.read_bytes() == b"owned index collision", "derived index failure preserves committed originals")
        archive(inputs, root, code=1)
        collision.unlink()
        check(archive(inputs, root)["closed"] and selected.read_bytes() == base_root.read_bytes(), "derived index repair preserves historical root")
        for fault in ("checksum", "extra", "whitespace", "oversized", "time", "traversal", "duplicate", "unsorted", "extra-input", "missing-input", "bytes", "schema"):
            root = sandbox / ("bad-root-" + fault)
            shutil.copytree(baseline_store, root)
            selected = root / baseline["approval_path"]
            document = json.loads(selected.read_bytes())
            p = document["payload"]
            if fault == "checksum": document["publication_sha256"] = "0" * 64
            elif fault == "extra": document["extra"] = True
            elif fault == "time": p["evaluation_filetime"] = "0"
            elif fault == "traversal": p["inputs"][0]["logical_path"] = "../input.knslice"
            elif fault == "duplicate": p["inputs"].insert(0, p["inputs"][0])
            elif fault == "unsorted": p["inputs"].reverse()
            elif fault == "extra-input":
                p["inputs"].append({**p["inputs"][0], "logical_path": "image-reads/reads-7-99.knreads"})
                p["inputs"].sort(key=lambda e: e["logical_path"])
            elif fault == "missing-input": p["inputs"].pop(0)
            elif fault == "bytes": p["inputs"][0]["bytes"] = str(int(p["inputs"][0]["bytes"]) + 1)
            elif fault == "schema": p["inputs"][0]["schema"] = "kn.image_slice.v1"
            raw = b" " * (8 * 1024 * 1024 + 1) if fault == "oversized" else \
                  (encoded(document) if fault == "checksum" else seal(document, "publication_sha256")) + (b" " if fault == "whitespace" else b"")
            selected.write_bytes(raw)
            replay(selected, inputs[3], code=1)
            remove_owned(root)

        for offset, entry in enumerate(publication["inputs"]):
            root = sandbox / ("missing-" + str(offset))
            shutil.copytree(baseline_store, root)
            victim = root / f"image-scope-inputs/{entry['sha256']}.knscopeblob"
            ambient = root / entry["logical_path"]
            ambient.parent.mkdir(parents=True, exist_ok=True)
            ambient.write_bytes(victim.read_bytes())
            victim.unlink()
            replay(root / baseline["approval_path"], inputs[3], code=1, issue="scope_inputs_missing_or_corrupt")
            check(recover(root, code=1)["committed_segments"] == "0", "ambient original filename cannot substitute missing CAS")
            remove_owned(root)
        for field, relative in (("reference", f"image-references/{publication['reference_sha256']}.knblob"),
                                ("policy", f"image-approvals/policy-{inputs[3]}.knapproval"),
                                ("manifest", f"image-approvals/changes-{publication['manifest_sha256']}.knchange")):
            root = sandbox / ("missing-" + field)
            shutil.copytree(baseline_store, root)
            (root / relative).unlink()
            replay(root / baseline["approval_path"], inputs[3], code=1,
                   issue="scope_inputs_missing_or_corrupt" if field == "reference" else "approval_inputs_missing_or_corrupt")
            check(recover(root, code=1)["committed_segments"] == "0", "missing external approval dependency invalidates membership")
            remove_owned(root)

        old_policies = ["kn.image_collection_journal.v1", "kn.image_irp_collection_journal.v2", "kn.image_claim_irp_collection_journal.v3",
                        "kn.image_irp_claim_collection_journal.v4", "kn.direct_image_collection_journal.v1", "kn.approved_image_collection_journal.v1"]
        for fault in [*range(6), "dependency", "kind", "root-id", "missing-member", "extra-member", "forged-report"]:
            root = sandbox / ("tamper-" + str(fault))
            shutil.copytree(baseline_store, root)
            collection = root / "collections/7"
            session = collection / "session.knsession"
            if isinstance(fault, int):
                document = json.loads(session.read_bytes())
                document["payload"]["policy"] = old_policies[fault]
                session.write_bytes(seal(document))
            if fault == "forged-report":
                selected = root / baseline["approval_path"]
                document = json.loads(selected.read_bytes())
                document["payload"]["assessment"]["decision"] = "no_observed_change"
                selected.write_bytes(seal(document, "publication_sha256"))
                replay(selected, inputs[3], code=1, issue="recorded_assessment_mismatch")
            previous = sha(session.read_bytes())
            for index, segment in enumerate(sorted((collection / "journal-segments").glob("*.knjseg")), 1):
                document = json.loads(segment.read_bytes())
                document["payload"]["previous_sha256"] = previous
                tx = document["payload"]["transaction"]
                if index == 1:
                    if fault == "kind": tx["kind"] = "image_approval"
                    elif fault == "root-id": tx["id"] = "0" * 64
                    elif fault == "missing-member":
                        missing = next(m for m in tx["members"] if m["path"].startswith("image-scope-inputs/"))
                        tx["members"].remove(missing)
                    elif fault == "extra-member":
                        extra = encoded({"schema": "kn.image_reads.v3", "owned": True})
                        name = f"image-scope-inputs/{sha(extra)}.knscopeblob"
                        (root / name).write_bytes(extra)
                        tx["members"].append(dict(path=name, sha256=sha(extra), bytes=str(len(extra)), schema="kn.image_reads.v3"))
                        tx["members"].sort(key=lambda m: m["path"])
                    elif fault == "forged-report":
                        changed = next(m for m in tx["members"] if m["path"].endswith(".knscopeapproval"))
                        raw = (root / changed["path"]).read_bytes()
                        changed["sha256"], changed["bytes"], tx["id"] = sha(raw), str(len(raw)), sha(raw)
                elif fault == "dependency":
                    tx["requires"].pop()
                segment.write_bytes(seal(document))
                previous = sha(segment.read_bytes())
            result = recover(root, code=0 if fault == "forged-report" else 1, index=False)
            check(result["closed"] == (fault == "forged-report") and result["committed_segments"] ==
                  ("2" if fault == "forged-report" else "1" if fault == "dependency" else "0"), "physical dependency graph separate from report truth")
            if fault in ("missing-member", "extra-member"):
                check(result["issue"] == ("scope_approval_input_not_committed" if fault == "missing-member" else
                      "scope_approval_dependency_set_mismatch"), (fault, result))
            remove_owned(root)

        orphan_raw = encoded({"schema": "kn.image_reads.v3", "owned_orphan": True})
        orphan = store / f"image-scope-inputs/{sha(orphan_raw)}.knscopeblob"
        orphan.write_bytes(orphan_raw)
        ledger = store / "image-approvals/scope-session-99.knscopeledger"
        ledger.write_bytes((store / "image-approvals/scope-session-7.knscopeledger").read_bytes())
        rows = inventory(store)["artifacts"]
        for selected, eligible in ((orphan, True), (ledger, False), (root_path, False), (store / f"image-scope-inputs/{publication['root_sha256']}.knscopeblob", False)):
            row = next(r for r in rows if r["artifact"]["path"] == selected.relative_to(store).as_posix())
            check(row["verified"] and row["retention"] == ("uncommitted_requires_policy" if eligible else "failure_ledger_protected" if selected == ledger else "committed_original_protected"), row)
            policy = sandbox / (selected.name + ".gc-policy")
            policy.write_bytes(encoded(dict(schema="kn.evidence_gc_policy.v1", policy="kn.gc_explicit_uncommitted.v1",
                reason="owned scope archive GC control", minimum_age_seconds="0", byte_limit="67108864", members=[row["artifact"]])))
            command = [exe, "--offline", "!kmon", "gc", store, policy] if args.cli else [journal, "--gc", store, policy, "-"]
            planned = invoke(command, 0 if eligible else 1)
            check(planned["status"] == ("planned" if eligible else "unavailable" if selected == ledger else "denied") and selected.exists(), "GC preserves committed evidence and ledger")
            if eligible:
                command = [exe, "--offline", "!kmon", "gc", store, policy, "/apply", "99"] if args.cli else [journal, "--gc", store, policy, "99"]
                check(invoke(command)["status"] == "completed" and not selected.exists(), "explicit orphan CAS removal")
        if args.cli:
            efs_store = sandbox / "efs"
            init(efs_store, efs=True)
            check(archive(inputs, efs_store)["closed"], "default EFS admission covers entire closure")
            check(invoke([exe, "--offline", "!kmon", "privacy", efs_store, "/audit"])["status"] == "ready", "all outputs remain admitted")
            command = [exe, "--offline", "!kmon", "replay-image-approval", root_path, inputs[3]]
            for tail in (["/current", "/current"], ["/json", "/json"], ["/bad"]):
                denied = subprocess.run(list(map(str, [*command, *tail])), capture_output=True, encoding="utf-8", timeout=60)
                check(denied.returncode == 2 and not denied.stdout and "usage:" in denied.stderr, "CLI grammar rejection")
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
        check(base_root.exists(), "baseline retained through controls")
    print(f"[image.scope.approval.journal] checks={checks} mode={'product' if args.cli else 'harness'} interrupted={len(stages)} children_remaining=0")


if __name__ == "__main__":
    main()
