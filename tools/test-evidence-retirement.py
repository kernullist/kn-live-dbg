"""Exercise closed-root retirement and exact-member GC using disposable native collections."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--archive-store", action="append", default=[], type=Path,
                        help="copy and exercise an existing single closed native fixture with collection ID 7")
    parser.add_argument("--previous-cli", type=Path, help="check recovery with the preceding offline binary")
    args = parser.parse_args()
    exe, producer = args.exe.resolve(), (args.producer or args.exe).resolve()
    cli = [exe, "--offline", "!kmon"]
    checks = 0

    def check(value, message):
        nonlocal checks
        if not value:
            raise AssertionError(message)
        checks += 1

    def invoke(command, code=0):
        output = subprocess.run(list(map(str, command)), capture_output=True, timeout=60)
        check(output.returncode == code, (command[1:4], code, output.returncode, output.stdout[:900], output.stderr[:200]))
        return output.stdout

    def inspect(root, code=0):
        result = json.loads(invoke([*cli, "store", root, "/artifacts"] if args.cli else [exe, "--store", root], code))
        if code == 0:
            check(result["artifacts_sha256"] == sha(encoded(result["artifacts"])) and
                  result["catalog_sha256"] == sha(encoded(result["collections"])), "independent complete inventory digests")
        return result, {row["artifact"]["path"]: row for row in result["artifacts"]}

    def recovery(root, key, index=False, code=0):
        folder = root / "collections" / key
        return json.loads(invoke([*cli, "journal", folder] + (["/index"] if index else []) if args.cli else
                                 [exe, "--recover", folder] + (["--index"] if index else []), code))

    def files(folder):
        return {p.relative_to(folder).as_posix(): sha(p.read_bytes()) for p in folder.rglob("*") if p.is_file()}

    def journal_members(root, key):
        folder = root / "collections" / key
        previous = sha((folder / "session.knsession").read_bytes())
        members, logical, records = {}, 0, 0
        for segment in sorted((folder / "journal-segments").glob("*.knjseg")):
            data = segment.read_bytes()
            document = json.loads(data)
            payload = document["payload"]
            check(document["payload_sha256"] == sha(encoded(payload)) and payload["previous_sha256"] == previous, "original chain")
            transaction = payload["transaction"]
            for m in transaction["members"]:
                content = (root / m["path"]).read_bytes()
                check(m["sha256"] == sha(content) and int(m["bytes"]) == len(content), "original member")
                members[m["path"]] = m
                logical += len(content)
            records += 1
            previous = sha(data)
        check(transaction["kind"] == "closure", "original closing record")
        return members, logical, records

    with tempfile.TemporaryDirectory(prefix="ret-", dir=args.fixtures.resolve()) as temporary:
        sandbox = Path(temporary)
        root = sandbox / "store"
        for key in ("7", "8"):
            invoke([producer, "--produce-collection", root, key])
        memberships = {key: journal_members(root, key) for key in ("7", "8")}
        before = files(root)
        snapshot, table = inspect(root)
        sample = sandbox / "snapshot.json"
        rule = sandbox / "selection.json"
        helper = Path(__file__).with_name("new-evidence-gc-policy.py")

        def prepare(snap, options, output, code=0):
            sample.write_bytes(encoded(snap))
            invoke([sys.executable, "-B", helper, "--inventory", sample, *options, "--reason", "보존 기간 종료",
                    "--minimum-age-seconds", "0", "--output", output], code)

        def retire(store, policy, apply=False, code=0):
            command = [*cli, "retire-collection", store, policy] + (["/apply"] if apply else []) if args.cli else [
                exe, "--retire-collection", store, policy, "apply" if apply else "-"]
            return json.loads(invoke(command, code))

        def gc(store, operation=None, code=0):
            command = [*cli, "gc", store, rule] + (["/apply", operation] if operation else []) if args.cli else [
                exe, "--gc", store, rule, operation or "-"]
            return json.loads(invoke(command, code))

        def choose(rows, paths, source=None, receipt=None):
            policy = dict(schema="kn.evidence_gc_policy.v1", policy="kn.gc_explicit_uncommitted.v1") if source is None else dict(
                schema="kn.evidence_gc_policy.v2", policy="kn.gc_explicit_retired.v1", retired_collection_id=source, retirement_sha256=receipt)
            rule.write_bytes(encoded(dict(policy, reason="owned retirement GC", minimum_age_seconds="0", byte_limit="134217728",
                                          members=[rows[p]["artifact"] for p in sorted(paths)])))

        def hold(command, stage, body):
            proc = subprocess.Popen(list(map(str, command)), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            seen = queue.Queue()
            worker = threading.Thread(target=lambda: seen.put(proc.stdout.readline()), daemon=True)
            worker.start()
            try:
                check(seen.get(timeout=30).strip() == "[journal.stage] " + stage, "observed publication boundary")
                body()
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate(timeout=15)
                worker.join(timeout=5)
            check(proc.poll() is not None and not worker.is_alive(), "interruption child reaped")

        policies = {}
        for key in memberships:
            policies[key] = sandbox / ("retire-" + key + ".json")
            prepare(snapshot, ["--retire-collection", key], policies[key])
        policy = policies["7"]
        check(not retire(root, policy)["receipt_sha256"] and files(root) == before, "preflight makes no filesystem changes")
        plan = retire(root, policy)
        details = plan["record"]["payload"]
        group = lambda label: {"paths": str(len(label)), "named_bytes": str(sum(int(m["bytes"]) for m in label))}
        seven, eight = memberships["7"][0], memberships["8"][0]
        shared = [m for p, m in seven.items() if p in eight]
        ledgers = [m for p, m in seven.items() if p.endswith("ledger")]
        exclusive = [m for p, m in seven.items() if p not in eight and not p.endswith("ledger")]
        check(plan["status"] == "planned" and details["exclusive_nonledger"] == group(exclusive) and details["shared_nonledger"] == group(shared)
              and details["failure_ledgers"] == group(ledgers) and len(shared) == len(ledgers) == 1, "independent unique-path ownership impact")
        check(details["catalog_sha256"] == snapshot["catalog_sha256"] and details["artifacts_sha256"] == snapshot["artifacts_sha256"],
              "plan bound to both complete native observations")
        guard = sandbox / "guard.json"
        for field, value, issue in (("head_sha256", "0" * 64, "retirement_root_mismatch"),
                                   ("session_sha256", "a" * 64, "retirement_root_mismatch"),
                                   ("exclusive_byte_limit", "0", "retirement_exclusive_byte_limit"),
                                   ("minimum_age_seconds", "86400", "closure_too_young_or_future"),
                                   ("collection_id", "../7", "invalid_retirement_policy"),
                                   ("unexpected", True, "invalid_retirement_policy")):
            altered = json.loads(policy.read_bytes())
            altered[field] = value
            guard.write_bytes(encoded(altered))
            check(retire(root, guard, True, 1)["issue"] == issue and files(root) == before, field)
        if args.cli:
            for extra in (["/apply", "/apply"], ["/apply", "9"], ["/other"]):
                invoke([*cli, "retire-collection", root, policy, *extra], 2)
            invoke([*cli, "retire-collection", root, "/apply"], 2)
            check(files(root) == before, "invalid grammar makes no changes")
            branch = sandbox / "broken-pipe"
            shutil.copytree(root, branch)
            reader, writer = os.pipe()
            os.close(reader)
            with os.fdopen(writer, "wb") as pipe:
                result = subprocess.run([*cli, "retire-collection", branch, policy, "/apply"], stdout=pipe, stderr=subprocess.PIPE, timeout=30)
            check(result.returncode == 3 and retire(branch, policy, True)["reused_receipt"], "output failure preserves completed withdrawal")

        first = root / "collections/7/retirement.knretirement"
        branch = sandbox / "changed-ownership"
        shutil.copytree(root, branch)
        capped = sandbox / "exclusive-cap.json"
        capped.write_bytes(encoded(dict(json.loads(policy.read_bytes()), exclusive_byte_limit=group(exclusive)["named_bytes"])))
        check(retire(branch, capped)["status"] == "planned", "initial owners fit the exact exclusive-byte cap")
        retire(branch, policies["8"], True)
        check(retire(branch, capped, True, 1)["issue"] == "retirement_exclusive_byte_limit" and
              not (branch / first.relative_to(root)).exists(), "fresh ownership on apply enforces the previously shared PE against the cap")
        for fault in ("other-open", "other-corrupt", "receipt-collision"):
            branch = sandbox / fault
            shutil.copytree(root, branch)
            marker = branch / first.relative_to(root)
            if fault == "receipt-collision":
                marker.write_bytes(b"unreadable receipt")
            else:
                other_closure = max((branch / "collections/8/journal-segments").glob("*.knjseg"))
                if fault == "other-open":
                    other_closure.unlink()
                else:
                    other_closure.write_bytes(b"{}")
            expected = files(branch)
            check(retire(branch, policy, True, 1)["issue"] == "retirement_requires_complete_closed_store" and files(branch) == expected,
                  "partial store cannot authorize a withdrawal " + fault)
        for stage in ("retire_preflight", "retire_published"):
            branch = sandbox / stage
            shutil.copytree(root, branch)
            marker = branch / first.relative_to(root)

            def during():
                check(marker.exists() == (stage == "retire_published"), "visibility at observed boundary")
                check(inspect(branch, 1)[0]["status"] != "verified", "stopped-store lease")
                invoke([producer, "--produce-collection", branch, "9"], 1)
                check(not (branch / "collections/9").exists(), "competing producer held outside the store")
            hold([producer, "--retire-collection", branch, policy, "apply", stage], stage, during)
            prior = marker.read_bytes() if marker.exists() else None
            outcome = retire(branch, policy, True)
            check(outcome["status"] == "retired" and outcome["reused_receipt"] == (prior is not None) and
                  (prior is None or marker.read_bytes() == prior), "retry adopts only a matching complete receipt")
            check(sha(marker.read_bytes()) == outcome["receipt_sha256"] and all(
                sha((branch / p).read_bytes()) == h for p, h in before.items()), "no original changed during interruption")

        applied = retire(root, policy, True)
        receipt = sha(first.read_bytes())
        record = json.loads(first.read_bytes())
        check(applied["status"] == "retired" and applied["receipt_sha256"] == receipt and record == applied["record"] and
              record["payload_sha256"] == sha(encoded(record["payload"])) and record["payload"]["policy"] == json.loads(policy.read_bytes()) and
              record["payload"]["exclusive_nonledger"] == group(exclusive) and first.read_bytes() == encoded(record), "durable receipt binds policy and impact")
        check(len(files(root)) == len(before) + 1 and all(sha((root / p).read_bytes()) == h for p, h in before.items()),
              "logical retirement only creates its receipt")
        guard.write_bytes(encoded(dict(json.loads(policy.read_bytes()), reason="different policy")))
        check(retire(root, guard, True, 1)["issue"] == "collection_retirement_policy_conflict" and
              retire(root, policy, True)["reused_receipt"], "conflicting and idempotent retirement")
        invoke([producer, "--resume", root], 1)
        damaged = sandbox / "retired-missing-session"
        shutil.copytree(root, damaged)
        for name in ("session.knsession", "writer.knjlock"):
            (damaged / "collections/7" / name).unlink()
        prior = files(damaged)
        invoke([producer, "--resume", damaged], 1)
        check(files(damaged) == prior, "a writer cannot recreate missing metadata in a retired collection")
        rec = recovery(root, "7")
        check(rec["status"] == "retired" and rec["closed"] and not rec["can_resume"] and not rec["original_set_verified"] and
              rec["denominator_scope"] == "retired_manifest_membership" and not rec["committed_sweep_paths"] and
              recovery(root, "7", True, 1)["index_status"] == "retired", "original replay/index status after withdrawal")
        snap, rows = inspect(root)
        check(snap["closed_collections"] == snap["retired_collections"] == "1" and snap["unattributed_files"] == "0" and
              int(snap["logical_reference_bytes"]) == memberships["8"][1] and int(snap["retired_logical_bytes"]) == memberships["7"][1],
              "live and historical denominators")
        ref = shared[0]["path"]
        sweep = "image-sweeps/sweep-7-1.knsweep"
        raw = "image-reads/reads-7-1.knreads"
        ledger = ledgers[0]["path"]
        check(rows[ref]["collections"] == ["8"] and rows[ref]["retired_collections"] == ["7"] and
              rows[ref]["retention"] == "committed_reference_protected" and rows[ledger]["retention"] == "failure_ledger_protected" and
              rows[sweep]["retention"] == "retired_requires_policy" and rows[raw]["retention"] == "uncommitted_image_input_protected",
              "surviving root, co-owner and ledger protections")
        prepare(snap, ["--path", sweep], sandbox / "wrong-mode", 1)
        prepare(snap, ["--from-retired-collection", "7", "--path", ref], sandbox / "shared-mode", 1)
        choose(rows, [sweep])
        check(gc(root, "11", 1)["deleted_this_call"] == "0", "legacy selection cannot release a historical original")
        choose(rows, [sweep], "7", "f" * 64)
        check(gc(root, "11", 1)["issue"] == "gc_retirement_receipt_mismatch", "receipt pin required")
        choose(rows, [raw, sweep], "7", receipt)
        check(gc(root, "11", 1)["status"] == "denied" and not (root / "retention/11/operation.kngc").exists(),
              "batch containing a surviving dependency is denied before any intent")
        out = sandbox / "release-sweep.json"
        prepare(snap, ["--from-retired-collection", "7", "--path", sweep], out)
        rule.write_bytes(out.read_bytes())
        check(gc(root)["status"] == "planned" and gc(root, "11")["deleted_this_call"] == "1" and not (root / sweep).exists() and
              gc(root, "11")["entries"][0]["reused_receipt"], "normal exact-member file release and receipt retry")
        audit = json.loads((root / "retention/11/operation.kngc").read_bytes())
        check(audit["payload"]["policy"]["retirement_sha256"] == receipt and audit["payload"]["policy_sha256"] == sha(rule.read_bytes()),
              "deletion audit binds its historical root")
        snap, rows = inspect(root)
        check(snap["retired_absent_paths"] == "1" and rows[raw]["retention"] == "retired_requires_policy" and
              recovery(root, "8")["status"] == "verified_prefix", "sweep withdrawal releases children while live root still verifies")
        replacement = root / raw
        saved = replacement.read_bytes()
        replacement.write_bytes(b"{}")
        partial, physical = inspect(root, 1)
        check(partial["retired_changed_paths"] == partial["retired_absent_paths"] == "0" and
              partial["retired_unobserved_paths"] == "2" and not physical[raw]["verified"] and
              physical[raw]["retention"] == "unverified_artifact_protected", "unreadable content and unobserved paths remain unknown")
        replacement.write_bytes(saved)
        changed = json.loads(saved)
        changed["payload"]["fixture_id"] = "replacement"
        changed["payload_sha256"] = sha(encoded(changed["payload"]))
        replacement.write_bytes(encoded(changed))
        snap, rows = inspect(root)
        check(rows[raw]["retention"] == "retired_path_changed_protected" and not rows[raw]["retired_original_matched"] and
              snap["retired_changed_paths"] == "1", "different bytes at retired name preserved")
        choose(rows, [raw], "7", receipt)
        check(gc(root, "12", 1)["deleted_this_call"] == "0", "replacement is ineligible even under its current physical digest")
        replacement.write_bytes(saved)
        receipt8 = retire(root, policies["8"], True)["receipt_sha256"]
        for key, binding in (("8", receipt8), ("7", receipt)):
            snap, rows = inspect(root)
            path = f"image-sweeps/sweep-{key}-1.knsweep"
            if path in rows:
                choose(rows, [path], "7", receipt)
                check(gc(root, "21", 1)["status"] == "denied", "retired selection cannot cross collection membership")
                choose(rows, [path], key, binding)
                check(gc(root, "21")["deleted_this_call"] == "1", "withdraw remaining sweep")
            snap, rows = inspect(root)
            reads = [p for p in memberships[key][0] if p.endswith((".knreads", ".knslice"))]
            check(all(rows[p]["retention"] == "retired_requires_policy" for p in reads), "all surviving dependencies released")
            choose(rows, reads, key, binding)
            check(int(gc(root, "3" + key)["deleted_this_call"]) == len(reads), "exact retired read and slice counts")
        snap, rows = inspect(root)
        check(rows[ref]["retired_collections"] == ["7", "8"] and rows[ref]["collections"] == [] and
              rows[ref]["retention"] == "retired_requires_policy", "last active and loose owners withdrawn")
        choose(rows, [ref], "7", receipt)
        saved_policy = rule.read_bytes()
        hold([producer, "--gc", root, rule, "41", "gc_intent"], "gc_intent", lambda: check((root / ref).exists(), "intent precedes PE deletion"))
        payload = {"reference_sha256": shared[0]["sha256"]}
        direct = encoded(dict(schema="kn.image_recipe.v1", recipe_sha256=sha(encoded(payload)), payload=payload))
        loose = f"image-captures/capture-99-{sha(direct)}.kncapture"
        (root / loose).parent.mkdir()
        (root / loose).write_bytes(direct)
        denied = gc(root, "41", 1)
        check(denied["entries"][0]["issue"] == "uncommitted_image_input_protected" and not (root / "retention/41/1.kngcreceipt").exists(),
              "new live dependency blocks an existing retired-file intent")
        _, rows = inspect(root)
        choose(rows, [loose])
        check(gc(root, "42")["deleted_this_call"] == "1", "withdraw only the loose capture")
        rule.write_bytes(saved_policy)
        check(gc(root, "41")["deleted_this_call"] == "1", "exact retry after withdrawing last referrer")
        final, rows = inspect(root)
        union = set(seven) | set(eight)
        check(final["closed_collections"] == "0" and final["retired_collections"] == "2" and set(rows) == {p for p in union if p.endswith("ledger")} and
              int(final["retired_declared_paths"]) == len(union) and int(final["retired_absent_paths"]) == len(union) - len(rows) and
              all(row["retention"] == "failure_ledger_protected" for row in rows.values()), "final retained ledgers and historical denominators")
        check(all(sha((root / p).read_bytes()) == h for p, h in before.items() if p.startswith("collections/") or p in rows),
              "all original sessions, chains, indexes and failure ledgers intact")
        for fault in ("ledger", "receipt", "head", "counts", "segment", "removed"):
            other = sandbox / ("fault-" + fault)
            shutil.copytree(root, other)
            marker = other / first.relative_to(root)
            if fault == "ledger": (other / ledger).write_bytes(b"{}")
            elif fault == "segment": next((other / "collections/7/journal-segments").glob("*.knjseg")).unlink()
            elif fault == "removed": marker.unlink()
            else:
                doc = json.loads(marker.read_bytes())
                if fault == "head": doc["payload"]["policy"]["head_sha256"] = "1" * 64
                if fault == "counts": doc["payload"]["shared_nonledger"]["named_bytes"] = "9500"
                doc["payload_sha256"] = "a" * 64 if fault == "receipt" else sha(encoded(doc["payload"]))
                marker.write_bytes(encoded(doc))
            broken = recovery(other, "7", code=1)
            check(not broken["closed"] and not broken["can_resume"] and broken["committed_segments"] == "0" and
                  inspect(other, 1)[0]["membership_complete"] is False and gc(other, "41", 1)["deleted_this_call"] == "0",
                  "unverified retirement never authorizes GC " + fault)
        (root / "image-reads/unexpected.entry").write_bytes(b"owned enumeration control")
        partial, _ = inspect(root, 1)
        check(partial["retired_absent_paths"] == "0" and int(partial["retired_unobserved_paths"]) == len(union) - len(rows),
              "partial scan separates unobserved paths from established absence")

        for ordinal, source in enumerate([None, *args.archive_store]):
            archive = sandbox / f"archive-{ordinal}"
            if source is None:
                invoke([producer, "--produce-irp", archive, "7", ""])
            else:
                shutil.copytree(source.resolve(), archive)
            records, _, _ = journal_members(archive, "7")
            library, table = inspect(archive)
            check(library["closed_collections"] == "1" and library["retired_collections"] == "0", "single closed archive fixture")
            collection_dir = archive / "collections/7"
            metadata = files(collection_dir)
            archive_policy = sandbox / f"archive-{ordinal}.json"
            prepare(library, ["--retire-collection", "7"], archive_policy)
            replay = None
            if source is not None and args.cli:
                for name in records:
                    if name.endswith((".knapprovalcase", ".knscopeapproval")):
                        anchor = json.loads((archive / name).read_bytes())["payload"]["policy_sha256"]
                        replay = [*cli, "replay-image-approval", archive / name, anchor, "/json"]
                        break
                    if name.endswith(".knirp"):
                        replay = [*cli, "replay-irp", archive / name, "/json"]
                    elif name.endswith(".kncapture") and replay is None:
                        replay = [*cli, "replay-image", archive / name, "/json"]
                check(replay is not None and bool(json.loads(invoke(replay))), "genuine archive replays through the offline CLI")
            legacy = [args.previous_cli, "--offline", "!kmon", "journal", collection_dir] if args.previous_cli else []
            if legacy:
                check(json.loads(invoke(legacy))["closed"], "preceding CLI reads the original journal")
            proof = retire(archive, archive_policy, True)["receipt_sha256"]
            if legacy:
                check(json.loads(invoke(legacy))["status"] == "verified_prefix", "preceding CLI verifies retained original bytes")
            if replay:
                check(bool(json.loads(invoke(replay))), "standalone archived evidence still replays after logical withdrawal")
            ledgers = {n for n in records if n.endswith("ledger")}
            remaining = set(records) - ledgers
            round_id = 0
            while remaining:
                library, table = inspect(archive)
                eligible = sorted(n for n in remaining if table[n]["retention"] == "retired_requires_policy")
                check(bool(eligible) and all(table[n]["retention"] == "failure_ledger_protected" for n in ledgers),
                      "each release round preserves every failure ledger")
                choose(table, eligible, "7", proof)
                released = gc(archive, str(800 + round_id))
                check(int(released["deleted_this_call"]) == len(eligible) and all(not (archive / n).exists() for n in eligible),
                      "exact native outputs removed only after all referring originals allow it")
                round_id += 1
                remaining.difference_update(eligible)
            if legacy:
                old = json.loads(invoke(legacy, 1))
                check(not old["closed"] and not old["can_resume"], "preceding CLI fails closed after physical release")
            if replay:
                invoke(replay, 1)
            library, table = inspect(archive)
            check(recovery(archive, "7")["status"] == "retired" and int(library["retired_absent_paths"]) == len(records) - len(ledgers)
                  and all(sha((archive / n).read_bytes()) == records[n]["sha256"] for n in ledgers) and
                  all(sha((collection_dir / n).read_bytes()) == h for n, h in metadata.items()),
                  "verified historical chain and exact ledger bytes survive every applicable file release")
    print(f"[retirement.oracle] checks={checks} mode={'cli' if args.cli else 'harness'} interrupted_stages=3")


if __name__ == "__main__":
    main()
