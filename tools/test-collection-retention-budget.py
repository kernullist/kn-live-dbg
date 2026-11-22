"""Independent stopped-store accounting and policy checks on disposable, hash-linked collections."""
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
import time


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def seal(document, field):
    document[field] = sha(encoded(document["payload"]))
    return encoded(document)


def ledger(key, irp, activity, sweeps=0):
    family = "irp" if irp else "image"
    names = ("first_observed_state", "observation_gap", "repeat_or_empty") if irp else (
        "first_difference", "observation_gap", "repeat_or_clean")
    lanes = []
    for name, amount in zip(names, activity):
        lane = dict.fromkeys(("attempted", "admitted", "finished", "complete"), str(amount))
        lane.update(dict.fromkeys(("abandoned", "in_flight", "slot_denied", "key_denied", "preparation_denied"), "0"))
        lane.update(dict.fromkeys(("memory_denied", "unavailable", "invalid") if irp else ("reference_denied",), "0"))
        lanes.append(dict(lane, **{"class": name}))
    total = sum(activity)
    value = str if irp else int
    result = dict(schema="kn.irp_capture_session.v1" if irp else "kn.image_read_session.v1", collection_id=key,
                  queued=value(total), written=value(total), failed=value(0), dropped=value(0), pending=value(0),
                  retention=dict(schema=f"kn.{family}_retention.v1", policy=f"kn.{family}_retention_partition.v1",
                                 scope="recording_session", classes=lanes))
    if irp:
        result.update(dict.fromkeys(("unavailable", "claims_unavailable", "reserved_bytes", "references_failed",
                                     "journal_captures_failed"), "0"))
        result.update(journal_captures_committed=str(total), claims_written=str(total))
    else:
        result.update(dict.fromkeys(("reference_blobs_failed", "reference_reserved_bytes", "reference_captures_missing",
                                     "slice_recipes_failed", "slice_recipes_unavailable", "slice_claims_unavailable",
                                     "sweep_claims_unavailable", "sweep_manifests_failed", "sweep_manifest_pending",
                                     "sweep_manifest_admission_denied_slices", "sweep_manifest_entry_drops", "sweep_metadata_failures",
                                     "journal_read_batches_failed", "journal_sweeps_failed", "journal_index_failures_before_closure",
                                     "store_admission_failures"), 0))
        result.update(journal_read_batches_committed=total, journal_sweeps_committed=sweeps, sweeps_started=sweeps,
                      sweep_terminals_observed=sweeps, sweep_manifests_written=sweeps,
                      slice_recipes_queued=total, slice_recipes_written=total, slice_claims_written=total, sweep_claims_written=sweeps)
    return result


def prepare_members(root, key, family, variant):
    """Model current/older/damaged producer observations. Recompute original named-file hashes and the journal chain."""
    folder = root / "collections" / key
    segments = sorted((folder / "journal-segments").glob("*.knjseg"))
    previous = sha((folder / "session.knsession").read_bytes())
    irp = family == "irp"
    for path in segments:
        document = json.loads(path.read_bytes())
        payload = document["payload"]
        transaction = payload["transaction"]
        if variant == "missing_recipe" and transaction["kind"] == "image_reads" and transaction["id"] == "2":
            transaction["members"] = [m for m in transaction["members"] if not m["path"].endswith(".knslice")]
        for member in transaction["members"]:
            file = root / member["path"]
            if file.suffix == ".knreads":
                raw = json.loads(file.read_bytes())
                ticket = dict(policy="kn.image_retention_partition.v1", difference_keys="0", unkeyed_difference=False,
                              scope="recording_session", **{"class": "repeat_or_clean"})
                if variant == "ticket_first":
                    ticket.update(difference_keys="1", **{"class": "first_difference"})
                elif variant == "ticket_conflict":
                    ticket["difference_keys"] = "1"
                if variant != "no_ticket":
                    raw["payload"]["retention"] = ticket
                if variant == "missing_reference":
                    raw["payload"]["reference"]["persistence"] = "not_captured"
                file.write_bytes(seal(raw, "payload_sha256"))
            elif file.suffix == ".knsweep":
                sweep = json.loads(file.read_bytes())
                manifest = sweep["payload"]
                row = manifest["slices"][0]
                completed = variant != "open_sweep"
                row["terminal"] = row["traversal_complete"] = completed
                manifest.update(terminal_observed=completed, traversal_complete=completed, tail_unknown=not completed)
                if variant == "skipped_range":
                    manifest["sweep"].update(total_ranges="2", expected_bytes="2")
                    row["start_range"] = "1"
                raw = root / f"image-reads/reads-{key}-1.knreads"
                row["raw_payload_sha256"] = json.loads(raw.read_bytes())["payload_sha256"]
                file.write_bytes(seal(sweep, "manifest_sha256"))
            elif file.suffix in (".knreadledger", ".knirpledger") and variant != "legacy":
                irp_ledger = file.suffix == ".knirpledger"
                amount = 1 if irp_ledger else (0 if irp else 2)
                lane = 0 if variant == "first" else (1 if variant == "gap" else 2)
                activity = [amount if i == lane else 0 for i in range(3)]
                counts = ledger(key, irp_ledger, activity, int(not irp))
                if variant == "overflow" and irp_ledger:
                    counts["retention"]["classes"][2]["attempted"] = str(2**64)
                if variant == "duplicate_lane" and irp_ledger:
                    counts["retention"]["classes"][0] = counts["retention"]["classes"][1]
                if variant == "loss" and irp_ledger:
                    counts["claims_unavailable"] = "1"
                if variant == "wrong_written" and irp_ledger:
                    counts["written"] = "0"
                file.write_bytes(encoded(counts))
            data = file.read_bytes()
            member.update(sha256=sha(data), bytes=str(len(data)))
        payload["previous_sha256"] = previous
        data = seal(document, "payload_sha256")
        path.write_bytes(data)
        previous = sha(data)
    return segments[-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--previous-cli", type=Path)
    args = parser.parse_args()
    exe = args.exe.resolve()
    producer = (args.producer or args.exe).resolve()
    cli = [exe, "--offline", "!kmon"]
    helper = Path(__file__).with_name("new-evidence-gc-policy.py")
    checks = 0

    def check(value, message):
        nonlocal checks
        if not value:
            raise AssertionError(message)
        checks += 1

    def call(command, code=0):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=90)
        check(result.returncode == code, (command[1:5], result.returncode, code, result.stdout[-850:], result.stderr[:180]))
        return result.stdout

    def inventory(root, *flags, code=0):
        cmd = [*cli, "store", root, "/artifacts"] if args.cli else [exe, "--store", root]
        return json.loads(call(cmd + list(flags), code))

    def retire(root, rule, apply=False, code=0):
        cmd = [*cli, "retire-collection", root, rule] + (["/apply"] if apply else []) if args.cli else [
            exe, "--retire-collection", root, rule, "apply" if apply else "-"]
        return json.loads(call(cmd, code))

    def originals(folder):
        return {f.relative_to(folder).as_posix(): sha(f.read_bytes()) for f in folder.rglob("*") if f.is_file()}

    classes = ["first_observation", "observation_gap", "unclassified", "routine_only", "empty"]
    with tempfile.TemporaryDirectory(prefix="rb-", dir=args.fixtures.resolve()) as temporary:
        work = Path(temporary)
        store = work / "store"
        closures, expected = {}, {}
        baseline_time = int(time.time()) - 7200
        cases = [("7", "irp", "routine", 3), ("12", "irp", "routine", 3), ("24", "image", "routine", 3),
                 ("4", "image", "ticket_first", 0), ("5", "image", "open_sweep", 1), ("6", "image", "skipped_range", 1),
                 ("32", "image", "ticket_conflict", 2), ("33", "image", "no_ticket", 2), ("34", "irp", "loss", 1),
                 ("35", "irp", "overflow", 2), ("36", "irp", "duplicate_lane", 2), ("37", "irp", "wrong_written", 1),
                 ("38", "irp", "legacy", 2), ("39", "irp", "first", 0), ("40", "irp", "gap", 1),
                 ("41", "image", "missing_reference", 1), ("42", "image", "missing_recipe", 1)]
        for key, family, variant, lane in cases:
            cmd = ["--produce-irp", store, key, "-"] if family == "irp" else ["--produce-collection", store, key]
            call([producer, *cmd])
            closures[key] = prepare_members(store, key, family, variant)
            expected[key] = classes[lane]
            stamp = baseline_time - 60 if key in ("7", "12") else baseline_time
            os.utime(closures[key], (stamp, stamp))
        snapshot = inventory(store, "/retention")
        ordinary = inventory(store)
        report = snapshot["collection_retention"]
        check("collection_retention" not in ordinary and report["status"] == "verified" and
              snapshot["catalog_sha256"] == ordinary["catalog_sha256"] == sha(encoded(snapshot["collections"])) and
              snapshot["artifacts_sha256"] == ordinary["artifacts_sha256"] == sha(encoded(snapshot["artifacts"])), "stable complete digests")
        roots = {row["collection_id"]: row for row in report["roots"]}
        check({k: row["class"] for k, row in roots.items()} == expected, {k: (row["class"], expected[k]) for k, row in roots.items()})
        memberships = {}
        for key in expected:
            for segment in sorted(closures[key].parent.glob("*.knjseg")):
                for member in json.loads(segment.read_bytes())["payload"]["transaction"]["members"]:
                    memberships.setdefault(member["path"], set()).add(key)
        totals = {lane: [0, 0] for lane in classes + ["ledger"]}
        exclusive = dict.fromkeys(expected, 0)
        routine_paths = dict.fromkeys(expected, 0)
        for path, owners in memberships.items():
            lane = "ledger" if path.endswith("ledger") else min((expected[k] for k in owners), key=classes.index)
            size = (store / path).stat().st_size
            totals[lane][0] += 1
            totals[lane][1] += size
            if lane == "routine_only":
                for key in owners:
                    routine_paths[key] += 1
                if len(owners) == 1:
                    exclusive[next(iter(owners))] += size
        for row in [*report["classes"], dict(report["failure_ledgers"], **{"class": "ledger"})]:
            check([int(row["paths"]), int(row["named_bytes"])] == totals[row["class"]], row["class"])
        check(all((int(r["exclusive_routine_bytes"]), int(r["routine_paths"])) == (exclusive[k], routine_paths[k])
                  for k, r in roots.items()), "independent exclusive bytes and per-root routine paths")
        page = inventory(store, "/limit", "1", "/retention")
        check(len(page["artifacts"]) == 1 and page["next_artifact_cursor"] and page["collection_retention"]["classes"] == report["classes"],
              "class totals include all pages")
        sample = work / "inventory.json"
        rule = work / "budget.json"
        guard = work / "guard.json"
        reason = "반복 관측 보존 예산"

        def prepare(snap, options, output, age=0, cap=134217728, code=0):
            sample.write_bytes(encoded(snap))
            call([sys.executable, "-B", helper, "--inventory", sample, *options, "--minimum-age-seconds", age,
                  "--byte-limit", cap, "--reason", reason, "--output", output], code)

        def policy(target, output, **kwargs):
            prepare(page, ["--retire-excess-routine", target], output, **kwargs)

        amount = totals["routine_only"][1]
        policy(amount, guard, code=1)
        policy(0, guard, age=10000, code=1)
        policy(0, guard, cap=0, code=1)
        policy(0, guard, cap=exclusive["7"] - 1, code=1)
        policy(0, guard, cap=exclusive["7"])
        check(json.loads(guard.read_bytes())["collection_id"] == "7", "inclusive maximum")
        policy(0, rule)
        selected = json.loads(rule.read_bytes())
        check(selected["collection_id"] == "7" and selected["reason"] == reason, "oldest closure then numeric tie")
        plan = retire(store, rule)
        check(plan["status"] == "planned", plan)
        before = originals(store)
        for key in ("4", "5", "33", "38", "12"):
            chosen = next(c for c in snapshot["collections"] if c["id"] == key)
            forged = dict(selected, collection_id=key, session_sha256=chosen["session_sha256"], head_sha256=chosen["head_sha256"])
            guard.write_bytes(encoded(forged))
            check(retire(store, guard, True, 1)["issue"] == ("routine_budget_candidate_changed_or_ineligible" if key == "12" else
                  "routine_budget_root_protected"), key)
        for field, value, issue in (("routine_named_byte_target", str(amount), "routine_budget_within_target"),
                                    ("artifacts_sha256", "a" * 64, "routine_budget_inventory_changed"),
                                    ("catalog_sha256", "b" * 64, "routine_budget_inventory_changed"),
                                    ("exclusive_byte_limit", "0", "routine_budget_candidate_changed_or_ineligible")):
            guard.write_bytes(encoded(dict(selected, **{field: value})))
            check(retire(store, guard, True, 1)["issue"] == issue, field)
        stamp = baseline_time - 120
        os.utime(closures["24"], (stamp, stamp))
        reordered = inventory(store, "/retention")
        prepare(reordered, ["--retire-excess-routine", 0], work / "oldest")
        check(json.loads((work / "oldest").read_bytes())["collection_id"] == "24" and
              retire(store, work / "oldest")["status"] == "planned", "oldest eligible image wins")
        prepare(reordered, ["--retire-excess-routine", 0], work / "bounded", cap=exclusive["7"])
        check(json.loads((work / "bounded").read_bytes())["collection_id"] == "7" and
              retire(store, work / "bounded")["status"] == "planned", "oversized oldest root skipped")
        os.utime(closures["24"], (baseline_time, baseline_time))
        os.utime(closures["12"], (stamp, stamp))
        check(retire(store, rule, True, 1)["issue"] == "routine_budget_candidate_changed_or_ineligible", "changed closure order")
        os.utime(closures["12"], (baseline_time - 60, baseline_time - 60))
        check(originals(store) == before, "refused policies leave all original bytes intact")

        for stage in ("retire_preflight", "retire_published"):
            branch = work / stage
            shutil.copytree(store, branch)
            with subprocess.Popen([str(producer), "--retire-collection", str(branch), str(rule), "apply", stage],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
                seen = queue.Queue()
                reader = threading.Thread(target=lambda: seen.put(process.stdout.readline()), daemon=True)
                reader.start()
                try:
                    check(seen.get(timeout=30).decode().strip() == "[journal.stage] " + stage, stage)
                finally:
                    process.kill()
                    process.wait(timeout=30)
                    reader.join(timeout=5)
            check(retire(branch, rule, True)["reused_receipt"] == (stage == "retire_published"), "interruption retry " + stage)

        receipt = store / "collections/7/retirement.knretirement"
        result = retire(store, rule, True)
        data = receipt.read_bytes()
        record = json.loads(data)
        audit = record["payload"]
        check(sha(data) == result["receipt_sha256"] and record["schema"] == "kn.evidence_retirement.v2" and
              record["payload_sha256"] == sha(encoded(audit)) and audit["policy"] == selected and
              int(audit["routine_named_bytes_before"]) == amount and int(audit["routine_named_bytes_after"]) == amount - exclusive["7"] and
              retire(store, rule, True)["reused_receipt"], "durable v2 impact and identical retry")
        check(originals(store) == dict(before, **{"collections/7/retirement.knretirement": sha(data)}), "retirement writes only its receipt")
        current = inventory(store, "/retention")
        remaining = next(int(row["named_bytes"]) for row in current["collection_retention"]["classes"] if row["class"] == "routine_only")
        check(remaining == amount - exclusive["7"], "physical and active before/after agree")
        if args.previous_cli:
            legacy = json.loads(call([args.previous_cli.resolve(), "--offline", "!kmon", "store", store], 1))
            check(legacy["status"] == "partial" and not legacy["membership_complete"], "previous reader fails closed on a v2 receipt")
        other = next(c for c in current["collections"] if c["id"] == "12")
        guard.write_bytes(encoded(dict(selected, collection_id="12", session_sha256=other["session_sha256"], head_sha256=other["head_sha256"])))
        check(retire(store, guard, True, 1)["issue"] == "routine_budget_inventory_changed", "concurrent withdrawal invalidates peer plan")
        prepare(current, ["--retire-excess-routine", remaining], work / "done", code=1)
        prepare(current, ["--retire-excess-routine", 0], work / "next")
        check(json.loads((work / "next").read_bytes())["collection_id"] == "12", "next snapshot selects surviving candidate")
        pair = work / "pair"
        for key in ("8", "10"):
            call([producer, "--produce-irp", pair, key, "-"])
            last = prepare_members(pair, key, "irp", "routine")
            os.utime(last, (baseline_time, baseline_time))
        pair_report = inventory(pair, "/retention")
        pair_roots = pair_report["collection_retention"]["roots"]
        shared_file = next(pair.glob("irp-reference-*.knblob"))
        pair_bytes = next(int(row["named_bytes"]) for row in pair_report["collection_retention"]["classes"] if row["class"] == "routine_only")
        check(pair_bytes == sum(int(row["exclusive_routine_bytes"]) for row in pair_roots) + shared_file.stat().st_size and
              all(row["routine_paths"] == "2" for row in pair_roots), "two routine owners charge the same PE once")
        pair_rule = work / "pair-rule"
        prepare(pair_report, ["--retire-excess-routine", 0], pair_rule)
        check(json.loads(pair_rule.read_bytes())["collection_id"] == "8", "numeric ID tie across string lengths")
        retire(pair, pair_rule, True)
        survivor = inventory(pair, "/retention")["collection_retention"]["roots"]
        check(len(survivor) == 1 and survivor[0]["collection_id"] == "10" and int(survivor[0]["exclusive_routine_bytes"]) ==
              next(int(r["exclusive_routine_bytes"]) for r in pair_roots if r["collection_id"] == "10") + shared_file.stat().st_size,
              "last owner inherits full shared path accounting")
        open_store = work / "open"
        shutil.copytree(pair, open_store)
        closing_record = sorted((open_store / "collections/10/journal-segments").glob("*.knjseg"))[-1]
        closing_record.rename(work / "held-closing-segment")
        open_report = inventory(open_store, "/retention", code=1)
        check(open_report["open_collections"] == "1" and open_report["collection_retention"]["status"] == "unavailable",
              "open collection disables the entire budget")
        prepare(open_report, ["--retire-excess-routine", 0], work / "unavailable", code=1)
        shared = next(row for row in current["artifacts"] if row["artifact"]["path"].startswith("irp-reference-"))
        check("7" in shared["retired_collections"] and len(shared["collections"]) > 1 and
              shared["retention"] == "committed_reference_protected", "shared reference stays protected")
        prepare(current, ["--path", shared["artifact"]["path"], "--from-retired-collection", "7"], work / "shared", code=1)
        capture = next(row["artifact"]["path"] for row in current["artifacts"] if row["artifact"]["path"].startswith("irp-7-"))
        file_rule = work / "gc"
        prepare(current, ["--path", capture, "--from-retired-collection", "7"], file_rule)
        gc_command = [*cli, "gc", store, file_rule, "/apply", "2"] if args.cli else [exe, "--gc", store, file_rule, "2"]
        check(json.loads(call(gc_command))["deleted_this_call"] == "1" and not (store / capture).exists() and
              (store / shared["artifact"]["path"]).is_file() and all((store / p).is_file() for p in memberships if p.endswith("ledger")),
              "receipt-bound GC releases only the selected file")
        record["payload"]["routine_named_bytes_after"] = str(amount)
        receipt.write_bytes(seal(record, "payload_sha256"))
        broken = inventory(store, "/retention", code=1)
        check(broken["status"] == "partial" and broken["collection_retention"]["status"] == "unavailable" and
              not broken["collection_retention"]["roots"], "rehashing impossible impact cannot reopen policy")
        print(f"[collection.retention] checks={checks} roots={len(expected)} paths={len(memberships)} "
              f"routine_before={amount} routine_after={remaining} ledger_paths={totals['ledger'][0]}")


if __name__ == "__main__":
    main()
