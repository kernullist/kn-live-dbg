"""Exercise native image-source collections, using the owned DLL acquisition as the oracle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from image_source_retention_oracle import check_source_copies


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def relabel_copy(store, destination, collection_id, other_operation):
    """Reseal a disposable archive's physical chain around a report naming another operation."""
    shutil.copytree(store, destination)
    folder = destination / "collections" / collection_id
    sources = destination / "image-captures"
    original, = sources.glob(f"source-{collection_id}-*.knsource")
    old_pin = sha(original.read_bytes())
    page = json.loads(original.read_bytes())
    assert page["operation_id"] != other_operation
    page["operation_id"] = other_operation
    edited = encode(page)
    new_pin = sha(edited)
    report = original.with_name(original.name.replace(old_pin, new_pin))
    original.rename(report)
    report.write_bytes(edited)
    claim, = sources.glob(f"case-{collection_id}-*.kncapture")
    claim.rename(claim.with_name(claim.name.replace(old_pin, new_pin)))
    previous = sha((folder / "session.knsession").read_bytes())
    total = 0
    for segment in sorted((folder / "journal-segments").glob("*.knjseg")):
        record = json.loads(segment.read_bytes())
        payload = record["payload"]
        txn = payload["transaction"]
        txn["id"] = txn["id"].replace(old_pin, new_pin)
        txn["requires"] = [path.replace(old_pin, new_pin) for path in txn["requires"]]
        for item in txn["members"]:
            item["path"] = item["path"].replace(old_pin, new_pin)
            path = destination / item["path"]
            if txn["kind"] == "closure":
                ledger = json.loads(path.read_bytes())
                ledger.update(report_path=report.relative_to(destination).as_posix(), report_sha256=new_pin,
                              logical_referenced_bytes=str(total))
                path.write_bytes(encode(ledger))
            data = path.read_bytes()
            item.update(sha256=sha(data), bytes=str(len(data)))
            total += len(data)
        payload["previous_sha256"] = previous
        record["payload_sha256"] = sha(encode(payload))
        data = encode(record)
        segment.write_bytes(data)
        previous = sha(data)
    return report, new_pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--root", type=Path, help="retain the verified private archive in a new directory")
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, message
        checks += 1

    def cli(action, *operands, code=0):
        p = subprocess.run([str(exe), "--offline", "!kmon", action, *map(str, operands), "/json"],
                           capture_output=True, timeout=60)
        check(p.returncode == code, (action, p.returncode, code, p.stdout[-450:], p.stderr[-200:]))
        if code == 2:
            check(not p.stdout and b"usage" in p.stderr, "syntax error has no DTO")
            return None
        return json.loads(p.stdout)

    def tree(root):
        return {p.relative_to(root).as_posix(): (sha(p.read_bytes()), p.stat().st_mtime_ns)
                for p in root.rglob("*") if p.is_file()}

    def verify_segments(store, identifier, output, original, claim, reference):
        folder = store / "collections" / identifier
        session = (folder / "session.knsession").read_bytes()
        page = json.loads(session)
        check(page["payload"]["policy"] == "kn.image_source_collection_journal.v1" and
              sha(encode(page["payload"])) == page["payload_sha256"], "original policy identity")
        previous = sha(session)
        segments = sorted((folder / "journal-segments").glob("*.knjseg"))
        check(len(segments) == 2, "one attempt and its closure")
        first_paths = []
        for seq, path in enumerate(segments, 1):
            raw = path.read_bytes()
            page = json.loads(raw)
            payload = page["payload"]
            check(sha(encode(payload)) == page["payload_sha256"] and int(payload["sequence"]) == seq and
                  payload["previous_sha256"] == previous, "independently verified the journal chain")
            previous = sha(raw)
            txn = payload["transaction"]
            members = txn["members"]
            paths = [m["path"] for m in members]
            check(paths == sorted(set(paths)), "canonical unique names")
            for member in members:
                data = (store / member["path"]).read_bytes()
                check(sha(data) == member["sha256"] and len(data) == int(member["bytes"]), "exact physical member")
            if seq == 1:
                first_paths = paths
                check(txn["kind"] == "image_source" and txn["id"] == sha(original) and not txn["requires"],
                      "acquisition identity is the original stdout digest")
                expected = {output["report_path"]}
                if claim is not None:
                    expected.update([output["capture_path"], "image-references/" + sha(reference) + ".knblob"])
                check(set(paths) == expected, "complete original dependency set")
            else:
                check(txn["kind"] == "closure" and len(members) == 1 and txn["requires"] == first_paths,
                      "closure requires exactly the first commit")
                ledger = json.loads((store / paths[0]).read_bytes())
                report = json.loads(original)
                check(ledger["report_sha256"] == sha(original) and ledger["capture_status"] == report["status"] and
                      ledger["source_status"] == report["source_initialization"]["status"] and ledger["archived_attempts"] == "1" and
                      int(ledger["archived_claims"]) == int(claim is not None), "original outcome and denominator")
                check(int(ledger["logical_referenced_bytes"]) == len(original) + len(claim or b"") + len(reference or b""),
                      "byte denominator measured independently")
        check(previous == output["head_sha256"], "returned head is the physical terminal record")

    with tempfile.TemporaryDirectory(prefix="image-source-archive-") as temporary:
        directory = Path(temporary)
        store = args.root.resolve() if args.root else directory / "store"
        check(not store.exists(), "use a fresh private store")
        check(cli("init-store", store, "/acl-only")["root_acl_verified"], "store admission")
        with tempfile.TemporaryDirectory(dir=directory, prefix="acquisition-") as source:
            inputs = Path(source) / "inputs"
            subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("test-image-source-receipts.py")),
                            "--exe", str(exe), "--root", str(inputs)], timeout=200, check=True)
            managed, = (inputs / "image-captures").glob("*.kncapture")
            ref, = (inputs / "image-references").glob("*.knblob")
            source_tree = tree(inputs)
            saved = {}
            for identifier, (name, case) in enumerate((("denied", None), ("wrong-generation", None), ("missing-process", None),
                                                      ("missing-reference", None), ("second", inputs / "second"), ("normal", managed)), 1):
                id_text = str(identifier)
                report = inputs / (name + ".json")
                data = report.read_bytes()
                pin = sha(data)
                claim = (case / "recipe.knverify" if case and case.is_dir() else case).read_bytes() if case else None
                reference = ref.read_bytes() if case else None
                extra = [case] if case else []
                expected = cli("replay-image-source", report, pin, *extra)
                result = cli("journal-image-source", report, pin.upper(), store, id_text, *extra)
                check(result["status"] == "archived" and result["report_committed"] and result["closed"] and result["indexed"],
                      "closed and indexed archive")
                check((store / result["report_path"]).read_bytes() == data and result["report_sha256"] == pin,
                      "stdout byte-for-byte with external pin")
                if case:
                    check((store / result["capture_path"]).read_bytes() == claim and
                          (store / "image-references" / ref.name).read_bytes() == reference, "exact original claim and PE")
                else:
                    check(not result["capture_path"] and not (store / "image-references").exists(), "failed attempt owns only its report")
                verify_segments(store, id_text, result, data, claim, reference)
                recovered = cli("journal", store / "collections" / id_text, "/index")
                check(recovered["closed"] and recovered["committed_source_report_path"] == result["report_path"] and
                      recovered["committed_direct_capture_paths"] == ([result["capture_path"]] if case else []), "recovery exposes exact members")
                before = tree(store)
                retry = cli("journal-image-source", report, pin, store, id_text, *extra)
                check(retry == result and before == tree(store), "identical closed retry preserves all bytes and file times")
                saved[name] = result, expected, pin
            check(source_tree == tree(inputs), "archiving preserved all source bytes and modification times")
            raw = inputs / "normal.json"
            pin = saved["normal"][2]
            for new_pin, case, issue in (("0" * 64, managed, "report_digest_mismatch"),
                                         (pin, inputs / "second", "image_case_mismatch"), (pin, None, "image_case_required")):
                refusal = cli("journal-image-source", raw, new_pin, store, "70", *([case] if case else []), code=1)
                check(refusal["issue"] == issue and not (store / "collections/70").exists(), "refused before store mutation")
            check(cli("journal-image-source", raw, pin, store, "01", managed, code=2) is None, "noncanonical collection ID")
            before = tree(store)
            refusal = cli("journal-image-source", raw, pin, store, "1", managed, code=1)
            check(refusal["issue"] == "collection_contains_different_report" and before == tree(store), "closed identifier collision")
            second_report = inputs / "second.json"
            second_pin = saved["second"][2]
            impediment = store / "image-captures/session-7.knsourceledger"
            impediment.mkdir()
            incomplete = cli("journal-image-source", second_report, second_pin, store, "7", inputs / "second", code=1)
            check(incomplete["report_committed"] and not incomplete["closed"] and incomplete["issue"] == "ledger_publication_failed",
                  "real closure publication failure preserves the source transaction")
            prefix = cli("journal", store / "collections/7")
            check(prefix["committed_segments"] == "1" and prefix["can_resume"] and not prefix["closed"], "new process sees open prefix")
            part = next((store / "collections/7/journal-segments").glob("*.knjseg"))
            stamp = (sha(part.read_bytes()), part.stat().st_mtime_ns)
            impediment.rmdir()
            check(cli("journal-image-source", second_report, second_pin, store, "7", inputs / "second")["closed"] and
                  stamp == (sha(part.read_bytes()), part.stat().st_mtime_ns), "retry closes exactly the same original segment")
        check(not inputs.exists(), "standalone reports, their source cases and private input journal removed")
        for out, expected, pin in saved.values():
            check(cli("replay-image-source", store / out["report_path"], pin) == expected, "complete source replay after original removal")
        inventory = cli("store", store, "/artifacts")
        check(inventory["closed_collections"] == "7" and inventory["unattributed_files"] == "0" and
              len(list((store / "image-references").glob("*.knblob"))) == 1, "shared PE and seven verified collection roots")

        result, expected, pin = saved["normal"]
        report = store / result["report_path"]
        claim = store / result["capture_path"]
        alias = store / report.parent.name.upper() / report.name.upper()
        if alias.exists() and alias.samefile(report):
            check(cli("replay-image-source", alias, pin.upper()) == expected, "case-insensitive spelling of the same managed input")
        copy_store = directory / "copy"
        cli("init-store", copy_store, "/acl-only")
        migrated = cli("journal-image-source", report, pin, copy_store, "2")
        check(cli("replay-image-source", copy_store / migrated["report_path"], pin) == expected, "rearchive from managed evidence only")
        forged_store = directory / "relabeled"
        peer = json.loads((store / saved["second"][0]["report_path"]).read_bytes())
        relabeled, new_pin = relabel_copy(copy_store, forged_store, "2", peer["operation_id"])
        check(cli("replay-image-source", relabeled, new_pin, code=1)["status"] == "image_case_mismatch", "repinned report cannot change the operation")
        rejected = cli("journal", forged_store / "collections/2", code=1)
        check(rejected["committed_segments"] == "0" and rejected["issue"] == "capture_report_dependencies_mismatch",
              "fully resealed physical chain still requires the original operation and result")
        for protected in (report, claim, next((store / "image-references").glob("*.knblob")), copy_store / migrated["report_path"]):
            link = directory / "outside-link"
            os.link(protected, link)
            try:
                before = tree(store), tree(copy_store)
                args = [str(exe), "--offline", "!kmon", "journal-image-source", str(report), pin, str(copy_store), "81", "/json"]
                with link.open("ab") as sink:
                    output = subprocess.run(args, stdout=sink, stderr=subprocess.PIPE, timeout=40)
                check(output.returncode == 2 and before == (tree(store), tree(copy_store)), "redirected archive output protects all inputs and destination")
            finally:
                link.unlink()

        copy_claim = copy_store / migrated["capture_path"]
        original = copy_claim.read_bytes()
        other = (store / saved["second"][0]["capture_path"]).read_bytes()
        record = next((copy_store / "collections/2/journal-segments").glob("*0001.knjseg"))
        original_record = record.read_bytes()
        try:
            copy_claim.write_bytes(other)
            check(cli("replay-image-source", copy_store / migrated["report_path"], pin, code=1)["status"] == "image_case_mismatch",
                  "same bytes from another acquisition")
            forged = json.loads(original_record)
            member = next(m for m in forged["payload"]["transaction"]["members"] if m["path"] == migrated["capture_path"])
            member.update(sha256=sha(other), bytes=str(len(other)))
            forged["payload_sha256"] = sha(encode(forged["payload"]))
            record.write_bytes(encode(forged))
            rejected = cli("journal", copy_store / "collections/2", code=1)
            check(rejected["committed_segments"] == "0" and not rejected["closed"], "fresh physical digests cannot relabel a different recipe")
        finally:
            copy_claim.write_bytes(original)
            record.write_bytes(original_record)
        check(cli("journal", copy_store / "collections/2")["closed"] and cli("replay-image-source", copy_store / migrated["report_path"], pin) == expected,
              "the restored originals reproduce")

        # Lose the response after publishing a failed acquisition. The journal
        # independently reveals the outcome before an exact retry.
        delivery = directory / "delivery"
        cli("init-store", delivery, "/acl-only")
        denied, _, denied_pin = saved["denied"]
        delivery_args = [str(exe), "--offline", "!kmon", "journal-image-source", str(store / denied["report_path"]),
                         denied_pin, str(delivery), "9", "/json"]
        sink_file = directory / "read-only-sink"
        sink_file.touch()
        with sink_file.open("rb") as sink:
            undelivered = subprocess.run(delivery_args, stdout=sink, stderr=subprocess.PIPE, timeout=40)
        check(undelivered.returncode == 3 and not sink_file.read_bytes(), "publication survives an undeliverable acknowledgement")
        closed = cli("journal", delivery / "collections/9", "/index")
        before = tree(delivery)
        again = cli("journal-image-source", store / denied["report_path"], denied_pin, delivery, "9")
        check(closed["closed"] and again["head_sha256"] == closed["head_sha256"] and before == tree(delivery), "outcome lookup and exact retry")

        # Withdraw only a disposable copy through the actual policy, retirement
        # and GC entry points. Each pass must honor the surviving dependency.
        helper = Path(__file__).with_name("new-evidence-gc-policy.py")

        def policy_for(name, *selection):
            snapshot = cli("store", copy_store, "/artifacts")
            inventory = directory / (name + "-inventory.json")
            inventory.write_bytes(encode(snapshot))
            policy = directory / (name + "-policy.json")
            proc = subprocess.run([sys.executable, "-B", str(helper), "--inventory", str(inventory), *selection,
                                   "--reason", "owned archive retirement", "--minimum-age-seconds", "0", "--output", str(policy)],
                                  capture_output=True, timeout=30)
            check(proc.returncode == 0 and policy.is_file(), (name, proc.stderr))
            return policy, {row["artifact"]["path"]: row["retention"] for row in snapshot["artifacts"]}

        retirement, _ = policy_for("retire", "--retire-collection", "2")
        cli("retire-collection", copy_store, retirement)
        cli("retire-collection", copy_store, retirement, "/apply")
        witness = copy_store / "image-captures/session-2.knsourceledger"
        ledger_bytes = witness.read_bytes()
        shared_pe, = (copy_store / "image-references").glob("*.knblob")
        pe_path = shared_pe.relative_to(copy_store).as_posix()
        for index, path in enumerate((migrated["report_path"], migrated["capture_path"], pe_path), 1):
            policy, flags = policy_for(f"gc-{index}", "--path", path, "--from-retired-collection", "2")
            if index == 1:
                check(flags[migrated["capture_path"]] == flags[pe_path] == "uncommitted_image_input_protected",
                      "the retired report still protects its original claim and shared PE")
            cli("gc", copy_store, policy)
            cli("gc", copy_store, policy, "/apply", str(index))
            check(not (copy_store / path).exists() and witness.read_bytes() == ledger_bytes, "explicit ordered reclamation retains the outcome ledger")
        retired = cli("journal", copy_store / "collections/2")
        check(retired["status"] == "retired" and not retired["original_set_verified"] and
              "committed_source_report_path" not in retired and not retired["committed_direct_capture_paths"], "retired journal preserves historical membership")
        check_source_copies(store, directory, cli, check)
    print(f"[image.source.archive] passed={checks} acquisitions=6 source_removed=true")


if __name__ == "__main__":
    main()
