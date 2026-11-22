"""Exact original IRP claims, current evaluation, physical membership and failure controls."""
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

from irp_claim_oracle import validate as validate_claims
from irp_retention_oracle import check_irp_retention

SCHEMA = "kn.irp_claim_publication.v1"


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def seal(value):
    value["publication_sha256"] = sha(encoded(value["payload"]))
    return encoded(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--publisher", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--journal-exe", type=Path)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    checks = 0

    def check(ok, label):
        nonlocal checks
        checks += 1
        assert ok, label

    def invoke(command, code=0):
        result = subprocess.run(list(map(str, command)), capture_output=True, encoding="utf-8", timeout=60)
        check(result.returncode == code, (command[:2], code, result.returncode, result.stdout[-600:], result.stderr[-600:]))
        return result

    prefix = [args.exe.resolve()] + (["--offline", "!kmon", "replay-irp"] if args.product else ["--replay-irp"])

    def replay(path, issue="", current=False, status="reproduced"):
        before = path.read_bytes()
        result = json.loads(invoke(prefix + [path] + (["/current"] if current else []), 1 if issue else 0).stdout)
        check(path.read_bytes() == before and result["capture_sha256"] == sha(before), "immutable physical capture digest")
        original = result["original_claim_replay"]
        check(not original["journal_membership_checked"] and not original["collector_authenticated"], "reproduction does not authenticate membership")
        check(result["issue"] == issue and original["status"] == status, (result["issue"], original["status"], issue, status))
        if issue:
            check(result["result"] is None and result["claim_assessment"] is None and not result["summary_matched"] and
                  not result["qualified_observation_reproduced"] and not original["original_claim_policy_reproduced"], "failure withholds all derived results")
            return result
        document = json.loads(before)
        raw = document["payload"]["capture"] if document["schema"] == SCHEMA else document
        check(result["original_capture_sha256"] == sha(encoded(raw)), "inner evidence pointers use original raw hash")
        validate_claims(encoded(raw), result["claim_assessment"], replay=True, reference_available=result["reference_status"] == "verified")
        check(original["original_claim_policy_reproduced"] == (status == "reproduced"), "separate original claim reproduction outcome")
        if document["schema"] == SCHEMA:
            stored = document["payload"]["recorded_claim"]
            check(original["publication_sha256"] == sha(encoded(document["payload"])) and
                  original["recorded_report_sha256"] == sha(encoded(stored)), "original report and noncircular payload digests")
            check(original["registry"] == stored["registry"] and original["policy"] == stored["policy"], "stored policy identity")
            check(result["claim_assessment"]["evaluation_mode"] == "current_policy_on_replayed_observations", "current evaluation is separately labelled")
        return result

    references = list(args.fixtures.glob("irp-reference-*.knblob"))
    cases = sorted(args.fixtures.glob("case-*.knirp"))
    check(bool(references) and bool(cases), "owned capture and reference fixtures present")
    with tempfile.TemporaryDirectory(prefix="irp-claims-", dir=args.fixtures.resolve()) as temporary:
        root = Path(temporary)
        for ref in references:
            shutil.copyfile(ref, root / ref.name)
        published = []
        for case in cases:
            destination = root / case.name
            invoke([args.publisher, "--publish-irp", case, destination])
            raw = destination.read_bytes()
            document = json.loads(raw)
            check(document["schema"] == SCHEMA and len(raw) <= 16 * 1024 * 1024, "bounded whole publication")
            check(encoded(document["payload"]["capture"]) == case.read_bytes(), "exact original capture bytes retained")
            check(encoded(document["payload"]["recorded_claim"]) == case.with_suffix(".knirp.knclaims").read_bytes(), "equals independently saved capture-time report")
            validate_claims(case.read_bytes(), document["payload"]["recorded_claim"], reference_available=int(json.loads(case.read_bytes())["reference_captured_bytes"]) != 0)
            replay(destination)
            replay(destination, current=True, status="not_requested")
            published.append(destination)

        path = root / "mutated.knirp"
        original = published[0].read_bytes()
        document = json.loads(original)
        raw = encoded(document["payload"]["capture"])
        source = root / "source.knirp"
        source.write_bytes(raw)
        replay(source, status="not_recorded")
        if args.journal_exe:
            check_irp_retention(root, raw, original, journal=args.journal_exe.resolve(),
                                product=args.exe.resolve() if args.product else None, invoke=invoke, replay=replay, check=check)
        invoke([args.publisher, "--publish-irp", source, published[0]], 1)
        check(published[0].read_bytes() == original, "immutable collision leaves original unchanged")
        budget = root / "budget.knirp"
        invoke([args.publisher, "--publish-irp", source, budget, len(original) - 1], 1)
        check(not budget.exists(), "whole publication budget includes report and envelope")
        invoke([args.publisher, "--publish-irp", source, budget, len(original)])
        check(budget.read_bytes() == original, "exact budget boundary deterministic publication")

        def mutation(change, issue, status, current_ok=False):
            altered = copy.deepcopy(document)
            change(altered)
            path.write_bytes(seal(altered))
            replay(path, issue, status=status)
            if current_ok:
                replay(path, current=True, status="not_requested")
            elif issue == "invalid_claim_publication":
                replay(path, issue, current=True, status=status)

        mutation(lambda c: c["payload"]["recorded_claim"].update(policy="future.v9"), "recorded_claim_policy_unavailable", "policy_unavailable", True)
        mutation(lambda c: c["payload"]["recorded_claim"].update(registry="future.v9"), "recorded_claim_policy_unavailable", "policy_unavailable", True)
        mutation(lambda c: c["payload"]["recorded_claim"].update(evaluation_mode="current_policy_on_replayed_observations"), "recorded_claim_assessment_mismatch", "assessment_mismatch", True)
        mutation(lambda c: c["payload"]["recorded_claim"]["ledgers"]["trust"].update(collector_authenticated=True), "recorded_claim_assessment_mismatch", "assessment_mismatch", True)
        mutation(lambda c: c["payload"]["recorded_claim"]["claims"].clear(), "recorded_claim_assessment_mismatch", "assessment_mismatch", True)
        mutation(lambda c: c["payload"]["recorded_claim"].update(capture_sha256="0" * 64), "invalid_claim_publication", "invalid_publication")
        mutation(lambda c: c["payload"]["recorded_claim"].update(capture_sha256=""), "invalid_claim_publication", "invalid_publication")
        mutation(lambda c: c["payload"].update(extra=True), "invalid_claim_publication", "invalid_publication")
        mutation(lambda c: c.update(extra=True), "invalid_claim_publication", "invalid_publication")
        mutation(lambda c: c["payload"]["recorded_claim"].update(registry="x" * 129), "invalid_claim_publication", "invalid_publication")
        mutation(lambda c: c["payload"]["recorded_claim"].update(padding="x" * (128 * 1024)), "invalid_claim_publication", "invalid_publication")
        altered = copy.deepcopy(document)
        altered["payload"]["capture"]["runtime_qualified"] = not altered["payload"]["capture"]["runtime_qualified"]
        altered["payload"]["recorded_claim"]["capture_sha256"] = sha(encoded(altered["payload"]["capture"]))
        path.write_bytes(seal(altered))
        replay(path, "recomputed_capture_differs", status="not_reproduced")
        replay(path, "recomputed_capture_differs", current=True, status="not_requested")
        altered = copy.deepcopy(document)
        altered["publication_sha256"] = "0" * 64
        path.write_bytes(encoded(altered))
        replay(path, "invalid_claim_publication", status="invalid_publication")
        path.write_bytes(original[:-1] + b',"schema":"' + SCHEMA.encode() + b'"}')
        replay(path, "invalid_capture_encoding", status="not_recorded")

        # Missing references retain legacy bounded replay, but cannot reproduce
        # a stored capture-time report that was evaluated with that reference.
        missing = root / "missing"
        missing.mkdir()
        missing_file = missing / "publication.knirp"
        missing_file.write_bytes(original)
        replay(missing_file, "original_claim_inputs_unavailable", status="inputs_unavailable")
        replay(missing_file, current=True, status="not_requested")
        invoke([args.publisher, "--publish-irp", source, missing / "new.knirp"], 1)
        check(not (missing / "new.knirp").exists(), "missing original input cannot create original report")
        if args.product:
            integrated = json.loads(invoke([args.exe, "--self-test", "irp-publication", cases[0]]).stdout)
            check(integrated["passed"] and integrated["owned_files_cleaned"] and not integrated["driver_loaded"] and
                  integrated["failed"] == 0, "actual writer publication, budget fallback, reference failure and cleanup")
            invoke([args.exe, "--self-test", "irp-publication"], 2)
            invoke([args.exe, "--self-test", "irp-publication", cases[0], "extra"], 2)
            for flags in (("/current", "/current"), ("/json", "/json"), ("/unknown",)):
                invoke(prefix + [published[0], *flags], 2)
            invoke(prefix + [published[0], "/json", "/current"])

        if args.journal_exe:
            journal = str(args.journal_exe.resolve())

            def prepare(name):
                folder = root / name
                folder.mkdir()
                for ref in references:
                    shutil.copyfile(ref, folder / ref.name)
                (folder / ("irp-7-" + sha(original) + ".knirp")).write_bytes(original)
                return folder

            def recover(folder, ok=True):
                result = json.loads(invoke([journal, "--recover", folder / "collections/7", "--index"], 0 if ok else 1).stdout)
                return result

            def oracle(folder, result):
                session = (folder / "collections/7/session.knsession").read_bytes()
                check(json.loads(session)["payload"]["policy"] == "kn.image_irp_claim_collection_journal.v4", "new membership policy explicit")
                previous = sha(session)
                for segment in sorted((folder / "collections/7/journal-segments").glob("*.knjseg")):
                    data = segment.read_bytes()
                    entry = json.loads(data)
                    check(entry["payload_sha256"] == sha(encoded(entry["payload"])) and entry["payload"]["previous_sha256"] == previous, "independent hash chain")
                    transaction = entry["payload"]["transaction"]
                    for member in transaction["members"]:
                        saved = (folder / member["path"]).read_bytes()
                        check(sha(saved) == member["sha256"] and len(saved) == int(member["bytes"]), "physical membership includes frozen report")
                    if transaction["kind"] == "irp_capture":
                        check(transaction["id"] == sha(original) and len(transaction["members"]) == 2, "one whole publication plus retained reference")
                    previous = sha(data)
                check(previous == result["head_sha256"], "exact committed head")

            for stage, count, closed in (("irp_claim_files", 0, False), ("irp_claim_commit", 1, False),
                                         ("irp_claim_ledger", 2, False), ("irp_claim_closed", 3, True)):
                folder = prepare(stage)
                actor = subprocess.Popen([journal, "--commit-published-irp", str(folder), stage, "4"],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
                observed = queue.Queue()
                thread = threading.Thread(target=lambda: observed.put(actor.stdout.readline()), daemon=True)
                thread.start()
                try:
                    check(observed.get(timeout=60).strip() == "[journal.stage] " + stage, "kill only after observed durable stage")
                finally:
                    if actor.poll() is None:
                        actor.kill()
                    actor.communicate(timeout=30)
                    thread.join(timeout=5)
                result = recover(folder)
                check(int(result["committed_segments"]) == count and result["closed"] == closed, "interrupted original claim prefix")
                oracle(folder, result)
                saved = next(folder.glob("*.knirp"))
                replay(saved)
                if count:
                    altered = copy.deepcopy(document)
                    altered["payload"]["recorded_claim"]["evaluation_mode"] = "substituted"
                    saved.write_bytes(seal(altered))
                    check(recover(folder, False)["issue"] == "member_hash_or_size_mismatch", "rehashed report cannot replace committed physical member")
                    saved.write_bytes(original)
            for version in ("1", "2", "3"):
                folder = prepare("old-policy-" + version)
                invoke([journal, "--commit-published-irp", folder, "", version], 1)
                check(recover(folder)["committed_segments"] == "0", "older policies reject publication schema")

    print(f"[irp.claim.publication] checks={checks} cases={len(cases)} journal={bool(args.journal_exe)} product={args.product}")


if __name__ == "__main__":
    main()
