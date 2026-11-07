"""Independent typed IRP membership, interruption, inventory and conservative GC oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import uuid

CHECKS = 0


def check(ok, message):
    global CHECKS
    CHECKS += 1
    if not ok:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    exe, producer = args.exe.resolve(), (args.producer or args.exe).resolve()
    sandbox = args.fixtures.resolve() / ("irp-journal-" + uuid.uuid4().hex)
    sandbox.mkdir(parents=True)

    def invoke(kind, root, *extra):
        check(root.resolve().is_relative_to(sandbox), "owned fixture namespace")
        if args.product:
            command = [str(exe), "--offline", "!kmon", kind, str(root)]
            if kind == "store":
                command += ["/artifacts", "/json"]
            elif kind == "journal":
                command += ["/index"] if extra else []
            else:
                command += [str(extra[0]), *(["/apply", extra[1]] if len(extra) > 1 else []), "/json"]
        else:
            flag = {"store": "--store", "journal": "--recover", "gc": "--gc"}[kind]
            command = [str(exe), flag, str(root)]
            if kind == "journal" and extra:
                command += ["--index"]
            elif kind == "gc":
                command += [str(extra[0]), extra[1] if len(extra) > 1 else "-"]
        p = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=45)
        schema = {"store": "kn.evidence_store_inventory.v1", "journal": "kn.evidence_journal_recovery.v1",
                  "gc": "kn.evidence_gc_result.v1"}[kind]
        lines = [line for line in p.stdout.splitlines() if line.startswith('{"schema":"' + schema + '"')]
        check(len(lines) == 1, f"one {kind} report, rc={p.returncode}, stderr={p.stderr[-300:]}")
        report = json.loads(lines[0])
        good = report["status"] in ("verified", "verified_prefix", "planned", "completed") and report.get("index_status") != "failed"
        check(p.returncode == (0 if good else 1), "report and exit status agree")
        check(report["collector_authenticated"] is False and report["power_loss_durability_established"] is False, "no authentication/durability invention")
        if kind == "journal":
            check(report["replay_established"] is False and report["orphan_files_included"] is False, "membership does not establish replay")
        if kind == "store":
            check(report["scope"] == "image_and_irp_collection_namespace" and report["deletion_authorized"] is False, "typed inventory is not deletion authority")
            check(report["artifacts_sha256"] == sha(encoded(report["artifacts"])), "exact artifact table receipt")
        return report

    def produce(root, collection="7"):
        p = subprocess.run([str(producer), "--produce-irp", str(root), collection, ""], capture_output=True, timeout=30)
        check(p.returncode == 0, "produce typed owned fixture")

    original = sandbox / "original"
    produce(original)
    produce(original, "8")
    p = subprocess.run([str(producer), "--produce-collection", str(original), "9"], capture_output=True, timeout=30)
    check(p.returncode == 0, "legacy and typed sessions coexist")
    members, content, logical, references, per_collection_bytes = {}, {}, 0, 0, 0
    for directory in sorted((original / "collections").iterdir()):
        session = (directory / "session.knsession").read_bytes()
        previous, local = sha(session), set()
        policy = json.loads(session)["payload"]["policy"]
        check(policy == ("kn.image_collection_journal.v1" if directory.name == "9" else "kn.image_irp_collection_journal.v2"), "explicit session policy")
        for segment in sorted((directory / "journal-segments").glob("*.knjseg")):
            raw = segment.read_bytes()
            record = json.loads(raw)
            body = record["payload"]
            check(record["payload_sha256"] == sha(encoded(body)) and body["previous_sha256"] == previous, "independent journal hash chain")
            check(all(path in local for path in body["transaction"]["requires"]), "dependencies belong to prior prefix")
            for member in body["transaction"]["members"]:
                path = member["path"]
                data = (original / path).read_bytes()
                check(member["sha256"] == sha(data) and int(member["bytes"]) == len(data), "exact original byte receipt")
                check(path not in members or members[path] == member, "global immutable path")
                members[path] = member
                content[sha(data)] = len(data)
                logical += len(data)
                references += 1
                if path not in local:
                    per_collection_bytes += len(data)
                local.add(path)
            previous = sha(raw)
        recovered = invoke("journal", directory, True)
        check(recovered["closed"] and recovered["head_sha256"] == previous, "typed or legacy final prefix and rebuilt index")
    inventory = invoke("store", original)
    for key, expected in {"closed_collections": 3, "member_references": references, "collection_path_bytes": per_collection_bytes,
                          "logical_reference_bytes": logical, "unique_path_bytes": sum(int(m["bytes"]) for m in members.values()),
                          "unique_content_bytes": sum(content.values()), "unattributed_files": 0}.items():
        check(int(inventory[key]) == expected, "independent global denominator: " + key)
    check(inventory["status"] == "verified" and inventory["membership_complete"], "mixed-policy complete inventory")
    for row in inventory["artifacts"]:
        expected = "failure_ledger_protected" if "session.v1" in row["artifact"]["schema"] else (
            "committed_reference_protected" if row["artifact"]["schema"] == "raw.bytes" else "committed_original_protected")
        check(row["retention"] == expected and row["verified"], "all committed artifact kinds protected")

    def copy(name):
        root = sandbox / name
        shutil.copytree(original, root)
        return root

    def rechain(root, mutate):
        directory = root / "collections/7"
        previous = sha((directory / "session.knsession").read_bytes())
        for number, path in enumerate(sorted((directory / "journal-segments").glob("*.knjseg")), 1):
            record = json.loads(path.read_bytes())
            record["payload"]["previous_sha256"] = previous
            mutate(number, record["payload"]["transaction"])
            record["payload_sha256"] = sha(encoded(record["payload"]))
            path.write_bytes(encoded(record))
            previous = sha(path.read_bytes())

    mutations = {
        "wrong-id": (1, lambda t: t.update(id="0" * 64)),
        "no-capture": (1, lambda t: t.update(members=[m for m in t["members"] if m["schema"] == "raw.bytes"])),
        "cross-kind": (1, lambda t: t.update(kind="image_reads", id="1")),
        "cross-collection": (1, lambda t: t["members"][0].update(path=t["members"][0]["path"].replace("irp-7-", "irp-8-"))),
        "traversal": (1, lambda t: t["members"][0].update(path="../" + t["members"][0]["path"])),
        "wrong-schema": (1, lambda t: t["members"][0].update(schema="kn.image_reads.v3")),
        "over-budget": (1, lambda t: t["members"][0].update(bytes=str(16 * 1024 * 1024 + 1))),
        "wrong-ledger-kind": (2, lambda t: t.update(kind="image_reads")),
        "closure-no-dependency": (3, lambda t: t.update(requires=[])),
    }
    for name, (number, mutate) in mutations.items():
        root = copy(name)
        rechain(root, lambda n, t: mutate(t) if n == number else None)
        r = invoke("journal", root / "collections/7")
        check(r["status"] != "verified_prefix" and int(r["committed_segments"]) == number - 1 and not r["closed"], "rehashed invalid transaction preserves only verified prefix: " + name)
        check(invoke("store", root)["membership_complete"] is False, "invalid root prevents global retirement")

    for stage, prefix, closed in (("irp_session", 0, False), ("irp_reference", 0, False), ("irp_capture", 0, False),
                                   ("irp_commit", 1, False), ("irp_ledger_file", 1, False), ("irp_ledger_commit", 2, False),
                                   ("irp_closure_file", 2, False), ("irp_closed", 3, True)):
        root = sandbox / ("stop-" + stage)
        process = subprocess.Popen([str(producer), "--produce-irp", str(root), "7", stage], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        observed = queue.Queue()
        threading.Thread(target=lambda: observed.put(process.stdout.readline()), daemon=True).start()
        try:
            check(observed.get(timeout=30).strip() == "[journal.stage] " + stage, "observed exact publication stage before kill")
            process.kill()
            process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
        recovered = invoke("journal", root / "collections/7", True)
        check(int(recovered["committed_segments"]) == prefix and recovered["closed"] == closed, "restart recovers exact observed prefix")
        stopped = invoke("store", root)
        check(stopped["membership_complete"] == closed, "open collection protects unattributed originals")
        for row in stopped["artifacts"]:
            if row["artifact"]["schema"] in ("kn.irp_capture_session.v1", "kn.image_read_session.v1"):
                check(row["retention"] == "failure_ledger_protected", "interrupted ledger remains protected")
            elif row["journal_references"] == "0":
                check(row["retention"] == "unresolved_membership_protected", "interrupted unpublished raw evidence protected")

    root = copy("gc")
    capture_raw = encoded({"schema": "kn.irp_capture.v2", "owned_orphan": True})
    reference_raw = b"owned orphan IRP reference"
    orphan_members = []
    for path, raw, schema in (("irp-99-" + sha(capture_raw) + ".knirp", capture_raw, "kn.irp_capture.v2"),
                              ("irp-reference-" + sha(reference_raw) + ".knblob", reference_raw, "raw.bytes")):
        (root / path).write_bytes(raw)
        orphan_members.append(dict(path=path, sha256=sha(raw), bytes=str(len(raw)), schema=schema))
    orphan_ledger = root / "irp-session-99.knirpledger"
    orphan_ledger.write_bytes(encoded({"schema": "kn.irp_capture_session.v1", "failed": "1"}))
    rows = {row["artifact"]["path"]: row for row in invoke("store", root)["artifacts"]}
    check(rows[orphan_ledger.name]["retention"] == "failure_ledger_protected", "uncommitted failure ledger protected")
    check(all(rows[m["path"]]["retention"] == "uncommitted_requires_policy" for m in orphan_members), "uncommitted typed originals require explicit selection")

    def policy(selected, name):
        path = root / (name + ".json")
        path.write_bytes(encoded(dict(schema="kn.evidence_gc_policy.v1", policy="kn.gc_explicit_uncommitted.v1", reason="owned test",
                                      minimum_age_seconds="0", byte_limit=str(128 * 1024 * 1024), members=sorted(selected, key=lambda m: m["path"]))))
        return path

    committed_capture = next(m for m in members.values() if m["schema"] == "kn.irp_capture.v2")
    for name, selected in (("committed", committed_capture), ("failure-ledger", rows[orphan_ledger.name]["artifact"])):
        check(invoke("gc", root, policy([selected], name), "123")["status"] != "completed", "GC rejects protected typed member")
        check((root / selected["path"]).exists(), "protected file retained")
    selected = policy(orphan_members, "selected")
    check(invoke("gc", root, selected)["status"] == "planned", "typed GC preflight")
    check(all((root / m["path"]).exists() for m in orphan_members), "preflight does not delete")
    applied = invoke("gc", root, selected, "456")
    check(applied["status"] == "completed" and int(applied["deleted_this_call"]) == 2, "explicit typed GC deletes only selected orphans")
    check(invoke("gc", root, selected, "456")["deleted_this_call"] == "0", "typed GC idempotent receipts")
    check(orphan_ledger.exists() and all(sha((root / m["path"]).read_bytes()) == m["sha256"] for m in members.values()), "all committed evidence and failure ledgers preserved")
    for name in ("irp-bad-name.knirp", "irp-unfinished.knirp.pending-owned", "unexpected.knirpledger"):
        isolated = copy("unknown-" + name)
        (isolated / name).write_bytes(capture_raw)
        r = invoke("store", isolated)
        check(r["artifact_inventory_complete"] is False and r["unverified_artifact_files"] == "1", "unknown reserved artifact protects inventory")
    print(f"[irp.journal] checks={CHECKS} stages=8 mutations={len(mutations)} fixtures={sandbox}")


if __name__ == "__main__":
    main()
