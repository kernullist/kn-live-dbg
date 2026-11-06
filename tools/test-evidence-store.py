"""Independent image-store membership, byte accounting and publisher-barrier oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import shutil
import subprocess
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    exe, producer = args.exe.resolve(), (args.producer or args.exe).resolve()
    sandbox = args.fixtures.resolve() / ("store-" + uuid.uuid4().hex)
    sandbox.mkdir(parents=True)

    def run(root, details=True):
        command = [str(exe), "--offline", "!kmon", "store", str(root)] if args.cli else [str(exe), "--store", str(root)]
        if args.cli and details:
            command += ["/artifacts", "/json"]
        p = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=45)
        lines = [x for x in p.stdout.splitlines() if x.startswith('{"schema":"kn.evidence_store_inventory.v1"')]
        check(len(lines) == 1, f"one inventory: rc={p.returncode}, stderr={p.stderr[-300:]}")
        r = json.loads(lines[0])
        check(p.returncode == (0 if r["status"] == "verified" else 1), "exit status")
        for key in ("deletion_authorized", "disk_allocation_established", "target_coverage_established", "collector_authenticated", "power_loss_durability_established"):
            check(r[key] is False, f"no unsupported claim: {key}")
        check(r["scope"] == "image_collection_namespace" and r["coordination"] == "participating_publishers", "explicit namespace and coordination")
        check(int(r["ended_tick"]) >= int(r["started_tick"]), "observation interval")
        if r["catalog_sha256"]:
            check(r["catalog_sha256"] == sha(encoded(r["collections"])), "root receipt hash")
        if r["artifacts_included"] and r["artifacts_sha256"] and r["artifact_rows_omitted"] == "0":
            check(r["artifacts_sha256"] == sha(encoded(r["artifacts"])), "canonical artifact receipt hash")
        return r

    original = sandbox / "original"
    for collection in ("7", "8"):
        p = subprocess.run([str(producer), "--produce-collection", str(original), collection], capture_output=True, timeout=30)
        check(p.returncode == 0, f"publish original collection {collection}")

    def copy(name):
        root = sandbox / name
        shutil.copytree(original, root)
        return root

    r = run(original)
    check(r["status"] == "verified" and r["catalog_complete"] and r["membership_complete"] and r["artifact_inventory_complete"], "two closed roots")
    members, contents, owners, refs, logical, collection_bytes, read_bytes, segments = {}, {}, {}, {}, 0, 0, 0, 0
    for collection in sorted((original / "collections").iterdir()):
        session = (collection / "session.knsession").read_bytes()
        previous, local = sha(session), set()
        read_bytes += len(session)
        for path in sorted((collection / "journal-segments").glob("*.knjseg")):
            raw = path.read_bytes()
            envelope = json.loads(raw)
            record = envelope["payload"]
            check(sha(encoded(record)) == envelope["payload_sha256"] and record["previous_sha256"] == previous, "independent linked record")
            previous = sha(raw)
            read_bytes += len(raw)
            segments += 1
            for member in record["transaction"]["members"]:
                name = member["path"]
                raw_member = (original / name).read_bytes()
                check(sha(raw_member) == member["sha256"] and len(raw_member) == int(member["bytes"]), "physical file identity")
                members[name] = member
                contents[member["sha256"]] = len(raw_member)
                logical += len(raw_member)
                refs[name] = refs.get(name, 0) + 1
                owners.setdefault(name, set()).add(collection.name)
                if name not in local:
                    collection_bytes += len(raw_member)
                    local.add(name)
    unique_bytes = sum(int(m["bytes"]) for m in members.values())
    expected = {"collections_observed": 2, "closed_collections": 2, "open_collections": 0, "unresolved_collections": 0,
                "committed_segments": segments, "member_references": sum(refs.values()),
                "collection_path_references": sum(len(v) for v in owners.values()), "logical_reference_bytes": logical,
                "collection_path_bytes": collection_bytes, "unique_path_bytes": unique_bytes, "unique_content_bytes": sum(contents.values()),
                "unattributed_files": 0, "unverified_artifact_files": 0, "observed_artifact_files": len(members),
                "read_bytes": read_bytes + unique_bytes}
    for key, value in expected.items():
        check(r[key] == str(value), f"independent exact aggregate: {key}")
    for row in r["artifacts"]:
        name = row["artifact"]["path"]
        check(row["artifact"] == members[name] and row["verified"], "exact inventory member")
        check(row["collections"] == sorted(owners[name]) and row["journal_references"] == str(refs[name]), "cross-collection reachability")
        check(row["retention"] in ("committed_reference_protected", "committed_original_protected", "failure_ledger_protected"), "committed originals retained")
    check(logical > unique_bytes > sum(contents.values()), "reference multiplicity, named-file bytes and content dedup differ")
    check(logical > collection_bytes, "repeated reference within each collection counted separately")
    check(run(str(original) + "\\")["artifacts_sha256"] == r["artifacts_sha256"], "trailing separator invariant")
    if args.cli:
        summary = run(original, False)
        check(summary["artifacts"] == [] and summary["artifact_rows_emitted"] == "0" and summary["artifact_rows_omitted"] == str(len(members)), "explicit detail omission")
        for tail in ([], [str(original), "/unknown"], [str(original), "/json", "/json"],
                     [str(original), "/artifacts", "/artifacts"], [str(original), "/index"]):
            invalid = subprocess.run([str(exe), "--offline", "!kmon", "store", *tail], capture_output=True, timeout=30)
            check(invalid.returncode == 2 and b'kn.evidence_store_inventory.v1' not in invalid.stdout, "invalid store grammar")

    orphan = "image-reads/reads-99-1.knreads"
    for name, mutation in (("closed-orphan", None), ("open-root", "open"), ("invalid-root", "invalid"), ("corrupt-shared-reference", "corrupt")):
        root = copy(name)
        (root / orphan).write_bytes(b'{"schema":"kn.image_reads.v3","fixture":"uncommitted"}')
        if mutation == "open":
            (root / "collections/8/journal-segments/00000000000000000004.knjseg").unlink()
        elif mutation == "invalid":
            (root / "collections/not-an-id").mkdir()
        elif mutation == "corrupt":
            next((root / "image-references").iterdir()).write_bytes(b"corrupt")
        result = run(root)
        row = next(x for x in result["artifacts"] if x["artifact"]["path"] == orphan)
        check(row["verified"] and row["collections"] == [] and row["journal_references"] == "0", "unattributed file is not a committed member")
        check(row["retention"] == ("uncommitted_requires_policy" if mutation is None else "unresolved_membership_protected"), "unknown roots prevent orphan retention eligibility")
        check(result["membership_complete"] == (mutation is None), "membership closure gate")
        if mutation == "corrupt":
            check(result["unresolved_collections"] == "2" and result["committed_segments"] == "0", "shared corruption invalidates both roots")
        # The returned report owns no leases and supplies no deletion authority.
        (root / orphan).write_bytes(b"changed after the snapshot")
        check(run(root)["artifact_inventory_complete"] is False, "a later call revalidates changed original bytes")

    for name in ("reads-99-1.knreads.pending-owned", "unrecognized.bin", "session-bad.knreadledger"):
        root = copy(name.replace(".", "-"))
        (root / "image-reads" / name).write_bytes(b'{"schema":"kn.image_read_session.v1"}')
        result = run(root)
        check(result["status"] == "partial" and result["unverified_artifact_files"] == "1", "unknown/pending/invalid ID stays unverified")
    root = copy("case-only")
    file = root / "image-reads/reads-7-1.knreads"
    file.rename(file.with_name(file.name.upper()))
    check(run(root)["artifacts_sha256"] == r["artifacts_sha256"], "Windows case-only filename change")
    root = copy("bad-lock")
    (root / "store.knstorelock").write_bytes(b"preserve invalid lock")
    check(run(root)["issue"] == "store_lock_invalid" and (root / "store.knstorelock").read_bytes() == b"preserve invalid lock", "lock collision preserved")
    empty = sandbox / "empty"
    empty.mkdir()
    check(run(empty)["status"] == "verified", "empty observed namespace")
    ledger_root = sandbox / "uncommitted-failure-ledger"
    (ledger_root / "image-reads").mkdir(parents=True)
    (ledger_root / "image-reads/session-99.knreadledger").write_bytes(b'{"schema":"kn.image_read_session.v1","failed":3}')
    result = run(ledger_root)
    check(result["membership_complete"] and result["unattributed_files"] == "1" and
          result["artifacts"][0]["retention"] == "failure_ledger_protected", "uncommitted failure denominator remains protected without a journal root")
    absent = sandbox / "absent"
    check(run(absent)["status"] == "unavailable" and not absent.exists(), "inspection cannot create a missing root")
    # A redirected root/namespace/collection must never borrow another store's files.
    for location in ("root", "collections", "image-reads", "collections/7"):
        root = sandbox / ("junction-" + location.replace("/", "-"))
        root.mkdir()
        link = root / location if location != "root" else root / "alias"
        link.parent.mkdir(parents=True, exist_ok=True)
        target = original if location == "root" else original / location
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        check(made.returncode == 0, "owned junction creation")
        try:
            result = run(link if location == "root" else root)
            check(result["status"] != "verified", "reparse namespace cannot establish complete store")
        finally:
            # rmdir unlinks this junction itself, with no traversal of the target.
            check(link.parent.resolve().is_relative_to(sandbox), "junction cleanup parent remains owned")
            link.rmdir()
        check(run(original)["artifacts_sha256"] == r["artifacts_sha256"], "junction target originals preserved")
    long_root = sandbox / ("x" * 100) / ("y" * 100)
    # Python on this host also needs extended syntax to create the fixture.
    # The product still receives the original unprefixed long local path.
    shutil.copytree(original, Path("\\\\?\\" + str(long_root)))
    check(run(long_root)["artifacts_sha256"] == r["artifacts_sha256"], "extended-path store and temporary names")
    over = sandbox / "over-catalog-budget"
    (over / "collections").mkdir(parents=True)
    for i in range(1025):
        (over / "collections" / str(i)).mkdir()
    result = run(over)
    check(result["issue"] == "store_catalog_budget_exhausted" and result["collections_observed"] == "1024" and not result["catalog_complete"], "bounded catalog reports observed prefix")

    # Observe the exact owned-lease stage, never infer interleaving from a sleep.
    for mode in ("shared", "exclusive"):
        root = copy("hold-" + mode)
        child = subprocess.Popen([str(producer), "--store-hold", str(root), mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: lines.put(child.stdout.readline()), daemon=True)
        reader.start()
        try:
            check(lines.get(timeout=15).strip() == "[journal.stage] store_held" and child.poll() is None, "observed held store lease")
            check(run(root)["issue"] == "store_busy", "inventory rejects active lease")
            publish = subprocess.run([str(producer), "--produce-collection", str(root), "9"], capture_output=True, timeout=30)
            check(publish.returncode == (0 if mode == "shared" else 1), "shared publishers coexist; exclusive inventory denies publication")
            if mode == "exclusive":
                check(not (root / "collections/9").exists(), "denied writer creates no collection")
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=15)
            reader.join(timeout=5)
        check(child.poll() is not None and not reader.is_alive(), "owned child reaped")
        check(run(root)["status"] == "verified", "process termination releases barrier")
    print(f"[store.oracle] checks={CHECKS} children_remaining=0 mode={'cli' if args.cli else 'harness'} fixtures={sandbox}")


if __name__ == "__main__":
    main()
