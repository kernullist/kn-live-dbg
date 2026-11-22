"""Independent image-store membership, byte accounting and publisher-barrier oracle."""
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--large-detail", action="store_true", help="exercise the 16 Mi code-unit limit using 24,576 owned capture files")
    parser.add_argument("--previous-cli", type=Path, help="compare the earlier detail output on the same large store")
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
        check(r["scope"] == "image_and_irp_collection_namespace" and r["coordination"] == "participating_publishers", "explicit namespace and coordination")
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
                     [str(original), "/artifacts", "/artifacts"], [str(original), "/index"], [str(original), "/limit", "1"],
                     [str(original), "/cursor", "token"], [str(original), "/artifacts", "/limit", "0"],
                     [str(original), "/artifacts", "/limit", "4097"], [str(original), "/artifacts", "/limit", "01"],
                     [str(original), "/artifacts", "/limit", "1", "/limit", "1"], [str(original), "/artifacts", "/cursor"]):
            invalid = subprocess.run([str(exe), "--offline", "!kmon", "store", *tail], capture_output=True, timeout=30)
            check(invalid.returncode == 2 and b'kn.evidence_store_inventory.v1' not in invalid.stdout, "invalid store grammar")

    def page(root, limit, cursor="", code=0):
        command = [exe, "--offline", "!kmon", "store", root, "/artifacts"] if args.cli else [exe, "--store", root]
        result = subprocess.run(command + ["/limit", str(limit)] + (["/cursor", cursor] if cursor else []), capture_output=True, timeout=45)
        check(result.returncode == code, ("page exit", code, result.returncode, result.stderr[:200]))
        return json.loads(result.stdout)

    def token(offset):
        position = str(offset)
        basis = "|".join(("kn.store_artifact_cursor.v1", r["catalog_sha256"], r["artifacts_sha256"], position))
        return "kns1." + position + "." + sha(basis.encode())

    collected, cursor = [], ""
    while len(collected) < len(members):
        limit = 1 if not collected else 3
        selected = page(original, limit, cursor)
        offset = len(collected)
        collected.extend(selected["artifacts"])
        remaining = len(members) - len(collected)
        check(selected["artifact_row_offset"] == str(offset) and selected["artifact_rows_remaining"] == str(remaining) and
              selected["artifact_rows_omitted"] == str(len(members) - len(selected["artifacts"])) and 0 < len(selected["artifacts"]) <= limit,
              "independent page offset, earlier omissions and remaining rows")
        cursor = selected["next_artifact_cursor"]
        check(selected["artifact_page_status"] == ("more" if remaining else "complete") and cursor == (token(len(collected)) if remaining else ""),
              "next offset bound to both complete digests")
    check(collected == r["artifacts"] and sha(encoded(collected)) == r["artifacts_sha256"], "ordered pages recover the full canonical row digest")
    for bad in ("invalid", token(0), token(len(members)), token(1).replace(".1.", ".2.")):
        refused = page(original, 2, bad, 1)
        check(refused["status"] == "verified" and refused["artifact_page_status"] == "cursor_mismatch" and
              not refused["artifacts"] and not refused["next_artifact_cursor"], "reject malformed, terminal and edited positions")
    root = copy("paged-catalog")
    pending = root / "collections/7/journal-segments/held.knjseg.pending-test"
    pending.write_bytes(b"owned pending publication")
    stale = page(root, 2, token(1), 1)
    check(stale["catalog_sha256"] != r["catalog_sha256"] and stale["artifacts_sha256"] == r["artifacts_sha256"] and
          stale["artifact_page_status"] == "cursor_mismatch" and not stale["artifacts"], "catalog-only change rejects continuation")
    pending.unlink()
    orphan = "image-reads/reads-99-1.knreads"
    (root / orphan).write_bytes(b'{"schema":"kn.image_reads.v3","fixture":"page"}')
    stale = page(root, 2, token(1), 1)
    check(stale["catalog_sha256"] == r["catalog_sha256"] and stale["artifacts_sha256"] != r["artifacts_sha256"] and
          stale["artifact_page_status"] == "cursor_mismatch" and not stale["artifacts"], "artifact-only change rejects continuation")
    inventory = sandbox / "page.json"
    policy = sandbox / "paged-policy.json"
    helper = [sys.executable, "-B", Path(__file__).with_name("new-evidence-gc-policy.py"), "--inventory", inventory,
              "--path", orphan, "--reason", "owned page test", "--minimum-age-seconds", "0", "--output", policy]
    inventory.write_bytes(encoded(stale))
    check(subprocess.run(helper, capture_output=True).returncode == 1 and not policy.exists(), "rejected page cannot prepare a policy")
    retire_helper = [sys.executable, "-B", Path(__file__).with_name("new-evidence-gc-policy.py"), "--inventory", inventory,
                     "--retire-collection", "7", "--reason", "owned page test", "--output", policy]
    check(subprocess.run(retire_helper, capture_output=True).returncode == 1 and not policy.exists(),
          "stale cursor cannot prepare a retirement even when the requested catalog row is present")
    current = page(root, 1)
    inventory.write_bytes(encoded(current))
    check(subprocess.run(helper, capture_output=True).returncode == 1 and not policy.exists(), "a valid page cannot select an omitted file")
    while current["artifacts"][0]["artifact"]["path"] != orphan:
        check(bool(current["next_artifact_cursor"]), "eligible path appears on a subsequent page")
        current = page(root, 1, current["next_artifact_cursor"])
    inventory.write_bytes(encoded(current))
    check(int(current["artifact_row_offset"]) > 0 and subprocess.run(helper, capture_output=True).returncode == 0, "prepare GC from a later page")
    preflight = [exe, "--offline", "!kmon", "gc", root, policy] if args.cli else [exe, "--gc", root, policy, "-"]
    checked = subprocess.run(preflight, capture_output=True, timeout=45)
    check(checked.returncode == 0 and json.loads(checked.stdout)["status"] == "planned" and (root / orphan).exists(), "normal GC revalidates the selection")
    extra = root / "image-reads/미확인.entry"
    extra.write_bytes(b"owned partial scan")
    partial = page(root, 4096, code=1)
    check(partial["artifact_page_status"] == "incomplete_inventory" and not partial["next_artifact_cursor"] and
          any(row["artifact"]["path"].endswith(extra.name) for row in partial["artifacts"]), "partial first page preserves Unicode evidence")
    partial = page(root, 1, token(1), 1)
    check(partial["artifact_page_status"] == "incomplete_inventory" and not partial["artifacts"] and not partial["next_artifact_cursor"],
          "partial scan withholds continuation")

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
    if args.large_detail or args.previous_cli:
        wide = sandbox / "detail-cap"
        captures = wide / "image-captures"
        captures.mkdir(parents=True)
        (wide / "image-references").mkdir()
        reference = b"owned inventory paging reference"
        digest = sha(reference)
        reference_path = f"image-references/{digest}.knblob"
        (wide / reference_path).write_bytes(reference)
        payload = dict(reference_sha256=digest)
        original = encoded(dict(schema="kn.image_recipe.v1", recipe_sha256=sha(encoded(payload)), payload=payload))
        physical = sha(original)
        paths = [f"image-captures/capture-{i}-{physical}.kncapture" for i in range(10000, 34576)]
        for relative in paths:
            (wide / relative).write_bytes(original)

        def wide_page(program, product, cursor=""):
            command = [program, "--offline", "!kmon", "store", wide, "/artifacts"] if product else [program, "--store", wide]
            output = subprocess.run(command + (["/cursor", cursor] if cursor else []), capture_output=True, timeout=180)
            report = json.loads(output.stdout)
            check(output.returncode == 0 and report["status"] == "verified", ("wide inventory", report["issue"]))
            return report

        if args.previous_cli:
            old = wide_page(args.previous_cli.resolve(), True)
            check(old["artifact_rows_omitted"] == "1" and not old.get("next_artifact_cursor"), "preceding CLI omits the PE row at the detail cap")
            del old
        first = wide_page(exe, args.cli)
        tail = wide_page(exe, args.cli, first["next_artifact_cursor"])
        check(first["artifact_page_status"] == "more" and first["artifact_rows_remaining"] == "1" and
              [v["artifact"]["path"] for v in first["artifacts"]] == paths, "all on-disk capture paths in the first page")
        check(tail["artifact_page_status"] == "complete" and not tail["next_artifact_cursor"] and
              tail["artifact_row_offset"] == str(len(paths)) and len(tail["artifacts"]) == 1, "terminal page contains the previously omitted row")
        pe = tail["artifacts"][0]
        check(pe["artifact"]["path"] == reference_path and
              [v["path"] for v in pe["uncommitted_image_referrers"]] == paths and
              all(v["sha256"] == physical and v["input_matched"] for v in pe["uncommitted_image_referrers"]), "every captured PE referrer survives paging")
        full = encoded(first["artifacts"] + tail["artifacts"])
        check(len(full) > 16 * 1024 * 1024 and sha(full) == first["artifacts_sha256"] == tail["artifacts_sha256"], "reconstructed wide inventory digest")
        print(f"[store.detail-cap] rows={len(paths) + 1} first={len(paths)} tail=1 canonical_units={len(full)}")
    print(f"[store.oracle] checks={CHECKS} children_remaining=0 mode={'cli' if args.cli else 'harness'} fixtures={sandbox}")


if __name__ == "__main__":
    main()
