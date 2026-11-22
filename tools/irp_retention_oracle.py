"""Compare native IRP reference retention to the capture's original PE bytes."""
import json
import queue
import subprocess
import threading

from approval_retention_oracle import digest, encoded


def check_irp_retention(sandbox, raw, wrapped, *, journal, product, invoke, replay, check):
    cli = [product, "--offline", "!kmon"] if product else []
    rule = sandbox / "irp.gc-policy"
    cap = json.loads(raw)
    hashes = {p["payload"]["image_sha256"] for p in cap["schemas"]}
    check(len(hashes) == 1, "three original schemas agree on PE")
    key = next(iter(hashes))
    ref = f"irp-reference-{key}.knblob"
    original = (sandbox / ref).read_bytes()
    check(digest(original) == key and int(cap["reference_captured_bytes"]) == len(original), "independent reference identity")

    def init(name):
        root = sandbox / name
        if cli:
            check(json.loads(invoke([*cli, "init-store", root, "/acl-only"]).stdout)["status"] == "ready", "owned store")
        else:
            root.mkdir()
        return root

    def store(root):
        command = [*cli, "store", root, "/artifacts"] if cli else [journal, "--store", root]
        result = json.loads(invoke(command).stdout)
        check(result["status"] == "verified" and result["artifacts_sha256"] == digest(encoded(result["artifacts"])), "physical inventory hash")
        return result, {r["artifact"]["path"]: r for r in result["artifacts"]}

    def put(root, n, data):
        name = f"irp-{n}-{digest(data)}.knirp"
        (root / name).write_bytes(data)
        return name

    def select(rows, paths):
        rule.write_bytes(encoded(dict(schema="kn.evidence_gc_policy.v1", policy="kn.gc_explicit_uncommitted.v1",
            reason="owned IRP replay reference", minimum_age_seconds="0", byte_limit="67108864",
            members=[rows[p]["artifact"] for p in sorted(paths)])))

    def gc(root, op=None, code=0):
        cmd = ([*cli, "gc", root, rule] + (["/apply", op] if op else []) if cli else [journal, "--gc", root, rule, op or "-"])
        return json.loads(invoke(cmd, code).stdout)

    root = init("loose-irps")
    (root / ref).write_bytes(original)
    a, b = put(root, 7, raw), put(root, 8, wrapped)
    image = f"image-references/{key}.knblob"
    (root / image).parent.mkdir()
    (root / image).write_bytes(original)
    snap, rows = store(root)
    def referrer(path, data, committed=False):
        return dict(path=path, sha256=digest(data), expected_bytes=str(len(original)), root_committed=committed, input_matched=True)
    check(snap["irp_capture_roots"] == "2" and snap["unreadable_irp_catalogs"] == snap["missing_irp_references"] ==
          snap["mismatched_irp_references"] == "0" and rows[a]["irp_catalog"] == rows[b]["irp_catalog"] == "resolved", "two genuine capture declarations")
    check(rows[ref]["irp_referrers"] == [referrer(a, raw), referrer(b, wrapped)] and rows[image]["retention"] == "uncommitted_requires_policy",
          "sorted referrers and exact namespace")
    select(rows, [a, b, ref, image])
    for op in (None, "41"):
        denied = gc(root, op, 1)
        check(denied["status"] == "denied" and denied["deleted_this_call"] == "0" and
              next(e for e in denied["entries"] if e["artifact"]["path"] == ref)["issue"] == "irp_replay_reference_protected", "all-member preflight")
    check(not (root / "retention/41/operation.kngc").exists() and (root / ref).read_bytes() == original, "no durable mutation")
    replay(root / a, status="not_recorded")
    replay(root / b)
    (root / ref).unlink()
    snap, rows = store(root)
    check(snap["missing_irp_references"] == "2" and rows[a]["irp_catalog"] == rows[b]["irp_catalog"] == "inputs_incomplete",
          "one missing physical PE counted per referring capture")
    (root / ref).write_bytes(original)
    changed = json.loads(raw)
    changed["reference_captured_bytes"] = str(len(original) + 1)
    c = put(root, 9, encoded(changed))
    snap, rows = store(root)
    check(snap["mismatched_irp_references"] == "1" and rows[c]["irp_catalog"] == "inputs_incomplete" and
          rows[ref]["irp_referrers"][-1]["expected_bytes"] == str(len(original) + 1) and
          not rows[ref]["irp_referrers"][-1]["input_matched"] and rows[ref]["retention"] == "irp_replay_reference_protected",
          "wrong capture length keeps the original")
    select(rows, [a, b, c])
    check(gc(root, "42")["deleted_this_call"] == "3", "withdraw roots in a separate operation")
    for fault in ("seal", "claim", "package", "disagree", "unknown-size", "legacy"):
        doc = json.loads(wrapped if fault in ("seal", "claim") else raw)
        if fault == "seal": doc["publication_sha256"] = "0" * 64
        if fault == "claim":
            doc["payload"]["recorded_claim"]["capture_sha256"] = "a" * 64
            doc["publication_sha256"] = digest(encoded(doc["payload"]))
        if fault == "package": doc["schemas"][1]["package_sha256"] = "a" * 64
        if fault == "disagree":
            pkg = doc["schemas"][2]
            pkg["payload"]["image_sha256"] = "b" * 64
            pkg["package_sha256"] = digest(encoded(pkg["payload"]))
        if fault == "unknown-size": doc["reference_captured_bytes"] = "67108865"
        if fault == "legacy": doc["schema"] = "kn.irp_capture.v1"
        path = put(root, 9, encoded(doc))
        snap, rows = store(root)
        check(snap["unreadable_irp_catalogs"] == "1" and rows[path]["irp_catalog"] == "unreadable" and
              rows[ref]["retention"] == "unresolved_irp_reference_protected" and rows[image]["retention"] == "uncommitted_requires_policy", fault)
        select(rows, [ref])
        check(gc(root, None, 1)["entries"][0]["issue"] == "unresolved_irp_reference_protected", "native uncertainty denial")
        (root / path).unlink()
    changed["reference_captured_bytes"] = "0"
    absent = put(root, 9, encoded(changed))
    snap, rows = store(root)
    check(rows[absent]["irp_catalog"] == "not_captured" and rows[ref]["retention"] == "uncommitted_requires_policy", "explicit zero has no external PE")
    select(rows, [ref])
    actor = subprocess.Popen(list(map(str, [journal, "--gc", root, rule, "43", "gc_intent"])), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    worker = threading.Thread(target=lambda: lines.put(actor.stdout.readline()), daemon=True)
    worker.start()
    try:
        check(lines.get(timeout=30).strip() == "[journal.stage] gc_intent", "observed durable intent")
    finally:
        if actor.poll() is None:
            actor.kill()
        actor.communicate(timeout=15)
        worker.join(timeout=5)
    intent = root / "retention/43/1.kngcintent"
    saved = intent.read_bytes()
    put(root, 8, wrapped)
    denied = gc(root, "43", 1)
    check(denied["deleted_this_call"] == "0" and denied["entries"][0]["issue"] == "irp_replay_reference_protected" and
          (root / ref).read_bytes() == original and intent.read_bytes() == saved and not (root / "retention/43/1.kngcreceipt").exists(),
          "capture published after intent protects pending deletion")

    for bundled in (False, True):
        mixed = init("committed-with-pe" if bundled else "committed-without-pe")
        path = put(mixed, 7, wrapped)
        if bundled: (mixed / ref).write_bytes(original)
        invoke([journal, "--commit-published-irp", mixed, "none", "4"])
        if not bundled:
            snap, _ = store(mixed)
            check(snap["closed_collections"] == snap["missing_irp_references"] == "1", "original closed membership remains recoverable")
            (mixed / ref).write_bytes(original)
        loose = put(mixed, 8, raw)
        snap, rows = store(mixed)
        check(rows[ref]["irp_referrers"] == [referrer(path, wrapped, True), referrer(loose, raw)] and
              rows[ref]["retention"] == ("committed_reference_protected" if bundled else "irp_replay_reference_protected") and
              rows[ref]["collections"] == (["7"] if bundled else []), "capture commitment and reference membership are independent")
        select(rows, [ref])
        check(gc(mixed, "44", 1)["deleted_this_call"] == "0" and (mixed / ref).read_bytes() == original, "committed capture retains its PE")
    check((sandbox / ref).read_bytes() == original, "source reference intact")
