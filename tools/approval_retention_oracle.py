"""Exercise native GC against disposable copies of two real approval publications."""
import hashlib
import json
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading


def encoded(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def input_paths(payload):
    paths = {f'image-references/{payload["reference_sha256"]}.knblob',
             f'image-approvals/policy-{payload["policy_sha256"]}.knapproval',
             f'image-approvals/changes-{payload["manifest_sha256"]}.knchange'}
    if "inputs" in payload:
        paths.update(f'image-scope-inputs/{row["sha256"]}.knscopeblob' for row in payload["inputs"])
    else:
        paths.add(f'image-captures/capture-{payload["collection_id"]}-{payload["capture_sha256"]}.kncapture')
    return paths


def check_uncommitted_approvals(source, first_root, sandbox, *, init, inventory, invoke, check, journal, product=None):
    loose = sandbox / "loose-approvals"
    init(loose)
    first = first_root.relative_to(source).as_posix()
    second = first.replace("-7.", "-8.")
    originals = {p: (source / p).read_bytes() for p in (first, second)}
    docs = {p: json.loads(raw)["payload"] for p, raw in originals.items()}
    inputs = {p: input_paths(doc) for p, doc in docs.items()}
    for path in inputs[first] | inputs[second]:
        originals[path] = (source / path).read_bytes()
    source_paths = set(originals)
    unrelated = "image-reads/reads-71-1.knreads"
    payload = {"owned_fixture": True}
    originals[unrelated] = encoded(dict(schema="kn.image_reads.v1", payload_sha256=digest(encoded(payload)), payload=payload))
    spare_raw = b"owned unreferenced image input"
    spare_reference = f"image-references/{digest(spare_raw)}.knblob"
    originals[spare_reference] = spare_raw
    if "inputs" in docs[first]:
        side_blob = b"owned independent capture reference"
        originals[f"image-references/{digest(side_blob)}.knblob"] = side_blob
        payload = dict(reference_sha256=digest(side_blob))
        raw = encoded(dict(schema="kn.image_recipe.v1", recipe_sha256=digest(encoded(payload)), payload=payload))
        other_family = f"image-captures/capture-71-{digest(raw)}.kncapture"
    else:
        raw = encoded({"schema": "kn.image_reads.v3", "owned_fixture": True})
        other_family = f"image-scope-inputs/{digest(raw)}.knscopeblob"
    originals[other_family] = raw
    for path, raw in originals.items():
        destination = loose / path
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(raw)
    rule = sandbox / "loose-approval-inputs.gc-policy"

    def rows():
        snapshot = inventory(loose)
        check(snapshot["status"] == "verified" and snapshot["artifacts_sha256"] == digest(encoded(snapshot["artifacts"])),
              "independent canonical artifact inventory")
        return snapshot, {r["artifact"]["path"]: r for r in snapshot["artifacts"]}

    def policy(table, paths):
        rule.write_bytes(encoded(dict(schema="kn.evidence_gc_policy.v1", policy="kn.gc_explicit_uncommitted.v1",
            reason="owned approval retention control", minimum_age_seconds="0", byte_limit="67108864",
            members=[table[p]["artifact"] for p in sorted(paths)])))

    def collect(operation=None, code=0):
        cmd = ([product, "--offline", "!kmon", "gc", loose, rule] + (["/apply", operation] if operation else [])
               if product else [journal, "--gc", loose, rule, operation or "-"])
        return invoke(cmd, code)

    snapshot, table = rows()
    check(snapshot["uncommitted_approval_roots"] == "2" and snapshot["unreadable_approval_catalogs"] == "0" and
          snapshot["missing_approval_inputs"] == snapshot["mismatched_approval_inputs"] == "0", "both catalogs resolved")
    for path in inputs[first] | inputs[second]:
        expected = [dict(path=p, sha256=digest(originals[p]), input_matched=True) for p in sorted(inputs) if path in inputs[p]]
        row = table[path]
        check(row["uncommitted_approval_referrers"] == expected and row["retention"] == "uncommitted_approval_input_protected" and
              row["collections"] == [] and row["journal_references"] == "0", "exact sorted original referrers")
    check(all(table[p]["approval_catalog"] == "resolved" for p in inputs) and
          all(table[p]["retention"] == "uncommitted_requires_policy" for p in (unrelated, spare_reference, other_family)),
          "unreferenced originals stay eligible under readable catalogs")
    reference = next(p for p in inputs[first] if p.startswith("image-references/"))
    saved_inventory = sandbox / "loose-inventory.json"
    saved_inventory.write_bytes(encoded(snapshot))
    helper = Path(__file__).with_name("new-evidence-gc-policy.py")
    for path, allowed in ((reference, False), (unrelated, True)):
        generated = sandbox / ("generated-" + str(allowed) + ".gc-policy")
        result = subprocess.run([sys.executable, "-B", str(helper), "--inventory", str(saved_inventory), "--path", path,
                                 "--reason", "owned approval input", "--output", str(generated)], capture_output=True, timeout=30)
        check(result.returncode == (0 if allowed else 1) and generated.exists() == allowed, "operator policy helper honors input retention")
    policy(table, {first, unrelated} | inputs[first])
    for operation in (None, "50"):
        denied = collect(operation, 1)
        issues = {r["artifact"]["path"]: r["issue"] for r in denied["entries"]}
        check(denied["status"] == "denied" and denied["deleted_this_call"] == "0" and
              all(issues[p] == "uncommitted_approval_input_protected" for p in inputs[first]), "all-member preflight")
    check(not (loose / "retention/50/operation.kngc").exists() and
          all((loose / p).read_bytes() == raw for p, raw in originals.items()), "denied operation preserves every original")

    mixed = sandbox / "committed-and-loose"
    init(mixed)
    shutil.copytree(source / "collections/7", mixed / "collections/7")
    for path in source_paths:
        (mixed / path).parent.mkdir(exist_ok=True)
        (mixed / path).write_bytes(originals[path])
    ledger = next((source / "image-approvals").glob("*session-7.*ledger"))
    shutil.copyfile(ledger, mixed / "image-approvals" / ledger.name)
    mixed_inventory = inventory(mixed)
    shared = next(row for row in mixed_inventory["artifacts"] if row["artifact"]["path"] == reference)
    check(mixed_inventory["closed_collections"] == "1" and shared["collections"] == ["7"] and
          shared["retention"] == "committed_reference_protected" and
          shared["uncommitted_approval_referrers"] == [dict(path=second, sha256=digest(originals[second]), input_matched=True)],
          "journal ownership and independently published approval both retained")
    (loose / reference).unlink()
    snapshot, table = rows()
    check(snapshot["missing_approval_inputs"] == "2" and all(table[p]["approval_catalog"] == "inputs_incomplete" for p in inputs) and
          all(table[p]["retention"] == "uncommitted_approval_input_protected" for p in inputs[first] - {reference}),
          "missing shared input counted once per root, siblings protected")
    (loose / reference).write_bytes(originals[reference])
    if "inputs" in docs[first]:
        changed = json.loads(originals[first])
        entry = changed["payload"]["inputs"][0]
        entry["bytes"] = str(int(entry["bytes"]) + 1)
        changed["publication_sha256"] = digest(encoded(changed["payload"]))
        (loose / first).write_bytes(encoded(changed))
        snapshot, table = rows()
        altered = table[f'image-scope-inputs/{entry["sha256"]}.knscopeblob']
        check(snapshot["mismatched_approval_inputs"] == "1" and table[first]["approval_catalog"] == "inputs_incomplete" and
              altered["retention"] == "uncommitted_approval_input_protected" and
              not next(r for r in altered["uncommitted_approval_referrers"] if r["path"] == first)["input_matched"],
              "mismatched declared length keeps physical input protected")
        aliased = json.loads(originals[first])
        declarations = aliased["payload"]["inputs"]
        source_entry = next(row for row in declarations if row["logical_path"].startswith("image-reads/"))
        alias = dict(source_entry, logical_path="image-reads/reads-99-99." + source_entry["logical_path"].split(".")[-1])
        declarations.append(alias)
        for fault in ("consistent", "conflicting-length", "invalid-name"):
            if fault == "conflicting-length":
                alias["bytes"] = str(int(source_entry["bytes"]) + 1)
            if fault == "invalid-name":
                alias.update(bytes=source_entry["bytes"], logical_path="../input")
            declarations.sort(key=lambda row: row["logical_path"])
            aliased["publication_sha256"] = digest(encoded(aliased["payload"]))
            (loose / first).write_bytes(encoded(aliased))
            snapshot, table = rows()
            if fault == "consistent":
                row = table[f'image-scope-inputs/{alias["sha256"]}.knscopeblob']
                check(table[first]["approval_catalog"] == "resolved" and
                      sum(ref["path"] == first for ref in row["uncommitted_approval_referrers"]) == 1,
                      "logical aliases count one physical input per root")
            else:
                check(snapshot["unreadable_approval_catalogs"] == "1" and table[first]["approval_catalog"] == "unreadable" and
                      table[spare_reference]["retention"] == "unresolved_approval_input_protected", "invalid logical input catalog")
        (loose / first).write_bytes(originals[first])

    policy(table, [second])
    check(collect("51")["status"] == "completed" and not (loose / second).exists(), "explicitly withdraw one loose root")
    _, table = rows()
    check([r["path"] for r in table[reference]["uncommitted_approval_referrers"]] == [first], "surviving root keeps shared original")
    for field in ("publication_sha256", "collection_id", "contradictory-reference"):
        changed = json.loads(originals[first])
        if field == "publication_sha256":
            changed[field] = "0" * 64
        else:
            if field == "collection_id":
                changed["payload"][field] = "99"
            else:
                changed["payload"]["reference_sha256"] = digest(spare_raw)
            changed["publication_sha256"] = digest(encoded(changed["payload"]))
        (loose / first).write_bytes(encoded(changed))
        snapshot, table = rows()
        check(snapshot["unreadable_approval_catalogs"] == "1" and table[first]["approval_catalog"] == "unreadable" and
              all(table[p]["retention"] == "unresolved_approval_input_protected" for p in inputs[first]) and
              table[spare_reference]["retention"] == "unresolved_approval_input_protected" and
              all(table[p]["retention"] == "uncommitted_requires_policy" for p in (unrelated, other_family)),
              "unreadable catalog protects possible input families")
        policy(table, [reference])
        check(collect("52", 1)["entries"][0]["issue"] == "unresolved_approval_input_protected", "native apply guards unreadable catalog")
    policy(table, [first])
    check(collect("53")["status"] == "completed", "explicit withdrawal of unreadable approval root")
    snapshot, table = rows()
    check(snapshot["uncommitted_approval_roots"] == "0", "last approval withdrawn")
    if "capture_sha256" in docs[first]:
        captures = {p for p in source_paths if p.endswith(".kncapture")}
        check(table[reference]["retention"] == "uncommitted_image_input_protected" and
              {r["path"] for r in table[reference]["uncommitted_image_referrers"]} == captures,
              "both direct captures independently retain their reference")
        policy(table, captures)
        check(collect("55")["status"] == "completed", "withdraw direct captures under their own exact policy")
        _, table = rows()
    check(table[reference]["retention"] == "uncommitted_requires_policy", "original eligible after all referring roots are withdrawn")

    # Stop at the durable intent. A publication arriving before retry must protect the same physical file.
    policy(table, [reference])
    actor = subprocess.Popen(list(map(str, [journal, "--gc", loose, rule, "54", "gc_intent"])),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    reader = threading.Thread(target=lambda: lines.put(actor.stdout.readline()), daemon=True)
    reader.start()
    try:
        check(lines.get(timeout=30).strip() == "[journal.stage] gc_intent", "observed native durable intent before interruption")
    finally:
        if actor.poll() is None:
            actor.kill()
        actor.communicate(timeout=15)
        reader.join(timeout=5)
    intent = loose / "retention/54/1.kngcintent"
    saved_intent = intent.read_bytes()
    (loose / first).write_bytes(originals[first])
    denied = collect("54", 1)
    check(denied["status"] == "denied" and denied["entries"][0]["issue"] == "uncommitted_approval_input_protected" and
          denied["deleted_this_call"] == "0" and intent.read_bytes() == saved_intent and
          not (loose / "retention/54/1.kngcreceipt").exists() and (loose / reference).read_bytes() == originals[reference],
          "resumed operation rechecks newly published dependency before deletion")
    check(all((source / p).read_bytes() == originals[p] for p in source_paths), "source evidence intact")
