"""Check image retention against original producer files using the native store and GC."""
import argparse
from collections import defaultdict
from pathlib import Path
import json
import queue
import subprocess
import tempfile
import threading

from approval_retention_oracle import digest, encoded


SWEEP = "image-sweeps/sweep-7-1.knsweep"
PROTECTED = "uncommitted_image_input_protected"
UNRESOLVED = "unresolved_image_input_protected"
ELIGIBLE = "uncommitted_requires_policy"


def unwrapped(raw):
    doc = json.loads(raw)
    if "publication_sha256" in doc:
        return doc["payload"]["artifact"]
    return doc


def ref_path(sha256):
    return f"image-references/{sha256}.knblob"


def fixture(source):
    files = {SWEEP: (source / SWEEP).read_bytes()}
    payload = unwrapped(files[SWEEP])["payload"]
    expected = defaultdict(dict)
    for row in payload["slices"]:
        prefix = f'image-reads/reads-{payload["sweep"]["collection_id"]}-{row["read_set_id"]}'
        if row["reference_written"]:
            key = row["reference_sha256"]
            expected[ref_path(key)][SWEEP] = (key, "file_bytes")
        for flag, suffix, key in (("raw_written", ".knreads", "raw_payload_sha256"), ("recipe_written", ".knslice", "recipe_sha256")):
            if row[flag]:
                expected[prefix + suffix][SWEEP] = (row[key], "unwrapped_payload")
    for path in list(expected):
        if not path.startswith("image-reads/"):
            continue
        files[path] = (source / path).read_bytes()
        child = unwrapped(files[path])["payload"]
        if path.endswith(".knslice"):
            key = child["reference_sha256"]
        else:
            ref = child.get("reference", {})
            if ref.get("persistence") != "committed":
                continue
            key = ref["sha256"]
        expected[ref_path(key)][path] = (key, "file_bytes")
    for path in expected:
        if path not in files:
            files[path] = (source / path).read_bytes()
    return files, expected


def write(root, path, data):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--journal-exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--product", type=Path)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    journal = args.journal_exe.resolve()
    cli = [args.product.resolve(), "--offline", "!kmon"] if args.product else []
    checks = 0

    def check(value, message):
        nonlocal checks
        if not value:
            raise AssertionError(message)
        checks += 1

    def run(command, code=0):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=60)
        check(result.returncode == code, (command[1:4], result.returncode, result.stdout[:900], result.stderr[:200]))
        return json.loads(result.stdout)

    def inventory(root):
        snap = run([*cli, "store", root, "/artifacts"] if cli else [journal, "--store", root])
        rows = snap["artifacts"]
        check(snap["status"] == "verified" and snap["artifacts_sha256"] == digest(encoded(rows)), "canonical inventory digest")
        return snap, {r["artifact"]["path"]: r for r in rows}

    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="im-") as tmp:
        sandbox = Path(tmp).resolve()
        rule = sandbox / "policy.json"

        def init(name):
            root = sandbox / name
            if cli:
                check(run([*cli, "init-store", root, "/acl-only"])["status"] == "ready", "initialize owned store")
            else:
                root.mkdir()
            return root

        def policy(rows, paths):
            members = [rows[path]["artifact"] for path in sorted(paths)]
            rule.write_bytes(encoded(dict(schema="kn.evidence_gc_policy.v1", policy="kn.gc_explicit_uncommitted.v1",
                reason="owned image retention control", minimum_age_seconds="0", byte_limit="67108864", members=members)))

        def gc(root, operation=None, code=0):
            command = ([*cli, "gc", root, rule] + (["/apply", operation] if operation else []) if cli
                       else [journal, "--gc", root, rule, operation or "-"])
            result = run(command, code)
            check(result["uncommitted_dependents_resolved"] is False, "all-family coverage remains bounded")
            return result

        spare = b"owned unrelated IRP reference"
        independent = f"irp-reference-{digest(spare)}.knblob"
        cases = ("sweep_boundary_modified", "scope-claim-publications/sweep_clean", "scope-claim-publications/sweep_raw_lost")
        for i, case in enumerate(cases):
            source = args.fixtures / case
            originals, expected = fixture(source)
            root = init(f"real-{i}")
            for path, raw in originals.items():
                write(root, path, raw)
            write(root, independent, spare)
            snap, rows = inventory(root)
            roots = {p for p in originals if not p.endswith(".knblob")}
            check(snap["uncommitted_image_roots"] == str(len(roots)) and
                  all(snap[n] == "0" for n in ("missing_image_inputs", "mismatched_image_inputs", "unreadable_image_catalogs")),
                  "written flags and original digests resolve")
            check(all(rows[p]["image_catalog"] == "resolved" for p in roots), "every loose root decoded")
            for path, parents in expected.items():
                refs = [dict(path=p, sha256=digest(originals[p]), expected_sha256=h, digest_basis=b, input_matched=True)
                        for p, (h, b) in sorted(parents.items())]
                check(rows[path]["retention"] == PROTECTED and rows[path]["uncommitted_image_referrers"] == refs, path)
                for parent, (h, basis) in parents.items():
                    if basis == "unwrapped_payload":
                        check(h == digest(encoded(unwrapped(originals[path])["payload"])) and h != digest(originals[path]),
                              "sweep identifies payload inside original envelope")
            policy(rows, set(originals) | {independent})
            for operation in (None, "11"):
                result = gc(root, operation, 1)
                check(result["status"] == "denied" and result["deleted_this_call"] == "0" and
                      all(e["issue"] == PROTECTED for e in result["entries"] if e["artifact"]["path"] in expected),
                      "mixed selection is denied before mutation")
            check(not (root / "retention/11/operation.kngc").exists() and
                  all((root / p).read_bytes() == b for p, b in originals.items()) and (root / independent).read_bytes() == spare,
                  "no operation or partial deletion")
            if cli and i != 2:
                check(run([*cli, "replay-image", root / SWEEP])["status"] == "replayed", "original sweep still replays")
            if i == 2:
                missing_raw = next(r for r in unwrapped(originals[SWEEP])["payload"]["slices"] if not r["raw_written"])
                absent = f'image-reads/reads-7-{missing_raw["read_set_id"]}.knreads'
                check(absent not in rows and snap["missing_image_inputs"] == "0", "producer-declared raw loss is not a missing input")
            managed = init(f"published-{i}")
            for path, raw_bytes in originals.items():
                write(managed, path, raw_bytes)
            subprocess.run([str(journal), "--commit-published", str(managed), "none", "3" if i else "1"],
                           capture_output=True, check=True, timeout=60)
            collection = managed / "collections/7"
            recovered = run([*cli, "journal", collection] if cli else [journal, "--recover", collection])
            check(recovered["closed"] and recovered["committed_sweep_paths"] == [SWEEP] and
                  all((managed / p).read_bytes() == data for p, data in originals.items()),
                  "genuine bare, wrapped and loss-declared files survive native commit and recovery")
            if i == 0:
                ref = next(p for p in expected if p.endswith(".knblob"))
                raw = next(p for p in expected if p.endswith(".knreads"))
                (root / ref).unlink()
                snap, rows = inventory(root)
                check(snap["missing_image_inputs"] == str(len(expected[ref])) and
                      all(rows[p]["image_catalog"] == "inputs_incomplete" for p in expected[ref]) and
                      all(rows[p]["retention"] == PROTECTED for p in expected if p != ref), "missing PE, surviving siblings retained")
                write(root, ref, originals[ref])
                changed = json.loads(originals[raw])
                changed["payload"]["reference"]["bytes"] = len(originals[ref]) + 1
                changed["payload_sha256"] = digest(encoded(changed["payload"]))
                write(root, raw, encoded(changed))
                snap, rows = inventory(root)
                check(snap["mismatched_image_inputs"] == "2" and rows[SWEEP]["image_catalog"] == rows[raw]["image_catalog"] == "inputs_incomplete"
                      and not rows[raw]["uncommitted_image_referrers"][0]["input_matched"] and rows[raw]["retention"] == PROTECTED
                      and not next(r for r in rows[ref]["uncommitted_image_referrers"] if r["path"] == raw)["input_matched"],
                      "child reseal and declared PE length checked independently")
                write(root, raw, originals[raw])
                _, rows = inventory(root)
                policy(rows, [SWEEP])
                check(gc(root, "12")["deleted_this_call"] == "1", "explicitly withdraw loose sweep alone")
                _, rows = inventory(root)
                check(rows[ref]["retention"] == PROTECTED and len(rows[ref]["uncommitted_image_referrers"]) == len(expected[ref]) - 1,
                      "surviving read and slice retain their PE")
                policy(rows, [raw])
                actor = subprocess.Popen(list(map(str, [journal, "--gc", root, rule, "13", "gc_intent"])), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                lines = queue.Queue()
                reader = threading.Thread(target=lambda: lines.put(actor.stdout.readline()), daemon=True)
                reader.start()
                try:
                    check(lines.get(timeout=30).strip() == "[journal.stage] gc_intent", "observed durable deletion intent")
                finally:
                    if actor.poll() is None:
                        actor.kill()
                    actor.communicate(timeout=15)
                    reader.join(timeout=5)
                intent = root / "retention/13/1.kngcintent"
                saved = intent.read_bytes()
                write(root, SWEEP, originals[SWEEP])
                denied = gc(root, "13", 1)
                check(denied["entries"][0]["issue"] == PROTECTED and denied["deleted_this_call"] == "0" and
                      not (root / "retention/13/1.kngcreceipt").exists() and intent.read_bytes() == saved and
                      (root / raw).read_bytes() == originals[raw], "retry respects sweep published after durable intent")
            if i == 1:
                changed = json.loads(originals[SWEEP])
                changed["publication_sha256"] = "0" * 64
                write(root, SWEEP, encoded(changed))
                foreign = "image-reads/reads-99-1.knreads"
                write(root, foreign, next(b for p, b in originals.items() if p.endswith(".knreads")))
                snap, rows = inventory(root)
                check(snap["unreadable_image_catalogs"] == "1" and rows[SWEEP]["image_catalog"] == "unreadable" and
                      rows[foreign]["retention"] == UNRESOLVED and rows[independent]["retention"] == ELIGIBLE,
                      "unreadable wrapper protects candidate families")
                policy(rows, [SWEEP, foreign, independent])
                check(gc(root, "14", 1)["deleted_this_call"] == "0" and (root / foreign).exists(), "uncertain sweep blocks mixed deletion")
                (root / SWEEP).unlink()
                wrong = "image-sweeps/sweep-8-1.knsweep"
                write(root, wrong, originals[SWEEP])
                snap, rows = inventory(root)
                check(snap["unreadable_image_catalogs"] == "1" and rows[wrong]["image_catalog"] == "unreadable",
                      "genuine manifest bound to wrong filename cannot resolve")
            check(all((source / p).read_bytes() == original for p, original in originals.items()), "source files preserved")

        root = init("states")
        key = digest(spare)
        write(root, ref_path(key), spare)
        for n, (version, state) in enumerate(((1, None), (3, None), (2, "failed"), (3, "not_captured"), (2, "not_attempted")), 1):
            payload = {} if state is None else {"reference": {"sha256": key, "persistence": state}}
            write(root, f"image-reads/reads-7-{n}.knreads", encoded(dict(schema=f"kn.image_reads.v{version}",
                  payload_sha256=digest(encoded(payload)), payload=payload)))
        snap, rows = inventory(root)
        check(snap["uncommitted_image_roots"] == "5" and snap["unreadable_image_catalogs"] == "0" and
              rows[ref_path(key)]["retention"] == ELIGIBLE, "unwritten references do not create dependencies")
        for payload in ({}, {"reference": {"sha256": key, "persistence": "pending"}}):
            write(root, "image-reads/reads-7-6.knreads", encoded(dict(schema="kn.image_reads.v2", payload_sha256=digest(encoded(payload)), payload=payload)))
            snap, rows = inventory(root)
            check(snap["unreadable_image_catalogs"] == "1" and rows[ref_path(key)]["retention"] == UNRESOLVED,
                  "unknown or absent v2 declaration protects possible PE")

        root = init("mixed")
        subprocess.run([str(journal), "--produce-collection", str(root), "7"], capture_output=True, check=True, timeout=60)
        doc = json.loads((root / SWEEP).read_bytes())
        doc["payload"]["sweep"]["sweep_id"] = "7-2"
        doc["manifest_sha256"] = digest(encoded(doc["payload"]))
        loose = "image-sweeps/sweep-7-2.knsweep"
        write(root, loose, encoded(doc))
        snap, rows = inventory(root)
        check(snap["closed_collections"] == snap["uncommitted_image_roots"] == "1" and rows[loose]["image_catalog"] == "resolved",
              "loose sweep resolves inputs in closed collection")
        _, expected = fixture(root)
        for path in expected:
            row = rows[path]
            check(row["collections"] == ["7"] and row["retention"].startswith("committed_") and
                  row["uncommitted_image_referrers"][0]["path"] == loose and row["uncommitted_image_referrers"][0]["input_matched"],
                  "verified prior original keeps journal ownership and loose referrer")
    print(f"[image.dependencies] checks={checks} mode={'cli' if cli else 'harness'}")


if __name__ == "__main__":
    main()
