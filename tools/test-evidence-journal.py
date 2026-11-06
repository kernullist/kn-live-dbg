"""Independent physical-byte, prefix, restart and observed-stage interruption oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import shutil
import subprocess
import threading


CHECKS = 0


def check(condition, message):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def envelope(path, schema):
    raw = path.read_bytes()
    doc = json.loads(raw)
    check(doc["schema"] == schema, f"schema: {path.name}")
    check(sha(encoded(doc["payload"])) == doc["payload_sha256"], f"payload checksum: {path.name}")
    check(encoded(doc) == raw, f"canonical segment: {path.name}")
    return doc["payload"], sha(raw)


def run(exe, collection, index=False, cli=False):
    args = [str(exe), "--offline", "!kmon", "journal", str(collection)] if cli else [str(exe), "--recover", str(collection)]
    if index:
        args.append("/index" if cli else "--index")
    process = subprocess.run(args, capture_output=True, text=True, timeout=30)
    lines = [line for line in process.stdout.splitlines() if line.startswith('{"schema":"kn.evidence_journal_recovery.v1"')]
    check(len(lines) == 1, f"one recovery result: rc={process.returncode}, stderr={process.stderr[-300:]}")
    result = json.loads(lines[0])
    check(process.returncode == (0 if result["status"] == "verified_prefix" and result["index_status"] != "failed" else 1), "status exit code")
    for key in ("orphan_files_included", "target_coverage_established", "replay_established", "collector_authenticated", "power_loss_durability_established"):
        check(result[key] is False, f"bounded publication claim: {key}")
    return result


def oracle(root, result, index=False):
    collection = root / "collections/7"
    session, previous = envelope(collection / "session.knsession", "kn.evidence_session.v1")
    check(session["collection_id"] == "7", "original collection id")
    check(result["session_sha256"] == previous, "session physical hash")
    members, contents, references, logical, roots, chunks = {}, {}, 0, 0, [], []
    closed = False
    for sequence in range(1, int(result["committed_segments"]) + 1):
        record, digest = envelope(collection / "journal-segments" / f"{sequence:020}.knjseg", "kn.evidence_journal_segment.v1")
        check(record["collection_id"] == "7" and int(record["sequence"]) == sequence, "exact sequence and collection")
        check(record["previous_sha256"] == previous, "physical hash chain")
        transaction = record["transaction"]
        check(all(path in members for path in transaction["requires"]), "dependencies precede transaction")
        for member in transaction["members"]:
            path = member["path"]
            check(path not in members or members[path] == member, "immutable member identity")
            data = (root / path).read_bytes()
            check(len(data) == int(member["bytes"]) and sha(data) == member["sha256"], "exact physical member bytes")
            if member["schema"] != "raw.bytes":
                check(json.loads(data)["schema"] == member["schema"], "original member schema")
            members[path] = member
            contents[member["sha256"]] = len(data)
            logical += len(data)
            references += 1
            if member["schema"] == "kn.image_sweep.v1":
                roots.append(path)
        if index:
            chunk, _ = envelope(collection / "indexes/chunks" / f"{digest}.knjindex", "kn.evidence_journal_index_chunk.v1")
            check(chunk["transaction"] == transaction and chunk["segment_sha256"] == digest, "derived chunk uses exact committed transaction")
        closed = transaction["kind"] == "closure"
        check(not closed or sequence == int(result["committed_segments"]), "closure is terminal")
        previous = digest
        chunks.append(digest)
    expected = {"head_sha256": previous, "member_references": str(references), "unique_paths": str(len(members)),
                "logical_bytes": str(logical), "unique_content_bytes": str(sum(contents.values())),
                "duplicate_reference_bytes": str(logical - sum(contents.values())), "committed_sweep_paths": roots}
    for key, value in expected.items():
        check(result[key] == value, f"independent denominator: {key}")
    if result["status"] == "verified_prefix":
        check(result["closed"] == closed and result["tail_unknown"] != closed, "closure and unknown tail remain distinct")
    if index:
        head, _ = envelope(collection / "indexes/heads" / f"{previous}.knjindex", "kn.evidence_journal_index.v1")
        check(head["chunks"] == chunks and head["head_sha256"] == previous and head["closed"] == closed, "derived immutable head")


def rechain(root, mutate):
    collection = root / "collections/7"
    previous = sha((collection / "session.knsession").read_bytes())
    for i, path in enumerate(sorted((collection / "journal-segments").glob("*.knjseg")), 1):
        doc = json.loads(path.read_bytes())
        doc["payload"]["previous_sha256"] = previous
        mutate(i, doc)
        doc["payload_sha256"] = sha(encoded(doc["payload"]))
        path.write_bytes(encoded(doc))
        previous = sha(path.read_bytes())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--producer", type=Path)
    options = parser.parse_args()
    exe, fixture = options.exe.resolve(), options.fixtures.resolve()
    producer = (options.producer or exe).resolve()
    sandbox = fixture.with_name(fixture.name + ("-cli-oracle" if options.cli else "-oracle"))
    sandbox.mkdir()

    def recover(root, index=False):
        return run(exe, root / "collections/7", index, options.cli)

    def copy(name):
        target = sandbox / name
        shutil.copytree(fixture, target)
        return target

    def remove_tree(path):
        # Never recurse outside this invocation's owned fixture directory.
        check(path.resolve().is_relative_to(sandbox), "cleanup stays inside owned fixtures")
        shutil.rmtree(path)

    original = recover(fixture, True)
    oracle(fixture, original, True)
    check(original["closed"] and original["committed_segments"] == "4", "completed fixture")
    trailing = run(exe, str(fixture / "collections/7") + "\\", False, options.cli)
    check(trailing["head_sha256"] == original["head_sha256"], "trailing directory separator")

    deep = sandbox / ("owned-long-" + "d" * 130) / ("nested-" + "e" * 50)
    extended_deep = Path("\\\\?\\" + str(deep))
    shutil.copytree(fixture, extended_deep)
    # Rebuild under a path where the final file, not just the temporary name,
    # exceeds MAX_PATH. Original members and their physical hashes stay fixed.
    check((deep / "collections/7/indexes").resolve().is_relative_to(sandbox), "long cleanup stays inside owned fixtures")
    shutil.rmtree(extended_deep / "collections/7/indexes")
    deep_result = recover(deep, True)
    check(deep_result["index_status"] == "ready" and deep_result["index_created"] == "5", "long local path index publication")
    oracle(extended_deep, deep_result, True)
    checks = [
        ("missing-first-raw", "image-reads/reads-7-1.knreads", 0),
        ("missing-second-raw", "image-reads/reads-7-2.knreads", 1),
        ("missing-sweep", "image-sweeps/sweep-7-1.knsweep", 2),
        ("missing-ledger", "image-reads/session-7.knreadledger", 3),
        ("segment-gap", "collections/7/journal-segments/00000000000000000002.knjseg", 1),
    ]
    for name, path, prefix in checks:
        root = copy(name)
        (root / path).unlink()
        result = recover(root)
        check(int(result["committed_segments"]) == prefix and not result["can_resume"], name)
        oracle(root, result)

    for name, path, prefix in [
        ("corrupt-member", "image-reads/reads-7-2.knslice", 1),
        ("corrupt-segment", "collections/7/journal-segments/00000000000000000002.knjseg", 1),
        ("corrupt-session", "collections/7/session.knsession", 0),
    ]:
        root = copy(name)
        target = root / path
        data = bytearray(target.read_bytes())
        data[-2] ^= 1
        target.write_bytes(data)
        result = recover(root)
        check(int(result["committed_segments"]) == prefix and result["status"] != "verified_prefix", name)

    mutations = [
        ("wrong-segment-schema", 2, lambda d: d.update(schema="kn.evidence_journal_segment.v9"), 1),
        ("wrong-sequence", 2, lambda d: d["payload"].update(sequence="3"), 1),
        ("wrong-previous", 2, lambda d: d["payload"].update(previous_sha256="0" * 64), 1),
        ("unknown-field", 2, lambda d: d["payload"].update(unexpected=True), 1),
        ("duplicate-transaction", 2, lambda d: d["payload"]["transaction"].update(id="1"), 1),
        ("uncommitted-dependency", 1, lambda d: d["payload"]["transaction"].update(requires=["image-sweeps/sweep-7-1.knsweep"]), 0),
        ("duplicate-member", 1, lambda d: d["payload"]["transaction"]["members"].append(d["payload"]["transaction"]["members"][0]), 0),
        ("parent-escape", 1, lambda d: d["payload"]["transaction"]["members"][0].update(path="../outside.knreads"), 0),
        ("absolute-member", 1, lambda d: d["payload"]["transaction"]["members"][0].update(path="C:/outside.knreads"), 0),
        ("alternate-stream", 1, lambda d: d["payload"]["transaction"]["members"][0].update(path="image-reads/reads-7-1.knreads:stream"), 0),
        ("cross-collection", 1, lambda d: d["payload"]["transaction"]["members"][0].update(path="image-reads/reads-8-1.knreads"), 0),
        ("unsupported-member-schema", 1, lambda d: d["payload"]["transaction"]["members"][0].update(schema="kn.image_reads.v99"), 0),
        ("overlarge-member", 1, lambda d: d["payload"]["transaction"]["members"][0].update(bytes=str(65 * 1024 * 1024)), 0),
    ]
    for name, number, change, prefix in mutations:
        root = copy(name)
        rechain(root, lambda i, d: change(d) if i == number else None)
        result = recover(root)
        check(int(result["committed_segments"]) == prefix and not result["can_resume"], name)
        oracle(root, result)

    root = copy("rehash-wrong-member-schema")
    member_path = root / "image-reads/reads-7-1.knreads"
    member = json.loads(member_path.read_bytes())
    member["schema"] = "kn.image_reads.v9"
    member_path.write_bytes(encoded(member))

    def change_schema(i, doc):
        if i == 1:
            for m in doc["payload"]["transaction"]["members"]:
                if m["path"] == "image-reads/reads-7-1.knreads":
                    m["sha256"], m["bytes"] = sha(member_path.read_bytes()), str(member_path.stat().st_size)
    rechain(root, change_schema)
    result = recover(root)
    check(result["committed_segments"] == "0" and result["issue"] == "member_schema_mismatch", "exact file digest does not bypass schema")

    root = copy("missing-terminal-record")
    (root / "collections/7/journal-segments/00000000000000000004.knjseg").unlink()
    result = recover(root)
    check(result["committed_segments"] == "3" and result["tail_unknown"] and result["can_resume"], "unanchored missing tail is explicitly unknown")
    oracle(root, result)

    root = copy("records-after-closure")
    last = root / "collections/7/journal-segments/00000000000000000004.knjseg"
    (last.parent / "00000000000000000005.knjseg").write_bytes(last.read_bytes())
    result = recover(root)
    check(result["committed_segments"] == "4" and result["status"] == "incomplete_prefix" and
          not result["closed"] and result["tail_unknown"] and not result["can_resume"], "extra suffix invalidates collection closure")
    oracle(root, result)

    root = copy("interrupted-index")
    chunks = sorted((root / "collections/7/indexes/chunks").glob("*.knjindex"))
    for path in chunks[2:]:
        path.unlink()
    remove_tree(root / "collections/7/indexes/heads")
    result = recover(root, True)
    check(result["index_created"] == "3" and result["index_reused"] == "2", "index resumes exact existing chunks")
    oracle(root, result, True)

    root = copy("corrupt-derived-index")
    chunk = next((root / "collections/7/indexes/chunks").glob("*.knjindex"))
    chunk.write_bytes(b'{}')
    check(recover(root)["status"] == "verified_prefix", "index is not source of collection membership")
    result = recover(root, True)
    check(result["index_status"] == "failed" and result["closed"] and chunk.read_bytes() == b'{}', "invalid index is reported without overwrite")

    root = copy("pending-and-orphan")
    pending = root / "collections/7/journal-segments/00000000000000000005.knjseg.pending-owned"
    pending.write_bytes(b'{incomplete')
    result = recover(root)
    check(result["pending_segment_files"] == "1" and result["unique_paths"] == "7" and pending.exists(), "pending bytes excluded and preserved")

    # A directory junction is available without symlink privilege on Windows.
    root = copy("reparse-members")
    external = sandbox / "owned-external-members"
    shutil.copytree(root / "image-reads", external)
    remove_tree(root / "image-reads")
    junction = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(root / "image-reads"), str(external)], capture_output=True, text=True, timeout=10)
    check(junction.returncode == 0, "owned junction setup")
    result = recover(root)
    check(result["committed_segments"] == "0" and not result["can_resume"], "member parent reparse denied")
    # Remove only the junction itself; never walk into its target.
    (root / "image-reads").rmdir()
    check((external / "reads-7-1.knreads").exists(), "junction target survives cleanup")

    stages = {"session": 0, "raw": 0, "readset": 0, "recipe": 0, "journal_before_index": 1,
              "index": 1, "sweep_file": 1, "sweep_commit": 2, "ledger_file": 2, "closure": 3}
    children = []
    for stage, prefix in stages.items():
        root = sandbox / ("interrupt-" + stage)
        child = subprocess.Popen([str(producer), "--produce", str(root), stage], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(child)
        lines = queue.Queue()
        reader = threading.Thread(target=lambda p=child, q=lines: q.put(p.stdout.readline()), daemon=True)
        reader.start()
        try:
            line = lines.get(timeout=30)
            check(line.strip() == "[journal.stage] " + stage and child.poll() is None, f"observed child stage: {stage}")
            child.kill()
            child.wait(timeout=10)
            reader.join(timeout=5)
            check(not reader.is_alive() and child.poll() is not None, "observed actor terminated and reaped")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            child.stdin.close()
            child.stdout.close()
            stderr = child.stderr.read()
            child.stderr.close()
        check(not stderr.strip(), f"child has no hidden failure: {stage}")
        if stage == "journal_before_index":
            (root / "collections/7/indexes").unlink()
        result = recover(root, True)
        check(result["committed_segments"] == str(prefix) and result["closed"] == (stage == "closure"), f"exact interrupted prefix: {stage}")
        oracle(root, result, True)
        resumed = subprocess.run([str(producer), "--resume", str(root)], capture_output=True, text=True, timeout=30)
        check(resumed.returncode == (1 if stage == "closure" else 0), f"restart admission: {stage}")
        after = recover(root)
        check(int(after["committed_segments"]) == prefix + (0 if stage == "closure" else 1), f"resume at next committed offset: {stage}")
        oracle(root, after)
    check(all(child.poll() is not None for child in children), "no owned interruption child remains")
    print(f"[journal.oracle] checks={CHECKS} interrupted_stages={len(stages)} children_remaining=0 mode={'cli' if options.cli else 'harness'}")


if __name__ == "__main__":
    main()
