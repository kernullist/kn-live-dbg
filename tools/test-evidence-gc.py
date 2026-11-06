"""Owned-fixture GC oracle: explicit policy, exact records, interruption and replacement safety."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import stat
import subprocess
import sys
import threading
import time
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


def physical_identity(path):
    class FileIdInfo(ctypes.Structure):
        _fields_ = [("volume", ctypes.c_uint64), ("identifier", ctypes.c_ubyte * 16)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.GetFileTime.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    kernel.GetFileTime.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x80, 7, None, 3, 0x02200000, None)
    check(handle != ctypes.c_void_p(-1).value, "independent FILE_READ_ATTRIBUTES handle")
    try:
        identifier, creation = FileIdInfo(), wintypes.FILETIME()
        # FileIdInfo is ordinal 18 in SDK 10.0.26100.0 minwinbase.h.
        check(kernel.GetFileInformationByHandleEx(handle, 18, ctypes.byref(identifier), ctypes.sizeof(identifier)), "independent full 128-bit file ID")
        check(kernel.GetFileTime(handle, ctypes.byref(creation), None, None), "independent creation time")
        return f"{identifier.volume}:{bytes(identifier.identifier).hex()}:{creation.dwHighDateTime << 32 | creation.dwLowDateTime}"
    finally:
        kernel.CloseHandle(handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    exe, producer = args.exe.resolve(), (args.producer or args.exe).resolve()
    sandbox = args.fixtures.resolve() / ("gc-" + uuid.uuid4().hex)
    sandbox.mkdir(parents=True)
    original = sandbox / "original"
    made = subprocess.run([str(producer), "--produce-collection", str(original), "7"], capture_output=True, timeout=30)
    check(made.returncode == 0, "owned committed fixture")
    baseline = {p.relative_to(original): sha(p.read_bytes()) for p in original.rglob("*") if p.is_file()}

    def owned(root):
        check(root.resolve().is_relative_to(sandbox), "all GC calls stay inside this invocation's owned fixtures")

    def command(root, policy, operation=""):
        if args.cli:
            return [str(exe), "--offline", "!kmon", "gc", str(root), str(policy), *(["/apply", operation] if operation else []), "/json"]
        return [str(exe), "--gc", str(root), str(policy), operation or "-"]

    def run(root, policy, operation=""):
        owned(root)
        p = subprocess.run(command(root, policy, operation), capture_output=True, text=True, encoding="utf-8", timeout=45)
        lines = [x for x in p.stdout.splitlines() if x.startswith('{"schema":"kn.evidence_gc_result.v1"')]
        check(len(lines) == 1, f"one GC result: rc={p.returncode}, stderr={p.stderr[-300:]}")
        r = json.loads(lines[0])
        check(p.returncode == (0 if r["status"] in ("planned", "completed") else 1), "status exit contract")
        for key in ("deletion_authority_after_return", "disk_reclamation_established", "collector_authenticated", "power_loss_durability_established",
                    "current_path_absence_established", "uncommitted_dependents_resolved"):
            check(r[key] is False, f"bounded claim: {key}")
        check(r["scope"] == "explicit_uncommitted_image_artifacts" and r["coordination"] == "participating_publishers", "explicit GC scope")
        return r

    def case(name):
        root = sandbox / name
        shutil.copytree(original, root)
        raw = encoded({"schema": "kn.image_reads.v3", "fixture": "explicitly selected unpublished owned file"})
        blob = b"owned non-executable reference orphan"
        artifacts = [("image-reads/reads-99-1.knreads", raw, "kn.image_reads.v3"),
                     ("image-references/" + sha(blob) + ".knblob", blob, "raw.bytes")]
        members = []
        for path, data, schema in artifacts:
            (root / path).write_bytes(data)
            members.append({"path": path, "sha256": sha(data), "bytes": str(len(data)), "schema": schema})
        policy = {"schema": "kn.evidence_gc_policy.v1", "policy": "kn.gc_explicit_uncommitted.v1",
                  "reason": "discard explicitly selected obsolete owned test artifacts", "minimum_age_seconds": "0",
                  "byte_limit": str(128 * 1024 * 1024), "members": sorted(members, key=lambda x: x["path"])}
        path = sandbox / (name + ".policy.json")
        path.write_bytes(encoded(policy))
        return root, path, policy

    def intact(root):
        for path, digest in baseline.items():
            check((root / path).is_file() and sha((root / path).read_bytes()) == digest, "committed original/index/session remains exact")

    def record(path, schema):
        raw = path.read_bytes()
        doc = json.loads(raw)
        check(doc["schema"] == schema and doc["payload_sha256"] == sha(encoded(doc["payload"])) and raw == encoded(doc), "canonical checksum-bound audit record")
        return doc["payload"], sha(raw)

    def receipts(root, policy_path, policy, result):
        folder = root / "retention" / result["operation_id"]
        operation, digest = record(folder / "operation.kngc", "kn.evidence_gc_operation.v1")
        check(result["operation_sha256"] == digest and operation["policy_sha256"] == sha(policy_path.read_bytes()), "operation binds exact policy file")
        check(operation["policy"] == policy and operation["root_identity"] == result["root_identity"], "reason, selection and physical root bound")
        for i, member in enumerate(policy["members"], 1):
            intent, intent_hash = record(folder / f"{i}.kngcintent", "kn.evidence_gc_intent.v1")
            receipt, receipt_hash = record(folder / f"{i}.kngcreceipt", "kn.evidence_gc_receipt.v1")
            check(intent["operation_sha256"] == digest == receipt["operation_sha256"], "audit links operation")
            check(intent["artifact"] == member == receipt["artifact"] and intent["ordinal"] == str(i) == receipt["ordinal"], "exact policy member and order")
            check(intent["file_identity"] == receipt["file_identity"] and intent["last_write_filetime"] == receipt["last_write_filetime"], "original file identity survives deletion")
            check(receipt["intent_sha256"] == intent_hash and result["entries"][i - 1]["receipt_sha256"] == receipt_hash, "returned outcome resolves durable intent and receipt")

    root, path, policy = case("complete")
    original_selected = {m["path"]: (root / m["path"]).read_bytes() for m in policy["members"]}
    store_command = [str(exe), "--offline", "!kmon", "store", str(root), "/artifacts"] if args.cli else [str(exe), "--store", str(root)]
    inventory = subprocess.run(store_command, capture_output=True, text=True, encoding="utf-8", timeout=30)
    check(inventory.returncode == 0, "actual store inventory feeds policy preparation")
    snapshot = json.loads(next(line for line in inventory.stdout.splitlines() if line.startswith('{"schema":"kn.evidence_store_inventory.v1"')))
    snapshot_path = sandbox / "inventory.json"
    snapshot_path.write_bytes(encoded(snapshot))
    generated = sandbox / "generated.policy.json"
    builder = [sys.executable, str(Path(__file__).with_name("new-evidence-gc-policy.py")), "--inventory", str(snapshot_path),
               "--reason", policy["reason"], "--minimum-age-seconds", "0", "--output", str(generated)]
    for m in policy["members"]:
        builder += ["--path", m["path"]]
    check(subprocess.run(builder, capture_output=True, timeout=30).returncode == 0 and generated.read_bytes() == path.read_bytes(),
          "builder emits independently specified canonical explicit policy")
    check(subprocess.run(builder, capture_output=True, timeout=30).returncode == 1 and generated.read_bytes() == path.read_bytes(),
          "builder cannot overwrite existing policy")
    rejected_output = sandbox / "rejected.policy.json"
    bad_builder = [str(rejected_output) if value == str(generated) else value for value in builder]
    snapshot["membership_complete"] = "false"
    snapshot_path.write_bytes(encoded(snapshot))
    check(subprocess.run(bad_builder, capture_output=True, timeout=30).returncode == 1 and not rejected_output.exists(),
          "builder rejects a string in a completeness flag")
    snapshot["membership_complete"] = True
    snapshot_path.write_bytes(encoded(snapshot))
    path = generated
    planned = run(root, path)
    check(planned["root_identity"] == physical_identity(root), "physical root identity uses all 128 bits")
    for entry in planned["entries"]:
        check(entry["file_identity"] == physical_identity(root / entry["artifact"]["path"]), "candidate identity matches independent OS query")
    check(planned["status"] == "planned" and not planned["apply"] and planned["deleted_this_call"] == "0" and
          not (root / "retention").exists(), "dry run has no deletion/audit operation")
    check(all(e["state"] == "eligible" for e in planned["entries"]), "exact explicit members eligible")
    done = run(root, path, "1")
    check(done["status"] == "completed" and done["deleted_this_call"] == "2" and
          done["deleted_named_bytes_this_call"] == str(sum(int(m["bytes"]) for m in policy["members"])), "actual named-entry deletion counters")
    check(all(not (root / m["path"]).exists() for m in policy["members"]), "only selected paths removed")
    receipts(root, path, policy, done)
    intact(root)
    retry = run(root, path, "1")
    check(retry["status"] == "completed" and retry["deleted_this_call"] == "0" and all(e["reused_receipt"] for e in retry["entries"]), "same operation returns historical receipts without repeated deletion")
    restored = root / policy["members"][0]["path"]
    restored.write_bytes(original_selected[policy["members"][0]["path"]])
    historical = run(root, path, "1")
    check(historical["status"] == "completed" and historical["deleted_this_call"] == "0" and restored.exists() and
          historical["receipt_scope"] == "operation_history", "completed receipt never deletes a later replacement")
    policy["reason"] = "different policy must not reuse an operation"
    path.write_bytes(encoded(policy))
    check(run(root, path, "1")["issue"] == "gc_operation_collision_or_policy_mismatch", "operation ID cannot change policy")

    for name in ("open-root", "corrupt-root", "unknown-artifact", "protected-reference", "young", "future", "readonly", "hardlink", "changed", "missing"):
        root, path, policy = case(name)
        candidate = root / policy["members"][0]["path"]
        if name == "open-root":
            (root / "collections/7/journal-segments/00000000000000000004.knjseg").unlink()
        elif name == "corrupt-root":
            (root / "collections/7/session.knsession").write_bytes(b"corrupt")
        elif name == "unknown-artifact":
            (root / "image-reads/unmanaged.bin").write_bytes(b"unresolved")
        elif name == "protected-reference":
            original_blob = next((original / "image-references").iterdir())
            policy["members"] = [{"path": "image-references/" + original_blob.name, "sha256": sha(original_blob.read_bytes()),
                                  "bytes": str(original_blob.stat().st_size), "schema": "raw.bytes"}]
            path.write_bytes(encoded(policy))
        elif name == "young":
            policy["minimum_age_seconds"] = "86400"
            path.write_bytes(encoded(policy))
        elif name == "future":
            os.utime(candidate, (time.time() + 3600, time.time() + 3600))
        elif name == "readonly":
            candidate.chmod(stat.S_IREAD)
        elif name == "hardlink":
            os.link(candidate, root / "owned-other-link.bin")
        elif name == "changed":
            candidate.write_bytes(encoded({"schema": "kn.image_reads.v3", "fixture": "replacement"}))
        elif name == "missing":
            candidate.unlink()
        try:
            result = run(root, path, "1")
            check(result["status"] not in ("planned", "completed") and result["deleted_this_call"] == "0" and
                  not (root / "retention").exists(), f"preflight prevents any mutation: {name}")
            check((root / policy["members"][-1]["path"]).exists(), "no partial selection deletion during denied preflight")
        finally:
            if name == "readonly":
                candidate.chmod(stat.S_IREAD | stat.S_IWRITE)

    for name in ("ledger", "traversal", "budget", "overflow", "duplicate", "schema", "extra", "nul"):
        root, path, policy = case("policy-" + name)
        if name == "ledger":
            policy["members"][0].update(path="image-reads/session-99.knreadledger", schema="kn.image_read_session.v1")
        elif name == "traversal":
            policy["members"][0]["path"] = "../outside.knreads"
        elif name == "budget":
            policy["byte_limit"] = "1"
        elif name == "overflow":
            policy["byte_limit"] = "18446744073709551616"
        elif name == "duplicate":
            policy["members"] *= 2
        elif name == "schema":
            policy["schema"] = "kn.evidence_gc_policy.v9"
        elif name == "extra":
            policy["future_authority"] = True
        elif name == "nul":
            policy["reason"] = "hidden\0suffix"
        path.write_bytes(encoded(policy))
        check(run(root, path, "1")["issue"] == "invalid_gc_policy", "malformed or overbroad policy rejected")
        intact(root)

    interruptions = 0

    def stopped(name, stage):
        nonlocal interruptions
        root, path, policy = case(name)
        owned(root)
        child = subprocess.Popen([str(producer), "--gc", str(root), str(path), "1", stage], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: lines.put(child.stdout.readline()), daemon=True)
        reader.start()
        try:
            check(lines.get(timeout=30).strip() == "[journal.stage] " + stage and child.poll() is None, "observed exact GC stage")
            if stage == "gc_intent":
                candidate = root / policy["members"][0]["path"]
                for mutation in (lambda: candidate.write_bytes(b"overwrite denied"), candidate.unlink):
                    try:
                        mutation()
                        check(False, "verified candidate must exclude writes and path deletion")
                    except PermissionError:
                        check(True, "verified candidate remains pinned through intent")
            check(run(root, path)["issue"] == "store_busy", "inventory and second GC excluded while owned actor holds barrier")
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=15)
            reader.join(timeout=5)
        check(child.poll() is not None and not reader.is_alive(), "interrupted GC child reaped")
        interruptions += 1
        return root, path, policy

    for stage in ("gc_preflight", "gc_operation", "gc_intent", "gc_delete", "gc_receipt"):
        root, path, policy = stopped("interrupt-" + stage, stage)
        resumed = run(root, path, "1")
        check(resumed["status"] == ("completed_with_unresolved_outcomes" if stage == "gc_delete" else "completed"), "resume preserves unknown deletion outcome")
        if stage == "gc_delete":
            check(resumed["entries"][0]["state"] == "absent_after_intent" and resumed["deleted_this_call"] == "1", "absence after durable intent is not attributed to collector")
        receipts(root, path, policy, resumed)
        intact(root)
    root, path, policy = stopped("replacement", "gc_intent")
    candidate = root / policy["members"][0]["path"]
    old = candidate.read_bytes()
    candidate.rename(root / "owned-original-backup.bin")
    candidate.write_bytes(old)
    result = run(root, path, "1")
    check(result["status"] == "denied" and result["entries"][0]["issue"] == "replacement_after_intent_preserved" and candidate.read_bytes() == old,
          "same-byte replacement cannot inherit interrupted deletion authority")
    root, path, policy = stopped("corrupt-intent", "gc_intent")
    (root / "retention/1/1.kngcintent").write_bytes(b"corrupt")
    check(run(root, path, "1")["issue"] == "gc_audit_record_unavailable" and
          all((root / m["path"]).exists() for m in policy["members"]), "invalid durable intent blocks deletion")
    root, path, policy = stopped("unbound-receipt", "gc_receipt")
    receipt_path = root / "retention/1/1.kngcreceipt"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["payload"]["intent_sha256"] = "0" * 64
    receipt["payload_sha256"] = sha(encoded(receipt["payload"]))
    receipt_path.write_bytes(encoded(receipt))
    check(run(root, path, "1")["issue"] == "gc_receipt_invalid_or_unbound" and
          (root / policy["members"][1]["path"]).exists(), "rehashed receipt cannot change its durable intent")
    root, path, policy = stopped("root-identity", "gc_operation")
    copied = sandbox / "copied-operation"
    shutil.copytree(root, copied)
    check(run(copied, path, "1")["issue"] == "gc_operation_collision_or_policy_mismatch" and
          all((copied / m["path"]).exists() for m in policy["members"]), "copied operation cannot authorize another physical root")
    root, path, policy = case("old-enough")
    policy["minimum_age_seconds"] = "86400"
    path.write_bytes(encoded(policy))
    for member in policy["members"]:
        os.utime(root / member["path"], (time.time() - 172800, time.time() - 172800))
    check(run(root, path, "1")["status"] == "completed", "positive minimum-age admission")
    root, path, policy = case("audit-collision")
    (root / "retention/1").mkdir(parents=True)
    collision = root / "retention/1/1.kngcintent"
    collision.write_bytes(b"preserve unexplained record")
    check(run(root, path, "1")["issue"] == "gc_operation_directory_collision" and
          collision.read_bytes() == b"preserve unexplained record" and all((root / m["path"]).exists() for m in policy["members"]),
          "unexplained audit output is preserved before any deletion")

    if args.cli:
        for tail in ([], [str(original)], [str(original), str(path), "/apply"], [str(original), str(path), "/apply", "../escape"],
                     [str(original), str(path), "/json", "/json"], [str(original), str(path), "/apply", "01"]):
            invalid = subprocess.run([str(exe), "--offline", "!kmon", "gc", *tail], capture_output=True, timeout=30)
            check(invalid.returncode == 2 and b'kn.evidence_gc_result.v1' not in invalid.stdout, "invalid GC grammar")
    print(f"[gc.oracle] checks={CHECKS} interrupted_stages={interruptions} children_remaining=0 mode={'cli' if args.cli else 'harness'} fixtures={sandbox}")


if __name__ == "__main__":
    main()
