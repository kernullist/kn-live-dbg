"""Exercise receipt-checked retirement and file GC on a private, generated store."""
import argparse
from collections import defaultdict
import contextlib
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def wrong_history(page, files):
    field, scope, domain, index = (("file_receipt", "file_namespace_sha256", "kn.store_file_position.v1", 3) if files else
                                   ("scan_receipt", "namespace_sha256", "kn.store_catalog_position.v1", 2))
    parts = page[field].split(".")[:-1]
    parts[index] = "0" * 64
    body = ".".join(parts) + "."
    return body + digest(f"{domain}|{page[scope]}|{body}".encode())


@contextlib.contextmanager
def at_stage(command, stage):
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        events = queue.Queue()
        listener = threading.Thread(target=lambda: events.put(child.stdout.readline()), daemon=True)
        listener.start()
        try:
            if events.get(timeout=35).strip() != b"[journal.stage] " + stage.encode() or child.poll() is not None:
                raise AssertionError("missing native observation " + stage)
            yield child
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=15)
            listener.join(5)
            if listener.is_alive():
                raise AssertionError("observer thread still running")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--previous-cli", type=Path)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--large", action="store_true", help="use 1,025 closed native collections")
    args = parser.parse_args()
    exe = args.exe.resolve()
    producer = (args.producer or exe).resolve()
    checks = 0

    def check(ok, label):
        nonlocal checks
        if not ok:
            raise AssertionError(label)
        checks += 1

    def invoke(command, code=0):
        result = subprocess.run(command, capture_output=True, timeout=190)
        check(result.returncode == code, (str(command[1]), result.returncode, code, result.stdout[:260], result.stderr[:180]))
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="retained-", dir=args.fixtures.resolve()) as tmp:
        space = Path(tmp)
        root = space / "store"
        if args.large:
            invoke([producer, "--produce-catalog", root])
        else:
            for name in ("1", "2"):
                invoke([producer, "--produce-collection", root, name])
        retirement = space / "retire.json"
        deletion = space / "delete.json"
        receipt = root / "collections/1/retirement.knretirement"
        selected = "image-sweeps/sweep-1-1.knsweep"
        victim = root / selected
        original = victim.read_bytes()
        cli = [exe, "--offline", "!kmon"]

        def store(*flags, code=0):
            command = [*cli, "store"] if args.cli else [exe, "--store"]
            return json.loads(invoke([*command, root, *flags], code))

        def terminal(files):
            flag, cursor_key = ("/scan-files", "next_file_cursor") if files else ("/scan-catalog", "next_scan_cursor")
            cursor = ""
            while True:
                page = store(flag, "/limit", "1024", *(["/cursor", cursor] if cursor else []))
                if page["status"] == "complete":
                    return page
                check(page["status"] == "more" and page[cursor_key] and cursor != page[cursor_key], "advancing original scan")
                cursor = page[cursor_key]

        def action(name, rule, flags, apply="", code=0):
            if args.cli:
                command = [*cli, name, root, rule, *flags]
                if apply:
                    command += ["/apply"] if name == "retire-collection" else ["/apply", apply]
            else:
                command = [exe, "--" + name, root, rule, apply or "-", *flags]
            raw = invoke(command, code)
            return json.loads(raw) if code != 2 else None

        def prepare(snapshot, rule, *choice):
            sample = space / "inventory.json"
            sample.write_bytes(encoded(snapshot))
            invoke([sys.executable, "-B", Path(__file__).with_name("new-evidence-gc-policy.py"), "--inventory", sample,
                    "--minimum-age-seconds", "0", "--reason", "owned retention test", "--output", rule, *choice])

        catalog, physical = terminal(False), terminal(True)
        c = ["/scan-receipt", catalog["scan_receipt"]]
        f = ["/file-receipt", physical["file_receipt"]]
        initial = store(*c, *f, "/artifacts")
        check(initial["closed_collections"] == str(1025 if args.large else 2), "full original catalog")
        prepare(initial, retirement, "--retire-collection", "1")
        # Establish a valid GC policy independently of a future retirement.
        orphan_data = b"explicitly selected unreferenced test blob"
        loose_path = "image-references/" + digest(orphan_data) + ".knblob"
        loose = root / loose_path
        loose.write_bytes(orphan_data)
        physical = terminal(True)
        f = ["/file-receipt", physical["file_receipt"]]
        current = store(*c, *f, "/artifacts")
        orphan_rule = space / "loose.json"
        prepare(current, orphan_rule, "--path", loose_path)
        if args.previous_cli:
            for name, rule in (("retire-collection", retirement), ("gc", orphan_rule)):
                old = [args.previous_cli.resolve(), "--offline", "!kmon", name, root, rule]
                invoke([*old, *c], 2)
                if args.large:
                    check(json.loads(invoke(old, 1))["issue"] == "store_catalog_budget_exhausted", "previous one-shot bound")

        if not args.large:
            if not args.cli:
                direct = invoke([exe, "--gc", root, orphan_rule, "001", *c, *f], 1)
                check(json.loads(direct)["issue"] == "invalid_gc_operation_id", "preserve the native API's invalid-operation result")
                invoke([exe, "--retire-collection", root, retirement, "-", "/apply", *f], 2)
                check(not receipt.exists(), "receipt flags cannot turn a harness preflight into apply")
            for name, rule, mode in (("retire-collection", retirement, "apply"), ("gc", orphan_rule, "51")):
                for bad, issue in ((["/scan-receipt", physical["file_receipt"]], "store_scan_receipt_mismatch"),
                                   (["/file-receipt", catalog["scan_receipt"]], "store_file_receipt_mismatch"),
                                   (["/scan-receipt", wrong_history(catalog, False), *f], "store_scan_recovery_mismatch"),
                                   ([*c, "/file-receipt", wrong_history(physical, True)], "store_file_bytes_mismatch")):
                    check(action(name, rule, bad, mode, 1)["issue"] == issue, "receipt must verify before apply")
                for bad in (["/scan-receipt"], [*f, *f], ["/cursor", "1"], ["/scan-files"], ["/retention"]):
                    action(name, rule, bad, code=2)
                for flags in (c, f, ["/FILE-RECEIPT", f[1], "/JSON", *c]):
                    check(action(name, rule, flags)["status"] == "planned", "independent optional receipts")
            check(loose.read_bytes() == orphan_data and victim.read_bytes() == original and not receipt.exists() and
                  not (root / "retention").exists(), "denials and plans leave originals and operation logs intact")
            shared = next(row["artifact"] for row in current["artifacts"] if row["collections"] == ["1", "2"])
            protected = space / "protected.json"
            protected.write_bytes(encoded(dict(json.loads(orphan_rule.read_bytes()), members=[shared])))
            denied = action("gc", protected, c + f, "50", 1)
            check(denied["entries"][0]["issue"] == "selected_file_protected" and not (root / "retention").exists() and
                  digest((root / shared["path"]).read_bytes()) == shared["sha256"], "valid receipts preserve an actively shared member")

            # Synchronize on a completed read, then add a file as a nonparticipating writer.
            command = [producer, "--gc", root, orphan_rule, "51", "file_inventory_hashed", *c, *f]
            late = root / "image-reads/session-88.knreadledger"
            try:
                with at_stage(command, "file_inventory_hashed") as child:
                    check(store(*c, code=1)["issue"] == "store_busy", "action retains exclusive store lease")
                    late.write_bytes(b'{"schema":"kn.image_read_session.v1"}')
                    output, _ = child.communicate(input=b"continue\n", timeout=45)
                    check(child.returncode == 1 and json.loads(output)["issue"] == "store_file_namespace_changed" and
                          loose.read_bytes() == orphan_data and not (root / "retention").exists(), "late change prevents audit or deletion")
            finally:
                late.unlink(missing_ok=True)
            incomplete = root / "collections/incomplete"
            command = [producer, "--retire-collection", root, retirement, "-", "file_inventory_hashed", *c, *f]
            try:
                with at_stage(command, "file_inventory_hashed") as child:
                    incomplete.mkdir()
                    output, _ = child.communicate(input=b"continue\n", timeout=45)
                    result = json.loads(output)
                    check(child.returncode == 1 and result["issue"] == "store_scan_namespace_changed" and not receipt.exists(),
                          ("catalog changed during final physical verification", child.returncode, result["status"], result["issue"]))
            finally:
                if incomplete.exists():
                    incomplete.rmdir()
            incomplete.mkdir()
            try:
                partial = ["/scan-receipt", terminal(False)["scan_receipt"], *f]
                for name, rule, mode in (("retire-collection", retirement, "apply"), ("gc", orphan_rule, "51")):
                    denied = action(name, rule, partial, mode, 1)
                    check(denied["status"] == "unavailable" and not receipt.exists() and not (root / "retention").exists(),
                          "a genuine terminal receipt over unresolved membership cannot authorize a change")
            finally:
                incomplete.rmdir()
            if args.cli:
                read_fd, write_fd = os.pipe()
                os.close(read_fd)
                try:
                    output = subprocess.run([*cli, "gc", root, orphan_rule, *c, *f], stdout=write_fd, stderr=subprocess.PIPE, timeout=60)
                    check(output.returncode == 3 and loose.read_bytes() == orphan_data, "GC reports an unwritable result stream")
                finally:
                    os.close(write_fd)
        else:
            for name, rule in (("retire-collection", retirement), ("gc", orphan_rule)):
                check(action(name, rule, [], code=1)["issue"] == "store_catalog_budget_exhausted", "default bound remains explicit")
                check(action(name, rule, f, code=1)["issue"] == "store_catalog_budget_exhausted", "file receipt cannot extend catalog")

        plan = action("retire-collection", retirement, c + f)
        record = plan["record"]["payload"]
        unique = {}
        for path in sorted((root / "collections/1/journal-segments").glob("*.knjseg")):
            for member in json.loads(path.read_bytes())["payload"]["transaction"]["members"]:
                data = (root / member["path"]).read_bytes()
                check(digest(data) == member["sha256"], "original transaction member digest")
                unique[member["path"]] = len(data)
        shared_paths = set()
        for folder in (root / "collections").iterdir():
            if folder.name == "1":
                continue
            for path in (folder / "journal-segments").glob("*.knjseg"):
                members = json.loads(path.read_bytes())["payload"]["transaction"]["members"]
                shared_paths.update(m["path"] for m in members if m["path"] in unique)
        groups = defaultdict(list)
        for name, size in unique.items():
            kind = "failure_ledgers" if name.endswith("ledger") else "shared_nonledger" if name in shared_paths else "exclusive_nonledger"
            groups[kind].append(size)
        check(set(groups) == {"exclusive_nonledger", "shared_nonledger", "failure_ledgers"}, "all three ownership classes observed")
        for kind, sizes in groups.items():
            check(sizes and record[kind] == {"paths": str(len(sizes)), "named_bytes": str(sum(sizes))}, "original ownership " + kind)
        check(record["catalog_sha256"] == digest(encoded(current["collections"])) and
              record["artifacts_sha256"] == digest(encoded(current["artifacts"])), "plan binds complete ordered inventory")
        result = action("retire-collection", retirement, c + f, "apply")
        check(receipt.read_bytes() == encoded(result["record"]) and result["receipt_sha256"] == digest(receipt.read_bytes()) and
              victim.read_bytes() == original, "withdrawal records policy and leaves original bytes")
        check(action("retire-collection", retirement, c + f, "apply", 1)["issue"] == "store_scan_recovery_mismatch",
              "stale catalog cannot bypass post-withdrawal verification on retry")
        c = ["/scan-receipt", terminal(False)["scan_receipt"]]
        check(action("retire-collection", retirement, c + f, "apply")["reused_receipt"], "current catalog reuses immutable withdrawal")
        retired = store(*c, *f, "/artifacts")
        prepare(retired, deletion, "--from-retired-collection", "1", "--path", selected)
        check(action("gc", deletion, c + f)["entries"][0]["state"] == "eligible" and victim.exists(), "explicit file preflight")
        gc = action("gc", deletion, c + f, "52")
        check(gc["status"] == "completed" and gc["deleted_this_call"] == "1" and not victim.exists() and
              loose.read_bytes() == orphan_data, "only the eligible selected name is deleted")
        audit = root / "retention/52/1.kngcreceipt"
        audit_bytes = audit.read_bytes()
        check(gc["entries"][0]["receipt_sha256"] == digest(audit_bytes) and
              gc["entries"][0]["artifact"]["sha256"] == digest(original), "durable receipt binds original bytes")
        check(action("gc", deletion, c + f, "52", 1)["issue"] == "store_file_receipt_mismatch", "prior file namespace no longer matches")
        f = ["/file-receipt", terminal(True)["file_receipt"]]
        retry = action("gc", deletion, c + f, "52")
        check(retry["deleted_this_call"] == "0" and retry["entries"][0]["reused_receipt"] and audit.read_bytes() == audit_bytes,
              "refreshed verification reuses the exact audit record")
        check(all((root / name).stat().st_size == size for name, size in unique.items() if name != selected),
              "other originals, shared reference and failure ledger preserved")
        if not args.large:
            replacement = space / "replacement"
            replacement.write_bytes(orphan_data)
            audit_root = root / "retention/53"
            with at_stage([producer, "--gc", root, orphan_rule, "53", "gc_delete", *c, *f], "gc_delete"):
                check(not loose.exists() and (audit_root / "1.kngcintent").is_file() and not (audit_root / "1.kngcreceipt").exists(),
                      "interrupted between named deletion and result publication")
            check(action("gc", orphan_rule, c + f, "53", 1)["issue"] == "store_file_receipt_mismatch",
                  "pre-interruption file receipt no longer verifies")
            replacement.rename(loose)
            current_files = ["/file-receipt", terminal(True)["file_receipt"]]
            denied = action("gc", orphan_rule, c + current_files, "53", 1)
            check(denied["deleted_this_call"] == "0" and denied["entries"][0]["issue"] == "replacement_after_intent_preserved" and
                  loose.read_bytes() == orphan_data, "fresh verification does not authorize deleting a replacement with identical bytes")
            loose.unlink()
            current_files = ["/file-receipt", terminal(True)["file_receipt"]]
            resumed = action("gc", orphan_rule, c + current_files, "53", 1)
            check(resumed["status"] == "completed_with_unresolved_outcomes" and resumed["deleted_this_call"] == "0" and
                  resumed["entries"][0]["state"] == "absent_after_intent", "resumed absence preserves the unknown deletion actor")
    print(f"[store.retention-receipts] checks={checks} large={args.large} product={args.cli}")


if __name__ == "__main__":
    main()
