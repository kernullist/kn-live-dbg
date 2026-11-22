"""Compare resumed native catalog reads to the exact original ledgers, segments and member bytes."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def payload(data):
    envelope = json.loads(data)
    value = envelope["payload"]
    assert sha(encoded(value)) == envelope["payload_sha256"]
    return value


def position(namespace, end, chain, terminal):
    prefix = ("kncr1" if terminal else "kncs1") + f".{end}.{chain}."
    return prefix + sha(("kn.store_catalog_position.v1|" + namespace + "|" + prefix).encode())


def originals(root):
    rows, paths, contents = [], {}, {}
    for folder in sorted((root / "collections").iterdir(), key=lambda path: path.name):
        session = (folder / "session.knsession").read_bytes()
        head = sha(session)
        assert payload(session)["collection_id"] == folder.name
        local, hashes = {}, {}
        references = logical = segments = 0
        closed = False
        for segment in sorted((folder / "journal-segments").glob("*.knjseg")):
            data = segment.read_bytes()
            record = payload(data)
            assert not closed and record["previous_sha256"] == head
            head = sha(data)
            segments += 1
            assert int(record["sequence"]) == segments
            tx = record["transaction"]
            closed = tx["kind"] == "closure"
            for member in tx["members"]:
                name = member["path"]
                raw = (root / name).read_bytes()
                digest = sha(raw)
                assert digest == member["sha256"] and len(raw) == int(member["bytes"])
                assert paths.setdefault(name, (digest, len(raw))) == (digest, len(raw))
                assert contents.setdefault(digest, len(raw)) == len(raw)
                local[name] = hashes[digest] = len(raw)
                references += 1
                logical += len(raw)
        rows.append(dict(id=folder.name, status="verified_prefix", issue="", session_sha256=sha(session), head_sha256=head,
                         committed_segments=str(segments), closed=closed, member_references=str(references),
                         unique_paths=str(len(local)), logical_bytes=str(logical), unique_content_bytes=str(sum(hashes.values())),
                         pending_files=str(len(list((folder / "journal-segments").glob("*.pending-*"))))))
    return rows, paths, contents


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--large", action="store_true", help="exercise 1,025 native closed collections and the namespace ceiling")
    args = parser.parse_args()
    exe = args.exe.resolve()
    producer = (args.producer or exe).resolve()
    count = 0

    def check(ok, label):
        nonlocal count
        count += 1
        if not ok:
            raise AssertionError(label)

    def run(root, *options, code=0):
        command = [exe, "--offline", "!kmon", "store"] if args.cli else [exe, "--store"]
        result = subprocess.run([*command, root, *options], capture_output=True, timeout=180)
        check(result.returncode == code, (options[:2], result.returncode, result.stderr[-180:]))
        if code == 2:
            check(not result.stdout.startswith(b"{"), "usage error never supplies a receipt")
            return {}
        return json.loads(result.stdout)

    def window(root, limit, cursor="", code=0):
        r = run(root, "/scan-catalog", "/limit", str(limit), *(["/cursor", cursor] if cursor else []), code=code)
        check(r["schema"] == "kn.store_catalog_scan.v1" and not r["global_membership_established"] and
              not r["deletion_authorized"] and not r["collector_authenticated"], "page scope")
        if code:
            check(not r["next_scan_cursor"] and not r["scan_receipt"] and not r["collections"], "failed page grants no progress")
        return r

    def cover(root, limits):
        expected, paths, contents = originals(root)
        start, cursor, chain, index = 0, "", "", 0
        while True:
            limit = limits[index % len(limits)]
            result = window(root, limit, cursor)
            scope = result["namespace_sha256"]
            if not index:
                chain = sha(("kn.store_catalog_rows.v1|" + scope).encode())
                namespace = scope
            stop = min(len(expected), start + limit)
            page_rows = expected[start:stop]
            check(scope == namespace and result["namespace_entries"] == str(len(expected)), "stable name denominator")
            check(result["collection_offset"] == str(start) and result["collections_scanned"] == str(len(page_rows)), "page bounds")
            check(result["collections"] == page_rows, "all original-linked collection fields")
            for row in page_rows:
                chain = sha(chain.encode() + b"|" + encoded(row))
            terminal = stop == len(expected)
            token = position(scope, stop, chain, terminal)
            check(result["status"] == ("complete" if terminal else "more") and result["next_scan_cursor"] == ("" if terminal else token)
                  and result["scan_receipt"] == (token if terminal else ""), "independent rolling receipt")
            if terminal:
                break
            start, cursor, index = stop, token, index + 1
        full = run(root, "/scan-receipt", token, *(["/artifacts"] if args.cli else []))
        check(full["status"] == "verified" and full["collections"] == expected and full["catalog_sha256"] == sha(encoded(expected)), "full replay")
        check(full["closed_collections"] == str(len(expected)) and full["committed_segments"] == str(sum(int(r["committed_segments"]) for r in expected))
              and full["member_references"] == str(sum(int(r["member_references"]) for r in expected)), "global denominators")
        check(full["unique_path_bytes"] == str(sum(size for _, size in paths.values())) and full["unique_content_bytes"] == str(sum(contents.values()))
              and full["logical_reference_bytes"] == str(sum(int(r["logical_bytes"]) for r in expected)), "physical dedup and logical references")
        check(full["artifacts_sha256"] == sha(encoded(full["artifacts"])) and
              all(paths[row["artifact"]["path"]][0] == row["artifact"]["sha256"] for row in full["artifacts"]), "global original members")
        return token, full

    with tempfile.TemporaryDirectory(prefix="catalog-", dir=args.fixtures.resolve()) as temp:
        sandbox = Path(temp)
        root = sandbox / "small"
        for item in ("1", "2"):
            subprocess.run([producer, "--produce-collection", root, item], capture_output=True, check=True, timeout=60)
        receipt, full = cover(root, [1])
        ordinary = run(root, *(["/artifacts"] if args.cli else []))
        check({k: v for k, v in full.items() if k not in ("started_tick", "ended_tick")} ==
              {k: v for k, v in ordinary.items() if k not in ("started_tick", "ended_tick")}, "existing small-store inventory compatibility")
        first = window(root, 1)
        check(run(root, "/SCAN-CATALOG", "/LIMIT", "1")["next_scan_cursor"] == first["next_scan_cursor"], "case-insensitive scan options")
        cursor = first["next_scan_cursor"]
        token_row = window(root, 2, cursor)
        check(token_row["scan_receipt"] == receipt, "resume with another page size")
        check(window(root, 1, cursor)["collections"] == token_row["collections"], "interior checkpoint retry")
        check(run(root, "/scan-receipt", receipt, "/retention")["collection_retention"]["status"] == "verified", "retention recomputed under lease")
        facts_args = ["/artifacts"] if args.cli else []
        a = run(root, "/scan-receipt", receipt, *facts_args, "/limit", "1")
        b = run(root, "/scan-receipt", receipt, *facts_args, "/limit", "1", "/cursor", a["next_artifact_cursor"])
        check(b["artifact_row_offset"] == "1" and b["artifacts"] == full["artifacts"][1:2], "separate artifact cursor")
        for malformed in (receipt, "wrong", cursor.replace(".1.", ".2.", 1), a["next_artifact_cursor"]):
            check(window(root, 1, malformed, 1)["issue"] == "store_scan_cursor_mismatch", "bad or wrong-purpose cursor")
        check(run(root, "/scan-receipt", cursor, code=1)["issue"] == "store_scan_receipt_mismatch", "incomplete checkpoint cannot verify store")
        forged = position(first["namespace_sha256"], 2, "a" * 64, True)
        check(run(root, "/scan-receipt", forged, code=1)["issue"] == "store_scan_recovery_mismatch", "rehashed wrong receipts need original rows")
        for opts in (["/scan-catalog", "/limit", "1025"], ["/scan-catalog", "/retention"], ["/scan-catalog", "/artifacts"],
                     ["/scan-catalog", "/scan-receipt", receipt], ["/scan-receipt"], ["/scan-catalog", "/scan-catalog"]):
            run(root, *opts, code=2)

        # The next page reads no bytes from the earlier collection. Global verification must reopen them.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        ledger = root / "image-reads/session-1.knreadledger"
        handle = kernel.CreateFileW(str(ledger), 0x80000000, 0, None, 3, 0x80, None)
        check(handle not in (None, wintypes.HANDLE(-1).value), "locked the earlier original")
        try:
            check(window(root, 1, cursor)["scan_receipt"] == receipt, "resume skips locked preceding evidence")
            check(run(root, "/scan-receipt", receipt, code=1)["issue"] == "store_scan_recovery_mismatch", "global proof reopens locked evidence")
        finally:
            kernel.CloseHandle(handle)
        saved = ledger.read_bytes()
        try:
            ledger.write_bytes(saved + b" ")
            check(window(root, 1, cursor)["scan_receipt"] == receipt, "later historical page independent of earlier bytes")
            check(run(root, "/scan-receipt", receipt, code=1)["issue"] == "store_scan_recovery_mismatch", "earlier byte replacement detected")
        finally:
            ledger.write_bytes(saved)
        check(run(root, "/scan-receipt", receipt)["status"] == "verified", "exact restored originals revalidate")
        loose = root / "image-reads/reads-45-1.knreads"
        loose.write_bytes(encoded(dict(schema="kn.image_reads.v3", fixture="new loose read")))
        try:
            refreshed = run(root, "/scan-receipt", receipt, *facts_args)
            check(refreshed["artifacts_sha256"] != full["artifacts_sha256"] and refreshed["catalog_sha256"] == full["catalog_sha256"] and
                  any(row["artifact"]["sha256"] == sha(loose.read_bytes()) and not row["collections"] for row in refreshed["artifacts"]),
                  "final inventory discovers current loose artifacts outside the journal receipt")
        finally:
            loose.unlink()

        clone = sandbox / "clone"
        shutil.copytree(root, clone)
        check(window(clone, 1, cursor, 1)["issue"] == "store_scan_cursor_mismatch", "copied root is a different namespace")
        before = window(clone, 2)
        sample, rule = sandbox / "inventory.json", sandbox / "retire.json"
        helper = [sys.executable, "-B", Path(__file__).with_name("new-evidence-gc-policy.py"), "--inventory", sample,
                  "--retire-collection", "1", "--minimum-age-seconds", "0", "--reason", "owned scan control", "--output", rule]
        sample.write_bytes(encoded(before))
        check(subprocess.run(helper, capture_output=True).returncode == 1 and not rule.exists(), "historical pages cannot prepare deletion policies")
        sample.write_bytes(encoded(run(clone, "/scan-receipt", before["scan_receipt"])))
        subprocess.run(helper, capture_output=True, check=True)
        retire = [exe, "--offline", "!kmon", "retire-collection", clone, rule, "/apply"] if args.cli else [exe, "--retire-collection", clone, rule, "apply"]
        subprocess.run(retire, capture_output=True, check=True, timeout=60)
        check(run(clone, "/scan-receipt", before["scan_receipt"], code=1)["issue"] == "store_scan_recovery_mismatch", "retirement invalidates an earlier closure")
        retired = window(clone, 2)
        current = run(clone, "/scan-receipt", retired["scan_receipt"])
        check(current["retired_collections"] == "1" and retired["collections"][0]["status"] == "retired" and
              retired["collections"] == current["collections"], "retired membership and receipt stay distinct from active roots")
        last = sorted((root / "collections/1/journal-segments").glob("*.knjseg"))[-1]
        saved_segment = sandbox / "held-segment"
        last.rename(saved_segment)
        try:
            opened = window(root, 2)
            check(not opened["collections"][0]["closed"] and run(root, "/scan-receipt", opened["scan_receipt"], code=1)["open_collections"] == "1",
                  "a traversed open journal cannot establish complete membership")
        finally:
            saved_segment.rename(last)
        renamed = root / "collections/2"
        old = sandbox / "parked"
        renamed.rename(old)
        try:
            shutil.copytree(old, renamed)
            check(window(root, 1, cursor, 1)["issue"] == "store_scan_cursor_mismatch", "same-named replacement invalidates namespace")
        finally:
            shutil.rmtree(renamed)
            old.rename(renamed)
        extra = root / "collections/unresolved-\uac00"
        extra.mkdir()
        check(window(root, 1, cursor, 1)["issue"] == "store_scan_cursor_mismatch", "added root invalidates cursor")
        incomplete = window(root, 10)
        check(incomplete["collections"][-1]["issue"] == "invalid_collection_id", "malformed entry stays in denominator")
        check(run(root, "/scan-receipt", incomplete["scan_receipt"], code=1)["status"] == "partial", "partial roots never verify complete membership")
        extra.rmdir()

        for interrupt in (False, True):
            child = subprocess.Popen([producer, "--hold-scan", root, "/scan-catalog", "/limit", "1", "/cursor", cursor],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            line = queue.Queue()
            listener = threading.Thread(target=lambda: line.put(child.stdout.readline()), daemon=True)
            listener.start()
            try:
                check(line.get(timeout=20).strip() == b"[journal.stage] collection_scanned" and child.poll() is None, "observed original read")
                check(window(root, 1, code=1)["issue"] == "store_busy", "concurrent scan excluded")
                if interrupt:
                    child.kill()
                    child.communicate(timeout=15)
                else:
                    extra.mkdir()
                    out, _ = child.communicate(input=b"continue\n", timeout=20)
                    denied = json.loads(out)
                    check(child.returncode == 1 and denied["issue"] == "store_scan_namespace_changed" and not denied["scan_receipt"],
                          "nonparticipating namespace change during page discards checkpoint")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=15)
                listener.join(5)
                if extra.exists():
                    extra.rmdir()
            check(window(root, 1, cursor)["scan_receipt"] == receipt and not listener.is_alive(), "resume last acknowledged window after interruption")

        empty = sandbox / "empty"
        empty.mkdir()
        absent = window(empty, 1)
        check(absent["status"] == "complete" and absent["collections"] == [] and run(empty, "/scan-receipt", absent["scan_receipt"])["status"] == "verified",
              "absent catalog has an exact zero receipt")
        (empty / "collections").mkdir()
        check(run(empty, "/scan-receipt", absent["scan_receipt"], code=1)["issue"] == "store_scan_receipt_mismatch", "absent and empty catalog distinct")
        if args.large:
            large = sandbox / "large"
            subprocess.run([producer, "--produce-catalog", large], capture_output=True, check=True, timeout=300)
            check(run(large, code=1)["issue"] == "store_catalog_budget_exhausted", "one-shot default bound preserved")
            _, large_result = cover(large, [512, 500, 64])
            check(large_result["collections_observed"] == "1025" and large_result["closed_collections"] == "1025", "cross the 1,024-root bound")
            for i in range(16384):
                (empty / "collections" / str(i)).touch()
            check(window(empty, 1)["namespace_entries"] == "16384", "exact discovery bound")
            (empty / "collections/16384").touch()
            check(window(empty, 1, code=1)["issue"] == "store_scan_namespace_budget_exhausted", "overflow yields no cursor")
    print(f"[store.catalog] checks={count} large={args.large} product={args.cli} children_remaining=0")


if __name__ == "__main__":
    main()
