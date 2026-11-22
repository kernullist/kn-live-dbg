"""Check resumed physical file reads against Windows file identities and independently hashed original ranges."""
import _winapi
import argparse
import contextlib
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading


BLOCK = 65536
FOLDERS = ("image-reads", "image-references", "image-sweeps", "image-captures", "image-approvals", "image-scope-inputs", "")
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel.CreateFileW.restype = wintypes.HANDLE
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
kernel.LockFile.argtypes = kernel.UnlockFile.argtypes = [wintypes.HANDLE] + [wintypes.DWORD] * 4


@contextlib.contextmanager
def handle(path, access=0x80, share=7):
    h = kernel.CreateFileW(str(path), access, share, None, 3, 0x02200000, None)
    if h == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield h
    finally:
        assert kernel.CloseHandle(h)


def info(h, kind, size):
    data = ctypes.create_string_buffer(size)
    if not kernel.GetFileInformationByHandleEx(h, kind, data, size):
        raise ctypes.WinError(ctypes.get_last_error())
    return data.raw


def identity(path, directory=False):
    with handle(path) as h:
        tag = info(h, 9, 8)
        basic = info(h, 0, 40)
        fid = info(h, 18, 24)
        regular_size = int.from_bytes(info(h, 1, 24)[8:16], "little")
    attr = int.from_bytes(tag[:4], "little") & 0x410
    reparse_tag = int.from_bytes(tag[4:], "little") if attr & 0x400 else 0
    key = f"{int.from_bytes(fid[:8], 'little')}:{fid[8:].hex()}:{int.from_bytes(basic[:8], 'little')}:{attr}:{reparse_tag}"
    if directory:
        assert attr == 0x10
        return key
    return f"{key}:{int.from_bytes(basic[16:24], 'little')}:{int.from_bytes(basic[24:32], 'little')}:{regular_size}", regular_size


def sha(value):
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def quote(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def namespace(root):
    text = "kn.store_file_namespace.v1"
    entries = []
    for folder in FOLDERS:
        directory = root / folder
        text += "|" + quote(folder) + "|" + (identity(directory, True) if directory.exists() else "absent")
        if not directory.exists():
            continue
        for file in directory.iterdir():
            exact = file.relative_to(root).as_posix()
            lower = exact.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
            if not folder and not (lower.startswith("irp-") or lower.endswith((".knirp", ".knirpledger"))):
                continue
            stamp, size = identity(file)
            entries.append((lower, exact, size, stamp))
    entries.sort(key=lambda row: row[0].encode("utf-16-be"))
    for _, exact, _, stamp in entries:
        text += "|" + quote(exact) + "|" + stamp
    return sha(text), entries


def token(scope, final, index, offset, rows, chunks="-"):
    prefix = ("knfr1" if final else "knfs1") + f".{index}.{offset}.{rows}.{chunks}."
    return prefix + sha("kn.store_file_position.v1|" + scope + "|" + prefix)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--large", action="store_true", help="verify 513 paths sharing one 2 MiB original beyond the default read budget")
    args = parser.parse_args()
    exe, writer = args.exe.resolve(), (args.producer or args.exe).resolve()
    checks = 0

    def check(ok, name):
        nonlocal checks
        if not ok:
            raise AssertionError(name)
        checks += 1

    def run(root, *flags, code=0):
        cmd = [exe, "--offline", "!kmon", "store"] if args.cli else [exe, "--store"]
        answer = subprocess.run([*cmd, root, *flags, "/json"], capture_output=True, timeout=170)
        if answer.returncode != code:
            raise AssertionError((flags[:2], code, answer.returncode, answer.stdout[:230], answer.stderr[:180]))
        return json.loads(answer.stdout) if code != 2 else None

    def window(root, limit, cursor="", code=0):
        return run(root, "/scan-files", "/limit", str(limit), *(("/cursor", cursor) if cursor else ()), code=code)

    @contextlib.contextmanager
    def observed(root, flags, stage):
        child = subprocess.Popen([writer, "--hold-scan", root, *flags], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        events = queue.Queue()
        listener = threading.Thread(target=lambda: events.put(child.stdout.readline()), daemon=True)
        listener.start()
        try:
            check(events.get(timeout=25).strip() == b"[journal.stage] " + stage and child.poll() is None, "observed native read stage")
            yield child
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=15)
            listener.join(5)
            check(not listener.is_alive(), "native reader stopped")

    def cover(root, limits, gaps=None, shared=None):
        scope, entries = namespace(root)
        gaps = gaps or {}
        cached = {}
        index = offset = page = 0
        rows = sha("kn.store_file_rows.v1|" + scope)
        cursor, chunks = "", "-"
        while True:
            limit = limits[page % len(limits)]
            result = window(root, limit, cursor)
            check(result["schema"] == "kn.store_file_scan.v1" and not result["issue"] and result["file_namespace_sha256"] == scope
                  and int(result["namespace_entries"]) == len(entries), "Windows physical namespace")
            check(int(result["block_bytes"]) == BLOCK and not any(result[k] for k in ("global_membership_established", "deletion_authorized", "collector_authenticated")),
                  "range scope")
            expected = []
            for _ in range(limit):
                if index == len(entries):
                    break
                name, exact, size, _ = entries[index]
                row = dict(path=name, file_offset=str(offset), bytes="0", block_sha256="", issue=gaps.get(name, ""))
                expected.append(row)
                if row["issue"]:
                    closed = "gap:" + row["issue"]
                else:
                    if not offset:
                        chunks = sha(f"kn.store_file_chunks.v1|{size}")
                    if shared is not None:
                        data = shared[offset:offset + BLOCK]
                    else:
                        if name not in cached:
                            cached[name] = (root / exact).read_bytes()
                        data = cached[name][offset:offset + BLOCK]
                    assert data
                    digest = sha(data)
                    row.update(bytes=str(len(data)), block_sha256=digest)
                    chunks = sha(f"{chunks}|{offset}|{len(data)}|{digest}")
                    offset += len(data)
                    if offset < size:
                        continue
                    assert offset == size
                    closed = chunks
                rows = sha(f"{rows}|{quote(name)}|{size}|{closed}")
                index += 1
                offset, chunks = 0, "-"
            check(result["ranges"] == expected and int(result["read_bytes"]) == sum(int(r["bytes"]) for r in expected), "original ranges and exact page byte count")
            final = index == len(entries)
            expected_token = token(scope, final, index, offset, rows, chunks)
            cursor = result["next_file_cursor"]
            check((result["status"], cursor, result["file_receipt"]) ==
                  (("complete", "", expected_token) if final else ("more", expected_token, "")), "continuation and terminal chain")
            if final:
                return expected_token
            page += 1

    with tempfile.TemporaryDirectory(dir=args.fixtures.resolve(), prefix="fs-") as temporary:
        sandbox = Path(temporary)
        root = sandbox / "ranges"
        refs = root / "image-references"
        refs.mkdir(parents=True)
        raw = bytes(range(256)) * 850 + b"end"
        blob = refs / (sha(raw) + ".knblob")
        blob.write_bytes(raw)
        first = window(root, 1)
        cursor = first["next_file_cursor"]
        page_json, policy = sandbox / "ranges.json", sandbox / "retire.json"
        page_json.write_text(json.dumps(first), encoding="utf-8")
        helper = [sys.executable, "-B", Path(__file__).with_name("new-evidence-gc-policy.py"), "--inventory", page_json,
                  "--retire-collection", "1", "--minimum-age-seconds", "0", "--reason", "owned range control", "--output", policy]
        check(subprocess.run(helper, capture_output=True).returncode == 1 and not policy.exists(), "range evidence cannot issue mutation policy")
        receipt = cover(root, [1, 2, 7])
        check(cover(root, [1024]) == receipt, "page size independent")
        original = run(root, "/file-receipt", receipt)
        check(original["status"] == "verified" and int(original["read_bytes"]) == len(raw) and
              original["verified_unattributed_bytes"] == str(len(raw)), "one full original read")
        with handle(blob, access=0x80000000) as h:
            assert kernel.LockFile(h, 0, 0, BLOCK, 0)
            try:
                check(window(root, 1, code=1)["issue"] == "store_file_read_failed", "first range is actually locked")
                next_page = window(root, 1, cursor)
                check(next_page["ranges"][0]["block_sha256"] == sha(raw[BLOCK:2*BLOCK]) and next_page["read_bytes"] == str(BLOCK),
                      "resume inside the same file without touching the locked prefix")
                check(run(root, "/file-receipt", receipt, code=1)["issue"] == "store_file_bytes_mismatch", "full inspection needs original prefix")
            finally:
                assert kernel.UnlockFile(h, 0, 0, BLOCK, 0)
        check(run(root, "/file-receipt", receipt)["artifacts_sha256"] == original["artifacts_sha256"], "released prefix revalidates")
        scope = first["file_namespace_sha256"]
        forged = token(scope, False, 0, BLOCK, sha("kn.store_file_rows.v1|" + scope), sha("different prefix"))
        counterfeit = window(root, 64, forged)["file_receipt"]
        check(counterfeit != receipt and run(root, "/file-receipt", counterfeit, code=1)["issue"] == "store_file_bytes_mismatch", "re-sealed false history requires original bytes")
        check(window(root, 1, receipt, 1)["issue"] == "store_file_cursor_mismatch" and
              run(root, "/file-receipt", cursor, code=1)["issue"] == "store_file_receipt_mismatch", "position purpose")
        copy = sandbox / "copy"
        shutil.copytree(root, copy)
        check(window(copy, 1, cursor, 1)["issue"] == "store_file_cursor_mismatch", "copied store has different identities")
        (root / "outside.txt").write_bytes(b"unmanaged")
        check(window(root, 1, cursor)["next_file_cursor"] == next_page["next_file_cursor"], "unmanaged root file outside scope")

        for kill in (True, False):
            added = refs / "during.pending"
            try:
                with observed(root, ["/scan-files", "/limit", "1", "/cursor", cursor], b"file_block_read") as child:
                    check(window(root, 1, code=1)["issue"] == "store_busy", "exclusive lease busy")
                    if kill:
                        child.kill()
                        child.communicate(timeout=15)
                    else:
                        added.touch()
                        stdout, _ = child.communicate(input=b"continue\n", timeout=20)
                        failed = json.loads(stdout)
                        check(child.returncode == 1 and failed["issue"] == "store_file_namespace_changed" and not failed["next_file_cursor"], "namespace change discards read")
            finally:
                added.unlink(missing_ok=True)
            check(window(root, 1, cursor)["next_file_cursor"] == next_page["next_file_cursor"], "retry acknowledged position after interruption")

        with observed(root, ["/file-receipt", receipt, "/retention"], b"file_inventory_hashed") as child:
            added.touch()
            stdout, _ = child.communicate(input=b"continue\n", timeout=20)
            failed = json.loads(stdout)
            check(child.returncode == 1 and failed["issue"] == "store_file_namespace_changed" and not failed["artifact_inventory_complete"]
                  and failed["collection_retention"]["status"] != "verified", "late namespace change withholds global and retention result")
            added.unlink()

        saved = blob.stat()
        with handle(blob) as h:
            generation = ctypes.create_string_buffer(info(h, 0, 40))
        with blob.open("r+b") as stream:
            stream.write(b"Z")
        os.utime(blob, ns=(saved.st_atime_ns, saved.st_mtime_ns))
        check(window(root, 1, cursor, 1)["issue"] == "store_file_cursor_mismatch" and run(root, "/file-receipt", receipt, code=1)["issue"] == "store_file_receipt_mismatch",
              "same-size rewrite with restored write time")
        with handle(blob, access=0x100) as h:
            assert kernel.SetFileInformationByHandle(h, 0, generation, 40)
        check(namespace(root)[0] == scope and window(root, 1, cursor)["next_file_cursor"] == next_page["next_file_cursor"], "previous range remains historical after metadata restoration")
        check(run(root, "/file-receipt", receipt, code=1)["issue"] == "store_file_bytes_mismatch", "changed earlier bytes with exactly restored file generation")
        old = refs / "retained"
        blob.rename(old)
        blob.write_bytes(raw)
        old.unlink()
        check(window(root, 1, cursor, 1)["issue"] == "store_file_cursor_mismatch", "same path and restored bytes with replaced identity")
        blob.rename(blob.with_suffix(".KNBLOB"))
        check(run(root, "/file-receipt", cover(root, [3]))["status"] == "verified", "upper-case source path")
        target = sandbox / "outside-target"
        target.mkdir()
        (target / "outside.dat").write_bytes(b"outside")
        link = refs / "linked"
        _winapi.CreateJunction(str(target), str(link))
        gaps = {"image-references/linked": "nonregular_entry", "image-references/empty.knblob": "file_size_outside_format", "image-references/unknown-\uac00": "unmanaged_format",
                "image-references/directory": "nonregular_entry", "irp-pending": "unmanaged_format", "image-reads/large.knreads": "file_size_outside_format"}
        (refs / "empty.knblob").touch()
        (refs / "unknown-\uac00").write_bytes(b"private")
        (refs / "directory").mkdir()
        (root / "irp-pending").touch()
        (root / "image-reads").mkdir()
        with (root / "image-reads/large.knreads").open("wb") as stream:
            stream.truncate(2*1024*1024+1)
        partial = run(root, "/file-receipt", cover(root, [1, 3], gaps), code=1)
        check(partial["status"] == "partial" and not partial["artifact_inventory_complete"] and int(partial["unverified_artifact_files"]) == len(gaps), "gaps stay protected in full inventory")
        link.rmdir()

        empty = sandbox / "empty"
        empty.mkdir()
        empty_receipt = cover(empty, [1])
        check(run(empty, "/file-receipt", empty_receipt)["status"] == "verified", "empty store")
        (empty / "image-references").mkdir()
        check(run(empty, "/file-receipt", empty_receipt, code=1)["issue"] == "store_file_receipt_mismatch", "absent versus existing physical folder")
        managed_link = empty / "image-reads"
        _winapi.CreateJunction(str(target), str(managed_link))
        check(window(empty, 1, code=1)["issue"] == "store_file_directory_unavailable", "managed directory junction refused")
        managed_link.rmdir()
        for flags in [("/scan-files", "/artifacts"), ("/scan-files", "/scan-catalog"), ("/scan-files", "/limit", "0"), ("/scan-files", "/limit", "1025"),
                      ("/scan-files", "/file-receipt", receipt), ("/scan-files", "/retention"), ("/file-receipt",), ("/file-receipt", receipt, "/file-receipt", receipt)]:
            check(run(empty, *flags, code=2) is None, "invalid options")
        case = run(empty, "/SCAN-FILES", "/LIMIT", "1")
        check(case["status"] == "complete", "case independent flags")

        mixed = sandbox / "mixed"
        for identifier in ("5", "31"):
            subprocess.run([writer, "--produce-collection", mixed, identifier], capture_output=True, check=True, timeout=90)
        file_receipt = cover(mixed, [2, 9])
        catalog = run(mixed, "/scan-catalog", "/limit", "2")["scan_receipt"]
        combined = ["/scan-receipt", catalog, "/file-receipt", file_receipt, "/retention", "/artifacts"]
        detail = run(mixed, *combined, "/limit", "1")
        fresh = run(mixed, "/retention", "/artifacts")
        check(all(detail[key] == fresh[key] for key in ("catalog_sha256", "artifacts_sha256", "read_bytes", "unique_content_bytes", "unique_path_bytes",
                  "committed_segments", "logical_reference_bytes")) and int(detail["logical_reference_bytes"]) > int(detail["unique_content_bytes"]), "combined full receipts and shared originals")
        second = run(mixed, *combined, "/limit", "1", "/cursor", detail["next_artifact_cursor"])
        check(second["artifact_row_offset"] == "1" and second["collection_retention"]["status"] == "verified", "both receipts, retention and detail paging")

        page_json.write_text(json.dumps(fresh), encoding="utf-8")
        retire_helper = list(helper)
        retire_helper[retire_helper.index("--retire-collection") + 1] = "5"
        subprocess.run(retire_helper, capture_output=True, check=True)
        retire = [exe, "--offline", "!kmon", "retire-collection", mixed, policy, "/apply"] if args.cli else [exe, "--retire-collection", mixed, policy, "apply"]
        subprocess.run(retire, capture_output=True, check=True, timeout=60)
        retired = run(mixed, "/artifacts")
        name = next(row["artifact"]["path"] for row in retired["artifacts"] if row["retention"] == "retired_requires_policy")
        withdrawn = sandbox / "withdrawn"
        (mixed / name).rename(withdrawn)
        missing_receipt = cover(mixed, [64])
        check(run(mixed, "/file-receipt", missing_receipt)["retired_absent_paths"] == "1", "one retired original absent under a stable lease")
        with observed(mixed, ["/file-receipt", missing_receipt], b"file_inventory_hashed") as child:
            withdrawn.rename(mixed / name)
            stdout, _ = child.communicate(input=b"continue\n", timeout=20)
            late = json.loads(stdout)
            check(child.returncode == 1 and late["issue"] == "store_file_namespace_changed" and late["retired_absent_paths"] == "0"
                  and int(late["retired_unobserved_paths"]) >= 1, "invalidated inventory withdraws retired absence count")
        if args.large:
            large = sandbox / "large"
            reads = large / "image-reads"
            reads.mkdir(parents=True)
            data = b'{"schema":"kn.image_read_session.v1"}'.ljust(2*1024*1024)
            base = reads / "session-1.knreadledger"
            base.write_bytes(data)
            for n in range(2, 514):
                os.link(base, reads / f"session-{n}.knreadledger")
            default = run(large, code=1)
            check(default["read_bytes"] == str(512*len(data)) and default["unverified_artifact_files"] == "1", "default reader byte ceiling")
            finished = cover(large, [1024, 731], shared=data)
            expanded = run(large, "/file-receipt", finished, "/artifacts", "/limit", "1")
            check(expanded["status"] == "verified" and expanded["observed_artifact_files"] == "513" and expanded["unverified_artifact_files"] == "0"
                  and int(expanded["read_bytes"]) == int(expanded["verified_unattributed_bytes"]) == 513*len(data), "all 513 named originals re-read in one bounded inventory")
    print(f"[store.files] checks={checks} large={args.large} product={args.cli}")


if __name__ == "__main__":
    main()
