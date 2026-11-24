"""Exercise the offline inventory CLI across processes and reconstruct its publications from original bytes."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import time
import unittest


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_profile_signature(frame, signature):
    ncrypt = ctypes.WinDLL("ncrypt")
    handle = ctypes.c_size_t
    pointer = ctypes.POINTER(handle)
    ncrypt.NCryptOpenStorageProvider.argtypes = [pointer, wintypes.LPCWSTR, wintypes.DWORD]
    ncrypt.NCryptOpenKey.argtypes = [handle, pointer, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    ncrypt.NCryptVerifySignature.argtypes = [handle, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    ncrypt.NCryptFreeObject.argtypes = [handle]
    provider, key = handle(), handle()
    try:
        if ncrypt.NCryptOpenStorageProvider(ctypes.byref(provider), "Microsoft Software Key Storage Provider", 0):
            raise RuntimeError("cannot open Windows software key provider")
        if ncrypt.NCryptOpenKey(provider, ctypes.byref(key), "KnLiveDbg.InventoryVerification.v1", 0, 0x40):
            raise RuntimeError("cannot open inventory verification key")
        hashed = hashlib.sha256(frame).digest()
        return ncrypt.NCryptVerifySignature(key, None, hashed, len(hashed), signature, len(signature), 0) == 0
    finally:
        if key.value:
            ncrypt.NCryptFreeObject(key)
        if provider.value:
            ncrypt.NCryptFreeObject(provider)


def ledger(number):
    return encode(dict(schema="kmon.evidence_session.v1", scope="attempted_hunt_bundle_publications", closed=True,
                       collection_id=f"owned-{number}", admitted="0", written="0", failed="0", dropped="0", bytes="0"))


class InventoryTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="kn-inventory-", dir=ARGS.work_dir)
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.source = self.root / "cases"
        self.source.mkdir()
        self.output = self.root / "index"

    def command(self, output=None, source=None, cli=None):
        return [str(cli or ARGS.cli), "--offline", "!kmon", "inventory",
                str(source or self.source), str(output or self.output)]

    def build(self, *args, output=None, source=None, status="ok", code=0):
        completed = subprocess.run(self.command(output, source) + list(args), capture_output=True, timeout=140)
        self.assertEqual(completed.returncode, code, (completed.stdout[-400:], completed.stderr[-400:]))
        if code == 2:
            return
        data = json.loads(completed.stdout)
        self.assertEqual(data["status"], status)
        return data

    def fill(self, count):
        for i in reversed(range(count)):
            (self.source / f"entry-{i:05}.knledger").write_bytes(ledger(i))

    def checkpoint(self):
        result = self.build("/resume", "/chunks", "1", status="checkpointed")
        self.assertEqual((result["entries"], result["reused_entries"], result["verified_entries"]), ("128", "0", "0"))
        self.assertFalse((self.output / "manifest.knindex").exists())
        return self.output / "window-0.knindex"

    def query(self, cli, *args):
        completed = subprocess.run([str(cli), "--offline", "!kmon", "evidence", str(self.source),
                                    "/inventory", str(self.output), *args, "/json"], capture_output=True, timeout=140)
        data = json.loads(completed.stdout)
        self.assertIn(data["status"], ("ok", "partial_inventory"))
        self.assertEqual(completed.returncode, 0 if data["status"] == "ok" else 1)
        return data

    def closure(self, *options, code=0, source=None, index=None):
        command = [str(ARGS.cli), "--offline", "!kmon", "evidence", str(source or self.source),
                   "/inventory", str(index or self.output), "/closure", *options]
        run = subprocess.run(command, capture_output=True, timeout=240)
        self.assertEqual(run.returncode, code, (run.stdout[-500:], run.stderr[-300:]))
        if code == 2:
            return
        report = json.loads(run.stdout)
        self.assertEqual(report["schema"], "kn.evidence_inventory_closure.v1")
        self.assertIs(report["collector_authenticated"], False)
        return report

    def test_global_closure_across_result_windows(self):
        # Use the preceding publisher if supplied. Each ledger is valid even at UINT64_MAX.
        maximum = 2**64 - 1
        wide = []
        for name in ("first", "middle", "last"):
            item = json.loads(ledger(name))
            item.update(admitted=str(maximum), failed=str(maximum), dropped=str(maximum))
            wide.append(encode(item))
        (self.source / "first.knledger").write_bytes(wide[0])
        (self.source / "middle.knledger").write_bytes(wide[1])
        for i in range(4100):
            (self.source / f"row-{i:04}.knledger").write_bytes(ledger(i))
        (self.source / "y-copy.knledger").write_bytes(b"\xef\xbb\xbf" + wide[0])
        (self.source / "z-last.knledger").write_bytes(wide[2])
        published = subprocess.run(self.command(cli=ARGS.legacy) + ["/json"], capture_output=True, timeout=140)
        self.assertEqual(published.returncode, 0, published.stdout[-400:])
        self.assertFalse(self.query(ARGS.cli)["publication_closure_evaluated"])
        (self.source / "later.knledger").write_bytes(ledger("outside-index"))
        report = self.closure("/json")
        self.assertEqual((report["status"], report["snapshot_entries"], report["inspected_files"]), ("ok", "4104", "4104"))
        manifest = self.output / "manifest.knindex"
        self.assertEqual(report["snapshot_sha256"], digest(manifest.read_bytes()))
        assessment = report["assessment"]
        self.assertEqual((assessment["publication_closure_known"], assessment["ledger_files"], assessment["duplicate_ledger_files"]),
                         (True, "4104", "1"))
        totals = assessment["unambiguous_ledger_totals"]
        self.assertEqual(totals, dict(collections="4103", admitted=str(3 * maximum), written="0", failed=str(3 * maximum),
                                      dropped=str(3 * maximum), reported_bytes="0", observed_canonical_bytes="0",
                                      byte_mismatch_collections="0", unavailable_written_bundles="0", unexpected_bundles="0"))
        read_bytes = sum(p.stat().st_size for p in self.source.iterdir() if p.name != "later.knledger")
        self.assertEqual(int(report["read_bytes"]), read_bytes)
        limit = self.closure("/max-bytes", str(read_bytes - 1), code=1)
        self.assertEqual((limit["status"], limit["assessment"]), ("budget_exhausted", None))
        self.assertLess(int(limit["read_bytes"]), read_bytes)
        self.assertEqual(self.closure("/max-bytes", str(read_bytes))["assessment"], assessment)
        expired = self.closure("/deadline-ms", "1", code=1)
        self.assertEqual((expired["status"], expired["assessment"]), ("deadline_exhausted", None))

    def test_global_conflicts_missing_and_invalid(self):
        original = json.loads(ledger("conflict"))
        other = dict(original, dropped="2")
        for i, record in enumerate((original, other, other, original)):
            (self.source / f"conflict-{i}.knledger").write_bytes(encode(record))
        clean = json.loads(ledger("independent"))
        clean.update(admitted="2", written="1", failed="1", dropped="3", bytes="220")
        (self.source / "kept.knledger").write_bytes(encode(clean))
        (self.source / "removed.knledger").write_bytes(ledger("removed"))
        (self.source / "replaced.knledger").write_bytes(ledger("old"))
        (self.source / "invalid.kncase").write_bytes(b"invalid")
        self.build("/resume")
        (self.source / "removed.knledger").unlink()
        (self.source / "replaced.knledger").write_bytes(ledger("new"))
        result = self.closure(code=1)
        a = result["assessment"]
        self.assertEqual((result["status"], a["publication_closure_known"], a["invalid_at_build"],
                          a["changed_or_missing"], a["conflicting_collections"], a["duplicate_ledger_files"]),
                         ("partial_inventory", False, "1", "2", "1", "2"))
        totals = a["unambiguous_ledger_totals"]
        self.assertEqual((totals["collections"], totals["written"], totals["failed"], totals["dropped"],
                          totals["unavailable_written_bundles"], totals["byte_mismatch_collections"]), ("1", "1", "1", "3", "1", "1"))
        empty = self.root / "different-source"
        empty.mkdir()
        denied = self.closure(source=empty, code=1)
        self.assertEqual((denied["status"], denied["assessment"]), ("source_directory_changed", None))

    def test_global_membership_and_incomplete_work(self):
        self.fill(129)
        self.checkpoint()
        partial = self.closure(code=1)
        self.assertEqual((partial["status"], partial["assessment"]), ("invalid_inventory", None))
        self.build("/resume")
        manifest = self.output / "manifest.knindex"
        initial = json.loads(manifest.read_bytes())
        head, tail = initial["chunks"]
        member = self.output / (tail["digest"] + ".knchunk")
        self.assertTrue(member.exists())
        member.rename(self.root / "saved-chunk")
        truncated = self.closure(code=1)
        self.assertEqual((truncated["status"], truncated["inspected_files"], truncated["assessment"]), ("corrupt_inventory_chunk", "128", None))
        rows = json.loads((self.output / (head["digest"] + ".knchunk")).read_bytes())
        row = dict(rows["entries"][0])
        for name, status in ((row["name"], "duplicate_inventory_name"), (row["name"].replace("entry", "ENTRY"), "partial_inventory")):
            changed = encode(dict(schema=rows["schema"], entries=[dict(row, name=name)]))
            key = digest(changed)
            (self.output / (key + ".knchunk")).write_bytes(changed)
            tail["digest"] = key
            manifest.write_bytes(encode(initial))
            report = self.closure(code=1)
            self.assertEqual(report["status"], status)
            if status == "partial_inventory":
                self.assertEqual(report["assessment"]["changed_or_missing"], "1")
            else:
                self.assertIsNone(report["assessment"])
        for args in (("/pid", "1"), ("/role", "x"), ("/limit", "1"), ("/cursor", "x"), ("/inventory-cursor", "x"),
                     ("/closure",), ("/max-bytes", "0"), ("/max-bytes", "-1"), ("/deadline-ms", "1", "/deadline-ms", "1"),
                     ("/max-bytes", "18446744073709551616")):
            self.closure(*args, code=2)

    def test_global_empty_inventory_and_held_writer(self):
        self.build("/resume")
        empty = self.closure(code=1)
        self.assertEqual((empty["snapshot_entries"], empty["assessment"]["publication_closure_known"]), ("0", False))
        member = self.source / "active.knledger"
        member.write_bytes(ledger("stable"))
        index = self.root / "active-index"
        self.build("/resume", output=index)
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in index.iterdir()}
        with member.open("r+b"):
            blocked = self.closure(index=index, code=1)
            self.assertEqual((blocked["read_bytes"], blocked["assessment"]["changed_or_missing"]), ("0", "1"))
        ready = self.closure(index=index)
        self.assertTrue(ready["assessment"]["publication_closure_known"])
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in index.iterdir()})

    def test_windows_and_legacy_reader(self):
        self.fill(300)
        bom_file = self.source / "entry-00001.knledger"
        bom_file.write_bytes(b"\xef\xbb\xbf" + bom_file.read_bytes())
        (self.source / "empty.knledger").write_bytes(b"")
        (self.source / "invalid.kncase").write_bytes(b"\xff\x01")
        (self.source / "메모.knledger").write_bytes(ledger(301))
        (self.source / "notes.txt").write_bytes(b"outside membership")
        files = sorted((p for p in self.source.iterdir() if p.suffix in (".kncase", ".knledger")), key=lambda p: p.name)
        rows, witnesses, sizes = [], [], []
        for path in files:
            raw = path.read_bytes()
            valid = path.suffix == ".knledger" and bool(raw)
            normalized = raw.removeprefix(b"\xef\xbb\xbf")
            rows.append(dict(name=path.name, digest=digest(normalized) if valid else "", bytes=str(len(raw)), valid=valid))
            witnesses.append(digest(raw) if raw else "")
            sizes.append(len(raw))
        first = self.checkpoint()
        original_time = first.stat().st_mtime_ns
        second = self.build("/chunks", "1", "/json", "/resume", status="checkpointed")
        self.assertEqual((second["entries"], second["reused_entries"], int(second["read_bytes"])),
                         ("256", "128", sum(sizes[128:256])))
        final = self.build("/resume", "/chunks", "1")
        self.assertEqual((final["entries"], final["reused_entries"], final["verified_entries"], final["invalid_files"]),
                         ("303", "256", "303", "2"))
        self.assertEqual(int(final["read_bytes"]), sum(sizes) + sum(sizes[256:]))
        self.assertEqual(first.stat().st_mtime_ns, original_time)
        header = (self.output / "build.knindex").read_bytes()
        previous = digest(header)
        chunks = []
        for start in range(0, len(files), 128):
            window = rows[start:start + 128]
            chunk = encode(dict(schema="kn.evidence_inventory_chunk.v1", entries=window))
            chunk_hash = digest(chunk)
            self.assertEqual((self.output / (chunk_hash + ".knchunk")).read_bytes(), chunk)
            raw_hash = digest("".join(s + "\n" for s in witnesses[start:start + 128]).encode())
            record = encode(dict(schema="kn.evidence_inventory_window.v1", previous_sha256=previous, offset=str(start),
                                 entries=str(len(window)), chunk_sha256=chunk_hash, originals_sha256=raw_hash))
            self.assertEqual((self.output / f"window-{start}.knindex").read_bytes(), record)
            previous = digest(record)
            chunks.append(dict(digest=chunk_hash, entries=str(len(window))))
        manifest = encode(dict(schema="kn.evidence_inventory.v1", capture="non_atomic_directory_walk",
                               directory_id=json.loads(header)["source_id"], entries=str(len(files)), chunks=chunks))
        self.assertEqual((self.output / "manifest.knindex").read_bytes(), manifest)
        self.assertEqual(final["snapshot_digest"], digest(manifest))
        for cli in [ARGS.cli] + ([ARGS.legacy] if ARGS.legacy else []):
            query = self.query(cli)
            self.assertTrue(query["inventory_complete"])
            self.assertEqual((query["snapshot_digest"], query["inspected_files"], query["invalid_files"]),
                             (digest(manifest), len(files), 2))
        before = {p.name: (p.stat().st_mtime_ns, digest(p.read_bytes())) for p in self.output.iterdir()}
        again = self.build("/resume")
        self.assertEqual((again["reused_entries"], again["verified_entries"], int(again["read_bytes"])),
                         ("303", "303", sum(sizes)))
        self.assertEqual({p.name: (p.stat().st_mtime_ns, digest(p.read_bytes())) for p in self.output.iterdir()}, before)
        self.build("/json", status="output_exists_or_unavailable", code=1)

    def test_ordinary_create_new_compatibility(self):
        self.fill(6)
        (self.source / "invalid.kncase").write_bytes(b"malformed")
        current = subprocess.run(self.command() + ["/json"], check=True, capture_output=True, timeout=140)
        report = json.loads(current.stdout)
        self.assertEqual((report["schema"], report["entries"], report["invalid_files"]),
                         ("kn.evidence_inventory_build.v1", "7", "1"))
        self.assertFalse((self.output / "build.knindex").exists())
        self.build("/resume", status="resume_marker_missing", code=1)
        if ARGS.legacy:
            previous = self.root / "ordinary-old"
            old = subprocess.run(self.command(previous, cli=ARGS.legacy) + ["/json"], check=True, capture_output=True, timeout=140)
            self.assertEqual(current.stdout, old.stdout)
            self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()},
                             {p.name: p.read_bytes() for p in previous.iterdir()})

    def test_bounded_original_windows(self):
        self.fill(270)
        member = self.source / "entry-00002.knledger"
        member.write_bytes(b"\xef\xbb\xbf" + member.read_bytes())
        (self.source / "entry-00040.knledger").write_bytes(b"")
        (self.source / "entry-00128.knledger").write_bytes(b"\xff")
        originals = [p.read_bytes() for p in sorted(self.source.iterdir())]
        sizes = list(map(len, originals))
        image = digest(ARGS.cli.read_bytes())
        writer = ARGS.legacy or ARGS.cli
        options = ["/resume", "/chunks", "1"]
        first = subprocess.run(self.command(cli=writer) + options, capture_output=True, timeout=140)
        if ARGS.legacy and first.returncode == 2:
            # Earlier v1 readers can query the published manifest but predate resumable construction.
            self.assertFalse(self.output.exists())
            writer = ARGS.cli
            first = subprocess.run(self.command(cli=writer) + options, capture_output=True, timeout=140)
        self.assertEqual(first.returncode, 0, first.stderr[-400:])
        self.assertEqual(json.loads(first.stdout)["entries"], "128")
        offset = 0
        manifest = self.output / "manifest.knindex"
        for limit in (37, 70, 55, 108):
            end = offset + limit
            result = self.build("/resume", "/verify-entries", str(limit), "/chunks", "4", "/json",
                                status="ok" if end == len(sizes) else "checkpointed")
            self.assertEqual((int(result["entries"]), int(result["verify_entry_limit"]), int(result["verified_entries"]),
                              int(result["reused_verified_entries"])), (len(sizes), limit, end, offset))
            self.assertEqual(int(result["read_bytes"]), sum(sizes[offset:end]) + (sum(sizes[128:]) if not offset else 0))
            self.assertEqual(bool(result["snapshot_digest"]), end == len(sizes))
            self.assertEqual(manifest.exists(), end == len(sizes))
            prefix = "" if end == len(sizes) else "".join((digest(data) if data else "") + "\n"
                for data in originals[end - end % 128:end])
            proof = json.loads((self.output / f"verify-{end}.knindex").read_bytes())
            self.assertEqual((int(proof["verified_through"]), proof["raw_witness_prefix"]), (end, prefix))
            chain = digest((self.output / "window-256.knindex").read_bytes())
            frame = f"KnLiveDbg.inventory.verification.v1\n{image}\n{chain}\n{end}\n{prefix}".encode()
            signature = bytes.fromhex(proof["verification_seal"])
            self.assertTrue(verify_profile_signature(frame, signature))
            self.assertFalse(verify_profile_signature(frame + b"\n", signature))
            if end == 37:
                pending = self.output / "verify-270.knindex.pending-11-1-1"
                pending.write_bytes(b"{")
            offset = end
        self.assertEqual(pending.read_bytes(), b"{")
        again = self.build("/resume", "/verify-entries", "1")
        self.assertEqual((int(again["reused_verified_entries"]), int(again["read_bytes"])), (len(sizes), 0))
        ordinary = self.build("/resume")
        self.assertEqual((ordinary["snapshot_digest"], int(ordinary["read_bytes"])), (again["snapshot_digest"], sum(sizes)))
        fresh = self.root / "fresh"
        subprocess.run(self.command(output=fresh, cli=writer) + ["/resume"], capture_output=True, check=True, timeout=140)
        self.assertEqual((fresh / manifest.name).read_bytes(), manifest.read_bytes())
        self.assertEqual(self.query(ARGS.legacy or ARGS.cli)["snapshot_digest"], again["snapshot_digest"])
        proof = (self.output / "verify-37.knindex").read_bytes()
        audit = runpy.run_path(str(Path(__file__).with_name("validate-public-content.py")))["inspect"]
        for text in (proof, b"diagnostic\n" + proof[:-1], proof.decode().encode("utf-16-be")):
            self.assertTrue(audit("renamed.txt", text))
        manifest.write_bytes(b"occupied")
        self.build("/resume", "/verify-entries", "1", status="manifest_mismatch", code=1)
        self.assertEqual(manifest.read_bytes(), b"occupied")

    def test_verification_seal_and_raw_prefix(self):
        self.fill(145)
        self.build("/resume", "/verify-entries", "17", status="checkpointed")
        path = self.output / "verify-17.knindex"
        data = path.read_bytes()
        other = self.root / "other"
        self.build("/resume", "/verify-entries", "17", output=other, status="checkpointed")
        edited = json.loads(data)
        seal = edited["verification_seal"]
        edited["verification_seal"] = seal[:-2] + f"{int(seal[-2:], 16) ^ 1:02x}"
        wrong_prefix = dict(json.loads(data), raw_witness_prefix=("0" * 64 + "\n") * 17)
        for raw in (encode(edited), encode(wrong_prefix), data[:-1], (other / path.name).read_bytes()):
            path.write_bytes(raw)
            self.build("/resume", "/verify-entries", "145", status="invalid_verification_checkpoint", code=1)
        path.write_bytes(data)
        jump = self.output / "verify-145.knindex"
        jump.write_bytes(encode(dict(json.loads(data), verified_through="145")))
        self.build("/resume", "/verify-entries", "145", status="invalid_verification_checkpoint", code=1)
        jump.unlink()
        # Recompute every unkeyed link. The existing protected prefix must fail in this new chain.
        window = self.output / "window-0.knindex"
        original = json.loads(window.read_bytes())
        window.write_bytes(encode(dict(original, originals_sha256=digest(b"different original bytes"))))
        tail = self.output / "window-128.knindex"
        tail.write_bytes(encode(dict(json.loads(tail.read_bytes()), previous_sha256=digest(window.read_bytes()))))
        self.build("/resume", "/verify-entries", "145", status="invalid_verification_checkpoint", code=1)
        path.unlink()
        self.build("/resume", "/verify-entries", "111", status="checkpointed")
        self.build("/resume", "/verify-entries", "34", status="original_mismatch", code=1)
        self.assertFalse((self.output / "verify-128.knindex").exists())
        self.assertFalse((self.output / "manifest.knindex").exists())

    def test_verified_member_replacement(self):
        self.fill(131)
        self.build("/resume", "/verify-entries", "128", status="checkpointed")
        path = self.source / "entry-00001.knledger"
        replacement = self.root / "replacement"
        shutil.copy2(path, replacement)
        self.assertNotEqual(path.stat().st_ino, replacement.stat().st_ino)
        os.replace(replacement, path)
        self.build("/resume", "/verify-entries", "3", status="resume_scope_mismatch", code=1)
        self.assertFalse((self.output / "manifest.knindex").exists())

    def test_change_after_signed_window(self):
        self.fill(1536)
        self.build("/resume", "/verify-entries", "1", status="checkpointed")
        path = self.source / "entry-00000.knledger"
        replacement = self.root / "copy"
        shutil.copy2(path, replacement)
        with subprocess.Popen(self.command() + ["/resume", "/verify-entries", "1536"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                deadline = time.monotonic() + 60
                while not (self.output / "verify-128.knindex").exists():
                    self.assertIsNone(child.poll(), "no signed window before exit")
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.001)
                os.replace(replacement, path)
                stdout, stderr = child.communicate(timeout=140)
                self.assertEqual(child.returncode, 1, stderr[-400:])
                report = json.loads(stdout)
                self.assertEqual((report["status"], report["verified_entries"], report["snapshot_digest"]),
                                 ("source_changed", "1536", ""))
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=15)
        self.assertTrue((self.output / "verify-1536.knindex").is_file())
        self.build("/resume", "/verify-entries", "1536", status="resume_scope_mismatch", code=1)
        self.assertFalse((self.output / "manifest.knindex").exists())

    def test_termination_after_verification_receipt(self):
        self.fill(1536)
        self.build("/resume", "/verify-entries", "1", status="checkpointed")
        with subprocess.Popen(self.command() + ["/resume", "/verify-entries", "1536"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                deadline = time.monotonic() + 60
                while not (self.output / "verify-128.knindex").is_file():
                    self.assertIsNone(child.poll(), "writer exited before the first full raw-witness check")
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.001)
                child.kill()
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=15)
        self.assertFalse((self.output / "manifest.knindex").exists())
        saved = {int(p.stem.split("-")[1]): (p.stat().st_mtime_ns, digest(p.read_bytes()))
                 for p in self.output.glob("verify-*.knindex")}
        offset = max(saved)
        self.assertGreaterEqual(offset, 128)
        self.assertLess(offset, 1536)
        result = self.build("/resume", "/verify-entries", "1536")
        self.assertEqual((int(result["verified_entries"]), int(result["reused_verified_entries"])), (1536, offset))
        self.assertEqual(int(result["read_bytes"]), sum(len(ledger(i)) for i in range(offset, 1536)))
        for end, receipt in saved.items():
            path = self.output / f"verify-{end}.knindex"
            self.assertEqual((path.stat().st_mtime_ns, digest(path.read_bytes())), receipt)

    def test_original_payload_above_eight_gib(self):
        if not ARGS.large_case:
            self.skipTest("supply a synthetic --large-case to exercise more than 8 GiB of original reads")
        data = ARGS.large_case.read_bytes()
        member_size = len(data)
        self.assertGreaterEqual(member_size, 1024**2, "use the case emitted by evidence-bundle-selftest --publish")
        self.assertLessEqual(member_size, 2 * 1024**2)
        count = (8 * 1024**3) // member_size + 1
        value = json.loads(data)["payload_sha256"]
        names = [f"member-{i:05}.kncase" for i in range(count)]
        for i, name in enumerate(names):
            path = self.source / name
            if i % 900 == 0:
                path.write_bytes(data)
                anchor = path
            else:
                os.link(anchor, path)
        entries = verified = reads = 0
        for calls in range(1, 2 * ((count + 511) // 512) + 2):
            proc = subprocess.run(self.command() + ["/resume", "/chunks", "4", "/verify-entries", "512"],
                                  capture_output=True, timeout=150)
            self.assertEqual(proc.returncode, 0, (proc.stdout[-600:], proc.stderr[-400:]))
            result = json.loads(proc.stdout)
            now, checked = int(result["entries"]), int(result["verified_entries"])
            self.assertEqual((int(result["reused_entries"]), int(result["reused_verified_entries"])), (entries, verified))
            self.assertGreater(now + checked, entries + verified)
            self.assertEqual(int(result["read_bytes"]), (now - entries + checked - verified) * member_size)
            self.assertLessEqual(int(result["read_bytes"]), 8 * 1024**3)
            self.assertEqual(result["invalid_files"], "0")
            entries, verified, reads = now, checked, reads + int(result["read_bytes"])
            if result["status"] == "ok":
                break
            self.assertEqual(result["status"], "checkpointed")
            self.assertFalse((self.output / "manifest.knindex").exists())
        self.assertEqual((entries, verified, reads), (count, count, 2 * count * member_size))
        chunks = []
        for i in range(0, count, 128):
            rows = [dict(name=name, digest=value, bytes=str(member_size), valid=True) for name in names[i:i + 128]]
            raw = encode(dict(schema="kn.evidence_inventory_chunk.v1", entries=rows))
            self.assertEqual((self.output / (digest(raw) + ".knchunk")).read_bytes(), raw)
            chunks.append(dict(digest=digest(raw), entries=str(len(rows))))
        source_id = json.loads((self.output / "build.knindex").read_bytes())["source_id"]
        manifest = encode(dict(schema="kn.evidence_inventory.v1", capture="non_atomic_directory_walk",
                               directory_id=source_id, entries=str(count), chunks=chunks))
        self.assertEqual((self.output / "manifest.knindex").read_bytes(), manifest)
        self.assertEqual(result["snapshot_digest"], digest(manifest))
        full = self.closure("/max-bytes", str(count * member_size), "/deadline-ms", "240000", code=1)
        self.assertEqual((full["status"], int(full["read_bytes"]), full["assessment"]["unique_bundles"],
                          int(full["assessment"]["duplicate_case_files"]), full["assessment"]["publication_closure_known"]),
                         ("partial_inventory", count * member_size, "1", count - 1, False))
        print(f"large inventory: members={count} calls={calls} original_bytes={count * member_size} read_bytes={reads}", flush=True)

    def test_global_case_and_publication_bytes(self):
        if not ARGS.large_case:
            self.skipTest("supply the synthetic case emitted by evidence-bundle-selftest --publish")
        base = json.loads(ARGS.large_case.read_bytes())
        payload = base["payload"]
        self.assertEqual(base["schema"], "kmon.bundle.v1")
        payload["collection_id"] = "closure-owned"
        base["payload_sha256"] = digest(encode(payload))
        canonical = encode(base)
        first = self.source / "case-0000.kncase"
        first.write_bytes(canonical)
        count = 260
        for i in range(1, count - 1):
            os.link(first, self.source / f"case-{i:04}.kncase")
        (self.source / "case-bom.kncase").write_bytes(b"\xef\xbb\xbf" + canonical)
        record = dict(json.loads(ledger(0)), collection_id=payload["collection_id"], admitted="3", written="1",
                      failed="2", dropped="1", bytes=str(len(canonical)))
        (self.source / "last.knledger").write_bytes(encode(record))
        self.build("/resume")
        head = self.query(ARGS.cli)
        tail = self.query(ARGS.cli, "/inventory-cursor", head["next_inventory_cursor"])
        self.assertFalse(head["publication_closure_evaluated"] or tail["publication_closure_evaluated"])
        # Terminate our reader after its I/O counters advance by 64 MiB.
        # Probing the manifest with a writer would race the reader's admission.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ("read_operations", "write_operations", "other_operations", "read_bytes", "write_bytes", "other_bytes")]
        kernel.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IoCounters)]
        counters = IoCounters()
        index_before = {p.name: (digest(p.read_bytes()), p.stat().st_mtime_ns) for p in self.output.iterdir()}
        command = [str(ARGS.cli), "--offline", "!kmon", "evidence", str(self.source), "/inventory", str(self.output), "/closure"]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                self.assertTrue(kernel.GetProcessIoCounters(int(child._handle), ctypes.byref(counters)))
                target_reads = counters.read_bytes + 64 * 1024**2
                deadline = time.monotonic() + 45
                while counters.read_bytes < target_reads:
                    self.assertIsNone(child.poll(), "reader finished before observed I/O")
                    self.assertLess(time.monotonic(), deadline)
                    self.assertTrue(kernel.GetProcessIoCounters(int(child._handle), ctypes.byref(counters)))
                    time.sleep(0.001)
                child.kill()
                stdout, _ = child.communicate(timeout=15)
                self.assertNotEqual(child.returncode, 0)
                self.assertEqual(stdout, b"")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=15)
        self.assertEqual(index_before, {p.name: (digest(p.read_bytes()), p.stat().st_mtime_ns) for p in self.output.iterdir()})
        report = self.closure()
        a = report["assessment"]
        self.assertEqual((report["status"], a["publication_closure_known"], a["unique_bundles"], int(a["duplicate_case_files"])),
                         ("ok", True, "1", count - 1))
        self.assertEqual(int(report["read_bytes"]), len(canonical) * count + 3 + len(encode(record)))
        self.assertEqual(a["unambiguous_ledger_totals"]["observed_canonical_bytes"], str(len(canonical)))
        # A different, valid ledger can agree on the file count but disagree on what was written.
        (self.source / "last.knledger").write_bytes(encode(dict(record, bytes=str(len(canonical) + 1))))
        second_index = self.root / "second-index"
        self.build("/resume", output=second_index)
        a = self.closure(index=second_index, code=1)["assessment"]
        self.assertFalse(a["publication_closure_known"])
        self.assertEqual((a["unambiguous_ledger_totals"]["byte_mismatch_collections"],
                          a["unambiguous_ledger_totals"]["unavailable_written_bundles"]), ("1", "0"))
        (self.source / "last.knledger").unlink()
        missing = self.closure(index=second_index, code=1)["assessment"]
        self.assertEqual((missing["collections_without_ledger"], missing["unattributed_bundles"],
                          missing["changed_or_missing"], missing["publication_closure_known"]), ("1", "0", "1", False))

    def test_source_and_output_generations(self):
        self.fill(145)
        self.checkpoint()
        other = self.root / "other"
        shutil.copytree(self.output, other)
        self.build("/resume", output=other, status="resume_scope_mismatch", code=1)
        other_source = self.root / "other-source"
        shutil.copytree(self.source, other_source)
        self.build("/resume", source=other_source, status="resume_scope_mismatch", code=1)
        added = self.source / "later.knledger"
        added.write_bytes(ledger(999))
        self.build("/resume", status="resume_scope_mismatch", code=1)
        added.unlink()
        member = self.source / "entry-00001.knledger"
        replacement = self.root / "replacement"
        shutil.copy2(member, replacement)
        prior = member.stat()
        os.replace(replacement, member)
        self.assertEqual(member.stat().st_mtime_ns, prior.st_mtime_ns)
        self.assertNotEqual(member.stat().st_ino, prior.st_ino)
        self.build("/resume", status="resume_scope_mismatch", code=1)
        self.assertFalse((self.output / "manifest.knindex").exists())

    def test_checkpoint_integrity_and_resealed_row(self):
        self.fill(145)
        checkpoint = self.checkpoint()
        saved = checkpoint.read_bytes()
        record = json.loads(saved)
        chunk = self.output / (record["chunk_sha256"] + ".knchunk")
        data = chunk.read_bytes()
        checkpoint.write_bytes(saved[:-1])
        self.build("/resume", status="invalid_checkpoint", code=1)
        checkpoint.write_bytes(saved)
        chunk.write_bytes(b"\xef\xbb\xbf" + data)
        self.build("/resume", status="corrupt_inventory_chunk", code=1)
        chunk.write_bytes(data)
        forged = json.loads(data)
        forged["entries"][0].update(digest="", valid=False)
        raw = encode(forged)
        record["chunk_sha256"] = digest(raw)
        (self.output / (digest(raw) + ".knchunk")).write_bytes(raw)
        checkpoint.write_bytes(encode(record))
        self.build("/resume", status="original_mismatch", code=1)
        self.assertFalse((self.output / "manifest.knindex").exists())
        self.assertEqual(chunk.read_bytes(), data)

    def test_orphan_chunk_and_first_marker(self):
        self.fill(152)
        self.output.mkdir()
        pending = self.output / "build.knindex.pending-17-123-1"
        pending.write_bytes(b"{")
        checkpoint = self.checkpoint()
        self.assertEqual(pending.read_bytes(), b"{")
        chunk = self.output / (json.loads(checkpoint.read_bytes())["chunk_sha256"] + ".knchunk")
        data = chunk.read_bytes()
        checkpoint.unlink()
        chunk.write_bytes(b"incomplete")
        self.build("/resume", status="corrupt_inventory_chunk", code=1)
        self.assertEqual(chunk.read_bytes(), b"incomplete")
        chunk.write_bytes(data)
        stamp = chunk.stat().st_mtime_ns
        final = self.build("/resume")
        self.assertEqual(final["reused_entries"], "0")
        self.assertEqual(chunk.stat().st_mtime_ns, stamp)
        unknown = self.root / "other"
        unknown.mkdir()
        other_file = unknown / chunk.name
        other_file.write_bytes(data)
        self.build("/resume", output=unknown, status="resume_marker_missing", code=1)
        self.assertEqual(list(unknown.iterdir()), [other_file])
        empty = self.root / "empty"
        empty.mkdir()
        (empty / "build.knindex.pending-1-2-x").touch()
        self.build("/resume", output=empty, status="resume_marker_missing", code=1)

    def test_writer_lease_and_arguments(self):
        self.fill(142)
        for options in (("/chunks", "1"), ("/resume", "/resume"), ("/resume", "/chunks", "0"),
                        ("/resume", "/chunks", "8193"), ("/resume", "/chunks", "-1"), ("/resume", "/chunks"),
                        ("/verify-entries", "1"), ("/resume", "/verify-entries", "0"),
                        ("/resume", "/verify-entries", "1048577"), ("/resume", "/verify-entries", "-1"),
                        ("/resume", "/verify-entries", "1", "/verify-entries", "2")):
            self.build(*options, code=2)
            self.assertFalse(self.output.exists())
        self.checkpoint()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        writer = kernel.CreateFileW(str(self.output / "writer.knindex"), 0x80000000, 0, None, 3, 0x00200000, None)
        self.assertNotEqual(writer, ctypes.c_void_p(-1).value)
        try:
            self.build("/resume", status="output_busy_or_unavailable", code=1)
            self.assertFalse((self.output / "manifest.knindex").exists())
        finally:
            kernel.CloseHandle(writer)
        self.build("/resume")
        alias = self.root / "joined"
        subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(alias), str(self.source)],
                       check=True, capture_output=True)
        self.build("/resume", source=alias, output=self.root / "new", status="invalid_path", code=1)
        self.build("/resume", output=alias / "nested", status="invalid_path", code=1)
        self.assertFalse((self.source / "nested").exists())
        self.build("/resume", output=self.source / "output.knledger", status="invalid_path", code=1)
        self.assertFalse((self.source / "output.knledger").exists())

    def test_termination_after_observed_commit(self):
        self.fill(4225)
        manifest = self.output / "manifest.knindex"
        with subprocess.Popen(self.command() + ["/resume"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                deadline = time.monotonic() + 60
                while not (self.output / "window-0.knindex").is_file():
                    self.assertIsNone(child.poll(), "writer exited before a checkpoint was observed")
                    self.assertLess(time.monotonic(), deadline, "no checkpoint before timeout")
                    time.sleep(0.005)
                child.kill()
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=15)
        self.assertFalse(manifest.exists())
        old = {p.name: (digest(p.read_bytes()), p.stat().st_mtime_ns) for p in self.output.glob("window-*.knindex")}
        result = self.build("/resume")
        self.assertEqual(int(result["reused_entries"]), 128 * len(old))
        self.assertEqual((result["entries"], result["verified_entries"]), ("4225", "4225"))
        for name, prior in old.items():
            p = self.output / name
            self.assertEqual((digest(p.read_bytes()), p.stat().st_mtime_ns), prior)
        fresh = self.root / "fresh"
        self.assertEqual(self.build("/resume", output=fresh)["snapshot_digest"], result["snapshot_digest"])
        self.assertEqual((fresh / "manifest.knindex").read_bytes(), manifest.read_bytes())
        reader = ARGS.legacy or ARGS.cli
        page = self.query(reader)
        self.assertEqual((page["inspected_files"], page["snapshot_entries"]), (4096, 4225))
        self.assertTrue(page["next_inventory_cursor"])
        tail = self.query(reader, "/inventory-cursor", page["next_inventory_cursor"])
        self.assertEqual((tail["inspected_files"], tail["inventory_offset"], tail["next_inventory_cursor"]), (129, 4096, None))

    def test_replacement_during_terminal_pass(self):
        self.fill(1536)
        self.build("/resume", "/chunks", "11", status="checkpointed")
        member = self.source / "entry-00000.knledger"
        replacement = self.root / "identical"
        shutil.copy2(member, replacement)
        completed_window = self.output / "window-1408.knindex"
        manifest = self.output / "manifest.knindex"
        with subprocess.Popen(self.command() + ["/resume"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            try:
                deadline = time.monotonic() + 60
                while not completed_window.is_file():
                    self.assertIsNone(child.poll(), "worker exited before last checkpoint")
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.001)
                while True:
                    try:
                        os.replace(replacement, member)
                        break
                    except PermissionError:
                        self.assertIsNone(child.poll(), "worker exited while member was pinned")
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.001)
                self.assertFalse(manifest.exists())
                stdout, stderr = child.communicate(timeout=140)
                self.assertEqual(child.returncode, 1, stderr[-300:])
                report = json.loads(stdout)
                self.assertEqual((report["status"], report["verified_entries"]), ("source_changed", "1536"))
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=15)
        self.assertFalse(manifest.exists())

    def test_empty_completed_manifest_and_private_records(self):
        self.output.mkdir()
        report = self.build("/resume", "/chunks", "1")
        self.assertEqual((report["entries"], report["verified_entries"], report["read_bytes"]), ("0", "0", "0"))
        manifest = self.output / "manifest.knindex"
        self.assertEqual(digest(manifest.read_bytes()), report["snapshot_digest"])
        empty = self.build("/resume", "/verify-entries", "1")
        self.assertEqual((empty["verified_entries"], empty["reused_verified_entries"], empty["read_bytes"]), ("0", "0", "0"))
        self.assertFalse(list(self.output.glob("verify-*.knindex")))
        manifest.write_bytes(b"occupied")
        self.build("/resume", status="manifest_mismatch", code=1)
        self.assertEqual(manifest.read_bytes(), b"occupied")
        self.fill(129)
        other = self.root / "two-windows"
        partial = self.build("/resume", "/chunks", "1", output=other, status="checkpointed")
        audit = runpy.run_path(str(Path(__file__).with_name("validate-public-content.py")))["inspect"]
        for raw in ((other / "build.knindex").read_bytes(), (other / "window-0.knindex").read_bytes(), encode(partial)):
            for text in (raw, b"diagnostic\n" + raw[:-1], raw.decode().encode("utf-16-be")):
                self.assertTrue(audit("renamed.txt", text))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--legacy", type=Path, help="Also query a completed v1 manifest with a previous CLI")
    parser.add_argument("--work-dir", type=Path, help="Parent of the disposable fixture directories")
    parser.add_argument("--large-case", type=Path, help="Synthetic valid .kncase for the optional 8 GiB logical input")
    ARGS = parser.parse_args()
    ARGS.cli = ARGS.cli.resolve(strict=True)
    if ARGS.legacy:
        ARGS.legacy = ARGS.legacy.resolve(strict=True)
    if ARGS.work_dir:
        ARGS.work_dir = ARGS.work_dir.resolve(strict=True)
    if ARGS.large_case:
        ARGS.large_case = ARGS.large_case.resolve(strict=True)
    unittest.main(argv=[__file__], verbosity=2)
