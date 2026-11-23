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
                        ("/resume", "/chunks", "8193"), ("/resume", "/chunks", "-1"), ("/resume", "/chunks")):
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
    ARGS = parser.parse_args()
    ARGS.cli = ARGS.cli.resolve(strict=True)
    if ARGS.legacy:
        ARGS.legacy = ARGS.legacy.resolve(strict=True)
    if ARGS.work_dir:
        ARGS.work_dir = ARGS.work_dir.resolve(strict=True)
    unittest.main(argv=[__file__], verbosity=2)
