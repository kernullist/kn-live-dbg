"""Interrupt real archive handles at known offsets and check recovery against the original frame."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import errno
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

import windows_private_archive as publisher


CLI = Path(__file__).with_name("archive-minidump-iat.py")
FRAME = struct.Struct("<8sIIQQ32s")
STOPPED = 37


def instrumented_child(action, offset, argv):
    class InterruptWrite:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def stop(self):
            self.stream.flush()
            os.fsync(self.stream.fileno())
            if action == "out-of-space":
                raise OSError(errno.ENOSPC, "test volume limit")
            os._exit(STOPPED)

        def write(self, data):
            if action == "pack" and offset > 4 << 30:
                assert os.fstat(self.stream.fileno()).st_file_attributes & stat.FILE_ATTRIBUTE_SPARSE_FILE
            remaining = offset - self.stream.tell()
            if 0 <= remaining <= len(data):
                self.stream.write(data[:remaining])
                self.stop()
            return self.stream.write(data)

    extend = publisher.extend_sparse_file

    def interrupted_hole(stream, end):
        if isinstance(stream, InterruptWrite) and stream.tell() <= offset <= end:
            extend(stream.stream, offset)
            stream.stop()
        return extend(stream, end)

    publisher.extend_sparse_file = interrupted_hole

    if action == "pack":
        publish = publisher.publish_archive

        def interrupted(destination, files, protection, write, **options):
            return publish(destination, files, protection, lambda stream: write(InterruptWrite(stream)), **options)
        publisher.publish_archive = interrupted
    elif action in ("recover", "out-of-space", "reference", "dump"):
        reopen = publisher.private_archive_stream

        @contextmanager
        def interrupted(files, path, protection, **options):
            with reopen(files, path, protection, **options) as stream:
                selected = ((action in ("recover", "out-of-space") and path.name.startswith(".kniatarchive.pending-")) or
                            (action == "reference" and path.name.endswith("-reference.knblob")) or
                            (action == "dump" and path.name.endswith("-original.dmp")))
                yield InterruptWrite(stream) if selected else stream
        publisher.private_archive_stream = interrupted
    elif action == "compete":
        seal = publisher.seal_archive

        def wait_for_destination(*args, **options):
            print("ready to publish", flush=True)
            if sys.stdin.readline() != "continue\n":
                raise ValueError("test controller did not release publication")
            return seal(*args, **options)
        publisher.seal_archive = wait_for_destination
    else:
        raise ValueError("unknown test action")
    sys.argv = [str(CLI), *argv]
    runpy.run_path(str(CLI), run_name="__main__")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_recovery(exe, originals, inputs, workspace, encrypted=None):
    exe = exe.resolve()
    reader = pin(exe)
    src_pe, src_dump = originals / "reference.dll", originals / "regular.dmp"
    args = [exe, "--offline", "!kmon", "dump-image-iat", src_dump, pin(src_dump), src_pe, pin(src_pe),
            "FixtureTick", "/declaration", "/json"]
    raw = subprocess.check_output(args, timeout=90)
    assert json.loads(raw)["declaration_check"]["status"] == "unfulfilled"
    report, pe, dump = [inputs / n for n in ("recover-report.json", "recover-pe.bin", "recover-dump.dmp")]
    originals_by_role = {"report": report, "reference": pe, "dump": dump}
    options = ["--debugger", exe, "--debugger-sha256", reader, "--report-sha256", sha(raw)]
    count = 0

    def check(ok, explanation):
        nonlocal count
        if not ok:
            raise AssertionError(explanation)
        count += 1

    def invoke(argv, code, reason=None):
        p = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
        check(p.returncode == code, (code, p.returncode, p.stderr[-160:]))
        if reason is not None:
            check(json.loads(p.stdout).get("reason") == reason, reason)
        return p.stdout

    def originals_for_pack():
        report.write_bytes(raw)
        shutil.copyfile(src_pe, pe)
        shutil.copyfile(src_dump, dump)

    def role_args(roles):
        return [value for role in roles for value in ("--" + role, originals_by_role[role])]

    def worker(action, offset, argv):
        return [sys.executable, "-B", __file__, action, str(offset), *argv]

    pe_bytes, dump_bytes = src_pe.read_bytes(), src_dump.read_bytes()
    report_end = FRAME.size + len(raw)
    dump_start = report_end + len(pe_bytes)
    total = dump_start + len(dump_bytes)

    def expected(efs):
        return FRAME.pack(b"KNMDIAT1", int(efs), len(raw), len(pe_bytes), len(dump_bytes), bytes.fromhex(reader)) + raw + pe_bytes + dump_bytes

    def stop_pack(folder, offset):
        originals_for_pack()
        destination = folder / (uuid.uuid4().hex + ".kniatarchive")
        before = set(folder.glob(".kniatarchive.pending-*"))
        invoke(worker("pack", offset, ["pack", *options, *role_args(originals_by_role), "--out", destination]), STOPPED)
        pending, = set(folder.glob(".kniatarchive.pending-*")) - before
        check(not destination.exists() and pending.stat().st_size == offset and
              pending.read_bytes() == expected(folder == encrypted)[:offset], "flushed prefix from interrupted publisher")
        return pending, destination

    def recovery(pending, destination, roles=()):
        return ["recover", *options, "--pending", pending, "--pending-sha256", pin(pending),
                "--out", destination, *role_args(roles)]

    def reject(pending, destination, argv, reason):
        before = (pin(pending), pending.stat().st_ino)
        invoke([sys.executable, "-B", CLI, *argv], 1, reason)
        check(not destination.exists() and (pin(pending), pending.stat().st_ino) == before, "refusal preserved the candidate")

    def finish(pending, destination, roles):
        old = pending.stat()
        data = expected(destination.parent == encrypted)
        prefix_pin = pin(pending)
        result = json.loads(invoke([sys.executable, "-B", CLI, *recovery(pending, destination, roles)], 0))
        check(result["status"] == "recovered" and result["archive_sha256"] == sha(data) and
              result["pending_archive_sha256"] == prefix_pin and int(result["retained_prefix_bytes"]) == old.st_size and
              int(result["appended_bytes"]) == len(data) - old.st_size and result["original_report_reproduced"] and
              result["native_exit_code"] == 0, "recovery receipt, exact offset and digest")
        check(not pending.exists() and os.path.samestat(old, destination.stat()) and destination.read_bytes() == data,
              "same file published with all original bytes")
        restored = json.loads(invoke([sys.executable, "-B", CLI, "replay", *options, "--archive", destination,
                                     "--archive-sha256", result["archive_sha256"], "--private-workspace", destination.parent], 0))
        check(restored["observation"] == json.loads(raw) and restored["original_report_reproduced"], "ordinary replay of recovered publication")
        check(bool(destination.stat().st_file_attributes & stat.FILE_ATTRIBUTE_ENCRYPTED) == (destination.parent == encrypted),
              "final NTFS encryption policy")
        destination.unlink()

    all_roles = tuple(originals_by_role)
    for offset, roles in ((0, all_roles), (45, all_roles), (FRAME.size + 11, all_roles),
                          (report_end + 1, ("reference", "dump")), (dump_start, ("dump",)),
                          (dump_start + (1 << 20) + 1, ("dump",)), (total - 1, ("dump",)), (total, ())):
        pending, destination = stop_pack(workspace, offset)
        for role, path in originals_by_role.items():
            if role not in roles:
                path.unlink()
        if roles:
            first = roles[0]
            reason = "a partial header requires all three originals" if offset < FRAME.size else f"original {first} required for missing bytes"
            reject(pending, destination, recovery(pending, destination, roles[1:]), reason)
        finish(pending, destination, roles)

    pending, destination = stop_pack(workspace, dump_start + 13)
    resume = recovery(pending, destination, ("dump",))
    invoke(worker("recover", dump_start + (2 << 20) + 31, resume), STOPPED)
    reject(pending, destination, resume, "pending archive pin mismatch")
    check(pending.read_bytes() == expected(False)[:pending.stat().st_size], "interrupted second writer preserved a longer true prefix")
    limited = json.loads(invoke(worker("out-of-space", dump_start + (3 << 20) + 19, recovery(pending, destination, ("dump",))),
                                1, "insufficient space for archive recovery"))
    check(limited["errno"] == errno.ENOSPC and pending.stat().st_size == dump_start + (3 << 20) + 19 and not destination.exists(),
          "write failure retained its numeric cause and the acknowledged prefix remained uncommitted")
    for path in (pe, report):
        path.unlink()
    finish(pending, destination, ("dump",))

    pending, destination = stop_pack(workspace, dump_start + 39)
    partial = pending.read_bytes()
    pending.write_bytes(partial[:-1] + bytes([partial[-1] ^ 1]))
    reject(pending, destination, recovery(pending, destination, ("dump",)), "pending bytes differ from the original")
    pending.write_bytes(partial)
    args = recovery(pending, destination, ("dump",))
    reject(pending, destination, [*args, "--packing-reader-sha256", "0" * 64], "pending archive policy or reader mismatch")
    with dump.open("r+b") as original:
        original.seek(-1, 2)
        last = original.read(1)
        original.seek(-1, 2)
        original.write(bytes([last[0] ^ 1]))
    reject(pending, destination, args, "original member pin mismatch")
    shutil.copyfile(src_dump, dump)

    with subprocess.Popen(list(map(str, worker("compete", 0, args))), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as actor:
        with ThreadPoolExecutor(max_workers=1) as waiter:
            ready = waiter.submit(actor.stdout.readline)
            try:
                check(ready.result(timeout=110).strip() == "ready to publish", "competitor reached the publication boundary")
            except BaseException:
                actor.kill()
                raise
        with destination.open("xb") as winner:
            winner.write(b"another publisher")
        output, _ = actor.communicate("continue\n", timeout=100)
        check(actor.returncode == 1 and json.loads(output)["status"] == "rejected" and
              destination.read_bytes() == b"another publisher" and pending.read_bytes() == expected(False),
              "rename collision preserves the winning publication and the complete recoverable file")
    destination.unlink()
    for path in originals_by_role.values():
        path.unlink()
    finish(pending, destination, ())

    for efs_folder in filter(None, (workspace, encrypted)):
        pending, destination = stop_pack(efs_folder, total)
        for path in originals_by_role.values():
            path.unlink()
        resume = recovery(pending, destination)
        invoke(worker("reference", 71, resume), STOPPED)
        copy, = efs_folder.glob(".kniat-recover-*-reference.knblob")
        check(copy.read_bytes() == pe_bytes[:71] and not destination.exists(), "interrupted verification left the recorded PE prefix")
        with copy.open("ab") as altered:
            altered.write(b"x")
        reject(pending, destination, resume, "recovery copy differs from the retained member")
        check(copy.read_bytes() == pe_bytes[:71] + b"x", "unexplained copy left in place")
        copy.write_bytes(pe_bytes[:71])
        alias = inputs / "copy-output"
        os.link(copy, alias)
        with alias.open("r+b") as sink:
            p = subprocess.run(list(map(str, [sys.executable, "-B", CLI, *resume])), stdout=sink, stderr=subprocess.PIPE, timeout=60)
        check(p.returncode == 2 and copy.read_bytes() == pe_bytes[:71], "implicit recovery copy protected from redirected output")
        alias.unlink()
        invoke(worker("dump", (1 << 20) + 17, resume), STOPPED)
        dump_copy, = efs_folder.glob(".kniat-recover-*-original.dmp")
        check(dump_copy.read_bytes() == dump_bytes[:(1 << 20) + 17] and copy.read_bytes() == pe_bytes,
              "retry reused the PE and reached the chosen dump offset")
        finish(pending, destination, ())
        check(not copy.exists() and not dump_copy.exists(), "both interrupted private copies reclaimed by their retry")

    pending, destination = stop_pack(workspace, 13)
    args = recovery(pending, destination, all_roles)
    reject(pending, destination, [*args, "--packing-reader-sha256", "f" * 64],
           "finishing a partial header requires its publishing reader")
    for name in ("store.knstorelock", ".kniat-recover-reserved.bin", ".knapprovalarchive.pending-control"):
        control = workspace / name
        reject(pending, control, recovery(pending, control, all_roles), "archive destination is reserved for store control or temporary files")
        invoke([sys.executable, "-B", CLI, "pack", *options, *role_args(all_roles), "--out", control], 1,
               "archive destination is reserved for store control or temporary files")
        check(not control.exists(), "store control name remains available")
    with pending.open("r+b"):
        invoke([sys.executable, "-B", CLI, *args], 1)
    alias = inputs / "link-to-pending"
    os.link(pending, alias)
    reject(pending, destination, args, "pending archive must be a single local file")
    for channel in ("stdout", "stderr"):
        with alias.open("r+b") as sink:
            r = subprocess.run(list(map(str, [sys.executable, "-B", CLI, *args])), timeout=90,
                               **{channel: sink, ("stderr" if channel == "stdout" else "stdout"): subprocess.PIPE})
        check(r.returncode == 2 and pending.read_bytes() == expected(False)[:13], "output hard link did not receive diagnostics")
    alias.unlink()
    alternate = str(pending) + ":unexpected"
    with open(alternate, "wb") as stream:
        stream.write(b"owned extra stream")
    reject(pending, destination, args, "pending archive has unexpected data streams")
    os.unlink(alternate)
    # Only a short format-header prefix is present for this access-control negative.
    subprocess.run(["icacls", str(pending), "/grant", "*S-1-1-0:(R)"], capture_output=True, check=True, timeout=20)
    reject(pending, destination, args, "pending archive owner or ACL changed")
    pending.unlink()

    pending, destination = stop_pack(workspace, total)
    old = pending.read_bytes()
    fake = raw.replace(b'"status":"unfulfilled"', b'"status":"supported"', 1)
    assert fake != raw
    fields = list(FRAME.unpack_from(old))
    fields[2] = len(fake)
    pending.write_bytes(FRAME.pack(*fields) + fake + old[report_end:])
    args = recovery(pending, destination)
    args[args.index("--report-sha256") + 1] = sha(fake)
    reject(pending, destination, args, "original native report did not reproduce")
    pending.write_bytes(old + b"x")
    reject(pending, destination, recovery(pending, destination), "archive extent mismatch")
    pending.unlink()

    # A zero-length dump still represents an original native failure, including when no dump bytes were retained.
    originals_for_pack()
    dump.write_bytes(b"")
    unavailable = invoke([exe, "--offline", "!kmon", "dump-image-iat", dump, pin(dump), pe, pin(pe), "FixtureTick",
                          "/declaration", "/json"], 1)
    assert json.loads(unavailable)["status"] == "unavailable"
    report.write_bytes(unavailable)
    gap_opts = ["--debugger", exe, "--debugger-sha256", reader, "--report-sha256", sha(unavailable)]
    destination = workspace / "recovered-gap.kniatarchive"
    gap_pack = ["pack", *gap_opts, *role_args(all_roles), "--out", destination]
    invoke(worker("pack", FRAME.size + len(unavailable) + 1, gap_pack), STOPPED)
    pending, = workspace.glob(".kniatarchive.pending-*")
    report.unlink()
    dump.unlink()
    result = json.loads(invoke([sys.executable, "-B", CLI, "recover", *gap_opts, "--pending", pending, "--pending-sha256",
                                pin(pending), "--out", destination, "--reference", pe], 0))
    pe.unlink()
    restored = json.loads(invoke([sys.executable, "-B", CLI, "replay", *gap_opts, "--archive", destination, "--archive-sha256",
                                  result["archive_sha256"], "--private-workspace", workspace], 0))
    check(result["native_exit_code"] == restored["native_exit_code"] == 1 and restored["observation"] == json.loads(unavailable),
          "partial recovery reproduced an unavailable original and its native exit code")
    destination.unlink()

    pending, destination = stop_pack(workspace, total)
    original_id, pending_pin = pending.stat(), pin(pending)
    args = recovery(pending, destination)
    for path in originals_by_role.values():
        path.unlink()
    with subprocess.Popen(list(map(str, [sys.executable, "-B", CLI, *args])), stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as actor:
        actor.stdout.close()
        check(actor.wait(timeout=120) == 2, "lost recovery reply reports delivery failure")
    check(not pending.exists() and os.path.samestat(original_id, destination.stat()) and pin(destination) == pending_pin,
          "completed recovery survives loss of the reply")
    invoke([sys.executable, "-B", CLI, *args], 1, "a new final archive name is required")
    restored = json.loads(invoke([sys.executable, "-B", CLI, "replay", *options, "--archive", destination,
                                  "--archive-sha256", pending_pin, "--private-workspace", workspace], 0))
    check(restored["observation"] == json.loads(raw), "verified published result after a lost reply")
    destination.unlink()

    if encrypted:
        pending, destination = stop_pack(workspace, FRAME.size)
        secure_pe = encrypted / "recover-source.knblob"
        shutil.copyfile(src_pe, secure_pe)
        check(bool(secure_pe.stat().st_file_attributes & stat.FILE_ATTRIBUTE_ENCRYPTED), "encrypted supplementary original")
        args = recovery(pending, destination, all_roles)
        args[args.index("--reference") + 1] = secure_pe
        reject(pending, destination, args, "destination would drop original file encryption")
        secure_pe.unlink()
        secured = ctypes.WinDLL("advapi32", use_last_error=True).EncryptFileW
        secured.argtypes, secured.restype = (wintypes.LPCWSTR,), wintypes.BOOL
        check(secured(str(pending)), "encrypted the disposable pending header")
        reject(pending, destination, recovery(pending, destination, all_roles), "pending file encryption does not match the private store")
        pending.unlink()
        for offset, roles in ((dump_start + 97, ("dump",)), (total, ())):
            pending, destination = stop_pack(encrypted, offset)
            reject(pending, workspace / destination.name, recovery(pending, workspace / destination.name, roles),
                   "select a publisher pending file directly inside the destination store")
            for role, path in originals_by_role.items():
                if role not in roles:
                    path.unlink()
            finish(pending, destination, roles)
    for directory in filter(None, (workspace, encrypted)):
        check(not list(directory.glob(".kniatarchive.pending-*")) and not list(directory.glob(".kniat-replay-*"))
              and not list(directory.glob(".kniat-recover-*")), "recovery fixture cleanup")
    print(f"Passed {count} interrupted archive recovery checks.")


def check_sparse_recovery(exe, originals, outer, *, size, retained):
    """Recover an owned sparse dump across a hole and reproduce its native report after removing the originals."""
    allocated = ctypes.WinDLL("kernel32", use_last_error=True).GetCompressedFileSizeW
    allocated.argtypes, allocated.restype = (wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)), wintypes.DWORD

    def physical(path):
        high = wintypes.DWORD()
        low = allocated(str(path), ctypes.byref(high))
        assert low != 0xffffffff or ctypes.get_last_error() == 0
        return (high.value << 32) | low

    def run(argv, code=0):
        started = time.monotonic()
        p = subprocess.run(list(map(str, argv)), capture_output=True, timeout=1200)
        if p.returncode != code:
            result = json.loads(p.stdout) if p.stdout.startswith(b"{") else {}
            failure = {k: result[k] for k in ("reason", "errno", "win32_error") if k in result}
            raise AssertionError((p.returncode, failure, round(time.monotonic() - started, 2), p.stderr[-180:]))
        return p.stdout

    final_byte = b"Z" if size > 2 << 30 else b"\0"
    with tempfile.TemporaryDirectory(dir=outer, prefix="sparse-recovery-") as tmp:
        base = Path(tmp).resolve()
        system = Path(os.environ["SystemRoot"]) / "System32"
        if base.stat().st_file_attributes & stat.FILE_ATTRIBUTE_COMPRESSED:
            run([system / "compact.exe", "/u", base])
        store = base / "private"
        native = [exe, "--offline", "!kmon"]
        assert json.loads(run([*native, "init-store", store, "/acl-only", "/json"]))["root_acl_verified"]
        assert not store.stat().st_file_attributes & stat.FILE_ATTRIBUTE_COMPRESSED
        dump, pe, report, out = [store / n for n in ("owned.dmp", "reference.knblob", "original.json", "observation.kniatarchive")]
        shutil.copyfile(originals / "regular.dmp", dump)
        shutil.copyfile(originals / "reference.dll", pe)
        run([system / "fsutil.exe", "sparse", "setflag", dump])
        assert dump.stat().st_file_attributes & stat.FILE_ATTRIBUTE_SPARSE_FILE
        source_size = dump.stat().st_size
        with dump.open("r+b") as stream:
            publisher.extend_sparse_file(stream, size)
        run([system / "fsutil.exe", "sparse", "setrange", dump, source_size, size - source_size])
        with dump.open("r+b") as stream:
            stream.seek(size - 1)
            stream.write(final_byte)
            stream.flush()
            os.fsync(stream.fileno())
        allocation_limit = min(150 << 20, size)
        assert physical(dump) < allocation_limit
        raw = run([*native, "dump-image-iat", dump, pin(dump), pe, pin(pe), "FixtureTick", "/declaration", "/json"])
        assert json.loads(raw)["slot_value_observed"]
        report.write_bytes(raw)
        reader = pin(exe)
        header = FRAME.pack(b"KNMDIAT1", 0, len(raw), pe.stat().st_size, size, bytes.fromhex(reader))
        expected = hashlib.sha256(header + raw + pe.read_bytes())
        with dump.open("rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                expected.update(block)
        extent = len(header) + len(raw) + pe.stat().st_size + size
        common = ["--debugger", exe, "--debugger-sha256", reader, "--report-sha256", sha(raw)]
        pack = ["pack", *common, "--report", report, "--reference", pe, "--dump", dump, "--out", out]
        run([sys.executable, "-B", __file__, "pack", retained, *pack], STOPPED)
        pending, = store.glob(".kniatarchive.pending-*")
        previous = pending.stat()
        assert previous.st_file_attributes & stat.FILE_ATTRIBUTE_SPARSE_FILE
        assert previous.st_size == retained and physical(pending) < allocation_limit and not out.exists()
        print(f"Interrupted at {retained} bytes for a {size}-byte dump.", flush=True)
        report.unlink()
        pe.unlink()
        cli = [sys.executable, "-B", CLI]
        recovered = json.loads(run([*cli, "recover", *common, "--pending", pending, "--pending-sha256", pin(pending),
                                    "--out", out, "--dump", dump]))
        assert recovered["archive_sha256"] == expected.hexdigest() and int(recovered["retained_prefix_bytes"]) == retained
        assert int(recovered["appended_bytes"]) == extent - retained and os.path.samestat(previous, out.stat())
        assert out.stat().st_size == extent
        assert physical(out) < allocation_limit, (physical(out), allocation_limit)
        assert not pending.exists()
        assert out.stat().st_file_attributes & stat.FILE_ATTRIBUTE_SPARSE_FILE
        with out.open("rb") as stream:
            stream.seek(-1, 2)
            assert stream.read() == final_byte
        with dump.open("r+b") as stream:
            publisher.extend_sparse_file(stream, (8 << 30) + 1)
        assert dump.stat().st_size == (8 << 30) + 1
        shutil.copyfile(originals / "reference.dll", pe)
        report.write_bytes(raw)
        denied = json.loads(run([*cli, *pack[:-1], store / "oversize.kniatarchive"], 1))
        assert denied["reason"] == "original evidence outside its byte limits" and not (store / "oversize.kniatarchive").exists()
        report.unlink()
        pe.unlink()
        dump.unlink()
        replay = json.loads(run([*cli, "replay", *common, "--archive", out, "--archive-sha256", expected.hexdigest(),
                                 "--private-workspace", store]))
        assert replay["observation"] == json.loads(raw) and {p.name for p in store.iterdir()} == {"store.knprivacy", out.name}
        print(f"Verified {extent} archive bytes, {extent - retained} appended, final byte and original report.", flush=True)
        print("Rejected the 8 GiB + 1 input.", flush=True)


if __name__ == "__main__":
    instrumented_child(sys.argv[1], int(sys.argv[2]), sys.argv[3:])
