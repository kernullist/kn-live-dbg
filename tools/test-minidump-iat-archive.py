"""Exercise portable IAT report replay after removing its standalone inputs (Windows x64)."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import ctypes
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

from etl_reader_process import WindowsFiles

CLI = Path(__file__).with_name("archive-minidump-iat.py")
FRAME = struct.Struct("<8sIIQQ32s")


def pin(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=180)


@contextmanager
def sibling_writer(directory):
    files = WindowsFiles()
    # A concurrent directory handle with FILE_ADD_FILE access. Existing evidence files stay read-only.
    handle = files.create(str(directory), 0x82, 7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        files.close(handle)


def exercise(args, outer):
    exe = args.exe.resolve(strict=True)
    cli = [sys.executable, "-B", CLI]
    reader_pin = pin(exe)
    native = [exe, "--offline", "!kmon"]
    count = 0

    def check(ok, message):
        nonlocal count
        if not ok:
            raise AssertionError(message)
        count += 1

    def result(command, code=0):
        proc = run(command)
        check(proc.returncode == code and bool(proc.stdout), (command[2], proc.returncode, proc.stderr[-200:]))
        return json.loads(proc.stdout)

    def store(name, efs=False):
        path = outer / name
        page = result([*native, "init-store", path, *([] if efs else ["/acl-only"]), "/json"])
        check(page["root_acl_verified"] and page["efs_required"] == efs, "verified private workspace")
        return path

    work = store("archives")
    scratch = store("replay")
    inputs = store("inputs")
    if args.fixtures:
        originals = args.fixtures.resolve(strict=True)
    else:
        originals = store("originals")
        harness = runpy.run_path(str(Path(__file__).with_name("test-minidump-iat.py")))
        build = originals / "fixture"
        build.mkdir()
        link = shutil.which(args.link)
        check(bool(link), "use the x64 Native Tools prompt or pass --link with the SDK LIB path set")
        dll = harness["FIXTURE"]["build_fixture"](link, build)
        shutil.copyfile(dll, originals / "reference.dll")
        harness["capture"](originals, build)
    pe = inputs / "original.bin"
    shutil.copyfile(originals / "reference.dll", pe)
    pe_pin = pin(pe)
    dump = inputs / "case.dmp"
    report = inputs / "original.json"
    saved = []

    def common(digest):
        return ["--debugger", exe, "--debugger-sha256", reader_pin.upper(), "--report-sha256", digest]

    def pack_args(archive, digest):
        return [*cli, "pack", *common(digest), "--report", report, "--reference", pe, "--dump", dump, "--out", archive]

    def replay_args(archive, package_pin, report_pin, workspace=scratch):
        return [*cli, "replay", *common(report_pin), "--archive", archive, "--archive-sha256", package_pin,
                "--private-workspace", workspace]

    def record(name, selector, *, code=0):
        proc = run([*native, "dump-image-iat", dump, pin(dump), pe, pe_pin, name, *selector, "/json"])
        check(proc.returncode == code, "direct native exit status")
        report.write_bytes(proc.stdout)
        return json.loads(proc.stdout)

    def rejected(command, reason):
        check(result(command, 1).get("reason") == reason, reason)

    def verify_archive(archive, report_pin, page, code, require_encryption=False):
        raw = archive.read_bytes()
        magic, flags, nr, np, nd, verifier = FRAME.unpack_from(raw)
        check(magic == b"KNMDIAT1" and flags == int(require_encryption) and verifier.hex() == reader_pin and
              FRAME.size + nr + np + nd == len(raw), "independent header and total extent")
        at = FRAME.size
        for size, original in ((nr, report), (np, pe), (nd, dump)):
            check(size == original.stat().st_size and hashlib.sha256(raw[at:at + size]).hexdigest() == pin(original),
                  "original file membership and exact length")
            at += size
        saved.append((archive, pin(archive), report_pin, page, code, require_encryption))

    for kind, name, detail, verdict, code in (("regular", "FixtureTick", False, None, 0),
                                             ("regular", "FixtureTick", True, "unfulfilled", 0),
                                             ("full", "FixtureOrdinal", True, "supported", 0),
                                             ("regular", "FixtureForward", True, "unfulfilled", 1)):
        shutil.copyfile(originals / (kind + ".dmp"), dump)
        page = record(name, ["/declaration"] if detail else [], code=code)
        check(page.get("declaration_check", {}).get("status") == verdict, "native baseline declaration")
        archive = (inputs if not detail else work) / (str(len(saved)) + ".kniatarchive")
        report_pin = pin(report)
        receipt = result(pack_args(archive, report_pin))
        check(receipt["archive_sha256"] == pin(archive) and receipt["native_exit_code"] == code and
              receipt["original_report_reproduced"] is True, "publication receipt")
        verify_archive(archive, report_pin, page, code)

    dump_pin = pin(dump)
    for original, reason in ((dump, "dump_pin_unavailable"), (pe, "reference_pin_unavailable")):
        with original.open("r+b"):
            busy = result([*native, "dump-image-iat", dump, dump_pin, pe, pe_pin, "FixtureTick", "/declaration", "/json"], 1)
            check(busy["reason"] == reason and not busy["slot_value_observed"] and
                  busy["declaration_check"]["status"] == "unfulfilled", "writable original remains unavailable")

    # Change a single retained name byte in a disposable dump. Keep its loaded slot intact.
    shutil.copyfile(originals / "full.dmp", dump)
    baseline = record("FixtureTick", ["/declaration"])
    dll, = [v for v in baseline["declaration_check"]["declaration_fields"] if v["field"] == "dll_name"]
    offset = int(dll["declaration_spans"][0]["file_offset"])
    with dump.open("r+b") as stream:
        stream.seek(offset)
        changed = stream.read(1)[0] ^ 1
        stream.seek(offset)
        stream.write(bytes([changed]))
    page = record("FixtureTick", ["/declaration"])
    check(page["declaration_check"]["status"] == "contradicted" and page["slot_value_observed"], "conflicting evidence")
    report_pin = pin(report)
    archive = work / "contradicted.kniatarchive"
    with sibling_writer(outer), ThreadPoolExecutor(max_workers=2) as pool:
        attempts = list(pool.map(run, [pack_args(archive, report_pin)] * 2))
    check(sorted(p.returncode for p in attempts) == [0, 1] and
          [json.loads(p.stdout)["archive_sha256"] for p in attempts if p.returncode == 0] == [pin(archive)],
          "competing publishers produce one verified immutable file")
    verify_archive(archive, report_pin, page, 0)
    rejected(pack_args(archive, report_pin), "archive destination already exists")

    if args.require_efs:
        secure = store("encrypted", True)
        sealed = secure / "encrypted.kniatarchive"
        result(pack_args(sealed, report_pin))
        check(bool(sealed.stat().st_file_attributes & stat.FILE_ATTRIBUTE_ENCRYPTED), "sealed archive is EFS encrypted")
        verify_archive(sealed, report_pin, page, 0, True)
        rejected(replay_args(sealed, pin(sealed), report_pin), "replay workspace would drop archive encryption")
        secure_report = secure / "source.json"
        shutil.copyfile(report, secure_report)
        check(bool(secure_report.stat().st_file_attributes & stat.FILE_ATTRIBUTE_ENCRYPTED), "encrypted original")
        command = pack_args(work / "downgrade.kniatarchive", report_pin)
        command[command.index("--report") + 1] = secure_report
        rejected(command, "destination would drop original file encryption")

    denied = work / "denied.kniatarchive"
    rejected(pack_args(denied, "0" * 64), "original report pin mismatch")
    for key, value, reason in (("--reference", report, "original roles share a file"),
                               ("--reference", originals / "regular.dmp", "original member pin mismatch"),
                               ("--debugger-sha256", "0" * 64, "debugger pin mismatch")):
        command = pack_args(denied, report_pin)
        command[command.index(key) + 1] = value
        rejected(command, reason)
    check(not denied.exists() and not list(work.glob("*.pending-*")), "failed pack left no final or pending file")
    for original in (report, pe, dump, work / "store.knprivacy", archive):
        before = pin(original)
        alias = inputs / "sink-alias"
        os.link(original, alias)
        try:
            for channel, extra in (("stdout", []), ("stderr", ["--unknown"])):
                with alias.open("r+b") as sink:
                    proc = subprocess.run(list(map(str, pack_args(archive, report_pin))) + extra, timeout=90,
                                          **{channel: sink, ("stderr" if channel == "stdout" else "stdout"): subprocess.PIPE})
                check(proc.returncode == 2 and pin(original) == before, "redirected output hard link protected")
        finally:
            alias.unlink()

    dump.write_bytes(b"")
    page = record("FixtureTick", ["/declaration"], code=1)
    report_pin = pin(report)
    archive = work / "empty-dump.kniatarchive"
    result(pack_args(archive, report_pin))
    verify_archive(archive, report_pin, page, 1)
    undelivered = work / "undelivered.kniatarchive"
    with subprocess.Popen(list(map(str, pack_args(undelivered, report_pin))), stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as publisher:
        publisher.stdout.close()
        check(publisher.wait(timeout=180) == 2, "closed output pipe reports delivery failure")
    verify_archive(undelivered, report_pin, page, 1)
    for original in (pe, dump, report):
        original.unlink()
    for archive, package_pin, report_pin, page, code, efs in saved:
        workspace = secure if efs else scratch
        with sibling_writer(outer):
            restored = result(replay_args(archive, package_pin.upper(), report_pin.upper(), workspace))
        check(restored["observation"] == page and restored["native_exit_code"] == code and
              restored["original_report_reproduced"] and restored["report_sha256"] == report_pin and
              restored["packing_reader_sha256"] == reader_pin, "original native report after removing all inputs")
        check(not list(workspace.glob(".kniat-replay-*")), "private replay cleanup")

    archive, package_pin, report_pin, _, _, _ = saved[1]
    rejected(replay_args(archive, "0" * 64, report_pin), "archive pin mismatch")
    rejected(replay_args(archive, package_pin, "0" * 64), "original report pin mismatch")
    data = archive.read_bytes()
    magic, flags, nr, np, nd, verifier = FRAME.unpack_from(data)
    rewritten = work / "revised.bin"

    def altered(header, content, reason, original_pin=report_pin):
        rewritten.write_bytes(FRAME.pack(*header) + content)
        rejected(replay_args(rewritten, pin(rewritten), original_pin), reason)
        check(not list(scratch.glob(".kniat-replay-*")), "rejected replay cleanup")

    header = [magic, flags, nr, np, nd, verifier]
    body = data[FRAME.size:]
    for index, value, reason in ((0, b"invalid!", "invalid archive header"), (1, 2, "invalid archive header"),
                                 (2, 0, "original evidence outside its byte limits"),
                                 (4, (8 << 30) + 1, "original evidence outside its byte limits"),
                                 (1, 1, "replay workspace would drop archive encryption")):
        h = header.copy()
        h[index] = value
        altered(h, body, reason)
    altered(header, body[:-1], "archive extent mismatch")
    altered(header, body + b"x", "archive extent mismatch")
    for offset in (nr, nr + np):
        damaged = bytearray(body)
        damaged[offset] ^= 1
        altered(header, damaged, "original member pin mismatch")
    fabricated = body[:nr].replace(b'"status":"unfulfilled"', b'"status":"supported"', 1)
    check(fabricated != body[:nr], "changed the stored conclusion")
    header[2] = len(fabricated)
    altered(header, fabricated + body[nr:], "original native report did not reproduce", hashlib.sha256(fabricated).hexdigest())
    check(pin(archive) == package_pin, "original archive preserved across altered controls")
    print(f"Passed {count} minidump archive checks and reproduced {len(saved)} original native reports after source removal.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, help="reuse the owned regular/full dumps and PE from test-minidump-iat.py")
    parser.add_argument("--link", default="link.exe")
    parser.add_argument("--require-efs", action="store_true", help="also require verified NTFS EFS publication and replay")
    with tempfile.TemporaryDirectory() as temporary:
        exercise(parser.parse_args(), Path(temporary))
