"""Seal and replay one private dump-image-iat observation with its original dump and reference PE."""
import argparse
from contextlib import ExitStack
import ctypes
from ctypes import wintypes
import errno
import hashlib
import io
import os
from pathlib import Path
import re
import runpy
import stat
import struct
import subprocess
import sys

from etl_reader_process import WindowsFiles, file_hash
from owned_module_benchmark import check, encoded, sha
from retained_corpus import CHUNK, OutputCollision
from saved_etl_comparison import digest, local_path, outputs_safe, write_result
from windows_private_archive import (SparseReader, check_archive_name, discard_private_copy, extend_sparse_file, held,
                                     logical_hash, logical_reader, native_result,
                                     private_archive_stream, publish_archive, replay_directory, seal_archive,
                                     verified_protection, verify_pending_file)


MAGIC = b"KNMDIAT1"
# Magic, EFS requirement, report/PE/dump byte counts and the publishing verifier's SHA-256.
HEADER = struct.Struct("<8sIIQQ32s")
REPORT_MAX, PE_MAX, DUMP_MAX = 1 << 20, 64 << 20, 8 << 30
PENDING = ".kniatarchive.pending-"
RECOVERY_COPY = ".kniat-recover-"
DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]


def attributes(files, stream):
    import msvcrt
    tag = (wintypes.DWORD * 2)()
    if not files.info(msvcrt.get_osfhandle(stream.fileno()), 9, tag, ctypes.sizeof(tag)):
        raise ctypes.WinError(ctypes.get_last_error())
    return tag[0]


def encrypted(files, stream):
    return bool(attributes(files, stream) & stat.FILE_ATTRIBUTE_ENCRYPTED)


def preserve_sparse(files, source, target, size, require_efs):
    # Sparse allocation is optional. Content, byte counts and protection are verified in either form.
    if require_efs or size < CHUNK or not attributes(files, source) & stat.FILE_ATTRIBUTE_SPARSE_FILE or encrypted(files, target):
        return False
    import msvcrt
    ioctl = ctypes.WinDLL("kernel32", use_last_error=True).DeviceIoControl
    ioctl.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                      wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
    ioctl.restype = wintypes.BOOL
    returned = wintypes.DWORD()
    return bool(ioctl(msvcrt.get_osfhandle(target.fileno()), 0x000900c4, None, 0, None, 0, ctypes.byref(returned), None))


def write_tail(target, block, sparse):
    # The caller writes strictly at EOF. Extend the logical prefix even when its final block is a hole.
    if sparse and (block is SparseReader.zero or (block and block[0] == 0 and block.count(0) == len(block))):
        extend_sparse_file(target, target.tell() + len(block))
    else:
        check(target.write(block) == len(block), "incomplete original file transfer")


def check_sizes(report, pe, dump):
    check(0 < report <= REPORT_MAX and 0 <= pe <= PE_MAX and 0 <= dump <= DUMP_MAX,
          "original evidence outside its byte limits")


def header_fields(header):
    magic, flags, report_size, pe_size, dump_size, reader = HEADER.unpack(header)
    check(magic == MAGIC and flags in (0, 1), "invalid archive header")
    sizes = report_size, pe_size, dump_size
    check_sizes(*sizes)
    return bool(flags), sizes, reader.hex()


def observation(raw, report_pin):
    check(sha(raw) == report_pin, "original report pin mismatch")
    page = DECODE(raw)
    check(page["schema"] == "kn.minidump_iat_observation.v1" and page["source"] == "saved_user_minidump" and
          page["status"] in ("observed", "unavailable") and type(page["export"]) is str and
          re.fullmatch(r"[!-~]{1,255}", page["export"]), "unsupported original observation")
    digest(page["expected_dump_sha256"])
    digest(page["expected_reference_sha256"])
    if "declaration_check" in page:
        check(page["declaration_check"]["schema"] == "kn.minidump_import_declaration.v1",
              "unsupported original declaration")
    return page


def reproduce(program, dump, pe, page, raw):
    options = ["/declaration"] if "declaration_check" in page else []
    result = native_result(program, "dump-image-iat", dump, page["expected_dump_sha256"],
                           pe, page["expected_reference_sha256"], page["export"], *options, timeout=600)
    code = 0 if page["status"] == "observed" else 1
    check(result.returncode == code and result.stdout == raw, "original native report did not reproduce")
    return code


def copy_original(source, output, length, expected, package_hash=None, *, sparse=False):
    actual = hashlib.sha256()
    reader = logical_reader(source)
    while length:
        block = reader.read(min(length, CHUNK))
        check(block, "incomplete original file transfer")
        write_tail(output, block, sparse)
        actual.update(block)
        if package_hash is not None:
            package_hash.update(block)
        length -= len(block)
    check(actual.hexdigest() == expected, "original member pin mismatch")


def pack(args, files, program, protection):
    destination = local_path(args.out)
    check_archive_name(destination)
    check(not os.path.lexists(destination), "archive destination already exists")
    report_path, pe_path, dump_path = (local_path(path) for path in (args.report, args.reference, args.dump))
    paths = (report_path, pe_path, dump_path)
    with ExitStack() as members:
        # Directory handles deny deletion while allowing sibling publications.
        # The original files themselves deny both writes and deletion.
        sources = [members.enter_context(held(files, path, share_directory_writes=True)) for path in paths]
        stats = [os.fstat(stream.fileno()) for stream in sources]
        check(len({(s.st_dev, s.st_ino) for s in stats}) == len(stats), "original roles share a file")
        sizes = [s.st_size for s in stats]
        check_sizes(*sizes)
        check(protection["efs_required"] or not any(encrypted(files, s) for s in sources),
              "destination would drop original file encryption")
        raw = sources[0].read(sizes[0])
        page = observation(raw, args.report_sha256)
        pins = [page["expected_reference_sha256"], page["expected_dump_sha256"]]
        for source, pin in zip(sources[1:], pins):
            check(logical_hash(source) == pin, "original member pin mismatch")
            source.seek(0)
        code = reproduce(program, dump_path, pe_path, page, raw)

        def write(target):
            header = HEADER.pack(MAGIC, int(protection["efs_required"]), *sizes, bytes.fromhex(args.debugger_sha256))
            package_hash = hashlib.sha256(header)
            sparse = preserve_sparse(files, sources[2], target, sizes[2], protection["efs_required"])
            target.write(header)
            target.write(raw)
            package_hash.update(raw)
            for source, size, pin in zip(sources[1:], sizes[1:], pins):
                copy_original(source, target, size, pin, package_hash, sparse=sparse)
            return dict(archive_sha256=package_hash.hexdigest(), archive_requires_efs=protection["efs_required"],
                        packing_reader_sha256=args.debugger_sha256, native_exit_code=code)

        return publish_archive(destination, files, protection, write, pending_prefix=PENDING)


def extract_member(stack, files, path, source, size, pin, require_efs):
    with path.open("xb") as output:
        check(not require_efs or encrypted(files, output), "private replay file did not inherit EFS")
        sparse = preserve_sparse(files, source, output, size, require_efs)
        copy_original(source, output, size, pin, sparse=sparse)
    saved = stack.enter_context(held(files, path, share_directory_writes=True))
    check(logical_hash(saved) == pin, "replay file identity changed")
    return saved


def replay(args, files, program, workspace, protection):
    with held(files, local_path(args.archive), share_directory_writes=True) as source:
        length = os.fstat(source.fileno()).st_size
        check(HEADER.size < length <= HEADER.size + REPORT_MAX + PE_MAX + DUMP_MAX, "invalid archive size")
        header = source.read(HEADER.size)
        require_efs, sizes, reader_pin = header_fields(header)
        report_size, pe_size, dump_size = sizes
        check(HEADER.size + sum(sizes) == length, "archive extent mismatch")
        raw = source.read(report_size)
        # Interpret the same header and report bytes that enter the archive digest.
        # The extracted payloads must independently match their original pins on the second pass.
        archive_hash = hashlib.sha256(header)
        archive_hash.update(raw)
        reader = logical_reader(source)
        for block in iter(lambda: reader.read(CHUNK), b""):
            archive_hash.update(block)
        check(archive_hash.hexdigest() == args.archive_sha256, "archive pin mismatch")
        check(protection["efs_required"] or not (require_efs or encrypted(files, source)),
              "replay workspace would drop archive encryption")
        page = observation(raw, args.report_sha256)
        source.seek(HEADER.size + report_size)
        with replay_directory(workspace, ".kniat-replay-") as scratch, files.hold(scratch, directory=True), ExitStack() as stack:
            pe, dump = scratch / "reference.knblob", scratch / "original.dmp"
            for path, size, pin in ((pe, pe_size, page["expected_reference_sha256"]),
                                    (dump, dump_size, page["expected_dump_sha256"])):
                extract_member(stack, files, path, source, size, pin, protection["efs_required"])
            code = reproduce(program, dump, pe, page, raw)
        return dict(archive_sha256=args.archive_sha256, archive_requires_efs=require_efs,
                    packing_reader_sha256=reader_pin, native_exit_code=code, observation=page)


def verify_prefix_and_suffix(pending, retained, members):
    # Compute the final digest from the original members, independently of the pin on the pending file.
    archive_hash, position, suffix = hashlib.sha256(), 0, []
    pending.seek(0)
    stored = logical_reader(pending)
    for stream, size, pin in members:
        stream.seek(0)
        reader = logical_reader(stream)
        have = min(size, max(retained - position, 0))
        if have < size:
            suffix.append((stream, have, size - have))
        member_hash = hashlib.sha256()
        while size:
            block = reader.read(min(CHUNK, size))
            check(block, "incomplete original file transfer")
            compare = min(len(block), max(retained - position, 0))
            if compare:
                check(stored.read(compare) == block[:compare], "pending bytes differ from the original")
            member_hash.update(block)
            archive_hash.update(block)
            position += len(block)
            size -= len(block)
        check(member_hash.hexdigest() == pin, "original member pin mismatch")
    return archive_hash.hexdigest(), suffix


def append_suffix(pending, retained, suffix, sparse):
    pending.seek(retained)
    for source, offset, size in suffix:
        source.seek(offset)
        reader = logical_reader(source)
        while size:
            block = reader.read(min(size, CHUNK))
            check(block, "incomplete pending archive write")
            write_tail(pending, block, sparse)
            size -= len(block)


def recovery_copies(path):
    stem = RECOVERY_COPY + path.name[len(PENDING):]
    return path.with_name(stem + "-reference.knblob"), path.with_name(stem + "-original.dmp")


def verify_copy_prefix(stream, pending, start, size):
    copied = os.fstat(stream.fileno()).st_size
    check(copied <= size, "unexpected recovery copy extent")
    pending.seek(start)
    stream.seek(0)
    source, copy = logical_reader(pending), logical_reader(stream)
    remaining = copied
    while remaining:
        count = min(CHUNK, remaining)
        block = source.read(count)
        check(len(block) == count and copy.read(count) == block, "recovery copy differs from the retained member")
        remaining -= count
    return copied


def recover_member(stack, files, protection, path, pending, start, size, pin, use_copy):
    existing = os.path.lexists(path)

    def cleanup(identity):
        with private_archive_stream(files, path, protection) as copy:
            check(os.path.samestat(identity, os.fstat(copy.fileno())), "recovery copy identity changed")
            verify_copy_prefix(copy, pending, start, size)
            discard_private_copy(copy)

    with private_archive_stream(files, path, protection, create=not existing) as copy:
        copied = verify_copy_prefix(copy, pending, start, size)
        stack.callback(cleanup, os.fstat(copy.fileno()))
        if use_copy:
            sparse = preserve_sparse(files, pending, copy, size, protection["efs_required"])
            source = logical_reader(pending)
            remaining = size - copied
            while remaining:
                block = source.read(min(CHUNK, remaining))
                check(block, "incomplete private recovery copy")
                write_tail(copy, block, sparse)
                remaining -= len(block)
            copy.flush()
    if use_copy:
        saved = stack.enter_context(held(files, path, share_directory_writes=True))
        check(logical_hash(saved) == pin, "original member pin mismatch")
        return saved


def recover(args, files, program, workspace, protection):
    path, destination = local_path(args.pending), local_path(args.out)
    check(path.parent == workspace and os.path.samefile(path.parent, workspace) and
          re.fullmatch(re.escape(PENDING) + "[0-9a-f]{32}", path.name),
          "select a publisher pending file directly inside the destination store")
    path = workspace / path.name
    check_archive_name(destination)
    check(not os.path.lexists(destination), "a new final archive name is required")
    efs = protection["efs_required"]
    copy_paths = recovery_copies(path)
    with private_archive_stream(files, path, protection) as pending, ExitStack() as stack:
        retained = os.fstat(pending.fileno()).st_size
        check(retained <= HEADER.size + REPORT_MAX + PE_MAX + DUMP_MAX, "invalid pending archive size")
        check(logical_hash(pending) == args.pending_sha256, "pending archive pin mismatch")
        paths = [local_path(v) if v is not None else None for v in (args.report, args.reference, args.dump)]
        check(all(p not in copy_paths for p in paths), "a recovery copy cannot be supplied as an original")
        originals = [stack.enter_context(held(files, p, share_directory_writes=True)) if p else None for p in paths]
        stats = [os.fstat(s.fileno()) if s is not None else None for s in originals]
        supplied = [s for s in stats if s is not None]
        check(len({(s.st_dev, s.st_ino) for s in supplied}) == len(supplied), "original roles share a file")
        check(efs or not any(encrypted(files, s) for s in originals if s is not None),
              "destination would drop original file encryption")

        pending.seek(0)
        if retained < HEADER.size:
            check(all(s is not None for s in stats), "a partial header requires all three originals")
            check(args.packing_reader_sha256 == args.debugger_sha256, "finishing a partial header requires its publishing reader")
            sizes = tuple(s.st_size for s in stats)
            check_sizes(*sizes)
            header = HEADER.pack(MAGIC, int(efs), *sizes, bytes.fromhex(args.packing_reader_sha256))
        else:
            header = pending.read(HEADER.size)
            archive_efs, sizes, reader_pin = header_fields(header)
            check(archive_efs == efs and reader_pin == args.packing_reader_sha256, "pending archive policy or reader mismatch")
        total = HEADER.size + sum(sizes)
        check(retained <= total, "archive extent mismatch")
        check(all(st is None or st.st_size == size for st, size in zip(stats, sizes)), "original member size mismatch")

        report_size, pe_size, dump_size = sizes
        have_report = min(report_size, max(retained - HEADER.size, 0))
        if originals[0] is None:
            check(have_report == report_size, "original report required for missing bytes")
            pending.seek(HEADER.size)
            raw = pending.read(report_size)
        else:
            raw = originals[0].read(report_size)
        page = observation(raw, args.report_sha256)
        members = [(io.BytesIO(header), HEADER.size, sha(header)), (io.BytesIO(raw), report_size, args.report_sha256)]
        start = HEADER.size + report_size
        input_paths = []
        with ExitStack() as reconstructed:
            for label, copy_path, source, original, size, pin in (
                    ("reference", copy_paths[0], originals[1], paths[1], pe_size, page["expected_reference_sha256"]),
                    ("dump", copy_paths[1], originals[2], paths[2], dump_size, page["expected_dump_sha256"])):
                if source is None or os.path.lexists(copy_path):
                    check(size == 0 or retained >= start + size, f"original {label} required for missing bytes")
                    copy = recover_member(reconstructed, files, protection, copy_path, pending, start, size, pin, source is None)
                if source is None:
                    original, source = copy_path, copy
                members.append((source, size, pin))
                input_paths.append(original)
                start += size
            package_pin, suffix = verify_prefix_and_suffix(pending, retained, members)
            pe, dump = input_paths
            code = reproduce(program, dump, pe, page, raw)
        # Only supplied originals and in-memory header/report bytes can have a missing suffix.
        # All private verification copies have been removed before the first recoverable write.
        append_suffix(pending, retained, suffix, bool(attributes(files, pending) & stat.FILE_ATTRIBUTE_SPARSE_FILE) and not efs)
        seal_archive(pending, destination, package_pin, before_rename=lambda: verify_pending_file(files, pending, protection))
    return dict(archive_sha256=package_pin, archive_requires_efs=efs, packing_reader_sha256=args.packing_reader_sha256,
                native_exit_code=code, pending_archive_sha256=args.pending_sha256, retained_prefix_bytes=str(retained),
                appended_bytes=str(total - retained))


def safe_sinks(argv):
    try:
        if not any(stat.S_ISREG(os.fstat(s.fileno()).st_mode) for s in (sys.stdout, sys.stderr) if s is not None):
            return True
        selected = list(argv)
        for i, arg in enumerate(argv):
            flag, equals, value = arg.partition("=")
            if flag in ("--out", "--private-workspace") and (equals or i + 1 < len(argv)):
                path = local_path(value if equals else argv[i + 1])
                root = path.parent if flag == "--out" else path
                selected.extend(str(root / name) for name in ("store.knprivacy", "store.knstorelock"))
            if flag == "--pending" and (equals or i + 1 < len(argv)):
                pending = local_path(value if equals else argv[i + 1])
                if re.fullmatch(re.escape(PENDING) + "[0-9a-f]{32}", pending.name):
                    selected.extend(map(str, recovery_copies(pending)))
        return outputs_safe(selected)
    except (OSError, ValueError):
        return False


def main(argv):
    if not safe_sinks(argv):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    writer = commands.add_parser("pack", allow_abbrev=False)
    reader = commands.add_parser("replay", allow_abbrev=False)
    recovery = commands.add_parser("recover", allow_abbrev=False, help="finish an interrupted private publication")
    fingerprint = commands.add_parser("hash", allow_abbrev=False, help="hash the logical bytes of a local archive or member")
    fingerprint.add_argument("--input", required=True, help="one local file within the maximum archive size")
    for op in (writer, reader, recovery):
        op.add_argument("--debugger", required=True, help="installed offline KnLiveDbg executable")
        op.add_argument("--debugger-sha256", required=True, help="independent digest of that executable")
        op.add_argument("--report-sha256", required=True, help="independent digest of the original native stdout")
    for op in (writer, recovery):
        op.add_argument("--report", required=op is writer, help="original UTF-8 dump-image-iat stdout including its newline")
        op.add_argument("--reference", required=op is writer, help="original reference PE")
        op.add_argument("--dump", required=op is writer, help="original user minidump")
        op.add_argument("--out", required=True, help="new archive directly inside an initialized private store")
    recovery.add_argument("--pending", required=True, help="the explicitly chosen pending file in that store")
    recovery.add_argument("--pending-sha256", required=True, help="digest of the pending bytes after interruption")
    recovery.add_argument("--packing-reader-sha256", help="original publishing reader digest if different from --debugger-sha256")
    reader.add_argument("--archive", required=True)
    reader.add_argument("--archive-sha256", required=True, help="independently retained archive digest")
    reader.add_argument("--private-workspace", required=True, help="initialized private store for replay files")
    args = parser.parse_args(argv)
    report = dict(schema="kn.minidump_iat_archive.v1", operation=args.command, status="rejected")
    try:
        check(os.name == "nt", "minidump archive verification requires Windows")
        if args.command == "hash":
            with held(WindowsFiles(), local_path(args.input), share_directory_writes=True) as source:
                size = os.fstat(source.fileno()).st_size
                check(size <= HEADER.size + REPORT_MAX + PE_MAX + DUMP_MAX, "input exceeds the maximum archive extent")
                report.update(status="hashed", input_bytes=str(size), sha256=logical_hash(source))
                return write_result(encoded(report)) if safe_sinks(argv) else 2
        args.debugger_sha256 = digest(args.debugger_sha256.lower())
        args.report_sha256 = digest(args.report_sha256.lower())
        if args.command == "replay":
            args.archive_sha256 = digest(args.archive_sha256.lower())
        elif args.command == "recover":
            args.pending_sha256 = digest(args.pending_sha256.lower())
            args.packing_reader_sha256 = digest((args.packing_reader_sha256 if args.packing_reader_sha256 is not None
                                                 else args.debugger_sha256).lower())
        program = local_path(args.debugger)
        workspace = local_path(args.private_workspace) if args.command == "replay" else local_path(args.out).parent
        files = WindowsFiles()
        with ExitStack() as stack:
            exe = stack.enter_context(held(files, program))
            check(file_hash(exe) == args.debugger_sha256, "debugger pin mismatch")
            files.parents(stack, workspace.parent, set())
            stack.enter_context(files.hold(workspace, directory=True))
            stack.enter_context(files.hold(workspace / "store.knprivacy"))
            result = native_result(program, "privacy", workspace)
            check(result.returncode == 0, "private store validation failed")
            protection = verified_protection(DECODE(result.stdout))
            if args.command == "pack":
                evidence = pack(args, files, program, protection)
                status = "archived"
            elif args.command == "recover":
                evidence = recover(args, files, program, workspace, protection)
                status = "recovered"
            else:
                evidence = replay(args, files, program, workspace, protection)
                status = "reproduced"
        report.update(evidence, status=status, report_sha256=args.report_sha256,
                      debugger_sha256=args.debugger_sha256, original_report_reproduced=True)
    except OutputCollision:
        return 2
    except (KeyError, AttributeError, TypeError, IndexError, RecursionError, struct.error, UnicodeError):
        report["reason"] = "invalid minidump archive or report structure"
    except OSError as exc:
        hashing = args.command == "hash"
        report["reason"] = "could not read the selected input" if hashing else "archive I/O or native reader unavailable"
        if hashing or args.command == "recover":
            if exc.errno is not None:
                report["errno"] = exc.errno
            if getattr(exc, "winerror", None) is not None:
                report["win32_error"] = exc.winerror
            if exc.errno == errno.ENOSPC or getattr(exc, "winerror", None) in (39, 112):
                report["reason"] = "insufficient space to hash the input" if hashing else "insufficient space for archive recovery"
    except subprocess.TimeoutExpired:
        report["reason"] = "native reader timed out" if args.command == "recover" else "archive I/O or native reader unavailable"
    except ValueError as exc:
        report["reason"] = str(exc)
    if not safe_sinks(argv):
        return 2
    return write_result(encoded(report)) or int(report["status"] == "rejected")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
