"""Seal and replay one private dump-image-iat observation with its original dump and reference PE."""
import argparse
from contextlib import ExitStack
import ctypes
from ctypes import wintypes
import hashlib
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
from windows_private_archive import held, native_result, publish_archive, replay_directory, verified_protection


MAGIC = b"KNMDIAT1"
# Magic, EFS requirement, report/PE/dump byte counts and the publishing verifier's SHA-256.
HEADER = struct.Struct("<8sIIQQ32s")
REPORT_MAX, PE_MAX, DUMP_MAX = 1 << 20, 64 << 20, 8 << 30
DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]


def encrypted(files, stream):
    import msvcrt
    attributes = (wintypes.DWORD * 2)()
    if not files.info(msvcrt.get_osfhandle(stream.fileno()), 9, attributes, ctypes.sizeof(attributes)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(attributes[0] & stat.FILE_ATTRIBUTE_ENCRYPTED)


def check_sizes(report, pe, dump):
    check(0 < report <= REPORT_MAX and 0 <= pe <= PE_MAX and 0 <= dump <= DUMP_MAX,
          "original evidence outside its byte limits")


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


def copy_original(source, output, length, expected, package_hash=None):
    actual = hashlib.sha256()
    while length:
        block = source.read(min(length, CHUNK))
        check(block and output.write(block) == len(block), "incomplete original file transfer")
        actual.update(block)
        if package_hash is not None:
            package_hash.update(block)
        length -= len(block)
    check(actual.hexdigest() == expected, "original member pin mismatch")


def pack(args, files, program, protection):
    destination = local_path(args.out)
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
            check(file_hash(source) == pin, "original member pin mismatch")
            source.seek(0)
        code = reproduce(program, dump_path, pe_path, page, raw)

        def write(target):
            header = HEADER.pack(MAGIC, int(protection["efs_required"]), *sizes, bytes.fromhex(args.debugger_sha256))
            package_hash = hashlib.sha256(header)
            target.write(header)
            target.write(raw)
            package_hash.update(raw)
            for source, size, pin in zip(sources[1:], sizes[1:], pins):
                copy_original(source, target, size, pin, package_hash)
            return dict(archive_sha256=package_hash.hexdigest(), archive_requires_efs=protection["efs_required"],
                        packing_reader_sha256=args.debugger_sha256, native_exit_code=code)

        return publish_archive(destination, files, protection, write, pending_prefix=".kniatarchive.pending-")


def replay(args, files, program, workspace, protection):
    with held(files, local_path(args.archive), share_directory_writes=True) as source:
        length = os.fstat(source.fileno()).st_size
        check(HEADER.size < length <= HEADER.size + REPORT_MAX + PE_MAX + DUMP_MAX, "invalid archive size")
        header = source.read(HEADER.size)
        magic, flags, report_size, pe_size, dump_size, reader = HEADER.unpack(header)
        check(magic == MAGIC and flags in (0, 1), "invalid archive header")
        check_sizes(report_size, pe_size, dump_size)
        check(HEADER.size + report_size + pe_size + dump_size == length, "archive extent mismatch")
        raw = source.read(report_size)
        # Interpret the same header and report bytes that enter the archive digest.
        # The extracted payloads must independently match their original pins on the second pass.
        archive_hash = hashlib.sha256(header)
        archive_hash.update(raw)
        for block in iter(lambda: source.read(CHUNK), b""):
            archive_hash.update(block)
        check(archive_hash.hexdigest() == args.archive_sha256, "archive pin mismatch")
        check(protection["efs_required"] or not (flags or encrypted(files, source)),
              "replay workspace would drop archive encryption")
        page = observation(raw, args.report_sha256)
        source.seek(HEADER.size + report_size)
        with replay_directory(workspace, ".kniat-replay-") as scratch, files.hold(scratch, directory=True):
            pe, dump = scratch / "reference.knblob", scratch / "original.dmp"
            for path, size, pin in ((pe, pe_size, page["expected_reference_sha256"]),
                                    (dump, dump_size, page["expected_dump_sha256"])):
                with path.open("xb") as output:
                    check(not protection["efs_required"] or encrypted(files, output),
                          "private replay file did not inherit EFS")
                    copy_original(source, output, size, pin)
            # Keep both reconstructed files immutable across the native invocation, even for gap reports.
            with (held(files, pe, share_directory_writes=True) as saved_pe,
                  held(files, dump, share_directory_writes=True) as saved_dump):
                check(file_hash(saved_pe) == page["expected_reference_sha256"] and
                      file_hash(saved_dump) == page["expected_dump_sha256"], "replay file identity changed")
                code = reproduce(program, dump, pe, page, raw)
        return dict(archive_sha256=args.archive_sha256, archive_requires_efs=bool(flags),
                    packing_reader_sha256=reader.hex(), native_exit_code=code, observation=page)


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
    for op in (writer, reader):
        op.add_argument("--debugger", required=True, help="installed offline KnLiveDbg executable")
        op.add_argument("--debugger-sha256", required=True, help="independent digest of that executable")
        op.add_argument("--report-sha256", required=True, help="independent digest of the original native stdout")
    writer.add_argument("--report", required=True, help="original UTF-8 dump-image-iat stdout including its newline")
    writer.add_argument("--reference", required=True, help="original reference PE")
    writer.add_argument("--dump", required=True, help="original user minidump")
    writer.add_argument("--out", required=True, help="new archive directly inside an initialized private store")
    reader.add_argument("--archive", required=True)
    reader.add_argument("--archive-sha256", required=True, help="independently retained archive digest")
    reader.add_argument("--private-workspace", required=True, help="initialized private store for replay files")
    args = parser.parse_args(argv)
    packing = args.command == "pack"
    report = dict(schema="kn.minidump_iat_archive.v1", operation=args.command, status="rejected")
    try:
        check(os.name == "nt", "minidump archive verification requires Windows")
        args.debugger_sha256 = digest(args.debugger_sha256.lower())
        args.report_sha256 = digest(args.report_sha256.lower())
        if not packing:
            args.archive_sha256 = digest(args.archive_sha256.lower())
        program = local_path(args.debugger)
        workspace = local_path(args.out).parent if packing else local_path(args.private_workspace)
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
            if packing:
                evidence = pack(args, files, program, protection)
            else:
                evidence = replay(args, files, program, workspace, protection)
        report.update(evidence, status="archived" if packing else "reproduced", report_sha256=args.report_sha256,
                      debugger_sha256=args.debugger_sha256, original_report_reproduced=True)
    except OutputCollision:
        return 2
    except (KeyError, AttributeError, TypeError, IndexError, RecursionError, struct.error, UnicodeError):
        report["reason"] = "invalid minidump archive or report structure"
    except (OSError, subprocess.TimeoutExpired):
        report["reason"] = "archive I/O or native reader unavailable"
    except ValueError as exc:
        report["reason"] = str(exc)
    if not safe_sinks(argv):
        return 2
    return write_result(encoded(report)) or int(report["status"] == "rejected")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
