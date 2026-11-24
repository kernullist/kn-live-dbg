"""Pack or replay a private native approval collection together with its original publisher evidence."""
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import uuid

from etl_reader_process import WindowsFiles, file_hash
from image_approval_policy import (DECODE, IMAGE_LIMIT, NATIVE_LIMIT, authority_parameters, fields, filetime, hash_field,
                                   image_identity, number, record_projection, record_windows, select_approval)
from owned_module_benchmark import check, encoded, sha
from retained_corpus import CHUNK, MAX_DOCUMENT, OutputCollision
from saved_etl_comparison import digest, local_path, outputs_safe, write_result
from windows_private_archive import publish_archive


MAGIC = b"KNAPARC1"
MIB = 1 << 20
SEGMENTS = ("00000000000000000001.knjseg", "00000000000000000002.knjseg")
# The first three records are the native session and its two journal segments.
# The remaining records hold the exact TUF envelope, signed policy, receipt and optional catalog.
LIMITS = (4096, 2 * MIB, 2 * MIB, MAX_DOCUMENT, NATIVE_LIMIT, MAX_DOCUMENT, IMAGE_LIMIT)
HEADER = struct.Struct("<8sI7I")
MAX_PACKAGE = 448 * MIB
MAX_SCOPE_INPUTS = 4097
PATH_FLAGS = {"--collection", "--publisher-reference", "--policy", "--receipt", "--catalog",
              "--out", "--archive", "--private-workspace", "--debugger"}


def collection_paths(directory):
    check(directory.parent.name == "collections" and re.fullmatch(r"0|[1-9][0-9]{0,19}", directory.name),
          "invalid native collection directory")
    return (directory / "session.knsession", *(directory / "journal-segments" / n for n in SEGMENTS))


@contextmanager
def held(files, path):
    with ExitStack() as stack:
        files.parents(stack, path.parent, set(), share_directory_writes=False)
        stream = stack.enter_context(files.hold(path))
        if not outputs_safe((), stream):
            raise OutputCollision("output aliases an input")
        yield stream


def document(files, path, limit):
    with held(files, path) as source:
        size = os.fstat(source.fileno()).st_size
        check(0 < size <= limit, "approval input outside its byte limit")
        raw = source.read(size)
        check(len(raw) == size and not source.read(1), "approval input size changed")
        return raw


def journal_layout(records):
    """Admit only fixed role names and content-addressed native files before opening any declared path."""
    session, first, last = (DECODE(raw)["payload"] for raw in records[:3])
    cid = session["collection_id"]
    check(type(cid) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", cid), "invalid collection ID")
    scoped = session["policy"] == "kn.approved_image_scope_collection_journal.v1"
    check(scoped or session["policy"] == "kn.approved_image_collection_journal.v1", "expected an approval collection")
    for seq, row in enumerate((first, last), 1):
        check(row["collection_id"] == cid and row["sequence"] == str(seq) and
              row["previous_sha256"] == sha(records[seq - 1]), "broken native journal chain")
    decision, closure = first["transaction"], last["transaction"]
    kind = "image_scope_approval" if scoped else "image_approval"
    check(decision["kind"] == kind and closure["kind"] == "closure", "expected a closed native approval")
    members, ending = decision["members"], closure["members"]
    check(type(members) is list and 5 <= len(members) <= (MAX_SCOPE_INPUTS + 4 if scoped else 5) and
          type(ending) is list and len(ending) == 1, "invalid approval membership count")
    root = f"image-approvals/scope-assessment-{cid}.knscopeapproval" if scoped else f"image-approvals/assessment-{cid}.knapprovalcase"
    ledger = f"image-approvals/scope-session-{cid}.knscopeledger" if scoped else f"image-approvals/session-{cid}.knapprovalledger"
    roles, entries = {}, {}
    scope_bytes = 0
    for member in [*members, *ending]:
        check(fields(member, "path sha256 bytes schema"), "invalid approval member")
        name, pin = member["path"], digest(member["sha256"])
        size = number(member["bytes"])
        if name == root:
            role, limit = "root", (8 if scoped else 4) * MIB
        elif name == ledger:
            role, limit = "ledger", 2 * MIB
        elif name == f"image-approvals/changes-{pin}.knchange":
            role, limit = "manifest", NATIVE_LIMIT
        elif name == f"image-approvals/policy-{pin}.knapproval":
            role, limit = "native", NATIVE_LIMIT
        elif name == f"image-references/{pin}.knblob":
            role, limit = "reference", IMAGE_LIMIT
        elif not scoped and name == f"image-captures/capture-{cid}-{pin}.kncapture":
            role, limit = "capture", 4 * MIB
        elif scoped and name == f"image-scope-inputs/{pin}.knscopeblob":
            role, limit = "scope_input", 2 * MIB
            scope_bytes += size
        else:
            raise ValueError("unrecognized approval member path")
        check(name not in entries and 0 < size <= limit, "duplicate or oversized native member")
        if role != "scope_input":
            check(role not in roles, "duplicate native role")
            roles[role] = name
        entries[name] = (pin, size)
    expected = {"root", "ledger", "manifest", "native", "reference"}
    if not scoped:
        expected.add("capture")
    check(roles.keys() == expected and scope_bytes <= 256 * MIB and (not scoped or scope_bytes > 0) and
          ending[0]["path"] == ledger and decision["id"] == entries[root][0], "incomplete native approval")
    return cid, roles, entries


def copy_member(read, target, size, expected):
    result = hashlib.sha256()
    while size:
        block = read(min(size, CHUNK))
        check(block, "truncated native member")
        target.write(block)
        result.update(block)
        size -= len(block)
    check(result.hexdigest() == expected, "native member bytes differ from the journal")


def native(program, *args):
    # The executable and its ancestors remain leased. Never search an extracted directory for a program or DLL.
    result = subprocess.run([str(program), "--offline", "!kmon", *map(str, args), "/json"], executable=program,
                            cwd=program.parent, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=180, creationflags=subprocess.CREATE_NO_WINDOW)
    check(result.returncode == 0 and 0 < len(result.stdout) <= 20 * MIB, f"native {args[0]} did not verify")
    return DECODE(result.stdout)


def check_journal(program, collection, parts, root, external_head):
    recovered = native(program, "journal", collection)
    head = sha(parts[2])
    check(recovered["schema"] == "kn.evidence_journal_recovery.v1" and recovered["status"] == "verified_prefix" and
          recovered["closed"] is True and recovered["committed_segments"] == "2" and
          recovered["denominator_scope"] == "verified_collection_prefix" and
          recovered["session_sha256"] == sha(parts[0]) and recovered["head_sha256"] == head and
          recovered["collection_id"] == collection.name and recovered["committed_approval_paths"] == [root],
          "native journal did not confirm this approval closure")
    check(external_head is None or external_head == head, "externally supplied journal head differs")
    return head


def privacy(program, root):
    result = native(program, "privacy", root)
    check(result["schema"] == "kn.evidence_privacy.v1" and result["status"] == "ready" and
          result["root_acl_verified"] is True and type(result["efs_required"]) is bool,
          "an initialized private store is required")
    return result


@contextmanager
def replay_directory(workspace):
    # Windows mode 0700 grants Administrators access. Create a new child with the private parent's inherited ACL.
    directory = workspace / (".knapproval-replay-" + uuid.uuid4().hex)
    directory.mkdir()
    identity = directory.stat(follow_symlinks=False)
    try:
        yield directory
    finally:
        check(directory.resolve(strict=True) == workspace.resolve(strict=True) / directory.name and
              os.path.samestat(identity, directory.stat(follow_symlinks=False)),
              "private replay directory identity changed")
        shutil.rmtree(directory)


def read_records(read):
    raw = read(HEADER.size)
    check(len(raw) == HEADER.size, "truncated approval archive header")
    magic, efs_required, *sizes = HEADER.unpack(raw)
    check(magic == MAGIC and efs_required in (0, 1) and all(0 < n <= limit for n, limit in zip(sizes[:-1], LIMITS[:-1])) and
          sizes[-1] <= LIMITS[-1], "invalid approval archive framing")
    parts = []
    for size in sizes:
        raw = read(size)
        check(len(raw) == size, "truncated archive evidence")
        parts.append(raw)
    return bool(efs_required), parts


def same_json(a, b):
    # Python equality otherwise allows a receipt to substitute True for 1.
    return json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(b, sort_keys=True, allow_nan=False)


def historical_windows(signature, policy, reference, catalog):
    base = "signature_policy started_utc finished_utc reference_sha256 reference_bytes wintrust_status signer_certificate_sha256 status"
    is_catalog = policy["kind"] == "catalog"
    if is_catalog:
        base += " catalog_sha256 catalog_bytes catalog_member_sha256"
    check(fields(signature, base) and same_json(signature["signature_policy"], policy) and
          signature["status"] == "verified" and signature["wintrust_status"] == "0x00000000" and
          signature["signer_certificate_sha256"] == policy["signer_certificate_sha256"] and
          type(signature["reference_bytes"]) is int and
          (signature["reference_sha256"], signature["reference_bytes"]) == reference, "invalid recorded Windows verification")
    check(is_catalog == bool(catalog), "catalog disagrees with the signed signature policy")
    if is_catalog:
        check(type(signature["catalog_bytes"]) is int and signature["catalog_bytes"] == len(catalog) and
              signature["catalog_sha256"] == policy["catalog_sha256"] == sha(catalog) and
              hash_field(signature["catalog_member_sha256"]), "recorded catalog evidence differs")
    for field in ("started_utc", "finished_utc"):
        check(type(signature[field]) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?\+00:00", signature[field]),
              "invalid recorded Windows clock")


def verify_authority(args, parts, store, roles):
    import publisher_truth
    envelope, source, original, catalog = parts[3:]
    check(sha(original) == args.receipt_sha256, "provisioning receipt pin mismatch")
    receipt = DECODE(original)
    floor = receipt["publisher_proof"].get("minimum_root_version")
    check(floor is None or type(floor) is int, "invalid recorded root version floor")
    inputs = argparse.Namespace(**vars(args))
    inputs.minimum_root_version = None if floor is None else str(floor)
    inputs.publisher_reference, inputs.policy = store / "publisher.json", store / "source.knapproval"
    inputs.manifest, inputs.reference = store / roles["manifest"], store / roles["reference"]
    inputs.catalog = store / "distribution.cat" if catalog else None
    for path, raw in ((inputs.publisher_reference, envelope), (inputs.policy, source), (inputs.catalog, catalog)):
        if path is not None:
            with path.open("xb") as target:
                target.write(raw)
    expected = dict(schema="kn.image_approval_provision.v1", status="rejected", native_policy_sha256=None)
    projected, policy = select_approval(inputs, expected, publisher_truth, authority_parameters(inputs, publisher_truth))
    minimum = publisher_truth.root_version_floor(args.minimum_root_version)
    root_version = expected["publisher_proof"]["roles"]["root"]["version"]
    check(minimum is None or root_version >= minimum, "root version below the independently requested minimum")
    fresh = None
    if policy is not None:
        signature = receipt["windows_publisher"]
        reference = image_identity(inputs.reference)
        check(reference[0] == projected["approvals"][0]["image_sha256"], "signed reference digest differs")
        historical_windows(signature, policy, reference, catalog)
        record_windows(expected, signature, projected)
        from windows_pe_trust import verify_reference
        fresh = verify_reference(inputs.reference, reference[0], IMAGE_LIMIT, inputs.catalog, policy)
        if policy["kind"] == "catalog" and (fresh["status"] == "verified" or "catalog_member_sha256" in fresh):
            check(fresh.get("catalog_member_sha256") == signature["catalog_member_sha256"], "Windows catalog member differs")
    raw = encoded(projected)
    check(raw == (store / roles["native"]).read_bytes(), "signed projection differs from the archived native policy")
    pin = sha(raw)
    record_projection(expected, projected, pin)
    check(same_json(receipt, expected), "retained provisioning receipt disagrees with the verified inputs")
    return pin, root_version, receipt.get("windows_publisher"), fresh


def verify_stream(stream, args, program, workspace, protection):
    length = stream.seek(0, os.SEEK_END)
    check(HEADER.size < length <= MAX_PACKAGE, "approval archive size outside limit")
    stream.seek(0)
    archive_digest = hashlib.sha256()

    def read(size):
        data = stream.read(size)
        archive_digest.update(data)
        return data

    efs_required, parts = read_records(read)
    check(not efs_required or protection["efs_required"], "private replay workspace would drop archive encryption")
    cid, roles, entries = journal_layout(parts)
    check(stream.tell() + sum(size for _, size in entries.values()) == length, "approval archive extent mismatch")
    check(sha(parts[5]) == args.receipt_sha256, "provisioning receipt pin mismatch")
    if args.journal_head_sha256 is not None:
        check(sha(parts[2]) == args.journal_head_sha256, "externally supplied journal head differs")
    with replay_directory(workspace) as scratch:
        store = scratch / "store"
        options = [] if protection["efs_required"] else ["/acl-only"]
        created = native(program, "init-store", store, *options)
        check(created["status"] == "ready" and created["root_acl_verified"] is True and
              created["efs_required"] is protection["efs_required"], "private replay store creation failed")
        collection = store / "collections" / cid
        (collection / "journal-segments").mkdir(parents=True)
        for path, raw in zip(collection_paths(collection), parts):
            with path.open("xb") as target:
                target.write(raw)
        # Locks belong to this replay instance. No source lock, index, or machine-bound privacy receipt is imported.
        (collection / "writer.knjlock").touch(exist_ok=False)
        for name, (pin, size) in sorted(entries.items()):
            path = store / name
            path.parent.mkdir(exist_ok=True)
            with path.open("xb") as target:
                copy_member(read, target, size, pin)
        check(not read(1), "trailing archive bytes")
        head = check_journal(program, collection, parts, roles["root"], args.journal_head_sha256)
        policy, version, original, fresh = verify_authority(args, parts, store, roles)
        replay = native(program, "replay-image-approval", store / roles["root"], policy)
        check(replay["status"] == "reproduced" and replay["mode"] == "original_assessment" and
              replay["root_file_sha256"] == entries[roles["root"]][0] and replay["policy_anchor_sha256"] == policy and
              replay["policy_anchor_matched"] is True and replay["original_assessment_reproduced"] is True and
              same_json(replay["assessment"], replay["recorded_assessment"]), "original native assessment did not reproduce")
        if original is not None:
            check(filetime(datetime.fromisoformat(original["finished_utc"])) <= number(replay["assessment"]["evaluation_filetime"]),
                  "recorded Windows verification finished after the original assessment")
        return dict(collection_id=cid, archive_sha256=archive_digest.hexdigest(), archive_requires_efs=efs_required,
                    journal_head_sha256=head, journal_membership_checked=True,
                    approval_root_sha256=replay["root_file_sha256"], native_policy_sha256=policy,
                    receipt_sha256=args.receipt_sha256, trusted_root_sha256=args.trusted_root_sha256,
                    terminal_root_version=version, policy_target=args.policy_target,
                    publisher_reference_sha256=sha(parts[3]), source_policy_sha256=sha(parts[4]),
                    original_windows_verification=original, current_windows_verification=fresh,
                    original_assessment_reproduced=True, assessment=replay["assessment"], collector_authenticated=False)


def pack(args, files, program, workspace, protection):
    destination = local_path(args.out)
    check(not os.path.lexists(destination), "archive destination already exists")
    collection = local_path(args.collection)
    paths = collection_paths(collection)
    origin = collection.parent.parent
    source_protection = privacy(program, origin)
    check(not source_protection["efs_required"] or protection["efs_required"], "destination would drop source encryption")
    sources = (*paths, local_path(args.publisher_reference), local_path(args.policy), local_path(args.receipt))
    parts = [document(files, p, limit) for p, limit in zip(sources, LIMITS)]
    parts.append(document(files, local_path(args.catalog), IMAGE_LIMIT) if args.catalog is not None else b"")
    cid, roles, entries = journal_layout(parts)
    check(cid == collection.name and sha(parts[5]) == args.receipt_sha256, "collection or original receipt mismatch")
    def write(target):
        target.write(HEADER.pack(MAGIC, int(protection["efs_required"]), *(len(raw) for raw in parts)))
        for raw in parts:
            target.write(raw)
        for name, (pin, size) in sorted(entries.items()):
            with held(files, origin / name) as source:
                check(os.fstat(source.fileno()).st_size == size, "native member size differs from the journal")
                copy_member(source.read, target, size, pin)
                check(not source.read(1), "native member grew")
        target.flush()
        check_journal(program, collection, parts, roles["root"], args.journal_head_sha256)
        return verify_stream(target, args, program, workspace, protection)

    return publish_archive(destination, files, protection, write)


def safe_sinks(argv):
    if not any(stat.S_ISREG(os.fstat(s.fileno()).st_mode) for s in (sys.stdout, sys.stderr) if s is not None):
        return True
    selected, collections = [], []
    for i, arg in enumerate(argv):
        flag, equals, value = arg.partition("=")
        if flag in PATH_FLAGS and (equals or i + 1 < len(argv)):
            path = local_path(value if equals else argv[i + 1])
            selected.append(path)
            if flag == "--collection":
                collections.append(path)
                selected.extend((*collection_paths(path), path / "writer.knjlock",
                                 path.parent.parent / "store.knprivacy", path.parent.parent / "store.knstorelock"))
            if flag in ("--out", "--private-workspace"):
                root = path.parent if flag == "--out" else path
                selected.extend((root / "store.knprivacy", root / "store.knstorelock"))
    if not outputs_safe(map(str, selected)):
        return False
    for directory in collections:
        records = [document(WindowsFiles(), p, lim) for p, lim in zip(collection_paths(directory), LIMITS)]
        _, _, entries = journal_layout(records)
        paths = [directory.parent.parent / name for name in entries]
        # A previously built index can also be the redirected file, even through a hard link.
        for index in ("chunks", "heads"):
            paths.extend(directory / "indexes" / index / (sha(raw) + ".knjindex") for raw in records)
        if not outputs_safe(map(str, paths)):
            return False
    return True


def main(argv):
    try:
        if not safe_sinks(argv):
            return 2
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    writer = sub.add_parser("pack", allow_abbrev=False, help="seal one closed native approval and its original authority")
    reader = sub.add_parser("replay", allow_abbrev=False, help="rebuild and verify both layers from the pinned archive")
    for op in (writer, reader):
        for flag, help_text in (("--debugger", "installed offline KnLiveDbg executable"),
                                ("--debugger-sha256", "independent digest of that executable"),
                                ("--receipt-sha256", "independently recorded digest of the original provisioning receipt"),
                                ("--trusted-root-sha256", "independent digest of the publisher's initial TUF root"),
                                ("--policy-target", "expected signed top-level policy target"),
                                ("--verification-time", "original UTC verification time, YYYYMMDDTHHMMSSZ")):
            op.add_argument(flag, required=True, help=help_text)
        op.add_argument("--journal-head-sha256", help="independently recorded native closure head")
        op.add_argument("--minimum-root-version", help="minimum accepted terminal TUF root version")
        op.add_argument("--require-windows-publisher", action="store_true", help="require a signed Windows publisher policy")
    writer.add_argument("--collection", required=True, help="private native store's collections/ID directory")
    writer.add_argument("--publisher-reference", required=True, help="exact retained TUF distribution envelope")
    writer.add_argument("--policy", required=True, help="exact signed source policy")
    writer.add_argument("--receipt", required=True, help="original successful provisioning receipt")
    writer.add_argument("--catalog", help="original catalog named by the signed policy")
    writer.add_argument("--out", required=True, help="new archive directly inside an initialized private store")
    reader.add_argument("--archive", required=True, help="retained approval archive")
    reader.add_argument("--archive-sha256", required=True, help="independently retained digest of the archive")
    reader.add_argument("--private-workspace", required=True, help="initialized private store for temporary replay files")
    args = parser.parse_args(argv)
    packing = args.command == "pack"
    report = dict(schema="kn.image_approval_archive_result.v1", operation=args.command, status="rejected")
    try:
        check(os.name == "nt", "native approval replay requires Windows")
        for pin in (args.debugger_sha256, args.receipt_sha256, args.trusted_root_sha256):
            digest(pin)
        if args.journal_head_sha256 is not None:
            digest(args.journal_head_sha256)
        if not packing:
            digest(args.archive_sha256)
        program = local_path(args.debugger)
        workspace = local_path(args.out).parent if packing else local_path(args.private_workspace)
        files = WindowsFiles()
        with ExitStack() as stack:
            exe = stack.enter_context(held(files, program))
            check(file_hash(exe) == args.debugger_sha256, "debugger pin mismatch")
            files.parents(stack, workspace.parent, set(), share_directory_writes=False)
            # Publishing a child by rename requires directory write sharing on Windows.
            stack.enter_context(files.hold(workspace, directory=True))
            protection = privacy(program, workspace)
            if packing:
                result = pack(args, files, program, workspace, protection)
            else:
                with held(files, local_path(args.archive)) as source:
                    check(HEADER.size < os.fstat(source.fileno()).st_size <= MAX_PACKAGE, "approval archive size outside limit")
                    check(file_hash(source) == args.archive_sha256, "approval archive pin mismatch")
                    result = verify_stream(source, args, program, workspace, protection)
                    check(result["archive_sha256"] == args.archive_sha256, "archive changed during replay")
        report.update(result, status="archived" if packing else "reproduced", debugger_sha256=args.debugger_sha256)
    except OutputCollision:
        return 2
    except (KeyError, AttributeError, TypeError, IndexError, RecursionError):
        report["reason"] = "invalid approval archive structure"
    except (OSError, subprocess.TimeoutExpired):
        report["reason"] = "approval archive I/O or native command unavailable"
    except ValueError as exc:
        report["reason"] = str(exc)
    return write_result(encoded(report)) or int(report["status"] == "rejected")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
