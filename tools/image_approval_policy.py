"""Select a signed approval row and its native validity window from retained evidence."""
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import re
import runpy

from owned_module_benchmark import sha
from retained_corpus import CHUNK, MAX_DOCUMENT, regular_file
from saved_etl_comparison import digest


DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]
COMPARISONS = {"kn.executable_page.direct.v1", "kn.executable_slice.direct.v1",
               "kn.executable_slice.secondary.v1", "kn.executable_sweep.temporal.v1"}
NATIVE_LIMIT = 64 << 10
IMAGE_LIMIT = 64 << 20
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class Denied(ValueError):
    """The publisher evidence cannot authorize this specific change."""


def require(test, reason):
    if not test:
        raise Denied(reason)


def fields(value, names):
    return type(value) is dict and value.keys() == set(names.split())


def identifier(value):
    return (type(value) is str and 0 < len(value.encode("utf-16-le")) <= 256 and
            all(ord(ch) >= 32 and ord(ch) != 127 for ch in value))


def hash_field(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def number(value, maximum=MAX_U64):
    if type(value) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise ValueError("invalid native integer")
    result = int(value)
    if result > maximum:
        raise ValueError("native integer outside range")
    return result


def window(record):
    epoch, start, stop = (number(record[k]) for k in ("policy_epoch", "not_before_filetime", "not_after_filetime"))
    if not (epoch and 0 < start < stop):
        raise ValueError("invalid native validity window")
    return epoch, start, stop


def rows(value):
    return type(value) is list and 1 <= len(value) <= 128


def signature_policy(value):
    if type(value) is not dict or value.get("kind") not in ("embedded", "catalog"):
        return False
    keys = "kind revocation signer_certificate_sha256"
    if value["kind"] == "catalog":
        keys += " catalog_sha256"
    return (fields(value, keys) and value["revocation"] in ("none", "cached_chain") and
            hash_field(value["signer_certificate_sha256"]) and
            (value["kind"] != "catalog" or hash_field(value["catalog_sha256"])))


def parse_policy(raw):
    try:
        obj = DECODE(raw)
        if not (fields(obj, "schema policy_id policy_epoch not_before_filetime not_after_filetime approvals") and
                obj["schema"] in ("kn.image_approval_policy.v1", "kn.image_approval_policy.v2") and
                identifier(obj["policy_id"]) and rows(obj["approvals"])):
            raise ValueError
        bounds = window(obj)
        seen = set()
        windows = obj["schema"] == "kn.image_approval_policy.v2"
        keys = "image_sha256 manifest_sha256 issuer" + (" reference_signature" if windows else "")
        for row in obj["approvals"]:
            if not (fields(row, keys) and hash_field(row["image_sha256"]) and hash_field(row["manifest_sha256"]) and
                    identifier(row["issuer"]) and row["manifest_sha256"] not in seen and
                    (not windows or signature_policy(row["reference_signature"]))):
                raise ValueError
            seen.add(row["manifest_sha256"])
        return obj, bounds
    except (ValueError, RecursionError):
        raise Denied("invalid_source_policy") from None


def parse_manifest(raw):
    try:
        obj = DECODE(raw)
        if not (fields(obj, "schema image_sha256 issuer policy_epoch not_before_filetime not_after_filetime "
                           "comparison_policy hash_basis changes") and obj["schema"] == "kn.authorized_image_changes.v1" and
                hash_field(obj["image_sha256"]) and identifier(obj["issuer"]) and rows(obj["changes"]) and
                type(obj["comparison_policy"]) is str and obj["comparison_policy"] in COMPARISONS and
                obj["hash_basis"] == "non_fixup_compared_bytes.v1"):
            raise ValueError
        bounds = window(obj)
        end = 0
        for row in obj["changes"]:
            if not (fields(row, "rva length before_sha256 after_sha256") and hash_field(row["before_sha256"]) and
                    hash_field(row["after_sha256"]) and row["before_sha256"] != row["after_sha256"]):
                raise ValueError
            rva, length = number(row["rva"], MAX_U32), number(row["length"], 4096)
            if length == 0 or rva < end or rva + length > MAX_U32:
                raise ValueError
            end = rva + length
        return obj, bounds
    except (ValueError, RecursionError):
        raise Denied("invalid_change_manifest") from None


def filetime(instant):
    delta = instant - EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def read_document(path, limit):
    with regular_file(path) as stream:
        data = stream.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError("input document outside byte limit")
    return data


def image_identity(path):
    with regular_file(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        if not 0 < size <= IMAGE_LIMIT:
            raise ValueError("reference outside native byte limit")
        observed = 0
        digest = hashlib.sha256()
        while observed < size:
            block = stream.read(min(CHUNK, size - observed))
            if not block:
                raise ValueError("reference shortened during read")
            observed += len(block)
            digest.update(block)
        if stream.read(1):
            raise ValueError("reference grew during read")
        return digest.hexdigest(), size


def authority_parameters(args, publisher):
    root = digest(args.trusted_root_sha256)
    minimum_version = publisher.root_version_floor(args.minimum_root_version)
    name = publisher.target_name(args.policy_target)
    instant = publisher.verification_time(args.verification_time)
    at = filetime(instant)
    if at < 0:
        raise ValueError("verification time precedes the Windows FILETIME epoch")
    return root, minimum_version, name, instant, at


def select_approval(args, receipt, publisher, parameters):
    root, minimum_version, name, instant, at = parameters
    envelope = read_document(args.publisher_reference, MAX_DOCUMENT)
    targets, proof = publisher.check_reference(envelope, DECODE, root, instant, minimum_version)
    receipt.update(trusted_root_sha256=root, verification_time_utc=instant.isoformat().replace("+00:00", "Z"),
                   publisher_reference_sha256=sha(envelope), policy_target=name, publisher_proof=proof)
    require(proof["status"] == "verified", proof["status"])
    source = read_document(args.policy, NATIVE_LIMIT)
    pin = sha(source)
    verdict, reason, descriptor = publisher.compare_target(
        (name, len(source), False), pin, (0, len(source)), targets, io.BytesIO(source), {})
    receipt.update(source_policy_sha256=pin, policy_target_comparison=descriptor)
    require(verdict == "positive", reason)
    policy, (epoch, start, stop) = parse_policy(source)
    windows = policy["schema"] == "kn.image_approval_policy.v2"
    require(windows or not args.require_windows_publisher, "windows_publisher_policy_required")
    require(windows or args.catalog is None, "unexpected_catalog")
    if windows:
        receipt["schema"] = "kn.image_approval_provision.v2"
    raw_manifest = read_document(args.manifest, NATIVE_LIMIT)
    manifest, (manifest_epoch, lower, upper) = parse_manifest(raw_manifest)
    manifest_pin = sha(raw_manifest)
    receipt.update(source_approval_count=len(policy["approvals"]), manifest_sha256=manifest_pin)
    if not windows:
        image_pin, size = image_identity(args.reference)
        receipt.update(reference_sha256=image_pin, reference_bytes=size)
        require(manifest["image_sha256"] == image_pin, "reference_mismatch")
    require(epoch == manifest_epoch, "epoch_mismatch")
    selected = dict(image_sha256=manifest["image_sha256"], manifest_sha256=manifest_pin, issuer=manifest["issuer"])
    approved = next((row for row in policy["approvals"] if all(row[k] == v for k, v in selected.items())), None)
    require(approved is not None, "approval_tuple_missing")
    # Both the captured observation and the assessment must fit the resulting native half-open window.
    role_expiry = min(filetime(datetime.fromisoformat(v["expires"])) for v in proof["roles"].values())
    start, stop = max(start, lower), min(stop, upper, role_expiry)
    require(start <= at < stop, "outside_approval_window")
    projected = dict(policy, schema="kn.image_approval_policy.v1", not_before_filetime=str(start),
                     not_after_filetime=str(stop), approvals=[selected])
    return projected, approved.get("reference_signature")


def record_windows(receipt, signature, projected):
    receipt["windows_publisher"] = signature
    require(signature["status"] == "verified", signature["status"])
    checked = filetime(datetime.fromisoformat(signature["started_utc"]))
    finished = filetime(datetime.fromisoformat(signature["finished_utc"]))
    require(int(projected["not_before_filetime"]) <= checked <= finished < int(projected["not_after_filetime"]),
            "outside_windows_verification_window")
    receipt.update(reference_sha256=signature["reference_sha256"], reference_bytes=signature["reference_bytes"])


def record_projection(receipt, projected, pin):
    receipt.update(status="provisioned", issuer=projected["approvals"][0]["issuer"], policy_epoch=projected["policy_epoch"],
                   not_before_filetime=projected["not_before_filetime"], not_after_filetime=projected["not_after_filetime"],
                   native_policy_sha256=pin)
