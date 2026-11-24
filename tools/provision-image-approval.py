"""Provision one native image approval from a locally retained, signed publisher policy."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import re
import runpy
import sys

from owned_module_benchmark import encoded, publish_new, sha
from retained_corpus import CHUNK, MAX_DOCUMENT, OutputCollision, regular_file
from saved_etl_comparison import digest, local_path, outputs_safe, write_result


DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]
PATH_OPTIONS = ("--publisher-reference", "--policy", "--manifest", "--reference", "--out")
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


def parse_policy(raw):
    try:
        obj = DECODE(raw)
        if not (fields(obj, "schema policy_id policy_epoch not_before_filetime not_after_filetime approvals") and
                obj["schema"] == "kn.image_approval_policy.v1" and identifier(obj["policy_id"]) and rows(obj["approvals"])):
            raise ValueError
        bounds = window(obj)
        seen = set()
        for row in obj["approvals"]:
            if not (fields(row, "image_sha256 manifest_sha256 issuer") and hash_field(row["image_sha256"]) and
                    hash_field(row["manifest_sha256"]) and identifier(row["issuer"]) and row["manifest_sha256"] not in seen):
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


def provision(args, receipt, publisher):
    root = digest(args.trusted_root_sha256)
    name = publisher.target_name(args.policy_target)
    instant = publisher.verification_time(args.verification_time)
    at = filetime(instant)
    if at < 0:
        raise ValueError("verification time precedes the Windows FILETIME epoch")
    destination = local_path(args.out)
    if os.path.lexists(destination):
        raise FileExistsError
    envelope = read_document(args.publisher_reference, MAX_DOCUMENT)
    targets, proof = publisher.check_reference(envelope, DECODE, root, instant)
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
    raw_manifest = read_document(args.manifest, NATIVE_LIMIT)
    manifest, (manifest_epoch, lower, upper) = parse_manifest(raw_manifest)
    manifest_pin = sha(raw_manifest)
    image_pin, size = image_identity(args.reference)
    receipt.update(source_approval_count=len(policy["approvals"]), manifest_sha256=manifest_pin,
                   reference_sha256=image_pin, reference_bytes=size)
    require(manifest["image_sha256"] == image_pin, "reference_mismatch")
    require(epoch == manifest_epoch, "epoch_mismatch")
    selected = dict(image_sha256=image_pin, manifest_sha256=manifest_pin, issuer=manifest["issuer"])
    require(selected in policy["approvals"], "approval_tuple_missing")
    # Both the captured observation and the assessment must fit the resulting native half-open window.
    role_expiry = min(filetime(datetime.fromisoformat(v["expires"])) for v in proof["roles"].values())
    start, stop = max(start, lower), min(stop, upper, role_expiry)
    require(start <= at < stop, "outside_approval_window")
    projected = dict(policy, not_before_filetime=str(start), not_after_filetime=str(stop), approvals=[selected])
    policy_data = encoded(projected)
    policy_pin = publish_new(destination, lambda stream: stream.write(policy_data))
    receipt.update(status="provisioned", issuer=manifest["issuer"], policy_epoch=str(epoch),
                   not_before_filetime=str(start), not_after_filetime=str(stop), native_policy_sha256=policy_pin)


def selected_paths(argv):
    for index, arg in enumerate(argv):
        flag, equals, value = arg.partition("=")
        if flag in PATH_OPTIONS and (equals or index + 1 < len(argv)):
            yield os.fspath(local_path(value if equals else argv[index + 1]))


def main(argv):
    try:
        if not outputs_safe(selected_paths(argv)):
            return 2
    except (ValueError, OSError):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for flag, help_text in (
            ("--publisher-reference", "retained four-role TUF reference file"),
            ("--trusted-root-sha256", "independently provisioned SHA-256 of the publisher's raw root metadata"),
            ("--verification-time", "UTC instant in YYYYMMDDTHHMMSSZ form"),
            ("--policy-target", "name in the signed top-level targets role"),
            ("--policy", "publisher's exact native image approval policy file"),
            ("--manifest", "exact native image change manifest"),
            ("--reference", "complete retained PE reference bytes"),
            ("--out", "new filename for the selected native policy")):
        parser.add_argument(flag, required=True, help=help_text)
    args = parser.parse_args(argv)
    receipt = dict(schema="kn.image_approval_provision.v1", status="rejected", native_policy_sha256=None)
    try:
        import publisher_truth
        provision(args, receipt, publisher_truth)
    except Denied as exc:
        receipt["reason"] = str(exc)
        return write_result(encoded(receipt)) or 1
    except OutputCollision:
        return 2
    except FileExistsError:
        print("output already exists", file=sys.stderr)
        return 2
    except OSError:
        print("could not read inputs or publish the selected policy", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return write_result(encoded(receipt))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
