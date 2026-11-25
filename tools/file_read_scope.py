"""Verify an acquisition controller's signed record of reads from one local file."""
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from retained_corpus import CHUNK, MAX_PACKAGE


SCHEMA = "kn.benchmark_windows_reads.v1"
DOMAIN = b"kn.benchmark_windows_reads.v1\0"
MAX_READS = 2048
MAX_TIME = (1 << 63) - 1


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def hex_value(value, width):
    return type(value) is str and len(value) == width and re.fullmatch("[0-9a-f]+", value) is not None


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def target_name_valid(name):
    return (type(name) is str and 0 < len(name) <= 512 and not any(0xd800 <= ord(ch) <= 0xdfff for ch in name) and
            len(name.encode("utf-8")) <= 512 and
            not any(ord(ch) < 32 or ord(ch) == 127 or ch in "\\:" for ch in name) and
            all(part not in ("", ".", "..") for part in name.split("/")))


def context_valid(case_id, target, nonce):
    return (type(case_id) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", case_id) is not None and
            target_name_valid(target) and hex_value(nonce, 64))


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


def inspect_reads(body):
    fields = {"case_id", "target_path", "capture_nonce", "source", "started_unix_ns", "attempts", "packed_sha256"}
    require(type(body) is dict and body.keys() == fields and
            context_valid(body["case_id"], body["target_path"], body["capture_nonce"]) and
            integer(body["started_unix_ns"], 1, MAX_TIME) and hex_value(body["packed_sha256"], 64), "invalid_read_receipt")
    source = body["source"]
    require(type(source) is dict and source.keys() == {"volume_serial", "file_id", "file_bytes", "opened_path_sha256"} and
            hex_value(source["volume_serial"], 16) and hex_value(source["file_id"], 32) and hex_value(source["opened_path_sha256"], 64) and
            integer(source["file_bytes"], 0, MAX_PACKAGE), "invalid_source_identity")
    length, attempts = source["file_bytes"], body["attempts"]
    require(type(attempts) is list and 1 <= len(attempts) <= MAX_READS, "invalid_read_attempts")
    requested_end = observed_end = last_time = packed = issued = errors = short = 0
    missing = []
    for row in attempts:
        require(type(row) is dict and row.keys() == {"offset", "requested", "transferred", "operation", "win32_status",
                                                     "start_ns", "end_ns"}, "invalid_read_attempt")
        offset, size, count = row["offset"], row["requested"], row["transferred"]
        status, operation = row["win32_status"], row["operation"]
        require(integer(offset, requested_end, MAX_PACKAGE) and integer(size, 1, min(CHUNK, MAX_PACKAGE - offset)) and
                integer(count, 0, min(size, max(0, length - offset))) and integer(status, 0, 0xffffffff) and
                operation in ("seek", "read") and (operation == "read" or status != 0) and
                (status == 0 or count == 0) and integer(row["start_ns"], last_time, MAX_TIME) and
                integer(row["end_ns"], row["start_ns"], MAX_TIME), "invalid_read_attempt")
        requested_end, last_time = offset + size, row["end_ns"]
        issued += int(operation == "read")
        errors += int(status != 0)
        short += int(status == 0 and count < size)
        if count:
            if observed_end < offset:
                missing.append([observed_end, offset])
            observed_end = offset + count
            packed += count
    if observed_end < length:
        missing.append([observed_end, length])
    witness = dict(case_id=body["case_id"], packed_sha256=body["packed_sha256"], packed_bytes=packed,
                   source=source, requested_ranges=len(attempts), read_calls=issued, failed_operations=errors, short_reads=short)
    return (body["target_path"], length, missing), witness


def verify(envelope, key_pin, nonce):
    require(key_pin is not None and nonce is not None, "collector_policy_required")
    require(envelope.keys() == {"schema", "body", "public_key", "signature"} and envelope["schema"] == SCHEMA and
            hex_value(envelope["public_key"], 64) and hex_value(envelope["signature"], 128), "invalid_read_receipt")
    public = bytes.fromhex(envelope["public_key"])
    require(hashlib.sha256(public).hexdigest() == key_pin, "untrusted_collector_key")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(envelope["signature"]), DOMAIN + canonical(envelope["body"]))
    except InvalidSignature:
        raise ValueError("invalid_collector_signature") from None
    scope, witness = inspect_reads(envelope["body"])
    require(envelope["body"]["capture_nonce"] == nonce, "capture_nonce_mismatch")
    return scope, witness


def binding_error(witness, case, original):
    if witness["case_id"] != case["id"]:
        return "receipt_case_mismatch"
    if case.get("artifact_layout") != "packed" or witness["packed_sha256"] != case["artifact_sha256"]:
        return "receipt_artifact_mismatch"
    if original is None or original[1] != witness["packed_bytes"]:
        return "receipt_capture_unavailable"
    return None
