"""Offline comparison of a collector receipt with separately signed Windows observations."""
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from file_read_scope import canonical, hex_value, integer, require
from retained_corpus import MAX_PACKAGE


MAGIC = b"KNREADW1"
HEADER = struct.Struct("<8sII")
MAX_CAPTURE = 1 << 20
MAX_OBSERVER = 2 << 20
MAX_COMBINED = HEADER.size + MAX_CAPTURE + MAX_OBSERVER
SCHEMA = "kn.windows_file_read_observation.v1"
DOMAIN = b"kn.windows_file_read_observation.v1\0"
U64 = (1 << 64) - 1


def combine(capture, observation):
    require(0 < len(capture) <= MAX_CAPTURE and 0 < len(observation) <= MAX_OBSERVER, "invalid_read_observation_extent")
    return HEADER.pack(MAGIC, len(capture), len(observation)) + capture + observation


def split(raw):
    require(len(raw) >= HEADER.size, "invalid_read_observation_extent")
    magic, size, extra = HEADER.unpack_from(raw)
    require(magic == MAGIC and 0 < size <= MAX_CAPTURE and 0 < extra <= MAX_OBSERVER and
            len(raw) == HEADER.size + size + extra, "invalid_read_observation_extent")
    end = HEADER.size + size
    return raw[HEADER.size:end], raw[end:]


def actor(value):
    return (type(value) is dict and value.keys() == {"pid", "process_created"} and integer(value["pid"], 1, 0xffffffff) and
            type(value["process_created"]) is str and value["process_created"].isascii() and value["process_created"].isdigit() and
            0 < len(value["process_created"]) <= 20 and 0 < int(value["process_created"]) <= U64)


def sample(value):
    return (type(value) is dict and value.keys() == {"position", "read_operations", "read_bytes"} and
            integer(value["position"], 0, MAX_PACKAGE) and
            all(integer(value[k], 0, U64) for k in ("read_operations", "read_bytes")))


def row_result(actual, seen, length):
    require(type(seen) is dict and seen.keys() == {"offset", "requested", "before", "after", "repeat_ntstatus", "repeat_bytes"} and
            integer(seen["offset"], 0, MAX_PACKAGE) and integer(seen["requested"], 1, 1 << 20) and
            sample(seen["before"]) and sample(seen["after"]) and integer(seen["repeat_ntstatus"], 0, 0xffffffff) and
            integer(seen["repeat_bytes"], 0, min(seen["requested"], max(0, length - seen["offset"]))),
            "invalid_observer_sample")
    if (seen["offset"], seen["requested"]) != (actual["offset"], actual["requested"]):
        return "different_range_plan"
    if actual["operation"] != "read":
        return "read_not_issued"
    before, after = seen["before"], seen["after"]
    if before["position"] != actual["offset"] or after["position"] != actual["offset"] + actual["transferred"]:
        return "cursor_disagreement"
    if after["read_operations"] - before["read_operations"] != 1:
        return "process_read_count_inconclusive"
    if after["read_bytes"] - before["read_bytes"] != actual["transferred"]:
        return "process_read_bytes_disagree"
    native = seen["repeat_ntstatus"]
    if native == 0 or (native == 0xc0000011 and seen["offset"] >= length and not seen["repeat_bytes"]):
        expected = 0  # Synchronous Win32 ReadFile succeeds with zero bytes at EOF.
    elif native in (0xc0000054, 0xc0000055) and not seen["repeat_bytes"]:
        expected = 33  # File lock conflict or lock not granted.
    else:
        return "repeat_status_unmapped"
    if (actual["win32_status"], actual["transferred"]) != (expected, seen["repeat_bytes"]):
        return "repeat_result_disagrees"
    return "corroborated"


def verify(raw, decode, capture, body, collector_pin, observer_pin):
    if observer_pin is None:
        return dict(status="observer_policy_not_supplied")
    envelope = decode(raw)
    require(type(envelope) is dict and envelope.keys() == {"schema", "body", "public_key", "signature"} and
            envelope["schema"] == SCHEMA and hex_value(envelope["public_key"], 64) and
            hex_value(envelope["signature"], 128), "invalid_observer_receipt")
    public = bytes.fromhex(envelope["public_key"])
    require(collector_pin != observer_pin and hashlib.sha256(public).hexdigest() == observer_pin, "untrusted_observer_key")
    record = envelope["body"]
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(envelope["signature"]), DOMAIN + canonical(record))
    except InvalidSignature:
        raise ValueError("invalid_observer_signature") from None
    require(type(record) is dict and record.keys() == {"collector_receipt_sha256", "source", "collector", "observer",
            "observations", "repeat_packed_sha256"} and hex_value(record["repeat_packed_sha256"], 64) and
            actor(record["collector"]) and actor(record["observer"]) and record["collector"]["pid"] != record["observer"]["pid"],
            "invalid_observer_receipt")
    require(record["collector_receipt_sha256"] == hashlib.sha256(capture).hexdigest() and
            canonical(record["source"]) == canonical(body["source"]), "observer_capture_mismatch")
    rows = record["observations"]
    require(type(rows) is list and len(rows) == len(body["attempts"]), "observer_attempt_count_mismatch")
    confirmed = 0
    first = None
    previous = None
    repeat_requested = repeat_returned = process_operations = process_bytes = 0
    for index, (attempt, row) in enumerate(zip(body["attempts"], rows)):
        outcome = row_result(attempt, row, body["source"]["file_bytes"])
        before, after = row["before"], row["after"]
        require(all((previous is None or previous[k] <= before[k]) and before[k] <= after[k]
                    for k in ("read_operations", "read_bytes")), "observer_counters_regressed")
        previous = after
        repeat_requested += row["requested"]
        repeat_returned += row["repeat_bytes"]
        process_operations += after["read_operations"] - before["read_operations"]
        process_bytes += after["read_bytes"] - before["read_bytes"]
        if outcome == "corroborated":
            confirmed += 1
        elif first is None:
            first = dict(attempt=index + 1, reason=outcome)
    same = record["repeat_packed_sha256"] == body["packed_sha256"]
    status = "corroborated" if same else "repeat_content_disagrees"
    if first:
        status = "attempts_inconclusive"
    return dict(status=status, sampled_ranges=len(rows), matching_attempt_results=confirmed, first_unconfirmed=first,
                repeat_requested_bytes=repeat_requested, repeat_returned_bytes=repeat_returned,
                sampled_process_read_operations=process_operations, sampled_process_read_bytes=process_bytes,
                repeated_content_matches=same, collector=record["collector"], observer=record["observer"])
