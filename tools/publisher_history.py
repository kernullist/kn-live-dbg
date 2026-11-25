"""Frame two exact, bounded TUF references for offline update and replay."""
from datetime import datetime, timezone
import hashlib
import re
import struct
from typing import NamedTuple

from retained_corpus import MAX_DOCUMENT


MAGIC = b"KNPUBHS1"
HEADER = struct.Struct("<8s16sI16sI")
MAX_REFERENCE = HEADER.size + 2 * MAX_DOCUMENT


def verification_time(at):
    try:
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", at):
            raise ValueError
        return datetime.strptime(at, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("verification time must be a valid UTC YYYYMMDDTHHMMSSZ") from None


class Observation(NamedTuple):
    at: str
    reference: bytes

    def checkpoint(self, root_pin):
        # All fields after the domain separator have fixed sizes.
        return hashlib.sha256(b"kn.publisher.observation.v1\x00" + bytes.fromhex(root_pin) +
                              self.at.encode("ascii") + hashlib.sha256(self.reference).digest()).hexdigest()


def pack(previous, current):
    for observation in (current, previous):
        if observation is not None:
            verification_time(observation.at)
            if not 0 < len(observation.reference) <= MAX_DOCUMENT or observation.reference.startswith(MAGIC):
                raise ValueError("invalid_history_member")
    prior = previous.reference if previous else b""
    header = HEADER.pack(MAGIC, previous.at.encode("ascii") if previous else bytes(16), len(prior),
                         current.at.encode("ascii"), len(current.reference))
    return header + prior + current.reference


def unpack(raw):
    if not HEADER.size < len(raw) <= MAX_REFERENCE:
        raise ValueError("invalid_publisher_history")
    magic, old_at, old_size, new_at, new_size = HEADER.unpack_from(raw)
    if (magic != MAGIC or old_size > MAX_DOCUMENT or not 0 < new_size <= MAX_DOCUMENT or
            HEADER.size + old_size + new_size != len(raw) or (not old_size and old_at != bytes(16))):
        raise ValueError("invalid_publisher_history")
    split = HEADER.size + old_size
    try:
        previous = Observation(old_at.decode("ascii"), raw[HEADER.size:split]) if old_size else None
        current = Observation(new_at.decode("ascii"), raw[split:])
        for observation in (current, previous):
            if observation is not None:
                verification_time(observation.at)
                if observation.reference.startswith(MAGIC):
                    raise ValueError
    except ValueError:
        raise ValueError("invalid_history_member") from None
    return previous, current
