"""Compare the observed file offsets in a retained capture against an authenticated publisher file."""
import hashlib

from retained_corpus import CHUNK, MAX_PACKAGE


def observed_spans(length, missing):
    offset = 0
    for start, end in missing:
        if offset < start:
            yield offset, start
        offset = end
    if offset < length:
        yield offset, length


def read_at(stream, offset, size):
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated original during publisher range comparison")
    return data


def compare_originals(stream, candidate, reference, case, length, missing, signed_hashes):
    # Each digest covers exactly the bytes read here, including unobserved filler in a dense capture.
    capture_hash, publisher_hash = hashlib.sha256(), hashlib.sha256()
    publisher_sha512 = hashlib.sha512() if "sha512" in signed_hashes else None
    packed = case["artifact_layout"] == "packed"
    capture_offset = candidate[0]
    compared = different = 0
    first = None
    spans = observed_spans(length, missing)
    span = next(spans, None)
    for offset in range(0, length, CHUNK):
        end = min(length, offset + CHUNK)
        baseline = read_at(stream, reference[0] + offset, end - offset)
        publisher_hash.update(baseline)
        if publisher_sha512 is not None:
            publisher_sha512.update(baseline)
        # One sequential read per member per block, even when the hole map has many short spans.
        parts = []
        while span is not None and span[0] < end:
            parts.append((max(offset, span[0]) - offset, min(end, span[1]) - offset))
            if span[1] > end:
                break
            span = next(spans, None)
        size = sum(b - a for a, b in parts) if packed else end - offset
        captured = read_at(stream, capture_offset, size) if size else b""
        capture_offset += size
        capture_hash.update(captured)
        packed_pos = 0
        for a, b in parts:
            count = b - a
            pos = packed_pos if packed else a
            actual, expected = captured[pos:pos + count], baseline[a:b]
            if actual != expected:
                # XOR leaves one nonzero byte at each differing file offset. Count the block in native code.
                xor = int.from_bytes(actual, "little") ^ int.from_bytes(expected, "little")
                delta = xor.to_bytes(count, "little")
                different += count - delta.count(0)
                if first is None:
                    first = offset + a + next(i for i, byte in enumerate(delta) if byte)
            compared += count
            packed_pos += count
    if capture_hash.hexdigest() != case["artifact_sha256"] or publisher_hash.hexdigest() != case["publisher_file_sha256"]:
        raise ValueError("selected original changed during publisher range comparison")
    hashes = {"sha256": publisher_hash.hexdigest()}
    if publisher_sha512 is not None:
        hashes["sha512"] = publisher_sha512.hexdigest()
    matches = all(hashes[algo] == value for algo, value in signed_hashes.items())
    return matches, compared, different, first


class RangeReplay:
    def __init__(self, stream, objects):
        self.stream = stream
        self.objects = objects
        self.cache = {}
        self.limit = 2 * MAX_PACKAGE
        self.read_bytes = 0
        self.reused = 0
        self.deferred = 0

    def accounting(self):
        return dict(byte_limit=self.limit, read_bytes=self.read_bytes, distinct_comparisons=len(self.cache),
                    reused_comparisons=self.reused, deferred_cases=self.deferred)

    def evidence(self, case, scope, scope_error=None):
        candidate = self.objects.get(case["artifact_sha256"])
        holes = sum(end - start for start, end in scope[2]) if scope is not None else None
        return dict(scope_status=scope_error or "registered", stored_capture_bytes=candidate[1] if candidate else None,
                    missing_bytes=holes, declared_observed_bytes=scope[1] - holes if scope is not None else None,
                    publisher_file_verified=None, compared_bytes=0, differing_bytes=None, first_difference_offset=None)

    def compare(self, case, scope, target, details):
        _, file_bytes, missing = scope
        candidate = self.objects[case["artifact_sha256"]]
        reference = self.objects.get(case["publisher_file_sha256"])
        ranges = self.evidence(case, scope)
        holes = ranges["missing_bytes"]
        details["file_range_comparison"] = ranges
        if reference is None:
            return "unknown", "publisher_file_missing", details
        if reference[1] != target.length:
            ranges["publisher_file_verified"] = False
            return "unknown", "publisher_file_not_signed_target", details
        if file_bytes != target.length:
            return "unknown", "scope_length_differs_from_signed_target", details
        stored_size = file_bytes - holes if case["artifact_layout"] == "packed" else file_bytes
        if candidate[1] != stored_size:
            return "unknown", "capture_layout_length_mismatch", details
        key = (case["artifact_sha256"], case["holes_sha256"], case["artifact_layout"],
               case["publisher_file_sha256"], tuple(sorted(target.hashes.items())))
        if key in self.cache:
            outcome = self.cache[key]
            self.reused += 1
        else:
            cost = candidate[1] + reference[1]
            if cost > self.limit - self.read_bytes:
                self.deferred += 1
                return "unknown", "range_comparison_budget_exhausted", details
            self.read_bytes += cost
            outcome = compare_originals(self.stream, candidate, reference, case, file_bytes, missing, target.hashes)
            self.cache[key] = outcome
        verified, compared, differing, first = outcome
        ranges["publisher_file_verified"] = verified
        if not verified:
            return "unknown", "publisher_file_not_signed_target", details
        ranges.update(compared_bytes=compared, differing_bytes=differing, first_difference_offset=first)
        if differing:
            return "negative", "observed_bytes_differ", details
        if holes:
            return "unknown", "no_observed_bytes" if not compared else "observed_match_with_holes", details
        return "positive", "matches_signed_target", details
