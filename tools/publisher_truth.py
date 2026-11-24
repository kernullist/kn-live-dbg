"""Adjudicate a retained whole file against an externally pinned TUF publisher."""
import base64
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import re

from retained_corpus import MAX_DOCUMENT, MAX_PACKAGE, visit_original

try:
    import cryptography.hazmat.primitives.asymmetric.ed25519  # Optional backend for securesystemslib.
    from securesystemslib.exceptions import Error as SigningLibraryError
    from securesystemslib.formats import encode_canonical
    from tuf.api.exceptions import LengthOrHashMismatchError, RepositoryError
    from tuf.api.metadata import Metadata
except ImportError:
    raise ValueError("publisher verification requires tools/requirements-publisher-truth.txt") from None


TASK = "publisher-target-bytes-match"
ROLES = ("root", "timestamp", "snapshot", "targets")
MAX_ROLE = 1 << 20
MAX_SCOPE = 1 << 20
TRUTHS = ("positive", "negative", "unknown")


class Rejected(ValueError):
    """A retained declaration could not supply the claimed evidence."""


def need(condition, reason):
    if not condition:
        raise Rejected(reason)


def read_small(stream, objects, pin, limit):
    extent = objects.get(pin)
    if extent is None:
        return None, "missing"
    if extent[1] > limit:
        return None, "over_limit"
    data = bytearray()
    # A changed member is an archive failure, not an unknown benchmark truth.
    visit_original(stream, pin, extent, data.extend)
    return bytes(data), None


def file_scope(raw, decode):
    try:
        scope = decode(raw)
        need(type(scope) is dict and scope.keys() == {"schema", "target_path", "file_bytes", "missing"} and
             scope["schema"] == "kn.benchmark_target_scope.v1", "invalid_file_scope")
        name, length, missing = scope["target_path"], scope["file_bytes"], scope["missing"]
        need(type(name) is str and 0 < len(name.encode("utf-8")) <= 512 and
             not any(ord(ch) < 32 or ord(ch) == 127 or ch in "\\:" for ch in name) and
             all(part not in ("", ".", "..") for part in name.split("/")), "invalid_target_name")
        need(type(length) is int and 0 <= length <= MAX_PACKAGE and type(missing) is list, "invalid_file_scope")
        end = 0
        for span in missing:
            need(type(span) is list and len(span) == 2 and all(type(x) is int for x in span) and
                 end <= span[0] < span[1] <= length, "invalid_file_scope")
            end = span[1]
        return (name, length, bool(missing)), None
    except Rejected as exc:
        return None, str(exc)
    except (ValueError, RecursionError):
        return None, "invalid_file_scope"


def strong_hashes(hashes):
    widths = {"sha256": 64, "sha512": 128}
    return (type(hashes) is dict and bool(hashes) and hashes.keys() <= widths.keys() and
            all(type(value) is str and len(value) == widths[key] and re.fullmatch("[0-9a-f]+", value)
                for key, value in hashes.items()))


def check_reference(raw, decode, trusted_root, instant):
    versions, links = {}, {}
    role = "reference"
    try:
        bundle = decode(raw)
        need(type(bundle) is dict and bundle.keys() == {"schema", *ROLES} and
             bundle["schema"] == "kn.benchmark_tuf_reference.v1", "invalid_reference")
        root = parent_link = None
        for role in ROLES:
            field = bundle[role]
            need(type(field) is str and len(field) <= 4 * ((MAX_ROLE + 2) // 3), "invalid_role_bytes")
            data = base64.b64decode(field, validate=True)
            need(0 < len(data) <= MAX_ROLE, "invalid_role_bytes")
            if role == "root":
                need(hashlib.sha256(data).hexdigest() == trusted_root, "untrusted_root")
            document = decode(data)
            signed = document["signed"]
            version = signed["version"]
            need(signed["_type"] == role and type(version) is int and version > 0 and
                 re.fullmatch(r"1\.[0-9]+(?:\.[0-9]+)?", signed["spec_version"]), "invalid_role_metadata")
            if role == "root":
                for name in ROLES:
                    policy = signed["roles"][name]
                    keyids = policy["keyids"]
                    need(type(keyids) is list and all(type(k) is str for k in keyids) and len(keyids) == len(set(keyids)) and
                         type(policy["threshold"]) is int and 1 <= policy["threshold"] <= len(keyids),
                         "invalid_role_threshold")
            if role in ("timestamp", "snapshot"):
                child = "snapshot.json" if role == "timestamp" else "targets.json"
                link = signed["meta"][child]
                # The TUF decoder folds JSON null and an omitted field into the same optional value.
                need(type(link["version"]) is int and link["version"] > 0, "metadata_version_mismatch")
                need("length" not in link or type(link["length"]) is int and link["length"] >= 0, "invalid_metadata_length")
                need("hashes" not in link or strong_hashes(link["hashes"]), "invalid_metadata_hashes")
            # Verify exactly what the publisher signed, before the typed decoder consumes the mapping.
            payload = encode_canonical(signed).encode("utf-8")
            metadata = Metadata.from_dict(document)
            if role == "root":
                root = metadata.signed
            result = root.get_verification_result(role, payload, metadata.signatures)
            need(bool(result), "signature_threshold_failed")
            need(not metadata.signed.is_expired(instant), "expired_metadata")
            if parent_link is not None:
                need(parent_link.version == version, "metadata_version_mismatch")
                parent_link.verify_length_and_hashes(data)
                links[role] = dict(version=version, length=parent_link.length, hashes=parent_link.hashes)
            versions[role] = dict(version=version, threshold=result.threshold, valid_key_ids=len(result.signed),
                                  expires=metadata.signed.expires.strftime("%Y-%m-%dT%H:%M:%SZ"))
            if role == "timestamp":
                parent_link = metadata.signed.snapshot_meta
            elif role == "snapshot":
                parent_link = metadata.signed.meta["targets.json"]
        return metadata.signed.targets, dict(status="verified", roles=versions, metadata_links=links)
    except Rejected as exc:
        reason = str(exc)
    except LengthOrHashMismatchError:
        reason = "metadata_length_or_hash_mismatch"
    except (KeyError, IndexError, TypeError, ValueError, AttributeError, OverflowError, RecursionError, RepositoryError, SigningLibraryError):
        reason = "invalid_role_metadata"
    return {}, dict(status=reason, failed_role=role, roles=versions)


def compare_target(scope, pin, original, targets, stream, sha512_cache):
    name, file_bytes, has_holes = scope
    details = dict(target_path=name, file_bytes=file_bytes)
    if original is None:
        return "unknown", "artifact_missing", details
    if has_holes or original[1] != file_bytes:
        return "unknown", "incomplete_file", details
    target = targets.get(name)
    if target is None:
        return "unknown", "target_not_in_top_level", details
    hashes = target.hashes
    if type(target.length) is not int or target.length < 0 or not strong_hashes(hashes):
        return "unknown", "unsupported_target_descriptor", details
    details.update(signed_length=target.length, signed_hashes=hashes)
    observed = {"sha256": pin}
    if "sha512" in hashes:
        if pin not in sha512_cache:
            digest = hashlib.sha512()
            visit_original(stream, pin, original, digest.update)
            sha512_cache[pin] = digest.hexdigest()
        observed["sha512"] = sha512_cache[pin]
    if file_bytes == target.length and all(observed[key] == value for key, value in hashes.items()):
        return "positive", "matches_signed_target", details
    return "negative", "differs_from_signed_target", details


def adjudicate(report, stream, objects, cases, trusted_root, at, decode, ratio):
    try:
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", at):
            raise ValueError
        instant = datetime.strptime(at, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("verification time must be a valid UTC YYYYMMDDTHHMMSSZ") from None
    groups = defaultdict(list)
    coverage = {r["case_id"]: r for r in report["coverage"]["cases"]}
    derived = {}
    for key, case in cases.items():
        derived[key] = dict(case, truth="unknown")
        coverage[key].update(declared_truth=case["truth"], publisher_truth="unknown", truth_reason="outside_publisher_task")
        if case["task"] == TASK and case["unit"] == "case":
            groups[case["truth_ref_sha256"]].append(key)
    if not groups:
        raise ValueError("no registered publisher file cases in this corpus")
    references, scope_cache, sha512_cache = [], {}, {}
    adjudicated = contradictions = confirmed = failed = 0
    for ref, group in groups.items():
        data, gap = read_small(stream, objects, ref, MAX_DOCUMENT)
        if gap:
            targets, proof = {}, dict(status="reference_" + gap)
        else:
            targets, proof = check_reference(data, decode, trusted_root, instant)
        references.append(dict(truth_ref_sha256=ref, **proof))
        status = proof["status"]
        failed += status not in ("verified", "reference_missing")
        for key in group:
            case = cases[key]
            truth, reason, details = "unknown", status, {}
            if status == "verified":
                holes = case["holes_sha256"]
                if holes not in scope_cache:
                    data, gap = read_small(stream, objects, holes, MAX_SCOPE)
                    scope_cache[holes] = (None, "scope_" + gap) if gap else file_scope(data, decode)
                scope, reason = scope_cache[holes]
                if scope is not None:
                    pin = case["artifact_sha256"]
                    truth, reason, details = compare_target(scope, pin, objects.get(pin), targets, stream, sha512_cache)
            derived[key]["truth"] = truth
            coverage[key].update(publisher_truth=truth, truth_reason=reason, truth_ref_sha256=ref,
                                 artifact_sha256=case["artifact_sha256"], **details)
            adjudicated += truth != "unknown"
            confirmed += truth != "unknown" and truth == case["truth"]
            contradictions += truth != "unknown" and case["truth"] not in ("unknown", truth)

    declared = Counter(c["truth"] for c in cases.values())
    report.update(schema="kn.benchmark_publisher_report.v1", truth_basis="whole_file_against_signed_top_level_target",
                  file_scope_basis="registered_acquisition_extent_and_hole_map",
                  trusted_root_sha256=trusted_root, verification_time_utc=instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  ground_truth_authenticated=adjudicated == len(cases), independent_detection_validation=False,
                  publisher_references=references, publisher_task_cases=sum(map(len, groups.values())),
                  registered_truth={t: declared[t] for t in TRUTHS}, confirmed_labels=confirmed,
                  contradicted_labels=contradictions, adjudicated_per_planned_case=ratio(adjudicated, len(cases)))
    return derived, int(bool(failed))
