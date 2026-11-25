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
MAX_ROOT_UPDATES = 32
MAX_DELEGATED_ROLES = 32
MAX_DELEGATION_SELECTORS = 256
DELEGATED_REFERENCE = "kn.benchmark_tuf_reference.v3"
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


def target_name(name):
    need(type(name) is str and 0 < len(name.encode("utf-8")) <= 512 and
         not any(ord(ch) < 32 or ord(ch) == 127 or ch in "\\:" for ch in name) and
         all(part not in ("", ".", "..") for part in name.split("/")), "invalid_target_name")
    return name


def file_scope(raw, decode):
    try:
        scope = decode(raw)
        need(type(scope) is dict and scope.keys() == {"schema", "target_path", "file_bytes", "missing"} and
             scope["schema"] == "kn.benchmark_target_scope.v1", "invalid_file_scope")
        name, length, missing = scope["target_path"], scope["file_bytes"], scope["missing"]
        target_name(name)
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


def root_version_floor(value):
    if value is None:
        return None
    if not re.fullmatch(r"[1-9][0-9]{0,18}", value) or int(value) > (1 << 63) - 1:
        raise ValueError("minimum root version must be a positive 63-bit decimal integer")
    return int(value)


def reference_updates(bundle):
    need(type(bundle) is dict, "invalid_reference")
    keys = {"schema", *ROLES}
    if bundle.get("schema") == "kn.benchmark_tuf_reference.v1":
        need(bundle.keys() == keys, "invalid_reference")
        return []
    delegated = bundle.get("schema") == DELEGATED_REFERENCE
    if delegated:
        need(bundle.keys() == keys | {"root_updates", "delegated_roles"}, "invalid_reference")
        roles = bundle["delegated_roles"]
        need(type(roles) is dict and len(roles) <= MAX_DELEGATED_ROLES, "invalid_delegated_roles")
        for name, field in roles.items():
            delegated_name(name)
            need(type(field) is str and 0 < len(field) <= 4 * ((MAX_ROLE + 2) // 3), "invalid_role_bytes")
    else:
        need(bundle.get("schema") == "kn.benchmark_tuf_reference.v2" and bundle.keys() == keys | {"root_updates"},
             "invalid_reference")
    updates = bundle["root_updates"]
    need(type(updates) is list and (0 if delegated else 1) <= len(updates) <= MAX_ROOT_UPDATES, "invalid_root_updates")
    return updates


def role_bytes(field):
    need(type(field) is str and len(field) <= 4 * ((MAX_ROLE + 2) // 3), "invalid_role_bytes")
    data = base64.b64decode(field, validate=True)
    need(0 < len(data) <= MAX_ROLE, "invalid_role_bytes")
    return data


def delegated_name(name):
    need(type(name) is str and name not in ROLES and 0 < len(name.encode("utf-8")) <= 128, "invalid_delegated_name")
    target_name(name)


def validate_delegations(delegations):
    need(type(delegations) is dict and type(delegations.get("keys")) is dict and
         (("roles" in delegations) != ("succinct_roles" in delegations)), "invalid_delegation_policy")
    explicit = "roles" in delegations
    policies = delegations["roles"] if explicit else [delegations["succinct_roles"]]
    need(type(policies) is list and len(policies) <= MAX_DELEGATED_ROLES, "invalid_delegation_policy")
    selectors = 0
    for policy in policies:
        keys, quorum = policy["keyids"], policy["threshold"]
        need(type(keys) is list and all(type(k) is str and k in delegations["keys"] for k in keys)
             and len(keys) == len(set(keys)) and type(quorum) is int and 1 <= quorum <= len(keys),
             "invalid_role_threshold")
        if explicit:
            delegated_name(policy["name"])
            need(type(policy["terminating"]) is bool and (("paths" in policy) != ("path_hash_prefixes" in policy)),
                 "invalid_delegation_policy")
            by_path = "paths" in policy
            rules = policy["paths"] if by_path else policy["path_hash_prefixes"]
            need(type(rules) is list, "invalid_delegation_policy")
            selectors += len(rules)
            need(selectors <= MAX_DELEGATION_SELECTORS, "delegation_selector_limit")
            for rule in rules:
                if by_path:
                    target_name(rule)
                else:
                    need(type(rule) is str and re.fullmatch(r"[0-9a-f]{1,64}", rule), "invalid_delegation_policy")
        else:
            bits = policy["bit_length"]
            need(type(bits) is int and 1 <= bits <= 32 and type(policy["name_prefix"]) is str
                 and policy["name_prefix"], "invalid_delegation_policy")
            delegated_name(policy["name_prefix"] + "-" + "f" * ((bits + 3) // 4))


def validate_link(link):
    need(type(link["version"]) is int and link["version"] > 0, "metadata_version_mismatch")
    need("length" not in link or type(link["length"]) is int and link["length"] >= 0, "invalid_metadata_length")
    need("hashes" not in link or strong_hashes(link["hashes"]), "invalid_metadata_hashes")


def parse_role(data, role, decode, *, delegated=False, invalid_links=None):
    document = decode(data)
    signed = document["signed"]
    need(signed["_type"] == role and type(signed["version"]) is int and signed["version"] > 0 and
         re.fullmatch(r"1\.[0-9]+(?:\.[0-9]+)?", signed["spec_version"]), "invalid_role_metadata")
    if role == "root":
        for name in ROLES:
            policy = signed["roles"][name]
            keyids = policy["keyids"]
            need(type(keyids) is list and all(type(k) is str for k in keyids) and len(keyids) == len(set(keyids)) and
                 type(policy["threshold"]) is int and 1 <= policy["threshold"] <= len(keyids), "invalid_role_threshold")
    if role in ("timestamp", "snapshot"):
        child = "snapshot.json" if role == "timestamp" else "targets.json"
        # The TUF decoder folds JSON null and an omitted field into the same optional value.
        validate_link(signed["meta"][child])
        if role == "snapshot" and invalid_links is not None:
            for name, link in signed["meta"].items():
                try:
                    validate_link(link)
                except Rejected as exc:
                    invalid_links[name] = str(exc)
    if delegated and role == "targets" and "delegations" in signed:
        validate_delegations(signed["delegations"])
    # Preserve exactly what was signed before the typed decoder consumes the mapping.
    payload = encode_canonical(signed).encode("utf-8")
    return Metadata.from_dict(document), payload


def verified_root(anchor, updates, decode, pin, proof):
    data = role_bytes(anchor)
    need(hashlib.sha256(data).hexdigest() == pin, "untrusted_root")
    metadata, payload = parse_role(data, "root", decode)
    root = metadata.signed
    result = root.get_verification_result("root", payload, metadata.signatures)
    need(bool(result), "signature_threshold_failed")
    if not updates:
        return root, result
    history = dict(anchor_version=root.version, presented_updates=len(updates), verified_updates=0,
                   last_root_version=root.version, last_root_sha256=pin)
    proof["root_rotation"] = history
    for index, field in enumerate(updates, 1):
        data = role_bytes(field)
        metadata, payload = parse_role(data, "root", decode)
        candidate = metadata.signed
        need(candidate.version == root.version + 1, "root_version_not_sequential")
        quorum = candidate.get_root_verification_result(root, payload, metadata.signatures)
        need(bool(quorum.first), "previous_root_threshold_failed")
        need(bool(quorum.second), "new_root_threshold_failed")
        root, result = candidate, quorum.second
        history.update(verified_updates=index, last_root_version=root.version, last_root_sha256=hashlib.sha256(data).hexdigest())
    return root, result


def role_receipt(signed, result):
    return dict(version=signed.version, threshold=result.threshold, valid_key_ids=len(result.signed),
                expires=signed.expires.strftime("%Y-%m-%dT%H:%M:%SZ"))


class DelegatedTargets:
    """Resolve a target using only the role bytes held in one verified release."""

    def __init__(self, top, snapshot, invalid_links, originals, decode, instant, checks):
        self.top = top
        self.snapshot = snapshot
        self.invalid_links = invalid_links
        self.originals = originals
        self.decode = decode
        self.instant = instant
        self.checks = checks
        self.loaded = {}
        self.edges = {}

    def load(self, name, receipt):
        # Parsing and snapshot checks are shared. Signing authority depends on the parent.
        if name not in self.loaded:
            need(name in self.originals, "delegated_metadata_missing")
            data = role_bytes(self.originals[name])
            details = dict(metadata_sha256=hashlib.sha256(data).hexdigest())
            receipt.update(details)
            filename = name + ".json"
            if filename in self.invalid_links:
                raise Rejected(self.invalid_links[filename])
            link = self.snapshot.meta.get(filename)
            need(link is not None, "delegated_snapshot_entry_missing")
            details["snapshot_link"] = dict(version=link.version, length=link.length, hashes=link.hashes)
            receipt.update(details)
            link.verify_length_and_hashes(data)
            metadata, payload = parse_role(data, "targets", self.decode, delegated=True)
            need(metadata.signed.version == link.version, "metadata_version_mismatch")
            self.loaded[name] = metadata, payload, details
        metadata, payload, details = self.loaded[name]
        receipt.update(details)
        return metadata, payload

    def verify_edge(self, parent_name, parent, name, terminating):
        edge = parent_name, name
        if edge in self.edges:
            return self.edges[edge]
        receipt = dict(parent_role=parent_name, delegated_role=name, terminating=terminating)
        child = None
        try:
            metadata, payload = self.load(name, receipt)
            result = parent.get_verification_result(name, payload, metadata.signatures)
            receipt.update(role_receipt(metadata.signed, result))
            need(bool(result), "signature_threshold_failed")
            need(not metadata.signed.is_expired(self.instant), "expired_metadata")
            receipt["status"] = "verified"
            child = metadata.signed
        except Rejected as exc:
            receipt["status"] = str(exc)
        except LengthOrHashMismatchError:
            receipt["status"] = "metadata_length_or_hash_mismatch"
        except (KeyError, IndexError, TypeError, ValueError, AttributeError, OverflowError,
                RecursionError, RepositoryError, SigningLibraryError):
            receipt["status"] = "invalid_role_metadata"
        index = len(self.checks)
        self.checks.append(receipt)
        self.edges[edge] = child, index
        return child, index

    def resolve(self, path):
        search = dict(role_check_indices=[], target_role=None, status="target_not_in_authorized_roles")
        stack = [("targets", None, False)]
        visited = {}
        while stack:
            name, parent, terminating = stack.pop()
            if name in visited:
                continue
            current = self.top
            if parent is not None:
                if len(visited) > MAX_DELEGATED_ROLES:
                    search.update(status="delegation_search_limit", failed_role=name)
                    return None, search
                current, index = self.verify_edge(parent, visited[parent], name, terminating)
                search["role_check_indices"].append(index)
                if current is None:
                    search.update(status=self.checks[index]["status"], failed_role=name)
                    return None, search
            visited[name] = current
            if path in current.targets:
                search.update(target_role=name, status="found")
                return current.targets[path], search
            if current.delegations is not None:
                children = []
                for child, terminal in current.delegations.get_roles_for_target(path):
                    children.append((child, name, terminal))
                    if terminal:
                        stack.clear()  # This subtree also takes precedence over pending ancestors' siblings.
                        break
                stack.extend(reversed(children))
        return None, search


def check_reference(raw, decode, trusted_root, instant, minimum_version=None):
    versions, links = {}, {}
    proof = {} if minimum_version is None else dict(minimum_root_version=minimum_version)
    role = "reference"
    try:
        need(0 < len(raw) <= MAX_DOCUMENT, "invalid_reference")
        bundle = decode(raw)
        delegated = type(bundle) is dict and bundle.get("schema") == DELEGATED_REFERENCE
        if delegated:
            proof["delegated_role_checks"] = []
        updates = reference_updates(bundle)
        invalid_links = {} if delegated else None
        role = "root"
        root, result = verified_root(bundle[role], updates, decode, trusted_root, proof)
        # Historical roots authorize the next transition. Only the terminal root authorizes these roles.
        need(not root.is_expired(instant), "expired_metadata")
        versions[role] = role_receipt(root, result)
        need(minimum_version is None or root.version >= minimum_version, "root_version_below_minimum")
        parent_link = None
        for role in ROLES[1:]:
            data = role_bytes(bundle[role])
            metadata, payload = parse_role(data, role, decode, delegated=delegated, invalid_links=invalid_links)
            version = metadata.signed.version
            result = root.get_verification_result(role, payload, metadata.signatures)
            need(bool(result), "signature_threshold_failed")
            need(not metadata.signed.is_expired(instant), "expired_metadata")
            if parent_link is not None:
                need(parent_link.version == version, "metadata_version_mismatch")
                parent_link.verify_length_and_hashes(data)
                links[role] = dict(version=version, length=parent_link.length, hashes=parent_link.hashes)
            versions[role] = role_receipt(metadata.signed, result)
            if role == "timestamp":
                parent_link = metadata.signed.snapshot_meta
            elif role == "snapshot":
                snapshot = metadata.signed
                parent_link = snapshot.meta["targets.json"]
        targets = metadata.signed.targets
        if delegated:
            targets = DelegatedTargets(metadata.signed, snapshot, invalid_links, bundle["delegated_roles"], decode, instant,
                                       proof["delegated_role_checks"])
        return targets, dict(status="verified", roles=versions, metadata_links=links, **proof)
    except Rejected as exc:
        reason = str(exc)
    except LengthOrHashMismatchError:
        reason = "metadata_length_or_hash_mismatch"
    except (KeyError, IndexError, TypeError, ValueError, AttributeError, OverflowError, RecursionError, RepositoryError, SigningLibraryError):
        reason = "invalid_role_metadata"
    return {}, dict(status=reason, failed_role=role, roles=versions, **proof)


def compare_target(scope, pin, original, targets, stream, sha512_cache):
    name, file_bytes, has_holes = scope
    details = dict(target_path=name, file_bytes=file_bytes)
    if isinstance(targets, DelegatedTargets):
        target, search = targets.resolve(name)
        details["delegation_search"] = search
        absent = search["status"]
    else:
        target = targets.get(name)
        absent = "target_not_in_top_level"
    if original is None:
        return "unknown", "artifact_missing", details
    if has_holes or original[1] != file_bytes:
        return "unknown", "incomplete_file", details
    if target is None:
        return "unknown", absent, details
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


def verification_time(at):
    try:
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", at):
            raise ValueError
        return datetime.strptime(at, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("verification time must be a valid UTC YYYYMMDDTHHMMSSZ") from None


def adjudicate(report, stream, objects, cases, trusted_root, at, decode, ratio, minimum_version=None):
    instant = verification_time(at)
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
            targets, proof = check_reference(data, decode, trusted_root, instant, minimum_version)
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
                    search = details.get("delegation_search")
                    if search and search["status"] not in ("found", "target_not_in_authorized_roles"):
                        failed += 1
            derived[key]["truth"] = truth
            coverage[key].update(publisher_truth=truth, truth_reason=reason, truth_ref_sha256=ref,
                                 artifact_sha256=case["artifact_sha256"], **details)
            adjudicated += truth != "unknown"
            confirmed += truth != "unknown" and truth == case["truth"]
            contradictions += truth != "unknown" and case["truth"] not in ("unknown", truth)
        references.append(dict(truth_ref_sha256=ref, **proof))

    declared = Counter(c["truth"] for c in cases.values())
    if minimum_version is not None:
        report["minimum_root_version"] = minimum_version
    report.update(schema="kn.benchmark_publisher_report.v1", truth_basis="whole_file_against_signed_top_level_target",
                  file_scope_basis="registered_acquisition_extent_and_hole_map",
                  trusted_root_sha256=trusted_root, verification_time_utc=instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  ground_truth_authenticated=adjudicated == len(cases), independent_detection_validation=False,
                  publisher_references=references, publisher_task_cases=sum(map(len, groups.values())),
                  registered_truth={t: declared[t] for t in TRUTHS}, confirmed_labels=confirmed,
                  contradicted_labels=contradictions, adjudicated_per_planned_case=ratio(adjudicated, len(cases)))
    if any("delegated_role_checks" in ref for ref in references):
        report.update(schema="kn.benchmark_publisher_report.v2", truth_basis="whole_file_against_signed_tuf_target")
    return derived, int(bool(failed))
