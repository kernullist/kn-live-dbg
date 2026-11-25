"""Offline publisher-verification controls. Run with the optional publisher requirements."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

import file_read_scope as reads
import publisher_truth as publisher
import publisher_history as history
import publisher_ranges
import retained_corpus as archive


CLI = Path(__file__).with_name("evaluate-corpus.py")
spec = importlib.util.spec_from_file_location("corpus", CLI)
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
TIME = datetime(2024, 2, 1, tzinfo=timezone.utc)
SOURCE = b"publisher release bytes"


def raw(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bundle(files):
    return raw(dict(schema="kn.benchmark_tuf_reference.v1",
                    **{k: base64.b64encode(v).decode("ascii") for k, v in files.items()}))


def history_bundle(files, anchor, updates):
    envelope = json.loads(bundle(files))
    envelope.update(schema="kn.benchmark_tuf_reference.v2", root=base64.b64encode(anchor).decode("ascii"),
                    root_updates=[base64.b64encode(data).decode("ascii") for data in updates])
    return raw(envelope)


def successor(previous, current, version, **changes):
    body = {**current.base["root"], "version": version, **changes}
    sigs = {}
    for repo in (previous, current):
        for sig in json.loads(repo.sign("root", body))["signatures"]:
            sigs[sig["keyid"]] = sig
    return raw(dict(signed=body, signatures=list(sigs.values())))


class Repository:
    def __init__(self):
        self.private = {}
        keys = {}
        for _ in range(4):
            key = Ed25519PrivateKey.generate()
            public = dict(keytype="ed25519", scheme="ed25519", keyval=dict(public=key.public_key().public_bytes_raw().hex()))
            key_id = sha(raw(public))
            self.private[key_id] = key
            keys[key_id] = public
        a, b, c, d = keys
        self.quorum = dict(root=[a, b], targets=[a, b], timestamp=[c], snapshot=[d])
        self.base = {role: dict(_type=role, expires="2025-01-01T00:00:00Z", spec_version="1.0.31", version=1)
                     for role in publisher.ROLES}
        self.base["root"].update(keys=keys, consistent_snapshot=True,
                                 roles={k: dict(threshold=len(v), keyids=v) for k, v in self.quorum.items()})
        self.base["targets"]["targets"] = {"file.bin": dict(length=len(SOURCE), hashes=dict(
            sha256=sha(SOURCE), sha512=hashlib.sha512(SOURCE).hexdigest()))}

    def sign(self, role, body, signers=None):
        # The fixture uses ASCII fields without escapes. Its sorted compact encoding is canonical for these fields.
        sigs = [dict(keyid=k, sig=self.private[k].sign(raw(body)).hex())
                for k in self.quorum[role] if signers is None or k in signers]
        return raw(dict(signed=body, signatures=sigs))

    def files(self, overrides=None):
        files = {}
        for role in ("targets", "snapshot", "timestamp", "root"):
            body = copy.deepcopy(self.base[role])
            child = {"snapshot": "targets", "timestamp": "snapshot"}.get(role)
            if child:
                data = files[child]
                body["meta"] = {child + ".json": dict(version=1, length=len(data), hashes=dict(sha256=sha(data)))}
            body.update((overrides or {}).get(role, {}))
            files[role] = self.sign(role, body)
        return files


class RootHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.first, cls.middle, cls.last = Repository(), Repository(), Repository()
        cls.middle.quorum["root"].append(cls.middle.quorum["snapshot"][0])
        cls.middle.base["root"]["roles"]["root"]["threshold"] = 3
        cls.anchor = cls.first.files({"root": {"expires": "2023-01-01T00:00:00Z"}})["root"]
        cls.two = successor(cls.first, cls.middle, 2, expires="2023-11-01T00:00:00Z")
        cls.three = successor(cls.middle, cls.last, 3)
        cls.files = cls.last.files()

    def verify(self, updates, floor=None, files=None, pin=None):
        targets, proof = publisher.check_reference(history_bundle(files or self.files, self.anchor, updates),
                                                   corpus.decode_document, pin or sha(self.anchor), TIME, floor)
        self.assertEqual(bool(targets), proof["status"] == "verified")
        return proof

    def test_trust_moves_across_expired_roots_and_distinct_quorums(self):
        verified = self.verify([self.two, self.three], 3)
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["root_rotation"], dict(anchor_version=1, presented_updates=2, verified_updates=2,
                                                        last_root_version=3, last_root_sha256=sha(self.three)))
        self.assertEqual(verified["roles"]["root"], dict(version=3, threshold=2, valid_key_ids=2,
                                                        expires="2025-01-01T00:00:00Z"))
        self.assertEqual(verified["minimum_root_version"], 3)
        older = self.first.files()
        for role in ("timestamp", "snapshot", "targets"):
            proof = self.verify([self.two, self.three], files={**self.files, role: older[role]})
            self.assertEqual((proof["status"], proof["failed_role"]), ("signature_threshold_failed", role))
        self.assertEqual(self.verify([self.two, self.three], pin=sha(self.three))["status"], "untrusted_root")

    def test_both_root_thresholds_are_independently_mandatory(self):
        for retain, status in ((self.first.quorum["root"], "new_root_threshold_failed"),
                               (self.middle.quorum["root"], "previous_root_threshold_failed"),
                               (self.first.quorum["root"] + self.middle.quorum["root"][:2], "new_root_threshold_failed")):
            docs = json.loads(self.two)
            docs["signatures"] = [s for s in docs["signatures"] if s["keyid"] in retain]
            proof = self.verify([raw(docs), self.three])
            self.assertEqual((proof["status"], proof["failed_role"]), (status, "root"))
            self.assertEqual(proof["root_rotation"]["last_root_sha256"], sha(self.anchor))
        docs = json.loads(self.three)
        docs["signatures"] = [s for s in docs["signatures"] if s["keyid"] in self.last.quorum["root"]]
        proof = self.verify([self.two, raw(docs)])
        self.assertEqual((proof["status"], proof["root_rotation"]["verified_updates"]), ("previous_root_threshold_failed", 1))
        docs["signatures"] += [docs["signatures"][0]]
        self.assertNotEqual(self.verify([self.two, raw(docs)])["status"], "verified")

    def test_exact_versions_terminal_expiry_and_operator_floor(self):
        expired = successor(self.middle, self.last, 3, expires="2024-02-01T00:00:00Z")
        self.assertEqual(self.verify([self.two, expired])["status"], "expired_metadata")
        self.assertEqual(self.verify([self.two, self.three], 4)["status"], "root_version_below_minimum")
        for sequence in ([self.three], [self.two, self.two], [self.two, self.anchor], [self.two, self.three, self.two]):
            self.assertEqual(self.verify(sequence)["status"], "root_version_not_sequential")
        single = self.first.files()
        v1 = publisher.check_reference(bundle(single), corpus.decode_document, sha(single["root"]), TIME, 2)[1]
        self.assertEqual((v1["status"], v1["minimum_root_version"], v1["roles"]["root"]["version"]),
                         ("root_version_below_minimum", 2, 1))
        for value in ("0", "+1", "01", "-1", "1.0", " 1", str(1 << 63)):
            with self.assertRaises(ValueError):
                publisher.root_version_floor(value)
        self.assertEqual(publisher.root_version_floor(str((1 << 63) - 1)), (1 << 63) - 1)

    def test_history_encoding_budgets_and_largest_valid_sequence(self):
        doc = json.loads(history_bundle(self.files, self.anchor, [self.two, self.three]))
        alternatives = [dict(doc, schema="kn.benchmark_tuf_reference.v1"), dict(doc, root_updates=[]),
                        dict(doc, root_updates=None), dict(doc, root_updates=[""] * (publisher.MAX_ROOT_UPDATES + 1)),
                        dict(doc, root_updates=[None]), dict(doc, root_updates=["!"]), dict(doc, root_updates=[doc["targets"]]),
                        dict(doc, root_updates=[base64.b64encode(bytes(publisher.MAX_ROLE + 1)).decode("ascii")])]
        for bad in alternatives:
            targets, proof = publisher.check_reference(raw(bad), corpus.decode_document, sha(self.anchor), TIME)
            self.assertFalse(targets)
            self.assertNotEqual(proof["status"], "verified")
        with mock.patch.object(corpus, "decode_document", side_effect=AssertionError("oversize envelope decoded")) as decode:
            self.assertEqual(publisher.check_reference(bytes(archive.MAX_DOCUMENT + 1), decode, sha(self.anchor), TIME)[1]["status"],
                             "invalid_reference")
        rotations = [successor(self.first, self.first, i + 2) for i in range(publisher.MAX_ROOT_UPDATES)]
        proof = self.verify(rotations, files=self.first.files())
        self.assertEqual((proof["status"], proof["root_rotation"]["verified_updates"]), ("verified", publisher.MAX_ROOT_UPDATES))


def delegation(repo, name, paths, *, terminating=False, signer="timestamp"):
    return dict(name=name, paths=paths, terminating=terminating, keyids=repo.quorum[signer], threshold=1)


def role_body(repo, targets, children=(), **changes):
    body = dict(repo.base["targets"], targets=targets, **changes)
    if children:
        body["delegations"] = dict(keys=repo.base["root"]["keys"], roles=list(children))
    return body


def delegated_release(repo, top, roles, *, retained=None, links=None, expires=None):
    # Sign the independent fixture from leaf to timestamp using exact lengths and digests.
    top_bytes = repo.sign("targets", top)
    descriptors = {name + ".json": dict(version=json.loads(data)["signed"]["version"], length=len(data),
                                         hashes=dict(sha256=sha(data)))
                   for name, data in {"targets": top_bytes, **roles}.items()}
    for name, value in (links or {}).items():
        if value is None:
            del descriptors[name + ".json"]
        else:
            descriptors[name + ".json"] = value
    overrides = {role: {"expires": expires} for role in publisher.ROLES} if expires else {}
    overrides.setdefault("snapshot", {})["meta"] = descriptors
    files = repo.files(overrides)
    files["targets"] = top_bytes
    envelope = json.loads(bundle(files))
    envelope.update(schema=publisher.DELEGATED_REFERENCE, root_updates=[],
                    delegated_roles={name: base64.b64encode(data).decode("ascii")
                                     for name, data in (roles if retained is None else retained).items()})
    return raw(envelope)


class DelegationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repository()
        cls.anchor = sha(cls.repo.files()["root"])
        cls.descriptor = dict(length=len(SOURCE), hashes=dict(sha256=sha(SOURCE)))

    def check(self, envelope):
        resolved, proof = publisher.check_reference(envelope, corpus.decode_document, self.anchor, TIME)
        self.assertEqual(proof["status"], "verified")
        return resolved, proof["delegated_role_checks"]

    def test_ordered_search_and_termination_across_subtrees(self):
        r, path = self.repo, "dist/item"
        def rule(name, terminal=False):
            return delegation(r, name, ["dist/*"], terminating=terminal)
        first = r.sign("timestamp", role_body(r, {}))
        winner = r.sign("timestamp", role_body(r, {path: self.descriptor}))
        other = r.sign("timestamp", role_body(r, {path: dict(length=0, hashes=dict(sha256=sha(b"")))}))
        top = role_body(r, {"dist/top": self.descriptor}, [rule("left"), rule("right")])
        for terminal, expected in ((False, "right"), (True, None)):
            left = r.sign("timestamp", role_body(r, {}, [rule("nested", terminal)]))
            roles = dict(left=left, nested=first, right=other)
            targets, checks = self.check(delegated_release(r, top, roles))
            self.assertEqual(targets.resolve("dist/top")[1]["role_check_indices"], [])
            target, result = targets.resolve(path)
            self.assertEqual(result["target_role"], expected)
            self.assertEqual([checks[i]["delegated_role"] for i in result["role_check_indices"]],
                             ["left", "nested"] if terminal else ["left", "nested", "right"])
            if not terminal:
                self.assertEqual(target.length, 0)
            roles["nested"] = winner
            targets, checks = self.check(delegated_release(r, top, roles))
            self.assertEqual(targets.resolve(path)[1]["target_role"], "nested")
            self.assertEqual(checks[-1]["snapshot_link"]["hashes"]["sha256"], sha(winner))
        # An earlier applicable role must resolve before a later valid descriptor can be considered.
        targets, checks = self.check(delegated_release(r, top, roles, retained={"right": other}))
        self.assertEqual(targets.resolve(path)[1]["status"], "delegated_metadata_missing")
        self.assertEqual(len(checks), 1)

    def test_parent_authority_is_checked_per_edge_and_path(self):
        r = self.repo
        paths = ["a/item", "b/item", "x/item"]
        top = role_body(r, {}, [delegation(r, "one", ["a/*"]), delegation(r, "two", ["b/*"])])
        one = role_body(r, {}, [delegation(r, "shared", ["*/*"])])
        two = role_body(r, {}, [delegation(r, "shared", ["*/*"], signer="snapshot")])
        leaf = role_body(r, {path: self.descriptor for path in paths})
        roles = {name: r.sign("timestamp", body) for name, body in (("one", one), ("two", two), ("shared", leaf))}
        targets, checks = self.check(delegated_release(r, top, roles))
        self.assertEqual(targets.resolve(paths[0])[1]["target_role"], "shared")
        self.assertEqual(targets.resolve(paths[1])[1]["status"], "signature_threshold_failed")
        self.assertEqual(targets.resolve(paths[2])[1]["role_check_indices"], [])
        self.assertEqual(targets.resolve("a/deeper/item")[1]["role_check_indices"], [])
        self.assertEqual(targets.resolve(paths[0])[1]["role_check_indices"], [0, 1])
        self.assertEqual(len(checks), 4)

    def test_hash_prefixes_succinct_roles_and_cycles(self):
        r, path = self.repo, "release/public"
        prefix = hashlib.sha256(path.encode()).hexdigest()[:5]
        rule = delegation(r, "bin", [])
        del rule["paths"]
        rule["path_hash_prefixes"] = [prefix]
        top = role_body(r, {}, [rule])
        nested = "bin-" + format(int(prefix, 16) >> 15, "02x")  # five high bits, padded to two hex digits
        bins = dict(keys=r.base["root"]["keys"], succinct_roles=dict(name_prefix="bin", bit_length=5,
                    keyids=r.quorum["snapshot"], threshold=1))
        middle = role_body(r, {}, delegations=bins)
        leaf = role_body(r, {path: self.descriptor}, [delegation(r, "bin", ["*/*"])])
        roles = {"bin": r.sign("timestamp", middle), nested: r.sign("snapshot", leaf)}
        targets, checks = self.check(delegated_release(r, top, roles))
        target, result = targets.resolve(path)
        self.assertEqual((target.length, result["target_role"]), (len(SOURCE), nested))
        self.assertTrue(checks[-1]["terminating"])
        self.assertIsNone(targets.resolve("release/other")[0])
        leaf["targets"] = {}
        roles[nested] = r.sign("snapshot", leaf)
        targets, checks = self.check(delegated_release(r, top, roles))
        self.assertEqual(targets.resolve(path)[1]["status"], "target_not_in_authorized_roles")
        self.assertEqual(len(checks), 2)

    def test_snapshot_signatures_expiry_and_encoding(self):
        r, path = self.repo, "file.bin"
        rule = delegation(r, "release", ["*"])
        rule.update(keyids=r.quorum["targets"], threshold=2)
        top = role_body(r, {}, [rule])
        body = role_body(r, {path: self.descriptor}, version=7)
        data = r.sign("targets", body)
        for retained, link, expected in (
                (data, None, "delegated_snapshot_entry_missing"),
                (data, dict(version=6), "metadata_version_mismatch"),
                (data, dict(version=7, length=len(data)+1), "metadata_length_or_hash_mismatch"),
                (data, dict(version=7, hashes=dict(sha256="0"*64)), "metadata_length_or_hash_mismatch"),
                (r.sign("targets", body, r.quorum["targets"][:1]), dict(version=7), "signature_threshold_failed"),
                (r.sign("targets", dict(body, expires="2024-02-01T00:00:00Z")), dict(version=7), "expired_metadata"),
                (data, dict(version=7), "found")):
            targets, checks = self.check(delegated_release(r, top, {"release": data}, retained={"release": retained},
                                                           links={"release": link}))
            self.assertEqual(targets.resolve(path)[1]["status"], expected)
            self.assertEqual(checks[0]["metadata_sha256"], sha(retained))
        for invalid, reason in ((dict(version=True), "metadata_version_mismatch"),
                                (dict(version=7, length=None), "invalid_metadata_length"),
                                (dict(version=7, hashes=None), "invalid_metadata_hashes")):
            bad = delegated_release(r, dict(top, targets={"local": self.descriptor}), {"release": data}, links={"release": invalid})
            targets, checks = self.check(bad)
            self.assertEqual(targets.resolve("local")[1]["target_role"], "targets")
            self.assertEqual(targets.resolve(path)[1]["status"], reason)
        for change in ({"threshold": True}, {"terminating": 1}, {"paths": "file.bin"}, {"name": "root"},
                       {"path_hash_prefixes": []}, {"paths": ["../*"]}, {"keyids": [rule["keyids"][0]] * 2}):
            bad = delegated_release(r, role_body(r, {}, [dict(rule, **change)]), {"release": data})
            self.assertNotEqual(publisher.check_reference(bad, corpus.decode_document, self.anchor, TIME)[1]["status"], "verified")

    def test_bounded_history_role_count_and_search(self):
        r, path = self.repo, "one"
        names = ["level-" + str(i) for i in range(publisher.MAX_DELEGATED_ROLES + 1)]
        def branch(name):
            return [delegation(r, name, ["*"])]
        top = role_body(r, {}, branch(names[0]))
        roles = {name: r.sign("timestamp", role_body(r, {}, branch(names[i+1])))
                 for i, name in enumerate(names[:-1])}
        ref = delegated_release(r, top, roles)
        targets, checks = self.check(ref)
        self.assertEqual(targets.resolve(path)[1]["status"], "delegation_search_limit")
        self.assertEqual(len(checks), publisher.MAX_DELEGATED_ROLES)
        roles[names[-2]] = r.sign("timestamp", role_body(r, {path: self.descriptor}))
        targets, checks = self.check(delegated_release(r, top, roles))
        self.assertEqual(targets.resolve(path)[1]["target_role"], names[-2])
        self.assertEqual(len(checks), publisher.MAX_DELEGATED_ROLES)
        doc = json.loads(ref)
        for bad in (dict(doc, delegated_roles={**doc["delegated_roles"], names[-1]: "AA=="}),
                    dict(doc, delegated_roles={"../outside": "AA=="}), dict(doc, delegated_roles={"targets": "AA=="}),
                    dict(doc, root_updates=[doc["root"]] * 33)):
            self.assertNotEqual(publisher.check_reference(raw(bad), corpus.decode_document, self.anchor, TIME)[1]["status"], "verified")


class PublisherRangeTests(unittest.TestCase):
    def replay(self, captured, reference, holes, layout, *, signed=None, length=None):
        pin, baseline = sha(captured), sha(reference)
        name = "file.bin"
        length = len(reference) if length is None else length
        scope = raw(dict(schema="kn.benchmark_target_scope.v1", target_path=name, file_bytes=length, missing=holes))
        target = SimpleNamespace(length=len(reference), hashes=signed or dict(sha512=hashlib.sha512(reference).hexdigest()))
        case = dict(artifact_sha256=pin, holes_sha256=sha(scope), artifact_layout=layout, publisher_file_sha256=baseline)
        stream = io.BytesIO(b"prefix" + captured + b"padding" + reference)
        objects = {pin: (6, len(captured)), baseline: (13 + len(captured), len(reference))}
        rr = publisher_ranges.RangeReplay(stream, objects)
        def run():
            parsed, reason = publisher.file_scope(scope, corpus.decode_document, keep_ranges=True)
            self.assertIsNone(reason)
            return publisher.compare_target(parsed, pin, objects[pin], {name: target}, stream, {},
                                            case=case, range_replay=rr)
        return rr, run

    def test_all_small_hole_maps_against_scalar_file_oracle(self):
        reference = bytes(range(7))
        with mock.patch.object(publisher_ranges, "CHUNK", 3):
            for mask in range(1 << len(reference)):
                observed = [i for i in range(len(reference)) if not mask & (1 << i)]
                holes = [[i, i + 1] for i in range(len(reference)) if i not in observed]
                for corrupt in (set(), {0, 2, 5, 6}):
                    data = bytes(x ^ (255 if i in corrupt else 0) for i, x in enumerate(reference))
                    expected = sorted(set(observed) & corrupt)
                    for layout in ("packed", "file_offsets"):
                        capture = bytes(data[i] for i in observed) if layout == "packed" else data
                        _, run = self.replay(capture, reference, holes, layout)
                        truth, _, details = run()
                        result = details["file_range_comparison"]
                        self.assertTrue(result["publisher_file_verified"])
                        self.assertEqual((truth, result["compared_bytes"], result["differing_bytes"], result["first_difference_offset"]),
                                         ("negative" if expected else "unknown" if holes else "positive", len(observed),
                                          len(expected), expected[0] if expected else None), (mask, layout))

    def test_untrusted_reference_and_replaced_archive_members(self):
        hashes = dict(sha256=sha(SOURCE), sha512="0" * 128)
        rr, run = self.replay(b"X" + SOURCE[4:], SOURCE, [[1, 4]], "packed", signed=hashes)
        truth, reason, details = run()
        evidence = details["file_range_comparison"]
        self.assertEqual((truth, reason, evidence["publisher_file_verified"], evidence["compared_bytes"],
                          evidence["differing_bytes"], evidence["first_difference_offset"]),
                         ("unknown", "publisher_file_not_signed_target", False, 0, None, None))
        for offset in (6, 13 + len(SOURCE) - 3):
            rr, run = self.replay(b"X" + SOURCE[4:], SOURCE, [[1, 4]], "packed")
            rr.stream.seek(offset)
            rr.stream.write(b"!")
            with self.assertRaisesRegex(ValueError, "original changed"):
                run()
        rr, run = self.replay(b"X" + SOURCE[4:], SOURCE, [[1, 4]], "packed")
        rr.stream.truncate(len(SOURCE))
        with self.assertRaisesRegex(ValueError, "truncated original"):
            run()

    def test_large_fragmented_capture_reads_each_member_once_per_block(self):
        block = archive.CHUNK
        ref = bytes(range(256)) * (2*block//256 + 1)
        holes = [[i, i+1] for i in range(1, 1000, 2)] + [[block-2, block+7], [2*block-1, 2*block+3]]
        offsets = bytearray(b"\x01") * len(ref)
        for start, end in holes:
            offsets[start:end] = bytes(end-start)
        capture = bytes(value ^ 255 for i, value in enumerate(ref) if offsets[i])
        rr, run = self.replay(capture, ref, holes, "packed")
        with mock.patch.object(rr.stream, "read", wraps=rr.stream.read) as reads:
            _, reason, details = run()
            self.assertEqual(reason, "observed_bytes_differ")
            q = details["file_range_comparison"]
            self.assertEqual((q["differing_bytes"], q["compared_bytes"], q["first_difference_offset"]),
                             (len(capture), len(capture), 0))
            self.assertEqual(reads.call_count, 6)
            self.assertLessEqual(max(c.args[0] for c in reads.call_args_list), block)

    def test_budgets_layout_empty_inputs_and_same_object(self):
        self.assertEqual(self.replay(b"", b"", [], "packed")[1]()[:2], ("positive", "matches_signed_target"))
        self.assertEqual(self.replay(b"", SOURCE, [[0, len(SOURCE)]], "packed")[1]()[:2], ("unknown", "no_observed_bytes"))
        self.assertEqual(self.replay(SOURCE, SOURCE, [[0, 1]], "packed")[1]()[1], "capture_layout_length_mismatch")
        self.assertEqual(self.replay(SOURCE[1:], SOURCE, [[0, 1]], "file_offsets")[1]()[1], "capture_layout_length_mismatch")
        self.assertEqual(self.replay(SOURCE, SOURCE, [], "file_offsets", length=len(SOURCE)+1)[1]()[1],
                         "scope_length_differs_from_signed_target")
        rr, run = self.replay(SOURCE, SOURCE, [], "file_offsets")
        rr.limit = 2 * len(SOURCE) - 1
        self.assertEqual(run()[1], "range_comparison_budget_exhausted")
        self.assertEqual(rr.read_bytes, 0)
        rr.limit += 1
        self.assertEqual(run()[0], "positive")
        self.assertEqual(run()[0], "positive")
        self.assertEqual(rr.accounting(), dict(byte_limit=rr.limit, read_bytes=2*len(SOURCE), distinct_comparisons=1,
                                              reused_comparisons=1, deferred_cases=1))
        rr, run = self.replay(b"X", SOURCE, [[1, len(SOURCE)]], "packed")
        del rr.objects[sha(SOURCE)]
        self.assertEqual(run()[1], "publisher_file_missing")

    def test_pinned_archive_replays_ranges_after_source_removal(self):
        repo = Repository()
        files = repo.files()
        blobs = {}
        def keep(data):
            blobs[sha(data)] = data
            return sha(data)
        ref = keep(bundle(files))
        original = keep(SOURCE)
        cases = []
        holes = [[1, 4], [8, 10]]
        changed = bytes([SOURCE[0] ^ 1]) + SOURCE[4:8] + SOURCE[10:]
        def case(name, data, missing, layout=None, witness=original):
            scope = keep(raw(dict(schema="kn.benchmark_target_scope.v1", target_path="file.bin", file_bytes=len(SOURCE), missing=missing)))
            row = dict(id=name, family="one", independence_group="one", partition="development", layer="owned_fixture",
                       unit="case", task=publisher.TASK, artifact_sha256=keep(data), holes_sha256=scope, truth="unknown", truth_ref_sha256=ref)
            if layout:
                row.update(artifact_layout=layout, publisher_file_sha256=witness)
            cases.append(row)
        case("old", changed, holes)
        case("full", SOURCE, [], "file_offsets")
        case("partial", changed, holes, "packed")
        case("again", changed, holes, "packed")
        case("match", SOURCE[:1] + b"xxx" + SOURCE[4:], holes, "file_offsets")
        case("untrusted", changed, holes, "packed", keep(SOURCE[::-1]))
        case("absent", changed, holes, "packed", sha(b"not retained"))
        case("missing-capture", changed, holes, "packed")
        cases[-1]["artifact_sha256"] = sha(b"absent capture")
        case("missing-scope", changed, holes, "packed")
        cases[-1]["holes_sha256"] = sha(b"absent scope")
        plan = raw(dict(schema="kn.benchmark_corpus.v2", corpus_id="ranges", cohort_id="files", cases=cases,
                        environment=dict(target_id="test", snapshot_id="one", os_build=None, architecture="unknown",
                                         hvci=None, vbs=None, verifier=None)))
        results = raw(dict(schema="kn.benchmark_results.v1", corpus_sha256=sha(plan), run_id="one", assessments=[],
                           tool=dict(name="reader", version="1", binary_sha256=keep(b"test tool"), config_sha256=keep(b"config"))))
        def invoke(code, *args):
            p = subprocess.run([sys.executable, "-B", CLI, *map(str, args)], capture_output=True, timeout=30)
            self.assertEqual(p.returncode, code, p.stderr or p.stdout[:500])
            return p.stdout
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "saved.knbench"
            with tempfile.TemporaryDirectory(dir=root) as stage:
                inputs = Path(stage)
                (inputs/"plan").write_bytes(plan)
                (inputs/"results").write_bytes(results)
                for pin, data in blobs.items():
                    (inputs/pin).write_bytes(data)
                (inputs/"list").write_bytes(raw(dict(schema="kn.benchmark_original_files.v1", original_files=sorted(blobs))))
                receipt = json.loads(invoke(0, "--corpus", inputs/"plan", "--results", inputs/"results", "--plan-sha256", sha(plan),
                                            "--write-archive", package, "--file-list", inputs/"list"))
            flags = ["--archive-corpus", package, "--sha256", receipt["package_sha256"], "--plan-sha256", sha(plan)]
            authority = ["--trusted-root-sha256", sha(files["root"]), "--verification-time", "20240201T000000Z"]
            data = invoke(1, *flags, *authority)
            self.assertEqual(invoke(1, *flags, *authority), data)
            report = json.loads(data)
            self.assertEqual(report["schema"], "kn.benchmark_publisher_report.v4")
            self.assertEqual(report["adjudicated_per_planned_case"], corpus.ratio(3, 9))
            self.assertEqual(report["range_replay"]["reused_comparisons"], 1)
            self.assertEqual(report["cases_decided_from_partial_captures"], 2)
            self.assertFalse(report["acquisition_scope_authenticated"])
            rows = {row["case_id"]: row for row in report["coverage"]["cases"]}
            self.assertEqual([rows[c["id"]]["truth_reason"] for c in cases], ["incomplete_file", "matches_signed_target",
                             "observed_bytes_differ", "observed_bytes_differ", "observed_match_with_holes",
                             "publisher_file_not_signed_target", "publisher_file_missing", "artifact_missing", "scope_missing"])
            missing_capture = rows["missing-capture"]["file_range_comparison"]
            self.assertEqual((missing_capture["stored_capture_bytes"], missing_capture["declared_observed_bytes"],
                              missing_capture["compared_bytes"]), (None, len(SOURCE)-5, 0))
            missing_scope = rows["missing-scope"]["file_range_comparison"]
            self.assertEqual((missing_scope["scope_status"], missing_scope["missing_bytes"],
                              missing_scope["declared_observed_bytes"]), ("scope_missing", None, None))
            self.assertEqual(rows["absent"]["original_status"]["publisher_file_sha256"], "missing")
            self.assertEqual(report["coverage"]["case_originals"]["publisher_file_sha256"],
                             dict(verified=7, missing=1, not_referenced=1))
            dest = root/"restored"
            invoke(0, *flags, "--get-original", original, "--destination", dest)
            self.assertEqual(dest.read_bytes(), SOURCE)
            with package.open("rb") as stream:
                _, _, objects = archive.read(stream, receipt["package_sha256"], sha(plan))
                for case_id, independent in (("partial", False), ("full", True)):
                    selected = next(c for c in cases if c["id"] == case_id)
                    one = dict(coverage=dict(cases=[dict(case_id=case_id)]))
                    publisher.adjudicate(one, stream, objects, {case_id:selected}, sha(files["root"]),
                                         "20240201T000000Z", corpus.decode_document, corpus.ratio)
                    self.assertEqual(one["adjudicated_per_planned_case"], corpus.ratio(1, 1))
                    self.assertEqual(one["ground_truth_authenticated"], independent)


class FileReadReceiptTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes_raw()
        self.nonce = "12" * 32
        self.row = dict(offset=2, requested=4, transferred=3, operation="read", win32_status=0, start_ns=1, end_ns=2)
        self.body = dict(case_id="case", target_path="file.bin", capture_nonce=self.nonce, started_unix_ns=123,
                         source=dict(file_bytes=5, file_id="00"*16, volume_serial="01"*8, opened_path_sha256=sha(b"name")),
                         packed_sha256=sha(b"abc"), attempts=[self.row])

    def envelope(self):
        return dict(schema=reads.SCHEMA, body=self.body, public_key=self.pub.hex(),
                    signature=self.key.sign(reads.DOMAIN + raw(self.body)).hex())

    def test_signature_key_nonce_and_sparse_set(self):
        envelope = self.envelope()
        scope, row = reads.verify(envelope, sha(self.pub), self.nonce)
        self.assertEqual(scope, ("file.bin", 5, [[0, 2]]))
        self.assertEqual((row["packed_bytes"], row["short_reads"]), (3, 1))
        for pin, nonce, reason in [(None, None, "policy_required"), (sha(b"wrong"), self.nonce, "untrusted"),
                                   (sha(self.pub), "ab"*32, "nonce_mismatch")]:
            with self.assertRaisesRegex(ValueError, reason):
                reads.verify(envelope, pin, nonce)
        self.row.update(offset=0)
        with self.assertRaisesRegex(ValueError, "invalid_collector_signature"):
            reads.verify(envelope, sha(self.pub), self.nonce)

    def test_signed_impossible_attempts(self):
        for change in (dict(offset=-1), dict(transferred=True), dict(offset=4), dict(requested=0),
                       dict(win32_status=33), dict(operation="seek"), dict(end_ns=0), dict(requested=reads.CHUNK+1)):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "invalid_read_attempt"):
                self.body["attempts"] = [{**self.row, **change}]
                reads.verify(self.envelope(), sha(self.pub), self.nonce)
        self.body["attempts"] = [self.row, self.row]
        with self.assertRaisesRegex(ValueError, "invalid_read_attempt"):
            reads.verify(self.envelope(), sha(self.pub), self.nonce)
        self.body["attempts"] = [dict(self.row, transferred=0, operation="seek", win32_status=87)]
        scope, row = reads.verify(self.envelope(), sha(self.pub), self.nonce)
        self.assertEqual((scope[2], row["failed_operations"], row["read_calls"]), ([[0, 5]], 1, 0))


@unittest.skipUnless(os.name == "nt", "requires local Windows file handles")
class WindowsFileAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.private, self.dest = (self.root / name for name in ("source", "controller.key", "capture"))
        self.source.write_bytes(SOURCE)
        key = Ed25519PrivateKey.generate()
        self.pin = sha(key.public_key().public_bytes_raw())
        self.private.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        self.nonce = os.urandom(32).hex()
        self.command = [sys.executable, "-B", CLI.with_name("capture-file-ranges.py"), "--source", self.source,
                        "--signing-key", self.private, "--case-id", "case", "--capture-nonce", self.nonce,
                        "--target-path", "file.bin", "--output", self.dest]

    def invoke(self, command, code=0, **kwargs):
        p = subprocess.run(command, capture_output=True, timeout=30, **kwargs)
        self.assertEqual(p.returncode, code, p.stderr or p.stdout[:500])
        return p.stdout

    def test_locked_range_short_read_eof_and_source_identity(self):
        import msvcrt
        with self.source.open("rb") as control:
            control.seek(3)
            msvcrt.locking(control.fileno(), msvcrt.LK_NBLCK, 4)
            receipt = json.loads(self.invoke([*self.command, "--range", "0+3", "--range", "3+4", "--range", "7+32",
                                              "--range", "40+1"]))
        actual = (self.dest / "capture.knblob").read_bytes()
        envelope = json.loads((self.dest / "scope.knreads").read_bytes())
        scope, row = reads.verify(envelope, self.pin, self.nonce)
        self.assertEqual(actual, SOURCE[:3] + SOURCE[7:])
        self.assertEqual((receipt["artifact_sha256"], row["packed_sha256"], scope[2]), (sha(actual), sha(actual), [[3, 7]]))
        self.assertEqual(int.from_bytes(bytes.fromhex(row["source"]["file_id"]), "little"), self.source.stat().st_ino)
        self.assertEqual([(a["transferred"], a["win32_status"]) for a in envelope["body"]["attempts"]],
                         [(3, 0), (0, 33), (len(SOURCE)-7, 0), (0, 0)])
        self.assertEqual((row["failed_operations"], row["short_reads"]), (1, 2))

    def test_collision_rejection_and_concurrent_publication(self):
        linked = self.root / "linked"
        os.link(self.private, linked)
        self.invoke([*self.command, "--source", linked, "--range", "0+1"], 2)
        self.invoke([*self.command, "--range", "2+2", "--range", "3+4"], 2)
        self.assertFalse(self.dest.exists())
        command = [*self.command, "--range", "3+5"]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as one:
            two = subprocess.run(command, capture_output=True, timeout=30)
            one.communicate(timeout=30)
        self.assertEqual(sorted([one.returncode, two.returncode]), [0, 2])
        self.assertEqual((self.dest/"capture.knblob").read_bytes(), SOURCE[3:8])
        self.assertFalse(list(self.root.glob(".knbench-*.tmp")))
        for protected in (self.source, self.private, self.dest/"scope.knreads", self.dest/"capture.knblob"):
            alias = self.root/"sink"
            os.link(protected, alias)
            before = protected.read_bytes()
            with alias.open("ab", buffering=0) as redirected:
                p = subprocess.run([*command, "--help"], stdout=redirected, stderr=redirected, timeout=30)
            self.assertEqual((p.returncode, protected.read_bytes()), (2, before))
            alias.unlink()

    def test_writer_empty_file_and_interrupted_read(self):
        command = [*self.command, "--range", "0+8"]
        with self.source.open("r+b"):
            self.invoke(command, 2)
        self.assertFalse(self.dest.exists())
        spec = importlib.util.spec_from_file_location("file_collector", self.command[2])
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        args = SimpleNamespace(ranges=["0+2", "2+2"], source=self.source, signing_key=self.private, output=self.dest,
                               case_id="case", target_path="file.bin", capture_nonce=self.nonce)
        with mock.patch.object(collector.DiskReader, "attempt", side_effect=[("read", 0, b"ab"), OSError("interrupted")]):
            with self.assertRaisesRegex(OSError, "interrupted"):
                collector.collect(args)
        self.assertFalse(self.dest.exists() or list(self.root.glob(".knbench-*.tmp")))
        self.source.write_bytes(b"")
        result = json.loads(self.invoke(command))
        scope, witness = reads.verify(json.loads((self.dest/"scope.knreads").read_bytes()), self.pin, self.nonce)
        self.assertEqual((scope, result["artifact_sha256"], witness["short_reads"]), (("file.bin", 0, []), sha(b""), 1))

    def test_identity_after_same_name_replacement(self):
        self.invoke([*self.command, "--range", "0+4"])
        before = json.loads((self.dest/"scope.knreads").read_bytes())["body"]["source"]
        self.source.rename(self.root/"first-file")
        self.source.write_bytes(SOURCE)
        other = self.root/"other"
        self.invoke([*self.command, "--output", other, "--range", "0+4"])
        after = json.loads((other/"scope.knreads").read_bytes())["body"]["source"]
        self.assertEqual(before["opened_path_sha256"], after["opened_path_sha256"])
        self.assertEqual(before["file_bytes"], after["file_bytes"])
        self.assertNotEqual(before["file_id"], after["file_id"])

    def test_archive_policy_and_replay_after_source_loss(self):
        # The offset differs in the actual candidate file. All other bytes remain independently known to the test.
        changed = bytearray(SOURCE)
        changed[4] ^= 1
        self.source.write_bytes(changed)
        self.invoke([*self.command, "--range", "2+6"])
        blobs = {}
        def keep(data):
            blobs[sha(data)] = data
            return sha(data)
        capture = keep((self.dest/"capture.knblob").read_bytes())
        signed = (self.dest/"scope.knreads").read_bytes()
        receipt = keep(signed)
        files = Repository().files()
        case = dict(id="case", family="file", independence_group="one", partition="development",
                    task=publisher.TASK, truth="unknown", layer="owned_fixture", unit="case", artifact_sha256=capture,
                    holes_sha256=receipt, truth_ref_sha256=keep(bundle(files)), publisher_file_sha256=keep(SOURCE),
                    artifact_layout="packed")
        def replay(plan_cases, *policy, expected=0):
            plan = raw(dict(schema="kn.benchmark_corpus.v2", corpus_id="files", cohort_id="one", cases=plan_cases,
                            environment=dict(target_id="local", snapshot_id="one", os_build=None, architecture="amd64",
                                             hvci=None, vbs=None, verifier=None)))
            results = raw(dict(schema="kn.benchmark_results.v1", corpus_sha256=sha(plan), run_id="one", assessments=[],
                               tool=dict(name="reader", version="1", binary_sha256=sha(b"test reader"), config_sha256=sha(b"test config"))))
            package = self.root/(sha(plan) + ".knbench")
            if not package.exists():
                with tempfile.TemporaryDirectory(dir=self.root) as inputs:
                    folder = Path(inputs)
                    (folder/"plan").write_bytes(plan)
                    (folder/"results").write_bytes(results)
                    referenced = {c[n] for c in plan_cases for n in ("holes_sha256", "truth_ref_sha256", "artifact_sha256", "publisher_file_sha256")}
                    paths = []
                    for pin in referenced:
                        if pin in blobs:
                            path = folder/pin
                            path.write_bytes(blobs[pin])
                            paths.extend(["--original", path])
                    self.invoke([sys.executable, "-B", CLI, "--corpus", folder/"plan", "--results", folder/"results",
                                 "--write-archive", package, "--plan-sha256", sha(plan), *paths])
            return json.loads(self.invoke([sys.executable, "-B", CLI, "--archive-corpus", package, "--sha256",
                                           sha(package.read_bytes()), "--plan-sha256", sha(plan), "--trusted-root-sha256",
                                           sha(files["root"]), "--verification-time", "20240201T000000Z", *policy], expected))
        self.source.unlink()
        self.private.unlink()
        policy_flags = ["--collector-key-sha256", self.pin, "--capture-nonce", self.nonce]
        report = replay([case], *policy_flags)
        row = report["coverage"]["cases"][0]
        self.assertEqual((row["publisher_truth"], row["file_range_comparison"]["first_difference_offset"]), ("negative", 4))
        self.assertTrue(report["acquisition_scope_authenticated"] and report["ground_truth_authenticated"])
        self.assertEqual(replay([case], *policy_flags), report)
        unsigned = keep(raw(dict(schema="kn.benchmark_target_scope.v1", target_path="file.bin", file_bytes=len(SOURCE),
                                 missing=[[0, 2], [8, len(SOURCE)]])))
        modified = json.loads(signed)
        modified["body"]["attempts"][0]["offset"] = 1
        wrong_scope = keep(raw(modified))
        for selected, policy, reason in [(case, [], "collector_policy_required"),
                                         (case, [*policy_flags[:3], "de"*32], "capture_nonce_mismatch"),
                                         (dict(case, holes_sha256=unsigned), policy_flags, "signed_read_receipt_required"),
                                         (dict(case, id="second"), policy_flags, "receipt_case_mismatch"),
                                         (dict(case, artifact_sha256=keep(b"xxxxxx")), policy_flags, "receipt_artifact_mismatch"),
                                         (dict(case, holes_sha256=wrong_scope), policy_flags, "invalid_collector_signature")]:
            result = replay([selected], *policy, expected=1)
            row = result["coverage"]["cases"][0]
            self.assertEqual((row["publisher_truth"], row["read_acquisition"]["status"]), ("unknown", reason))
            self.assertFalse(result["acquisition_scope_authenticated"])


class PublisherHistoryTests(unittest.TestCase):
    first_at = "20240101T000000Z"
    second_at = "20240201T000000Z"

    def setUp(self):
        self.repo = Repository()
        self.anchor = self.repo.files()["root"]
        self.pin = sha(self.anchor)

    def release(self, ts=2, snap=2, top=2, *, members=None, timestamp=None, snapshot=None, targets=None,
                roots=(), online_signer=None, extra_signatures=()):
        r = self.repo
        files = r.files()
        files["targets"] = r.sign("targets", dict(r.base["targets"], version=top, **(targets or {})))
        entries = {"targets.json": {"version": top}, **(members or {})}
        files["snapshot"] = r.sign("snapshot", dict(r.base["snapshot"], version=snap, meta=entries, **(snapshot or {})))
        body = dict(r.base["timestamp"], version=ts, meta={"snapshot.json": {"version": snap}}, **(timestamp or {}))
        files["timestamp"] = r.sign(online_signer or "timestamp", body)
        if extra_signatures:
            doc = json.loads(files["timestamp"])
            doc["signatures"].extend(sig for role in extra_signatures for sig in json.loads(r.sign(role, body))["signatures"])
            files["timestamp"] = raw(doc)
        return history_bundle(files, self.anchor, roots) if roots else bundle(files)

    def compare(self, old, new, *, previous_at=None, current_at=None, pin=None, minimum=None):
        prev = history.Observation(previous_at or self.first_at, old)
        current = history.Observation(current_at or self.second_at, new)
        return publisher.check_reference(history.pack(prev, current), corpus.decode_document, self.pin, TIME,
                                         minimum, pin if pin is not None else prev.checkpoint(self.pin))[1]

    def test_all_snapshot_names_and_same_version_content(self):
        old = self.release(members={"unvisited.json": {"version": 9}})
        def run(reason, **params):
            proof = self.compare(old, self.release(**params))
            self.assertEqual(proof["status"], reason, proof)
            self.assertNotIn("checkpoint_sha256", proof["publisher_history"])
            return proof["publisher_history"]
        run("timestamp_version_rollback", ts=1)
        run("snapshot_version_rollback", ts=3, snap=1)
        run("targets_version_rollback", ts=3, snap=3, top=1)
        run("timestamp_version_conflict", timestamp={"expires": "2024-10-01T00:00:00Z"})
        run("snapshot_version_conflict", ts=3)
        run("targets_version_conflict", ts=3, snap=3, targets={"targets": {}})
        self.assertEqual(run("snapshot_entry_removed", ts=3, snap=3)["metadata_filename"], "unvisited.json")
        h = run("snapshot_entry_rollback", ts=3, snap=3, members={"unvisited.json": {"version": 8}})
        self.assertEqual((h["metadata_filename"], h["previous_version"], h["current_version"]), ("unvisited.json", 9, 8))
        run("invalid_checkpoint_snapshot_entry", ts=3, snap=3, members={"unvisited.json": {"version": True}})
        self.assertEqual(self.compare(old, old+b" ")["publisher_history"]["transition"], "unchanged")
        advanced = self.release(ts=3, snap=3, members={"unvisited.json": {"version": 10}})
        self.assertEqual(self.compare(old, advanced)["publisher_history"]["transition"], "advanced")
        # Re-signing the identical body or changing its outer whitespace keeps its signed identity.
        doc = json.loads(old)
        for role in ("timestamp", "targets"):
            entry = json.loads(base64.b64decode(doc[role]))
            entry["signatures"].reverse()
            doc[role] = base64.b64encode(b" "+raw(entry)).decode()
        self.assertEqual(self.compare(old, raw(doc))["publisher_history"]["transition"], "unchanged")

    def test_time_and_independent_observation_binding(self):
        old = self.release(timestamp={"expires": "2024-01-15T00:00:00Z"})
        new = self.release(ts=3)
        self.assertEqual(self.compare(old, new)["status"], "verified")
        self.assertEqual(self.compare(old, new, previous_at=self.second_at)["status"], "expired_metadata")
        self.assertEqual(self.compare(old, new, previous_at="20240301T000000Z")["status"], "checkpoint_time_rollback")
        self.assertEqual(self.compare(old, new, current_at=self.first_at)["status"], "checkpoint_verification_time_mismatch")
        self.assertEqual(self.compare(old, new, pin="0"*64)["status"], "previous_checkpoint_mismatch")
        first = history.Observation(self.first_at, old)
        expected = sha(b"kn.publisher.observation.v1\0"+bytes.fromhex(self.pin)+self.first_at.encode()+bytes.fromhex(sha(old)))
        self.assertEqual(first.checkpoint(self.pin), expected)
        for wrong in (history.Observation(self.second_at, old).checkpoint(self.pin),
                      history.Observation(self.first_at, old+b" ").checkpoint(self.pin), first.checkpoint("0"*64)):
            self.assertEqual(self.compare(old, new, pin=wrong)["status"], "previous_checkpoint_mismatch")
        current = history.Observation(self.second_at, new)
        for ref, supplied, reason in ((new, expected, "publisher_history_required"),
                                      (history.pack(None, current), expected, "previous_observation_missing"),
                                      (history.pack(first, current), None, "previous_checkpoint_required")):
            targets, proof = publisher.check_reference(ref, corpus.decode_document, self.pin, TIME, previous_checkpoint=supplied)
            self.assertEqual((targets, proof["status"]), ({}, reason))

    def test_root_prefix_and_online_key_recovery(self):
        r = self.repo
        two = successor(r, r, 2)
        other_two = successor(r, r, 2, expires="2024-11-01T00:00:00Z")
        old = self.release(ts=20)
        self.assertEqual(self.compare(self.release(roots=[two]), self.release())["status"], "root_version_rollback")
        self.assertEqual(self.compare(self.release(roots=[two]), self.release(roots=[other_two]))["status"], "root_history_conflict")
        self.assertEqual(self.compare(old, self.release(roots=[two]))["status"], "timestamp_version_rollback")
        self.assertEqual(self.compare(old, self.release(ts=21, roots=[two]), minimum=2)["status"], "verified")
        self.assertEqual(self.compare(old, self.release(ts=21, roots=[two]), minimum=3)["status"], "root_version_below_minimum")
        policies = copy.deepcopy(r.base["root"]["roles"])
        policies["timestamp"] = policies["snapshot"].copy()
        rotated = successor(r, r, 2, roles=policies)
        new = self.release(ts=1, snap=1, top=1, roots=[rotated], online_signer="snapshot")
        proof = self.compare(old, new)
        self.assertEqual((proof["status"], proof["publisher_history"]["rotated_online_roles"]), ("verified", ["timestamp"]))
        self.assertEqual(self.compare(old, self.release(roots=[rotated]))["status"], "signature_threshold_failed")
        policies["timestamp"] = dict(keyids=r.quorum["timestamp"]+r.quorum["snapshot"], threshold=2)
        threshold = successor(r, r, 2, roles=policies)
        self.assertEqual(self.compare(old, self.release(roots=[threshold], extra_signatures=["snapshot"]))["status"],
                         "timestamp_version_rollback")
        policies = copy.deepcopy(r.base["root"]["roles"])
        policies["snapshot"] = policies["timestamp"].copy()
        next_root = successor(r, r, 2, roles=policies)
        wrapped = json.loads(self.release(ts=1, snap=1, top=1, roots=[next_root]))
        snapshot = json.loads(base64.b64decode(wrapped["snapshot"]))["signed"]
        wrapped["snapshot"] = base64.b64encode(r.sign("timestamp", snapshot)).decode()
        self.assertEqual(self.compare(old, raw(wrapped))["publisher_history"]["rotated_online_roles"], ["snapshot"])
        # Relabeling the same signing material can break verification by key ID without replacing the key.
        old_id, = r.quorum["timestamp"]
        new_id = sha(b"alias")
        keys = copy.deepcopy(r.base["root"]["keys"])
        keys[new_id] = {**keys[old_id], "keyval": {"public": keys[old_id]["keyval"]["public"].upper()}}
        policies = copy.deepcopy(r.base["root"]["roles"])
        policies["timestamp"] = dict(keyids=[new_id], threshold=1)
        wrapped = json.loads(self.release(roots=[successor(r, r, 2, roles=policies, keys=keys)]))
        meta = json.loads(base64.b64decode(wrapped["timestamp"]))
        meta["signatures"][0]["keyid"] = new_id
        wrapped["timestamp"] = base64.b64encode(raw(meta)).decode()
        self.assertEqual(self.compare(old, raw(wrapped))["status"], "timestamp_version_rollback")

    def test_delegated_witnesses_and_snapshot_only_members(self):
        r = self.repo
        rules = [delegation(r, "leaf", ["allowed/*"])]
        top = role_body(r, {}, rules)
        def witness(custom, *, wrong_key=False, omit=False, whitespace=False):
            data = r.sign("snapshot" if wrong_key else "timestamp", role_body(r, {}, custom=custom))
            if whitespace:
                data += b" "
            return delegated_release(r, top, {"leaf": data}, retained={} if omit else {"leaf": data},
                                     links={"leaf": {"version": 1}})
        old = witness("one")
        self.assertEqual(self.compare(old, witness("two"))["status"], "delegated_version_conflict")
        self.assertEqual(self.compare(old, witness("one", whitespace=True))["status"], "verified")
        self.assertEqual(self.compare(old, witness("one", omit=True))["status"], "verified")
        self.assertEqual(self.compare(old, witness("one", wrong_key=True))["status"], "checkpoint_witness_unauthenticated")
        self.assertEqual(self.compare(witness("one", wrong_key=True), old)["publisher_history"]["checkpoint_witness"], "leaf")
        detached = json.loads(old)
        detached["delegated_roles"]["orphan"] = detached["delegated_roles"].pop("leaf")
        self.assertEqual(self.compare(old, raw(detached))["checkpoint_witness"], "orphan")

    def test_snapshot_entry_comparison_against_python_tuf(self):
        from tuf.api import exceptions
        from tuf.ngclient._internal.trusted_metadata_set import EnvelopeType, TrustedMetadataSet
        old = self.release(members={"unvisited.json": {"version": 4}})
        old_bytes = base64.b64decode(json.loads(old)["snapshot"])
        for version, expected in ((None, "snapshot_entry_removed"), (3, "snapshot_entry_rollback"),
                                  (4, "verified"), (5, "verified")):
            members = {"unvisited.json": {"version": version}} if version is not None else {}
            new = self.release(ts=3, snap=3, members=members)
            doc = json.loads(new)
            sdk = TrustedMetadataSet(self.anchor, EnvelopeType.METADATA)
            sdk.reference_time = TIME
            sdk.update_timestamp(base64.b64decode(doc["timestamp"]))
            # The updater retains a previously trusted snapshot even when its version is no longer final.
            with self.assertRaises(exceptions.BadVersionNumberError):
                sdk.update_snapshot(old_bytes, trusted=True)
            self.assertEqual(sdk.snapshot.version, 2)
            if expected == "verified":
                self.assertEqual(sdk.update_snapshot(base64.b64decode(doc["snapshot"])).version, 3)
            else:
                with self.assertRaises(exceptions.RepositoryError):
                    sdk.update_snapshot(base64.b64decode(doc["snapshot"]))
            self.assertEqual(self.compare(old, new)["status"], expected)

    def test_framing_boundaries_and_previous_authentication(self):
        current = history.Observation(self.second_at, self.release())
        prev = history.Observation(self.first_at, current.reference)
        frame = history.pack(prev, current)
        for broken in (frame[:-1], frame+b"x", frame[:10], history.HEADER.pack(history.MAGIC, bytes(16), 0,
                        self.second_at.encode(), len(frame))+frame):
            self.assertNotEqual(publisher.check_reference(broken, corpus.decode_document, self.pin, TIME)[1]["status"], "verified")
        with self.assertRaises(ValueError):
            history.pack(None, history.Observation(self.second_at, frame))
        max_member = current.reference.ljust(archive.MAX_DOCUMENT)
        both = history.pack(prev._replace(reference=max_member), current._replace(reference=max_member))
        self.assertEqual(len(both), history.MAX_REFERENCE)
        self.assertEqual(self.compare(max_member, max_member)["status"], "verified")
        bad = json.loads(current.reference)
        bad["timestamp"] = bad["targets"]
        proof = self.compare(raw(bad), current.reference)
        self.assertEqual((proof["failed_role"], proof["publisher_history"]["previous_failed_role"]), ("previous", "timestamp"))
        self.assertNotIn("checkpoint_sha256", proof["publisher_history"])

    def test_command_advances_three_observations_without_overwriting(self):
        cli = Path(__file__).with_name("advance-publisher-reference.py")
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            src, first, second, third, rejected = (directory/n for n in ("input", "first", "second", "third", "rejected"))
            def command(out, at, *extra):
                return [sys.executable, "-B", cli, "--reference", src, "--trusted-root-sha256", self.pin,
                        "--verification-time", at, "--out", out, *extra]
            def run(code, out, at, *extra):
                proc = subprocess.run(command(out, at, *extra), capture_output=True, timeout=30)
                self.assertEqual(proc.returncode, code, (proc.stdout, proc.stderr))
                return json.loads(proc.stdout) if proc.stdout else {}
            src.write_bytes(self.release(ts=1))
            a = run(0, first, self.first_at)
            self.assertEqual(a["publisher_reference_sha256"], sha(first.read_bytes()))
            src.write_bytes(self.release(ts=2))
            args = ("--previous", first, "--previous-checkpoint-sha256", a["checkpoint_sha256"])
            b = run(0, second, self.second_at, *args)
            verify = [sys.executable, "-B", cli, "--verify-history", second, "--trusted-root-sha256", self.pin,
                      "--verification-time", self.second_at]
            replay = subprocess.run([*verify, "--previous-checkpoint-sha256", a["checkpoint_sha256"]], capture_output=True)
            self.assertEqual((replay.returncode, json.loads(replay.stdout)), (0, b))
            replay = subprocess.run(verify, capture_output=True)
            self.assertEqual((replay.returncode, json.loads(replay.stdout)["publisher_proof"]["status"]),
                             (1, "previous_checkpoint_required"))
            args2 = ("--previous", second, "--previous-checkpoint-sha256", b["checkpoint_sha256"])
            self.assertEqual(run(0, third, self.second_at, *args2)["publisher_proof"]["publisher_history"]["transition"], "unchanged")
            self.assertFalse(history.unpack(third.read_bytes())[0].reference.startswith(history.MAGIC))
            self.assertEqual(run(1, rejected, self.second_at, "--previous", first, "--previous-checkpoint-sha256",
                                 b["checkpoint_sha256"])["publisher_proof"]["status"], "previous_checkpoint_mismatch")
            src.write_bytes(self.release(ts=1))
            self.assertEqual(run(1, rejected, self.second_at, *args2)["publisher_proof"]["status"], "timestamp_version_rollback")
            self.assertFalse(rejected.exists())
            run(2, first, self.second_at, *args2)
            self.assertEqual(sha(first.read_bytes()), a["publisher_reference_sha256"])
            for path in (src, second, third):
                raw_before = path.read_bytes()
                alias = directory/"redirected-output"
                os.link(path, alias)
                with alias.open("ab", buffering=0) as sink:
                    proc = subprocess.run([*command(third, self.second_at, *args2), "--help"], stdout=sink, stderr=sink)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(path.read_bytes(), raw_before)
                alias.unlink()
            race = directory/"race"
            children = [subprocess.Popen(command(race, self.second_at), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        for _ in range(2)]
            outputs = [child.communicate(timeout=30) for child in children]
            self.assertEqual(sorted(child.returncode for child in children), [0, 2])
            index = next(i for i, child in enumerate(children) if child.returncode == 0)
            self.assertEqual(json.loads(outputs[index][0])["publisher_reference_sha256"], sha(race.read_bytes()))
            self.assertFalse(list(directory.glob(".knbench-*.tmp")))


class PublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repository()

    def proof(self, files, pin=None, when=TIME):
        return publisher.check_reference(bundle(files), corpus.decode_document, pin or sha(files["root"]), when)[1]

    def test_signatures_and_both_link_forms(self):
        for files in (self.repo.files(), self.repo.files({"timestamp": {"meta": {"snapshot.json": {"version": 1}}},
                                                         "snapshot": {"meta": {"targets.json": {"version": 1}}}})):
            proof = self.proof(files)
            self.assertEqual(proof["status"], "verified")
            self.assertEqual(proof["roles"]["targets"]["valid_key_ids"], 2)
            self.assertEqual(set(proof["metadata_links"]), {"snapshot", "targets"})
        self.assertIsNone(proof["metadata_links"]["targets"]["hashes"])

    def test_wrong_root_expiry_and_signing_authority(self):
        files = self.repo.files()
        self.assertEqual(self.proof(files, "0" * 64)["status"], "untrusted_root")
        for role in publisher.ROLES:
            with self.subTest(role=role):
                altered = self.repo.files({role: {"expires": "2024-02-01T00:00:00Z"}})
                self.assertEqual((self.proof(altered)["failed_role"], self.proof(altered)["status"]), (role, "expired_metadata"))
        files["timestamp"] = self.repo.sign("snapshot", json.loads(files["timestamp"])["signed"])
        self.assertEqual(self.proof(files)["status"], "signature_threshold_failed")
        for role in ("root", "targets"):
            files = self.repo.files({"snapshot": {"meta": {"targets.json": {"version": 1}}}})
            record = json.loads(files[role])
            record["signatures"].pop()
            files[role] = raw(record)
            self.assertEqual(self.proof(files)["status"], "signature_threshold_failed")
            record["signatures"] *= 2
            files[role] = raw(record)
            self.assertNotEqual(self.proof(files)["status"], "verified")

    def test_cross_version_length_hash_and_role_swaps(self):
        for role, child in (("timestamp", "snapshot"), ("snapshot", "targets")):
            for descriptor, status in ((dict(version=2), "metadata_version_mismatch"),
                                       (dict(version=True), "metadata_version_mismatch"),
                                       (dict(version=1, length=None), "invalid_metadata_length"),
                                       (dict(version=1, hashes=None), "invalid_metadata_hashes"),
                                       (dict(version=1, hashes={}), "invalid_metadata_hashes"),
                                       (dict(version=1, length=1), "metadata_length_or_hash_mismatch"),
                                       (dict(version=1, hashes=dict(sha256="f" * 64)), "metadata_length_or_hash_mismatch")):
                files = self.repo.files({role: {"meta": {child + ".json": descriptor}}})
                self.assertEqual(self.proof(files)["status"], status)
        files = self.repo.files()
        files["timestamp"], files["snapshot"] = files["snapshot"], files["timestamp"]
        self.assertNotEqual(self.proof(files)["status"], "verified")

    def test_malformed_and_duplicate_signed_fields(self):
        files = self.repo.files()
        files["timestamp"] = files["timestamp"].replace(b'"version":1', b'"version":99,"version":1', 1)
        self.assertNotEqual(self.proof(files)["status"], "verified")
        for bad in (b"null", b"[]", b'{"root":0}', b'{"schema":1,"schema":2}'):
            self.assertNotEqual(publisher.check_reference(bad, corpus.decode_document, "0" * 64, TIME)[1]["status"], "verified")

    def test_scope_bounds_and_unknown_descriptors(self):
        base = dict(schema="kn.benchmark_target_scope.v1", target_path="a/b", file_bytes=10, missing=[])
        self.assertEqual(publisher.file_scope(raw(base), corpus.decode_document)[0], ("a/b", 10, False))
        for change in (dict(missing=[[1, 2], [1, 3]]), dict(missing=[[0, 11]]), dict(missing=[[4, 4]]),
                       dict(file_bytes=True), dict(target_path="../a"), dict(target_path="/a"), dict(target_path="a\\b")):
            self.assertIsNone(publisher.file_scope(raw({**base, **change}), corpus.decode_document)[0])
        for descriptor in (dict(length=True, hashes=dict(sha256=sha(SOURCE))),
                           dict(length=0, hashes=dict(md5="a" * 32)), dict(length=1, hashes=dict(sha256="bad"))):
            out = publisher.compare_target(("a", 1, False), sha(b"x"), (0, 1), {"a": SimpleNamespace(**descriptor)}, None, {})
            self.assertEqual(out[:2], ("unknown", "unsupported_target_descriptor"))

    def test_all_hashes_and_zero_length_target(self):
        stream = io.BytesIO(b"")
        pin = sha(b"")
        hashes = dict(sha256=pin, sha512=hashlib.sha512(b"").hexdigest())
        targets = {"empty": SimpleNamespace(length=0, hashes=hashes)}
        args = (("empty", 0, False), pin, (0, 0), targets, stream, {})
        with mock.patch.object(publisher, "visit_original", wraps=archive.visit_original) as visit:
            self.assertEqual(publisher.compare_target(*args)[0], "positive")
            targets["empty"].hashes = {"sha512": hashes["sha512"]}
            self.assertEqual(publisher.compare_target(*args)[0], "positive")
            targets["empty"].hashes = {**hashes, "sha512": "0" * 128}
            self.assertEqual(publisher.compare_target(*args)[0], "negative")
            visit.assert_called_once()

    def test_complete_and_incomplete_cases_through_cli(self):
        files = self.repo.files()
        with tempfile.TemporaryDirectory(prefix="kn-publisher-") as tmp:
            directory = Path(tmp)
            inputs = {}
            def keep(data):
                pin = sha(data)
                path = directory / pin
                path.write_bytes(data)
                inputs[pin] = path
                return pin
            ref, config, binary = keep(bundle(files)), keep(b"config"), keep(b"tool")
            observations, cases = [], []
            controls = (
                ("match", SOURCE, "negative", [], "file.bin", "positive"),
                ("different", SOURCE[:-1], "positive", [], "file.bin", "negative"),
                ("holes", SOURCE, "positive", [[0, 1]], "file.bin", "positive"),
                ("unlisted", SOURCE, "negative", [], "other", "negative"),
                ("failed", SOURCE, "unknown", [], "file.bin", None),
                ("outside", SOURCE, "positive", [], "file.bin", "positive"),
            )
            for key, data, truth, holes, name, outcome in controls:
                pin = keep(data)
                scope = keep(raw(dict(schema="kn.benchmark_target_scope.v1", target_path=name, file_bytes=len(data), missing=holes)))
                cases.append(dict(id=key, family="test", independence_group="one", partition="development",
                                  layer="synthetic", task=publisher.TASK if key != "outside" else "other-task", unit="case",
                                  artifact_sha256=pin, holes_sha256=scope, truth_ref_sha256=ref, truth=truth))
                if outcome:
                    observations.append(dict(case_id=key, artifact_sha256=pin, holes_sha256=scope, outcome=outcome,
                                             evidence_sha256=keep(key.encode()), elapsed_us=1))
            plan = raw(dict(schema="kn.benchmark_corpus.v1", corpus_id="test", cohort_id="test", cases=cases,
                            environment=dict(target_id="test", snapshot_id="test", os_build=None, architecture="unknown",
                                             hvci=None, vbs=None, verifier=None)))
            results = raw(dict(schema="kn.benchmark_results.v1", corpus_sha256=sha(plan), run_id="test",
                               tool=dict(name="test", version="1", binary_sha256=binary, config_sha256=config),
                               assessments=observations))
            def run(args, code):
                p = subprocess.run([sys.executable, "-B", CLI, *args], capture_output=True, timeout=45)
                self.assertEqual(p.returncode, code, p.stderr)
                return json.loads(p.stdout) if code != 2 else p.stdout
            def replay(exclude=()):
                path = directory / ("run-" + str(len(exclude)) + ".knbench")
                selected = [p for k, p in inputs.items() if k not in exclude]
                receipt = archive.seal(path, plan, results, selected, set(inputs))
                return ["--archive-corpus", path, "--sha256", receipt["package_sha256"], "--plan-sha256", sha(plan)]

            full = replay()
            flags = ["--trusted-root-sha256", sha(files["root"]), "--verification-time", "20240201T000000Z"]
            original = run(full, 0)
            self.assertFalse(original["ground_truth_authenticated"])
            rep = run(full + flags, 0)
            self.assertEqual(rep["adjudicated_per_planned_case"]["numerator"], 3)
            self.assertEqual(rep["adjudicated_per_planned_case"]["denominator"], 6)
            self.assertEqual(rep["contradicted_labels"], 2)
            metrics = next(s["metrics"] for s in rep["scopes"] if s["task"] == publisher.TASK)
            self.assertEqual((metrics["end_to_end_recall"]["numerator"], metrics["end_to_end_recall"]["denominator"]), (1, 2))
            self.assertEqual(metrics["true_negatives"], 1)
            self.assertEqual([r["truth_reason"] for r in rep["coverage"]["cases"]],
                             ["matches_signed_target", "differs_from_signed_target", "incomplete_file",
                              "target_not_in_top_level", "matches_signed_target", "outside_publisher_task"])
            rejected = run(full + [*flags[:1], "0" * 64, *flags[2:]], 1)
            self.assertEqual(rejected["adjudicated_per_planned_case"]["numerator"], 0)
            self.assertEqual(len(rejected["coverage"]["cases"]), 6)
            self.assertEqual(run(full + flags[:2], 2), b"")
            no_backend = subprocess.run([sys.executable, "-S", "-B", CLI, *full, *flags], capture_output=True, timeout=30)
            self.assertEqual((no_backend.returncode, no_backend.stdout), (2, b""))
            self.assertIn(b"requirements-publisher-truth", no_backend.stderr)
            self.assertEqual(run(full + [*flags[:3], "20240231T000000Z"], 2), b"")
            path = full[1]
            before = sha(path.read_bytes())
            with path.open("ab") as output:
                collision = subprocess.run([sys.executable, "-B", CLI, *full, *flags, "--help"], stdout=output,
                                           stderr=output, timeout=30)
            self.assertEqual((collision.returncode, sha(path.read_bytes())), (2, before))
            self.assertEqual(run(full + flags + ["--get-original", ref, "--destination", directory / "out"], 2), b"")
            partial = run(replay((binary, sha(SOURCE))) + flags, 0)
            self.assertEqual(partial["adjudicated_per_planned_case"]["numerator"], 1)
            self.assertEqual(partial["assessments_with_originals_per_planned_case"]["numerator"], 0)
            without_ref = run(replay((ref,)) + flags, 0)
            self.assertEqual(without_ref["publisher_references"][0]["status"], "reference_missing")

            next_repo = Repository()
            next_root = successor(self.repo, next_repo, 2)
            rotated = keep(history_bundle(next_repo.files(), files["root"], [next_root]))
            mixed = [dict(case, truth_ref_sha256=rotated) if case["id"] == "match" else case for case in cases]
            new_plan = raw(dict(json.loads(plan), cases=mixed))
            new_results = raw(dict(json.loads(results), corpus_sha256=sha(new_plan)))
            path = directory / "rotation.knbench"
            receipt = archive.seal(path, new_plan, new_results, inputs.values(), set(inputs))
            command = ["--archive-corpus", path, "--sha256", receipt["package_sha256"], "--plan-sha256", sha(new_plan)]
            self.assertEqual(run(command + flags, 0)["adjudicated_per_planned_case"]["numerator"], 3)
            filtered = run(command + flags + ["--minimum-root-version", "2"], 1)
            by_ref = {r["truth_ref_sha256"]: r for r in filtered["publisher_references"]}
            self.assertEqual(by_ref[ref]["status"], "root_version_below_minimum")
            self.assertEqual(by_ref[rotated]["root_rotation"]["last_root_sha256"], sha(next_root))
            self.assertEqual(filtered["minimum_root_version"], 2)
            ratio = filtered["adjudicated_per_planned_case"]
            self.assertEqual((ratio["numerator"], ratio["denominator"]), (1, len(cases)))
            self.assertEqual(run(command + flags + ["--minimum-root-version", "0"], 2), b"")
            self.assertEqual(run(command + ["--minimum-root-version", "2"], 2), b"")

            top = role_body(self.repo, {}, [delegation(self.repo, "release", ["file.bin"]),
                                            delegation(self.repo, "absent", ["other"])])
            leaf = self.repo.sign("timestamp", role_body(self.repo, self.repo.base["targets"]["targets"]))
            delegated = keep(delegated_release(self.repo, top, {"release": leaf}))
            new_plan = raw(dict(json.loads(plan), cases=[dict(c, truth_ref_sha256=delegated) for c in cases]))
            new_results = raw(dict(json.loads(results), corpus_sha256=sha(new_plan)))
            path = directory / "delegations.knbench"
            members = set(inputs) - {ref, rotated}
            receipt = archive.seal(path, new_plan, new_results, [inputs[k] for k in sorted(members)], members)
            report = run(["--archive-corpus", path, "--sha256", receipt["package_sha256"],
                          "--plan-sha256", sha(new_plan), *flags], 1)
            self.assertEqual(report["schema"], "kn.benchmark_publisher_report.v2")
            self.assertEqual(report["adjudicated_per_planned_case"], corpus.ratio(3, len(cases)))
            by_case = {c["case_id"]: c for c in report["coverage"]["cases"]}
            self.assertEqual([by_case[k]["publisher_truth"] for k in ("match", "different", "holes")],
                             ["positive", "negative", "unknown"])
            self.assertEqual(by_case["unlisted"]["truth_reason"], "delegated_metadata_missing")
            self.assertEqual(by_case["match"]["delegation_search"]["target_role"], "release")
            self.assertEqual(len(report["publisher_references"][0]["delegated_role_checks"]), 2)

            previous = history.Observation("20240101T000000Z", inputs[delegated].read_bytes())
            current = history.Observation("20240201T000000Z", inputs[delegated].read_bytes())
            framed = keep(history.pack(previous, current))
            mixed = [dict(c, truth_ref_sha256=framed) if c["id"] == "match" else c for c in cases]
            new_plan = raw(dict(json.loads(plan), cases=mixed))
            new_results = raw(dict(json.loads(results), corpus_sha256=sha(new_plan)))
            members = set(inputs) - {rotated, delegated}
            path = directory / "observations.knbench"
            receipt = archive.seal(path, new_plan, new_results, [inputs[k] for k in sorted(members)], members)
            command = ["--archive-corpus", path, "--sha256", receipt["package_sha256"], "--plan-sha256", sha(new_plan)]
            checkpoint = previous.checkpoint(sha(files["root"]))
            report = run(command + flags + ["--previous-checkpoint-sha256", checkpoint], 1)
            self.assertEqual((report["schema"], report["previous_checkpoint_sha256"]), ("kn.benchmark_publisher_report.v3", checkpoint))
            proofs = {r["truth_ref_sha256"]: r for r in report["publisher_references"]}
            self.assertEqual(proofs[ref]["status"], "publisher_history_required")
            self.assertEqual(proofs[framed]["publisher_history"]["transition"], "unchanged")
            self.assertEqual(report["adjudicated_per_planned_case"], corpus.ratio(1, len(cases)))
            self.assertEqual(run(command + ["--previous-checkpoint-sha256", checkpoint], 2), b"")
            self.assertEqual(run(command + flags + ["--previous-checkpoint-sha256", "invalid"], 2), b"")

    def test_changed_original_is_an_archive_failure(self):
        with self.assertRaisesRegex(ValueError, "changed"):
            publisher.read_small(io.BytesIO(b"modified"), {"a": (0, 8)}, "a", 8)

    def test_all_registered_families_fit_with_long_target_names(self):
        files = self.repo.files()
        proof = bundle(files)
        scope = raw(dict(schema="kn.benchmark_target_scope.v1", target_path=chr(233) * 256, file_bytes=len(SOURCE), missing=[]))
        case = dict(partition="development", layer="synthetic", task=publisher.TASK, unit="case", independence_group="one",
                    artifact_sha256=sha(SOURCE), holes_sha256=sha(scope), truth="unknown", truth_ref_sha256=sha(proof))
        cases = [dict(case, id="i" * 120 + str(i), family="f" * 120 + str(i)) for i in range(corpus.MAX_CASES)]
        plan = raw(dict(schema="kn.benchmark_corpus.v1", corpus_id="long", cohort_id="test", cases=cases,
                        environment=dict(target_id="test", snapshot_id="test", os_build=None, architecture="unknown",
                                         hvci=None, vbs=None, verifier=None)))
        results = raw(dict(schema="kn.benchmark_results.v1", corpus_sha256=sha(plan), run_id="test", assessments=[],
                           tool=dict(name="test", version="1", binary_sha256=sha(b"x"), config_sha256=sha(b"y"))))
        with tempfile.TemporaryDirectory(prefix="kn-publisher-capacity-") as tmp:
            directory = Path(tmp)
            inputs = {}
            for data in (SOURCE, proof, scope):
                pin = sha(data)
                inputs[pin] = directory / pin
                inputs[pin].write_bytes(data)
            path = directory / "full.knbench"
            receipt = archive.seal(path, plan, results, inputs.values(), set(inputs))
            p = subprocess.run([sys.executable, "-B", CLI, "--archive-corpus", path, "--sha256", receipt["package_sha256"],
                                "--plan-sha256", sha(plan), "--trusted-root-sha256", sha(files["root"]),
                                "--verification-time", "20240201T000000Z"], capture_output=True, timeout=90)
            self.assertEqual(p.returncode, 0, p.stderr)
            report = json.loads(p.stdout)
            self.assertEqual(len(report["scopes"][0]["families"]), corpus.MAX_CASES)
            self.assertEqual(report["adjudicated_per_planned_case"]["denominator"], corpus.MAX_CASES)
            self.assertEqual(report["coverage"]["cases"][-1]["target_path"], chr(233) * 256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
