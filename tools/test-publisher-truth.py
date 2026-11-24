"""Offline publisher-verification controls. Run with the optional publisher requirements."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import publisher_truth as publisher
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
