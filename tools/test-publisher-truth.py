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
