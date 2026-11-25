"""Exercise offline provisioning with a test publisher, optionally replaying retained native cases."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from approval_archive_oracle import verify_archived_approval


TOOLS = Path(__file__).resolve().parent
CLI = TOOLS / "provision-image-approval.py"
P = runpy.run_path(str(CLI))
T = runpy.run_path(str(TOOLS / "test-publisher-truth.py"))
raw, sha = T["raw"], T["sha"]
NAME = "approval/windows/policy.json"
AT = "20240201T000000Z"
AT_TICKS = 133512192000000000  # 2024-02-01 UTC in Windows FILETIME.
FUTURE = "18446744073709551615"
native_exe, native_cases = None, []
test_archive_efs = False
embedded_sample, catalog_sample, signed_native_cases = None, None, []


class ApprovalFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository = T["Repository"]()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.env = self.root / "publisher.json"
        self.source = self.root / "published policy.knapproval"
        self.change = self.root / "변경.knchange"
        self.image = self.root / "original.knblob"
        self.out = self.root / "selected.knapproval"
        self.image.write_bytes(b"retained reference bytes")
        self.manifest = dict(schema="kn.authorized_image_changes.v1", image_sha256=sha(self.image.read_bytes()),
                             issuer="운영팀", policy_epoch="3", not_before_filetime="1", not_after_filetime=FUTURE,
                             comparison_policy="kn.executable_page.direct.v1", hash_basis="non_fixup_compared_bytes.v1",
                             changes=[dict(rva="123", length="1", before_sha256=sha(b"a"), after_sha256=sha(b"b"))])
        self.change.write_bytes(raw(self.manifest))
        self.selected = dict(issuer=self.manifest["issuer"], image_sha256=self.manifest["image_sha256"],
                             manifest_sha256=sha(self.change.read_bytes()))
        other = dict(self.selected, manifest_sha256=sha(b"another manifest"))
        self.policy = dict(schema="kn.image_approval_policy.v1", policy_id="test publisher", policy_epoch="3",
                           not_before_filetime="2", not_after_filetime=FUTURE, approvals=[other, self.selected])
        self.sign(raw(self.policy))

    def sign(self, source, descriptor=None, roles=None):
        self.source.write_bytes(source)
        hashes = {"sha256": sha(source), "sha512": hashlib.sha512(source).hexdigest()}
        entry = descriptor if descriptor is not None else dict(length=len(source), hashes=hashes)
        overrides = {"targets": {"targets": {NAME: entry}}}
        for role, changes in (roles or {}).items():
            overrides.setdefault(role, {}).update(changes)
        files = self.repository.files(overrides)
        self.env.write_bytes(T["bundle"](files))
        self.root_pin = sha(files["root"])

    def command(self, require_windows_publisher=False, **overrides):
        args = dict(publisher_reference=self.env, trusted_root_sha256=self.root_pin, verification_time=AT,
                    policy_target=NAME, policy=self.source, manifest=self.change, reference=self.image, out=self.out)
        args.update(overrides)
        command = [sys.executable, "-B", str(CLI), *["--" + k.replace("_", "-") + "=" + str(v) for k, v in args.items()]]
        return command + (["--require-windows-publisher"] if require_windows_publisher else [])

    def call(self, code, *, version=1, **overrides):
        result = subprocess.run(self.command(**overrides), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, code, (result.stdout, result.stderr))
        if code == 2:
            return
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["schema"], f"kn.image_approval_provision.v{version}")
        if code == 1:
            self.assertEqual(receipt["status"], "rejected")
            self.assertIsNone(receipt["native_policy_sha256"])
            self.assertFalse(Path(overrides.get("out", self.out)).exists())
        else:
            self.assertEqual(receipt["status"], "provisioned")
            self.assertEqual(receipt["native_policy_sha256"], sha(Path(overrides.get("out", self.out)).read_bytes()))
            self.provision_bytes = result.stdout
        return receipt

class ApprovalTests(ApprovalFixture):
    def delegate_policy(self, expiry, earlier):
        repo = self.repository
        source = self.source.read_bytes()
        rules = [T["delegation"](repo, name, ["approval/windows/*"]) for name in ("first", "release")]
        top = T["role_body"](repo, {}, rules, expires=expiry)
        leaf = T["role_body"](repo, {NAME: dict(length=len(source), hashes=dict(sha256=sha(source)))}, expires=expiry)
        roles = dict(first=repo.sign("timestamp", T["role_body"](repo, {}, expires=earlier)),
                     release=repo.sign("timestamp", leaf))
        self.env.write_bytes(T["delegated_release"](repo, top, roles, expires=expiry))
        self.root_pin = sha(repo.files({"root": {"expires": expiry}})["root"])

    def test_delegated_approval_uses_all_consulted_expiries(self):
        self.delegate_policy("2024-08-01T00:00:00Z", "2024-03-01T00:00:00Z")
        receipt = self.call(0, out=self.root / "accepted.knapproval")
        self.assertEqual(receipt["policy_target_comparison"]["delegation_search"],
                         dict(status="found", target_role="release", role_check_indices=[0, 1]))
        self.assertEqual([row["delegated_role"] for row in receipt["publisher_proof"]["delegated_role_checks"]],
                         ["first", "release"])
        self.assertEqual(int(receipt["not_after_filetime"]), P["filetime"](datetime(2024, 3, 1, tzinfo=timezone.utc)))
        denied = self.call(1, verification_time="20240301T000000Z")
        self.assertEqual(denied["reason"], "expired_metadata")
        self.assertEqual(denied["policy_target_comparison"]["delegation_search"]["failed_role"], "first")
        self.assertEqual(self.call(1, policy_target="outside/sub/policy.json")["reason"], "target_not_in_authorized_roles")

    def test_delegated_native_archive(self):
        if not native_cases:
            self.skipTest("supply a retained native case for delegated policy archive replay")
        capture, manifest, reference = native_cases[0]
        change = json.loads(manifest.read_bytes())
        row = dict(image_sha256=sha(reference.read_bytes()), manifest_sha256=sha(manifest.read_bytes()),
                   issuer=change["issuer"])
        self.source.write_bytes(raw(dict(self.policy, approvals=[row], policy_epoch=change["policy_epoch"])))
        now = datetime.now(timezone.utc)
        self.delegate_policy((now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                             (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        at = now.strftime("%Y%m%dT%H%M%SZ")
        self.call(0, manifest=manifest, reference=reference, verification_time=at)
        verify_archived_approval(native_exe, capture, manifest, self.out, self.env, self.source, self.provision_bytes,
                                 self.root_pin, NAME, at)

    def test_provision_with_rotated_approval_authority(self):
        replacement = T["Repository"]()
        anchor = self.repository.files({"root": {"expires": "2023-01-01T00:00:00Z"}})["root"]
        update = T["successor"](self.repository, replacement, 2, expires="2024-03-01T00:00:00Z")
        source = self.source.read_bytes()
        descriptor = dict(length=len(source), hashes=dict(sha256=sha(source)))
        files = replacement.files({"targets": {"targets": {NAME: descriptor}}})
        self.env.write_bytes(T["history_bundle"](files, anchor, [update]))
        self.root_pin = sha(anchor)
        accepted = self.call(0, out=self.root / "rotated.knapproval", minimum_root_version=2)
        self.assertEqual(accepted["publisher_proof"]["root_rotation"]["last_root_sha256"], sha(update))
        cutoff = P["filetime"](datetime(2024, 3, 1, tzinfo=timezone.utc))
        self.assertEqual(accepted["not_after_filetime"], str(cutoff))
        self.assertEqual(self.call(1, minimum_root_version=3)["reason"], "root_version_below_minimum")
        self.assertEqual(self.call(1, trusted_root_sha256=sha(update))["reason"], "untrusted_root")
        self.call(2, minimum_root_version="01")
        self.env.write_bytes(T["history_bundle"](files, anchor, [replacement.sign("root", json.loads(update)["signed"])]))
        self.assertEqual(self.call(1)["reason"], "previous_root_threshold_failed")

    def test_projection_and_preservation(self):
        frozen = {p: p.read_bytes() for p in (self.source, self.change, self.image, self.env)}
        receipt = self.call(0)
        projected = json.loads(self.out.read_bytes())
        self.assertEqual(projected, dict(self.policy, approvals=[self.selected], not_after_filetime="133801632000000000"))
        self.assertEqual(receipt["publisher_reference_sha256"], sha(frozen[self.env]))
        self.assertEqual(receipt["source_policy_sha256"], sha(frozen[self.source]))
        self.assertNotEqual(receipt["native_policy_sha256"], receipt["source_policy_sha256"])
        self.assertEqual(receipt["source_approval_count"], 2)
        self.assertEqual(receipt["policy_target_comparison"]["signed_hashes"]["sha512"],
                         hashlib.sha512(frozen[self.source]).hexdigest())
        another = self.root / "second.knapproval"
        self.call(0, out=another)
        self.assertEqual(self.out.read_bytes(), another.read_bytes())
        self.assertEqual(frozen, {p: p.read_bytes() for p in frozen})

    def test_trust_chain_and_target(self):
        data = self.source.read_bytes()
        self.assertEqual(self.call(1, trusted_root_sha256="0" * 64)["reason"], "untrusted_root")
        self.assertEqual(self.call(1, policy_target="another/policy")["reason"], "target_not_in_top_level")
        self.source.write_bytes(data + b"\n")
        self.assertEqual(self.call(1)["reason"], "differs_from_signed_target")
        self.sign(data, dict(length=len(data), hashes=dict(sha256=sha(data), sha512="0" * 128)))
        self.assertEqual(self.call(1)["reason"], "differs_from_signed_target")
        self.sign(data, dict(length=len(data), hashes=dict(sha1=hashlib.sha1(data).hexdigest())))
        self.assertEqual(self.call(1)["reason"], "unsupported_target_descriptor")
        self.sign(data, dict(length=len(data), hashes=dict(sha512=hashlib.sha512(data).hexdigest())))
        self.call(0)

    def test_half_open_validity(self):
        for role in ("root", "timestamp", "snapshot", "targets"):
            with self.subTest(role=role):
                self.sign(raw(self.policy), roles={role: dict(expires="2024-02-01T00:00:01Z")})
                self.assertEqual(self.call(0, out=self.root / role)["not_after_filetime"], str(AT_TICKS + 10_000_000))
                receipt = self.call(1, verification_time="20240201T000001Z")
                self.assertEqual((receipt["reason"], receipt["publisher_proof"]["failed_role"]), ("expired_metadata", role))
        manifest = dict(self.manifest, not_before_filetime=str(AT_TICKS), not_after_filetime=str(AT_TICKS + 1))
        self.change.write_bytes(raw(manifest))
        row = dict(self.selected, manifest_sha256=sha(self.change.read_bytes()))
        self.sign(raw(dict(self.policy, approvals=[row])))
        receipt = self.call(0, out=self.root / "one-tick")
        self.assertEqual((receipt["not_before_filetime"], receipt["not_after_filetime"]), (str(AT_TICKS), str(AT_TICKS + 1)))
        self.assertEqual(self.call(1, verification_time="20240131T235959Z")["reason"], "outside_approval_window")
        self.assertEqual(self.call(1, verification_time="20240201T000001Z")["reason"], "outside_approval_window")
        self.sign(raw(dict(self.policy, approvals=[row], not_after_filetime=str(AT_TICKS))))
        self.assertEqual(self.call(1)["reason"], "outside_approval_window")
        self.sign(raw(dict(self.policy, approvals=[row], not_before_filetime=str(AT_TICKS + 1))))
        self.assertEqual(self.call(1)["reason"], "outside_approval_window")

    def test_manifest_image_and_signed_row(self):
        image = self.image.read_bytes()
        self.image.write_bytes(image + b"!")
        self.assertEqual(self.call(1)["reason"], "reference_mismatch")
        self.image.write_bytes(image)
        self.change.write_bytes(self.change.read_bytes() + b"\n")
        self.assertEqual(self.call(1)["reason"], "approval_tuple_missing")
        self.change.write_bytes(raw(self.manifest))
        for row in (dict(self.selected, issuer="different"), dict(self.selected, image_sha256=sha(b"other"))):
            self.sign(raw(dict(self.policy, approvals=[row])))
            self.assertEqual(self.call(1)["reason"], "approval_tuple_missing")
        self.sign(raw(dict(self.policy, policy_epoch="4")))
        self.assertEqual(self.call(1)["reason"], "epoch_mismatch")

    def test_invalid_signed_policy_cannot_be_projected(self):
        other = self.policy["approvals"][0]
        for row in (self.selected, dict(other, issuer="bad\x7f"), dict(other, issuer="\U0001f680" * 65),
                    dict(other, extra=True), dict(other, manifest_sha256=sha(b"row").upper())):
            self.sign(raw(dict(self.policy, approvals=[row, self.selected])))
            self.assertEqual(self.call(1)["reason"], "invalid_source_policy")
        for changes in (dict(approvals=[]), dict(policy_epoch="03"), dict(not_after_filetime=str(1 << 64)),
                        dict(schema="kn.another.v1"), dict(policy_id=""), dict(extra=0)):
            with self.assertRaises(P["Denied"]):
                P["parse_policy"](raw(dict(self.policy, **changes)))
        # A signed duplicate member must not acquire validity through JSON normalization.
        self.sign(raw(self.policy).replace(b'"policy_epoch":', b'"policy_epoch":"3","policy_epoch":'))
        self.assertEqual(self.call(1)["reason"], "invalid_source_policy")
        full = [dict(other, manifest_sha256=sha(str(i).encode())) for i in range(128)]
        P["parse_policy"](raw(dict(self.policy, approvals=full, policy_id="\U0001f680" * 64)))
        with self.assertRaises(P["Denied"]):
            P["parse_policy"](raw(dict(self.policy, approvals=full + [self.selected])))

    def test_native_change_grammar_before_issuance(self):
        row = self.manifest["changes"][0]
        for change in (dict(changes=[]), dict(changes=[row, row]), dict(changes=[dict(row, rva="01")]),
                       dict(changes=[dict(row, after_sha256=row["before_sha256"])]),
                       dict(changes=[dict(row, length="4097")]), dict(changes=[dict(row, rva="4294967295")]),
                       dict(changes=[dict(row, length="0")]), dict(comparison_policy=[]), dict(hash_basis="another"),
                       dict(policy_epoch=3), dict(issuer="\0"), dict(extra="ignored")):
            with self.subTest(change=change), self.assertRaises(P["Denied"]):
                P["parse_manifest"](raw(dict(self.manifest, **change)))
        manifest = dict(self.manifest, changes=[dict(row, rva="4294967295")])
        self.change.write_bytes(raw(manifest))
        self.sign(raw(dict(self.policy, approvals=[dict(self.selected, manifest_sha256=sha(self.change.read_bytes()))])))
        self.assertEqual(self.call(1)["reason"], "invalid_change_manifest")
        limits = [dict(row, rva=str(4096 * i), length="4096") for i in range(127)] + [dict(row, rva="4294967294")]
        P["parse_manifest"](raw(dict(self.manifest, changes=limits)))

    def test_io_limits_destinations_and_arguments(self):
        source_bytes = self.source.read_bytes()
        self.call(2, out=self.source)
        self.assertEqual(self.source.read_bytes(), source_bytes)
        self.call(2, out=self.root / "missing" / "policy")
        for options in (dict(verification_time="20240230T000000Z"), dict(verification_time="15990101T000000Z"),
                        dict(policy_target="../bad"), dict(trusted_root_sha256="invalid"), dict(reference=self.root)):
            self.call(2, **options)
        with self.image.open("wb") as target:
            target.truncate((64 << 20) + 1)
        self.call(2)
        self.source.write_bytes(b" " * ((64 << 10) + 1))
        self.call(2)
        self.assertFalse(self.out.exists())
        self.assertFalse(list(self.root.glob(".knbench-*")))

    def test_full_native_byte_limits(self):
        with self.image.open("wb") as stream:
            stream.truncate(64 << 20)
        with self.image.open("rb") as stream:
            pin = hashlib.file_digest(stream, "sha256").hexdigest()
        self.change.write_bytes(raw(dict(self.manifest, image_sha256=pin)).ljust(64 << 10, b" "))
        row = dict(self.selected, image_sha256=pin, manifest_sha256=sha(self.change.read_bytes()))
        self.sign(raw(dict(self.policy, approvals=[row])).ljust(64 << 10, b" "))
        receipt = self.call(0)
        self.assertEqual((receipt["reference_bytes"], receipt["policy_target_comparison"]["signed_length"]),
                         (64 << 20, 64 << 10))

    def test_optional_dependencies(self):
        cmd = self.command()
        cmd.insert(1, "-S")  # No third-party packages, including the TUF verifier.
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"requirements-publisher-truth.txt", result.stderr)
        self.assertFalse(self.out.exists())

    def test_help_and_error_cannot_append_to_inputs(self):
        for flag, path in (("--manifest", self.change), ("--out", self.source), ("--reference", self.image),
                           ("--policy", self.source), ("--publisher-reference", self.env)):
            contents = path.read_bytes()
            alias = self.root / "output-alias"
            os.link(path, alias)
            try:
                for args in ([flag, str(path)], [flag + "=" + str(path)]):
                    for early in ("--help", "--bad-option"):
                        with alias.open("ab") as stream:
                            result = subprocess.run([sys.executable, "-B", str(CLI), early, *args],
                                                    stdout=stream, stderr=stream, timeout=30)
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(path.read_bytes(), contents)
            finally:
                alias.unlink()

    def test_competing_new_outputs(self):
        jobs = [subprocess.Popen(self.command(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        outcomes = [(p.communicate(timeout=30)[0], p.returncode) for p in jobs]
        self.assertEqual(sorted(code for _, code in outcomes), [0, 2])
        receipt = json.loads(next(data for data, code in outcomes if code == 0))
        self.assertEqual(sha(self.out.read_bytes()), receipt["native_policy_sha256"])
        self.assertFalse(list(self.root.glob(".knbench-*")))

    def test_receipt_delivery_failure_preserves_the_sealed_policy(self):
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            run = subprocess.run(self.command(), stdout=write_end, stderr=subprocess.PIPE, timeout=30)
        finally:
            os.close(write_end)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertEqual(json.loads(self.out.read_bytes())["approvals"], [self.selected])
        self.call(2)

    def test_native_assess_image(self):
        if not native_cases:
            self.skipTest("supply --native-exe and --native-case CAPTURE MANIFEST REFERENCE for retained PE replay")
        rows = []
        for _, manifest, reference in native_cases:
            data = manifest.read_bytes()
            entry = json.loads(data)
            rows.append(dict(issuer=entry["issuer"], image_sha256=sha(reference.read_bytes()), manifest_sha256=sha(data)))
        now = datetime.now(timezone.utc)
        expiry = (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        epoch = json.loads(native_cases[0][1].read_bytes())["policy_epoch"]
        self.sign(raw(dict(self.policy, policy_epoch=epoch, approvals=rows)),
                  roles={k: dict(expires=expiry) for k in self.repository.base})
        for i, (capture, change, reference) in enumerate(native_cases):
            out = self.root / f"native-{i}.knapproval"
            receipt = self.call(0, manifest=change, reference=reference, out=out, verification_time=now.strftime("%Y%m%dT%H%M%SZ"))
            def assess(selected, manifest):
                return subprocess.run([str(native_exe), "--offline", "!kmon", "assess-image", str(selected), str(manifest),
                                       str(out), receipt["native_policy_sha256"], "/json"], capture_output=True, timeout=60)
            result = assess(capture, change)
            self.assertEqual(result.returncode, 0, result.stdout[:1800])
            report = json.loads(result.stdout)
            self.assertTrue(report["reference_approved"])
            self.assertGreater(int(report["authorized_changed_bytes"]), 0)
            self.assertFalse(report["issuer_signature_verified"])
            archive_case = (native_exe, capture, change, out, self.env, self.source, self.provision_bytes,
                            self.root_pin, NAME, now.strftime("%Y%m%dT%H%M%SZ"))
            verify_archived_approval(*archive_case, exercise_failures=(i == 0))
            if i == 0 and test_archive_efs:
                verify_archived_approval(*archive_case, require_efs=True)
            for other, other_change, _ in native_cases:
                if change != other_change:
                    result = assess(other, other_change)
                    self.assertEqual(result.returncode, 1, result.stdout[:1800])
                    self.assertFalse(json.loads(result.stdout)["reference_approved"])


class WindowsApprovalTests(ApprovalFixture):
    def policy_for(self, signature, *, manifest=None, current=True):
        pin = sha(self.image.read_bytes())
        if manifest is None:
            self.change.write_bytes(raw(dict(self.manifest, image_sha256=pin)))
        else:
            self.change.write_bytes(manifest.read_bytes())
        definition = json.loads(self.change.read_bytes())
        self.assertEqual(definition["image_sha256"], pin)
        row = dict(image_sha256=pin, manifest_sha256=sha(self.change.read_bytes()), issuer=definition["issuer"],
                   reference_signature=signature)
        source = dict(self.policy, schema="kn.image_approval_policy.v2", policy_epoch=definition["policy_epoch"], approvals=[row])
        now = datetime.now(timezone.utc)
        expiry = (now + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.sign(raw(source), roles={k: dict(expires=expiry) for k in self.repository.base} if current else None)
        return dict(version=2, verification_time=now.strftime("%Y%m%dT%H%M%SZ") if current else AT,
                    require_windows_publisher=True)

    def sample(self, kind):
        sample = embedded_sample if kind == "embedded" else catalog_sample
        if sample is None or os.name != "nt":
            self.skipTest(f"supply a retained Windows {kind} fixture and independent signer pin")
        shutil.copyfile(sample[0], self.image)
        policy = dict(kind=kind, revocation="none", signer_certificate_sha256=sample[-1])
        options = {}
        if kind == "catalog":
            catalog = self.root / "retained.cat"
            shutil.copyfile(sample[1], catalog)
            policy["catalog_sha256"] = sha(catalog.read_bytes())
            options["catalog"] = catalog
        return policy, options

    def test_required_policy_and_invalid_unselected_signature(self):
        self.assertEqual(self.call(1, require_windows_publisher=True)["reason"], "windows_publisher_policy_required")
        self.assertEqual(self.call(1, catalog=self.env)["reason"], "unexpected_catalog")
        signature = dict(kind="embedded", revocation="none", signer_certificate_sha256=sha(b"cert"))
        signed = dict(self.selected, reference_signature=signature)
        for invalid in (None, {}, dict(signature, kind="other"), dict(signature, path="file"),
                        dict(signature, signer_certificate_sha256="bad"), dict(signature, revocation="allow_unknown"),
                        dict(signature, kind="catalog"), dict(signature, catalog_sha256=sha(b"catalog"))):
            other = dict(self.policy["approvals"][0], reference_signature=invalid)
            self.sign(raw(dict(self.policy, schema="kn.image_approval_policy.v2", approvals=[other, signed])))
            self.assertEqual(self.call(1)["reason"], "invalid_source_policy")
        self.sign(raw(dict(self.policy, approvals=[signed])))
        self.assertEqual(self.call(1)["reason"], "invalid_source_policy")

    def test_embedded_publisher_and_wrong_verified_signer(self):
        policy, _ = self.sample("embedded")
        args = self.policy_for(policy)
        receipt = self.call(0, out=self.root / "good.knapproval", **args)
        sig = receipt["windows_publisher"]
        self.assertEqual((sig["status"], sig["wintrust_status"], sig["signer_certificate_sha256"]),
                         ("verified", "0x00000000", embedded_sample[-1]))
        self.assertEqual(receipt["reference_sha256"], sha(self.image.read_bytes()))
        self.assertEqual(self.call(1, catalog=self.env, **args)["reason"], "unexpected_catalog")
        args = self.policy_for(dict(policy, signer_certificate_sha256=sha(b"unrelated signer")))
        denied = self.call(1, **args)
        self.assertEqual(denied["reason"], "signer_certificate_mismatch")
        self.assertEqual(denied["windows_publisher"]["signer_certificate_sha256"], embedded_sample[-1])

    def test_catalog_requires_the_exact_catalog_member_and_signer(self):
        policy, opts = self.sample("catalog")
        args = self.policy_for(policy)
        receipt = self.call(0, out=self.root / "accepted", **opts, **args)
        sig = receipt["windows_publisher"]
        self.assertEqual((sig["catalog_sha256"], sig["signer_certificate_sha256"]), (policy["catalog_sha256"], catalog_sample[-1]))
        self.assertEqual(len(sig["catalog_member_sha256"]), 64)
        self.assertEqual(self.call(1, **args)["reason"], "catalog_required")
        self.assertEqual(self.call(1, **self.policy_for(dict(policy, catalog_sha256=sha(b"other"))), **opts)["reason"],
                         "catalog_digest_mismatch")
        self.assertEqual(self.call(1, **self.policy_for(dict(policy, signer_certificate_sha256=sha(b"unknown"))), **opts)["reason"],
                         "signer_certificate_mismatch")
        if embedded_sample:
            shutil.copyfile(embedded_sample[0], self.image)
            self.assertEqual(self.call(1, **self.policy_for(policy), **opts)["reason"], "wintrust_rejected")

    def test_retained_file_must_pass_both_whole_file_and_windows_checks(self):
        policy, _ = self.sample("embedded")
        args = self.policy_for(policy)
        with self.image.open("r+b") as stream:
            stream.truncate(self.image.stat().st_size // 2)
        self.assertEqual(self.call(1, **args)["reason"], "reference_mismatch")
        self.assertEqual(self.call(1, **self.policy_for(policy))["reason"], "wintrust_rejected")
        self.image.write_bytes(b"ordinary signed-policy target")
        self.assertEqual(self.call(1, **self.policy_for(policy))["reason"], "invalid_pe_reference")

    def test_windows_host_time_and_signed_revocation_policy(self):
        policy, _ = self.sample("embedded")
        self.assertEqual(self.call(1, **self.policy_for(policy, current=False))["reason"], "outside_windows_verification_window")
        policy["revocation"] = "cached_chain"
        options = self.policy_for(policy)
        options.pop("version")
        run = subprocess.run(self.command(**options), capture_output=True, timeout=30)
        receipt = json.loads(run.stdout)
        sig = receipt["windows_publisher"]
        self.assertEqual(sig["signature_policy"]["revocation"], "cached_chain")
        if sig["wintrust_status"] == "0x00000000":
            self.assertEqual(run.returncode, 0)
            self.assertEqual(sig["signer_certificate_sha256"], embedded_sample[-1])
        else:
            self.assertEqual((run.returncode, receipt["reason"]), (1, "wintrust_rejected"))
            self.assertFalse(self.out.exists())

    def test_files_and_ancestors_remain_leased_during_windows_verification(self):
        import windows_pe_trust as win
        policy, opts = self.sample("catalog")
        real_verify = win.WinTrust.verify_signature
        entered = []
        def observe(trust, info, embedded, revocation, proof):
            for file in (self.image, opts["catalog"]):
                with self.assertRaises(PermissionError):
                    with file.open("r+b"):
                        pass
                with self.assertRaises(PermissionError):
                    file.rename(file.with_suffix(".replaced"))
            with self.assertRaises(PermissionError):
                self.root.rename(self.root.with_name(self.root.name + "-renamed"))
            entered.append(True)
            return real_verify(trust, info, embedded, revocation, proof)
        with mock.patch.object(win.WinTrust, "verify_signature", observe):
            proof = win.verify_reference(self.image, sha(self.image.read_bytes()), 64 << 20, opts["catalog"], policy)
        self.assertEqual((entered, proof["status"]), ([True], "verified"))
        with opts["catalog"].open("r+b"):
            self.assertEqual(self.call(1, **self.policy_for(policy), **opts)["reason"], "windows_signature_input_or_provider_unavailable")
        self.call(0, **self.policy_for(policy), **opts)

    def test_catalog_diagnostic_output_cannot_append_to_an_input(self):
        original = self.env.read_bytes()
        alias = self.root / "catalog-copy"
        os.link(self.env, alias)
        for opts in (["--catalog", str(alias)], ["--catalog=" + str(alias)]):
            with self.env.open("ab") as target:
                proc = subprocess.run([sys.executable, "-B", str(CLI), "--help", *opts], stdout=target, stderr=target, timeout=30)
            self.assertEqual((proc.returncode, self.env.read_bytes()), (2, original))

    def test_catalog_quota_and_platform(self):
        import windows_pe_trust as win
        with mock.patch.object(win.os, "name", "posix"):
            result = win.verify_reference(self.image, sha(b"file"), 16, None, {})
        self.assertEqual(result["status"], "windows_trust_unavailable")
        policy, opts = self.sample("catalog")
        with opts["catalog"].open("r+b") as stream:
            stream.truncate(win.CATALOG_LIMIT + 1)
        self.assertEqual(self.call(1, **self.policy_for(policy), **opts)["reason"], "signature_input_size_outside_limit")

    @unittest.skipUnless(os.name == "nt", "Windows trust provider")
    def test_revocation_failure_closes_provider_state_without_retry(self):
        import windows_pe_trust as win
        trust = win.WinTrust()
        for status in (1, -2146885613):  # Any nonzero LONG, including CRYPT_E_REVOCATION_OFFLINE.
            actions = []
            def refuse(_, __, pointer):
                data = win.c.cast(pointer, win.c.POINTER(win.TrustData)).contents
                actions.append(data.action)
                self.assertTrue(data.flags & win.WTD_CACHE_ONLY_URL_RETRIEVAL)
                self.assertTrue(data.flags & win.WTD_REVOCATION_CHECK_CHAIN)
                self.assertFalse(data.flags & win.WTD_REVOCATION_CHECK_NONE)
                if data.action == win.WTD_STATEACTION_VERIFY:
                    data.state = 17
                    return status
                return 0
            proof = {}
            with mock.patch.object(trust, "verify", refuse):
                result = trust.verify_signature(win.FileInfo(), True, "cached_chain", proof)
            self.assertEqual((result, actions), ("wintrust_rejected", [win.WTD_STATEACTION_VERIFY, win.WTD_STATEACTION_CLOSE]))
            self.assertEqual(proof["wintrust_status"], f"0x{status & 0xffffffff:08x}")
            self.assertNotIn("signer_certificate_sha256", proof)

    def test_native_replay_with_windows_publisher(self):
        if not signed_native_cases:
            self.skipTest("supply --windows-native-case KIND CAPTURE MANIFEST and matching publisher samples")
        for index, (kind, case, manifest) in enumerate(signed_native_cases):
            policy, opts = self.sample(kind)
            out = self.root / f"{kind}-{index}.knapproval"
            selection = self.policy_for(policy, manifest=Path(manifest))
            receipt = self.call(0, **opts, **selection, out=out)
            native = json.loads(out.read_bytes())
            self.assertEqual(native["schema"], "kn.image_approval_policy.v1")
            self.assertEqual(set(native["approvals"][0]), {"image_sha256", "manifest_sha256", "issuer"})
            run = subprocess.run([str(native_exe), "--offline", "!kmon", "assess-image", case, manifest, str(out),
                                  receipt["native_policy_sha256"], "/json"], capture_output=True, timeout=60)
            report = json.loads(run.stdout)
            self.assertEqual((run.returncode, report["reference_approved"], report["issuer_signature_verified"]), (0, True, False))
            self.assertEqual(report["decision"], "no_observed_change")
            verify_archived_approval(native_exe, Path(case), Path(manifest), out, self.env, self.source,
                                     self.provision_bytes, self.root_pin, NAME, selection["verification_time"],
                                     catalog=opts.get("catalog"))


if __name__ == "__main__":
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument("--native-exe", type=Path)
    options.add_argument("--native-case", type=Path, nargs=3, action="append", metavar=("CAPTURE", "MANIFEST", "REFERENCE"))
    options.add_argument("--archive-efs", action="store_true", help="also exercise real NTFS EFS with the first native case")
    options.add_argument("--windows-embedded", nargs=2, metavar=("PE", "SIGNER_SHA256"))
    options.add_argument("--windows-catalog", nargs=3, metavar=("PE", "CATALOG", "SIGNER_SHA256"))
    options.add_argument("--windows-native-case", nargs=3, action="append", metavar=("KIND", "CAPTURE", "MANIFEST"))
    args, remaining = options.parse_known_args()
    if bool(args.native_exe) != bool(args.native_case or args.windows_native_case):
        options.error("provide the native binary and at least one case together")
    if args.archive_efs and not args.native_case:
        options.error("--archive-efs requires a native case")
    for kind, _, _ in args.windows_native_case or []:
        if kind not in ("embedded", "catalog") or not getattr(args, "windows_" + kind):
            options.error("each Windows native case needs the corresponding embedded or catalog fixture")
    native_exe, native_cases = args.native_exe, args.native_case or []
    test_archive_efs = args.archive_efs
    embedded_sample, catalog_sample, signed_native_cases = args.windows_embedded, args.windows_catalog, args.windows_native_case or []
    unittest.main(argv=[sys.argv[0], *remaining])
