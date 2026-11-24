"""Regression tests for publication checks; all secret-shaped data is synthetic."""
import base64
from contextlib import closing
import importlib.util
import io
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("public_content", Path(__file__).with_name("validate-public-content.py"))
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class PublicContentTests(unittest.TestCase):
    def test_inventory_checkpoints_and_build_reports(self):
        for schema in AUDIT.INVENTORY_WORK_SCHEMAS:
            record = json.dumps(dict(offset="0", schema=schema))
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                for text in (record, "report\n" + record[:-1]):
                    self.assertTrue(AUDIT.inspect("renamed.txt", text.encode(encoding)), (schema, encoding))
            self.assertFalse(AUDIT.inspect("guide.md", ("The format is " + schema).encode()))
        for fields in (dict(source_id="a", output_id="b", catalog_sha256="c"),
                       dict(chunk_sha256="a", originals_sha256="b"), dict(reused_entries="1", verified_entries="0"),
                       dict(verified_through="5", verification_seal="00"), dict(verified_through="4", raw_witness_prefix=""),
                       dict(raw_witness_prefix="", verification_seal="00"), dict(unique_bundles="1", duplicate_case_files="1"),
                       dict(observed_canonical_bytes="100", byte_mismatch_collections="1")):
            self.assertTrue(AUDIT.inspect("fragment.txt", ("log\n" + json.dumps(fields)[:-1]).encode()))

    def test_release_path_rule_export(self):
        cli = [sys.executable, "-B", str(Path(AUDIT.__file__).resolve()), "--package-path-rules"]
        result = subprocess.run(cli, cwd=tempfile.gettempdir(), capture_output=True, check=True)
        rules = json.loads(result.stdout)
        self.assertEqual(rules["schema"], "kn.publication_path_rules.v1")
        directory, file = (re.compile(rules[key]) for key in ("directory", "file"))
        private = ["ops.knmcpjournal.tmp.42", "rows.ETL.ZIP", "logs", "notes/LOGS/t.txt",
                   r"attachments\.KNBENCH-ETL-one\event.xml", ".env.example.prod", "archive.kncampaign-wal",
                   "record.knjlock.pending-1", "record.knbench.pending-1", ".pem", "capture.kncase.pending-7.part",
                   ".env.example\n", ".knbench-first\nsecond.tmp"]
        private += ["record" + ext.upper() for ext in AUDIT.PRIVATE_EXTENSIONS]
        private += ["record" + ext + ".pending-9" for ext in AUDIT.PRIVATE_EXTENSIONS if ext.startswith(".kn")]
        public = ["x.env", "environments/README.md", "docs/.env.example", "source.kncapture.md",
                  "docs/.knbench-etl-readme.txt", "symbols-guide/note.txt", "docs/file [v2].txt"]
        for expected, paths in ((True, private), (False, public)):
            for path in paths:
                with self.subTest(path=path):
                    parts = path.replace("\\", "/").lower().split("/")
                    matched = any(directory.search(part) for part in parts[:-1]) or bool(file.search(parts[-1]))
                    self.assertEqual(matched, expected)
                    self.assertEqual(bool(AUDIT.path_rule(path)), expected)
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "report.json"
            for other in (["--root", temp], ["--index"], ["--tree"], ["--report", str(report)], ["--allow-private-symbols"]):
                denied = subprocess.run([*cli, *other], cwd=temp, capture_output=True)
                self.assertEqual(denied.returncode, 2)
            self.assertFalse(report.exists())

    def test_store_catalog_scan_exports(self):
        samples = [json.dumps(dict(schema="kn.store_catalog_scan.v1")), json.dumps(dict(namespace_sha256="x", namespace_entries="2")),
                   json.dumps(dict(next_scan_cursor="held", scan_receipt="")),
                   "kncs1.2." + "a" * 64 + "." + "b" * 64, "kncr1.2." + "c" * 39]
        for sample in samples:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                data = ("retained\n" + sample).encode(encoding)
                self.assertIn("private-evidence-bundle", {row["rule"] for row in AUDIT.inspect("export.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"Resume a kn.store_catalog_scan.v1 window with its cursor."))

    def test_process_image_source_receipts(self):
        samples = (dict(schema="kn.process_image_source.v1"), dict(schema="kn.image_source_replay.v1"),
                   dict(schema="kn.image_source_session.v1"), dict(schema="kn.image_source_collection.v1"),
                   dict(archived_attempts="1", archived_claims="0"), dict(report_committed=True, capture_status="failed"),
                   dict(committed_source_report_path="private"), dict(retained_collection_id="2", active_copies="3"),
                   dict(report_sha256="a" * 64, claim_file_sha256="b" * 64),
                   dict(requested_pid="1", requested_creation_filetime="3"),
                   dict(acquisition_id="2", parent_acquisition_id="1", requested_filetime="3"),
                   dict(pid="1", creation_filetime="3", win32_status="0"), dict(capture_status="failed", original_claim_matched=False))
        for sample in samples:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                data = json.dumps(sample).encode(encoding)
                self.assertIn("private-evidence-bundle", {row["rule"] for row in AUDIT.inspect("capture.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"Replay a saved kn.process_image_source.v1 receipt."))

    def test_image_iat_reference(self):
        records = (dict(schema="kn.image_iat_reference.v1"), dict(iat_slot_rva="8", instruction_hex="00"),
                   dict(import_lookup_rva="8", import_descriptor_rva="4"), dict(instruction_reread=False, byte_receipts=[]))
        for record in records:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("capture.txt", json.dumps(record).encode(encoding))})
        self.assertFalse(AUDIT.inspect("guide.md", b"Replay the kn.image_iat_reference.v1 record."))

    def test_minidump_iat_observation(self):
        for header in (b"MDMP", b"MDMP\x93", b"MDMP\x93\xa7", b"MDMP\x93\xa7" + bytes(26), b"MDMP" + bytes(28)):
            self.assertIn("private-user-minidump", {f["rule"] for f in AUDIT.inspect("copy.dat", header)})
        self.assertFalse(AUDIT.inspect("guide.md", b"MDMP identifies a user minidump."))
        records = (dict(schema="kn.minidump_iat_observation.v1"), dict(slot_value_sha256="a" * 64),
                   dict(slot_file_spans=[]), dict(instruction_file_spans=[]),
                   dict(module_list_index="2", basename="sample.dll", coff_timestamp="3"),
                   dict(expected_dump_sha256="a" * 64, expected_reference_sha256="b" * 64, export="Fixture"))
        for record in records:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                data = json.dumps(record).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("report.txt", data)})
        self.assertFalse(AUDIT.inspect("reference.md", b"Read the kn.minidump_iat_observation.v1 report."))

    def test_minidump_import_declaration(self):
        records = (dict(schema="kn.minidump_import_declaration.v1"), dict(declaration_fields=[]),
                   dict(declaration_spans=[]), dict(reference_field_sha256="a" * 64),
                   dict(field_offset="0", state="different", bytes="1"),
                   dict(reference_import_name="Sample", reference_module="owned.dll", reference_ordinal=None),
                   dict(different_bytes="1", excluded_bytes="0", read_error_bytes="0"))
        for record in records:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("excerpt.txt", json.dumps(record).encode(encoding))})
        self.assertFalse(AUDIT.inspect("guide.md", b"Compare a kn.minidump_import_declaration.v1 result."))

    def test_store_file_ranges_and_positions(self):
        samples = [json.dumps(dict(schema="kn.store_file_scan.v1")), json.dumps(dict(next_file_cursor="", file_receipt="held")),
                   json.dumps(dict(file_offset="0", block_sha256="held")), json.dumps(dict(file_namespace_sha256="held", namespace_entries="3")),
                   "knfs1.0.65536." + "b" * 64, "knfr1.13.0." + "c" * 33]
        for sample in samples:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {row["rule"] for row in AUDIT.inspect("export.txt", sample.encode(encoding))})
        self.assertFalse(AUDIT.inspect("guide.md", b"Use the kn.store_file_scan.v1 schema."))

    def test_store_retention_operation_output(self):
        for schema in ("kn.evidence_gc_result.v1", "kn.evidence_retirement_result.v1"):
            sample = json.dumps(dict(schema=schema, status="planned", issue=""))
            for text in (sample, "retention log\n" + sample[:sample.index(",") + 1]):
                for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                    self.assertIn("private-evidence-bundle", {row["rule"] for row in AUDIT.inspect("export.txt", text.encode(encoding))})
            self.assertFalse(AUDIT.inspect("guide.md", ("The command returns " + schema).encode()))
            prefix = json.dumps(dict(schema=schema), separators=(",", ":"))[:-1]
            self.assertFalse(AUDIT.inspect("consumer.py", f"matches = line.startswith({prefix!r})".encode()))

    def test_detached_store_retention(self):
        rows = (dict(input_matched=True, sha256="synthetic", path="fixture"),
                dict(artifact={}, uncommitted_approval_referrers=[]), dict(approval_catalog="resolved", artifact={}),
                dict(artifact={}, uncommitted_image_referrers=[]), dict(image_catalog="inputs_incomplete", artifact={}),
                dict(expected_sha256="synthetic", path="fixture", digest_basis="unwrapped_payload"),
                dict(artifact={}, irp_catalog="unreadable"), dict(artifact={}, irp_referrers=[]),
                dict(path="fixture", expected_bytes="4", root_committed=True), dict(retired_collections=["7"], retired_original_matched=True),
                dict(retired_collection_id="7", retirement_sha256="fixture"), dict(exclusive_nonledger={}, shared_nonledger={}, failure_ledgers={}),
                dict(collection_id="7", head_sha256="fixture", exclusive_byte_limit="4"),
                dict(collection_id="7", routine_paths="1", exclusive_routine_bytes="4"),
                dict(routine_named_bytes_before="20", routine_named_bytes_after="16"),
                dict(routine_named_byte_target="2", exclusive_byte_limit="4", catalog_sha256="fixture"),
                dict(paths="2", named_bytes="4", **{"class": "routine_only"}),
                dict(artifact_row_offset="1", next_artifact_cursor="owned"), dict(artifact_page_status="more", artifact_rows_remaining="2"))
        for row in rows:
            raw = json.dumps(dict(outer=[row])).encode()
            for sample in (raw, raw[:-3], raw.decode().encode("utf-16-le")):
                self.assertIn("private-evidence-bundle", {r["rule"] for r in AUDIT.inspect("export.txt", sample)})
        benign = json.dumps(dict(path="fixture", sha256="synthetic", allowed=True)).encode()
        self.assertFalse(AUDIT.inspect("example.txt", benign))
        ordinary = json.dumps(dict(paths="2", named_bytes="4", **{"class": "text_files"})).encode()
        self.assertFalse(AUDIT.inspect("file-counts.txt", ordinary))

    def test_detached_irp_disclosure(self):
        for name in ("case.knirp.KNCLAIMS", "case.knirp.knclaims.pending-7"):
            self.assertIsNotNone(AUDIT.path_rule(name))
        for fields in (dict(recorded_claims=None, requests_retained="1", qualified_replay=True),
                       dict(original_capture_sha256="fixture", recorded_claim_sha256=None, source_semantic_sha256="fixture"),
                       dict(claims_possible="7", claims_emitted="7", supported="3", not_applicable="1")):
            raw = json.dumps(dict(outer=[fields]))
            for data in (raw.encode(), raw[:-3].encode(), raw.encode("utf-16-le"), raw.encode("utf-16-be")):
                self.assertIn("private-evidence-bundle", {row["rule"] for row in AUDIT.inspect("attachment.txt", data)})
        for schema in ("kn.minimized_irp_facts.v1", "kn.redaction_manifest.v2", "kn.irp_capture.v1", "kn.irp_capture.v2",
                       "kn.irp_claim_publication.v1", "kn.irp_claim_report.v1"):
            raw = json.dumps(dict(schema=schema))
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {row["rule"] for row in AUDIT.inspect("renamed.txt", raw.encode(encoding))})

    def test_rotation_inventories_and_exports(self):
        for filename in ("source.knetlset", "source.knetlset.pending-1", "controller.knetlowner"):
            self.assertIsNotNone(AUDIT.path_rule(filename))
        rows = (dict(schema="kn.etl_rotation_inventory.v1"), dict(schema="kn.etl_rotation_set.v1"),
                dict(ordinal=1, etl_bytes="8", etl_sha256="digest"),
                dict(win32_status=0, final_ordinal=3, log_buffers_lost=0),
                dict(ordinal=1, expected_bytes=8, observed_bytes=8))
        for row in rows:
            wrapped = json.dumps(dict(outer=dict(inner=row))).encode()
            for text in (wrapped, wrapped[:-3], wrapped.decode().encode("utf-16-le")):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", text)})
        header = json.dumps(dict(typ="kn.etl_rotation_inventory.v1+jws", alg="ES256")).encode()
        payload = json.dumps(dict(schema="kn.etl_rotation_inventory.v1", members=["x" * 5500])).encode()
        for part in (header, payload):
            encoded = base64.urlsafe_b64encode(part).rstrip(b"=")
            self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", encoded)})
        self.assertFalse(AUDIT.inspect("unrelated.json", json.dumps(dict(ordinal=1, observed_bytes=8)).encode()))

    def test_minidump_observation_archive(self):
        self.assertEqual(AUDIT.path_rule(".kniat-replay-owned/copied.bin"), "local-state-directory")
        for name in ("saved.KNIATARCHIVE", ".kniatarchive.pending-owned", ".KNIAT-RECOVER-owned.partial"):
            self.assertEqual(AUDIT.path_rule(name), "private-container-or-capture")
        for data in (b"KNMDIAT1", b"KNMDIAT1" + bytes(100)):
            self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.bin", data)})
        for row in (dict(schema="kn.minidump_iat_archive.v1"), dict(packing_reader_sha256="a" * 64),
                    dict(original_report_reproduced=True, report_sha256="b" * 64),
                    dict(pending_archive_sha256="c" * 64),
                    dict(retained_prefix_bytes="4294967297", appended_bytes="0")):
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                found = AUDIT.inspect("excerpt.txt", json.dumps(row).encode(encoding))
                self.assertIn("private-evidence-bundle", {f["rule"] for f in found})
        self.assertFalse(AUDIT.inspect("guide.md", b"Replay a kn.minidump_iat_archive.v1 result."))

    def test_private_archive_scan_accounts_for_all_bytes_with_bounded_reads(self):
        class ArchiveStream(io.BytesIO):
            def read(self, size=-1):
                if not 0 <= size <= 1 << 20:
                    raise AssertionError("archive payload read exceeded the chunk limit")
                return super().read(size)

        for name, prefix, rule in (("renamed.bin", b"KNMDIAT1", "private-evidence-bundle"),
                                   ("renamed.bin", b"MDMP\x93\xa7", "private-user-minidump"),
                                   (".KNIAT-Recover-owned.partial", b"partial", "private-container-or-capture"),
                                   (".kniatarchive.pending-owned", b"damaged", "private-container-or-capture")):
            data = prefix + bytes((2 << 20) + 7)
            with ArchiveStream(data) as stream:
                size, findings = AUDIT.inspect_stream(name, stream)
                self.assertEqual(size, len(data))
                self.assertEqual([f["rule"] for f in findings], [rule])

    def test_portable_approval_evidence(self):
        for name in ("case.knapprovalarchive", ".knapprovalarchive.pending-owned"):
            self.assertEqual(AUDIT.path_rule(name), "private-container-or-capture")
        self.assertEqual(AUDIT.path_rule(".knapproval-replay-owned/raw.json"), "local-state-directory")
        for data in (b"KNAPARC1", b"KNAPARC1" + bytes(100)):
            self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.dat", data)})
        for row in (dict(schema="kn.image_approval_archive_result.v1"), dict(current_windows_verification=None),
                    dict(original_windows_verification={}), dict(archive_requires_efs=True, journal_head_sha256="pin")):
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                data = ("receipt\n" + json.dumps(row)).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", data)})

    def test_native_loader_window_evidence(self):
        for item in (dict(schema="kn.image_loader_window.v1"), dict(capture_start_qpc="4", capture_end_qpc="9"),
                     dict(strictly_inside_reads=["1"], image={}), dict(recorded_loader_interval=False),
                     dict(loader_marker_status=0, loader_marker_submitted=True),
                     dict(read="1", address="12", start_qpc="5", end_qpc="6"), dict(previous_image={}, next_image={}),
                     dict(collector_generation={}, target_generation={}), dict(schema="kn.image_loader_window_replay.v1"),
                     dict(read_window_in_attested_etl=False), dict(expected_etl_sha256="x", expected_recipe_sha256="y"),
                     dict(claim_publication_sha256="a", replayed_page_sha256="b"), dict(schema="kn.image_observation_pair.v1"),
                     dict(supporting_reads=["1"], observed_bytes_sha256="sample"), dict(read_start_qpc="2", read_end_qpc="3"),
                     dict(earlier_read_end_qpc="3", later_read_start_qpc="7"), dict(observed_bytes_equal=False, differing_byte_count="1")):
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                raw = ("result " + json.dumps(item)).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", raw)})

    def test_saved_etl_comparison_archives_and_excerpts(self):
        self.assertEqual(AUDIT.path_rule(".knbench-etl-abc/summary.txt"), "local-state-directory")
        for item in (b"KNETLBC1", b"KNETLBC1" + bytes(17), b"KNCORP1\0", b"KNCORP1\0" + bytes(12)):
            self.assertIn("private-benchmark-package", {f["rule"] for f in AUDIT.inspect("renamed.bin", item)})
        for row in (dict(schema="kn.etl_reader_archive.v1"), dict(schema="kn.etl_reader_comparison.v1"),
                    dict(schema="kn.etl_reader_evaluation.v1"), dict(schema="kn.etl_reader_comparison.v2"),
                    dict(schema="kn.etl_reader_evaluation.v2"), dict(retained_sha256="digest", byte_count=17),
                    dict(unresolved_opcode_names=0, supported_descriptors=2), dict(tracerpt=None, verdict="reader_unavailable", native=None),
                    dict(before_sha256="a", after_sha256="b", expected_sha256="c")):
            text = "export\n" + json.dumps(dict(payload=row), indent=2)[:-3]
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("excerpt.txt", text.encode(encoding))})
        for text in ("Files Processed:\r\n\tsource.etl", "Files Processed:\n\toriginal\nTotal Buffers Processed 1\n"):
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                self.assertIn("private-tracerpt-summary", {f["rule"] for f in AUDIT.inspect("summary.data", text.encode(encoding))})
        self.assertFalse(AUDIT.inspect("guide.md", b"The kn.etl_reader_comparison.v1 archive retains tracerpt output."))

    def test_registered_etl_campaign(self):
        distinct = (dict(plan_sha256="a", slot=2, ticket="t", admission_id="i"),
                    dict(admission_sha256="a", tick_ns="2", outcome="os_error"),
                    dict(planned_slots=2, plan_sha256="a"),
                    dict(observation="read", file_bytes=11, prefix_sha256="digest"),
                    dict(domain="admission", role="etl", expected_sha256="a", observed_sha256="b"),
                    dict(corpus_base64="example"), dict(unselected_eligible_case_ids=["a"]),
                    dict(agreement_per_planned_group=None, agreement_per_comparable_group=None),
                    dict(by_independence_group={}, unselected_corpus_cases=1),
                    dict(case_id="a", sample_family="family", partition="heldout", independence_group="group"),
                    dict(case_id="a", supplied_source_partition="development", acquisition="pin_mismatch"),
                    dict(agreement_per_planned=None, agreement_per_comparable=None),
                    dict(acquisition="published", source_sha256="s", evidence="missing", pair=None))
        for value in [*distinct, *(dict(schema=s) for s in AUDIT.ETL_COMPARISON_SCHEMAS)]:
            sample = "retained\n" + json.dumps(dict(data=value), indent=2)[:-3]
            for enc in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("excerpt.txt", sample.encode(enc))})
        self.assertFalse(AUDIT.inspect("guide.md", b"The kn.etl_reader_campaign.v1 snapshot records registered slots."))

    def test_private_operation_journal(self):
        for path in ("operations.KNMCPJOURNAL", "operations.knmcpjournal.tmp.1", "renamed.bin"):
            self.assertIn("private-operation-journal", {r["rule"] for r in AUDIT.inspect(path, b"KNMCPJ1\0ciphertext")})
        self.assertEqual(AUDIT.inspect("journal.cpp", b'const char* prefix = "KNMCPJ1";'), [])

    def test_pending_io_trace_pages_and_assessment(self):
        for name in ("report.KNIOTRACE", "report.kniotrace.pending-1"):
            self.assertEqual(AUDIT.path_rule(name), "private-container-or-capture")
        for data in (b"KNIT", b"KNIT\x01", b"KNIT" + bytes.fromhex("0100000088020000") + bytes(636)):
            self.assertIn("private-pending-io-trace", {r["rule"] for r in AUDIT.inspect("renamed.dat", data)})
        self.assertEqual(AUDIT.inspect("guide.md", b"KNIT pages are little endian."), [])
        schema = "kn.pending_io_trace.v1"
        for data in (json.dumps({"items": [], "schema": schema}),
                     "log\n" + json.dumps({"schema": schema, "requests": []}, indent=2)[:-2]):
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle",
                              {r["rule"] for r in AUDIT.inspect("renamed.txt", data.encode(encoding))})
        self.assertFalse(AUDIT.inspect("guide.md", ("Replay returns " + schema).encode()))

    def test_private_symbol_index(self):
        for name in ("symbols.KNSYMIDX", "symbols.knsymidx.pending-1"):
            self.assertTrue(AUDIT.inspect(name, b"empty"))
        self.assertIn("private-symbol-index", {row["rule"] for row in AUDIT.inspect("renamed.bin", b"KNSYMIDX" + b"\0" * 248)})
        self.assertEqual(AUDIT.inspect("sample.cpp", b'const char* magic = "KNSYMIDX";'), [])

    def test_private_files(self):
        for name in (".env", ".env.production", "sub/.env.backup", "signing.pfx",
                     "capture.DMP", "auth.json", "mcp-endpoint.json", "sub/id_ed25519",
                     ".build/trace.json", "sub/.kn-live-dbg/session.json", "run.log",
                     "capture.KNIRP", "capture.knirp.pending-1", "session.KNIRPLEDGER", "session.knirpledger.pending-1", "capture.KNCASE", "capture.kncase.pending-123", "session.knledger", "session.knledger.pending-123",
                     "manifest.KNINDEX", "chunk.knchunk", "manifest.knindex.pending-123", "chunk.knchunk.pending-123",
                     "types.KNSCHEMA", "types.knschema.pending-123", "ref.knblob", "ref.knblob.pending-123",
                     "case.KNSCOPEAPPROVAL", "case.knscopeapproval.pending-1", "input.KNSCOPEBLOB", "input.knscopeblob.pending-1", "session.KNSCOPELEDGER", "session.knscopeledger.pending-1", "case.KNAPPROVALCASE", "case.knapprovalcase.pending-1", "session.KNAPPROVALLEDGER", "session.knapprovalledger.pending-1", "changes.KNCHANGE", "changes.knchange.pending-1", "policy.KNAPPROVAL", "policy.knapproval.pending-1", "capture.KNCAPTURE", "capture.kncapture.pending-1", "source.KNSOURCE", "source.knsource.pending-1", "session.KNSOURCELEDGER", "session.knsourceledger.pending-1", "session.KNCAPTURELEDGER", "session.kncaptureledger.pending-1", "recipe.KNVERIFY", "recipe.knverify.pending-123", "capture.KNTRACE", "capture.kntrace.pending-123",
                     "original.KNREADS", "original.knreads.pending-123", "session.KNREADLEDGER", "session.knreadledger.pending-123",
                     "slice.KNSLICE", "slice.knslice.pending-123", "sweep.KNSWEEP", "sweep.knsweep.pending-123",
                     "session.KNSESSION", "session.knsession.pending-123", "record.KNJSEG", "record.knjseg.pending-123",
                     "chunk.KNJINDEX", "head.knjindex.pending-123", "writer.knjlock", "store.KNSTORELOCK", "operation.KNGC", "1.kngcintent", "1.kngcreceipt", "retirement.KNRETIREMENT", "retirement.knretirement.pending-123", "1.kngcintent.pending-123", "1.kngcreceipt.pending-123", "store.KNPRIVACY", "store.knprivacy.pending-123", "facts.KNSHARE", "facts.knshare.pending-1", "redaction.KNREDACT", "redaction.knredact.pending-1", "transfer.KNSEND", "transfer.knsend.pending-1", "transfer.KNSENDRESULT", "transfer.knsendresult.pending-1"):
            with self.subTest(name=name):
                self.assertTrue(AUDIT.inspect(name, b"empty"))

    def test_safe_examples(self):
        text = b"KNLIVEDBG_OPENROUTER_API_KEY=sk-or-replace-me\nAPI_KEY=sk-replace-me\n"
        self.assertEqual(AUDIT.inspect(".env.example", text), [])
        self.assertEqual(AUDIT.inspect("notes.md", b"sha256=" + b"a1" * 32), [])

    def test_renamed_evidence_stays_private(self):
        for schema in ("kmon.bundle.v1", "kmon.bundle.v2", "kmon.evidence.v1", "kmon.evidence.v2", "kn.temporal_facts.v1", "kmon.evidence_session.v1",
                       "kn.evidence_inventory.v1", "kn.evidence_inventory_chunk.v1", "kn.observation_read.v1", "kn.read_set.v1", "kn.type_schema.v1",
                       "kn.evidence_session.v1", "kn.evidence_journal_segment.v1", "kn.evidence_journal_recovery.v1",
                       "kn.evidence_journal_index.v1", "kn.evidence_journal_index_chunk.v1", "kn.evidence_store_inventory.v1",
                       "kn.evidence_gc_policy.v1", "kn.evidence_gc_policy.v2", "kn.evidence_retirement_policy.v1", "kn.evidence_retirement_policy.v2", "kn.evidence_retirement.v1", "kn.evidence_retirement.v2", "kn.evidence_collection_retention.v1", "kn.evidence_retirement_result.v1", "kn.evidence_gc_operation.v1", "kn.evidence_gc_intent.v1", "kn.evidence_gc_receipt.v1", "kn.evidence_gc_result.v1", "kn.image_retention.v1", "kn.evidence_private_store.v1", "kn.evidence_privacy.v1",
                    "kn.minimized_image_facts.v1", "kn.minimized_irp_facts.v1", "kn.redaction_manifest.v1", "kn.redaction_manifest.v2", "kn.disclosure_package.v1", "kn.disclosure_review.v1", "kn.disclosure_transfer_intent.v1", "kn.disclosure_transfer_result.v1",
                       "kn.irp_capture.v1", "kn.irp_capture.v2", "kn.irp_replay.v1", "kn.irp_capture_session.v1", "kn.irp_retention.v1", "kn.irp_retention_keys.v1", "kn.irp_claim_report.v1", "kn.irp_claim_publication.v1", "kn.routed_reads.v1", "kn.image_reads.v1", "kn.image_reads.v2", "kn.image_reads.v3", "kn.image_read_session.v1",
                       "kn.image_slice.v1", "kn.image_slice.v2", "kn.image_slice_proof.v1", "kn.image_slice_inputs.v1", "kn.image_slice_replay.v1",
                       "kn.image_sweep.v1", "kn.image_sweep_replay.v1", "kn.image_sweep_proof.v1", "kn.image_sweep_graph.v1",
                       "kn.translation_receipt.v1", "kn.dump_read.v1", "kn.dump_read.v2", "kn.dump_initialization.v1",
                       "kn.authorized_image_changes.v1", "kn.image_approval_policy.v1", "kn.image_change_assessment.v1", "kn.image_scope_change_assessment.v1", "kn.image_scope_approval_publication.v1", "kn.image_scope_approval_collection.v1", "kn.image_scope_approval_replay.v1", "kn.image_scope_approval_session.v1", "kn.image_approval_publication.v1", "kn.image_approval_replay.v1", "kn.image_approval_collection.v1", "kn.image_approval_session.v1", "kn.image_recipe.v1", "kn.image_recipe.v2", "kn.image_recipe.v3", "kn.process_image_mappings.v1", "kn.process_image_mapping_assessment.v1", "kn.image_replay.v1", "kn.image_capture.v1", "kn.image_capture.v2", "kn.image_capture.v3", "kn.image_capture_collection.v1", "kn.image_capture_session.v1", "kn.image_proof.v1", "kn.image_claim_report.v1", "kn.image_claim_publication.v1", "kn.image_scope_claim_publication.v1", "kn.capture_scheduling.v1", "kn.reference_scheduling.v1", "kn.reference_scheduler_test.v1", "kn.image_scheduling.v1", "kn.image_scheduler_test.v1", "kn.discovery_scheduling.v1", "kn.discovery_scheduler_test.v1", "kn.discovery_scheduler_fixtures.v1", "kn.user_inventory.v1", "kn.user_module_observation_debt.v1", "kn.owned_module_workload.v1", "kn.user_inventory_test.v1", "kn.user_inventory_fixtures.v1", "kn.user_deep_scheduling.v1", "kn.user_deep_test.v1", "kn.user_deep_fixtures.v1", "kn.analysis_scheduling.v1", "kn.analysis_scheduler_test.v1", "kn.analysis_scheduler_fixtures.v1", "kn.publication_scheduling.v1", "kn.publication_timing.v1", "kn.collection_timing.v1", "kn.publication_picker_test.v1", "kn.publication_writer_test.v1", "kn.layout_collection_scheduling.v1", "kn.layout_verification_scheduling.v1", "kn.layout_scheduler_test.v1", "kn.layout_scheduling_fixture.v1", "kn.image_reference_preparation.v1", "kn.image_preparation_test.v1", "kn.image_preparation_core.v1",
                       "kn.evidence_graph.v1", "kn-live-dbg.hidden-process.v1", "kn.execution_evidence.v1", "kn.irp_observation.v1",
                       "kn.execution_trace.v1", "kn.execution_trace_query.v1", "kn.mcp_operation.v1",
                       "kn.benchmark_corpus.v1", "kn.benchmark_results.v1", "kn.benchmark_report.v1",
                       "kn.owned_module_benchmark.v1", "kn.owned_module_truth.v1", "kn.owned_module_evaluation.v1"):
            data = json.dumps({"schema": schema, "payload": {"bytes_hex": "c3"}})
            for encoding in ("utf-8", "utf-16"):
                self.assertIn("private-evidence-bundle",
                              {f["rule"] for f in AUDIT.inspect("renamed.json", data.encode(encoding))})

    def test_game_manifest_and_registry_evidence(self):
        self.assertEqual(AUDIT.path_rule("owned.KNMANIFEST"), "private-container-or-capture")
        self.assertEqual(AUDIT.path_rule("owned.knmanifest.pending-123"), "private-container-or-capture")
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            for version in (1, 2):
                wire = "KNDBG_GAME_MANIFEST " + str(version) + "\r\n"
                self.assertIn("private-game-manifest", {f["rule"] for f in AUDIT.inspect("renamed.txt", wire.encode(encoding))})
            evidence = json.dumps({"lifetime_source": "game_reported_registry_slot_v1"})
            self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("copy.txt", evidence.encode(encoding))})
        self.assertEqual(AUDIT.inspect("guide.md", b"Use KNDBG_GAME_MANIFEST 2 with a selected build."), [])

    def test_crash_dump_and_diagnosis(self):
        for signature in (b"PAGEDU64", b"PAGEDUMP"):
            for data in (signature, signature + bytes(128)):
                self.assertIn("private-crash-dump", {f["rule"] for f in AUDIT.inspect("renamed.bin", data)})
        schema = "kn.crash_diagnosis.v1"
        frame = {"ip": "0x4000", "sp": "0x8000", "return": "0x10", "virtual": True, "module": {}}
        for data in (json.dumps({"x": 1, "schema": schema}), "log\n" + json.dumps({"header": {}, "schema": schema}),
                     "log\n" + json.dumps({"schema": schema, "header": {}}, indent=2)[:-3],
                     "trace\n" + json.dumps(frame, indent=2)[:-2]):
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", data.encode(encoding))})
        self.assertEqual(AUDIT.inspect("guide.md", ("See " + schema + " for the report.").encode()), [])

    def test_whea_record_and_detached_sections(self):
        for raw in (b"CPER", b"CPER\x10", b"CPER\x10\x02\xff", b"CPER" + bytes(5), b"CPER" + bytes.fromhex("1002ffffffff") + bytes(128)):
            self.assertIn("private-whea-record", {f["rule"] for f in AUDIT.inspect("renamed.dat", raw)})
        self.assertFalse(AUDIT.inspect("guide.md", b"CPER records can include padding."))
        schema = "kn.crash_diagnosis.v2"
        cases = (json.dumps({"header": {}, "schema": schema}), "log\n" + json.dumps({"whea_record": {}, "schema": schema}),
                 "log\n" + json.dumps({"schema": schema, "status": "matched"}, indent=2)[:-3],
                 json.dumps({"status": "linked", "reads": [], "captured_bytes": 4, "captured_sha256": "x"}, indent=2),
                 json.dumps({"type_guid": "id", "revision": 0, "offset": 1, "length": 2, "sha256": "x"}, indent=2),
                 json.dumps({"revision": 1, "record_id": 1, "creator": "id", "notify_type": "id"}),
                 json.dumps({"bank": 1, "status": "0x0", "valid": False, "matches_stop_status": None}),
                 json.dumps({"valid_bits": 0, "physical_address": None, "physical_address_mask": None, "error_type": None}))
        for sample in cases:
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.log", sample.encode(encoding))})
        self.assertFalse(AUDIT.inspect("guide.md", ("See " + schema).encode()))

    def test_saved_reboot_event_and_comparison(self):
        self.assertIsNotNone(AUDIT.path_rule("system.EvTx"))
        self.assertIsNotNone(AUDIT.path_rule("system.EVTX.zip"))
        for identity in ("Name='Microsoft-Windows-Kernel-Power'", 'Guid="{331C3B3A-2005-44C2-AC5E-77220C37D6B4}"'):
            export = "log\n" + "<Event><System><Provider " + identity + "/></System></Event>"
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-reboot-event", {f["rule"] for f in AUDIT.inspect("renamed.txt", export.encode(encoding))})
        for signature in (b"ElfFile\0", b"ElfChnk\0"):
            self.assertIn("private-windows-event-log", {f["rule"] for f in AUDIT.inspect("renamed.bin", signature + bytes(128))})
        for schema in ("kn.crash_diagnosis.v3", "kn.reboot_event_comparison.v1"):
            for text in (json.dumps({"status": "example", "schema": schema}),
                         "log\n" + json.dumps({"schema": schema, "status": "example"}, indent=2)[:-3],
                         "log\n" + json.dumps({"requested_record_id": "1", "log_sha256": "example", "same_stop_tuple": None})):
                for encoding in ("utf-8", "utf-16", "utf-16-be"):
                    self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("capture.txt", text.encode(encoding))})
            self.assertFalse(AUDIT.inspect("guide.md", ("See " + schema).encode()))

    def test_whea_export_and_event_comparison(self):
        name = "Microsoft-Windows-WHEA-Logger"
        guid = "{c26c4f3c-3f66-4e99-8f8a-39405cfed220}"
        header = '<e:Event xmlns:e="urn:test"><e:System><e:Provider '
        schema = "kn.whea_event_comparison.v1"
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            for attribute in (f'Name="{name}"', f"Guid='{guid.upper()}'"):
                content = ("log\n" + header + attribute + "/>").encode(encoding)
                self.assertIn("private-whea-event", {f["rule"] for f in AUDIT.inspect("export.txt", content)})
            for report in ({"schema": schema}, {"provider": name, "channel": "System", "event_record_id": "1", "system_time_utc": "time"}):
                content = ("log\n" + json.dumps(report, indent=2)).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("result.txt", content)})
        self.assertFalse(AUDIT.inspect("guide.md", ("Use the " + name + " provider.").encode()))
        scattered = '\n'.join(json.dumps({key: "example"}) for key in ("provider", "channel", "event_record_id", "system_time_utc"))
        self.assertFalse(AUDIT.inspect("examples.txt", scattered.encode()))
        nested = json.dumps({"provider": name, "channel": "System", "inner": {"event_record_id": "1", "system_time_utc": "time"}})
        self.assertFalse(AUDIT.inspect("examples.txt", nested.encode()))
        partial = 'log\n' + json.dumps({"provider": name, "channel": "System", "event_record_id": "1", "system_time_utc": "time"}, indent=2)[:-5]
        self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("result.txt", partial.encode())})


    def test_io_lifecycle_journals_and_reports(self):
        for schema in ("kn.io_lifetime.v1", "kn.io_lifetime_assessment.v1", "kn.io_lifetime_timing.v1",
                       "kn.io_lifetime_port.v1", "kn.io_lifetime_port_assessment.v1"):
            first = json.dumps({"schema": schema, "seq": 1, "kind": "result"})
            reordered = json.dumps({"kind": "result", "schema": schema, "seq": 1})
            for sample in (first, "log\n" + first[:-4], "log\n" + reordered + "\n" + reordered):
                for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                    findings = AUDIT.inspect("unrelated-name.txt", sample.encode(encoding))
                    self.assertIn("private-evidence-bundle", {f["rule"] for f in findings})
            self.assertFalse(AUDIT.inspect("guide.md", ("See the " + schema + " journal.").encode()))

    def test_io_timing_detached_evidence(self):
        for row in (dict(evidence_line=3, tick_field="start", tick_ms="20"),
                    dict(end_tick_ms="42", evidence_line=8, start_tick_ms="37"),
                    dict(clear_or_submission_from_line=11, signal_by_line=6),
                    dict(proven_precedences=[], possible_latest_generations=[1, 2]),
                    dict(accepted=2, right_censored=1, bounded_signals=1),
                    dict(signal_window=None, submission_to_signal_ms=None),
                    dict(completion_key="9", overlapped="64"), dict(port_open_line=2, phase_line=15),
                    dict(overlapped="64", directory_handle="7"), dict(start=7, ok=False, port_handle="4"),
                    dict(returned_port="4", directory_handle="7"),
                    dict(disputed_dequeue_lines=[7], packet_outcome=None), dict(joined_packets=1, corroborated_results=0)):
            snippet = "log\n" + json.dumps(dict(part=row), indent=2)[:-4]
            for enc in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", snippet.encode(enc))})
        self.assertFalse(AUDIT.inspect("timing.md", b"The optional report exposes signal_window and tick_field."))
        for field in ("overlapped", "directory_handle", "returned_port", "port_handle"):
            tail = 'log\n {"' + field + '": "128'
            for enc in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("partial.txt", tail.encode(enc))})
        self.assertFalse(AUDIT.inspect("config.json", json.dumps(dict(overlapped=True)).encode()))

    def test_hard_fault_pages_and_detached_rows(self):
        for row in (dict(status="partial", schema="kn.etl_hard_faults.v1"), dict(record_ordinal=15, fault_ordinal=2),
                    dict(faulting_thread_id=8, initial_time_raw="72"), dict(timing_status="ordered_qpc", elapsed_qpc_ticks="0"),
                    dict(untimed_faults=1, timed_faults=0), dict(first_longest_fault=None, longest_fault_ties=0),
                    dict(disk_request=None, critical_path=None, thread_lifetime=None),
                    dict(status="read", schema="kn.etl_hard_faults.v2"),
                    dict(status="partial", schema="kn.etl_hard_faults.v3"),
                    dict(status="read", schema="kn.etl_activity_markers.v1"), dict(marker_ordinal=3, event={}),
                    dict(fault_union_ticks="0", window_ticks="1"), dict(activity_id="private", record_ordinal=4),
                    dict(requested_start_record=1, requested_stop_record=2),
                    dict(on_cpu_ticks=None, off_cpu_ticks=None), dict(overlap_end_raw="2", overlap_start_raw="1"),
                    dict(before_ready_ticks="1", after_ready_ticks="0"), dict(requested_fault_ordinal=1, source_status="partial")):
            text = "log\n" + json.dumps(dict(part=row), indent=2)[:-4]
            for enc in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", text.encode(enc))})
        self.assertFalse(AUDIT.inspect("performance.md", b"The kn.etl_hard_faults.v1 page reports elapsed_qpc_ticks."))
        self.assertFalse(AUDIT.inspect("performance.md", b"The kn.etl_hard_faults.v2 page reports on_cpu_ticks."))

    def test_saved_disk_io(self):
        for row in (dict(status="partial", schema="kn.etl_disk_io.v1"), dict(disk_event_ordinal=3, record_ordinal=42),
                    dict(reported_issuing_tid=32, high_res_response_ticks="0"),
                    dict(completions=0, longest_response_ties=0, initiations=1),
                    dict(cross_provider_join=False, device_service_time=None, request_generation=None)):
            sample = "log\n" + json.dumps(dict(part=row), indent=2)[:-4]
            for enc in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", sample.encode(enc))})
        self.assertFalse(AUDIT.inspect("disk.md", b"See the kn.etl_disk_io.v1 report."))

    def test_saved_cpu_profile(self):
        for name in ("input.ETL", "input.etl.zip"):
            self.assertEqual(AUDIT.path_rule(name), "private-container-or-capture")
        for header_type in (1, 2):
            header = bytearray(80)
            header[:4] = (1024).to_bytes(4, "little")
            header[54] = 4
            header[74:76] = bytes((header_type, 192))
            self.assertIn("private-etl-buffer", {r["rule"] for r in AUDIT.inspect("renamed.bin", bytes(header))})
        schema = "kn.etl_profile.v1"
        for data in (json.dumps({"samples": [], "schema": schema}),
                     "log\n" + json.dumps({"schema": schema, "samples": []}, indent=2)[:-2]):
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                self.assertIn("private-evidence-bundle", {r["rule"] for r in AUDIT.inspect("renamed.txt", data.encode(encoding))})
        v2 = "kn.etl_profile.v2"
        point = dict(record_ordinal=1, raw_timestamp="2", event="start", opcode=1, payload_pid=3, payload_tid=4)
        pair = dict(relation="one_boundary", paired_record_pid=None, before=point, after=None)
        v3 = "kn.etl_profile.v3"
        image = dict(record_ordinal=8, raw_timestamp="9", payload_pid=3, image_base="0x20", image_size="0x10")
        identity = dict(image_checksum=4, pe_timestamp=5, recorded_file_name="sample.dll")
        witness = dict(relation="one_boundary", before_record=8, after_record=None)
        evidence = dict(relation="one_boundary", candidate_ranges=1, reported_rva=None, witnesses=[witness])
        switch_schema = "kn.etl_switches.v1"
        location = dict(switch_ordinal=1, record_ordinal=2, raw_timestamp="3", cpu=0)
        tids = dict(new_thread_id=4, old_thread_id=5, new_priority=8, old_priority=9)
        wait = dict(old_thread_id=4, new_thread_id=5, old_wait_reason=17)
        intervals = "kn.etl_switches.v2"
        cpu_span = dict(relation="running_on_cpu", elapsed_ticks="10", previous_switch=None)
        off_cpu = dict(previous_thread_event=None, relation="off_cpu", elapsed_ticks="30")
        readiness = dict(relation="ready_unobserved", ready_records=0, dispatchable_records=0)
        ready_point = dict(ready_flags=1, payload_tid=5, adjust_increment=-1)
        edge = dict(kind="switch_out", logger_id=0, payload_tid=5, raw_timestamp="2", record_ordinal=3)
        source = dict(thread_filter=5, matched_switches=2)
        split = dict(ready_to_switch_in_ticks="10", switch_out_to_ready_ticks="15")
        for raw in (b"x64\0C", b"ia32\0M", b"arm64\0G"):
            self.assertIn("private-v8-code-log", {x["rule"] for x in AUDIT.inspect("renamed.bin", raw)})
        self.assertIsNotNone(AUDIT.path_rule("capture.log.ll"))
        for raw in ("tick,0x1,9,0,0x0,0", "code-creation,JS,12,4,0x10000,16,f,0x1,*", "code-move,0x10000,0x20000"):
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                self.assertIn("private-v8-profile", {x["rule"] for x in AUDIT.inspect("renamed.txt", raw.encode(encoding))})
        v8 = "kn.etl_profile.v8"
        v7 = "kn.etl_profile.v7"
        switch_settings = "kn.etl_switches.v3"
        mask_bracket = dict(relation="equal_group_snapshots", before_record=5, after_record=6)
        v6 = "kn.etl_profile.v6"
        rsds = dict(rsds_guid="00000000-0000-0000-0000-000000000000", pdb_age=0)
        markers = dict(marker_count=1, marker_records=[8])
        v5 = "kn.etl_profile.v5"
        artifact = dict(max_window_bytes=32, file_sha256="a" * 64, file_bytes=1024)
        reference_name = dict(file_sha256="a" * 64, file_bytes=1024, file_name="fixture.bin")
        reference_error = dict(reference_sha256="b" * 64, win32_status=None, source_sha256="a" * 64)
        fields = dict(default_base_relation="recorded_load", image_checksum=True, image_size=True)
        window = dict(file_offset=512, byte_count=13, sha256="b" * 64)
        admitted = dict(reference_window=window, file_location="executable_file_bytes", loader_fields=fields)
        v4 = "kn.etl_profile.v4"
        process = dict(relation="start_end", candidate_pid=5, before_record=6, after_record=9,
                       opaque_key_comparison="equal", recorded_generation=dict(payload_pid=5, start_record=6))
        process_point = dict(payload_pid=5, parent_pid=4, session_id=1, exit_status=0)
        process_image = dict(relation="inside_process_generation", process_start_record=6, reported_rva="0x10")
        process_source = dict(generation_scope="source_sha256_and_start_record", defunct_events=1, decoded_events=4)
        for record in (dict(schema="kn.execution_trace_query.v2", samples=[]), dict(status="matched", schema="kn.etl_page_replay.v1"),
                       dict(schema="kn.v8_profile_query.v1", samples=[]), dict(profile_sha256="a" * 64, code_log_sha256=None),
                       dict(logger_time_us="8", sampled_pc="0x1"), dict(creation_record=3, mapped_start="0x1"),
                       dict(binary_record=9, body_sha256="b" * 64), dict(byte_relation="matched_code_record", code_record_bytes=None),
                       dict(schema=v8, samples=[]), dict(load_events=3, rundown_events=2, unsupported_events=0),
                       dict(candidate_ranges=1, method_offset="0x5", witnesses=[]), dict(before_record=3, after_record=7),
                       dict(method_start="0x10000", method_id="0x3", module_id="0x4"),
                       dict(reported_clr_relation="load_unload", reported_clr_method=None),
                       dict(load_record=9, unload_record=50, method_offset="5"),
                       dict(native_schema=v7, reported_etl_sha256="a" * 64), dict(expected_page_sha256="b" * 64, replayed_page_sha256=None),
                       dict(source_after=8, decoded_samples=9, records_seen=50), dict(sequence="9", record_ordinal=50, tick="4", ip="40"),
                       dict(file_sha256="a" * 64, reported_etl_sha256="b" * 64),
                       dict(raw_type=1, kind="qpc", header_perf_frequency="1000"), dict(start_filetime="4", events_lost=0, buffers_written=1),
                       dict(schema=switch_schema, switches=[]), location, tids, wait,
                       dict(schema=v7, samples=[]), dict(samples=[], schema=v7), dict(switches=[], schema=switch_settings),
                       dict(group_mask_records=1, profile_interval_records=2), dict(group_masks=[0] * 8, kernel_event_version=0),
                       dict(profile_source=0, new_interval_raw=10000, old_interval_raw=10000, profile_source_name="Timer"),
                       dict(header_flags=832, payload_bytes=0, record_ordinal=5, raw_timestamp="100"),
                       dict(group_mask_bracket=mask_bracket), dict(collection_start_record=4, reported_period_100ns=10000),
                       dict(schema=v6, samples=[]), dict(build_records=[], schema=v6), rsds, markers,
                       dict(loader_count=1, native_rsds=markers), dict(relation="endpoint_unqualified", reference_comparison=None),
                       dict(rsds_guid_equal=True, pdb_age_equal=True, merge_timestamp_equal=None),
                       dict(other_opcodes=0, header_pid_conflicts=1),
                       dict(record_ordinal=1, header_process_id=3, payload_pid=3, image_base="0x1000"),
                       dict(schema=v5, samples=[]), dict(samples=[], schema=v5), artifact, fields, window, admitted, reference_name, reference_error,
                       dict(schema=v4, samples=[]), dict(samples=[], schema=v4), process, process["recorded_generation"],
                       process_point, process_image, process_source,
                       dict(schema=intervals, switches=[]), dict(switches=[], schema=intervals),
                       cpu_span, off_cpu, readiness, ready_point, edge, source, split,
                       dict(schema=v2, samples=[]), point, pair, dict(schema=v3, image_records=[]),
                       image, identity, evidence, witness):
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                intact = json.dumps(record, indent=2).encode(encoding)
                self.assertIn("private-evidence-bundle", {r["rule"] for r in AUDIT.inspect("page.txt", intact)})
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                fragment = ("log\n" + json.dumps(record)[:-1]).encode(encoding)
                self.assertIn("private-evidence-bundle", {r["rule"] for r in AUDIT.inspect("fragment.txt", fragment)})
        row = json.dumps(dict(sample_ordinal=1, record_ordinal=2, raw_timestamp="3",
                              instruction_pointer="0x4", sampled_thread_id=5))
        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            self.assertIn("private-evidence-bundle", {r["rule"] for r in
                          AUDIT.inspect("fragment.txt", ("log\n" + row[:-1]).encode(encoding))})
        for version in (schema, v2, v3, v4, switch_schema, intervals):
            self.assertEqual(AUDIT.inspect("guide.md", ("Reports use " + version + ".").encode()), [])

    def test_signed_etl_capture_material(self):
        def encoded(data):
            return base64.urlsafe_b64encode(data).decode().rstrip("=")

        for indent in (None, 2):
            header = encoded(json.dumps({"typ": "kn.etl_capture_statement.v1+jws", "alg": "ES256"}, indent=indent).encode())
            claims = encoded(json.dumps({"role": "archive_witness", "schema": "kn.etl_capture_statement.v1"}, indent=indent).encode())
            for value in (header + "." + claims + "." + encoded(bytes(64)), header + ".", claims,
                          json.dumps({"schema": "kn.etl_page_replay.v2", "capture_statement": {}}),
                          json.dumps({"trusted_key_sha256": "a"*64, "statement_file_sha256": "b"*64})[:-1],
                          json.dumps({"role": "capture_controller", "session_id": None, "se_system_profile_privilege_enabled": False})[:-1]):
                for codec in ("utf-8", "utf-16-le", "utf-16-be"):
                    self.assertIn("private-evidence-bundle", {r["rule"] for r in AUDIT.inspect("copy.txt", ("log\n"+value).encode(codec))})
        self.assertEqual(AUDIT.inspect("guide.md", b"Capture statements use ES256 and kn.etl_page_replay.v2."), [])
        self.assertEqual(AUDIT.inspect("note.txt", encoded(b'{"alg":"ES256","typ":"unrelated"}').encode()), [])

    def test_wait_captures_and_reports(self):
        for schema in ("kn.wait_chain.v1", "kn.wait_assessment.v1", "kn.wait_series.v1", "kn.wait_series_assessment.v1", "kn.wait_diagnosis.v1"):
            intact = json.dumps({"requested": {}, "schema": schema})
            cut = "log start\n" + json.dumps({"schema": schema, "requested": {}}, indent=2)[:-3]
            for text in (intact, cut):
                for encoding in ("utf-8", "utf-16"):
                    rules = {f["rule"] for f in AUDIT.inspect("unrelated-name.txt", text.encode(encoding))}
                    self.assertIn("private-evidence-bundle", rules)
            self.assertEqual(AUDIT.inspect("guide.md", ("See the " + schema + " schema.").encode()), [])

        part = json.dumps({"pause": None, "views": [{"timing": None, "receipt": {"schema": "kn.wait_chain.v1"}}]})
        clock = json.dumps({"pause": {"start": 10, "signal": {"result": 258}}, "begin_qpc": "1", "end_qpc": None})
        for fragment in (part[:-4], clock[:-2]):
            for prefix in ("", "log start\n,"):
                for encoding in ("utf-8", "utf-16"):
                    rules = {f["rule"] for f in AUDIT.inspect("trace.log", (prefix + fragment).encode(encoding))}
                    self.assertIn("private-evidence-bundle", rules)

    def test_detached_thread_wait_dependencies(self):
        rows = (
            dict(target_created="12", target_tid=3, thread_created="11", node_indices=[0, 1, 2],
                 relation="waits_for_thread_termination"),
            dict(evidence=["/threads/0"], kind="thread_termination_wait_observed", round=1,
                 target_tid=3, target_created="12"),
            dict(waiter_created="11", waiter_tid=2, wait_semantics="thread_termination", target_tid=3,
                 target_created="12"))
        for row in rows:
            for text in (json.dumps(row), "log\n" + json.dumps(row, indent=2)[:-2]):
                for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                    self.assertIn("private-evidence-bundle",
                                  {f["rule"] for f in AUDIT.inspect("renamed.txt", text.encode(encoding))})
        self.assertFalse(AUDIT.inspect("guide.md", b'Fields "target_created" and "target_tid" identify the peer.'))
        self.assertFalse(AUDIT.inspect("example.json", b'{"target_created": null, "target_tid": null}'))

    def test_private_benchmark_archive(self):
        head = b"PK\x03\x04" + bytes(26)
        self.assertEqual(AUDIT.path_rule("case.KNBENCH"), "private-container-or-capture")
        self.assertEqual(AUDIT.path_rule(".knbench-interrupted.tmp"), "private-container-or-capture")
        self.assertIn("private-benchmark-package", {f["rule"] for f in AUDIT.inspect("renamed.dat", head + b"owned-module-manifest.json")})
        self.assertFalse(AUDIT.inspect("guide.zip", head + b"guide.txt"))
        for kind in ("benchmark", "truth", "evaluation", "plan", "campaign", "campaign_evaluation", "attempt", "attempt_receipt", "watch", "worker_failure"):
            truncated = "logged\n" + json.dumps({"schema": "kn.owned_module_" + kind + ".v1", "run_id": "interrupted"}, indent=2)[:-4]
            for encoding in ("utf-8", "utf-16"):
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", truncated.encode(encoding))})

    def test_campaign_database_and_recovery_files(self):
        for name in ("state.KNCAMPAIGN", "renamed.knruns", "state.kncampaign-journal", "state.kncampaign-wal", "state.kncampaign-shm"):
            self.assertEqual(AUDIT.path_rule(name), "private-container-or-capture")
        head = b"SQLite format 3\0" + bytes(52)
        for raw in (head + b"KNMC", b"\0journal page" + b'{"schema":"kn.owned_module_attempt_receipt.v1",'):
            self.assertIn("private-benchmark-campaign", {f["rule"] for f in AUDIT.inspect("renamed.db", raw)})
        self.assertFalse(AUDIT.inspect("ordinary.db", head + bytes(4)))

    def test_paired_benchmark_documents(self):
        for kind in ("benchmark", "truth", "plan"):
            schema = f"kn.owned_module_{kind}.v2"
            complete = json.dumps({"run_id": "synthetic", "schema": schema})
            cut = "worker output\n" + json.dumps({"schema": schema, "record": ["sample"]}, indent=2)[:-6]
            header = 'worker output\n{"schema":"' + schema + '"'
            for raw in (complete, cut, header):
                for encoding in ("utf-8", "utf-16"):
                    rules = {f["rule"] for f in AUDIT.inspect("renamed.txt", raw.encode(encoding))}
                    self.assertIn("private-evidence-bundle", rules)
            self.assertEqual(AUDIT.inspect("guide.md", f"The format is {schema}.".encode()), [])
        self.assertEqual(AUDIT.inspect("other.json", b'{"schema":[]}'), [])

    def test_paired_plan_in_sqlite_recovery_page(self):
        plan = json.dumps({"schema": "kn.owned_module_plan.v2", "tickets": ["synthetic"]},
                          separators=(",", ":")).encode()
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "fixture.db"
            with closing(sqlite3.connect(db)) as connection:
                self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                connection.execute("CREATE TABLE plans (record BLOB)")
                connection.execute("INSERT INTO plans VALUES (?)", (plan,))
                connection.commit()
                page = Path(str(db) + "-wal").read_bytes()
                self.assertIn(plan, page)
                self.assertIn("private-benchmark-campaign", {f["rule"] for f in AUDIT.inspect("renamed.dat", page)})

    def test_owned_module_workload_transcripts(self):
        schema = "kn.owned_module_workload.v1"
        event = json.dumps({"schema": schema, "payload": {"kind": "dispatch", "base": 123}})
        trace = json.dumps({"schema": schema, "passed": True, "worlds": []})
        for text in (event + "\n" + event, "runner output\n" + event[:-3], trace + "\n" + trace):
            for encoding in ("utf-8", "utf-16"):
                findings = AUDIT.inspect("renamed.txt", text.encode(encoding))
                self.assertIn("private-evidence-bundle", {f["rule"] for f in findings})
        self.assertFalse(AUDIT.inspect("guide.md", ("The trace uses " + schema + ".").encode()))

    def test_real_shaped_secrets_are_not_reported_verbatim(self):
        samples = ["gh" + "p_" + "A" * 36, "sk-" + "proj-" + "B" * 50,
                   "-----BEGIN " + "PRIVATE KEY-----",
                   "API_KEY=" + "not-a-placeholder",
                   "export SERVICE_ACCESS_TOKEN=" + "arbitrary-value",
                   "https://" + "user:password" + "@example.invalid",
                   "https://example.invalid?" + "sig=" + "c" * 40,
                   "<RSAKeyValue>\n" + "<D>example</D></RSAKeyValue>"]
        for sample in samples:
            with self.subTest(kind=samples.index(sample)):
                findings = AUDIT.inspect("sample.txt", sample.encode())
                self.assertTrue(findings)
                self.assertNotIn(sample, json.dumps(findings))

    def test_runtime_capability_is_not_public_compiled_inventory(self):
        compiled = {"schema": "kn.capabilities.v1", "target_probed": False}
        self.assertFalse(AUDIT.inspect("capabilities.json", json.dumps(compiled).encode()))
        runtime = {"schema": "kn.capabilities.v1", "target_probed": True}
        for encoding in ("utf-8", "utf-16"):
            findings = AUDIT.inspect("renamed.json", json.dumps(runtime).encode(encoding))
            self.assertIn("private-runtime-probe", {f["rule"] for f in findings})
        for overrides in ({"target_probed": False, "probe": {}}, {"target_probed": "true"},
                          {"target_probed": False, "scope": "runtime_probe"}):
            inconsistent = {**runtime, **overrides}
            self.assertTrue(AUDIT.inspect("renamed.json", json.dumps(inconsistent).encode()))

    def test_wait_investigation_exports(self):
        samples = (dict(schema="kn.wait_claim_proposal.v1"), dict(schema="kn.wait_investigation.v1"),
                   dict(claim="primary_cycle_observed", verdict="supported", evidence_ids=["a" * 64]),
                   dict(claim="primary_cycle_observed", verdict="supported", supporting_facts=["a" * 64]),
                   dict(candidate="reference_cycle_persisted_to_end_of_capture", unobserved=["continuous_wait"], next_observation="review"),
                   dict(id="b" * 64, kind="cycle_observed_in_traversal", round=1, evidence=["/query"]),
                   dict(pid=4000, process_created="1000", tid=5000, thread_created="2000"))
        for obj in samples:
            for encoding in ("utf-8", "utf-16", "utf-16-be", "utf-16-le"):
                text = "log entry\n" + json.dumps(dict(entry=[obj]), indent=2)[:-4]
                self.assertTrue(AUDIT.inspect("transcript.txt", text.encode(encoding)))
                self.assertTrue(AUDIT.inspect("renamed.log", ("banner\n" + json.dumps([obj])[:-1]).encode(encoding)))
        self.assertFalse(AUDIT.inspect("manual.md", b"Use kn.wait_investigation.v1 to check evidence_ids."))

    def test_retained_corpus_private_records(self):
        for row in (dict(schema="kn.benchmark_retention.v1"), dict(schema="kn.benchmark_retained_report.v1"),
                    dict(schema="kn.benchmark_original_recovery.v1"), dict(package_sha256="a", original_sha256="b", original_bytes=0),
                    dict(schema="kn.benchmark_original_files.v1"), dict(original_files=["sample.bin"]),
                    dict(case_id="sample", original_status={"artifact_sha256": "missing"}),
                    dict(missing_sha256=["f" * 64]), dict(package_sha256="a", results_sha256="b", corpus_sha256="c")):
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                data = ("record\n" + json.dumps({"nested": [row]})[:-2]).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"Read the missing_sha256 field in kn.benchmark_retained_report.v1."))

    def test_publisher_reference_and_comparison_exports(self):
        samples = (dict(schema="kn.benchmark_tuf_reference.v1"), dict(schema="kn.benchmark_target_scope.v1"),
                   dict(schema="kn.benchmark_publisher_report.v1"), dict(publisher_truth="unknown", truth_reason="scope_missing"),
                   dict(trusted_root_sha256="a", verification_time_utc="b"), dict(target_path="a", file_bytes=2, missing=[]),
                   dict(target_path="a", signed_hashes={}), dict(root="a", snapshot="b", timestamp="c", targets="d"),
                   dict(truth_ref_sha256="a", failed_role="root"), dict(truth_ref_sha256="a", metadata_links={}),
                   dict(valid_key_ids=2, threshold=2, expires="2030"))
        for sample in samples:
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                data = ("record\n" + json.dumps({"records": [sample]})[:-2]).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("unsorted.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"Use kn.benchmark_tuf_reference.v1 for retained metadata."))

    def test_image_policy_provisioning_receipts(self):
        samples = (dict(schema="kn.image_approval_provision.v1"), dict(native_policy_sha256=None),
                   dict(native_policy_sha256="a"), dict(policy_target="name", publisher_proof={}),
                   dict(publisher_reference_sha256="a", policy_target="name"),
                   dict(source_approval_count=2, manifest_sha256="b"),
                   dict(source_policy_sha256="c", policy_target_comparison={}),
                   dict(manifest_sha256="d", reference_sha256="e", reference_bytes=4),
                   dict(issuer="team", policy_epoch="3", not_before_filetime="1", not_after_filetime="9"))
        for sample in samples:
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                data = ("receipt\n" + json.dumps({"items": [sample]})[:-2]).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"Read native_policy_sha256 from the provisioning receipt."))

    def test_publisher_root_history_and_detached_progress(self):
        samples = (dict(schema="kn.benchmark_tuf_reference.v2"), dict(root_updates=["metadata"]),
                   dict(root_rotation={}), dict(last_root_sha256=None), dict(anchor_version=5, presented_updates=11),
                   dict(presented_updates=2, verified_updates=1), dict(verified_updates=3, last_root_version=8),
                   dict(minimum_root_version=2, failed_role="root"))
        for sample in samples:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                data = ("record\n" + json.dumps({"part": [sample]})[:-2]).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"Supply root_updates in ascending order."))

    def test_windows_publisher_policy_and_receipts(self):
        samples = (dict(schema="kn.image_approval_policy.v2"), dict(schema="kn.image_approval_provision.v2"),
                   dict(windows_publisher={}), dict(reference_signature={}, issuer="team"),
                   dict(signature_policy={}, started_utc="time"), dict(signer_certificate_sha256=None),
                   dict(catalog_member_sha256="b"), dict(catalog_sha256="a", catalog_bytes=32),
                   dict(wintrust_status="0x800b0100", status="wintrust_rejected"),
                   dict(win32_status=33, finished_utc="time"))
        for sample in samples:
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                data = ("receipt\n" + json.dumps({"nested": [sample]})[:-2]).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("detached.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"The signer_certificate_sha256 field names the Windows publisher."))

    def test_window_message_wait_exports(self):
        for row in (dict(schema="kn.wait_message_fixture.v1"), dict(receiver_tid=17, receiver_created="20"),
                    dict(send_return_tick=200, handler_entry_tick=100, handler_leave_tick=200)):
            for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
                data = ("log\n" + json.dumps(dict(entries=[row]))[:-2]).encode(encoding)
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("renamed.txt", data)})
        self.assertFalse(AUDIT.inspect("guide.md", b"The receiver_created field identifies a recorded thread generation."))

    def test_saved_dump_probe_exports(self):
        scope = dict(schema="kn.capabilities.v1", target_probed=False, scope="saved_dump_probe")
        metadata = dict(status="header_digest_mismatch", schema="kn.dump_capability_probe.v1")
        rows = (dict(expected_header_sha256="1" * 64, digest_scope="first_8192_bytes"),
                dict(availability_scope="supplied_dump_virtual_range", range_evidence=None),
                dict(range_state="partial", captured_bytes=8, unobserved_bytes=8),
                dict(range_offset=8, state="complete", span_sha256="a" * 64),
                dict(range_offset=0, translation_state="unsupported", translation_reason="reserved_paging_entry_bits"),
                dict(physical_read_sequence=9, native_status_domain="win32", win32_status=33))
        for encoding in ("utf-8", "utf-16", "utf-16-be", "utf-16-le"):
            for obj in (scope, metadata):
                rules = {f["rule"] for f in AUDIT.inspect("renamed.log", ("log\n" + json.dumps(obj)[:-1]).encode(encoding))}
                self.assertIn("private-runtime-probe", rules)
            for row in (*rows, scope, metadata):
                for indent in (None, 2):
                    fragment = "log\n" + json.dumps(dict(export=[row]), indent=indent)[:-3]
                    self.assertTrue(AUDIT.inspect("transcript.txt", fragment.encode(encoding)))
        self.assertFalse(AUDIT.inspect("manual.md", b"saved_dump_probe reports a range_state and span_sha256."))

    def test_dump_initialization_exports(self):
        receipt = dict(purpose="list_head", candidate_levels=4, file_offset="32", requested_bytes=8)
        metadata = dict(decision="depth_ambiguous", schema="kn.dump_initialization.v1")
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            for group in ([receipt], [metadata], dict(archive=metadata)):
                fragment = "banner\n" + json.dumps(group)[:-1]
                self.assertTrue(AUDIT.inspect("log.txt", fragment.encode(encoding)))
            for obj in (receipt, metadata, dict(schema="kn.dump_read.v2", initialization=metadata)):
                text = "private report\n" + json.dumps(obj, indent=2)[:-1]
                self.assertIn("private-evidence-bundle", {f["rule"] for f in AUDIT.inspect("log.txt", text.encode(encoding))})

    def test_saved_etl_capability_exports(self):
        nested = dict(schema="kn.etl_capability_probe.v1", expected_sha256="a" * 64)
        report = dict(schema="kn.capabilities.v1", target_probed=False, scope="saved_etl_probe", probe=nested)
        family = dict(observation="decoded_records", decoded=1, unsupported=0, first_decoded_record=18)
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            for content in (json.dumps(report), "log\n" + json.dumps(report)[:-8], json.dumps(nested, indent=2)):
                rules = {f["rule"] for f in AUDIT.inspect("renamed.log", content.encode(encoding))}
                self.assertIn("private-runtime-probe", rules)
            self.assertTrue(AUDIT.inspect("row.log", json.dumps(family).encode(encoding)))

    def test_utf16_and_binary_strings(self):
        secret = "gh" + "p_" + "A" * 36
        for data in (secret.encode("utf-16"), b"MZ\0\1" + secret.encode(),
                     b"MZ\0\1" + secret.encode("utf-16-le")):
            self.assertTrue(AUDIT.inspect("sample.bin", data))

    def test_filename_findings_are_redacted(self):
        secret = "gh" + "p_" + "A" * 36
        findings = AUDIT.inspect(secret + ".txt", b"empty")
        self.assertTrue(findings)
        self.assertNotIn(secret, json.dumps(findings))

    def test_profile_paths_and_test_controls(self):
        base = "C:" + "\\Users\\"
        self.assertTrue(AUDIT.inspect("notes.md", (base + "private-account\\source.cpp").encode()))
        for user in ("Public", "test", "a", "O'Brien", "O''Brien"):
            self.assertFalse(AUDIT.inspect("test.cpp", (base + user + "\\test.cpp").encode()))

    def test_private_symbols_opt_in_is_not_a_secret_bypass(self):
        data = ("C:" + "\\Users\\private-account\\source.cpp").encode()
        self.assertTrue(AUDIT.inspect("sample.pdb", data))
        self.assertFalse(AUDIT.inspect("sample.pdb", data, True))
        self.assertTrue(AUDIT.inspect("sample.cpp", data, True))
        self.assertTrue(AUDIT.inspect("sample.pdb", ("gh" + "p_" + "A" * 36).encode(), True))

    def test_exact_index_and_untracked_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            (root / "tracked.txt").write_text("staged")
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True, capture_output=True)
            (root / "tracked.txt").write_text("working")
            (root / "untracked.txt").write_text("new")
            self.assertEqual(dict(AUDIT.inputs(root, True, False)), {"tracked.txt": b"staged"})
            self.assertEqual(dict(AUDIT.inputs(root, False, False)),
                             {"tracked.txt": b"working", "untracked.txt": b"new"})
            (root / "tracked.txt").unlink()
            self.assertEqual(dict(AUDIT.inputs(root, False, False)), {"untracked.txt": b"new"})
            archived = b"KNMDIAT1" + bytes((1 << 20) + 19)
            (root / "tracked.txt").write_bytes(archived)
            subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True, capture_output=True)
            (root / "tracked.txt").write_bytes(b"working copy")
            size, findings = dict(AUDIT.inputs(root, True, False, AUDIT.inspect_stream))["tracked.txt"]
            self.assertEqual(size, len(archived))
            self.assertEqual([f["rule"] for f in findings], ["private-evidence-bundle"])

    def test_tree_mode_checks_ignored_files_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env.local").write_text("synthetic")
            result = subprocess.run([sys.executable, str(Path(AUDIT.__file__)),
                                     "--tree", "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("synthetic", result.stdout)
            self.assertEqual(json.loads(result.stdout)["files"], 1)
            missing = subprocess.run([sys.executable, str(Path(AUDIT.__file__)),
                                      "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)
            empty = root / "empty"
            empty.mkdir()
            for candidate in (empty, root / "missing"):
                result = subprocess.run([sys.executable, str(Path(AUDIT.__file__)),
                                         "--tree", "--root", str(candidate)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
