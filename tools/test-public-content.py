"""Regression tests for publication checks; all secret-shaped data is synthetic."""
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("public_content", Path(__file__).with_name("validate-public-content.py"))
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class PublicContentTests(unittest.TestCase):
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
                     "case.KNSCOPEAPPROVAL", "case.knscopeapproval.pending-1", "input.KNSCOPEBLOB", "input.knscopeblob.pending-1", "session.KNSCOPELEDGER", "session.knscopeledger.pending-1", "case.KNAPPROVALCASE", "case.knapprovalcase.pending-1", "session.KNAPPROVALLEDGER", "session.knapprovalledger.pending-1", "changes.KNCHANGE", "changes.knchange.pending-1", "policy.KNAPPROVAL", "policy.knapproval.pending-1", "capture.KNCAPTURE", "capture.kncapture.pending-1", "session.KNCAPTURELEDGER", "session.kncaptureledger.pending-1", "recipe.KNVERIFY", "recipe.knverify.pending-123", "capture.KNTRACE", "capture.kntrace.pending-123",
                     "original.KNREADS", "original.knreads.pending-123", "session.KNREADLEDGER", "session.knreadledger.pending-123",
                     "slice.KNSLICE", "slice.knslice.pending-123", "sweep.KNSWEEP", "sweep.knsweep.pending-123",
                     "session.KNSESSION", "session.knsession.pending-123", "record.KNJSEG", "record.knjseg.pending-123",
                     "chunk.KNJINDEX", "head.knjindex.pending-123", "writer.knjlock", "store.KNSTORELOCK", "operation.KNGC", "1.kngcintent", "1.kngcreceipt", "1.kngcintent.pending-123", "1.kngcreceipt.pending-123", "store.KNPRIVACY", "store.knprivacy.pending-123", "facts.KNSHARE", "facts.knshare.pending-1", "redaction.KNREDACT", "redaction.knredact.pending-1", "transfer.KNSEND", "transfer.knsend.pending-1", "transfer.KNSENDRESULT", "transfer.knsendresult.pending-1"):
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
                       "kn.evidence_gc_policy.v1", "kn.evidence_gc_operation.v1", "kn.evidence_gc_intent.v1", "kn.evidence_gc_receipt.v1", "kn.evidence_gc_result.v1", "kn.image_retention.v1", "kn.evidence_private_store.v1", "kn.evidence_privacy.v1",
                    "kn.minimized_image_facts.v1", "kn.redaction_manifest.v1", "kn.disclosure_package.v1", "kn.disclosure_review.v1", "kn.disclosure_transfer_intent.v1", "kn.disclosure_transfer_result.v1",
                       "kn.irp_capture.v1", "kn.irp_capture.v2", "kn.irp_replay.v1", "kn.irp_capture_session.v1", "kn.irp_retention.v1", "kn.irp_retention_keys.v1", "kn.irp_claim_report.v1", "kn.irp_claim_publication.v1", "kn.routed_reads.v1", "kn.image_reads.v1", "kn.image_reads.v2", "kn.image_reads.v3", "kn.image_read_session.v1",
                       "kn.image_slice.v1", "kn.image_slice.v2", "kn.image_slice_proof.v1", "kn.image_slice_inputs.v1", "kn.image_slice_replay.v1",
                       "kn.image_sweep.v1", "kn.image_sweep_replay.v1", "kn.image_sweep_proof.v1", "kn.image_sweep_graph.v1",
                       "kn.translation_receipt.v1", "kn.dump_read.v1",
                       "kn.authorized_image_changes.v1", "kn.image_approval_policy.v1", "kn.image_change_assessment.v1", "kn.image_scope_change_assessment.v1", "kn.image_scope_approval_publication.v1", "kn.image_scope_approval_collection.v1", "kn.image_scope_approval_replay.v1", "kn.image_scope_approval_session.v1", "kn.image_approval_publication.v1", "kn.image_approval_replay.v1", "kn.image_approval_collection.v1", "kn.image_approval_session.v1", "kn.image_recipe.v1", "kn.image_recipe.v2", "kn.image_recipe.v3", "kn.process_image_mappings.v1", "kn.process_image_mapping_assessment.v1", "kn.image_replay.v1", "kn.image_capture.v1", "kn.image_capture.v2", "kn.image_capture.v3", "kn.image_capture_collection.v1", "kn.image_capture_session.v1", "kn.image_proof.v1", "kn.image_claim_report.v1", "kn.image_claim_publication.v1", "kn.image_scope_claim_publication.v1", "kn.capture_scheduling.v1", "kn.reference_scheduling.v1", "kn.reference_scheduler_test.v1", "kn.image_scheduling.v1", "kn.image_scheduler_test.v1", "kn.discovery_scheduling.v1", "kn.discovery_scheduler_test.v1", "kn.discovery_scheduler_fixtures.v1", "kn.user_inventory.v1", "kn.user_module_observation_debt.v1", "kn.owned_module_workload.v1", "kn.user_inventory_test.v1", "kn.user_inventory_fixtures.v1", "kn.user_deep_scheduling.v1", "kn.user_deep_test.v1", "kn.user_deep_fixtures.v1", "kn.analysis_scheduling.v1", "kn.analysis_scheduler_test.v1", "kn.analysis_scheduler_fixtures.v1", "kn.publication_scheduling.v1", "kn.publication_timing.v1", "kn.collection_timing.v1", "kn.publication_picker_test.v1", "kn.publication_writer_test.v1", "kn.layout_collection_scheduling.v1", "kn.layout_verification_scheduling.v1", "kn.layout_scheduler_test.v1", "kn.layout_scheduling_fixture.v1", "kn.image_reference_preparation.v1", "kn.image_preparation_test.v1", "kn.image_preparation_core.v1",
                       "kn.evidence_graph.v1", "kn-live-dbg.hidden-process.v1", "kn.execution_evidence.v1", "kn.irp_observation.v1",
                       "kn.execution_trace.v1", "kn.execution_trace_query.v1", "kn.mcp_operation.v1",
                       "kn.benchmark_corpus.v1", "kn.benchmark_results.v1", "kn.benchmark_report.v1",
                       "kn.owned_module_benchmark.v1", "kn.owned_module_truth.v1", "kn.owned_module_evaluation.v1"):
            data = json.dumps({"schema": schema, "payload": {"bytes_hex": "c3"}})
            for encoding in ("utf-8", "utf-16"):
                self.assertIn("private-evidence-bundle",
                              {f["rule"] for f in AUDIT.inspect("renamed.json", data.encode(encoding))})

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
        for schema in ("kn.io_lifetime.v1", "kn.io_lifetime_assessment.v1"):
            first = json.dumps({"schema": schema, "seq": 1, "kind": "result"})
            reordered = json.dumps({"kind": "result", "schema": schema, "seq": 1})
            for sample in (first, "log\n" + first[:-4], "log\n" + reordered + "\n" + reordered):
                for encoding in ("utf-8", "utf-16"):
                    findings = AUDIT.inspect("unrelated-name.txt", sample.encode(encoding))
                    self.assertIn("private-evidence-bundle", {f["rule"] for f in findings})
            self.assertFalse(AUDIT.inspect("guide.md", ("See the " + schema + " journal.").encode()))

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
        v4 = "kn.etl_profile.v4"
        process = dict(relation="start_end", candidate_pid=5, before_record=6, after_record=9,
                       opaque_key_comparison="equal", recorded_generation=dict(payload_pid=5, start_record=6))
        process_point = dict(payload_pid=5, parent_pid=4, session_id=1, exit_status=0)
        process_image = dict(relation="inside_process_generation", process_start_record=6, reported_rva="0x10")
        process_source = dict(generation_scope="source_sha256_and_start_record", defunct_events=1, decoded_events=4)
        for record in (dict(schema=switch_schema, switches=[]), location, tids, wait,
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
