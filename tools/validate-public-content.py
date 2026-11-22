"""Offline publication checks. Reports locations/rule names, never matched values.

Default: current tracked and non-ignored untracked files, including new docs.
--index: exact Git index blobs. --tree: every file in a prepared package directory.
Pattern checks cannot prove that arbitrary prose, captures or media contain no secrets.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import stat
import subprocess
from pathlib import Path

PRIVATE_EXTENSIONS = {".pfx", ".p12", ".pem", ".key", ".dmp", ".dump", ".etl", ".log", ".kncase", ".knledger", ".knindex", ".knchunk", ".knirp", ".knirpledger", ".knschema", ".knsymidx", ".knblob", ".knchange", ".knapproval", ".knapprovalcase", ".knscopeapproval", ".knscopeledger", ".knscopeblob", ".knapprovalledger", ".knverify", ".kncapture", ".kncaptureledger", ".kntrace", ".knetlstatement", ".knetlset", ".knetlowner", ".kniotrace", ".knreads", ".knreadledger", ".knslice", ".knsweep", ".knsession", ".knjseg", ".knjindex", ".knjlock", ".knstorelock", ".kngc", ".kngcintent", ".kngcreceipt", ".knprivacy", ".knshare", ".knredact", ".knsend", ".knsendresult", ".knbench", ".knmanifest"}
PRIVATE_NAMES = {"auth.json", "credentials.json", "mcp-endpoint.json", "id_rsa", "id_ed25519"}
PRIVATE_DIRECTORIES = {".git", ".build", ".vs", ".codex", ".kn-live-dbg",
                       "logs", "knlivedbg-logs", "dump-bin", "symbols", "mcp-clients"}
ETL_COMPARISON_SCHEMAS = ("kn.etl_reader_archive.v1", "kn.etl_reader_comparison.v1", "kn.etl_reader_evaluation.v1",
                          "kn.etl_reader_comparison.v2", "kn.etl_reader_evaluation.v2", "kn.etl_reader_comparison.v3",
                          "kn.etl_reader_evaluation.v3", "kn.etl_reader_plan.v1", "kn.etl_reader_admission.v1",
                          "kn.etl_reader_outcome.v1", "kn.etl_reader_campaign.v1", "kn.etl_reader_campaign_evaluation.v1",
                          "kn.etl_reader_plan_receipt.v1", "kn.etl_reader_slot_receipt.v1", "kn.etl_reader_snapshot_receipt.v1",
                          "kn.etl_reader_plan.v2", "kn.etl_reader_campaign.v2", "kn.etl_reader_campaign_evaluation.v2")
BENCHMARK_RECORD_SCHEMAS = frozenset(ETL_COMPARISON_SCHEMAS) | frozenset(
    f"kn.owned_module_{kind}.{version}"
    for version, kinds in (
        ("v1", ("benchmark", "truth", "evaluation", "plan", "campaign", "campaign_evaluation",
                "attempt", "attempt_receipt", "watch", "worker_failure")),
        ("v2", ("benchmark", "truth", "plan")),
    )
    for kind in kinds
)
BENCHMARK_RECORD_START = re.compile(
    r'(?m)^[ \t]*\{\s*"schema"\s*:\s*"(?:' +
    "|".join(re.escape(schema) for schema in sorted(BENCHMARK_RECORD_SCHEMAS)) + r')"\s*(?:[,}]|$)')
RULES = {
    "private-key": re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "provider-token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|"
        r"sk-(?:proj-|ant-[\w-]*|or-v1-)?[A-Za-z0-9_-]{24,}|"
        r"xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|"
        r"AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}"),
    "credential-url": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/<>\"':]+:[^\s/<>\"'@]+@"),
    "signed-url": re.compile(r"[?&](?:access_token|api_key|apikey|token|secret|sig|signature|password)=[^\s&<>\"']{8,}", re.I),
    "storage-key": re.compile(r"AccountKey=[A-Za-z0-9+/]{30,}={0,2}"),
}
ENV_SECRET = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?(?:[A-Z][A-Z0-9]*_)*(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|PASSWORD|SECRET_ACCESS_KEY)[ \t]*=[ \t]*(\S[^\r\n]*)")
PROFILE_PATH = re.compile(
    r"(?<![\w/\\])(?:[a-z]:[\\/]+Users[\\/]+|/Users/|/home/)(\w[^\\/\s<>\"`]*)", re.I)
RSA_XML = re.compile(r"<RSAKeyValue>\s*(?:<[A-Za-z]+>[A-Za-z0-9+/=\s]+</[A-Za-z]+>\s*)*<D>[A-Za-z0-9+/=\s]+</D>[\s\S]*?</RSAKeyValue>")
# Synthetic users in checked-in self-tests; never add a developer's real account here.
EXAMPLE_USERS = {"a", "test", "user", "public", "default", "o'brien", "o''brien"}
PLACEHOLDERS = {"", "sk-replace-me", "sk-or-replace-me", "<api-key>", "<password>"}


def path_rule(name: str) -> str | None:
    path = Path(name)
    if any(p.lower() in PRIVATE_DIRECTORIES or p.lower().startswith(".knbench-etl-") for p in path.parts[:-1]):
        return "local-state-directory"
    base = path.name.lower()
    if base.endswith(".knmcpjournal") or ".knmcpjournal.tmp." in base:
        return "private-operation-journal"
    if base.endswith((".log.ll", ".etl.zip", ".kncampaign-journal", ".kncampaign-wal", ".kncampaign-shm", ".kncampaign", ".knruns")):
        return "private-container-or-capture"
    if (base.startswith(".env") and base != ".env.example") or base in PRIVATE_NAMES:
        return "credential-file"
    if (base.startswith(".knbench-") and base.endswith(".tmp")) or path.suffix.lower() in PRIVATE_EXTENSIONS or any(
        extension + ".pending-" in base for extension in (".knmanifest", ".kncase", ".knledger", ".knindex", ".knchunk", ".knirp", ".knirpledger", ".knschema", ".knsymidx", ".knblob", ".knchange", ".knapproval", ".knapprovalcase", ".knscopeapproval", ".knscopeledger", ".knscopeblob", ".knapprovalledger", ".knverify", ".kncapture", ".kncaptureledger", ".kntrace", ".knetlstatement", ".knetlset", ".knetlowner", ".kniotrace", ".knreads", ".knreadledger", ".knslice", ".knsweep", ".knsession", ".knjseg", ".knjindex", ".kngc", ".kngcintent", ".kngcreceipt", ".knprivacy", ".knshare", ".knredact", ".knsend", ".knsendresult")
    ):
        return "private-container-or-capture"
    return None


def text_views(data: bytes) -> list[str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return [data.decode("utf-16", errors="replace")]
    if b"\0" not in data[:8192]:
        return [data.decode("utf-8-sig", errors="replace")]
    # Inspect printable ASCII and UTF-16 strings in binaries without executing them.
    ascii_strings = re.findall(rb"[\x20-\x7e]{8,}", data)
    wide_strings = re.findall(rb"(?:[\x20-\x7e]\x00){8,}", data)
    return [b"\n".join(ascii_strings).decode("ascii"),
            "\n".join(s.decode("utf-16-le") for s in wide_strings)]


DISK_IO_SCHEMA = "kn.etl_disk_io.v1"
FAULT_QUERY_SCHEMAS = ("kn.etl_hard_faults.v1", "kn.etl_hard_faults.v2", "kn.etl_hard_faults.v3", "kn.etl_activity_markers.v1",
                       "kn.etl_activity_comparison.v1", "kn.etl_activity_comparison_receipt.v1",
                       "kn.etl_activity_comparison.v2", "kn.etl_activity_comparison_receipt.v2", "kn.traceprocessor_activity_rows.v1")
ETL_ROTATION_SCHEMAS = ("kn.etl_rotation_inventory.v1", "kn.etl_rotation_set.v1")
HANDOFF_SCHEMAS = ("kn.owned_etl_handoff.v1", *(f"kn.etl_handoff_{kind}{receipt}.v1" for kind in ("plan", "capture", "study")
                                               for receipt in ("", "_receipt")))
TRACE_QUERY_SCHEMAS = ("kn.etl_switches.v4", DISK_IO_SCHEMA, *FAULT_QUERY_SCHEMAS, "kn.execution_trace_query.v2", "kn.v8_profile_query.v1", "kn.etl_page_replay.v1", "kn.etl_page_replay.v2", "kn.etl_capture_statement.v1", *ETL_ROTATION_SCHEMAS, *HANDOFF_SCHEMAS)
V8_RAW_RECORD = re.compile(r"(?m)^(?:v8-version,\d+,\d+,\d+,\d+,[^\r\n]*\r?\nv8-platform,|"
                           r"tick,0x[0-9a-fA-F]+,\d+,[01],0x|code-creation,[A-Za-z]+,-?\d+,\d+,0x|"
                           r"code-(?:move|delete|source-info|disassemble),0x[0-9a-fA-F]+(?:,|$))")
# Detect a complete protected header or payload even after a JWS is renamed or cut.
ETL_JWS_OBJECT = re.compile(r"(?<![A-Za-z0-9_-])(e[wy][A-Za-z0-9_-]{18,16384})(?![A-Za-z0-9_-])")


def capture_jws_offset(text: str) -> int | None:
    for match in ETL_JWS_OBJECT.finditer(text):
        part = match.group(1)
        try:
            fields = json.loads(base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True).decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeError, RecursionError):
            continue
        if isinstance(fields, dict) and (fields.get("typ") in ("kn.etl_capture_statement.v1+jws", "kn.etl_rotation_inventory.v1+jws") or
                                         fields.get("schema") in ("kn.etl_capture_statement.v1", "kn.etl_rotation_inventory.v1")):
            return match.start()
    return None


IO_LIFETIME_SCHEMAS = ("kn.io_lifetime.v1", "kn.io_lifetime_assessment.v1", "kn.io_lifetime_timing.v1")
IO_TIMING_MARKERS = (*IO_LIFETIME_SCHEMAS, '"tick_field"', '"start_tick_ms"', '"signal_window"', '"signal_by_line"',
                     '"wait_call_ms"', '"possible_latest_generations"', '"bounded_signals"')
IO_TIMING_FIELDS = tuple(frozenset(fields) for fields in (
    ("evidence_line", "tick_field", "tick_ms"), ("evidence_line", "start_tick_ms", "end_tick_ms"),
    ("signal_window", "submission_to_signal_ms"), ("signal_by_line", "clear_or_submission_from_line"),
    ("monitor_line", "through_line", "wait_call_ms"), ("possible_latest_generations", "proven_precedences"),
    ("bounded_signals", "right_censored", "accepted"),
))
WAIT_PLAN_SCHEMAS = ("kn.wait_investigation.v1", "kn.wait_claim_proposal.v1")
WAIT_PLAN_MARKERS = (*WAIT_PLAN_SCHEMAS, '"evidence_ids"', '"required_evidence_groups"', '"evaluated_views"', '"round"', '"process_created"',
                     '"supporting_facts"', '"next_observation"')
WAIT_PLAN_FIELDS = tuple(frozenset(fields) for fields in (
    ("id", "kind", "round", "evidence"), ("claim", "verdict", "evidence_ids"),
    ("claim", "verdict", "required_evidence_groups"), ("claim", "verdict", "supporting_facts"),
    ("claim", "proposed_verdict", "evidence_ids"), ("candidate", "unobserved", "next_observation"),
    ("evaluated_views", "required_views", "capture_bytes"), ("pid", "process_created", "tid", "thread_created"),
))
DUMP_EVIDENCE_SCHEMAS = ("kn.dump_read.v2", "kn.dump_initialization.v1", "kn.dump_capability_probe.v1")
ETL_COMPARISON_MARKERS = (*ETL_COMPARISON_SCHEMAS, '"retained_sha256"', '"before_sha256"', '"supported_descriptors"',
                          '"verdict"', '"process_state"', '"started_ns"', '"unresolved_opcode_names"', '"admission_id"',
                          '"admission_sha256"', '"planned_slots"', '"distinct_source_hashes"', '"agreement_per_planned"', '"acquisition"', '"prefix_sha256"', '"observed_sha256"',
                          '"corpus_base64"', '"supplied_source_partition"', '"by_independence_group"', '"sample_family"',
                          '"agreement_per_planned_group"', '"unselected_eligible_case_ids"')
ETL_COMPARISON_FIELDS = tuple(frozenset(fields) for fields in (
    ("retained_sha256", "byte_count"), ("retained_sha256", "base64"),
    ("before_sha256", "after_sha256", "expected_sha256"), ("verdict", "native", "tracerpt"),
    ("supported_descriptors", "other_versions"), ("supported_descriptors", "unresolved_opcode_names"),
    ("process_state", "exit_code", "os_error"), ("state", "started_ns", "ended_ns", "os_error"),
    ("plan_sha256", "slot", "ticket", "admission_id"), ("admission_sha256", "tick_ns", "outcome"),
    ("observation", "prefix_sha256", "file_bytes"), ("domain", "role", "expected_sha256", "observed_sha256"),
    ("planned_slots", "plan_sha256"), ("distinct_source_hashes", "reader_statuses"),
    ("agreement_per_planned", "agreement_per_comparable"), ("source_sha256", "acquisition", "evidence", "pair"),
    ("corpus_base64",), ("unselected_eligible_case_ids",), ("by_independence_group", "unselected_corpus_cases"),
    ("agreement_per_planned_group", "agreement_per_comparable_group"),
    ("case_id", "sample_family", "partition", "independence_group"), ("supplied_source_partition", "case_id", "acquisition"),
))
DUMP_EVIDENCE_MARKERS = (*DUMP_EVIDENCE_SCHEMAS, '"candidate_levels"', '"seek_win32_status"', '"first_file_sequence"', "saved_dump_probe",
                         '"expected_header_sha256"', '"range_evidence"', '"range_state"', '"span_sha256"', '"physical_read_sequence"', '"translation_reason"')
DISK_IO_MARKERS = (DISK_IO_SCHEMA, '"disk_event_ordinal"', '"high_res_response_ticks"', '"longest_response_ties"',
                   '"response_ticks_per_second"', '"decoded_disk_records"', '"cross_provider_join"')
HARD_FAULT_FIELDS = tuple(frozenset(keys) for keys in (
    ("fault_ordinal", "record_ordinal"), ("initial_time_raw", "faulting_thread_id"),
    ("waiting_before_ready_ticks", "unclassified_off_cpu_ticks"), ("off_cpu_intervals", "split_off_cpu_intervals"),
    ("cross_thread_critical_path", "logical_task_identity"),
    ("elapsed_qpc_ticks", "timing_status"), ("timed_faults", "untimed_faults"),
    ("longest_fault_ties", "first_longest_fault"), ("decoded_hard_faults", "records_seen"),
    ("decoded_hard_faults", "unsupported_hard_fault_records"),
    ("thread_lifetime", "disk_request", "critical_path"),
    ("authenticated_thread_lifetime", "wait_cause", "critical_path"),
    ("requested_fault_ordinal", "thread_evidence"), ("on_cpu_ticks", "off_cpu_ticks"),
    ("requested_fault_ordinal", "source_status"),
    ("requested_start_record", "requested_stop_record"), ("activity_id", "record_ordinal"),
    ("fault_union_ticks", "window_ticks"), ("process_key_boundaries", "intervening_boundaries"),
    ("marker_ordinal", "event"), ("matched_markers", "decoded_activity_markers"),
    ("activity_duration", "observed_hard_fault_union"), ("baseline_ns", "candidate_ns"),
    ("candidate_minus_baseline_ns", "relative_change_percent"), ("start_event_id", "stop_event_id"),
    ("reader_sha256", "reader_schema"), ("report_sha256", "comparison_status"), ("stdout_sha256", "stdout_bytes"),
    ("equivalent_workload", "population_regression", "cause_of_change"),
    ("loaded_processing_modules", "provider_rows"), ("matched_rows", "row_limit"),
    ("table_row", "raw_timestamp"), ("matching_table_rows", "unqualified_clock_rows"),
    ("sdk_files_sha256", "executable_sha256"), ("native_page_sha256", "correspondence"),
    ("header_thread_id", "begin_raw", "end_raw"),
    ("evidence", "producer_authenticity", "logical_task_identity"),
    ("logical_task_identity", "wait_cause", "critical_path"),
    ("overlap_start_raw", "overlap_end_raw"), ("before_ready_ticks", "after_ready_ticks"),
    ("ready_flags", "record_ordinal"), ("old_thread_id", "record_ordinal"),
    ("payload_tid", "payload_pid", "record_ordinal"),
))
HARD_FAULT_MARKERS = (*FAULT_QUERY_SCHEMAS, *(f'"{key}"' for keys in HARD_FAULT_FIELDS for key in keys))
HANDOFF_FIELDS = tuple(frozenset(keys) for keys in (
    ("study_id", "slots"), ("ticket", "delay_ms"), ("write_brackets", "timer_call"), ("caller_result", "worker_result"),
    ("pid", "process_created"), ("retention", "ticket"), ("plan_sha256", "planned_pairs"), ("planned_arms", "retained_etls"),
    ("etl_sha256", "measurement"), ("wait_dependency", "scheduler_residency"),
    ("candidate_minus_baseline_ns", "order"), ("join_timer_overlap", "work_window_overlap"),
    ("longer", "shorter", "median_ns"), ("frequency", "ticks"), ("planned_pairs", "measured_pairs"),
    ("windows_version", "controller_pointer_bytes"), ("acquisition_id", "outcomes"),
))
HANDOFF_MARKERS = (*HANDOFF_SCHEMAS, *(f'"{key}"' for keys in HANDOFF_FIELDS for key in keys))
DISK_IO_FIELDS = tuple(frozenset(fields) for fields in (
    ("disk_event_ordinal", "record_ordinal"), ("high_res_response_ticks", "reported_issuing_tid"),
    ("longest_response_ties", "initiations", "completions"), ("response_ticks_per_second", "operations"),
    ("decoded_disk_records", "records_seen"), ("cross_provider_join", "device_service_time", "request_generation"),
))
ETL_ROTATION_MARKERS = (*ETL_ROTATION_SCHEMAS, '"expected_inventory_sha256"', '"closed_controller_inventory_verified"',
                        '"final_ordinal"', '"etl_bytes"', '"observed_bytes"')
ETL_ROW_MARKERS = (*TRACE_QUERY_SCHEMAS, *DISK_IO_MARKERS, *HARD_FAULT_MARKERS, *HANDOFF_MARKERS, *ETL_ROTATION_MARKERS, "kn.etl_capability_probe.v1", "saved_etl_probe", '"first_decoded_record"', '"first_payload_sha256"', '"statement_file_sha256"', '"trusted_key_sha256"', '"se_system_profile_privilege_enabled"', '"record_ordinal"', '"reported_etl_sha256"', '"expected_page_sha256"', '"event_keyword_decimal"',
                   '"source_after"', '"header_perf_frequency"', '"start_filetime"', '"sampled_thread_id"', '"paired_record_pid"', '"payload_tid"', '"image_base"',
                   '"recorded_file_name"', '"reported_rva"', '"before_record"', '"switch_ordinal"', '"new_thread_id"',
                   '"elapsed_ticks"', '"ready_records"', '"ready_flags"', '"thread_filter"', '"ready_to_switch_in_ticks"', 'kn.etl_switches.v', 'kn.etl_profile.v4', 'kn.etl_profile.v5', 'kn.etl_profile.v6', 'kn.etl_profile.v7', 'kn.etl_profile.v8',
                   '"profile_sha256"', '"logger_time_us"', '"creation_record"', '"binary_record"', '"byte_relation"',
                   '"load_events"', '"candidate_ranges"', '"method_start"', '"method_offset"', '"reported_clr_relation"', '"load_record"',
                   '"recorded_generation"', '"candidate_pid"', '"parent_pid"', '"start_record"', '"process_start_record"',
                   '"generation_scope"', '"opaque_key_comparison"', '"file_sha256"', '"reference_window"', '"file_location"',
                   '"default_base_relation"', '"file_offset"', '"max_window_bytes"', '"reference_sha256"', '"rsds_guid"', '"pdb_age"',
                   '"marker_count"', '"marker_records"', '"native_rsds"', '"reference_comparison"', '"merge_timestamp_equal"',
                   '"other_opcodes"', '"header_pid_conflicts"', '"group_mask_records"', '"profile_interval_records"',
                   '"group_masks"', '"profile_source_name"', '"payload_bytes"', '"group_mask_bracket"', '"reported_period_100ns"')

DUMP_EVIDENCE_FIELDS = tuple(frozenset(fields) for fields in (
    ("expected_header_sha256", "digest_scope"), ("availability_scope", "range_evidence"),
    ("range_state", "captured_bytes", "unobserved_bytes"), ("range_offset", "state", "span_sha256"),
    ("physical_read_sequence", "native_status_domain", "win32_status"), ("range_offset", "translation_state", "translation_reason"),
    ("purpose", "candidate_levels", "file_offset", "requested_bytes"),
    ("purpose", "candidate_levels", "virtual_address", "requested_bytes"),
    ("parser_accepted", "first_file_sequence", "file_read_count"),
    ("seek_win32_status", "read_win32_status", "hash_input_bytes"),
))
ETL_ROTATION_FIELDS = tuple(frozenset(fields) for fields in (
    ("expected_inventory_sha256", "trusted_key_sha256"), ("ordinal", "etl_bytes", "etl_sha256"),
    ("ordinal", "expected_bytes", "observed_bytes"), ("win32_status", "final_ordinal", "log_buffers_lost"),
    ("contiguous_inventory_verified", "closed_controller_inventory_verified"),
))
DETACHED_FIELD_SETS = WAIT_PLAN_FIELDS + DUMP_EVIDENCE_FIELDS + ETL_ROTATION_FIELDS + tuple(frozenset(fields) for fields in (
    ("captured_sha256", "captured_bytes", "reads", "status"),
    ("observation", "decoded", "unsupported", "first_decoded_record"),
    ("first_payload_bytes", "first_payload_sha256"),
    ("type_guid", "revision", "offset", "length", "sha256"),
    ("notify_type", "creator", "revision", "record_id"),
    ("bank", "status", "valid", "matches_stop_status"),
    ("provider", "channel", "event_record_id", "system_time_utc"),
    ("valid_bits", "physical_address", "physical_address_mask", "error_type"),
    ("relation", "node_indices", "thread_created", "target_tid", "target_created"),
    ("kind", "round", "evidence", "target_tid", "target_created"),
    ("waiter_tid", "waiter_created", "wait_semantics", "target_tid", "target_created"),
    ("sample_ordinal", "record_ordinal", "raw_timestamp", "instruction_pointer", "sampled_thread_id"),
    ("record_ordinal", "raw_timestamp", "event", "payload_pid", "payload_tid"),
    ("relation", "paired_record_pid", "before", "after"),
    ("record_ordinal", "raw_timestamp", "payload_pid", "image_base", "image_size"),
    ("image_checksum", "pe_timestamp", "recorded_file_name"),
    ("relation", "candidate_ranges", "reported_rva", "witnesses"),
    ("before_record", "after_record"),
    ("switch_ordinal", "record_ordinal", "raw_timestamp", "cpu"),
    ("new_thread_id", "old_thread_id", "new_priority", "old_priority"),
    ("new_thread_id", "old_thread_id", "old_wait_reason"),
    ("relation", "elapsed_ticks", "previous_switch"),
    ("relation", "elapsed_ticks", "previous_thread_event"),
    ("relation", "ready_records", "dispatchable_records"),
    ("payload_tid", "ready_flags", "adjust_increment"),
    ("record_ordinal", "raw_timestamp", "logger_id", "payload_tid", "kind"),
    ("thread_filter", "matched_switches"),
    ("ready_to_switch_in_ticks", "switch_out_to_ready_ticks"),
    ("payload_pid", "start_record"),
    ("candidate_pid", "relation", "before_record"),
    ("recorded_generation", "opaque_key_comparison"),
    ("parent_pid", "session_id", "payload_pid", "exit_status"),
    ("relation", "process_start_record", "reported_rva"),
    ("load_events", "rundown_events", "unsupported_events"),
    ("candidate_ranges", "method_offset", "witnesses"),
    ("method_start", "method_id", "module_id"),
    ("reported_clr_relation", "reported_clr_method"),
    ("load_record", "unload_record", "method_offset"),
    ("profile_sha256", "code_log_sha256"), ("logger_time_us", "sampled_pc"), ("creation_record", "mapped_start"),
    ("binary_record", "body_sha256"), ("byte_relation", "code_record_bytes"),
    ("generation_scope", "decoded_events", "defunct_events"),
    ("file_sha256", "file_bytes", "max_window_bytes"),
    ("file_sha256", "file_bytes", "file_name"),
    ("source_sha256", "reference_sha256", "win32_status"),
    ("loader_fields", "file_location", "reference_window"),
    ("image_size", "image_checksum", "default_base_relation"),
    ("file_offset", "byte_count", "sha256"),
    ("rsds_guid", "pdb_age"),
    ("marker_count", "marker_records"),
    ("loader_count", "native_rsds"),
    ("relation", "reference_comparison"),
    ("rsds_guid_equal", "pdb_age_equal"),
    ("other_opcodes", "header_pid_conflicts"),
    ("statement_file_sha256", "trusted_key_sha256"),
    ("role", "se_system_profile_privilege_enabled", "session_id"),
    ("native_schema", "reported_etl_sha256"),
    ("reported_etl_sha256", "file_sha256"),
    ("expected_page_sha256", "replayed_page_sha256"),
    ("source_after", "decoded_samples", "records_seen"),
    ("sequence", "record_ordinal", "tick", "ip"),
    ("kind", "raw_type", "header_perf_frequency"),
    ("start_filetime", "events_lost", "buffers_written"),
    ("group_mask_records", "profile_interval_records"),
    ("group_masks", "kernel_event_version"),
    ("profile_source", "new_interval_raw", "old_interval_raw"),
    ("header_flags", "payload_bytes", "record_ordinal", "raw_timestamp"),
    ("group_mask_bracket",),
    ("reported_period_100ns", "collection_start_record"),
    ("record_ordinal", "header_process_id", "payload_pid", "image_base"),
))
EVIDENCE_OBJECT_START = re.compile(r'(?m)^[ \t,]*(\{)\s*"')
NESTED_EVIDENCE_OBJECT_START = re.compile(r'(\{)\s*"')
JSON_SPACE = re.compile(r'[ \t\r\n]*')


DETACHED_SCHEMAS = (*WAIT_PLAN_SCHEMAS, *DUMP_EVIDENCE_SCHEMAS, *TRACE_QUERY_SCHEMAS, "kn.etl_switches.v1", "kn.etl_switches.v2", "kn.etl_switches.v3",
                    "kn.etl_profile.v4", "kn.etl_profile.v5", "kn.etl_profile.v6", "kn.etl_profile.v7", "kn.etl_profile.v8")


def detached_evidence_object(text, offset, decoder, field_sets, schemas) -> bool:
    # Count keys in one object. Exporters may reorder them or stop during its final value.
    keys = set()
    pos = JSON_SPACE.match(text, offset + 1).end()
    try:
        while text.startswith('"', pos):
            key, pos = decoder.raw_decode(text, pos)
            pos = JSON_SPACE.match(text, pos).end()
            if not text.startswith(":", pos):
                break
            keys.add(key)
            if any(fields <= keys for fields in field_sets):
                return True
            pos = JSON_SPACE.match(text, pos + 1).end()
            value, pos = decoder.raw_decode(text, pos)
            if key == "scope" and value in ("saved_dump_probe", "saved_etl_probe"):
                return True
            if key == "schema" and value in schemas:
                return True
            pos = JSON_SPACE.match(text, pos).end()
            if not text.startswith(",", pos):
                break
            pos = JSON_SPACE.match(text, pos + 1).end()
    except (ValueError, RecursionError):
        pass
    return False


def detached_evidence_line(text: str) -> int | None:
    patterns = [(EVIDENCE_OBJECT_START, DETACHED_FIELD_SETS, DETACHED_SCHEMAS)]
    if any(tag in text for tag in DISK_IO_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, DISK_IO_FIELDS, (DISK_IO_SCHEMA,)))
    if any(tag in text for tag in HARD_FAULT_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, HARD_FAULT_FIELDS, FAULT_QUERY_SCHEMAS))
    if any(tag in text for tag in HANDOFF_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, HANDOFF_FIELDS, HANDOFF_SCHEMAS))
    if any(tag in text for tag in IO_TIMING_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, IO_TIMING_FIELDS, IO_LIFETIME_SCHEMAS))
    if any(tag in text for tag in ETL_ROTATION_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, ETL_ROTATION_FIELDS, ETL_ROTATION_SCHEMAS))
    if any(tag in text for tag in ETL_COMPARISON_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, ETL_COMPARISON_FIELDS, ETL_COMPARISON_SCHEMAS))
    if any(tag in text for tag in DUMP_EVIDENCE_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, DUMP_EVIDENCE_FIELDS, DUMP_EVIDENCE_SCHEMAS))
    if any(tag in text for tag in WAIT_PLAN_MARKERS):
        patterns.append((NESTED_EVIDENCE_OBJECT_START, WAIT_PLAN_FIELDS, WAIT_PLAN_SCHEMAS))
    decoder = json.JSONDecoder()
    for pattern, fields, schemas in patterns:
        for match in pattern.finditer(text):
            offset = match.start(1)
            if detached_evidence_object(text, offset, decoder, fields, schemas):
                return text.count("\n", 0, offset) + 1
    return None


def inspect(name: str, data: bytes, allow_private_symbols: bool = False) -> list[dict]:
    findings = []
    reported_name = name
    for pattern in RULES.values():
        reported_name = pattern.sub("[redacted]", reported_name)
    def add(rule: str, line: int | None = None) -> None:
        item = {"path": reported_name, "rule": rule, "line": line}
        if item not in findings:
            findings.append(item)
    if reported_name != name:
        add("sensitive-filename")
    bad_path = path_rule(name)
    if bad_path:
        add(bad_path)
    # A partially written or renamed acquisition still contains private executable and process evidence.
    if data.startswith(b"KNETLBC1") or (data.startswith(b"PK\x03\x04") and data.startswith((b"owned-module-manifest.json", b"handoff-plan.json"), 30)):
        add("private-benchmark-package")
        return findings
    if any(data.startswith(arch + tag) for arch in (b"x64\0", b"ia32\0", b"arm64\0") for tag in (b"C", b"M", b"G")):
        add("private-v8-code-log")
        return findings
    # ETL's first WMI buffer may contain a 32- or 64-bit system trace header.
    # Check the header buffer type and the Trace/Header record together.
    if (len(data) >= 80 and data[54:56] == b"\x04\x00" and
            data[74:76] in (b"\x01\xc0", b"\x02\xc0") and data[78:80] == b"\x00\x00" and
            512 <= int.from_bytes(data[:4], "little") <= 16 << 20):
        add("private-etl-buffer")
        return findings
    if data.startswith((b"PAGEDU64", b"PAGEDUMP")) and (len(data) == 8 or b"\0" in data[8:256]):
        add("private-crash-dump")
        return findings
    if data.startswith(b"CPER") and ((len(data) <= 10 and bytes.fromhex("1002ffffffff").startswith(data[4:])) or
                                     b"\0" in data[4:128] or data[6:10] == b"\xff" * 4):
        add("private-whea-record")
        return findings
    trace_header = b"KNIT\x01\x00\x00\x00\x88\x02\x00\x00"
    if data.startswith(b"KNIT") and (trace_header.startswith(data) or b"\0" in data[4:64]):
        add("private-pending-io-trace")
        return findings
    if data.startswith(b"KNSYMIDX"):
        add("private-symbol-index")
    if data.startswith(b"KNMCPJ1\0"):
        add("private-operation-journal")
    private_symbols = Path(name).suffix.lower() == ".pdb"
    if private_symbols and not allow_private_symbols:
        add("private-symbol-file")
    binary = b"\0" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff"))
    if ((data.startswith(b"SQLite format 3\0") and data[68:72] == b"KNMC") or
            (binary and any(marker in data for marker in (b'{"schema":"kn.owned_module_plan.v1",',
                                                         b'{"schema":"kn.owned_module_plan.v2",',
                                                         b'{"schema":"kn.owned_module_attempt_receipt.v1",')))):
        add("private-benchmark-campaign")
        return findings
    view = data
    if binary:
        # Some Windows exporters omit the UTF-16 BOM. Keep the original bytes for binary rules.
        for encoding, lane, bom in (("utf-16-le", 1, b"\xff\xfe"), ("utf-16-be", 0, b"\xfe\xff")):
            prefix = data[lane:128:2]
            if (len(prefix) >= 8 and prefix.count(0) * 4 >= len(prefix) * 3 and
                    any(tag.encode(encoding) in data for tag in ("kn.crash_diagnosis.v", "kn.whea_event_comparison.v1", "kn.pending_io_trace.v1", "kn.etl_profile.v", "kn.etl_switches.v",
                                                                  "kn.wait_", "ey", "ew", "Files Processed:", *IO_TIMING_MARKERS, *ETL_COMPARISON_MARKERS, *ETL_ROW_MARKERS, *DUMP_EVIDENCE_MARKERS, *WAIT_PLAN_MARKERS, '"target_created"', '"begin_qpc"',
                                                                 "KNDBG_GAME_MANIFEST", "game_reported_registry_slot_v1", "v8-version,", "code-creation,", "tick,0x", "code-move,", "code-delete,", "code-source-info,", "code-disassemble,", "Provider", '"system_time_utc"', '"virtual"', '"captured_sha256"', '"type_guid"',
                                                                  '"notify_type"', '"matches_stop_status"', '"physical_address_mask"'))):
                view = bom + data
                break
    for text in text_views(view):
        if "Files Processed:" in text and re.search(r"(?m)^[ \t]*Files Processed:\r?\n[ \t]+(?:[^\r\n]+\.etl(?:\r?$)|[^\r\n]+\r?\nTotal Buffers Processed[ \t]+[0-9]+)", text, re.I):
            add("private-tracerpt-summary")
        if "KNDBG_GAME_MANIFEST" in text and re.search(r"(?m)^[ \t]*KNDBG_GAME_MANIFEST[ \t]+[12][ \t]*\r?$", text):
            add("private-game-manifest")
        if "game_reported_registry_slot_v1" in text and re.search(r'(?m)^[ \t]*(?:[\[{][^\r\n]*)?"lifetime_source"\s*:\s*"game_reported_registry_slot_v1"', text):
            add("private-evidence-bundle")
        if (not binary or view is not data) and V8_RAW_RECORD.search(text):
            add("private-v8-profile")
        if (not binary or view is not data) and ("ey" in text or "ew" in text):
            offset = capture_jws_offset(text)
            if offset is not None:
                add("private-evidence-bundle", text.count("\n", 0, offset) + 1)
        if (not binary or view is not data) and "Provider" in text and ("Microsoft-Windows-WHEA-Logger" in text or
                "c26c4f3c-3f66-4e99-8f8a-39405cfed220" in text.lower()):
            # Preserve exported Windows Event XML even after renaming or adding a log banner.
            if re.search(r'(?im)(?:^|>)[ \t\r\n]*<(?:[\w.-]+:)?(?:Event|Provider)\b', text) and re.search(
                    r'''(?is)<(?:[\w.-]+:)?Provider\b[^<>]*\b(?:Name|Guid)\s*=\s*["'](?:Microsoft-Windows-WHEA-Logger|\{c26c4f3c-3f66-4e99-8f8a-39405cfed220\})["']''', text):
                add("private-whea-event")
        if (not binary or view is not data) and any(m in text for m in (
                "saved_etl_probe", "kn.etl_capability_probe.v1", "saved_dump_probe", "kn.dump_capability_probe.v1")):
            # Outer scope and detached probe metadata can survive a truncated export.
            marker = re.search(r'(?m)^[ \t]*(?:\{[^\r\n]*?)?"(?:scope"\s*:\s*"saved_(?:etl|dump)_probe|schema"\s*:\s*"kn\.(?:etl|dump)_capability_probe\.v1)"', text)
            if marker:
                add("private-runtime-probe", text.count("\n", 0, marker.start()) + 1)
        # Capture contents remain private even if the extension was changed.
        if text.lstrip().startswith("{"):
            try:
                document = json.loads(text)
                schema = document.get("schema") if isinstance(document, dict) else None
                if (schema == "kn.capabilities.v1" and
                        (document.get("target_probed") is not False or document.get("scope") in ("runtime_probe", "saved_etl_probe", "saved_dump_probe") or "probe" in document)):
                    add("private-runtime-probe")
                if isinstance(schema, str) and (schema in BENCHMARK_RECORD_SCHEMAS or schema in {
                    "kmon.bundle.v1", "kmon.bundle.v2", "kmon.evidence.v1", "kmon.evidence.v2", "kn.temporal_facts.v1", "kmon.evidence_session.v1",
                    "kn.evidence_inventory.v1", "kn.evidence_inventory_chunk.v1", "kn.observation_read.v1", "kn.read_set.v1", "kn.type_schema.v1",
                    "kn.evidence_session.v1", "kn.evidence_journal_segment.v1", "kn.evidence_journal_recovery.v1",
                    "kn.evidence_journal_index.v1", "kn.evidence_journal_index_chunk.v1", "kn.evidence_store_inventory.v1",
                    "kn.evidence_gc_policy.v1", "kn.evidence_gc_operation.v1", "kn.evidence_gc_intent.v1", "kn.evidence_gc_receipt.v1", "kn.evidence_gc_result.v1", "kn.image_retention.v1", "kn.evidence_private_store.v1", "kn.evidence_privacy.v1",
                    "kn.minimized_image_facts.v1", "kn.redaction_manifest.v1", "kn.disclosure_package.v1", "kn.disclosure_review.v1", "kn.disclosure_transfer_intent.v1", "kn.disclosure_transfer_result.v1",
                    "kn.irp_capture.v1", "kn.irp_capture.v2", "kn.irp_replay.v1", "kn.irp_capture_session.v1", "kn.irp_retention.v1", "kn.irp_retention_keys.v1", "kn.irp_claim_report.v1", "kn.irp_claim_publication.v1", "kn.routed_reads.v1", "kn.image_reads.v1", "kn.image_reads.v2", "kn.image_reads.v3", "kn.image_read_session.v1",
                    "kn.image_slice.v1", "kn.image_slice.v2", "kn.image_slice_proof.v1", "kn.image_slice_inputs.v1", "kn.image_slice_replay.v1",
                    "kn.image_sweep.v1", "kn.image_sweep_replay.v1", "kn.image_sweep_proof.v1", "kn.image_sweep_graph.v1",
                    "kn.translation_receipt.v1", "kn.dump_read.v1", "kn.dump_read.v2", "kn.dump_initialization.v1", "kn.crash_diagnosis.v1", "kn.crash_diagnosis.v2", "kn.whea_event_comparison.v1",
                    "kn.authorized_image_changes.v1", "kn.image_approval_policy.v1", "kn.image_change_assessment.v1", "kn.image_scope_change_assessment.v1", "kn.image_scope_approval_publication.v1", "kn.image_scope_approval_collection.v1", "kn.image_scope_approval_replay.v1", "kn.image_scope_approval_session.v1", "kn.image_approval_publication.v1", "kn.image_approval_replay.v1", "kn.image_approval_collection.v1", "kn.image_approval_session.v1", "kn.image_recipe.v1", "kn.image_recipe.v2", "kn.image_recipe.v3", "kn.process_image_mappings.v1", "kn.process_image_mapping_assessment.v1", "kn.image_replay.v1", "kn.image_capture.v1", "kn.image_capture.v2", "kn.image_capture.v3", "kn.image_capture_collection.v1", "kn.image_capture_session.v1", "kn.image_proof.v1", "kn.image_claim_report.v1", "kn.image_claim_publication.v1", "kn.image_scope_claim_publication.v1", "kn.capture_scheduling.v1", "kn.reference_scheduling.v1", "kn.reference_scheduler_test.v1", "kn.image_scheduling.v1", "kn.image_scheduler_test.v1", "kn.discovery_scheduling.v1", "kn.discovery_scheduler_test.v1", "kn.discovery_scheduler_fixtures.v1", "kn.user_inventory.v1", "kn.user_module_observation_debt.v1", "kn.owned_module_workload.v1", "kn.user_inventory_test.v1", "kn.user_inventory_fixtures.v1", "kn.user_deep_scheduling.v1", "kn.user_deep_test.v1", "kn.user_deep_fixtures.v1", "kn.analysis_scheduling.v1", "kn.analysis_scheduler_test.v1", "kn.analysis_scheduler_fixtures.v1", "kn.publication_scheduling.v1", "kn.publication_timing.v1", "kn.collection_timing.v1", "kn.publication_picker_test.v1", "kn.publication_writer_test.v1", "kn.layout_collection_scheduling.v1", "kn.layout_verification_scheduling.v1", "kn.layout_scheduler_test.v1", "kn.layout_scheduling_fixture.v1", "kn.image_reference_preparation.v1", "kn.image_preparation_test.v1", "kn.image_preparation_core.v1",
                    "kn.evidence_graph.v1", "kn-live-dbg.hidden-process.v1", "kn.execution_evidence.v1", "kn.irp_observation.v1",
                    "kn.execution_trace.v1", "kn.execution_trace_query.v1", *TRACE_QUERY_SCHEMAS, "kn.etl_profile.v1", "kn.etl_profile.v2", "kn.etl_profile.v3", "kn.etl_profile.v4", "kn.etl_profile.v5", "kn.etl_profile.v6", "kn.etl_profile.v7", "kn.etl_profile.v8", "kn.etl_switches.v1", "kn.etl_switches.v2", "kn.etl_switches.v3", "kn.mcp_operation.v1",
                    *IO_LIFETIME_SCHEMAS, "kn.pending_io_trace.v1",
                    "kn.wait_chain.v1", "kn.wait_assessment.v1", "kn.wait_series.v1", "kn.wait_series_assessment.v1", "kn.wait_diagnosis.v1", *WAIT_PLAN_SCHEMAS,
                    "kn.benchmark_corpus.v1", "kn.benchmark_results.v1", "kn.benchmark_report.v1"
                }):
                    add("private-evidence-bundle")
            except (ValueError, RecursionError):
                pass
        # Reports can be logged with a preamble, reordered by a JSON exporter or cut during a write.
        if ((not binary or view is not data) and ("kn.io_lifetime" in text or "kn.pending_io_trace" in text or "kn.crash_diagnosis" in text or "kn.whea_event_comparison" in text or "kn.etl_profile" in text or "kn.etl_switches" in text or any(tag in text for tag in TRACE_QUERY_SCHEMAS)) and
                not any(f["rule"] == "private-evidence-bundle" for f in findings)):
            marker = re.search(r'(?m)^[ \t]*\{\s*"schema"\s*:\s*"kn\.(?:io_lifetime(?:_assessment|_timing)?\.v1|pending_io_trace\.v1|crash_diagnosis\.v[12]|whea_event_comparison\.v1|v8_profile_query\.v1|etl_profile\.v[12345678]|etl_switches\.v[123]|etl_disk_io\.v1|etl_hard_faults\.v[123]|etl_activity_markers\.v1|etl_activity_comparison(?:_receipt)?\.v[12]|traceprocessor_activity_rows\.v1|owned_etl_handoff\.v1|etl_handoff_(?:plan|capture|study)(?:_receipt)?\.v1|execution_trace_query\.v2|etl_page_replay\.v[12]|etl_capture_statement\.v1|etl_rotation_(?:set|inventory)\.v1)"\s*(?:[,}]|$)', text)
            if marker:
                add("private-evidence-bundle", text.count("\n", 0, marker.start()) + 1)
            else:
                for number, line in enumerate(text.splitlines(), 1):
                    if not line.lstrip().startswith("{") or not ("kn.io_lifetime" in line or "kn.pending_io_trace" in line or "kn.crash_diagnosis" in line or "kn.whea_event_comparison" in line or "kn.etl_profile" in line or "kn.etl_switches" in line or any(tag in line for tag in TRACE_QUERY_SCHEMAS)):
                        continue
                    try:
                        row = json.loads(line)
                    except (ValueError, RecursionError):
                        continue
                    if isinstance(row, dict) and row.get("schema") in (*TRACE_QUERY_SCHEMAS, *IO_LIFETIME_SCHEMAS, "kn.pending_io_trace.v1", "kn.crash_diagnosis.v1", "kn.crash_diagnosis.v2", "kn.whea_event_comparison.v1", "kn.etl_profile.v1", "kn.etl_profile.v2", "kn.etl_profile.v3", "kn.etl_profile.v4", "kn.etl_profile.v5", "kn.etl_profile.v6", "kn.etl_profile.v7", "kn.etl_profile.v8", "kn.etl_switches.v1", "kn.etl_switches.v2", "kn.etl_switches.v3"):
                        add("private-evidence-bundle", number)
                        break
        if ((not binary or view is not data) and '"virtual"' in text and
                not any(f["rule"] == "private-evidence-bundle" for f in findings)):
            frame = re.search(r'(?m)^[ \t,]*\{\s*"ip"\s*:\s*"0x[0-9a-f]+"\s*,\s*"sp"\s*:\s*"0x[0-9a-f]+"'
                              r'\s*,\s*"return"\s*:\s*"0x[0-9a-f]+"\s*,\s*"virtual"\s*:\s*(?:true|false)\s*,\s*"module"\s*:', text)
            if frame:
                add("private-evidence-bundle", text.count("\n", 0, frame.start()) + 1)
        if (not binary or view is not data) and any(key in text for key in
                ('"captured_sha256"', '"type_guid"', '"notify_type"', '"matches_stop_status"', '"physical_address_mask"', '"system_time_utc"', '"target_created"', *ETL_ROW_MARKERS, *DUMP_EVIDENCE_MARKERS, *WAIT_PLAN_MARKERS, *ETL_COMPARISON_MARKERS, *IO_TIMING_MARKERS)):
            line = detached_evidence_line(text)
            if line is not None:
                add("private-evidence-bundle", line)
        # WCT output may be redirected or cut between individually flushed rounds.
        if (not binary or view is not data) and ("kn.wait_" in text or '"begin_qpc"' in text) and not any(f["rule"] == "private-evidence-bundle" for f in findings):
            record = re.search(r'(?m)^[ \t]*\{\s*"schema"\s*:\s*"kn\.wait_(?:chain|assessment|diagnosis|series(?:_assessment)?)\.v1"\s*(?:[,}]|$)', text)
            if not record:
                record = re.search(r'(?m)^[ \t]*,?[ \t]*\{[ \t]*"pause"\s*:[^\r\n]*?"receipt"\s*:\s*'
                                   r'\{\s*"schema"\s*:\s*"kn\.wait_chain\.v1"', text)
            if not record and '"begin_qpc"' in text:
                record = re.search(r'(?m)^[ \t]*,?[ \t]*\{[ \t]*"pause"\s*:\s*(?:null|\{[^\r\n]*?\})\s*,\s*'
                                   r'"begin_qpc"\s*:\s*(?:null|"[0-9]+")\s*,\s*"end_qpc"\s*:', text)
            if record:
                add("private-evidence-bundle", text.count("\n", 0, record.start()) + 1)
        # The workload emits one tagged object per reply. A transcript can
        # include multiple replies, a log banner or a partially written tail.
        if not binary and "kn.owned_module_" in text and not any(f["rule"] == "private-evidence-bundle" for f in findings):
            partial = BENCHMARK_RECORD_START.search(text)
            if partial:
                add("private-evidence-bundle", text.count("\n", 0, partial.start()) + 1)
        if not binary and "kn.owned_module_workload.v1" in text and not any(f["rule"] == "private-evidence-bundle" for f in findings):
            record = re.search(r'(?m)^[ \t]*\{[ \t]*"schema"[ \t]*:[ \t]*"kn\.owned_module_workload\.v1"[ \t]*,'
                               r'[ \t]*"(?:payload|passed)"[ \t]*:[ \t]*(?:\{|true\b|false\b)', text)
            if record:
                add("private-evidence-bundle", text.count("\n", 0, record.start()) + 1)
        for rule, pattern in RULES.items():
            for match in pattern.finditer(text):
                add(rule, None if binary else text.count("\n", 0, match.start()) + 1)
        if RSA_XML.search(text):
            add("private-rsa-xml")
        for match in ENV_SECRET.finditer(text):
            value = match[1].strip().strip("\"'")
            if value not in PLACEHOLDERS:
                add("environment-secret", None if binary else text.count("\n", 0, match.start()) + 1)
        for match in PROFILE_PATH.finditer(text):
            if match[1].lower() not in EXAMPLE_USERS and not (private_symbols and allow_private_symbols):
                add("personal-profile-path", None if binary else text.count("\n", 0, match.start()) + 1)
    return findings


def git(root: Path, *args: str) -> bytes:
    # Do not copy stderr, which may contain private paths or credentials, into a report.
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def is_reparse(file: Path) -> bool:
    return file.is_symlink() or bool(getattr(file.lstat(), "st_file_attributes", 0) &
                                    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def inputs(root: Path, index: bool, tree: bool):
    if tree:
        for file in sorted(root.rglob("*")):
            if is_reparse(file):
                raise ValueError("reparse point in package input")
            if file.is_file():
                yield file.relative_to(root).as_posix(), file.read_bytes()
    elif index:
        for entry in git(root, "ls-files", "--stage", "-z").split(b"\0"):
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            mode, oid, stage = metadata.split()
            if stage != b"0" or mode not in (b"100644", b"100755"):
                raise ValueError("unmerged or non-regular index input")
            yield name.decode("utf-8"), git(root, "cat-file", "blob", oid.decode("ascii"))
    else:
        names = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
        for name in sorted(set(names.decode("utf-8").split("\0")) - {""}):
            file = root / name
            if not file.exists() and not file.is_symlink():
                continue  # tracked deletion in the current working tree
            if any(is_reparse(p) for p in (file, *file.parents) if p != root and root in p.parents) or not file.resolve().is_relative_to(root):
                raise ValueError("reparse point in working-tree input")
            if file.is_file():
                yield name, file.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--index", action="store_true")
    mode.add_argument("--tree", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--allow-private-symbols", action="store_true",
                        help="permit PDB files and their source-path metadata; still check credentials")
    args = parser.parse_args()
    result = {"mode": "tree" if args.tree else "index" if args.index else "working-tree",
              "files": 0, "bytes": 0, "findings": []}
    try:
        if not args.root.is_dir():
            raise ValueError("input root is not a directory")
        for name, data in inputs(args.root.resolve(), args.index, args.tree):
            result["files"] += 1
            result["bytes"] += len(data)
            result["findings"].extend(inspect(name, data, args.allow_private_symbols))
        if args.tree and result["files"] == 0:
            raise ValueError("empty package input")
    except (OSError, ValueError, subprocess.CalledProcessError):
        # Never report success after an unreadable/unsupported input.
        print("Public-content check failed: an input could not be inspected.")
        return 2
    result["passed"] = not result["findings"]
    rendered = json.dumps(result, ensure_ascii=True, indent=2) + "\n"
    if args.report:
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
