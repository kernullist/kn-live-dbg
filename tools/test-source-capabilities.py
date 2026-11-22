"""Check compiled capability claims without starting a live controller."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    exe = str(args.exe.resolve())
    result = subprocess.run([exe, "--capabilities"], capture_output=True, text=True,
                            check=True, timeout=30)
    data = json.loads(result.stdout)
    assert data["schema"] == "kn.capabilities.v1"
    assert data["scope"] == "compiled_contract" and data["target_probed"] is False
    assert data["inventory_complete"] is False
    assert data["target"] == {"os_build": None, "security_state": "unknown",
                              "virtual_address_bits": None, "validation": "not_performed"}
    root = Path(__file__).resolve().parents[1]
    abi = re.search(r"#define KNDBG_ABI_VERSION (\d+)u",
                    (root / "shared/KnLiveDbgIoctl.h").read_text()).group(1)
    assert data["driver_abi"] == int(abi)
    keys = [(c["domain"], c["operation"], c["backend"]) for c in data["capabilities"]]
    assert len(set(keys)) == len(keys)
    temporal = next(c for c in data["capabilities"] if (c["domain"], c["operation"], c["backend"]) == ("evidence", "temporal_graph", "bundle"))
    assert temporal["consistency"] == "recorded_local_collector_scope" and "origin_bound_kncase_v2" in temporal["requirements"]
    assert "no_cross_collector_bridge" in temporal["limits"] and temporal["availability"] == "not_probed"
    for capability in data["capabilities"]:
        assert capability["availability"] == "not_probed"
        assert capability["availability_scope"] == "none"
        assert capability["address_contract"]
        assert capability["validation"] == "not_performed_for_target_environment"
        assert capability["probe_stages"] == {
            "source_opened": "not_probed", "sample_read": "not_probed", "layout_qualified": "not_probed",
            "semantic_validation": "not_probed", "environment_regression": "not_performed"}
        assert capability["requirements"] and capability["limits"]
    by_key = dict(zip(keys, data["capabilities"]))
    game = by_key[("objects", "game_object_lifetime", "game_build_manifest")]
    assert game["consistency"] == "game_reported_two_observations"
    assert "stable_even_publication_before_and_after" in game["requirements"] and "expected_container_and_member" in game["requirements"]
    assert "no_independent_lifetime_or_execution" in game["limits"]
    crash = by_key[("diagnostics", "crash_diagnosis", "dbgeng_dump")]
    assert crash["consistency"] == "pinned_offline_dump" and "typed_bugcheck_and_stack" in crash["requirements"]
    assert "optional_stop_parameter_2_cper" in crash["requirements"] and "cper_1MiB_128_sections_512_reads" in crash["limits"]
    assert "optional_separately_pinned_whea_event_xml" in crash["requirements"] and "event_xml_8MiB_4096_nodes" in crash["limits"]
    assert crash["address_contract"] == "typed_amd64_saved_context;no_arbitrary_address_input"
    assert "no_host_crash_or_culprit_attribution" in crash["limits"]
    reference_scheduler = by_key[("scheduler", "reference_admission", "native")]
    assert "confirmed_live_source_for_dispatch" in reference_scheduler["requirements"]
    assert "admitted_subject_role_round_robin" in reference_scheduler["limits"]
    assert "attempt_cooldown_not_success_revisit" in reference_scheduler["limits"]
    assert "no_deferred_rediscovery_hard_deadline_or_measured_slo" in reference_scheduler["limits"]
    image_scheduler = by_key[("scheduler", "image_observation", "native")]
    assert "confirmed_live_source_for_continuations" in image_scheduler["requirements"]
    assert "attempt_slice_traversal_and_gap_free_separate" in image_scheduler["limits"]
    assert "cooperative_25ms_includes_lookup" in image_scheduler["limits"]
    assert "minimum_page_and_final_fences_may_overrun" in image_scheduler["limits"]
    publication = by_key[("scheduler", "publication", "native")]
    analysis = by_key[("scheduler", "analysis", "native")]
    discovery = by_key[("scheduler", "discovery", "native")]
    assert "live_binding_readiness" in discovery["requirements"]
    assert "ten_group_26_phase_rotation" in discovery["limits"]
    assert "midcycle_requests_retained" in discovery["limits"]
    assert "cycle_due_debt_not_target_success" in discovery["limits"]
    assert "continued_phase_once_per_turn" in discovery["limits"]
    assert "user_inventory_32_steps_25ms" in discovery["limits"]
    assert "capped_inventory_rotating_deep_slot" in discovery["limits"] and "frozen_pid_lap" in discovery["limits"]
    assert "generation_fenced_toolhelp_module_debt" in discovery["limits"]
    assert "one_selected_deep_target_per_turn" in discovery["limits"]
    assert "cohort_tail_survives_target_faults" in discovery["limits"]
    assert "stage_specific_live_source_gates" in analysis["requirements"]
    assert "nine_stage_persistent_rotation" in analysis["limits"]
    assert "cooperative_250ms_turn_100ms_maximum_slice" in analysis["limits"]
    assert "first_observed_continuous_backlog_not_target_freshness" in analysis["limits"]
    assert "explicit_local_acquisition_window_for_end_to_end_samples" in publication["requirements"]
    assert "file_and_journal_success_separate" in publication["limits"]
    assert "unknown_historical_acquisition_excluded" in publication["limits"]
    layout_scheduler = by_key[("scheduler", "layout", "native")]
    assert "original_candidate_clock" in layout_scheduler["requirements"]
    assert "original_pending_and_expiry_preserved" in layout_scheduler["limits"]
    assert "mapping_not_byte_success" in layout_scheduler["limits"]
    preparation = by_key[("scheduler", "image_reference_preparation", "native")]
    assert "matching_work_episode_on_application" in preparation["requirements"]
    assert "preparation_not_live_verification" in preparation["limits"]
    assert "cooperative_cancellation_and_actual_join" in preparation["limits"]
    assert "pe_metadata_and_sweep_ranges_only" in preparation["limits"]
    assert "per_slice_content_preparation_separate" in preparation["limits"]
    assert "final_fences_remain_synchronous" in preparation["limits"]
    content = by_key[("scheduler", "image_content_preparation", "native")]
    assert "single_comparison_source_lease" in content["requirements"]
    assert "final_content_and_target_fences_preserved" in content["limits"]
    assert "source_lease_released_before_publication" in content["limits"]
    policy = by_key[("session", "mutation_gate", "native")]
    assert "default_write_denied_driver_flag" in policy["requirements"]
    assert "confirmed_session_status" in policy["requirements"]
    assert "not_an_observe_collect_partition" in policy["limits"]
    assert by_key[("security", "inspect_vtl1_memory", "native")]["implementation"] == "unsupported"
    assert by_key[("io", "interpose_dispatch", "native")]["implementation"] == "experimental"
    assert "image_verification_not_replayed" in by_key[("evidence", "replay", "bundle")]["limits"]
    assert "single_bundle_fact_graph" in by_key[("evidence", "graph", "bundle")]["limits"]
    assert "graph_and_query_bound_cursor" in by_key[("evidence", "graph", "bundle")]["requirements"]
    sweep_graph = by_key[("evidence", "graph", "recipe")]
    assert "successful_original_slice_replay" in sweep_graph["requirements"]
    assert "no_execution_or_cross_bundle_lifetime_join" in sweep_graph["limits"]
    assert "query_budget_excludes_replay" in sweep_graph["limits"]
    dump_requirements = by_key[("memory", "read_virtual", "dump")]["requirements"]
    assert "qualified_paging_depth" in dump_requirements and "optional_initialization_file_read_receipts" in dump_requirements
    assert "not_captured_vs_not_present" in by_key[("memory", "read_virtual", "dump")]["limits"]
    schema = by_key[("schema", "export_type", "local_pdb")]
    assert "exact_amd64_image_pdb_identity" in schema["requirements"]
    assert "cli_parser_process_containment" in schema["limits"] and "no_runtime_qualification" in schema["limits"]
    assert "other_symbol_paths_not_isolated" in schema["limits"] and "no_filesystem_or_network_sandbox" in schema["limits"]
    assert "exact_reference_blob" in by_key[("image", "replay_verification", "recipe")]["requirements"]
    approval = by_key[("image", "assess_changes", "recipe")]
    assert approval["consistency"] == "recorded_direct_range" and "separate_policy_sha256_anchor" in approval["requirements"]
    assert "no_fixup_overlap" in approval["limits"] and "caller_policy_not_signature_authentication" in approval["limits"]
    scope_approval = by_key[("image", "assess_scope_changes", "recipe")]
    assert scope_approval["consistency"] == "recorded_slice_or_temporal_sweep"
    assert "all_observation_and_evaluation_times" in scope_approval["requirements"] and "per_part_recipe_provenance" in scope_approval["requirements"]
    assert "16384_pages_2048_slices" in scope_approval["limits"] and "no_fixup_overlap" in scope_approval["limits"]
    journal = by_key[("evidence", "journal", "local_files")]
    assert journal["availability"] == "not_probed" and journal["consistency"] == "verified_committed_prefix"
    assert "exact_file_hashes" in journal["requirements"] and "no_gc_or_global_retention" in journal["limits"]
    assert "image_v1_image_irp_v2_image_claim_irp_v3_or_image_irp_claim_v4_policy" in journal["requirements"] and "irp_ledger_before_closure" in journal["requirements"]
    assert "direct_image_collection_v1_policy" in journal["requirements"]
    assert "approved_image_collection_v1_policy" in journal["requirements"]
    assert "approved_image_scope_collection_v1_policy" in journal["requirements"]
    assert "exact_declared_input_closure" in by_key[("evidence", "journal_image_scope_approval", "local_files")]["requirements"]
    assert "no_ambient_input_fallback" in by_key[("image", "replay_scope_approval", "recipe")]["limits"]
    assert "five_exact_members" in by_key[("evidence", "journal_image_approval", "local_files")]["requirements"]
    assert "no_self_appointed_trust" in by_key[("image", "replay_approval", "recipe")]["limits"]
    direct = by_key[("evidence", "journal_image", "local_files")]
    assert direct["consistency"] == "one_archived_capture" and "initialized_private_store" in direct["requirements"]
    assert "membership_separate_from_semantic_replay" in direct["limits"] and "one_capture_per_collection" in direct["limits"]
    store = by_key[("evidence", "store", "local_files")]
    assert store["availability"] == "not_probed" and store["consistency"] == "coordinated_stopped_store"
    assert "participating_publishers" in store["requirements"] and "no_deletion_authority_or_disk_allocation" in store["limits"]
    assert "image_folders_and_reserved_irp_root_namespace" in store["limits"]
    gc = by_key[("evidence", "gc", "local_files")]
    assert gc["availability"] == "not_probed" and "durable_intent_before_delete" in gc["requirements"]
    assert "committed_roots_and_failure_ledgers_protected" in gc["limits"]
    assert "uncommitted_image_and_irp_artifacts_only" in gc["limits"]
    retention = by_key[("evidence", "retention", "native")]
    privacy = by_key[("evidence", "privacy", "local_files")]
    disclosure = by_key[("evidence", "disclosure", "local_files")]
    assert disclosure["availability"] == "not_probed" and disclosure["consistency"] == "reviewed_historical_image_counts"
    assert "durable_intent_before_http" in disclosure["requirements"] and "no_raw_capture_transfer" in disclosure["limits"]
    catalog_scan = by_key[("evidence", "store_catalog_scan", "local_files")]
    assert "original_journal_and_member_reads" in catalog_scan["requirements"]
    assert "page_results_historical" in catalog_scan["limits"] and "no_deletion_authority" in catalog_scan["limits"]
    irp_disclosure = by_key[("evidence", "disclosure_irp", "local_files")]
    assert irp_disclosure["availability"] == "not_probed" and irp_disclosure["consistency"] == "reviewed_historical_irp_counts"
    assert "reproduce_embedded_claims" in irp_disclosure["requirements"] and "supplied_thread_inventory_only" in irp_disclosure["limits"]
    assert privacy["availability"] == "not_probed" and privacy["consistency"] == "observed_os_access_controls"
    assert "efs_default" in privacy["requirements"] and "no_transfer_authority" in privacy["limits"]
    assert retention["availability"] == "not_probed" and retention["consistency"] == "recording_session_partitions"
    assert "complete_journal_batch_before_repeat_demotion" in retention["requirements"] and "image_pipeline_only" in retention["limits"]
    irp_retention = by_key[("evidence", "retention_irp", "native")]
    assert "reference_and_journal_before_repeat_demotion" in irp_retention["requirements"]
    assert "unavailable_capture_denominator" in irp_retention["requirements"] and "4_slots_240MiB_reserved" in irp_retention["limits"]
    irp_claims = by_key[("evidence", "claims_irp", "capture")]
    assert "seven_ledgers" in irp_claims["requirements"] and "single_capture_evidence" in irp_claims["requirements"]
    assert "omitted_denominator" in irp_claims["limits"] and irp_claims["availability"] == "not_probed"
    assert "writer_original_claim_publication" in irp_claims["requirements"]
    assert "raw_fallback_and_unavailable_counter" in irp_claims["limits"]
    irp_replay = by_key[("evidence", "replay_irp", "local_files")]
    assert "irp_claim_publication_v1" in irp_replay["requirements"]
    assert "current_flag_skips_original_claim_reproduction" in irp_replay["limits"]
    assert "direct_mapping_basis" in by_key[("image", "capture_verification", "dump")]["limits"]
    live_image = by_key[("image", "capture_verification", "process_handle")]
    assert "explicit_residency_consent" in live_image["requirements"] and "no_native_fallback" in live_image["limits"]
    assert "v3_original_before_after_final_mapping_queries" in live_image["requirements"]
    assert "mapping_conflict_and_failure_gate" in live_image["requirements"]
    assert "64_reads_192_mapping_observations_384_queries" in live_image["limits"]
    assert "no_mapping_lifetime_aba_backing_or_execution_claim" in live_image["limits"]
    assert "claim_specific_requirements" in by_key[("proof", "image_range", "recipe")]["requirements"]
    image_claims = by_key[("proof", "image_range", "recipe")]
    assert "common_claim_registry_v1" in image_claims["requirements"] and "seven_ledgers" in image_claims["requirements"]
    assert "per_original_policy_partitions" in image_claims["limits"] and "original_claim_reproduction_requires_publication" in image_claims["limits"]
    assert "collection_membership_separate" in image_claims["limits"]
    assert "slice_sweep_2Mi_UTF16_units" in image_claims["limits"]
    wait = by_key[("diagnostics", "wait_chain", "windows_wct")]
    assert wait["availability"] == "not_probed" and wait["consistency"] == "one_live_traversal"
    assert wait["address_contract"] == "not_an_address_reader"
    assert "requested_process_and_thread_creation" in wait["requirements"] and "no_timeout_or_deadlock_proof" in wait["limits"]
    life = by_key[("diagnostics", "io_request_lifetime", "win32_directory_changes")]
    assert life["consistency"] == "retained_overlapped_request" and life["address_contract"] == "not_an_address_reader"
    assert "per_generation_manual_reset_event" in life["requirements"] and "no_kernel_dispatch_identity" in life["limits"]
    repeat = by_key[("diagnostics", "wait_cycle_corroboration", "windows_wct")]
    assert repeat["consistency"] == "paired_live_traversals" and repeat["address_contract"] == "not_an_address_reader"
    assert "measured_qpc_overlap" in repeat["requirements"] and "gaps_and_missing_roots_in_denominator" in repeat["limits"]
    image_replay = by_key[("image", "replay_verification", "recipe")]
    assert "exact_recorded_claim_reproduction" in image_replay["requirements"] and "legacy_claim_not_recorded" in image_replay["limits"]
    assert "no_hard_deadline_or_measured_slo" in by_key[("scheduler", "capture_timing", "native")]["limits"]
    cross_view = by_key[("process", "cross_view", "native")]
    assert "matching_pid_eprocess_create_time" in cross_view["requirements"]
    assert "unverified_candidates_retained" in cross_view["limits"]
    assert "shared_api_dependency" in cross_view["limits"]
    assert "fair_session_queue" in cross_view["limits"]
    assert "x0_or_x1_only" in by_key[("execution", "classify_reference", "native")]["limits"]
    assert "saved_context_not_cpu_sample" in by_key[("execution", "classify_reference", "native")]["limits"]
    assert "single_observation_ids" in by_key[("io", "request_graph", "native")]["limits"]
    assert "no_request_lifetime_or_completion_inference" in by_key[("io", "request_graph", "native")]["limits"]
    v8 = by_key[("execution", "v8_profile", "v8_windows_log")]
    assert "ordered_code_event_and_label_match" in v8["requirements"] and "no_code_bytes_at_sample_time" in v8["limits"]
    trace = by_key[("execution", "trace_import", "trace")]
    assert trace["implementation"] == "implemented" and "unauthenticated_producer" in trace["limits"]
    assert "no_raw_decoder_or_live_backend" in trace["limits"]
    assert all(s in trace["requirements"] for s in ("saved_etl_profile_pages_v1_to_v7", "saved_etl_profile_v8_clr",
                                                   "separate_report_and_source_digests"))
    switches = by_key[("execution", "context_switch", "etl")]
    assert switches["implementation"] == "implemented" and switches["consistency"] == "reported_scheduler_event"
    assert "classic_thread_opcode36_versions2_3_4" in switches["requirements"]
    assert all(item in switches["requirements"] for item in ("opt_in_on_cpu_and_off_cpu_intervals", "readythread_v2_boundaries", "numeric_tid_filter"))
    assert "recorded_capture_settings" in switches["requirements"] and "1024_capture_setting_records" in switches["limits"]
    assert "no_authenticated_thread_lifetime_or_wait_cause" in switches["limits"]
    faults = by_key[("memory", "hard_fault", "etl")]
    assert faults["consistency"] == "reported_hard_fault" and faults["address_contract"] == "not_an_address_reader"
    assert "qpc_endpoints" in faults["requirements"] and "file_scoped_observed_faults" in faults["limits"]
    inventory = by_key[("evidence", "rotation_inventory", "etl")]
    assert inventory["consistency"] == "authenticated_file_inventory" and "trusted_es256_key_and_role" in inventory["requirements"]
    assert "controller_reported_stop_and_loss" in inventory["limits"]
    profile = by_key[("execution", "cpu_profile", "etl")]
    assert profile["consistency"] == "reported_cpu_samples" and "raw_clock" in profile["requirements"]
    assert "no_thread_lifetime_or_code_binding" in profile["limits"]
    assert "thread_v3_start_end_and_rundown_records" in profile["requirements"] and "65536_thread_events" in profile["limits"]
    assert "process_scoped_image_v2_v3_load_unload_and_rundown" in profile["requirements"]
    assert all(s in profile["requirements"] for s in ("opt_in_process_lifecycle_v2_v3_v4", "defunct_v2_to_v5", "image_bracket_in_recorded_process_generation"))
    assert all(s in profile["limits"] for s in ("65536_process_events", "source_local_process_generation"))
    assert all(s in profile["requirements"] for s in ("explicit_pinned_pe_reference", "file_backed_executable_window_sha256", "opt_in_merge_image_id_and_native_rsds"))
    assert all(s in profile["limits"] for s in ("64MiB_reference_file", "32_byte_reference_window", "131072_merge_markers", "runtime_bytes_unobserved"))
    assert all(s in profile["requirements"] for s in ("timer_interval_brackets", "recorded_capture_settings"))
    for entry in (profile, switches):
        assert all(item in entry["requirements"] for item in ("exact_page_replay_sha256", "opt_in_pinned_es256_capture_statement"))
    assert "1024_capture_setting_records" in profile["limits"]
    assert "65536_image_events" in profile["limits"] and "16MiB_image_names" in profile["limits"]
    operation = by_key[("session", "operation_status", "mcp")]
    observe = by_key[("session", "observe_scope", "mcp")]
    assert observe["consistency"] == "listener_lifetime"
    assert "authenticated_loopback" in observe["requirements"] and "admission_and_dispatch_checks" in observe["requirements"]
    assert "64_events_per_query" in observe["limits"] and "shared_principal" in observe["limits"]
    assert "optional_exact_source_grants_16" in observe["limits"] and "principal_scoped_sessions_budgets_and_receipts" in observe["limits"]
    assert "optional_ti_header_process_lifetime_with_expiring_target_session" in observe["limits"]
    assert "independent_evidence_and_operation_access" in observe["limits"]
    assert "listener_budget_calls_requested_examined_events_and_payload_utf8_bytes" in observe["limits"]
    assert "optional_private_operation_journal_256" in observe["limits"]
    assert operation["implementation"] == "implemented"
    assert "returned_operation_id" in operation["requirements"]
    assert "no_effect_verification_or_rollback" in operation["limits"]
    assert "no_idempotent_resubmission" in operation["limits"]
    process_source = by_key[("memory", "read_virtual", "process_handle")]
    assert "expected_pid_create_time" in process_source["requirements"]
    assert "no_liveness_or_atomic_snapshot_claim" in process_source["limits"]
    registry = (root / "user/CommandRegistry.cpp").read_text(encoding="utf-8-sig")
    expected = re.findall(r'Make\(L"([^"\n]+)",\s*L"([^"\n]*)",[^\n]*?CommandSupport::(\w+)\)', registry)
    assert expected, "command registry was not parsed"
    actual = [(c["name"], c["canonical"], c["route"]) for c in data["commands"]]
    assert actual == [(name, canonical, route.lower()) for name, canonical, route in expected]
    invalid = subprocess.run([exe, "--capabilities", "unexpected"], capture_output=True,
                             text=True, timeout=30)
    assert invalid.returncode != 0 and not invalid.stdout.strip()
    help_result = subprocess.run([exe, "--help"], capture_output=True, text=True,
                                 check=True, timeout=30)
    assert all(flag in help_result.stdout for flag in ("--etl-hard-faults", "--etl-disk-io", "--etl-switches", "--intervals", "--thread-id", "--capture-settings", "--clr-evidence", "--check-page", "--capture-statement"))
    assert "check saved CPU sample, context switch, disk I/O and hard page fault records" in help_result.stdout
    assert all(s in help_result.stdout for s in ("--etl-profile", "--image-evidence", "--process-evidence", "--build-evidence", "--reference-image"))
    assert "--capabilities" in help_result.stdout
    assert "--capabilities --probe" in help_result.stdout
    catalog = {c["id"]: c for c in data["probe_contracts"]}
    assert set(catalog) == {"owned_read", "native_connection", "saved_etl_family", "saved_dump_range"}
    assert len(catalog) == len(data["probe_contracts"])
    for contract in catalog.values():
        assert "KnLiveDbg.exe " + contract["invocation"] in help_result.stdout and contract["observation"]
    expected_routes = {("io", "disk_io", "etl"): "saved_etl_family",
                       ("memory", "hard_fault", "etl"): "saved_etl_family",
                       ("memory", "read_virtual", "process_handle"): "owned_read",
                       ("memory", "read_virtual", "dump"): "saved_dump_range",
                       ("execution", "cpu_profile", "etl"): "saved_etl_family",
                       ("execution", "context_switch", "etl"): "saved_etl_family"}
    for key, row in by_key.items():
        expected_route = "native_connection" if key[2] == "native" and row["implementation"] != "unsupported" else expected_routes.get(key)
        assert row["probe_contract"] == expected_route, key
    assert "--capabilities --probe-etl <local.etl> --sha256 <digest>" in help_result.stdout
    assert "--schema create" in help_result.stdout and "--schema inspect" in help_result.stdout
    print(f"source capabilities passed: {len(keys)} contracts, {len(actual)} command routes")


if __name__ == "__main__":
    main()
