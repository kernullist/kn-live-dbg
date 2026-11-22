#pragma once

#include "CommandRegistry.h"
#include "McpJson.h"
#include "RuntimeCapabilities.h"
#include "../shared/KnLiveDbgIoctl.h"
#include <sstream>

struct SourceCapability
{
    const wchar_t* Domain;
    const wchar_t* Operation;
    const wchar_t* Backend;
    const wchar_t* Implementation;
    const wchar_t* Consistency;
    const wchar_t* Requirements;
    const wchar_t* Limits;
};

inline const std::vector<SourceCapability>& SourceCapabilities()
{
    static const std::vector<SourceCapability> capabilities =
    {
        {L"session", L"restricted_launch", L"local_cli", L"implemented", L"one_shot",
            L"leading_mode_selector;closed_operation_list;inherited_local_trace_file;self_probe_requires_residency_consent",
            L"offline_or_observe_only;no_controller_collection_device_or_transport;other_processes_and_legacy_launch_outside_scope"},
        {L"session", L"mutation_gate", L"native", L"implemented", L"per_handle",
            L"default_write_denied_driver_flag;explicit_write_enable;confirmed_session_status",
            L"not_an_observe_collect_partition;read_side_effects_possible;administrator_not_a_trust_boundary"},
        {L"memory", L"read_virtual", L"native", L"implemented", L"live_non_atomic",
            L"matching_driver_abi;controller_session;readable_mapping",
            L"partial_reads;selected_read_observation_v1_status;legacy_raw_ntstatus_unavailable;residency_changes_possible;no_vtl1_access_contract"},
        {L"memory", L"read_process", L"native", L"implemented", L"live_non_atomic",
            L"matching_driver_abi;process_identity;readable_mapping",
            L"pid_reuse_checked;read_observation_v1_source_available;existing_direct_callers_require_migration;mapping_can_change;residency_changes_possible"},
        {L"memory", L"translate", L"native", L"implemented", L"live_non_atomic",
            L"matching_driver_abi;qualified_root;active_paging_mode",
            L"la48_or_la57_walk;not_a_pipeline_la57_validation;no_mmio_contract"},
        {L"memory", L"analyze_dump", L"dump", L"implemented", L"offline_dump",
            L"supported_dump_header;captured_physical_runs;qualified_root",
            L"uncaptured_pages;not_all_dump_formats;not_live_execution"},
        {L"memory", L"read_virtual", L"dump", L"implemented", L"offline_dump",
            L"amd64_full_dump_runs;qualified_paging_depth;readable_file",
            L"captured_root_only;not_captured_vs_not_present;file_handle_scope;no_collector_authentication"},
        {L"evidence", L"query", L"bundle", L"implemented", L"recorded_bundle",
            L"valid_kncase_v1_or_v2;readable_directory",
            L"legacy_bounded_inventory;optional_immutable_snapshot;separate_inventory_and_result_cursors;window_scoped_counts"},
        {L"schema", L"export_type", L"local_pdb", L"implemented", L"offline_artifacts",
            L"exact_amd64_image_pdb_identity;stable_local_files;packaged_dia_provider",
            L"layout_bounds_only;explicit_nested_paths;no_pointer_follow;no_runtime_qualification;cli_parser_process_containment;other_symbol_paths_not_isolated;no_filesystem_or_network_sandbox"},
        {L"evidence", L"replay", L"bundle", L"implemented", L"recorded_bundle",
            L"valid_kncase_v1_or_v2;declared_read_set",
            L"page_digest_and_static_path_only;image_verification_not_replayed"},
        {L"evidence", L"replay_irp", L"local_files", L"implemented", L"recorded_ordered_reads",
            L"canonical_irp_capture_v2_or_irp_claim_publication_v1;three_bound_schemas;complete_ordered_read_trace;exact_sibling_reference_for_qualification",
            L"16MiB_whole_publication;64MiB_reference;original_claim_reproduction_separate_from_current_evaluation;current_flag_skips_original_claim_reproduction;declared_external_final_state;no_pdb_reparse_source_initialization_lifetime_execution_or_build_approval;v1_inputs_incomplete"},
        {L"evidence", L"graph", L"bundle", L"implemented", L"recorded_bundle",
            L"valid_kncase_v1_or_v2;bounded_saved_reads;graph_and_query_bound_cursor",
            L"single_bundle_fact_graph;static_references_only;no_execution_or_cross_source_join;query_budget_excludes_materialization"},
        {L"evidence", L"graph", L"recipe", L"implemented", L"recorded_temporal_sweep",
            L"valid_image_sweep_v1;successful_original_slice_replay;exact_reference_blob;graph_and_query_bound_cursor",
            L"replayed_comparison_provenance;256_nodes_512_edges;no_execution_or_cross_bundle_lifetime_join;query_budget_excludes_replay"},
        {L"evidence", L"temporal_graph", L"bundle", L"implemented", L"recorded_local_collector_scope",
            L"explicit_2_to_32_bundles;origin_bound_kncase_v2;matching_target_generation_and_assertions;common_recorded_clock;query_bound_cursor",
            L"legacy_unfulfilled;candidate_relations_only;no_cross_collector_bridge;no_mapping_lifetime_execution_write_or_causality;collector_not_authenticated"},
        {L"evidence", L"journal", L"local_files", L"implemented", L"verified_committed_prefix",
            L"image_v1_image_irp_v2_image_claim_irp_v3_or_image_irp_claim_v4_policy;direct_image_collection_v1_policy;approved_image_collection_v1_policy;approved_image_scope_collection_v1_policy;exclusive_collection_lock;exact_file_hashes;original_member_schemas;irp_ledger_before_closure",
            L"collection_scoped_dedup;bounded_recovery;resumable_derived_chunks;no_gc_or_global_retention;no_target_coverage_or_power_loss_guarantee"},
        {L"evidence", L"store", L"local_files", L"implemented", L"coordinated_stopped_store",
            L"exclusive_store_lease;participating_publishers;verified_image_and_irp_collection_roots",
            L"image_folders_and_reserved_irp_root_namespace;bounded_inventory;open_or_unresolved_roots_protect_unattributed_files;no_deletion_authority_or_disk_allocation"},
        {L"evidence", L"journal_image", L"local_files", L"implemented", L"one_archived_capture",
            L"initialized_private_store;exact_recipe_or_claim_publication;retained_reference;exclusive_collection_lock;shared_store_lease",
            L"one_capture_per_collection;4MiB_root;64MiB_reference;membership_separate_from_semantic_replay;source_directory_unchanged;no_new_target_reads_or_power_loss_guarantee"},
        {L"evidence", L"journal_image_approval", L"local_files", L"implemented", L"one_archived_assessment",
            L"initialized_private_store;separate_policy_sha256_anchor;original_direct_replay;five_exact_members;all_members_before_closure;immutable_historical_retry",
            L"one_assessment_per_collection;4MiB_capture_and_approval;64MiB_reference;64KiB_policy_and_manifest;no_current_approval_or_power_loss_guarantee"},
        {L"image", L"replay_approval", L"recipe", L"implemented", L"recorded_assessment_time",
            L"separate_policy_sha256_anchor;exact_capture_reference_policy_manifest;original_report_equality;explicit_current_retained_policy_mode",
            L"no_self_appointed_trust;original_mode_not_current_validity;journal_membership_separate;no_signature_clock_collector_or_execution_authentication"},
        {L"evidence", L"journal_image_scope_approval", L"local_files", L"implemented", L"one_archived_temporal_assessment",
            L"initialized_private_store;separate_policy_sha256_anchor;original_scope_replay;exact_declared_input_closure;shared_content_addressed_inputs_and_reference;immutable_historical_retry",
            L"4097_inputs_256MiB;8MiB_approval;64MiB_reference;64KiB_policy_and_manifest;no_atomic_snapshot_current_approval_or_power_loss_guarantee"},
        {L"image", L"replay_scope_approval", L"recipe", L"implemented", L"recorded_assessment_time",
            L"separate_policy_sha256_anchor;exact_input_catalog;explicit_logical_path_resolver;original_report_equality;explicit_current_retained_policy_mode",
            L"no_ambient_input_fallback;membership_separate_from_replay;no_clock_signature_collector_execution_or_atomic_snapshot_authentication"},
        {L"evidence", L"gc", L"local_files", L"implemented", L"coordinated_explicit_policy",
            L"offline_cli;explicit_exact_member_policy;closed_verified_store;exclusive_store_lease;durable_intent_before_delete",
            L"uncommitted_image_and_irp_artifacts_only;committed_roots_and_failure_ledgers_protected;unknown_outcomes_preserved;no_disk_reclamation_or_power_loss_claim"},
        {L"image", L"capture_verification", L"dump", L"implemented", L"offline_dump",
            L"exact_local_reference;qualified_dump_root;new_private_case_directory",
            L"single_range_4096;direct_mapping_basis;no_signer_approval;no_execution_claim"},
        {L"evidence", L"privacy", L"local_files", L"implemented", L"observed_os_access_controls",
            L"current_principal_and_system;new_local_root;efs_default;explicit_acl_only;strict_private_log",
            L"not_atomic;trusted_administrator_and_recovery_agents;no_transfer_authority;no_redaction;no_key_backup"},
        {L"evidence", L"disclosure", L"local_files", L"implemented", L"reviewed_historical_image_counts",
            L"original_policy_replay;private_original_hash_link;closed_vocabulary_facts;exact_destination_review;durable_intent_before_http;one_use_approval",
            L"image_recipe_slice_sweep_only;no_raw_capture_transfer;no_external_cli_confinement;no_offline_inference;no_recipient_retention_or_collector_authentication_claim"},
        {L"evidence", L"retention", L"native", L"implemented", L"recording_session_partitions",
            L"routed_image_reads;first_difference_gap_routine_lanes;complete_journal_batch_before_repeat_demotion;independent_failure_ledger",
            L"image_pipeline_only;bounded_key_memory;cooperative_writer;no_disk_space_reservation_or_cross_session_dedup"},
        {L"evidence", L"retention_irp", L"native", L"implemented", L"recorded_state_session_partitions",
            L"source_and_schema_bound_state_signatures;first_state_gap_repeat_lanes;reference_and_journal_before_repeat_demotion;unavailable_capture_denominator",
            L"4_slots_240MiB_reserved;320MiB_new_raw_files;bounded_keys;no_object_lifetime_maliciousness_cross_session_dedup_or_disk_space_reservation"},
        {L"evidence", L"claims_irp", L"capture", L"implemented", L"current_policy_on_recorded_invariants",
            L"canonical_original_reads;exact_reference_for_qualified_claims;versioned_requirements;single_capture_evidence;seven_ledgers;explicit_refutations_and_gaps;writer_original_claim_publication",
            L"128_claims_128Ki_UTF16_units;16MiB_whole_publication;raw_fallback_and_unavailable_counter;omitted_denominator;no_request_lifetime_completion_execution_driver_ownership_or_authenticated_collector"},
        {L"image", L"assess_changes", L"recipe", L"implemented", L"recorded_direct_range",
            L"original_direct_replay;separate_policy_sha256_anchor;exact_image_manifest_issuer_epoch;capture_and_evaluation_validity;before_after_range_hashes",
            L"128_ranges_4096_bytes_each;64KiB_policy_and_manifest;no_fixup_overlap;caller_policy_not_signature_authentication;host_clock_not_authenticated;no_current_state_execution_or_full_image_approval"},
        {L"image", L"assess_scope_changes", L"recipe", L"implemented", L"recorded_slice_or_temporal_sweep",
            L"original_direct_or_secondary_slice_replay;separate_policy_sha256_anchor;exact_scope_policy;all_observation_and_evaluation_times;per_part_recipe_provenance",
            L"16384_pages_2048_slices;4MiB_output;128_ranges_4096_bytes_each;64KiB_policy_and_manifest;no_fixup_overlap;no_atomic_snapshot_signed_distribution_current_state_or_execution"},
        {L"image", L"replay_verification", L"recipe", L"implemented", L"recorded_reads",
            L"valid_image_recipe;exact_reference_blob;explicit_policy_mode;atomic_direct_slice_sweep_claim_publication;exact_recorded_claim_reproduction",
            L"original_ordered_reads;direct_publication_4MiB;scope_publication_2MiB;legacy_claim_not_recorded;current_reanalysis_is_distinct;no_collector_authentication"},
        {L"image", L"capture_verification", L"process_handle", L"implemented", L"handle_bound_single_read",
            L"pid_creation_identity;read_query_access;explicit_residency_consent;exact_local_reference;new_private_case_directory;v3_original_before_after_final_mapping_queries;mapping_conflict_and_failure_gate",
            L"single_range_4096;ordered_read_receipts_not_atomic;64_reads_192_mapping_observations_384_queries;legacy_la48_shape_with_os_user_ceiling;no_native_fallback;no_background_kmon_capture;no_mapping_lifetime_aba_backing_or_execution_claim"},
        {L"proof", L"image_range", L"recipe", L"implemented", L"recorded_reads",
            L"validated_replay;recomputed_typed_comparison;claim_specific_requirements;common_claim_registry_v1;original_read_references;seven_ledgers",
            L"direct_recipe_256Ki_UTF16_units;slice_sweep_2Mi_UTF16_units;per_original_policy_partitions;selected_range_only;acquisition_intervals_only;original_claim_reproduction_requires_publication;collection_membership_separate;no_execution_writer_or_maliciousness_claim"},
        {L"scheduler", L"capture_timing", L"native", L"implemented", L"collector_monotonic",
            L"active_capture_worker;coverage_pipeline_event",
            L"class_urgency_thresholds;log2_percentile_upper_bounds;no_hard_deadline_or_measured_slo"},
        {L"scheduler", L"reference_admission", L"native", L"implemented", L"collector_monotonic",
            L"analysis_thread;coverage_pipeline_event;confirmed_live_source_for_dispatch",
            L"admitted_subject_role_round_robin;1024_global_64_subject_16_subject_role_256_role;bounded_deferred_scopes_and_resident_history;attempt_cooldown_not_success_revisit;no_deferred_rediscovery_hard_deadline_or_measured_slo"},
        {L"scheduler", L"image_observation", L"native", L"implemented", L"collector_monotonic",
            L"analysis_thread;coverage_pipeline_event;confirmed_live_source_for_continuations",
            L"resident_key_debt;attempt_slice_traversal_and_gap_free_separate;bounded_debt_priority_preserves_rotation;30000ms_reference_retry;cooperative_25ms_includes_lookup;minimum_page_and_final_fences_may_overrun;no_hard_deadline_native_read_latency_durable_latency_or_measured_slo"},
        {L"scheduler", L"publication", L"native", L"implemented", L"collector_monotonic",
            L"capture_writer;explicit_local_acquisition_window_for_end_to_end_samples;coverage_pipeline_event",
            L"four_family_rotation;bounded_oldest_family_loan;existing_retention_classes_preserved;file_and_journal_success_separate;unknown_historical_acquisition_excluded;shutdown_separate;no_native_api_latency_hard_deadline_or_power_loss_proof"},
        {L"scheduler", L"analysis", L"native", L"implemented", L"collector_monotonic",
            L"analysis_thread_safe_boundaries;stage_specific_live_source_gates;original_target_fences_preserved;coverage_pipeline_event",
            L"nine_stage_persistent_rotation;cooperative_250ms_turn_100ms_maximum_slice;one_dispatch_per_stage_per_turn;native_calls_and_final_fences_may_overrun;first_observed_continuous_backlog_not_target_freshness;shutdown_separate;no_measured_slo_or_whole_source_unobserved_bound"},
        {L"scheduler", L"discovery", L"native", L"implemented", L"collector_monotonic",
            L"analysis_worker;live_binding_readiness;original_scanner_target_fences;coverage_pipeline_event",
            L"ten_group_26_phase_rotation;cooperative_250ms_includes_interleaved_analysis;preserved_group_phase_order;one_cycle_per_group_per_turn;midcycle_requests_retained;continued_phase_once_per_turn;user_inventory_32_steps_25ms;pinned_generation_path;one_selected_deep_target_per_turn;cohort_tail_survives_target_faults;inventory_caps_4096_8192_12288;capped_inventory_rotating_deep_slot;frozen_pid_lap;generation_fenced_toolhelp_module_debt;faults_advance_phase;cycle_due_debt_not_target_success;individual_native_calls_not_preemptible;no_measured_native_slo"},
        {L"scheduler", L"layout", L"native", L"implemented", L"collector_monotonic",
            L"layout_collection_worker;analysis_thread_mapping_revalidation;qualified_process_identity;original_candidate_clock",
            L"process_ring_join_behind_waiters;bounded_oldest_loans;subject_and_class_quotas;original_pending_and_expiry_preserved;rediscovery_separate;bounded_deferred_scopes;mapping_not_byte_success;shutdown_separate;non_atomic_layout_not_mapping_lifetime_proof;no_measured_slo"},
        {L"scheduler", L"image_reference_preparation", L"native", L"implemented", L"collector_monotonic",
            L"dedicated_reference_workers;original_admission_clock;matching_work_episode_on_application;native_identity_revalidation_before_target_read",
            L"pe_metadata_and_sweep_ranges_only;two_workers;bounded_subject_ring;queued_inflight_ready_quotas;bounded_completion_slots;preparation_not_live_verification;failure_and_shutdown_separate;cooperative_cancellation_and_actual_join;per_slice_content_preparation_separate;final_fences_remain_synchronous;no_hard_deadline_or_process_memory_bound"},
        {L"scheduler", L"image_content_preparation", L"native", L"implemented", L"collector_monotonic",
            L"dedicated_content_workers;single_comparison_source_lease;matching_work_episode;immutable_original_reference_bytes",
            L"two_workers;four_running_or_ready_slots;bounded_subject_admission;ready_expiry_cooperative_5000ms;retained_and_unretained_leases_separate;final_content_and_target_fences_preserved;source_lease_released_before_publication;no_hard_deadline"},
        {L"process", L"cross_view", L"native", L"implemented", L"live_non_atomic",
            L"complete_comparison_inventories;matching_pid_eprocess_create_time;readable_lifecycle",
            L"128_candidate_confirmation;fair_session_queue;reserved_fresh_comparison;cooperative_5000ms;shared_api_dependency;unverified_candidates_retained;no_actor_or_hiding_mechanism_claim"},
        {L"debugger", L"execute", L"dbgeng", L"implemented", L"backend_defined",
            L"installed_runtime;successful_kdinit;target_permissions",
            L"command_text_bridge;no_typed_observation_source;no_implicit_fallback"},
        {L"io", L"interpose_dispatch", L"native", L"experimental", L"live_non_atomic",
            L"lab_target;write_gate;explicit_arm",
            L"unresolved_publication_and_unload_lifetime;not_a_supported_sensor"},
        {L"security", L"inspect_vtl1_memory", L"native", L"unsupported", L"unavailable",
            L"separate_authorized_backend", L"vtl0_posture_is_not_vtl1_memory"},
        {L"execution", L"context_switch", L"etl", L"implemented", L"reported_scheduler_event",
            L"pinned_local_etl;classic_thread_opcode36_versions2_3_4;raw_clock;original_event_ordinal;header_loss_counters;opt_in_on_cpu_and_off_cpu_intervals;readythread_v2_boundaries;numeric_tid_filter;recorded_capture_settings;exact_page_replay_sha256;opt_in_pinned_es256_capture_statement",
            L"512MiB;2000000_event_records;128_rows;unverified_producer;numeric_tid_only;1024_capture_setting_records;no_authenticated_thread_lifetime_or_wait_cause"},
        {L"execution", L"cpu_profile", L"etl", L"implemented", L"reported_cpu_samples",
            L"pinned_local_etl;classic_perfinfo_v2_opcode46;raw_clock;original_event_ordinal;header_loss_counters;opt_in_thread_v3_start_end_and_rundown_records;process_scoped_image_v2_v3_load_unload_and_rundown;opt_in_process_lifecycle_v2_v3_v4;defunct_v2_to_v5;image_bracket_in_recorded_process_generation;explicit_pinned_pe_reference;file_backed_executable_window_sha256;opt_in_merge_image_id_and_native_rsds;recorded_capture_settings;timer_interval_brackets;exact_page_replay_sha256;opt_in_pinned_es256_capture_statement",
            L"512MiB;2000000_event_records;65536_thread_events;65536_image_events;65536_process_events;source_local_process_generation;16MiB_image_names;128_rows;unverified_producer;no_thread_lifetime_or_code_binding;64MiB_reference_file;32_byte_reference_window;131072_merge_markers;1024_capture_setting_records;runtime_bytes_unobserved"},
        {L"objects", L"game_object_lifetime", L"game_build_manifest", L"implemented", L"game_reported_two_observations",
            L"amd64_main_image;selected_v2_manifest;private_pdb_typed_registry_and_subobject;expected_container_and_member;nonzero_generation;stable_even_publication_before_and_after",
            L"two_vptr_rules_per_pass;direct_nonvirtual_bases_or_root;cooperating_writer;no_independent_lifetime_or_execution"},
        {L"execution", L"v8_profile", L"v8_windows_log", L"implemented", L"reported_runtime_samples",
            L"pinned_local_v8_tick_log;original_pc_and_record;optional_pinned_x64_low_level_log;ordered_code_event_and_label_match;recorded_body_and_window_sha256",
            L"13_6_233_17_node_63;64MiB_per_input;65536_mapping_events;128_rows;logger_time_only;no_code_bytes_at_sample_time;unauthenticated_producer"},
        {L"execution", L"trace_import", L"trace", L"implemented", L"imported_producer_claims",
            L"versioned_normalized_samples;bounded_local_file;explicit_cpu_vm_vtl_clock_scope;retained_code_hashes;saved_etl_profile_pages_v1_to_v7;saved_etl_profile_v8_clr;separate_report_and_source_digests",
            L"no_raw_decoder_or_live_backend;unauthenticated_producer;no_independently_verified_execution;no_x3_x4_or_writer"},
        {L"session", L"observe_scope", L"mcp", L"implemented", L"listener_lifetime",
            L"operator_selected_observe;authenticated_loopback;closed_tool_and_resource_catalog;admission_and_dispatch_checks",
            L"existing_controller;retained_queries_and_status_only;64_events_per_query;shared_principal;listener_budget_calls_requested_examined_events_and_payload_utf8_bytes;optional_private_operation_journal_256;optional_exact_source_grants_16;principal_scoped_sessions_budgets_and_receipts;optional_ti_header_process_lifetime_with_expiring_target_session;independent_evidence_and_operation_access"},
        {L"session", L"operation_status", L"mcp", L"implemented", L"engine_reported",
            L"authenticated_server;returned_operation_id;retained_metadata",
            L"256_metadata_records;no_effect_verification_or_rollback;no_automatic_retry;no_idempotent_resubmission;no_remote_protocol_adapter"},
        {L"memory", L"read_virtual", L"process_handle", L"implemented", L"handle_bound_single_read",
            L"query_and_vm_read_handle;expected_pid_create_time;declared_address_shape;explicit_residency_consent",
            L"owned_handle_duplicate;4096_byte_reads;no_liveness_or_atomic_snapshot_claim;selected_image_reader_only;native_fallback_not_a_unified_receipt"},
        {L"io", L"request_graph", L"native", L"implemented", L"repeated_snapshot",
            L"exact_pdb_layout;matched_thread_generation;stable_list_and_packet_reads",
            L"supplied_threads_only;single_observation_ids;no_request_lifetime_or_completion_inference;no_wait_graph"},
        {L"diagnostics", L"crash_diagnosis", L"dbgeng_dump", L"implemented", L"pinned_offline_dump",
            L"sha256_pinned_local_amd64_kernel_dump;retained_handle;typed_bugcheck_and_stack;optional_stop_parameter_2_cper;optional_separately_pinned_whea_event_xml",
            L"16GiB_30s_per_hash_pass;32_frames;cper_1MiB_128_sections_512_reads;event_xml_8MiB_4096_nodes;no_external_symbols_or_image_mapping;unverified_unwind;no_host_crash_or_culprit_attribution"},
        {L"diagnostics", L"io_request_lifetime", L"win32_directory_changes", L"implemented", L"retained_overlapped_request",
            L"local_directory_handle;per_generation_manual_reset_event;provider_run_and_sequence;explicit_result_and_retirement",
            L"up_to_8_requests;caller_issued_notifications;no_kernel_dispatch_identity;no_address_join;unknown_outcomes_retained"},
        {L"diagnostics", L"wait_chain", L"windows_wct", L"implemented", L"one_live_traversal",
            L"requested_process_and_thread_creation;query_and_synchronize_handles;windows_wct_access",
            L"same_process_mutex_and_critical_section;discovery_only_for_pins;non_atomic;no_timeout_or_deadlock_proof"},
        {L"diagnostics", L"wait_cycle_corroboration", L"windows_wct", L"implemented", L"paired_live_traversals",
            L"two_requested_thread_generations;retained_process_and_thread_handles;separate_wct_sessions;measured_qpc_overlap",
            L"2_to_8_rounds;gaps_and_missing_roots_in_denominator;lock_lifetimes_and_continuous_wait_unverified"},
        {L"execution", L"classify_reference", L"native", L"implemented", L"source_metadata",
            L"typed_source_kind;qualified_process_identity;source_specific_context_fields",
            L"x0_or_x1_only;saved_context_not_cpu_sample;no_execution_write_or_actor_attribution"},
        {L"execution", L"observe_writes", L"vmi", L"unsupported", L"unavailable",
            L"authorized_vm_backend", L"shared_pfn_does_not_attribute_a_writer"}
    };
    return capabilities;
}

inline const wchar_t* SourceCommandRoute(CommandSupport support)
{
    switch (support)
    {
    case CommandSupport::Native:
        return L"native";
    case CommandSupport::Alias:
        return L"alias";
    case CommandSupport::DbgEng:
        return L"dbgeng";
    case CommandSupport::Extension:
        return L"extension";
    default:
        return L"unknown";
    }
}

// Serialization never probes a target. Runtime observations must be supplied
// explicitly; compiled implementation alone is not availability or validation.
inline std::wstring SourceCapabilitiesJson(const std::wstring& binaryVersion, const RuntimeCapabilityProbe* probe = nullptr)
{
    const auto quote = [](const std::wstring& value)
    {
        return L"\"" + mcpjson::Escape(value) + L"\"";
    };
    std::wostringstream out;
    out << L"{\"schema\":\"kn.capabilities.v1\",\"scope\":" << quote(probe == nullptr ? L"compiled_contract" : L"runtime_probe") << L","
        << L"\"inventory_complete\":false,\"binary_version\":" << quote(binaryVersion)
        << L",\"driver_abi\":" << KNDBG_ABI_VERSION
        << L",\"architecture\":\"x64\",\"target_probed\":" << (probe != nullptr ? L"true" : L"false") << L","
        << L"\"target\":{\"os_build\":null,\"security_state\":\"unknown\","
        << L"\"virtual_address_bits\":null,\"validation\":\"not_performed\"},"
        << L"\"capabilities\":[";
    bool first = true;
    for (const auto& capability : SourceCapabilities())
    {
        // An owned byte sample does not exercise reference capture or replay.
        const bool unsampledProcessOperation = std::wstring(capability.Backend) == L"process_handle" &&
            (std::wstring(capability.Domain) != L"memory" || std::wstring(capability.Operation) != L"read_virtual");
        const auto* contractProbe = unsampledProcessOperation ? nullptr : probe;
        if (!first)
        {
            out << L",";
        }
        first = false;
        out << L"{\"domain\":" << quote(capability.Domain)
            << L",\"operation\":" << quote(capability.Operation)
            << L",\"backend\":" << quote(capability.Backend)
            << L",\"implementation\":" << quote(capability.Implementation)
            << L",\"availability\":" << quote(CapabilityAvailability(capability.Implementation, capability.Backend, contractProbe))
            << L",\"availability_scope\":" << quote(probe == nullptr ? L"none" :
                contractProbe == nullptr ? L"not_probed" :
                std::wstring(capability.Backend) == L"process_handle" ? L"owned_control_range_only" :
                std::wstring(capability.Backend) == L"native" ? (probe->NativeProbeAttempted ? L"connection_contract_only" : L"launch_policy") : L"not_probed")
            << L",\"validation\":\"not_performed_for_target_environment\""
            << L",\"probe_stages\":" << CapabilityProbeStagesJson(capability.Backend, contractProbe)
            << L",\"address_contract\":" << quote(CapabilityAddressContract(capability.Domain, capability.Operation, capability.Backend))
            << L",\"consistency\":" << quote(capability.Consistency)
            << L",\"requirements\":" << quote(capability.Requirements)
            << L",\"limits\":" << quote(capability.Limits) << L"}";
    }
    out << L"]";
    if (probe != nullptr)
    {
        out << L",\"probe\":" << RuntimeCapabilityProbeJson(*probe);
    }
    out << L",\"commands\":[";
    first = true;
    for (const auto& command : CommandRegistry::Commands())
    {
        if (!first)
        {
            out << L",";
        }
        first = false;
        out << L"{\"name\":" << quote(command.Name)
            << L",\"canonical\":" << quote(command.Canonical)
            << L",\"route\":" << quote(SourceCommandRoute(command.Support)) << L"}";
    }
    out << L"]}";
    return out.str();
}
