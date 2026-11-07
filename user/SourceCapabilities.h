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
            L"canonical_irp_capture_v2;three_bound_schemas;complete_ordered_read_trace;exact_sibling_reference_for_qualification",
            L"16MiB_capture;64MiB_reference;declared_external_final_state;no_pdb_reparse_source_initialization_lifetime_execution_or_build_approval;v1_inputs_incomplete"},
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
            L"image_collection_session_v1;exclusive_collection_lock;exact_file_hashes;original_member_schemas",
            L"collection_scoped_dedup;bounded_recovery;resumable_derived_chunks;no_gc_or_global_retention;no_target_coverage_or_power_loss_guarantee"},
        {L"evidence", L"store", L"local_files", L"implemented", L"coordinated_stopped_store",
            L"exclusive_store_lease;participating_publishers;verified_image_collection_roots",
            L"image_namespace_only;bounded_inventory;open_or_unresolved_roots_protect_unattributed_files;no_deletion_authority_or_disk_allocation"},
        {L"evidence", L"gc", L"local_files", L"implemented", L"coordinated_explicit_policy",
            L"offline_cli;explicit_exact_member_policy;closed_verified_store;exclusive_store_lease;durable_intent_before_delete",
            L"uncommitted_image_artifacts_only;committed_roots_and_failure_ledgers_protected;unknown_outcomes_preserved;no_disk_reclamation_or_power_loss_claim"},
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
        {L"image", L"replay_verification", L"recipe", L"implemented", L"recorded_reads",
            L"valid_image_recipe;exact_reference_blob;explicit_policy_mode",
            L"original_ordered_reads;current_reanalysis_is_distinct;no_collector_authentication"},
        {L"image", L"capture_verification", L"process_handle", L"implemented", L"handle_bound_single_read",
            L"pid_creation_identity;read_query_access;explicit_residency_consent;exact_local_reference;new_private_case_directory",
            L"single_range_4096;ordered_v2_receipts_not_atomic;legacy_la48_shape_with_os_user_ceiling;no_native_fallback;no_background_kmon_capture;no_mapping_lifetime_or_execution_claim"},
        {L"proof", L"image_range", L"recipe", L"implemented", L"recorded_reads",
            L"validated_replay;recomputed_typed_comparison;claim_specific_requirements",
            L"selected_range_only;acquisition_intervals_only;no_execution_writer_or_maliciousness_claim"},
        {L"scheduler", L"capture_timing", L"native", L"implemented", L"collector_monotonic",
            L"active_capture_worker;coverage_pipeline_event",
            L"class_urgency_thresholds;log2_percentile_upper_bounds;no_hard_deadline_or_measured_slo"},
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
        {L"execution", L"trace_import", L"trace", L"implemented", L"imported_producer_claims",
            L"versioned_normalized_samples;bounded_local_file;explicit_cpu_vm_vtl_clock_scope;retained_code_hashes",
            L"no_raw_decoder_or_live_backend;unauthenticated_producer;no_independently_verified_execution;no_x3_x4_or_writer"},
        {L"session", L"operation_status", L"mcp", L"implemented", L"engine_reported",
            L"authenticated_server;returned_operation_id;retained_metadata",
            L"256_metadata_records;no_effect_verification_or_rollback;no_automatic_retry;no_idempotent_resubmission;no_remote_protocol_adapter"},
        {L"memory", L"read_virtual", L"process_handle", L"implemented", L"handle_bound_single_read",
            L"query_and_vm_read_handle;expected_pid_create_time;declared_address_shape;explicit_residency_consent",
            L"owned_handle_duplicate;4096_byte_reads;no_liveness_or_atomic_snapshot_claim;selected_image_reader_only;native_fallback_not_a_unified_receipt"},
        {L"io", L"request_graph", L"native", L"implemented", L"repeated_snapshot",
            L"exact_pdb_layout;matched_thread_generation;stable_list_and_packet_reads",
            L"supplied_threads_only;single_observation_ids;no_request_lifetime_or_completion_inference;no_wait_graph"},
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
                std::wstring(capability.Backend) == L"native" ? L"connection_contract_only" : L"not_probed")
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
