#pragma once

#include "CommandRegistry.h"
#include "McpJson.h"
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
            L"partial_reads;residency_changes_possible;no_vtl1_access_contract"},
        {L"memory", L"read_process", L"native", L"implemented", L"live_non_atomic",
            L"matching_driver_abi;process_identity;readable_mapping",
            L"pid_reuse_checked;mapping_can_change;residency_changes_possible"},
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
            L"valid_kncase_v1;readable_directory",
            L"legacy_bounded_inventory;optional_immutable_snapshot;separate_inventory_and_result_cursors;window_scoped_counts"},
        {L"schema", L"export_type", L"local_pdb", L"implemented", L"offline_artifacts",
            L"exact_amd64_image_pdb_identity;stable_local_files;packaged_dia_provider",
            L"layout_bounds_only;explicit_nested_paths;no_pointer_follow;no_runtime_qualification;parser_not_isolated"},
        {L"evidence", L"replay", L"bundle", L"implemented", L"recorded_bundle",
            L"valid_kncase_v1;declared_read_set",
            L"page_digest_and_static_path_only;image_verification_not_replayed"},
        {L"image", L"capture_verification", L"dump", L"implemented", L"offline_dump",
            L"exact_local_reference;qualified_dump_root;new_private_case_directory",
            L"single_range_4096;direct_mapping_basis;no_signer_approval;no_execution_claim"},
        {L"image", L"replay_verification", L"recipe", L"implemented", L"recorded_reads",
            L"valid_image_recipe;exact_reference_blob;explicit_policy_mode",
            L"original_ordered_reads;current_reanalysis_is_distinct;no_collector_authentication"},
        {L"proof", L"image_range", L"recipe", L"implemented", L"recorded_reads",
            L"validated_replay;recomputed_typed_comparison;claim_specific_requirements",
            L"selected_range_only;acquisition_intervals_only;no_execution_writer_or_maliciousness_claim"},
        {L"scheduler", L"capture_timing", L"native", L"implemented", L"collector_monotonic",
            L"active_capture_worker;coverage_pipeline_event",
            L"class_urgency_thresholds;log2_percentile_upper_bounds;no_hard_deadline_or_measured_slo"},
        {L"debugger", L"execute", L"dbgeng", L"implemented", L"backend_defined",
            L"installed_runtime;successful_kdinit;target_permissions",
            L"command_text_bridge;no_typed_observation_source;no_implicit_fallback"},
        {L"io", L"interpose_dispatch", L"native", L"experimental", L"live_non_atomic",
            L"lab_target;write_gate;explicit_arm",
            L"unresolved_publication_and_unload_lifetime;not_a_supported_sensor"},
        {L"security", L"inspect_vtl1_memory", L"native", L"unsupported", L"unavailable",
            L"separate_authorized_backend", L"vtl0_posture_is_not_vtl1_memory"},
        {L"execution", L"trace_import", L"trace", L"unsupported", L"unavailable",
            L"versioned_trace_adapter", L"static_references_do_not_establish_execution"},
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

// This inventory never probes a target or opens a device. Implemented does not
// imply that an operation is usable or validated on the caller's machine.
inline std::wstring SourceCapabilitiesJson(const std::wstring& binaryVersion)
{
    const auto quote = [](const std::wstring& value)
    {
        return L"\"" + mcpjson::Escape(value) + L"\"";
    };
    std::wostringstream out;
    out << L"{\"schema\":\"kn.capabilities.v1\",\"scope\":\"compiled_contract\","
        << L"\"inventory_complete\":false,\"binary_version\":" << quote(binaryVersion)
        << L",\"driver_abi\":" << KNDBG_ABI_VERSION
        << L",\"architecture\":\"x64\",\"target_probed\":false,"
        << L"\"target\":{\"os_build\":null,\"security_state\":\"unknown\","
        << L"\"virtual_address_bits\":null,\"validation\":\"not_performed\"},"
        << L"\"capabilities\":[";
    bool first = true;
    for (const auto& capability : SourceCapabilities())
    {
        if (!first)
        {
            out << L",";
        }
        first = false;
        out << L"{\"domain\":" << quote(capability.Domain)
            << L",\"operation\":" << quote(capability.Operation)
            << L",\"backend\":" << quote(capability.Backend)
            << L",\"implementation\":" << quote(capability.Implementation)
            << L",\"availability\":\"not_probed\",\"consistency\":" << quote(capability.Consistency)
            << L",\"requirements\":" << quote(capability.Requirements)
            << L",\"limits\":" << quote(capability.Limits) << L"}";
    }
    out << L"],\"commands\":[";
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
