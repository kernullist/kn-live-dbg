#pragma once

#include "McpJson.h"
#include "ObservationSource.h"

#include <cstdint>
#include <algorithm>
#include <string>

struct RuntimeCapabilityProbe
{
    uint64_t StartedMs = 0;
    uint64_t FinishedMs = 0;
    uint32_t ProcessId = 0;
    uint64_t ProcessCreateTime = 0;
    bool ProcessHandleAttempted = false;
    bool ProcessSourceOpened = false;
    bool ProcessReadAttempted = false;
    bool ProcessReadPassed = false;
    bool ProcessBytesMatched = false;
    std::wstring ProcessReason;
    std::wstring ProcessReadJson = L"null";
    std::wstring ProcessReadSetJson = L"null";
    std::wstring ProcessHandleTimelineJson = L"null";
    uint64_t ProcessHandlesAcquired = 0, ProcessHandlesClosed = 0;
    bool NativeProbeAttempted = false;
    bool NativeSourceOpened = false;
    bool NativeContractPassed = false;
    bool NativeSessionPassed = false;
    uint64_t NativeSourceEpoch = 0;
    uint32_t NativeVirtualAddressBits = 0;
    bool NativeReadObservationSupported = false;
    bool NativeCloseAttempted = false, NativeCloseSucceeded = false;
    DWORD NativeCloseError = ERROR_SUCCESS;
    std::wstring NativeReason;
};

RuntimeCapabilityProbe ProbeOwnedProcessCapabilities();
RuntimeCapabilityProbe ProbeRuntimeCapabilities();

inline bool CapabilityReadAccepted(const ObservationReadResult& read)
{
    return read.State == ObservationReadState::Complete && read.IdentityRevalidated &&
        !read.CancellationObserved && !read.OperationDeadlineExceeded;
}

inline std::string CapabilityJsonFileBytes(const std::wstring& json)
{
    return mcpjson::WideToUtf8(json + L"\n");
}

inline bool WriteCapabilityJson(const std::wstring& json)
{
    // Wide iostream output can truncate at localized status text in the C
    // locale. Use Unicode for consoles and explicit UTF-8 for redirected JSON.
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(output, &mode))
    {
        const std::wstring line = json + L"\n";
        size_t offset = 0;
        while (offset < line.size())
        {
            size_t length = (std::min)(size_t{4096}, line.size() - offset);
            if (length < line.size() - offset && line[offset + length - 1] >= 0xd800 && line[offset + length - 1] <= 0xdbff)
            {
                --length;
            }
            DWORD written = 0;
            if (!WriteConsoleW(output, line.data() + offset, static_cast<DWORD>(length), &written, nullptr) || written == 0)
            {
                return false;
            }
            offset += written;
        }
        return true;
    }
    const auto bytes = CapabilityJsonFileBytes(json);
    if (bytes.empty())
    {
        return false;
    }
    size_t offset = 0;
    while (offset < bytes.size())
    {
        DWORD written = 0;
        const auto length = static_cast<DWORD>((std::min)(size_t{65536}, bytes.size() - offset));
        if (!WriteFile(output, bytes.data() + offset, length, &written, nullptr) || written == 0)
        {
            return false;
        }
        offset += written;
    }
    return true;
}

inline const wchar_t* CapabilityAddressContract(const std::wstring& domain,
    const std::wstring& operation, const std::wstring& backend)
{
    if (backend == L"process_handle")
    {
        if (domain == L"image" && operation == L"capture_verification")
        {
            return L"cli_legacy_la48_with_os_user_ceiling;user_only;pointer_bytes_8";
        }
        return L"caller_descriptor_la48_la57;user_only;pointer_bytes_8";
    }
    if ((domain == L"memory" && (backend == L"native" || backend == L"dump")) ||
        (backend == L"native" && (operation == L"cross_view" || operation == L"request_graph")))
    {
        return L"source_descriptor_la48_la57;amd64;pointer_bytes_8;selected_paths_only";
    }
    if (backend == L"bundle" || backend == L"recipe" || backend == L"trace")
    {
        return L"recorded_descriptor;legacy_la48_when_declared;decoder_specific";
    }
    if (backend == L"dbgeng_dump") { return L"typed_amd64_saved_context;no_arbitrary_address_input"; }
    if (backend == L"dbgeng")
    {
        return L"backend_defined;command_text_only";
    }
    if (domain == L"schema" || domain == L"session" || domain == L"scheduler" ||
        backend == L"windows_wct" || backend == L"win32_directory_changes")
    {
        return L"not_an_address_reader";
    }
    return L"collector_specific;extended_address_pipeline_unvalidated";
}

inline const wchar_t* CapabilityAvailability(const std::wstring& implementation,
    const std::wstring& backend, const RuntimeCapabilityProbe* probe)
{
    if (probe == nullptr)
    {
        return L"not_probed";
    }
    if (implementation == L"unsupported")
    {
        return L"unsupported";
    }
    if (backend == L"process_handle")
    {
        return probe->ProcessSourceOpened && probe->ProcessReadPassed && probe->ProcessBytesMatched
            ? L"available" : L"unavailable";
    }
    if (backend == L"native")
    {
        if (!probe->NativeProbeAttempted) { return L"blocked_by_policy"; }
        // Device/ABI/session checks do not qualify any layout, read or scanner.
        return probe->NativeSourceOpened && probe->NativeContractPassed && probe->NativeSessionPassed
            ? L"partial" : L"unavailable";
    }
    return L"not_probed";
}

inline std::wstring CapabilityProbeStagesJson(const std::wstring& backend,
    const RuntimeCapabilityProbe* probe)
{
    const bool process = probe != nullptr && backend == L"process_handle";
    const bool native = probe != nullptr && probe->NativeProbeAttempted && backend == L"native";
    const auto quote = mcpjson::Quote;
    const wchar_t* source = process && probe->ProcessHandleAttempted ? (probe->ProcessSourceOpened ? L"passed" : L"failed") :
        native ? (probe->NativeSourceOpened ? L"passed" : L"failed") : L"not_probed";
    const wchar_t* sample = process && probe->ProcessReadAttempted ?
        (probe->ProcessReadPassed ? L"passed" : L"failed") : L"not_probed";
    return L"{\"source_opened\":" + quote(source) + L",\"sample_read\":" + quote(sample) +
        L",\"layout_qualified\":\"not_probed\",\"semantic_validation\":\"not_probed\","
        L"\"environment_regression\":\"not_performed\"}";
}

inline std::wstring RuntimeCapabilityProbeJson(const RuntimeCapabilityProbe& probe)
{
    const auto boolean = [](bool value) { return value ? L"true" : L"false"; };
    std::wstring actions = L"[";
    if (probe.ProcessReadAttempted) { actions += L"\"owned_process_handle_and_read\""; }
    else if (probe.ProcessHandleAttempted) { actions += L"\"owned_process_handle_attempt\""; }
    if (probe.NativeProbeAttempted)
    {
        if (actions.size() > 1) { actions += L","; }
        if (probe.NativeContractPassed) { actions += L"\"existing_native_device_open_and_status\""; }
        else if (probe.NativeSourceOpened) { actions += L"\"existing_native_device_open_and_version\""; }
        else { actions += L"\"existing_native_device_open_attempt\""; }
    }
    actions += L"]";
    return L"{\"scope\":" + mcpjson::Quote(probe.NativeProbeAttempted ?
        L"owned_process_range_and_native_connection_only" : L"owned_process_range_only") + L","
        L"\"clock_domain\":\"collector_GetTickCount64\",\"started_ms\":" + std::to_wstring(probe.StartedMs) +
        L",\"finished_ms\":" + std::to_wstring(probe.FinishedMs) +
        L",\"process_id\":" + std::to_wstring(probe.ProcessId) +
        L",\"process_create_time\":" + mcpjson::Quote(std::to_wstring(probe.ProcessCreateTime)) +
        L",\"process_handle_attempted\":" + boolean(probe.ProcessHandleAttempted) +
        L",\"process_source_opened\":" + boolean(probe.ProcessSourceOpened) +
        L",\"process_read_attempted\":" + boolean(probe.ProcessReadAttempted) +
        L",\"process_read_may_change_residency\":" + boolean(probe.ProcessReadAttempted) +
        L",\"sample_bytes_matched\":" + boolean(probe.ProcessBytesMatched) +
        L",\"process_reason\":" + mcpjson::Quote(probe.ProcessReason) +
        L",\"process_read\":" + probe.ProcessReadJson +
        L",\"process_read_set\":" + probe.ProcessReadSetJson +
        L",\"process_handle_timeline\":" + probe.ProcessHandleTimelineJson +
        L",\"process_handles_acquired\":" + std::to_wstring(probe.ProcessHandlesAcquired) +
        L",\"process_handles_closed\":" + std::to_wstring(probe.ProcessHandlesClosed) +
        L",\"process_address_shape\":\"legacy_la48_probe_only_not_active_paging_detection\","
        L"\"native_probe_attempted\":" + boolean(probe.NativeProbeAttempted) +
        L",\"native_source_opened\":" + boolean(probe.NativeSourceOpened) +
        L",\"native_contract_passed\":" + boolean(probe.NativeContractPassed) +
        L",\"native_session_passed\":" + boolean(probe.NativeSessionPassed) +
        L",\"native_source_epoch\":" + std::to_wstring(probe.NativeSourceEpoch) +
        L",\"native_virtual_address_bits\":" + (probe.NativeContractPassed ? std::to_wstring(probe.NativeVirtualAddressBits) : L"null") +
        L",\"native_read_observation_contract\":" + (probe.NativeContractPassed ? boolean(probe.NativeReadObservationSupported) : L"null") +
        L",\"native_reason\":" + mcpjson::Quote(probe.NativeReason) +
        L",\"native_close_win32_status\":" + (probe.NativeCloseAttempted ? std::to_wstring(probe.NativeCloseError) : L"null") +
        L",\"native_close_succeeded\":" + (probe.NativeCloseAttempted ? boolean(probe.NativeCloseSucceeded) : L"null") +
        L",\"native_raw_status_available\":false,\"probe_handles_closed\":" +
        boolean(probe.ProcessHandlesAcquired == probe.ProcessHandlesClosed && (!probe.NativeSourceOpened ||
            (probe.NativeCloseAttempted && probe.NativeCloseSucceeded))) + L","
        L"\"observer_actions\":" + actions + L","
        L"\"driver_load_requested\":false,\"symbol_network_requested\":false,"
        L"\"mutation_requested\":false,\"validation\":\"not_performed_for_target_environment\"}";
}
