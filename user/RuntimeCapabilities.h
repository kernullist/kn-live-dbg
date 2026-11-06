#pragma once

#include "McpJson.h"

#include <cstdint>
#include <algorithm>
#include <string>

struct RuntimeCapabilityProbe
{
    uint64_t StartedMs = 0;
    uint64_t FinishedMs = 0;
    uint32_t ProcessId = 0;
    uint64_t ProcessCreateTime = 0;
    bool ProcessSourceOpened = false;
    bool ProcessReadAttempted = false;
    bool ProcessReadPassed = false;
    bool ProcessBytesMatched = false;
    std::wstring ProcessReason;
    std::wstring ProcessReadJson = L"null";
    std::wstring ProcessReadSetJson = L"null";
    bool NativeSourceOpened = false;
    bool NativeContractPassed = false;
    bool NativeSessionPassed = false;
    uint64_t NativeSourceEpoch = 0;
    uint32_t NativeVirtualAddressBits = 0;
    std::wstring NativeReason;
};

RuntimeCapabilityProbe ProbeRuntimeCapabilities();

inline bool WriteCapabilityJson(const std::wstring& json)
{
    // Wide iostream output can truncate at localized status text in the C
    // locale. Use Unicode for consoles and explicit UTF-8 for redirected JSON.
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    const std::wstring line = json + L"\n";
    DWORD mode = 0;
    if (GetConsoleMode(output, &mode))
    {
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
    const auto bytes = mcpjson::WideToUtf8(line);
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
    if (backend == L"dbgeng")
    {
        return L"backend_defined;command_text_only";
    }
    if (domain == L"schema" || domain == L"session" || domain == L"scheduler")
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
    const bool native = probe != nullptr && backend == L"native";
    const auto quote = mcpjson::Quote;
    const wchar_t* source = process ? (probe->ProcessSourceOpened ? L"passed" : L"failed") :
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
    return L"{\"scope\":\"owned_process_range_and_native_connection_only\","
        L"\"clock_domain\":\"collector_GetTickCount64\",\"started_ms\":" + std::to_wstring(probe.StartedMs) +
        L",\"finished_ms\":" + std::to_wstring(probe.FinishedMs) +
        L",\"process_id\":" + std::to_wstring(probe.ProcessId) +
        L",\"process_create_time\":" + mcpjson::Quote(std::to_wstring(probe.ProcessCreateTime)) +
        L",\"process_source_opened\":" + boolean(probe.ProcessSourceOpened) +
        L",\"sample_bytes_matched\":" + boolean(probe.ProcessBytesMatched) +
        L",\"process_reason\":" + mcpjson::Quote(probe.ProcessReason) +
        L",\"process_read\":" + probe.ProcessReadJson +
        L",\"process_read_set\":" + probe.ProcessReadSetJson +
        L",\"process_address_shape\":\"legacy_la48_probe_only_not_active_paging_detection\","
        L"\"native_source_opened\":" + boolean(probe.NativeSourceOpened) +
        L",\"native_contract_passed\":" + boolean(probe.NativeContractPassed) +
        L",\"native_session_passed\":" + boolean(probe.NativeSessionPassed) +
        L",\"native_source_epoch\":" + std::to_wstring(probe.NativeSourceEpoch) +
        L",\"native_virtual_address_bits\":" + (probe.NativeContractPassed ? std::to_wstring(probe.NativeVirtualAddressBits) : L"null") +
        L",\"native_reason\":" + mcpjson::Quote(probe.NativeReason) +
        L",\"native_raw_status_available\":false,\"probe_handles_closed\":true,"
        L"\"observer_actions\":[\"owned_process_handle_and_read\",\"existing_native_device_open_and_status\"],"
        L"\"driver_load_requested\":false,\"symbol_network_requested\":false,"
        L"\"mutation_requested\":false,\"validation\":\"not_performed_for_target_environment\"}";
}
