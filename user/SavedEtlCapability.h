#pragma once

#include "CapabilityProbeContracts.h"
#include "EtlProfileRecord.h"
#include "McpJson.h"
#include <optional>
#include <string_view>

struct EtlCapabilityRecords
{
    uint32_t Decoded = 0, Unsupported = 0, FirstDecodedRecord = 0;
    uint16_t FirstPayloadBytes = 0;
    std::wstring FirstPayloadSha256;

    void Count(etl_profile::Match match, uint32_t ordinal)
    {
        if (match == etl_profile::Match::Decoded)
        {
            if (!Decoded) { FirstDecodedRecord = ordinal; }
            ++Decoded;
        }
        else if (match == etl_profile::Match::Unsupported) { ++Unsupported; }
    }
};

struct EtlCapabilityCoverage
{
    EtlCapabilityRecords Profile, Switches, DiskIo;
    uint32_t RecordsSeen = 0, EventsLost = 0, BuffersLost = 0, LossMarkers = 0, BuffersWritten = 0;
    uint32_t LogMode = 0;
    uint64_t BuffersProcessed = 0;
    etl_profile::BufferAccounting Accounting = etl_profile::BufferAccounting::Unavailable;

    bool HasGap() const
    {
        return Accounting != etl_profile::BufferAccounting::Matched || EventsLost || BuffersLost || LossMarkers;
    }
};

struct SavedEtlCapabilityProbe
{
    static constexpr auto Scope = L"saved_etl_probe";
    static constexpr auto AvailabilityScope = capability_probes::SavedEtl.AvailabilityScope;
    std::wstring ExpectedSha256, SourceSha256;
    uint64_t SourceBytes = 0;
    const wchar_t* Status = L"source_unavailable";
    std::optional<ULONG> Win32Status;
    std::optional<bool> SourceRevalidated;
    bool TraceOpened = false;
    std::optional<EtlCapabilityCoverage> Coverage;

    static bool Covers(std::wstring_view domain, std::wstring_view operation, std::wstring_view backend)
    {
        return capability_probes::For(domain, operation, backend) == &capability_probes::SavedEtl;
    }

    const EtlCapabilityRecords* Records(std::wstring_view operation) const
    {
        if (!Coverage) { return nullptr; }
        if (operation == L"cpu_profile") { return &Coverage->Profile; }
        if (operation == L"context_switch") { return &Coverage->Switches; }
        if (operation == L"disk_io") { return &Coverage->DiskIo; }
        return nullptr;
    }

    const wchar_t* Availability(std::wstring_view operation) const
    {
        const auto* records = Records(operation);
        if (!records) { return L"unavailable"; }
        return records->Decoded && !records->Unsupported && !Coverage->HasGap() ? L"available" : L"partial";
    }

    std::wstring StagesJson(std::wstring_view operation) const
    {
        const auto* records = Records(operation);
        const bool decoded = records && records->Decoded;
        const auto layout = records && records->Unsupported ? (decoded ? L"partial" : L"failed") :
            decoded ? L"passed" : L"not_probed";
        return L"{\"source_opened\":" + mcpjson::Quote(SourceSha256.empty() ? L"failed" : L"passed") +
            L",\"sample_read\":" + mcpjson::Quote(decoded ? L"passed" : L"not_probed") +
            L",\"layout_qualified\":" + mcpjson::Quote(layout) +
            L",\"semantic_validation\":\"not_probed\",\"environment_regression\":\"not_performed\"}";
    }

    std::wstring RecordsJson(std::wstring_view operation) const
    {
        const auto* records = Records(operation);
        if (!records) { return L"null"; }
        const auto observation = records->Decoded ? L"decoded_records" :
            records->Unsupported ? L"unsupported_layout_only" : L"no_matching_records_observed";
        return L"{\"observation\":" + mcpjson::Quote(observation) +
            L",\"decoded\":" + std::to_wstring(records->Decoded) +
            L",\"unsupported\":" + std::to_wstring(records->Unsupported) +
            L",\"first_decoded_record\":" + (records->Decoded ? std::to_wstring(records->FirstDecodedRecord) : L"null") +
            L",\"first_payload_bytes\":" + (records->Decoded ? std::to_wstring(records->FirstPayloadBytes) : L"null") +
            L",\"first_payload_sha256\":" + (records->FirstPayloadSha256.empty() ? L"null" : mcpjson::Quote(records->FirstPayloadSha256)) + L"}";
    }

    std::wstring EvidenceJson(std::wstring_view operation) const
    {
        return L",\"record_evidence\":" + RecordsJson(operation);
    }

    std::wstring Json() const
    {
        std::wstring coverage = L"null", rotation;
        if (Coverage)
        {
            const auto& c = *Coverage;
            if (c.LogMode & EVENT_TRACE_FILE_MODE_NEWFILE)
            {
                rotation = L",\"rotation_member\":{\"scope\":\"supplied_file\",\"log_mode\":" + std::to_wstring(c.LogMode) +
                    L",\"ordinal\":null,\"set_size\":null,\"session_complete\":null}";
            }
            coverage = L"{\"records_seen\":" + std::to_wstring(c.RecordsSeen) +
                L",\"buffers_written\":" + std::to_wstring(c.BuffersWritten) +
                L",\"buffers_processed\":" + std::to_wstring(c.BuffersProcessed) +
                L",\"buffer_comparison\":" + mcpjson::Quote(etl_profile::BufferComparisonName(c.Accounting)) +
                L",\"events_lost\":" + std::to_wstring(c.EventsLost) + L",\"buffers_lost\":" + std::to_wstring(c.BuffersLost) +
                L",\"loss_marker_records\":" + std::to_wstring(c.LossMarkers) + L"}";
        }
        return L"{\"schema\":\"kn.etl_capability_probe.v1\",\"status\":" + mcpjson::Quote(Status) +
            L",\"expected_sha256\":" + mcpjson::Quote(ExpectedSha256) +
            L",\"source_sha256\":" + (SourceSha256.empty() ? L"null" : mcpjson::Quote(SourceSha256)) +
            L",\"source_bytes\":" + (SourceSha256.empty() ? L"null" : std::to_wstring(SourceBytes)) +
            L",\"trace_opened\":" + (TraceOpened ? L"true" : L"false") +
            L",\"source_revalidated\":" + (!SourceRevalidated ? L"null" : *SourceRevalidated ? L"true" : L"false") +
            L",\"win32_status\":" + (Win32Status ? std::to_wstring(*Win32Status) : L"null") +
            L",\"producer_authenticity\":\"unverified\"" + rotation + L",\"coverage\":" + coverage + L"}";
    }
};
