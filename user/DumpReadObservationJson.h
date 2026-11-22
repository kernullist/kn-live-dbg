#pragma once

#include "DumpObservationSource.h"
#include "TranslationReceiptJson.h"

inline std::wstring DumpReadObservationJson(const DumpReadObservation& observed)
{
    std::wstring json = L"{\"schema\":\"kn.dump_read.v1\",\"scope\":\"requested_range_after_source_initialization\","
        L"\"initialization_reads_included\":false,\"collector_authenticated\":false,\"read\":" +
        ObservationReadJson(observed.Source, observed.Request, observed.Result) +
        L",\"physical_read_set\":" + ObservationReadSetJson(observed.PhysicalReads) + L",\"translations\":[";
    for (const auto& translation : observed.Translations)
    {
        if (&translation != &observed.Translations.front()) { json += L","; }
        json += TranslationReceiptJson(translation);
    }
    return json + L"]}";
}

inline std::wstring DumpProbeReadsJson(const std::vector<DumpInitializationProbeRead>& reads)
{
    std::wstring json = L"[";
    for (const auto& read : reads)
    {
        if (&read != &reads.front()) { json += L','; }
        json += L"{\"purpose\":" + mcpjson::Quote(read.Purpose) + L",\"candidate_levels\":" + std::to_wstring(read.CandidateLevels) +
            L",\"source_id\":" + mcpjson::Quote(read.Original.SourceId) + L",\"virtual_address\":" +
            mcpjson::Quote(std::to_wstring(read.Address)) + L",\"requested_bytes\":" + std::to_wstring(read.Length) +
            L",\"state\":" + mcpjson::Quote(ObservationReadStateName(read.Original.State)) +
            L",\"parser_accepted\":" + (read.ParserAccepted ? L"true" : L"false") +
            L",\"first_file_sequence\":" + (read.FileReadCount ? std::to_wstring(read.FirstFileSequence) : L"null") +
            L",\"file_read_count\":" + std::to_wstring(read.FileReadCount) + L",\"spans\":[";
        for (const auto& span : read.Original.Spans)
        {
            if (&span != &read.Original.Spans.front()) { json += L','; }
            json += L"{\"requested_bytes\":" + std::to_wstring(span.RequestedBytes) +
                L",\"state\":" + mcpjson::Quote(ObservationReadStateName(span.State)) + L"}";
        }
        json += L"]}";
    }
    return json + L"]";
}

inline std::wstring DumpInitializationJson(const DumpInitializationObservation& init)
{
    const auto number = [](const std::optional<uint32_t>& value) { return value ? std::to_wstring(*value) : L"null"; };
    const auto large = [](const std::optional<uint64_t>& value) { return value ? mcpjson::Quote(std::to_wstring(*value)) : L"null"; };
    const auto id = init.SourceId.empty() ? L"null" : mcpjson::Quote(init.SourceId);
    const auto operation = init.SourceId.empty() ? L"null" : mcpjson::Quote(init.SourceId + L":initialization");
    std::wstring json = L"{\"schema\":\"kn.dump_initialization.v1\",\"operation_id\":" + operation +
        L",\"source_id\":" + id + L",\"source_bytes\":" + large(init.FileBytes) +
        L",\"decision\":" + mcpjson::Quote(init.Decision) + L",\"open_win32_status\":" + number(init.OpenStatus) +
        L",\"qualification_win32_error\":" + number(init.QualificationError) +
        L",\"four_level_probe\":" + mcpjson::Quote(init.Probe4) + L",\"five_level_probe\":" + mcpjson::Quote(init.Probe5) +
        L",\"context_levels\":" + number(init.ContextLevels) + L",\"selected_levels\":" + number(init.SelectedLevels) +
        L",\"final_identity_matched\":" + (!init.FinalIdentityMatched ? L"null" : *init.FinalIdentityMatched ? L"true" : L"false") +
        L",\"final_identity_win32_status\":" + number(init.FinalIdentityStatus) +
        L",\"clock_domain\":\"collector_GetTickCount64\",\"max_reads\":" + std::to_wstring(init.MaxReads) +
        L",\"max_requested_bytes\":" + std::to_wstring(init.MaxRequestedBytes) +
        L",\"attempts\":" + std::to_wstring(init.Attempts) + L",\"charged_requested_bytes\":" + std::to_wstring(init.ChargedBytes) +
        L",\"recording_complete\":" + (init.RecordingComplete ? L"true" : L"false") +
        L",\"probe_reads\":" + DumpProbeReadsJson(init.ProbeReads) + L",\"reads\":[";
    for (size_t i = 0; i < init.Reads.size(); ++i)
    {
        const auto& r = init.Reads[i];
        if (i) { json += L','; }
        json += L"{\"sequence\":" + std::to_wstring(i + 1) + L",\"purpose\":" + mcpjson::Quote(r.Purpose) +
            L",\"candidate_levels\":" + (r.CandidateLevels ? std::to_wstring(r.CandidateLevels) : L"null") +
            L",\"physical_address\":" + large(r.PhysicalAddress) + L",\"file_offset\":" + large(r.FileOffset) +
            L",\"requested_bytes\":" + std::to_wstring(r.RequestedBytes) +
            L",\"state\":" + mcpjson::Quote(ObservationReadStateName(r.State)) +
            L",\"seek_win32_status\":" + number(r.SeekStatus) + L",\"read_win32_status\":" + number(r.ReadStatus) +
            L",\"transferred_bytes\":" + number(r.TransferredBytes) + L",\"identity_failure_win32_status\":" + number(r.IdentityFailureStatus) +
            L",\"hash_input_bytes\":" + std::to_wstring(r.DigestBytes) +
            L",\"sha256\":" + (r.Sha256.empty() ? L"null" : mcpjson::Quote(r.Sha256)) +
            L",\"started_ms\":" + std::to_wstring(r.StartedMs) + L",\"finished_ms\":" + std::to_wstring(r.FinishedMs) + L"}";
    }
    return json + L"]}";
}

inline std::wstring DumpReadWithInitializationJson(const DumpInitializationObservation& init,
    const DumpReadObservation* observed, const std::wstring& error)
{
    return std::wstring(L"{\"schema\":\"kn.dump_read.v2\",\"scope\":\"source_initialization_and_requested_range\",") +
        L"\"initialization_reads_included\":true,\"collector_authenticated\":false,\"status\":" +
        mcpjson::Quote(observed ? ObservationReadStateName(observed->Result.State) : L"unavailable") +
        L",\"error\":" + (error.empty() ? L"null" : mcpjson::Quote(error)) + L",\"initialization\":" + DumpInitializationJson(init) +
        L",\"requested_range\":" + (observed ? DumpReadObservationJson(*observed) : L"null") + L"}";
}
