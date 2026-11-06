#pragma once

#include "ObservationReadRouting.h"
#include "ReadReceiptJson.h"

bool ValidObservationRoutedReadSet(const ObservationRoutedReadSet& set);
bool ParseObservationRoutedReadSet(const std::wstring& json, ObservationRoutedReadSet* set);

inline std::wstring ObservationRoutedReadSetJson(const ObservationRoutedReadSet& set)
{
    const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
    std::wstring json = L"{\"schema\":\"kn.routed_reads.v1\",\"reference_preserved\":false,"
        L"\"image_verification_replayed\":false,\"collector_authenticated\":false,\"atomic_snapshot\":false,"
        L"\"scope\":\"parser_byte_reads_excludes_source_initialization\",\"unrecorded_parser_calls\":" +
        n(set.UnrecordedParserCalls) + L",\"attempts\":" + ObservationReadSetJson(set.Attempts) + L",\"parser_reads\":[";
    for (const auto& call : set.ParserReads)
    {
        if (&call != &set.ParserReads.front()) { json += L","; }
        json += L"{\"address\":" + n(call.Address) + L",\"length\":" + n(call.Length) +
            L",\"primary_receipt\":" + n(call.PrimaryReceipt) + L",\"returned_receipt\":" + n(call.ReturnedReceipt) +
            L",\"accepted\":" + (call.Accepted ? L"true" : L"false") + L",\"before_guard\":" + mcpjson::Quote(call.BeforeGuard) +
            L",\"after_guard\":" + mcpjson::Quote(call.AfterGuard) + L",\"reason\":" + mcpjson::Quote(call.Reason) + L"}";
    }
    return json + L"]}";
}
