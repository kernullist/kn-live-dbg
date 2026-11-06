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
