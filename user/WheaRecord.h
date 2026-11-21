#pragma once

#include <Windows.h>
#include <DbgEng.h>
#include <cstdint>
#include <string>
#include <optional>

// Evidence from the one CPER named by a matched saved AMD64 stop tuple.
struct WheaRecord
{
    std::wstring status = L"stop_tuple_unavailable";
    std::wstring reads, header = L"null", sections = L"null", issues;
    std::wstring contrary, missing;
    std::wstring digest, fatalState = L"unresolved";
    size_t captured = 0;
    std::optional<uint64_t> stopMciStatus;

    std::wstring Json() const;
    std::wstring Hypothesis() const;
};

void InspectStopWheaRecord(IDebugClient4& client, uint64_t sourceType, uint64_t address,
    uint64_t statusHigh, uint64_t statusLow, WheaRecord& result);
