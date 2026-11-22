#pragma once

#include "EtlProfileRecord.h"
#include <atomic>
#include <map>
#include <optional>
#include <string>
#include <vector>

struct EtlTraceSample : etl_profile::Sample
{
    std::wstring ReportedClrFields;
};

struct EtlTracePage
{
    std::wstring Schema, EtlSha256, ClockKind, ClockJson, LogHeaderJson, BufferComparison;
    uint64_t EtlBytes = 0, BuffersProcessed = 0;
    std::optional<uint64_t> TicksPerSecond;
    uint32_t RecordsSeen = 0, Decoded = 0, Unsupported = 0, LossMarkers = 0, After = 0;
    std::optional<uint32_t> NextAfter;
    bool Partial = false, ReversedTicks = false;
    std::vector<EtlTraceSample> Rows;
};

bool ParseEtlTracePage(const std::map<std::wstring, std::wstring>& root, unsigned version,
    EtlTracePage& page, const std::atomic<bool>* cancellation);
std::wstring EtlTraceQueryFields(const EtlTracePage& page, size_t offset, size_t end, const std::wstring& cursor);
