#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct TimelineEvent
{
    uint64_t EventId = 0;
    uint64_t TimestampFileTime = 0;
    std::wstring TimestampUtc;
    std::wstring Source;
    std::wstring Domain;
    std::wstring Action;
    uint32_t ProcessId = 0;
    uint32_t ThreadId = 0;
    uint32_t TargetProcessId = 0;
    std::wstring Entity;
    std::wstring Summary;
    std::wstring Risk;
    std::wstring Confidence;
    std::map<std::wstring, std::wstring> Evidence;
};

struct TimelineQueryOptions
{
    std::wstring Source;
    std::wstring Domain;
    bool HasProcessId = false;
    uint32_t ProcessId = 0;
    size_t Limit = 50;
    bool NewestFirst = true;
};

struct TimelineIngestResult
{
    uint64_t SourceRecords = 0;
    uint64_t Added = 0;
    uint64_t Dropped = 0;
    std::vector<std::wstring> Warnings;
};

struct TimelineStats
{
    uint64_t Stored = 0;
    uint64_t Capacity = 0;
    uint64_t NextEventId = 0;
    uint64_t Dropped = 0;
    std::map<std::wstring, uint64_t> BySource;
    std::map<std::wstring, uint64_t> ByDomain;
};

std::wstring TimelineToLower(const std::wstring& value);
std::wstring TimelineEventToJson(const TimelineEvent& event);
std::wstring BuildTimelineEventsJson(
    const std::vector<TimelineEvent>& events,
    const TimelineQueryOptions& options,
    uint64_t totalStored);
std::wstring BuildTimelineStatusJson(const TimelineStats& stats);
std::wstring BuildTimelineJsonl(const std::vector<TimelineEvent>& events);
