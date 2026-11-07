#pragma once

#include "EvidenceBundle.h"
#include <atomic>

struct TemporalFactQuery
{
    std::wstring Cursor;
    size_t Limit = 64;
    uint64_t MaximumGapMs = 30000, TimeBudgetMs = 1000;
    const std::atomic<bool>* Cancellation = nullptr;
};

struct TemporalFactPage
{
    std::wstring Status = L"unavailable", QueryDigest, NextCursor, Decisions = L"[]";
    size_t Offset = 0, TotalPairs = 0, Returned = 0, Supported = 0;
};

class TemporalFactStore
{
public:
    const std::wstring& Status() const { return State; }
private:
    struct Observation
    {
        EvidenceBundle Bundle;
        std::wstring Path, Digest, Id, OriginJson, ReferenceJson;
    };
    std::wstring State = L"unavailable", Issue, Digest;
    size_t Requested = 0;
    std::vector<Observation> Rows;
    friend TemporalFactStore LoadTemporalFactStore(const std::vector<std::wstring>&,
        const std::atomic<bool>*, uint64_t);
    friend TemporalFactPage QueryTemporalFacts(const TemporalFactStore&, const TemporalFactQuery&);
    friend std::wstring TemporalFactsJson(const TemporalFactStore&, const TemporalFactQuery&, const TemporalFactPage&);
};

// Exact input membership, bounded to 32 published bundles / 64 MiB. No target
// acquisition, persisted index, source bridging or current-state refresh occurs.
TemporalFactStore LoadTemporalFactStore(const std::vector<std::wstring>& paths,
    const std::atomic<bool>* cancellation = nullptr, uint64_t timeBudgetMs = 5000);
TemporalFactPage QueryTemporalFacts(const TemporalFactStore& store, const TemporalFactQuery& query);
std::wstring TemporalFactsJson(const TemporalFactStore& store, const TemporalFactQuery& query, const TemporalFactPage& page);
