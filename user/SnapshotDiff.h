#pragma once

#include "SnapshotModel.h"

#include <map>
#include <string>
#include <vector>

struct SnapshotDiffOptions
{
    bool Details = false;
    bool SummaryOnly = false;
    bool HighOnly = false;
    bool InMemoryBaseline = false;
    uint32_t Limit = 10;
    std::wstring DomainFilter;
};

struct SnapshotDiffFinding
{
    std::wstring Kind;
    SnapshotRecord OldRecord;
    SnapshotRecord NewRecord;
};

struct SnapshotDiffDomainSummary
{
    std::wstring Domain;
    uint64_t Added = 0;
    uint64_t Escalated = 0;
    uint64_t High = 0;
    uint64_t Medium = 0;
    uint64_t PoolPeSuspect = 0;
    uint64_t PoolPe = 0;
    uint64_t PoolWx = 0;
    uint64_t VadNewProcesses = 0;
    uint64_t VadScanned = 0;
    uint64_t VadHiddenPte = 0;
    uint64_t VadWxHidden = 0;
    uint64_t VadFailed = 0;
    uint64_t HiddenChildFindings = 0;
};

struct SnapshotDiffResult
{
    std::wstring BaselineLabel;
    std::wstring CurrentLabel;
    std::wstring ReportPath;
    bool SameBoot = true;
    uint64_t Added = 0;
    uint64_t Escalated = 0;
    uint64_t High = 0;
    std::vector<std::wstring> Warnings;
    std::vector<SnapshotDiffFinding> Findings;
    std::map<std::wstring, SnapshotDiffDomainSummary> Domains;
};

bool BuildSnapshotDiff(
    const SnapshotDocument& oldSnapshot,
    const SnapshotDocument& newSnapshot,
    const SnapshotDiffOptions& options,
    SnapshotDiffResult* result,
    std::wstring* error);

bool SnapshotDriverDispatchDiffSelfTest();
