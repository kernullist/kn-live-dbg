#pragma once

#include "EvidenceInvestigation.h"
#include <atomic>

struct EvidenceInventoryBuildOptions
{
    size_t MaximumEntries = 1024 * 1024;
    uint64_t ReadBudget = 8ull * 1024 * 1024 * 1024;
    uint64_t DeadlineMs = 120000;
    const std::atomic<bool>* Cancellation = nullptr;
};

struct EvidenceInventoryBuildResult
{
    std::wstring Status = L"unavailable";
    std::wstring Digest;
    size_t Entries = 0;
    size_t InvalidFiles = 0;
    uint64_t ReadBytes = 0;
};

EvidenceInventoryBuildResult BuildEvidenceInventory(const std::wstring& directory,
    const std::wstring& newSnapshotDirectory, const EvidenceInventoryBuildOptions& options = {});
std::wstring EvidenceInventoryBuildJson(const EvidenceInventoryBuildResult& result);
EvidenceQueryResult QueryEvidenceInventory(const std::wstring& directory, const KmonHuntFilter& filter,
    const KmonHuntQueryOptions& options, const EvidenceInventoryOptions& inventory);
