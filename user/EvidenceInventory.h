#pragma once

#include "EvidenceInvestigation.h"
#include <atomic>

inline constexpr size_t EvidenceInventoryMaxChunks = 8192;
inline constexpr size_t EvidenceInventoryChunkEntries = 128;
inline constexpr size_t EvidenceInventoryMaxEntries = EvidenceInventoryMaxChunks * EvidenceInventoryChunkEntries;

struct EvidenceInventoryBuildOptions
{
    size_t MaximumEntries = EvidenceInventoryMaxEntries;
    uint64_t ReadBudget = 8ull * 1024 * 1024 * 1024;
    uint64_t DeadlineMs = 120000;
    const std::atomic<bool>* Cancellation = nullptr;
    bool Resume = false;
    size_t NewChunkLimit = EvidenceInventoryMaxChunks;
    // Zero requests the original full verification in the current process.
    size_t VerifyEntryLimit = 0;
};

struct EvidenceInventoryBuildResult
{
    std::wstring Status = L"unavailable";
    std::wstring Digest;
    size_t Entries = 0;
    size_t InvalidFiles = 0;
    uint64_t ReadBytes = 0;
    bool Resume = false;
    size_t ReusedEntries = 0;
    size_t VerifiedEntries = 0;
    size_t VerifyEntryLimit = 0;
    size_t ReusedVerifiedEntries = 0;
};

EvidenceInventoryBuildResult BuildEvidenceInventory(const std::wstring& directory,
    const std::wstring& newSnapshotDirectory, const EvidenceInventoryBuildOptions& options = {});
std::wstring EvidenceInventoryBuildJson(const EvidenceInventoryBuildResult& result);
EvidenceQueryResult QueryEvidenceInventory(const std::wstring& directory, const KmonHuntFilter& filter,
    const KmonHuntQueryOptions& options, const EvidenceInventoryOptions& inventory);
