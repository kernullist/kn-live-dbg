#pragma once

#include "EvidenceBundle.h"
#include "CodeTargetResolver.h"

struct EvidenceSessionSummary
{
    std::wstring CollectionId;
    uint64_t Admitted = 0;
    uint64_t Written = 0;
    uint64_t Failed = 0;
    uint64_t Dropped = 0;
    uint64_t Bytes = 0;
};
std::wstring EvidenceSessionJson(const EvidenceSessionSummary& session);
bool ParseEvidenceSession(const std::wstring& json, EvidenceSessionSummary* session);

struct EvidenceCaseSummary
{
    std::wstring FileName;
    std::wstring Digest;
    std::wstring CollectionId;
    KmonHuntReceipt Receipt;
    bool ReadSetComplete = false;
};

struct EvidenceQueryResult
{
    std::wstring Status = L"ok";
    std::wstring InventoryDigest;
    std::wstring NextCursor;
    std::vector<EvidenceCaseSummary> Cases;
    std::vector<EvidenceSessionSummary> Sessions;
    size_t UnclosedCollections = 0;
    uint64_t UnavailableWrittenBundles = 0;
    size_t Matched = 0;
    size_t Offset = 0;
    size_t Limit = 256;
    size_t InvalidFiles = 0;
    size_t DuplicateFiles = 0;
    size_t ImportedFiles = 0;
    bool InventoryComplete = true;
    bool UsesSnapshot = false;
    bool PublicationClosureEvaluated = true;
    std::wstring SnapshotDigest;
    std::wstring InventoryCursor;
    std::wstring NextInventoryCursor;
    size_t SnapshotEntries = 0;
    size_t InventoryOffset = 0;
    size_t InspectedFiles = 0;
    size_t ReadBytes = 0;
};

struct EvidenceInventoryOptions
{
    std::wstring Path;
    std::wstring Cursor;
    size_t WindowFiles = 4096;
    size_t ReadBudget = 64 * 1024 * 1024;
};

EvidenceQueryResult QueryEvidenceDirectory(const std::wstring& directory, const KmonHuntFilter& filter = {},
    const KmonHuntQueryOptions& options = {}, const EvidenceInventoryOptions& inventory = {});
std::wstring EvidenceQueryJson(const EvidenceQueryResult& result, const KmonHuntFilter& filter);

struct EvidenceReplayResult
{
    CodeTargetChain Chain;
    std::wstring PageDigest = L"not_replayed";
    std::wstring Slot = L"not_applicable";
    std::vector<std::wstring> Gaps;
    bool ReferenceReached = false;
};

EvidenceReplayResult ReplayEvidence(const EvidenceBundle& bundle);
std::wstring EvidenceReplayJson(const EvidenceBundle& bundle, const EvidenceReplayResult& result, const std::wstring& digest);
