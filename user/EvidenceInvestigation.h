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
};

EvidenceQueryResult QueryEvidenceDirectory(const std::wstring& directory, const KmonHuntFilter& filter = {},
    const KmonHuntQueryOptions& options = {});
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
