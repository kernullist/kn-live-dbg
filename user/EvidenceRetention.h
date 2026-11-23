#pragma once

#include "EvidenceStore.h"
#include <functional>

struct EvidenceStoreReceipts
{
    std::wstring Catalog, Files;
};

struct EvidenceRetentionOptions
{
    EvidenceStoreReceipts Receipts;
    bool Apply = false;
    std::wstring OperationId;
};

bool ParseEvidenceRetentionOptions(const std::vector<std::wstring>& flags, bool retireCollection, EvidenceRetentionOptions& options);

// Explicit operator selection, never inferred from a released inventory.
// Retired originals require a separate policy bound to the retirement receipt.
struct EvidenceGcPolicy
{
    std::wstring Reason;
    std::wstring RetiredCollection, RetirementSha256;
    uint64_t MinimumAgeSeconds = 86400;
    uint64_t ByteLimit = 128ull * 1024 * 1024;
    std::vector<EvidenceJournalMember> Members;
};

struct EvidenceGcEntry
{
    EvidenceJournalMember Artifact;
    std::wstring State, Issue, FileIdentity, IntentSha256, ReceiptSha256;
    uint64_t LastWriteTime = 0;
    bool ReusedReceipt = false;
};

struct EvidenceGcResult
{
    std::wstring Status = L"unavailable", Issue, OperationId, PolicySha256, CatalogSha256, ArtifactsSha256;
    std::wstring RootIdentity, OperationSha256;
    uint64_t ObservedFileTime = 0, SelectedBytes = 0, DeletedThisCall = 0, DeletedBytesThisCall = 0;
    bool Apply = false;
    std::wstring RetiredCollection, RetirementSha256;
    std::vector<EvidenceGcEntry> Entries;
};

std::wstring EvidenceGcPolicyJson(const EvidenceGcPolicy& policy);
bool ParseEvidenceGcPolicy(const std::wstring& json, EvidenceGcPolicy* policy);
// Empty operation ID performs preflight only. An explicit ID applies or resumes
// that exact policy under the exclusive store barrier. Observer runs synchronously
// under the leases and must not reenter the store. Exceptions stop further work.
EvidenceGcResult CollectEvidenceStore(const std::wstring& root, const std::wstring& policyPath,
    const std::wstring& operationId = L"", const std::function<void(const wchar_t*)>& observer = {},
    const EvidenceStoreReceipts& receipts = {});
std::wstring EvidenceGcResultJson(const EvidenceGcResult& result);

struct EvidenceRetirementResult
{
    std::wstring Status = L"unavailable", Issue, PolicySha256, ReceiptSha256, Record;
    bool Apply = false, Reused = false;
};

// A single create-new record withdraws a closed root. Physical cleanup uses GC.
EvidenceRetirementResult RetireEvidenceCollection(const std::wstring& root, const std::wstring& policyPath,
    bool apply, const std::function<void(const wchar_t*)>& observer = {}, const EvidenceStoreReceipts& receipts = {});
std::wstring EvidenceRetirementResultJson(const EvidenceRetirementResult& result);
