#pragma once

#include "EvidenceStore.h"
#include <functional>

// Explicit operator selection, never inferred from a released inventory.
// This policy cannot retire a committed root or discard a failure ledger.
struct EvidenceGcPolicy
{
    std::wstring Reason;
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
    std::vector<EvidenceGcEntry> Entries;
};

std::wstring EvidenceGcPolicyJson(const EvidenceGcPolicy& policy);
bool ParseEvidenceGcPolicy(const std::wstring& json, EvidenceGcPolicy* policy);
// Empty operation ID performs preflight only. An explicit ID applies or resumes
// that exact policy under the exclusive store barrier. Observer runs synchronously
// under the leases and must not reenter the store. Exceptions stop further work.
EvidenceGcResult CollectEvidenceStore(const std::wstring& root, const std::wstring& policyPath,
    const std::wstring& operationId = L"", const std::function<void(const wchar_t*)>& observer = {});
std::wstring EvidenceGcResultJson(const EvidenceGcResult& result);
