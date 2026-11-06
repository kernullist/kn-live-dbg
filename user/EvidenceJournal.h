#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Physical file hashes, distinct from hashes of canonical JSON payloads.
struct EvidenceJournalMember
{
    std::wstring Path, Sha256, Schema;
    uint64_t Bytes = 0;
};

struct EvidenceJournalTransaction
{
    std::wstring Kind, Id;
    std::vector<EvidenceJournalMember> Members;
    // Every dependency must already belong to the verified committed prefix.
    std::vector<std::wstring> Requires;
};

struct EvidenceJournalRecovery
{
    std::wstring Status = L"unavailable", Issue, CollectionId, SessionSha256, HeadSha256;
    uint64_t CommittedSegments = 0, MemberReferences = 0, UniquePaths = 0;
    uint64_t LogicalBytes = 0, UniqueContentBytes = 0, ReadBytes = 0;
    uint64_t PendingFiles = 0, IndexCreated = 0, IndexReused = 0;
    bool Closed = false, CanResume = false;
    std::wstring IndexStatus = L"not_requested";
    // These roots are collection members, not evidence of successful replay.
    std::vector<std::wstring> SweepPaths;
};

struct EvidenceJournalCommit
{
    bool Committed = false, AlreadyCommitted = false, Indexed = false;
    std::wstring Issue;
    uint64_t Sequence = 0;
};

struct EvidenceStoreInventory;

// One writer owns the collection lock and immutable-file leases. Recovery uses
// the same lock: no live snapshot can be mistaken for a final committed prefix.
// The caller owns raw-file publication; the journal never deletes or replaces it.
class EvidenceJournal
{
public:
    EvidenceJournal();
    ~EvidenceJournal();
    EvidenceJournal(const EvidenceJournal&) = delete;
    EvidenceJournal& operator=(const EvidenceJournal&) = delete;
    bool Open(const std::wstring& artifactRoot, const std::wstring& collectionId, std::wstring* error);
    EvidenceJournalCommit Commit(EvidenceJournalTransaction transaction);
    const EvidenceJournalRecovery& State() const;
private:
    friend EvidenceJournalRecovery RecoverEvidenceJournal(const std::wstring&, bool);
    friend EvidenceStoreInventory InspectEvidenceStore(const std::wstring&);
    friend struct EvidenceStoreAccess;
    struct Impl;
    std::unique_ptr<Impl> Data;
};

// collectionDirectory must be <artifact-root>/collections/<collection-id>.
// /index reuses exact completed chunks, then publishes an immutable head. The
// complete journal and original files are revalidated even when chunks exist.
EvidenceJournalRecovery RecoverEvidenceJournal(const std::wstring& collectionDirectory, bool rebuildIndex = false);
std::wstring EvidenceJournalRecoveryJson(const EvidenceJournalRecovery& result);
EvidenceJournalMember EvidenceJournalJsonMember(const std::wstring& path, const std::wstring& json);
