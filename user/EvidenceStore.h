#pragma once

#include "EvidenceJournal.h"
#include <memory>

// Shared by participating publishers; exclusive for a stopped-store inventory.
// This is coordination, not an access-control or collector-authentication boundary.
class EvidenceStoreLease
{
public:
    EvidenceStoreLease();
    ~EvidenceStoreLease();
    EvidenceStoreLease(const EvidenceStoreLease&) = delete;
    EvidenceStoreLease& operator=(const EvidenceStoreLease&) = delete;
    bool Acquire(const std::wstring& root, bool exclusive, std::wstring* error, bool createRoot = false);
private:
    struct Impl;
    std::unique_ptr<Impl> Data;
};

struct EvidenceStoreCollection
{
    std::wstring Id;
    EvidenceJournalRecovery Recovery;
};

struct EvidenceStoreApprovalReferrer
{
    std::wstring Path, Sha256;
    bool InputMatched;
};

struct EvidenceStoreImageReferrer
{
    std::wstring Path, Sha256, ExpectedSha256;
    bool PayloadDigest, InputMatched;
};

struct EvidenceStoreArtifact
{
    EvidenceJournalMember Artifact;
    std::vector<std::wstring> Collections;
    std::vector<EvidenceStoreApprovalReferrer> ApprovalReferrers;
    std::wstring ApprovalCatalog;
    std::vector<EvidenceStoreImageReferrer> ImageReferrers;
    std::wstring ImageCatalog, ImagePayloadSha256;
    uint64_t JournalReferences = 0;
    bool Verified = false;
    std::wstring Retention;
};

struct EvidenceStoreInventory
{
    std::wstring Status = L"unavailable", Issue, CatalogSha256;
    std::wstring ArtifactsSha256;
    uint64_t StartedTick = 0, EndedTick = 0;
    uint64_t CollectionsObserved = 0, ClosedCollections = 0, OpenCollections = 0, UnresolvedCollections = 0;
    uint64_t CommittedSegments = 0, MemberReferences = 0, CollectionPathReferences = 0;
    uint64_t LogicalReferenceBytes = 0, CollectionPathBytes = 0, UniquePathBytes = 0, UniqueContentBytes = 0;
    uint64_t ObservedArtifactFiles = 0, UnverifiedArtifactFiles = 0, UnmanagedEntries = 0;
    uint64_t UnattributedFiles = 0, UnattributedBytes = 0, ReadBytes = 0;
    uint64_t UncommittedApprovalRoots = 0, UnreadableApprovalCatalogs = 0;
    uint64_t MissingApprovalInputs = 0, MismatchedApprovalInputs = 0;
    uint64_t UncommittedImageRoots = 0, UnreadableImageCatalogs = 0;
    uint64_t MissingImageInputs = 0, MismatchedImageInputs = 0;
    bool CatalogComplete = false, MembershipComplete = false, ArtifactInventoryComplete = false;
    std::vector<EvidenceStoreCollection> Collections;
    std::vector<EvidenceStoreArtifact> Artifacts;
};

// Exact counts for the image folders and reserved IRP root namespace under the participating
// publisher barrier. The returned data releases all leases and NEVER grants
// deletion authority. Unresolved roots protect all unattributed artifacts.
EvidenceStoreInventory InspectEvidenceStore(const std::wstring& artifactRoot);
std::wstring EvidenceStoreInventoryJson(const EvidenceStoreInventory& inventory, bool includeArtifacts = false);
