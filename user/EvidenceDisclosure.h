#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

struct ImageRecipeReplay;

// A closed vocabulary: no source-controlled text, addresses, identities,
// artifact hashes, instructions, paths or byte sequences leave this projection.
struct MinimizedImageFacts
{
    std::wstring Id, Scope;
    uint64_t Extent = 0, Compared = 0, Excluded = 0, Unreadable = 0, Unobserved = 0, Changed = 0;
    bool ChangedKnown = false, ReferenceQualified = false;
};
std::wstring MinimizedImageFactsJson(const MinimizedImageFacts& facts);
bool ParseMinimizedImageFacts(const std::wstring& json, MinimizedImageFacts* facts);
bool ProjectImageDisclosure(const ImageRecipeReplay& replay, const std::wstring& id, MinimizedImageFacts* facts);
std::wstring DisclosureTextSha256(const std::wstring& text);
std::wstring NewDisclosureId();

class EvidenceDisclosureLease;
struct EvidenceDisclosurePackage
{
    std::wstring Status = L"unavailable", Issue, Root, TemporaryDirectory;
    std::wstring Id, Facts, FactsSha256, Manifest, ManifestSha256;
    // Keeps the validated private root and exact immutable files pinned during review/send.
    std::shared_ptr<EvidenceDisclosureLease> Lease;
};
EvidenceDisclosurePackage PrepareImageDisclosure(const std::wstring& source, const std::wstring& newRoot,
    bool efs = true, const std::function<void(const wchar_t*)>& observer = {});
EvidenceDisclosurePackage LoadEvidenceDisclosure(const std::wstring& root);
std::wstring EvidenceDisclosurePackageJson(const EvidenceDisclosurePackage& package);

// These are private local audit records. A caller must obtain exact operator
// approval before recording intent, and record intent before invoking transport.
bool SaveDisclosureTransferRecord(const EvidenceDisclosurePackage& package, const std::wstring& id,
    bool outcome, const std::wstring& json, std::wstring* error);
