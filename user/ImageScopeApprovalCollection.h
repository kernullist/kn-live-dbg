#pragma once

#include "ImageApprovalCollection.h"
#include <vector>

inline constexpr const wchar_t* ImageScopeApprovalCollectionPolicy = L"kn.approved_image_scope_collection_journal.v1";
inline constexpr const wchar_t* ImageScopeApprovalCollectionLedger = L"kn.image_scope_approval_session.v1";
inline constexpr const wchar_t* ImageScopeApprovalPublicationSchema = L"kn.image_scope_approval_publication.v1";
inline constexpr size_t ImageScopeApprovalPublicationMaxBytes = 8 * 1024 * 1024;
inline constexpr size_t ImageScopeApprovalMaximumInputs = 4097;
inline constexpr uint64_t ImageScopeApprovalMaximumInputBytes = 256ull * 1024 * 1024;

inline const wchar_t* ImageScopeApprovalRootName(bool sweep) { return sweep ? L"root.knsweep" : L"root.knslice"; }
inline bool IsImageScopeApprovalInputName(const std::wstring& path, bool sweep)
{
    if (path == ImageScopeApprovalRootName(sweep)) { return true; }
    const std::wstring prefix = L"image-reads/reads-";
    if (!sweep || path.rfind(prefix, 0) != 0 || path.size() > 80) { return false; }
    const auto dash = path.find(L'-', prefix.size()), dot = path.rfind(L'.');
    if (dash == std::wstring::npos || dot == std::wstring::npos || dot <= dash) { return false; }
    const auto validId = [](const std::wstring& id) {
        return !id.empty() && id.size() <= 20 && id.find_first_not_of(L"0123456789") == std::wstring::npos &&
            (id.size() == 1 || id.front() != L'0');
    };
    return validId(path.substr(prefix.size(), dash - prefix.size())) && validId(path.substr(dash + 1, dot - dash - 1)) &&
        (path.substr(dot) == L".knslice" || path.substr(dot) == L".knreads");
}

struct ImageScopeApprovalInput
{
    std::wstring LogicalPath, Sha256, Schema;
    uint64_t Bytes = 0;
};
struct ImageScopeApprovalPublication
{
    std::wstring CollectionId, RootSha256, ReferenceSha256, PolicySha256, ManifestSha256;
    std::wstring Assessment, Sha256;
    uint64_t EvaluationFileTime = 0;
    bool Sweep = false;
    std::vector<ImageScopeApprovalInput> Inputs;
};
std::wstring ImageScopeApprovalPublicationJson(const ImageScopeApprovalPublication& publication);
bool ParseImageScopeApprovalPublication(const std::wstring& json, ImageScopeApprovalPublication* publication);

struct ImageScopeApprovalCollection
{
    std::wstring Status = L"unavailable", Issue, CollectionId, ApprovalPath, ApprovalSha256, HeadSha256;
    std::wstring RootSha256, ReferenceSha256, PolicySha256, ManifestSha256;
    uint64_t InputCount = 0, InputBytes = 0, UniqueInputFiles = 0, UniqueInputBytes = 0;
    uint64_t ReferenceBytes = 0, PolicyBytes = 0, ManifestBytes = 0, ApprovalBytes = 0;
    bool Committed = false, Closed = false, Indexed = false, HistoricalRootReused = false;
};

// Retains the exact declared dependency closure in a separately versioned
// journal. Missing source inputs stay unavailable; no ambient-file fallback.
ImageScopeApprovalCollection JournalImageScopeApproval(const std::wstring& scope, const std::wstring& manifest,
    const std::wstring& policy, const std::wstring& policySha256, const std::wstring& privateStore,
    const std::wstring& collectionId, uint64_t evaluationFileTime = 0,
    const std::function<void(const wchar_t*)>& observer = {});
std::wstring ImageScopeApprovalCollectionJson(const ImageScopeApprovalCollection& result);
ImageApprovalReplay ReplayImageScopeApproval(const std::wstring& root, const std::wstring& policySha256, bool current = false);
