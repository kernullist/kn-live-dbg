#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

inline constexpr const wchar_t* ImageApprovalCollectionPolicy = L"kn.approved_image_collection_journal.v1";
inline constexpr const wchar_t* ImageApprovalCollectionLedger = L"kn.image_approval_session.v1";
inline constexpr const wchar_t* ImageApprovalPublicationSchema = L"kn.image_approval_publication.v1";
inline constexpr size_t ImageApprovalPublicationMaxBytes = 4 * 1024 * 1024;
inline constexpr size_t ImageApprovalInputMaxBytes = 64 * 1024;

struct ImageApprovalPublication
{
    std::wstring CollectionId, CaptureSha256, ReferenceSha256, PolicySha256, ManifestSha256;
    std::wstring Assessment, Sha256;
    uint64_t EvaluationFileTime = 0;
};
std::wstring ImageApprovalPublicationJson(const ImageApprovalPublication& publication);
bool ParseImageApprovalPublication(const std::wstring& json, ImageApprovalPublication* publication);

struct ImageApprovalReplay
{
    bool Succeeded = false;
    std::wstring Json;
};
// The caller must provide the trust anchor again. Recorded hashes cannot appoint
// their own authority. Original replay uses the recorded assessment time; current
// evaluation uses the host clock and preserves the historical report separately.
ImageApprovalReplay ReplayImageApproval(const std::wstring& root, const std::wstring& policySha256, bool current = false);

struct ImageApprovalCollection
{
    std::wstring Status = L"unavailable", Issue, CollectionId, ApprovalPath, CapturePath;
    std::wstring CaptureSha256, ReferenceSha256, PolicySha256, ManifestSha256, ApprovalSha256, HeadSha256;
    uint64_t CaptureBytes = 0, ReferenceBytes = 0, PolicyBytes = 0, ManifestBytes = 0, ApprovalBytes = 0;
    bool Committed = false, Closed = false, Indexed = false, HistoricalRootReused = false;
};
ImageApprovalCollection JournalImageApproval(const std::wstring& capture, const std::wstring& manifest,
    const std::wstring& policy, const std::wstring& policySha256, const std::wstring& privateStore,
    const std::wstring& collectionId, uint64_t evaluationFileTime = 0,
    const std::function<void(const wchar_t*)>& observer = {});
std::wstring ImageApprovalCollectionJson(const ImageApprovalCollection& result);
