#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

inline constexpr const wchar_t* DirectImageCollectionPolicy = L"kn.direct_image_collection_journal.v1";
inline constexpr const wchar_t* DirectImageCollectionLedger = L"kn.image_capture_session.v1";
inline constexpr size_t DirectImageCaptureMaxBytes = 4 * 1024 * 1024;

// One direct capture operation has one bounded recipe/reference pair. Collection
// membership describes stored files; semantic replay remains an independent step.
struct ImageCaptureCollection
{
    std::wstring Status = L"unavailable", Issue, CollectionId, CapturePath;
    std::wstring CaptureSha256, ReferenceSha256, HeadSha256;
    uint64_t CaptureBytes = 0, ReferenceBytes = 0;
    bool CaptureCommitted = false, Closed = false, Indexed = false;
    bool CaptureCreated = false, ReferenceCreated = false, OriginalClaimRecorded = false;
};

// Requires an already initialized private store. Exact retries reuse immutable
// files/transactions, including a closed collection; another input cannot replace it.
ImageCaptureCollection JournalImageCapture(const std::wstring& caseDirectory, const std::wstring& privateStore,
    const std::wstring& collectionId, const std::function<void(const wchar_t*)>& observer = {});
std::wstring ImageCaptureCollectionJson(const ImageCaptureCollection& result);
