#pragma once

#include "EvidenceJournal.h"
#include <map>

enum class ImageArchiveKind { None, Capture, Reads, Slice, Sweep, SourceReport };

inline constexpr const wchar_t* ImageSourceCollectionPolicy = L"kn.image_source_collection_journal.v1";
inline constexpr const wchar_t* ImageSourceCollectionLedger = L"kn.image_source_session.v1";

inline std::wstring ImageSourceReportPath(const std::wstring& id, const std::wstring& hash)
{ return L"image-captures/source-" + id + L"-" + hash + L".knsource"; }
inline std::wstring ImageSourceCasePath(const std::wstring& id, const std::wstring& hash)
{ return L"image-captures/case-" + id + L"-" + hash + L".kncapture"; }
inline std::wstring ImageSourceSessionPath(const std::wstring& id)
{ return L"image-captures/session-" + id + L".knsourceledger"; }

inline std::wstring ImageSourceReportCollection(const std::wstring& relative, const std::wstring& hash)
{
    const std::wstring prefix = L"image-captures/source-";
    if (relative.rfind(prefix, 0) != 0) { return {}; }
    const auto end = relative.find(L'-', prefix.size());
    if (end == std::wstring::npos) { return {}; }
    const auto id = relative.substr(prefix.size(), end - prefix.size());
    if (id.empty() || id.size() > 20 || id.find_first_not_of(L"0123456789") != std::wstring::npos ||
        (id.size() > 1 && id.front() == L'0') || relative != ImageSourceReportPath(id, hash)) { return {}; }
    return id;
}
std::wstring ImageSourceSessionJson(const std::wstring& id, const std::vector<EvidenceJournalMember>& members,
    const std::wstring& captureStatus, const std::wstring& sourceStatus);

struct ImageArchiveInput
{
    std::wstring Sha256;
    uint64_t Bytes = 0;
    bool PayloadDigest = false;
};

struct ImageArchiveCatalog
{
    bool SweepHasGap = false;
    std::wstring PayloadSha256, RetentionTicket;
    std::wstring CaptureStatus, SourceStatus, SourceClaimBinding;
    std::map<std::wstring, ImageArchiveInput> Inputs;
};

// Only named originals have a standalone replay namespace. A scoped approval
// supplies the logical paths for its content-addressed input files.
ImageArchiveKind ImageArchiveKindForPath(const std::wstring& path);
bool ReadImageArchiveCatalog(ImageArchiveKind kind, const EvidenceJournalMember& root,
    const std::wstring& json, ImageArchiveCatalog& catalog, bool includeReadTicket = false);
bool MatchesImageArchiveInput(const ImageArchiveInput& input, const EvidenceJournalMember& member,
    const std::wstring& payloadSha256);
