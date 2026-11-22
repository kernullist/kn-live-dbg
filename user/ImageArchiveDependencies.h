#pragma once

#include "EvidenceJournal.h"
#include <map>

enum class ImageArchiveKind { None, Capture, Reads, Slice, Sweep };

struct ImageArchiveInput
{
    std::wstring Sha256;
    uint64_t Bytes = 0;
    bool PayloadDigest = false;
};

struct ImageArchiveCatalog
{
    std::wstring PayloadSha256;
    std::map<std::wstring, ImageArchiveInput> Inputs;
};

// Only named originals have a standalone replay namespace. A scoped approval
// supplies the logical paths for its content-addressed input files.
ImageArchiveKind ImageArchiveKindForPath(const std::wstring& path);
bool ReadImageArchiveCatalog(ImageArchiveKind kind, const EvidenceJournalMember& root,
    const std::wstring& json, ImageArchiveCatalog& catalog);
bool MatchesImageArchiveInput(const ImageArchiveInput& input, const EvidenceJournalMember& member,
    const std::wstring& payloadSha256);
