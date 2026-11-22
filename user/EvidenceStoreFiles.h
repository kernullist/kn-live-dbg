#pragma once

#include "EvidenceStoreCatalog.h"
#include <functional>

struct EvidenceStorePageOptions;

namespace store_files
{
    inline constexpr const wchar_t* Folders[] = {L"image-reads", L"image-references", L"image-sweeps", L"image-captures",
        L"image-approvals", L"image-scope-inputs", L""};
    constexpr size_t MaxEntries = 65536, MaxWindow = 1024;
    constexpr DWORD BlockBytes = 65536;
    constexpr uint64_t DeadlineMs = 120000, MaxJsonBytes = 2 * 1024 * 1024, MaxBlobBytes = 64 * 1024 * 1024, MaxIrpBytes = 16 * 1024 * 1024;
    struct Format { uint64_t Maximum = 0; bool Blob = false; };
    bool ReservedRootName(const std::wstring& lowerName);
    Format FileFormat(const std::wstring& folder, const std::wstring& extension);
    struct Entry
    {
        std::wstring Path, ExactPath, Stamp, Gap, ObservedChunks;
        uint64_t Size = 0;
    };
    struct Snapshot
    {
        std::vector<Entry> Entries;
        std::vector<store_catalog::Handle> Directories;
        std::wstring Digest;
        bool Open(const std::filesystem::path& nativeRoot, uint64_t started, std::wstring& issue);
        Entry* Match(const std::wstring& path, HANDLE file);
        bool Accepts(const std::wstring& receipt) const;
        bool Verified(const std::wstring& receipt) const;
    };
    std::wstring StartChunks(uint64_t size);
    bool AppendChunk(std::wstring& chain, uint64_t offset, const uint8_t* bytes, DWORD count, std::wstring* digest = nullptr);
    std::wstring Scan(const std::wstring& root, const EvidenceStorePageOptions& page, bool* ready,
        const std::function<void(const wchar_t*)>& observer);
}
