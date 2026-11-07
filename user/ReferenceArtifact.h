#pragma once
#include <functional>

#include <Windows.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

constexpr size_t ReferenceArtifactMaxBytes = 64 * 1024 * 1024;

struct RetainedReferenceArtifact
{
    std::wstring OriginalPath;
    std::wstring OriginalFileIdentity;
    std::wstring Sha256;
    std::vector<uint8_t> Bytes;
};

// Leases local regular files, denies writes/deletes, and checks content on reuse.
class ReferenceArtifact
{
public:
    ReferenceArtifact() = default;
    ~ReferenceArtifact();
    ReferenceArtifact(const ReferenceArtifact&) = delete;
    ReferenceArtifact& operator=(const ReferenceArtifact&) = delete;
    bool Open(const std::wstring& path, std::wstring* error, size_t maximumBytes = ReferenceArtifactMaxBytes);
    // Reopen the exact file object with its own read pointer and a write/delete
    // exclusion lease. Never resolves the caller's old pathname to another file.
    bool OpenHandle(HANDLE file, std::wstring* error, size_t maximumBytes = ReferenceArtifactMaxBytes);
    bool Unchanged();
    // Shares immutable bytes only, not the source lease. Caller records its
    // final Unchanged fence separately before destroying the lease.
    std::shared_ptr<const RetainedReferenceArtifact> Snapshot() const;
    const std::wstring& Path() const;
    const std::wstring& Sha256() const;
    const std::vector<uint8_t>& Bytes() const;
    std::wstring FileIdentity() const;
private:
    bool Initialize(std::wstring* error, size_t maximumBytes);
    HANDLE File = INVALID_HANDLE_VALUE;
    FILE_ID_INFO Identity{};
    std::shared_ptr<const RetainedReferenceArtifact> Content;
};

// A failed or interrupted publication never exposes a valid final blob.
bool PublishReferenceArtifact(const std::wstring& path, const std::vector<uint8_t>& bytes, std::wstring* error,
    const std::function<bool(HANDLE)>& admitOutput = {});

// Content-addressed create-new publication or exact-byte reuse. A returned lease
// pins the verified blob until the caller commits the referring publication.
// New-byte budget never prevents reuse of a verified existing blob.
bool PublishReferenceBlob(const std::wstring& directory, const RetainedReferenceArtifact& artifact,
    uint64_t maximumNewBytes, std::unique_ptr<ReferenceArtifact>* lease, bool* created, std::wstring* error);
