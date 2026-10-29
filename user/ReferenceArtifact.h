#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

constexpr size_t ReferenceArtifactMaxBytes = 64 * 1024 * 1024;

// Leases local regular files, denies writes/deletes, and checks content on reuse.
class ReferenceArtifact
{
public:
    ReferenceArtifact() = default;
    ~ReferenceArtifact();
    ReferenceArtifact(const ReferenceArtifact&) = delete;
    ReferenceArtifact& operator=(const ReferenceArtifact&) = delete;
    bool Open(const std::wstring& path, std::wstring* error);
    bool Unchanged();
    const std::wstring& Path() const;
    const std::wstring& Sha256() const;
    const std::vector<uint8_t>& Bytes() const;
    std::wstring FileIdentity() const;
private:
    HANDLE File = INVALID_HANDLE_VALUE;
    FILE_ID_INFO Identity{};
    std::wstring FinalPath;
    std::wstring Hash;
    std::vector<uint8_t> Data;
};

// A failed or interrupted publication never exposes a valid final blob.
bool PublishReferenceArtifact(const std::wstring& path, const std::vector<uint8_t>& bytes, std::wstring* error);
