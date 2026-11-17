#pragma once

#include "EvidencePrivacy.h"
#include "ReferenceArtifact.h"
#include "SchemaArtifact.h"
#include <filesystem>

namespace evidence_artifact_publication
{
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    inline Handle PinFolder(const std::filesystem::path& path)
    {
        if (!CreateDirectoryW(path.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
            { return Handle(nullptr, &CloseHandle); }
        // Metadata-only access does not enforce Windows share exclusion. Pin
        // even an empty directory before publishing its first private member.
        const auto file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Handle owner(file == INVALID_HANDLE_VALUE ? nullptr : file, &CloseHandle);
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!owner || !GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            !(attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            { owner.reset(); }
        return owner;
    }
    inline bool Retain(const std::filesystem::path& path, const std::vector<uint8_t>& bytes, const std::wstring& hash,
        EvidencePrivacyGuard& privacy, std::unique_ptr<SchemaArtifact>* lease, bool* created)
    {
        const auto acquire = [&]()
        {
            auto file = std::make_unique<SchemaArtifact>();
            if (!file->Open(path.wstring(), bytes.size()) || !privacy.CheckFile(file->Handle()) ||
                file->Bytes() != bytes.size() || file->Sha256 != hash) { return false; }
            *lease = std::move(file);
            return true;
        };
        if (acquire()) { return true; }
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES || GetLastError() != ERROR_FILE_NOT_FOUND) { return false; }
        *created = PublishReferenceArtifact(path.wstring(), bytes, nullptr, [&](HANDLE file) { return privacy.CheckFile(file); });
        // A concurrent publisher may win CREATE_NEW but cannot replace bytes.
        return acquire();
    }
}
