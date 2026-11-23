#pragma once

#include "ContentHash.h"
#include "McpJson.h"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace inventory_files
{
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;

    inline Handle Open(const std::filesystem::path& path, DWORD access, DWORD sharing)
    {
        // Callers pass normalized drive paths. Address each literal component even when it has a DOS device alias.
        const auto native = L"\\\\?\\" + path.native();
        const auto handle = CreateFileW(native.c_str(), access, sharing, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        return Handle(handle == INVALID_HANDLE_VALUE ? nullptr : handle, &CloseHandle);
    }

    inline bool LocalPath(const std::wstring& input, std::filesystem::path& path)
    {
        std::error_code error;
        path = std::filesystem::absolute(input, error).lexically_normal();
        if (error || path.root_name().native().size() != 2 || path.root_name().native()[1] != L':' ||
            GetDriveTypeW(path.root_path().c_str()) != DRIVE_FIXED) { return false; }
        if (path != path.root_path() && path.filename().empty()) { path = path.parent_path(); }
        for (const auto& part : path.relative_path())
        {
            const auto& leaf = part.native();
            if (leaf.empty() || leaf.back() == L'.' || leaf.back() == L' ' ||
                leaf.find_first_of(L":*?\"<>|") != std::wstring::npos) { return false; }
        }
        return true;
    }

    // Keep every admitted directory on its original path and committed files read-only.
    class Pins
    {
    public:
        bool Directory(const std::filesystem::path& path)
        {
            return Keep(Open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE), true);
        }

        bool Ancestors(const std::filesystem::path& path)
        {
            auto current = path.root_path();
            if (!Directory(current)) { return false; }
            for (const auto& part : path.relative_path())
            {
                current /= part;
                if (!Directory(current)) { return false; }
            }
            return true;
        }

        bool ReadFile(const std::filesystem::path& path)
        {
            return Keep(Open(path, GENERIC_READ, FILE_SHARE_READ), false);
        }

        bool Writer(const std::filesystem::path& path, bool initialize)
        {
            // A no-share regular file excludes other builders without denying the directory
            // write access Windows needs for the atomic publication rename.
            const auto raw = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr,
                initialize ? OPEN_ALWAYS : OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            Handle file(raw == INVALID_HANDLE_VALUE ? nullptr : raw, &CloseHandle);
            FILE_STANDARD_INFO info{};
            return file && GetFileInformationByHandleEx(file.get(), FileStandardInfo, &info, sizeof(info)) &&
                info.EndOfFile.QuadPart == 0 && info.NumberOfLinks == 1 && Keep(std::move(file), false);
        }

    private:
        bool Keep(Handle file, bool directory)
        {
            FILE_ATTRIBUTE_TAG_INFO info{};
            if (!file || GetFileType(file.get()) != FILE_TYPE_DISK ||
                !GetFileInformationByHandleEx(file.get(), FileAttributeTagInfo, &info, sizeof(info)) ||
                (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory) { return false; }
            Handles.push_back(std::move(file));
            return true;
        }

        std::vector<Handle> Handles;
    };

    inline bool Missing(const std::filesystem::path& path)
    {
        return GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND;
    }

    // Encode fixed-width fields on Windows in little-endian order, omitting last-access time.
    // Replacing a file with identical bytes is still a new generation.
    inline bool AddGeneration(ContentHash& hash, const std::filesystem::path& path, const std::wstring& name)
    {
        auto file = Open(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        FILE_ID_INFO id{};
        FILE_BASIC_INFO basic{};
        FILE_STANDARD_INFO standard{};
        if (!file || GetFileType(file.get()) != FILE_TYPE_DISK ||
            !GetFileInformationByHandleEx(file.get(), FileIdInfo, &id, sizeof(id)) ||
            !GetFileInformationByHandleEx(file.get(), FileBasicInfo, &basic, sizeof(basic)) ||
            !GetFileInformationByHandleEx(file.get(), FileStandardInfo, &standard, sizeof(standard))) { return false; }
        const auto utf8 = mcpjson::WideToUtf8(name);
        const uint32_t length = static_cast<uint32_t>(utf8.size());
        const auto add = [&](const auto& field) { return hash.Add(reinterpret_cast<const uint8_t*>(&field), sizeof(field)); };
        return !utf8.empty() && add(length) && hash.Add(reinterpret_cast<const uint8_t*>(utf8.data()), length) &&
            add(id.VolumeSerialNumber) && add(id.FileId.Identifier) && add(basic.CreationTime.QuadPart) &&
            add(basic.LastWriteTime.QuadPart) && add(basic.ChangeTime.QuadPart) && add(basic.FileAttributes) &&
            add(standard.EndOfFile.QuadPart);
    }
}
