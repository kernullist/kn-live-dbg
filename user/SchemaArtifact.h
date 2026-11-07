#pragma once

#include "ContentHash.h"
#include "ApprovedFileRead.h"
#include <algorithm>
#include <cstring>
#include <filesystem>

// Streaming, read-only lease. No pathname is used after approval for image/PDB
// parsing. The provider DLL still requires a pathname at the Windows loader.
class SchemaArtifact
{
public:
    ~SchemaArtifact()
    {
        for (const auto directory : Directories) { CloseHandle(directory); }
        if (File != INVALID_HANDLE_VALUE) { CloseHandle(File); }
    }
    SchemaArtifact() = default;
    SchemaArtifact(const SchemaArtifact&) = delete;
    SchemaArtifact& operator=(const SchemaArtifact&) = delete;

    bool Open(const std::wstring& path, uint64_t maximum)
    {
        if (File != INVALID_HANDLE_VALUE || path.empty() || path.size() > 30000 ||
            path.find(L'\0') != std::wstring::npos || path.rfind(L"\\\\", 0) == 0 || path.rfind(L"\\??\\", 0) == 0)
        {
            return false;
        }
        std::error_code ec;
        const auto absolute = std::filesystem::absolute(path, ec).wstring();
        if (ec || absolute.size() < 3 || absolute[1] != L':' || absolute.size() > 30000 ||
            absolute.find(L':', 2) != std::wstring::npos)
        {
            return false;
        }
        File = CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        return Initialize(maximum);
    }

    bool OpenHandle(HANDLE file, uint64_t maximum, approved_file::Access access = approved_file::Access::Reopen)
    {
        if (File != INVALID_HANDLE_VALUE || file == nullptr || file == INVALID_HANDLE_VALUE ||
            GetFileType(file) != FILE_TYPE_DISK)
        {
            return false;
        }
        File = approved_file::Open(file, access);
        return Initialize(maximum);
    }

    bool Unchanged()
    {
        FILE_ID_INFO current{};
        std::wstring after;
        return File != INVALID_HANDLE_VALUE &&
            GetFileInformationByHandleEx(File, FileIdInfo, &current, sizeof(current)) &&
            std::memcmp(&current, &Identity, sizeof(current)) == 0 && Hash(&after) && after == Sha256;
    }

    // LoadLibrary requires a path. Pin its non-reparse ancestor directories
    // against rename/delete and verify that the path still names this file.
    // Image/PDB parsers do not need this: they consume the approved handle.
    bool PinPath()
    {
        if (!Directories.empty() || File == INVALID_HANDLE_VALUE || Path.size() < 4) { return false; }
        for (size_t end = Path.find(L'\\', 3); end != std::wstring::npos; end = Path.find(L'\\', end + 1))
        {
            const auto directory = Path.substr(0, end);
            HANDLE handle = CreateFileW(directory.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            if (handle == INVALID_HANDLE_VALUE) { return false; }
            // Retain ownership even if metadata validation fails.
            try { Directories.push_back(handle); }
            catch (...) { CloseHandle(handle); throw; }
            if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) { return false; }
        }
        HANDLE current = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        FILE_ID_INFO identity{};
        const bool same = current != INVALID_HANDLE_VALUE &&
            GetFileInformationByHandleEx(current, FileIdInfo, &identity, sizeof(identity)) &&
            std::memcmp(&identity, &Identity, sizeof(identity)) == 0;
        if (current != INVALID_HANDLE_VALUE) { CloseHandle(current); }
        return same;
    }

    HANDLE Handle() const { return File; }
    uint64_t Bytes() const { return Size; }
    std::wstring Path;
    std::wstring Sha256;

private:
    bool Initialize(uint64_t maximum)
    {
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        LARGE_INTEGER size{};
        if (File == INVALID_HANDLE_VALUE || GetFileType(File) != FILE_TYPE_DISK ||
            !GetFileInformationByHandleEx(File, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
            !GetFileSizeEx(File, &size) || size.QuadPart <= 0 || static_cast<uint64_t>(size.QuadPart) > maximum ||
            !GetFileInformationByHandleEx(File, FileIdInfo, &Identity, sizeof(Identity)))
        {
            return false;
        }
        std::vector<wchar_t> finalPath(32768);
        const auto length = GetFinalPathNameByHandleW(File, finalPath.data(), static_cast<DWORD>(finalPath.size()), 0);
        if (length < 7 || length >= finalPath.size()) { return false; }
        Path.assign(finalPath.data(), length);
        if (Path.rfind(L"\\\\?\\", 0) != 0 || Path[5] != L':' || Path.find(L':', 6) != std::wstring::npos)
        {
            return false;
        }
        Path.erase(0, 4);
        wchar_t volume[MAX_PATH]{};
        if (!GetVolumePathNameW(Path.c_str(), volume, MAX_PATH) || GetDriveTypeW(volume) != DRIVE_FIXED)
        {
            return false;
        }
        Size = static_cast<uint64_t>(size.QuadPart);
        return Hash(&Sha256);
    }

    bool Hash(std::wstring* hash)
    {
        LARGE_INTEGER currentSize{};
        if (!GetFileSizeEx(File, &currentSize) ||
            static_cast<uint64_t>(currentSize.QuadPart) != Size) { return false; }
        ContentHash digest;
        std::vector<uint8_t> buffer(65536);
        uint64_t remaining = Size;
        const auto started = GetTickCount64();
        while (remaining != 0)
        {
            DWORD received = 0;
            const auto requested = static_cast<DWORD>((std::min)(remaining, static_cast<uint64_t>(buffer.size())));
            if (GetTickCount64() - started >= 30000 || !approved_file::ReadAt(File, Size - remaining, buffer.data(), requested, &received) ||
                received != requested || !digest.Add(buffer.data(), received)) { return false; }
            remaining -= received;
        }
        *hash = digest.Finish();
        return !hash->empty();
    }
    HANDLE File = INVALID_HANDLE_VALUE;
    FILE_ID_INFO Identity{};
    uint64_t Size = 0;
    std::vector<HANDLE> Directories;
};
