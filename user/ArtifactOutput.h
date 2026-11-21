#pragma once

#include "SymbolArtifactCache.h"
#include <memory>

// Keep each input pinned until the diagnostic has been written. A redirected
// stream may already own a writable hard link and prevent the normal read lease.
class DistinctArtifactInput
{
public:
    bool Hold(HANDLE sink, const std::wstring& name)
    {
        if (name.empty()) { return true; }
        std::filesystem::path path;
        if (!symbol_artifacts::LocalRoot(name, &path) || !Parents.Pin(path.parent_path(), false)) { return false; }
        HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL, nullptr);
        if (raw == INVALID_HANDLE_VALUE)
        {
            const auto error = GetLastError();
            return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
        }
        Input.reset(raw);
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        FILE_ID_INFO sourceId{}, sinkId{};
        return GetFileInformationByHandleEx(raw, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
            !(attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
            GetFileInformationByHandleEx(raw, FileIdInfo, &sourceId, sizeof(sourceId)) &&
            GetFileInformationByHandleEx(sink, FileIdInfo, &sinkId, sizeof(sinkId)) &&
            std::memcmp(&sourceId, &sinkId, sizeof(sourceId)) != 0;
    }
private:
    symbol_artifacts::Directories Parents;
    std::unique_ptr<void, decltype(&CloseHandle)> Input{ nullptr, &CloseHandle };
};

template<class Write>
int WriteWithDistinctInput(DWORD stream, const std::wstring& name, Write write)
{
    const auto sink = GetStdHandle(stream);
    DistinctArtifactInput input;
    return GetFileType(sink) != FILE_TYPE_DISK || input.Hold(sink, name) ? write() : 2;
}
