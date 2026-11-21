#pragma once

#include "SymbolArtifactCache.h"
#include <memory>

template<class Write>
int WriteWithDistinctInput(DWORD stream, const std::wstring& name, Write write)
{
    // A writable redirection can itself prevent the normal read lease. Never
    // append the error to the source, including through another hard link.
    const HANDLE sink = GetStdHandle(stream);
    if (name.empty() || GetFileType(sink) != FILE_TYPE_DISK) { return write(); }
    std::filesystem::path path;
    symbol_artifacts::Directories parents;
    if (!symbol_artifacts::LocalRoot(name, &path) || !parents.Pin(path.parent_path(), false)) { return 2; }
    HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (raw == INVALID_HANDLE_VALUE)
    {
        const auto error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? write() : 2;
    }
    const std::unique_ptr<void, decltype(&CloseHandle)> input(raw, &CloseHandle);
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_ID_INFO sourceId{}, sinkId{};
    if (!GetFileInformationByHandleEx(raw, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        !GetFileInformationByHandleEx(raw, FileIdInfo, &sourceId, sizeof(sourceId)) ||
        !GetFileInformationByHandleEx(sink, FileIdInfo, &sinkId, sizeof(sinkId)) ||
        std::memcmp(&sourceId, &sinkId, sizeof(sourceId)) == 0) { return 2; }
    return write();
}
