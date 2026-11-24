#pragma once

#include "SymbolArtifactCache.h"
#include <memory>

// Keep each input pinned until the diagnostic has been written. A redirected
// stream may already own a writable hard link and prevent the normal read lease.
class DistinctArtifactInput
{
public:
    HANDLE PinnedHandle() const { return Input.get(); }

    bool Hold(HANDLE sink, const std::wstring& name, bool allowMissingParent = false)
    {
        if (name.empty()) { return true; }
        std::filesystem::path path;
        if (!symbol_artifacts::LocalRoot(name, &path)) { return false; }
        DWORD parentError = ERROR_SUCCESS;
        if (!Parents.Pin(path.parent_path(), false, FILE_SHARE_READ | FILE_SHARE_WRITE, allowMissingParent ? &parentError : nullptr))
        { return allowMissingParent && (parentError == ERROR_FILE_NOT_FOUND || parentError == ERROR_PATH_NOT_FOUND); }
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

template<class Select, class Write>
int WriteWithDistinctSelectedInputs(DWORD stream, const std::vector<std::wstring>& args, Select selector, Write write)
{
    const auto sink = GetStdHandle(stream);
    if (GetFileType(sink) != FILE_TYPE_DISK) { return write(); }
    std::vector<DistinctArtifactInput> inputs(std::count_if(args.begin(), args.end(), selector));
    size_t guard = 0;
    for (size_t i = 0; i + 1 < args.size(); ++i)
    {
        if (selector(args[i]) && !inputs[guard++].Hold(sink, args[i + 1])) { return 2; }
    }
    return write();
}

template<class Write>
int WriteWithDistinctInput(DWORD stream, const std::wstring& name, Write write, bool allowMissingParent = false)
{
    const auto sink = GetStdHandle(stream);
    DistinctArtifactInput input;
    return GetFileType(sink) != FILE_TYPE_DISK || input.Hold(sink, name, allowMissingParent) ? write() : 2;
}
