#pragma once

#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace store_catalog
{
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    bool IsDigest(const std::wstring& value);
    std::wstring Hash(const std::wstring& text);
    Handle OpenAttributes(const std::filesystem::path& path, DWORD sharing);
    std::wstring Identity(HANDLE handle, bool directory);
    std::wstring NativePath(std::filesystem::path path);
    constexpr size_t MaxEntries = 16384, MaxWindow = 1024;
    struct Names
    {
        std::vector<std::wstring> Entries;
        std::wstring Digest;
        Handle Directory{nullptr, &CloseHandle};
    };
    // Caller owns the exclusive store lease and supplies its extended local root.
    bool ReadNames(const std::filesystem::path& root, uint64_t started, uint64_t deadlineMs, Names& result, std::wstring& issue);
    std::wstring FirstChain(const std::wstring& scope);
    std::wstring AppendRow(const std::wstring& chain, const std::wstring& row);
    std::wstring Token(bool terminal, const std::wstring& scope, size_t offset, const std::wstring& chain);
    bool ParseToken(const std::wstring& token, bool terminal, const Names& names, size_t& offset, std::wstring& chain);
}
