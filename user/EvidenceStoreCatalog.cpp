#include "EvidenceStoreCatalog.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <map>

namespace store_catalog
{
    namespace fs = std::filesystem;
    bool IsDigest(const std::wstring& value)
    { return value.size() == 64 && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos; }

    std::wstring Hash(const std::wstring& text)
    {
        const auto bytes = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }

    Handle OpenAttributes(const fs::path& path, DWORD sharing)
    {
        const auto file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, sharing, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        return Handle(file == INVALID_HANDLE_VALUE ? nullptr : file, &CloseHandle);
    }

    std::wstring Identity(HANDLE handle, bool directory)
    {
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        FILE_ID_INFO id{};
        FILETIME created{};
        if (!handle || GetFileType(handle) != FILE_TYPE_DISK ||
            !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (directory && ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))) ||
            !GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id)) || !GetFileTime(handle, &created, nullptr, nullptr)) { return {}; }
        std::wstring key = std::to_wstring(id.VolumeSerialNumber) + L":";
        for (const auto byte : id.FileId.Identifier)
        {
            key.push_back(L"0123456789abcdef"[byte >> 4]);
            key.push_back(L"0123456789abcdef"[byte & 15]);
        }
        return key + L":" + std::to_wstring((uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime) +
            L":" + std::to_wstring(attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) +
            L":" + std::to_wstring((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? attributes.ReparseTag : 0);
    }

    std::wstring NativePath(fs::path path)
    {
        // Store leases admit only normalized local paths. Extended paths need native separators.
        path.make_preferred();
        return L"\\\\?\\" + path.wstring();
    }

    bool ReadNames(const fs::path& root, uint64_t started, uint64_t deadlineMs, Names& result, std::wstring& issue)
    {
        const auto fail = [&](const wchar_t* reason) { issue = reason; return false; };
        const auto timely = [&]() { return GetTickCount64() - started <= deadlineMs; };
        auto rootHandle = OpenAttributes(root, FILE_SHARE_READ | FILE_SHARE_WRITE);
        const auto rootId = Identity(rootHandle.get(), true);
        if (rootId.empty()) { return fail(L"store_scan_root_identity_unavailable"); }
        const auto catalog = root / L"collections";
        Names names;
        names.Directory = OpenAttributes(catalog, FILE_SHARE_READ | FILE_SHARE_WRITE);
        const auto catalogError = names.Directory ? ERROR_SUCCESS : GetLastError();
        std::wstring catalogId = L"absent";
        std::map<std::wstring, std::wstring> items;
        if (names.Directory)
        {
            catalogId = Identity(names.Directory.get(), true);
            if (catalogId.empty()) { return fail(L"store_scan_catalog_identity_unavailable"); }
            std::error_code error;
            for (fs::directory_iterator it(catalog, error), end; !error && it != end; it.increment(error))
            {
                if (!timely() || items.size() == MaxEntries) { return fail(L"store_scan_namespace_budget_exhausted"); }
                const auto name = it->path().filename().wstring();
                if (!bounded_observation_json::Text(name, 255)) { return fail(L"store_scan_invalid_name"); }
                auto entry = OpenAttributes(it->path(), FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
                const auto id = Identity(entry.get(), false);
                if (id.empty() || !items.emplace(name, id).second) { return fail(L"store_scan_entry_identity_unavailable"); }
            }
            if (error) { return fail(L"store_scan_enumeration_failed"); }
        }
        else if (catalogError != ERROR_FILE_NOT_FOUND && catalogError != ERROR_PATH_NOT_FOUND)
            { return fail(L"store_scan_catalog_unavailable"); }

        std::wstring input = L"kn.store_catalog_namespace.v1|" + rootId + L"|" + catalogId + L"|[";
        for (const auto& item : items)
        {
            if (!names.Entries.empty()) { input += L","; }
            input += L"[" + mcpjson::Quote(item.first) + L"," + mcpjson::Quote(item.second) + L"]";
            names.Entries.push_back(item.first);
        }
        names.Digest = Hash(input + L"]");
        if (!IsDigest(names.Digest) || !timely()) { return fail(L"store_scan_namespace_unavailable"); }
        result = std::move(names);
        return true;
    }

    std::wstring FirstChain(const std::wstring& scope)
    { return IsDigest(scope) ? Hash(L"kn.store_catalog_rows.v1|" + scope) : L""; }

    std::wstring AppendRow(const std::wstring& chain, const std::wstring& row)
    { return IsDigest(chain) ? Hash(chain + L"|" + row) : L""; }

    std::wstring Token(bool terminal, const std::wstring& scope, size_t offset, const std::wstring& chain)
    {
        if (!IsDigest(scope) || !IsDigest(chain)) { return {}; }
        const auto prefix = (terminal ? L"kncr1." : L"kncs1.") + std::to_wstring(offset) + L"." + chain + L".";
        const auto seal = Hash(L"kn.store_catalog_position.v1|" + scope + L"|" + prefix);
        return IsDigest(seal) ? prefix + seal : L"";
    }

    bool ParseToken(const std::wstring& token, bool terminal, const Names& names, size_t& offset, std::wstring& chain)
    {
        if (token.rfind(terminal ? L"kncr1." : L"kncs1.", 0) != 0) { return false; }
        const auto end = token.find(L'.', 6);
        if (end == std::wstring::npos || end <= 6 || end > 11 || token.size() != end + 130) { return false; }
        const auto number = token.substr(6, end - 6);
        if (number.find_first_not_of(L"0123456789") != std::wstring::npos) { return false; }
        const size_t value = std::stoul(number);
        const auto digest = token.substr(end + 1, 64);
        if ((terminal ? value != names.Entries.size() : (!value || value >= names.Entries.size())) ||
            token != Token(terminal, names.Digest, value, digest)) { return false; }
        offset = value;
        chain = digest;
        return true;
    }
}
