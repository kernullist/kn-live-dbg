#include "AnalystSnapshot.h"
#include "McpJson.h"

#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <memory>
#include <set>

namespace
{
    constexpr size_t MaxSnapshotBytes = 32 * 1024 * 1024;
    constexpr size_t MaxRows = 40000;
    using Fields = std::map<std::wstring, std::wstring>;

    bool Object(const std::wstring& json, Fields* fields)
    {
        fields->clear();
        size_t pos = 0;
        mcpjson::SkipWhitespace(json, &pos);
        if (pos >= json.size() || json[pos++] != L'{')
        {
            return false;
        }
        while (pos < json.size())
        {
            mcpjson::SkipWhitespace(json, &pos);
            if (pos < json.size() && json[pos] == L'}')
            {
                ++pos;
                mcpjson::SkipWhitespace(json, &pos);
                return pos == json.size();
            }
            size_t end = 0;
            if (pos >= json.size() || json[pos] != L'"' || !mcpjson::ScanValue(json, pos, &end))
            {
                return false;
            }
            auto name = mcpjson::Unescape(json.substr(pos, end - pos));
            if (name.find(L'\0') != std::wstring::npos)
            {
                return false;
            }
            pos = end;
            mcpjson::SkipWhitespace(json, &pos);
            if (pos >= json.size() || json[pos++] != L':')
            {
                return false;
            }
            mcpjson::SkipWhitespace(json, &pos);
            if (!mcpjson::ScanValue(json, pos, &end) || name.size() > 64 || fields->size() >= 64 ||
                !fields->emplace(name, json.substr(pos, end - pos)).second)
            {
                return false;
            }
            pos = end;
            mcpjson::SkipWhitespace(json, &pos);
            if (pos < json.size() && json[pos] == L',')
            {
                ++pos;
            }
        }
        return false;
    }

    bool Text(Fields& fields, const wchar_t* name, std::wstring* value, size_t maximum = 4096)
    {
        const auto found = fields.find(name);
        if (found == fields.end() || found->second.size() < 2 || found->second.front() != L'"')
        {
            return false;
        }
        *value = mcpjson::Unescape(found->second);
        found->second = mcpjson::Quote(*value);
        return value->size() <= maximum && value->find(L'\0') == std::wstring::npos;
    }

    bool Number(Fields& fields, const wchar_t* name, uint64_t* value)
    {
        const auto found = fields.find(name);
        if (found == fields.end())
        {
            return false;
        }
        auto text = found->second;
        if (!text.empty() && text.front() == L'"')
        {
            text = mcpjson::Unescape(text);
        }
        *value = 0;
        if (text.empty() || text.size() > 20)
        {
            return false;
        }
        for (const auto ch : text)
        {
            if (ch < L'0' || ch > L'9' || *value > (UINT64_MAX - (ch - L'0')) / 10)
            {
                return false;
            }
            *value = *value * 10 + (ch - L'0');
        }
        found->second = mcpjson::Quote(std::to_wstring(*value));
        return true;
    }

    bool Boolean(const Fields& fields, const wchar_t* name, bool* value)
    {
        const auto found = fields.find(name);
        if (found == fields.end() || (found->second != L"true" && found->second != L"false"))
        {
            return false;
        }
        *value = found->second == L"true";
        return true;
    }

    std::wstring Canonical(const Fields& fields)
    {
        std::wstring out = L"{";
        for (const auto& item : fields)
        {
            if (out.size() > 1)
            {
                out += L",";
            }
            out += mcpjson::Quote(item.first) + L":" + item.second;
        }
        return out + L"}";
    }

    bool Identity(Fields& fields, std::wstring* key, std::wstring* boot, bool allowUnknown = false)
    {
        uint64_t pid = 0, creation = 0;
        if (!Text(fields, L"boot_id", boot, 128) || (!allowUnknown && boot->empty()) ||
            !Number(fields, L"pid", &pid) || pid > UINT32_MAX ||
            !Number(fields, L"create_time", &creation) || (!allowUnknown && pid != 0 && creation == 0))
        {
            return false;
        }
        *key = mcpjson::Quote(*boot) + L":" + std::to_wstring(pid) + L":" + std::to_wstring(creation);
        return true;
    }

    bool Reference(const std::wstring& json, std::wstring* key, std::wstring* state, std::set<std::wstring>* boots)
    {
        Fields fields;
        std::wstring boot, role, ownership, hash, ignored;
        uint64_t address = 0, slot = 0, root = 0, number = 0;
        bool value = false;
        if (!Object(json, &fields) || !Identity(fields, key, &boot) ||
            !Text(fields, L"role", &role, 128) || role.empty() || !Text(fields, L"ownership", &ownership, 64) ||
            !Text(fields, L"page_sha256", &hash, 64) || (!hash.empty() && !KmonHuntHash(hash)) ||
            !Number(fields, L"address", &address) || !Number(fields, L"slot", &slot) || !Number(fields, L"root", &root) ||
            !Boolean(fields, L"execution_observed", &value) || value)
        {
            return false;
        }
        const std::set<std::wstring> ownerships = {L"unknown", L"owned_unverified", L"owned_verified",
            L"owned_modified", L"unowned_executable", L"owned_unexpected_executable"};
        if (ownerships.count(ownership) == 0)
        {
            return false;
        }
        for (const auto name : {L"id", L"eprocess", L"session_id", L"mapping_generation", L"observed_ms",
            L"observed_at", L"reference_at", L"pfn"})
        {
            if (!Number(fields, name, &number) || (std::wstring(name) == L"session_id" && number > UINT32_MAX))
            {
                return false;
            }
        }
        for (const auto name : {L"session_known", L"page_comparable", L"slot_stable", L"page_executable_verified", L"pfn_known"})
        {
            if (!Boolean(fields, name, &value))
            {
                return false;
            }
        }
        if (!Text(fields, L"source", &ignored, 128) || !Text(fields, L"dependency_group", &ignored, 128))
        {
            return false;
        }
        boots->insert(boot);
        *key += L":" + mcpjson::Quote(role) + L":" + std::to_wstring(root) + L":" +
            std::to_wstring(slot) + L":" + std::to_wstring(address);
        // Observation age and ephemeral index IDs do not constitute a changed lead.
        for (const auto name : {L"id", L"observed_ms", L"observed_at", L"reference_at"})
        {
            fields.erase(name);
        }
        *state = Canonical(fields);
        return true;
    }

    struct Snapshot
    {
        std::wstring Schema;
        std::wstring Coverage;
        std::set<std::wstring> Boots;
        std::map<std::wstring, std::wstring> Rows;
    };

    bool SnapshotStringsValid(const std::wstring& json)
    {
        bool inString = false;
        bool highSurrogate = false;
        for (size_t i = 0; i < json.size(); ++i)
        {
            wchar_t unit = json[i];
            if (!inString)
            {
                inString = unit == L'"';
                continue;
            }
            if (unit == L'"')
            {
                if (highSurrogate)
                {
                    return false;
                }
                inString = false;
                continue;
            }
            if (unit == L'\\')
            {
                if (++i >= json.size())
                {
                    return false;
                }
                unit = 0;
                if (json[i] == L'u')
                {
                    if (json.size() - i <= 4)
                    {
                        return false;
                    }
                    for (size_t n = 0; n < 4; ++n)
                    {
                        const wchar_t digit = json[++i];
                        const uint32_t value = digit >= L'0' && digit <= L'9' ? digit - L'0' :
                            (digit >= L'a' && digit <= L'f' ? digit - L'a' + 10 : digit - L'A' + 10);
                        if (value > 15)
                        {
                            return false;
                        }
                        unit = static_cast<wchar_t>((unit << 4) | value);
                    }
                }
            }
            const bool lowSurrogate = unit >= 0xdc00 && unit <= 0xdfff;
            if (highSurrogate != lowSurrogate)
            {
                return false;
            }
            highSurrogate = unit >= 0xd800 && unit <= 0xdbff;
        }
        return !inString && !highSurrogate;
    }

    bool Parse(const std::wstring& json, Snapshot* snapshot)
    {
        Fields fields;
        bool value = false;
        uint64_t number = 0;
        std::wstring claim, array, processKey, boot;
        bool unknownIdentity = false;
        if (json.size() > MaxSnapshotBytes || !mcpjson::ValidateDocument(json) || !SnapshotStringsValid(json) || !Object(json, &fields) ||
            !Text(fields, L"schema", &snapshot->Schema, 64) || !Text(fields, L"claim", &claim, 64))
        {
            return false;
        }
        const bool surfaces = snapshot->Schema == L"kmon.surfaces.v1";
        if (surfaces)
        {
            if (claim != L"static_references" || !Boolean(fields, L"execution_observed", &value) || value ||
                !Boolean(fields, L"identity_stable", &value) || !Identity(fields, &processKey, &boot, !value) ||
                !Boolean(fields, L"module_inventory_complete", &value) ||
                !Number(fields, L"observed_ms", &number) || !Number(fields, L"observed_at", &number) ||
                !Number(fields, L"next_module", &number) || !Number(fields, L"next_handle", &number))
            {
                return false;
            }
            if (!boot.empty())
            {
                snapshot->Boots.insert(boot);
            }
            uint64_t creation = 0;
            unknownIdentity = !Number(fields, L"create_time", &creation) || creation == 0 || boot.empty();
            Fields coverage;
            if (fields.count(L"coverage") == 0 || !Object(fields.at(L"coverage"), &coverage))
            {
                return false;
            }
            for (auto& entry : coverage)
            {
                std::wstring detail;
                if (!Text(coverage, entry.first.c_str(), &detail))
                {
                    return false;
                }
            }
            snapshot->Coverage = Canonical(coverage) + fields.at(L"identity_stable") + fields.at(L"module_inventory_complete") +
                L":" + fields.at(L"next_module") + L":" + fields.at(L"next_handle");
        }
        else if (snapshot->Schema != L"kmon.hunt.v1" || claim != L"investigation_leads" ||
            !Boolean(fields, L"communication_proven", &value) || value ||
            !Number(fields, L"generated_ms", &number) || !Number(fields, L"expires_after_ms", &number) || number != 30000 ||
            !Number(fields, L"evidence_evicted", &number) || !Number(fields, L"evidence_rejected", &number))
        {
            return false;
        }
        else
        {
            std::wstring inputMode;
            if (!Text(fields, L"input_mode", &inputMode, 64))
            {
                return false;
            }
            Fields coverage;
            for (const auto name : {L"evidence_evicted", L"evidence_rejected", L"input_mode"})
            {
                coverage.emplace(name, fields.at(name));
            }
            for (const auto name : {L"filter_pid", L"filter_role", L"candidate_limit"})
            {
                if (fields.count(name) != 0)
                {
                    if (std::wstring(name) == L"filter_role")
                    {
                        std::wstring role;
                        if (!Text(fields, name, &role, 128))
                        {
                            return false;
                        }
                    }
                    else if (std::wstring(name) == L"filter_pid")
                    {
                        if (fields.at(name) != L"null" && (!Number(fields, name, &number) || number > UINT32_MAX))
                        {
                            return false;
                        }
                    }
                    else if (!Number(fields, name, &number) || number == 0 || number > 256)
                    {
                        return false;
                    }
                    coverage.emplace(name, fields.at(name));
                }
            }
            snapshot->Coverage = Canonical(coverage);
        }
        const auto found = fields.find(surfaces ? L"rows" : L"cases");
        if (found == fields.end())
        {
            return false;
        }
        array = found->second;
        size_t pos = 0;
        mcpjson::SkipWhitespace(array, &pos);
        if (pos >= array.size() || array[pos++] != L'[')
        {
            return false;
        }
        while (pos < array.size())
        {
            mcpjson::SkipWhitespace(array, &pos);
            if (pos < array.size() && array[pos] == L']')
            {
                return true;
            }
            size_t end = 0;
            Fields row;
            std::wstring key, state, kind;
            if (unknownIdentity || snapshot->Rows.size() >= MaxRows || !mcpjson::ScanValue(array, pos, &end) || end - pos > 32768 ||
                !Object(array.substr(pos, end - pos), &row) || !Text(row, L"kind", &kind, 128) || kind.empty())
            {
                return false;
            }
            if (surfaces)
            {
                uint64_t module = 0, root = 0, handle = 0, index = 0;
                std::wstring ignored;
                if (!Number(row, L"module_base", &module) || !Number(row, L"root_slot", &root) ||
                    !Number(row, L"handle", &handle) || !Number(row, L"index", &index) || index > UINT32_MAX)
                {
                    return false;
                }
                for (const auto name : {L"table", L"slot", L"target", L"peb", L"protection", L"memory_type", L"pointer_size"})
                {
                    if (!Number(row, name, &number) ||
                        ((std::wstring(name) == L"protection" || std::wstring(name) == L"memory_type") && number > UINT32_MAX) ||
                        (std::wstring(name) == L"pointer_size" && number != 0 && number != 4 && number != 8))
                    {
                        return false;
                    }
                }
                for (const auto name : {L"stable", L"table_complete", L"table_present", L"executable", L"unowned"})
                {
                    if (!Boolean(row, name, &value))
                    {
                        return false;
                    }
                }
                for (const auto name : {L"name", L"status", L"baseline", L"owner"})
                {
                    if (!Text(row, name, &ignored))
                    {
                        return false;
                    }
                }
                key = processKey + L":" + mcpjson::Quote(kind) + L":" + std::to_wstring(module) +
                    L":" + std::to_wstring(module == 0 ? root : 0) + L":" + std::to_wstring(handle) + L":" + std::to_wstring(index);
                state = Canonical(row);
            }
            else
            {
                std::wstring primaryKey, primaryState, relatedKey, relatedState, relation;
                if (row.count(L"primary") == 0 || !Text(row, L"relation", &relation, 64) ||
                    !Reference(row.at(L"primary"), &primaryKey, &primaryState, &snapshot->Boots))
                {
                    return false;
                }
                if (row.count(L"related") != 0 && !Reference(row.at(L"related"), &relatedKey, &relatedState, &snapshot->Boots))
                {
                    return false;
                }
                key = mcpjson::Quote(kind) + L":" + primaryKey + L":" + relatedKey;
                state = L"{\"kind\":" + mcpjson::Quote(kind) + L",\"relation\":" + mcpjson::Quote(relation) +
                    L",\"primary\":" + primaryState + (relatedState.empty() ? L"" : L",\"related\":" + relatedState) + L"}";
            }
            if (!snapshot->Rows.emplace(key, state).second)
            {
                return false;
            }
            pos = end;
            mcpjson::SkipWhitespace(array, &pos);
            if (pos < array.size() && array[pos] == L',')
            {
                ++pos;
            }
        }
        return false;
    }

    bool DiskPath(const std::wstring& path)
    {
        if (path.empty() || path.find(L'\0') != std::wstring::npos || path.rfind(L"\\\\.\\", 0) == 0 ||
            path.rfind(L"\\\\?\\GLOBALROOT", 0) == 0)
        {
            return false;
        }
        auto name = std::filesystem::path(path).filename().wstring();
        if (name.empty() || name.back() == L'.' || name.back() == L' ' || name.find(L':') != std::wstring::npos)
        {
            return false;
        }
        name = name.substr(0, name.find(L'.'));
        for (auto& ch : name)
        {
            if (ch >= L'a' && ch <= L'z')
            {
                ch -= L'a' - L'A';
            }
        }
        const std::set<std::wstring> devices = {L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$"};
        return devices.count(name) == 0 && !(name.size() == 4 &&
            (name.substr(0, 3) == L"COM" || name.substr(0, 3) == L"LPT") &&
            ((name[3] >= L'0' && name[3] <= L'9') || name[3] == 0xB9 || name[3] == 0xB2 || name[3] == 0xB3));
    }
}

std::vector<KmonHuntCase> FilterAnalystCases(const std::vector<KmonHuntCase>& cases, const AnalystCaseFilter& filter)
{
    std::vector<KmonHuntCase> result;
    const auto matches = [&](const KmonHuntReference& row)
    {
        return (!filter.HasPid || row.Context.Identity.ProcessId == filter.ProcessId) &&
            (filter.Role.empty() || row.Role == filter.Role);
    };
    for (const auto& item : cases)
    {
        if (matches(item.Primary) || (item.HasRelated && matches(item.Related)))
        {
            result.push_back(item);
        }
    }
    return result;
}

bool SaveAnalystSnapshot(const std::wstring& path, const std::wstring& json, std::wstring* error)
{
    bool ok = false;
    std::wstring ignored;
    if (error == nullptr)
    {
        error = &ignored;
    }
    *error = L"snapshot must be valid, bounded JSON and use a new output path";
    do
    {
        Snapshot parsed;
        if (!DiskPath(path) || !Parse(json, &parsed))
        {
            break;
        }
        const auto utf8 = mcpjson::WideToUtf8(json);
        if (utf8.empty() || utf8.size() > MaxSnapshotBytes)
        {
            break;
        }
        std::error_code ec;
        const auto absolute = std::filesystem::absolute(path, ec).wstring();
        if (ec || absolute.size() > 30000)
        {
            break;
        }
        static LONG serial = 0;
        const auto temporary = absolute + L".pending-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(InterlockedIncrement(&serial));
        HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE | DELETE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            *error = L"cannot create snapshot temporary file: " + std::to_wstring(GetLastError());
            break;
        }
        DWORD written = 0;
        if (GetFileType(file) == FILE_TYPE_DISK && WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr) &&
            written == utf8.size() && FlushFileBuffers(file))
        {
            // KernelBase converts absolute DOS paths with a NUL-terminated helper.
            const size_t bytes = offsetof(FILE_RENAME_INFO, FileName) + (absolute.size() + 1) * sizeof(wchar_t);
            std::vector<uint8_t> storage(bytes, 0);
            auto rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
            rename->ReplaceIfExists = FALSE;
            rename->FileNameLength = static_cast<DWORD>(absolute.size() * sizeof(wchar_t));
            std::memcpy(rename->FileName, absolute.data(), rename->FileNameLength);
            ok = SetFileInformationByHandle(file, FileRenameInfo, rename, static_cast<DWORD>(bytes)) != FALSE;
        }
        if (!ok)
        {
            *error = L"snapshot write/rename failed (existing files are preserved): " + std::to_wstring(GetLastError());
            FILE_DISPOSITION_INFO remove = {TRUE};
            SetFileInformationByHandle(file, FileDispositionInfo, &remove, sizeof(remove));
        }
        CloseHandle(file);
    }
    while (false);
    if (ok)
    {
        error->clear();
    }
    return ok;
}

bool ReadAnalystSnapshot(const std::wstring& path, std::wstring* json, std::wstring* error)
{
    bool ok = false;
    std::wstring ignored;
    if (error == nullptr)
    {
        error = &ignored;
    }
    if (json == nullptr)
    {
        *error = L"snapshot output is null";
        return false;
    }
    json->clear();
    *error = L"snapshot cannot be read as bounded UTF-8 JSON";
    const DWORD attributes = DiskPath(path) ? GetFileAttributesW(path.c_str()) : INVALID_FILE_ATTRIBUTES;
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        return false;
    }
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE)
    {
        LARGE_INTEGER length = {};
        if (GetFileType(file) == FILE_TYPE_DISK && GetFileSizeEx(file, &length) && length.QuadPart > 0 && length.QuadPart <= MaxSnapshotBytes)
        {
            std::string bytes(static_cast<size_t>(length.QuadPart), '\0');
            DWORD read = 0;
            if (ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size())
            {
                if (bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") == 0)
                {
                    bytes.erase(0, 3);
                }
                *json = mcpjson::Utf8ToWide(bytes);
                ok = !json->empty();
            }
        }
        CloseHandle(file);
    }
    if (ok)
    {
        error->clear();
    }
    return ok;
}

bool CompareAnalystSnapshots(const std::wstring& before, const std::wstring& after,
    AnalystSnapshotDiff* result, std::wstring* error)
{
    std::wstring ignored;
    if (error == nullptr)
    {
        error = &ignored;
    }
    if (result == nullptr)
    {
        *error = L"diff output is null";
        return false;
    }
    *result = {};
    Snapshot a, b;
    if (!Parse(before, &a) || !Parse(after, &b) || a.Schema != b.Schema)
    {
        *error = L"unsupported, malformed, duplicate, oversized, or different snapshot schemas";
        return false;
    }
    result->Schema = a.Schema;
    result->BootRelation = a.Boots.size() == 1 && b.Boots.size() == 1 ?
        (a.Boots == b.Boots ? L"same" : L"different") : L"unknown_or_multiple";
    result->CoverageChanged = a.Coverage != b.Coverage;
    for (const auto& row : b.Rows)
    {
        const auto old = a.Rows.find(row.first);
        if (old == a.Rows.end())
        {
            ++result->Added;
            result->Changes.push_back({L"newly_observed", row.first, L"", row.second});
        }
        else if (old->second != row.second)
        {
            ++result->Changed;
            result->Changes.push_back({L"changed", row.first, old->second, row.second});
        }
        else
        {
            ++result->Unchanged;
        }
    }
    for (const auto& row : a.Rows)
    {
        if (b.Rows.count(row.first) == 0)
        {
            ++result->NoLongerObserved;
            result->Changes.push_back({L"no_longer_observed", row.first, row.second, L""});
        }
    }
    error->clear();
    return true;
}

std::wstring AnalystSnapshotDiffJson(const AnalystSnapshotDiff& result)
{
    std::wstring out = L"{\"schema\":\"kmon.diff.v1\",\"claim\":\"observation_differences\",\"input_trust\":\"unverified_snapshots\"";
    out += L",\"absence_is_resolution\":false,\"execution_observed\":false,\"source_schema\":" + mcpjson::Quote(result.Schema);
    out += L",\"boot_relation\":" + mcpjson::Quote(result.BootRelation);
    out += L",\"newly_observed\":" + std::to_wstring(result.Added);
    out += L",\"changed\":" + std::to_wstring(result.Changed);
    out += L",\"no_longer_observed\":" + std::to_wstring(result.NoLongerObserved);
    out += L",\"unchanged\":" + std::to_wstring(result.Unchanged);
    out += L",\"coverage_changed\":" + std::wstring(result.CoverageChanged ? L"true" : L"false") + L",\"changes\":[";
    bool first = true;
    for (const auto& change : result.Changes)
    {
        out += first ? L"{" : L",{";
        first = false;
        out += L"\"kind\":" + mcpjson::Quote(change.Kind) + L",\"identity\":" + mcpjson::Quote(change.Identity);
        out += L",\"before\":" + (change.Before.empty() ? L"null" : change.Before);
        out += L",\"after\":" + (change.After.empty() ? L"null" : change.After) + L"}";
    }
    return out + L"]}";
}
