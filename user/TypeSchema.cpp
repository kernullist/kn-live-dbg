#include "TypeSchema.h"
#include "AnalystSnapshot.h"
#include "ContentHash.h"
#include "McpJson.h"
#include "SymbolEngine.h"
#include <algorithm>
#include <map>

namespace
{
    std::wstring Number(uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    }

    bool Number(const std::wstring& json, const wchar_t* key, uint64_t* value)
    {
        std::wstring text;
        if (!mcpjson::GetString(json, key, &text) || text.empty() || text.size() > 20)
        {
            return false;
        }
        *value = 0;
        for (const auto c : text)
        {
            if (c < L'0' || c > L'9' || *value > (UINT64_MAX - (c - L'0')) / 10)
            {
                return false;
            }
            *value = *value * 10 + c - L'0';
        }
        return true;
    }

    bool Text(const std::wstring& value, size_t maximum = 1024)
    {
        return !value.empty() && value.size() <= maximum && value.find(L'\0') == std::wstring::npos &&
            value == mcpjson::SanitizeUtf16(value);
    }

    bool Hex(const std::wstring& value, size_t length)
    {
        return value.size() == length && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos &&
            value.find_first_not_of(L'0') != std::wstring::npos;
    }

    std::wstring Digest(const std::wstring& text)
    {
        const auto bytes = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }

    std::wstring PathJson(const std::vector<std::wstring>& path)
    {
        std::wstring json = L"[";
        for (const auto& part : path)
        {
            if (json.size() > 1)
            {
                json += L",";
            }
            json += mcpjson::Quote(part);
        }
        return json + L"]";
    }

    bool Array(const std::wstring& json, std::vector<std::wstring>* rows, size_t maximum)
    {
        rows->clear();
        size_t pos = 0;
        if (json.empty() || json[pos++] != L'[')
        {
            return false;
        }
        while (pos < json.size() && json[pos] != L']')
        {
            size_t end = 0;
            if (rows->size() == maximum || !mcpjson::ScanValue(json, pos, &end))
            {
                return false;
            }
            rows->push_back(json.substr(pos, end - pos));
            pos = end;
            if (pos < json.size() && json[pos] == L',')
            {
                ++pos;
                if (pos == json.size() || json[pos] == L']')
                {
                    return false;
                }
            }
            else
            {
                break;
            }
        }
        return pos + 1 == json.size() && json[pos] == L']';
    }

    bool Path(const std::wstring& row, std::vector<std::wstring>* path)
    {
        std::wstring raw;
        std::vector<std::wstring> parts;
        if (!mcpjson::FindRawValue(row, L"path", &raw) || !Array(raw, &parts, TypeSchemaMaxDepth))
        {
            return false;
        }
        for (const auto& part : parts)
        {
            std::wstring text;
            if (!mcpjson::GetString(L"{\"part\":" + part + L"}", L"part", &text))
            {
                return false;
            }
            path->push_back(std::move(text));
        }
        return true;
    }

    std::wstring Payload(const TypeSchemaPackage& p)
    {
        std::wstring json = L"{\"image_sha256\":" + mcpjson::Quote(p.ImageSha256) +
            L",\"pdb_sha256\":" + mcpjson::Quote(p.PdbSha256) + L",\"pdb_guid\":" + mcpjson::Quote(p.PdbGuid) +
            L",\"pdb_age\":" + Number(p.PdbAge) + L",\"machine\":" + Number(p.Machine) +
            L",\"image_size\":" + Number(p.ImageSize) + L",\"provider_sha256\":" + mcpjson::Quote(p.ProviderSha256) +
            L",\"provider_version\":" + mcpjson::Quote(p.ProviderVersion) + L",\"type_name\":" + mcpjson::Quote(p.TypeName) +
            L",\"type_bytes\":" + Number(p.TypeBytes) +
            L",\"root_interpretation\":\"direct_object_bytes\",\"validation\":\"pdb_identity_and_layout_bounds\","
            L"\"trusted_distribution\":false,\"runtime_invariants_checked\":false,\"parser_isolated\":false,\"fields\":[";
        bool first = true;
        for (const auto& f : p.Fields)
        {
            if (!first)
            {
                json += L",";
            }
            first = false;
            json += L"{\"path\":" + PathJson(f.Path) + L",\"type_name\":" + mcpjson::Quote(f.TypeName) +
                L",\"symbol_tag\":" + Number(f.SymbolTag) + L",\"base_type\":" + Number(f.BaseType) +
                L",\"offset\":" + Number(f.Offset) + L",\"storage_bytes\":" + Number(f.StorageBytes) +
                L",\"bit_position\":" + Number(f.BitPosition) + L",\"bit_width\":" + Number(f.BitWidth) +
                L",\"expansion\":" + mcpjson::Quote(f.Expansion) + L"}";
        }
        json += L"],\"gaps\":[";
        first = true;
        for (const auto& gap : p.Gaps)
        {
            if (!first)
            {
                json += L",";
            }
            first = false;
            json += L"{\"path\":" + PathJson(gap.Path) + L",\"reason\":" + mcpjson::Quote(gap.Reason) + L"}";
        }
        return json + L"]}";
    }
}

std::wstring TypeSchemaExpansion(uint64_t symbolTag, size_t depth)
{
    if (symbolTag == KNDBG_SYMTAG_UDT)
    {
        return depth == TypeSchemaMaxDepth ? L"depth_limit" : L"embedded";
    }
    if (symbolTag == KNDBG_SYMTAG_POINTER_TYPE)
    {
        return L"pointer_value";
    }
    if (symbolTag == KNDBG_SYMTAG_ARRAY_TYPE)
    {
        return L"array_storage";
    }
    // SymTagEnum is 12 in the DIA/DbgHelp symbol-tag contract.
    return symbolTag == KNDBG_SYMTAG_BASE_TYPE || symbolTag == 12 ? L"scalar" : L"unavailable";
}

bool ValidateTypeSchema(const TypeSchemaPackage& p, std::wstring* error)
{
    if (error != nullptr)
    {
        *error = L"invalid or unsupported type schema identity, path, extent, or budget";
    }
    if (!Hex(p.ImageSha256, 64) || !Hex(p.PdbSha256, 64) || !Hex(p.ProviderSha256, 64) || !Hex(p.PdbGuid, 32) ||
        p.PdbAge == 0 || p.PdbAge > UINT32_MAX || p.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        p.ImageSize == 0 || p.ImageSize > UINT32_MAX || !Text(p.ProviderVersion, 128) || !Text(p.TypeName) ||
        p.TypeBytes == 0 || p.TypeBytes > 16 * 1024 * 1024 || p.Fields.size() > TypeSchemaMaxFields ||
        p.Gaps.size() > TypeSchemaMaxFields)
    {
        return false;
    }
    std::map<std::vector<std::wstring>, const TypeSchemaField*> fields;
    for (const auto& f : p.Fields)
    {
        if (f.Path.empty() || f.Path.size() > TypeSchemaMaxDepth ||
            !std::all_of(f.Path.begin(), f.Path.end(), [](const auto& part) { return Text(part); }) ||
            !Text(f.TypeName) || f.SymbolTag == 0 || f.SymbolTag > UINT32_MAX || f.BaseType > UINT32_MAX ||
            f.StorageBytes == 0 || f.Offset > p.TypeBytes || f.StorageBytes > p.TypeBytes - f.Offset ||
            f.Expansion != TypeSchemaExpansion(f.SymbolTag, f.Path.size()) ||
            (f.Expansion == L"pointer_value" && f.StorageBytes != 8) ||
            (f.BitWidth == 0 && f.BitPosition != 0) || f.BitPosition >= f.StorageBytes * 8 ||
            f.BitWidth > f.StorageBytes * 8 - f.BitPosition ||
            (f.BitWidth != 0 && f.Expansion != L"scalar") || !fields.emplace(f.Path, &f).second)
        {
            return false;
        }
    }
    for (const auto& f : p.Fields)
    {
        if ((f.Expansion == L"unavailable" || f.Expansion == L"depth_limit") &&
            std::none_of(p.Gaps.begin(), p.Gaps.end(), [&](const auto& gap)
            {
                return gap.Path == f.Path && gap.Reason == f.Expansion;
            }))
        {
            return false;
        }
        if (f.Path.size() > 1)
        {
            auto parent = f.Path;
            parent.pop_back();
            const auto found = fields.find(parent);
            if (found == fields.end() || found->second->Expansion != L"embedded" || f.Offset < found->second->Offset ||
                f.Offset - found->second->Offset > found->second->StorageBytes ||
                f.StorageBytes > found->second->StorageBytes - (f.Offset - found->second->Offset))
            {
                return false;
            }
        }
    }
    for (const auto& gap : p.Gaps)
    {
        if (gap.Path.size() > TypeSchemaMaxDepth || !Text(gap.Reason, 128) ||
            !std::all_of(gap.Path.begin(), gap.Path.end(), [](const auto& part) { return Text(part); }) ||
            (!gap.Path.empty() && fields.find(gap.Path) == fields.end()))
        {
            return false;
        }
    }
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

std::wstring TypeSchemaJson(const TypeSchemaPackage& package)
{
    if (!ValidateTypeSchema(package, nullptr))
    {
        return L"";
    }
    const auto payload = Payload(package);
    const auto digest = Digest(payload);
    if (digest.empty())
    {
        return L"";
    }
    const auto json = L"{\"schema\":\"kn.type_schema.v1\",\"package_sha256\":" + mcpjson::Quote(digest) +
        L",\"payload\":" + payload + L"}";
    return mcpjson::WideToUtf8(json).size() <= TypeSchemaMaxBytes ? json : L"";
}

bool ParseTypeSchema(const std::wstring& json, TypeSchemaPackage* package, std::wstring* error)
{
    if (error != nullptr)
    {
        *error = L"type schema is corrupt, noncanonical, unsupported, or exceeds its budget";
    }
    if (package == nullptr || json.size() > TypeSchemaMaxBytes || !mcpjson::ValidateDocument(json))
    {
        return false;
    }
    TypeSchemaPackage p;
    std::wstring payload, raw;
    std::vector<std::wstring> rows;
    if (!mcpjson::FindRawValue(json, L"payload", &payload) ||
        !mcpjson::GetString(payload, L"image_sha256", &p.ImageSha256) ||
        !mcpjson::GetString(payload, L"pdb_sha256", &p.PdbSha256) ||
        !mcpjson::GetString(payload, L"pdb_guid", &p.PdbGuid) || !Number(payload, L"pdb_age", &p.PdbAge) ||
        !Number(payload, L"machine", &p.Machine) || !Number(payload, L"image_size", &p.ImageSize) ||
        !mcpjson::GetString(payload, L"provider_sha256", &p.ProviderSha256) ||
        !mcpjson::GetString(payload, L"provider_version", &p.ProviderVersion) ||
        !mcpjson::GetString(payload, L"type_name", &p.TypeName) || !Number(payload, L"type_bytes", &p.TypeBytes) ||
        !mcpjson::FindRawValue(payload, L"fields", &raw) || !Array(raw, &rows, TypeSchemaMaxFields))
    {
        return false;
    }
    for (const auto& row : rows)
    {
        TypeSchemaField f;
        if (!Path(row, &f.Path) || !mcpjson::GetString(row, L"type_name", &f.TypeName) ||
            !Number(row, L"symbol_tag", &f.SymbolTag) || !Number(row, L"base_type", &f.BaseType) ||
            !Number(row, L"offset", &f.Offset) || !Number(row, L"storage_bytes", &f.StorageBytes) ||
            !Number(row, L"bit_position", &f.BitPosition) || !Number(row, L"bit_width", &f.BitWidth) ||
            !mcpjson::GetString(row, L"expansion", &f.Expansion))
        {
            return false;
        }
        p.Fields.push_back(std::move(f));
    }
    if (!mcpjson::FindRawValue(payload, L"gaps", &raw) || !Array(raw, &rows, TypeSchemaMaxFields))
    {
        return false;
    }
    for (const auto& row : rows)
    {
        TypeSchemaGap gap;
        if (!Path(row, &gap.Path) || !mcpjson::GetString(row, L"reason", &gap.Reason))
        {
            return false;
        }
        p.Gaps.push_back(std::move(gap));
    }
    if (!ValidateTypeSchema(p, nullptr) || TypeSchemaJson(p) != json)
    {
        return false;
    }
    *package = std::move(p);
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

bool LoadTypeSchema(const std::wstring& path, TypeSchemaPackage* package, std::wstring* error)
{
    std::wstring json;
    return ReadAnalystSnapshot(path, &json, error, TypeSchemaMaxBytes, nullptr, true) && ParseTypeSchema(json, package, error);
}

bool SaveTypeSchema(const std::wstring& path, const TypeSchemaPackage& package, std::wstring* error)
{
    if (!ValidateTypeSchema(package, error))
    {
        return false;
    }
    return SaveObservationJson(path, TypeSchemaJson(package), error);
}
