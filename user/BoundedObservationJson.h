#pragma once

#include "McpJson.h"
#include <limits>
#include <map>
#include <initializer_list>
#include <vector>

namespace bounded_observation_json
{
    inline std::wstring N(uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); }
    inline std::wstring B(bool value) { return value ? L"true" : L"false"; }
    inline bool Text(const std::wstring& text, size_t limit, bool empty = false)
    {
        return (empty || !text.empty()) && text.size() <= limit && text.find(L'\0') == std::wstring::npos &&
            mcpjson::SanitizeUtf16(text) == text;
    }
    template<class T> bool Number(const std::wstring& json, const wchar_t* key, T* out)
    {
        std::wstring text;
        if (!mcpjson::GetString(json, key, &text) || text.empty() || text.size() > 20) { return false; }
        uint64_t value = 0;
        for (const auto c : text)
        {
            if (c < L'0' || c > L'9' || value > (UINT64_MAX - (c - L'0')) / 10) { return false; }
            value = value * 10 + c - L'0';
        }
        if (value > (std::numeric_limits<T>::max)()) { return false; }
        *out = static_cast<T>(value);
        return true;
    }
    inline bool Boolean(const std::wstring& json, const wchar_t* key, bool* out)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(json, key, &raw) || (raw != L"true" && raw != L"false")) { return false; }
        *out = raw == L"true";
        return true;
    }
    inline bool Array(const std::wstring& json, const wchar_t* key, size_t limit, std::vector<std::wstring>* rows)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(json, key, &raw) || raw.empty() || raw[0] != L'[') { return false; }
        size_t pos = 1;
        while (pos < raw.size() && raw[pos] != L']')
        {
            size_t end = 0;
            if (rows->size() == limit || !mcpjson::ScanValue(raw, pos, &end)) { return false; }
            rows->push_back(raw.substr(pos, end - pos));
            pos = end;
            if (pos < raw.size() && raw[pos] == L',')
            {
                ++pos;
                if (pos == raw.size() || raw[pos] == L']') { return false; }
            }
            else { break; }
        }
        return pos + 1 == raw.size() && raw[pos] == L']';
    }

    // Index a bounded object's top-level values once. Repeated FindRawValue on
    // a multi-MiB receipt array revalidates that entire array for every scalar.
    // Consumers still compare their complete canonical encoding with the input.
    class IndexedObject
    {
    public:
        bool Parse(const std::wstring& json)
        {
            Fields.clear();
            if (!mcpjson::IsObject(json)) { return false; }
            size_t pos = 0;
            mcpjson::SkipWhitespace(json, &pos);
            ++pos;
            while (pos < json.size())
            {
                mcpjson::SkipWhitespace(json, &pos);
                if (json[pos] == L'}') { return true; }
                size_t keyEnd = 0, valueEnd = 0;
                if (Fields.size() == 128 || !mcpjson::ScanValue(json, pos, &keyEnd)) { return false; }
                const auto key = mcpjson::Unescape(json.substr(pos, keyEnd - pos));
                pos = keyEnd;
                mcpjson::SkipWhitespace(json, &pos);
                ++pos; // Colon and complete object syntax were validated above.
                mcpjson::SkipWhitespace(json, &pos);
                if (!mcpjson::ScanValue(json, pos, &valueEnd) || !Fields.emplace(key, json.substr(pos, valueEnd - pos)).second) { return false; }
                pos = valueEnd;
                mcpjson::SkipWhitespace(json, &pos);
                if (json[pos] == L',') { ++pos; }
            }
            return false;
        }
        bool Raw(const wchar_t* key, std::wstring* out) const
        {
            const auto it = Fields.find(key);
            if (it == Fields.end()) { return false; }
            *out = it->second;
            return true;
        }
        bool Rows(const wchar_t* key, size_t limit, std::vector<std::wstring>* out) const
        {
            const auto it = Fields.find(key);
            return it != Fields.end() && Array(L"{" + mcpjson::Quote(key) + L":" + it->second + L"}", key, limit, out);
        }
        std::wstring Metadata(std::initializer_list<const wchar_t*> excluded) const
        {
            std::wstring out = L"{";
            for (const auto& field : Fields)
            {
                bool omit = false;
                for (const auto key : excluded) { omit |= field.first == key; }
                if (omit) { continue; }
                if (field.second.size() > 65536 || out.size() + field.first.size() + field.second.size() > 65536) { return L""; }
                if (out.size() > 1) { out += L","; }
                out += mcpjson::Quote(field.first) + L":" + field.second;
            }
            return out + L"}";
        }
    private:
        std::map<std::wstring, std::wstring> Fields;
    };
}
