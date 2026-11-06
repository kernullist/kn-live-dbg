#pragma once

#include "McpJson.h"
#include <limits>
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
}
