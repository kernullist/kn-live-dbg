#pragma once

#include "McpJson.h"
#include <algorithm>
#include <map>
#include <optional>
#include <vector>

namespace trace_json
{
    using Object = std::map<std::wstring, std::wstring>;

    inline bool ReadObject(const std::wstring& json, Object* out)
    {
        if (!mcpjson::IsObject(json))
        {
            return false;
        }
        size_t pos = 0;
        mcpjson::SkipWhitespace(json, &pos);
        ++pos;
        for (;;)
        {
            mcpjson::SkipWhitespace(json, &pos);
            if (pos == json.size() || json[pos] == L'}')
            {
                break;
            }
            size_t end = pos;
            if (!mcpjson::ScanString(json, &end))
            {
                return false;
            }
            const auto key = mcpjson::Unescape(json.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(json, &pos);
            if (pos == json.size() || json[pos++] != L':')
            {
                return false;
            }
            mcpjson::SkipWhitespace(json, &pos);
            if (!mcpjson::ScanValue(json, pos, &end))
            {
                return false;
            }
            out->emplace(key, json.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(json, &pos);
            if (pos < json.size() && json[pos] == L',')
            {
                ++pos;
            }
        }
        return true;
    }

    inline bool HasFields(const Object& data, std::initializer_list<const wchar_t*> required,
        std::initializer_list<const wchar_t*> optional = {})
    {
        const auto has = [&](const wchar_t* key) { return data.count(key) != 0; };
        return std::all_of(required.begin(), required.end(), has) &&
            data.size() == required.size() + std::count_if(optional.begin(), optional.end(), has);
    }

    inline bool Members(const std::wstring& json, std::initializer_list<const wchar_t*> keys, Object* out)
    {
        return ReadObject(json, out) && HasFields(*out, keys);
    }

    inline bool Text(const std::wstring& raw, std::wstring* value, size_t maximum = 128)
    {
        if (raw.size() < 2 || raw.front() != L'"' || raw.back() != L'"')
        {
            return false;
        }
        // The shared display decoder repairs unpaired surrogates. Identity
        // input must reject them before decoding to avoid silent aliasing.
        bool high = false;
        for (size_t i = 1; i + 1 < raw.size(); ++i)
        {
            wchar_t c = raw[i];
            if (c == L'\\')
            {
                c = raw[++i];
                if (c == L'u')
                {
                    if (i + 4 >= raw.size())
                    {
                        return false;
                    }
                    c = static_cast<wchar_t>(wcstoul(raw.substr(i + 1, 4).c_str(), nullptr, 16));
                    i += 4;
                }
            }
            if (c >= 0xd800 && c <= 0xdbff)
            {
                if (high)
                {
                    return false;
                }
                high = true;
            }
            else if (c >= 0xdc00 && c <= 0xdfff)
            {
                if (!high)
                {
                    return false;
                }
                high = false;
            }
            else if (high)
            {
                return false;
            }
        }
        if (high)
        {
            return false;
        }
        *value = mcpjson::Unescape(raw);
        return !value->empty() && value->size() <= maximum && mcpjson::SanitizeUtf16(*value) == *value &&
            std::none_of(value->begin(), value->end(), [](wchar_t c)
            {
                return c < 0x20;
            });
    }

    inline bool Decimal(const std::wstring& value, uint64_t* number)
    {
        if (value.empty() || value.size() > 20 || (value.size() > 1 && value[0] == L'0'))
        {
            return false;
        }
        *number = 0;
        for (const auto c : value)
        {
            if (c < L'0' || c > L'9' || *number > (UINT64_MAX - (c - L'0')) / 10)
            {
                return false;
            }
            *number = *number * 10 + c - L'0';
        }
        return true;
    }

    template<typename T>
    inline bool Number(const std::wstring& raw, T* value)
    {
        std::wstring text;
        uint64_t number = 0;
        if (!Text(raw, &text, 20) || !Decimal(text, &number) || number > static_cast<T>(-1))
        {
            return false;
        }
        *value = static_cast<T>(number);
        return true;
    }

    template<typename T>
    inline bool OptionalNumber(const std::wstring& raw, std::optional<T>* value)
    {
        T number = 0;
        if (raw == L"null")
        {
            value->reset();
            return true;
        }
        if (!Number(raw, &number))
        {
            return false;
        }
        *value = number;
        return true;
    }

    inline bool Array(const std::wstring& raw, size_t maximum, std::vector<std::wstring>* rows)
    {
        if (raw.empty() || raw.front() != L'[' || !mcpjson::ValidateDocument(raw))
        {
            return false;
        }
        size_t pos = 1;
        for (;;)
        {
            mcpjson::SkipWhitespace(raw, &pos);
            if (pos == raw.size() || raw[pos] == L']')
            {
                break;
            }
            size_t end = 0;
            if (rows->size() == maximum || !mcpjson::ScanValue(raw, pos, &end))
            {
                return false;
            }
            rows->push_back(raw.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(raw, &pos);
            if (pos < raw.size() && raw[pos] == L',')
            {
                ++pos;
            }
        }
        return true;
    }
}
