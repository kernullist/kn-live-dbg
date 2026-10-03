#pragma once

// Minimal, dependency-free JSON helpers for the MCP server transport layer.
// The project deliberately avoids an external JSON library; these inline
// helpers mirror that convention while staying self-contained so McpServer.cpp
// does not need any of main.cpp's file-static JSON routines. All routines are
// surrogate-safe so that ill-formed UTF-16 from kernel-derived strings can
// never produce invalid UTF-8 on the JSON-RPC byte stream (which MUST be UTF-8).

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <set>
#include <string>

namespace mcpjson
{
    // Replaces unpaired UTF-16 surrogates with U+FFFD so downstream conversion
    // and escaping can never emit invalid byte sequences.
    inline std::wstring SanitizeUtf16(const std::wstring& value)
    {
        std::wstring out;
        out.reserve(value.size());
        for (size_t i = 0; i < value.size(); ++i)
        {
            wchar_t ch = value[i];
            if (ch >= 0xD800 && ch <= 0xDBFF)
            {
                bool paired = false;
                if (i + 1 < value.size())
                {
                    wchar_t next = value[i + 1];
                    if (next >= 0xDC00 && next <= 0xDFFF)
                    {
                        out.push_back(ch);
                        out.push_back(next);
                        ++i;
                        paired = true;
                    }
                }
                if (!paired)
                {
                    out.push_back(static_cast<wchar_t>(0xFFFD));
                }
            }
            else if (ch >= 0xDC00 && ch <= 0xDFFF)
            {
                out.push_back(static_cast<wchar_t>(0xFFFD));
            }
            else
            {
                out.push_back(ch);
            }
        }
        return out;
    }

    inline std::string WideToUtf8(const std::wstring& value)
    {
        std::string result;
        if (value.empty())
        {
            return result;
        }

        std::wstring clean = SanitizeUtf16(value);
        int needed = WideCharToMultiByte(CP_UTF8, 0, clean.c_str(), static_cast<int>(clean.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
        {
            return result;
        }

        result.resize(static_cast<size_t>(needed));
        WideCharToMultiByte(CP_UTF8, 0, clean.c_str(), static_cast<int>(clean.size()), &result[0], needed, nullptr, nullptr);
        return result;
    }

    inline std::wstring Utf8ToWide(const std::string& value)
    {
        std::wstring result;
        if (value.empty())
        {
            return result;
        }

        int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
        if (needed <= 0)
        {
            return result;
        }

        result.resize(static_cast<size_t>(needed));
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), static_cast<int>(value.size()), &result[0], needed);
        return result;
    }

    // Escapes a string for inclusion inside a JSON double-quoted literal. Does
    // NOT add the surrounding quotes. Control characters below 0x20 become
    // \uXXXX; quote and backslash are escaped; surrogates are sanitized first.
    inline std::wstring Escape(const std::wstring& value)
    {
        std::wstring clean = SanitizeUtf16(value);
        std::wstring out;
        out.reserve(clean.size() + 8);
        for (wchar_t ch : clean)
        {
            switch (ch)
            {
                case L'\"':
                {
                    out += L"\\\"";
                    break;
                }
                case L'\\':
                {
                    out += L"\\\\";
                    break;
                }
                case L'\b':
                {
                    out += L"\\b";
                    break;
                }
                case L'\f':
                {
                    out += L"\\f";
                    break;
                }
                case L'\n':
                {
                    out += L"\\n";
                    break;
                }
                case L'\r':
                {
                    out += L"\\r";
                    break;
                }
                case L'\t':
                {
                    out += L"\\t";
                    break;
                }
                default:
                {
                    if (ch < 0x20)
                    {
                        wchar_t buffer[8];
                        swprintf_s(buffer, L"\\u%04x", static_cast<unsigned int>(ch));
                        out += buffer;
                    }
                    else
                    {
                        out.push_back(ch);
                    }
                    break;
                }
            }
        }
        return out;
    }

    inline std::wstring Quote(const std::wstring& value)
    {
        return L"\"" + Escape(value) + L"\"";
    }

    inline void SkipWhitespace(const std::wstring& text, size_t* pos)
    {
        while (*pos < text.size())
        {
            wchar_t ch = text[*pos];
            if (ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n')
            {
                ++(*pos);
            }
            else
            {
                break;
            }
        }
    }

    inline std::wstring Unescape(const std::wstring& quoted);

    // Validate one value, including nested grammar and duplicate member names.
    // Bound recursion before accepting network-controlled nesting.
    inline bool ScanValue(const std::wstring& text, size_t pos, size_t* endOut, unsigned depth = 0)
    {
        if (endOut == nullptr || pos >= text.size() || depth > 128)
        {
            return false;
        }
        const wchar_t first = text[pos];
        if (first == L'\"')
        {
            size_t cursor = pos + 1;
            while (cursor < text.size())
            {
                const wchar_t ch = text[cursor++];
                if (ch == L'\"')
                {
                    *endOut = cursor;
                    return true;
                }
                if (ch < 0x20)
                {
                    return false;
                }
                if (ch == L'\\')
                {
                    if (cursor == text.size())
                    {
                        return false;
                    }
                    const wchar_t escaped = text[cursor++];
                    if (escaped == L'u')
                    {
                        if (text.size() - cursor < 4)
                        {
                            return false;
                        }
                        for (unsigned index = 0; index < 4; ++index)
                        {
                            const wchar_t hex = text[cursor++];
                            if (!((hex >= L'0' && hex <= L'9') || (hex >= L'a' && hex <= L'f') ||
                                (hex >= L'A' && hex <= L'F')))
                            {
                                return false;
                            }
                        }
                    }
                    else if (escaped != L'\"' && escaped != L'\\' && escaped != L'/' &&
                        escaped != L'b' && escaped != L'f' && escaped != L'n' && escaped != L'r' && escaped != L't')
                    {
                        return false;
                    }
                }
            }
            return false;
        }
        if (first == L'{' || first == L'[')
        {
            const bool object = first == L'{';
            const wchar_t close = object ? L'}' : L']';
            size_t cursor = pos + 1;
            SkipWhitespace(text, &cursor);
            if (cursor < text.size() && text[cursor] == close)
            {
                *endOut = cursor + 1;
                return true;
            }
            std::set<std::wstring> keys;
            while (cursor < text.size())
            {
                if (object)
                {
                    size_t keyEnd = 0;
                    if (text[cursor] != L'\"' || !ScanValue(text, cursor, &keyEnd, depth + 1) ||
                        !keys.insert(Unescape(text.substr(cursor, keyEnd - cursor))).second)
                    {
                        return false;
                    }
                    cursor = keyEnd;
                    SkipWhitespace(text, &cursor);
                    if (cursor == text.size() || text[cursor++] != L':')
                    {
                        return false;
                    }
                    SkipWhitespace(text, &cursor);
                }
                if (!ScanValue(text, cursor, &cursor, depth + 1))
                {
                    return false;
                }
                SkipWhitespace(text, &cursor);
                if (cursor == text.size())
                {
                    return false;
                }
                if (text[cursor] == close)
                {
                    *endOut = cursor + 1;
                    return true;
                }
                if (text[cursor++] != L',')
                {
                    return false;
                }
                SkipWhitespace(text, &cursor);
            }
            return false;
        }
        for (const wchar_t* literal : {L"true", L"false", L"null"})
        {
            const size_t length = wcslen(literal);
            if (text.compare(pos, length, literal) == 0)
            {
                *endOut = pos + length;
                return true;
            }
        }
        size_t cursor = pos;
        if (text[cursor] == L'-')
        {
            ++cursor;
        }
        const auto digit = [&](size_t index)
        {
            return index < text.size() && text[index] >= L'0' && text[index] <= L'9';
        };
        if (!digit(cursor))
        {
            return false;
        }
        if (text[cursor++] != L'0')
        {
            while (digit(cursor))
            {
                ++cursor;
            }
        }
        if (cursor < text.size() && text[cursor] == L'.')
        {
            if (!digit(++cursor))
            {
                return false;
            }
            while (digit(cursor))
            {
                ++cursor;
            }
        }
        if (cursor < text.size() && (text[cursor] == L'e' || text[cursor] == L'E'))
        {
            ++cursor;
            if (cursor < text.size() && (text[cursor] == L'+' || text[cursor] == L'-'))
            {
                ++cursor;
            }
            if (!digit(cursor))
            {
                return false;
            }
            while (digit(cursor))
            {
                ++cursor;
            }
        }
        *endOut = cursor;
        return true;
    }

    inline bool IsObject(const std::wstring& text)
    {
        size_t pos = 0;
        SkipWhitespace(text, &pos);
        if (pos == text.size() || text[pos] != L'{' || !ScanValue(text, pos, &pos))
        {
            return false;
        }
        SkipWhitespace(text, &pos);
        return pos == text.size();
    }

    // Finds a top-level member named key inside a JSON object and returns its
    // raw value substring (verbatim, including quotes for strings, braces for
    // objects). Only scans the outermost object level.
    inline bool FindRawValue(const std::wstring& object, const std::wstring& key, std::wstring* rawValue)
    {
        if (rawValue == nullptr || !IsObject(object))
        {
            return false;
        }
        bool found = false;
        do
        {
            size_t pos = 0;
            SkipWhitespace(object, &pos);
            if (pos >= object.size() || object[pos] != L'{')
            {
                break;
            }
            ++pos;

            while (pos < object.size())
            {
                SkipWhitespace(object, &pos);
                if (pos < object.size() && object[pos] == L'}')
                {
                    break;
                }
                if (pos >= object.size() || object[pos] != L'\"')
                {
                    break;
                }

                size_t keyEnd = 0;
                if (!ScanValue(object, pos, &keyEnd))
                {
                    break;
                }
                std::wstring memberKey = Unescape(object.substr(pos, keyEnd - pos));
                pos = keyEnd;

                SkipWhitespace(object, &pos);
                if (pos >= object.size() || object[pos] != L':')
                {
                    break;
                }
                ++pos;
                SkipWhitespace(object, &pos);

                size_t valueEnd = 0;
                if (!ScanValue(object, pos, &valueEnd))
                {
                    break;
                }

                if (memberKey == key)
                {
                    *rawValue = object.substr(pos, valueEnd - pos);
                    found = true;
                    break;
                }

                pos = valueEnd;
                SkipWhitespace(object, &pos);
                if (pos < object.size() && object[pos] == L',')
                {
                    ++pos;
                }
            }
        } while (false);

        return found;
    }

    inline std::wstring Unescape(const std::wstring& quoted)
    {
        std::wstring out;
        size_t start = 0;
        size_t end = quoted.size();
        if (end >= 2 && quoted.front() == L'\"' && quoted.back() == L'\"')
        {
            start = 1;
            end = quoted.size() - 1;
        }

        for (size_t i = start; i < end; ++i)
        {
            wchar_t ch = quoted[i];
            if (ch != L'\\' || i + 1 >= end)
            {
                out.push_back(ch);
                continue;
            }

            wchar_t next = quoted[i + 1];
            switch (next)
            {
                case L'\"':
                {
                    out.push_back(L'\"');
                    ++i;
                    break;
                }
                case L'\\':
                {
                    out.push_back(L'\\');
                    ++i;
                    break;
                }
                case L'/':
                {
                    out.push_back(L'/');
                    ++i;
                    break;
                }
                case L'b':
                {
                    out.push_back(L'\b');
                    ++i;
                    break;
                }
                case L'f':
                {
                    out.push_back(L'\f');
                    ++i;
                    break;
                }
                case L'n':
                {
                    out.push_back(L'\n');
                    ++i;
                    break;
                }
                case L'r':
                {
                    out.push_back(L'\r');
                    ++i;
                    break;
                }
                case L't':
                {
                    out.push_back(L'\t');
                    ++i;
                    break;
                }
                case L'u':
                {
                    if (i + 5 < end)
                    {
                        std::wstring hex = quoted.substr(i + 2, 4);
                        wchar_t code = static_cast<wchar_t>(wcstoul(hex.c_str(), nullptr, 16));
                        out.push_back(code);
                        i += 5;
                    }
                    else
                    {
                        out.push_back(ch);
                    }
                    break;
                }
                default:
                {
                    out.push_back(ch);
                    break;
                }
            }
        }

        return SanitizeUtf16(out);
    }

    // Returns the string value of a top-level member, JSON-unescaped. Returns
    // false if the member is missing or is not a JSON string.
    inline bool GetString(const std::wstring& object, const std::wstring& key, std::wstring* value)
    {
        std::wstring raw;
        if (value == nullptr || !FindRawValue(object, key, &raw))
        {
            return false;
        }
        if (raw.empty() || raw.front() != L'\"')
        {
            return false;
        }
        *value = Unescape(raw);
        return true;
    }
}
