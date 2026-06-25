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

        int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
        if (needed <= 0)
        {
            return result;
        }

        result.resize(static_cast<size_t>(needed));
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &result[0], needed);
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

    // Given pos at the first character of a JSON value, returns the index just
    // past the end of that value. Handles strings (with escapes), objects,
    // arrays, and bare tokens (numbers/true/false/null). Returns false on a
    // structurally unterminated value.
    inline bool ScanValue(const std::wstring& text, size_t pos, size_t* endOut)
    {
        bool ok = false;
        do
        {
            if (pos >= text.size())
            {
                break;
            }

            wchar_t first = text[pos];
            if (first == L'\"')
            {
                size_t i = pos + 1;
                bool terminated = false;
                while (i < text.size())
                {
                    wchar_t ch = text[i];
                    if (ch == L'\\')
                    {
                        i += 2;
                        continue;
                    }
                    if (ch == L'\"')
                    {
                        terminated = true;
                        ++i;
                        break;
                    }
                    ++i;
                }
                if (!terminated)
                {
                    break;
                }
                *endOut = i;
                ok = true;
                break;
            }

            if (first == L'{' || first == L'[')
            {
                wchar_t open = first;
                wchar_t close = (first == L'{') ? L'}' : L']';
                int depth = 0;
                size_t i = pos;
                bool inString = false;
                bool terminated = false;
                while (i < text.size())
                {
                    wchar_t ch = text[i];
                    if (inString)
                    {
                        if (ch == L'\\')
                        {
                            i += 2;
                            continue;
                        }
                        if (ch == L'\"')
                        {
                            inString = false;
                        }
                        ++i;
                        continue;
                    }
                    if (ch == L'\"')
                    {
                        inString = true;
                        ++i;
                        continue;
                    }
                    if (ch == open)
                    {
                        ++depth;
                    }
                    else if (ch == close)
                    {
                        --depth;
                        if (depth == 0)
                        {
                            terminated = true;
                            ++i;
                            break;
                        }
                    }
                    ++i;
                }
                if (!terminated)
                {
                    break;
                }
                *endOut = i;
                ok = true;
                break;
            }

            // Bare token: number, true, false, null. Stops at structural chars.
            size_t i = pos;
            while (i < text.size())
            {
                wchar_t ch = text[i];
                if (ch == L',' || ch == L'}' || ch == L']' || ch == L' ' ||
                    ch == L'\t' || ch == L'\r' || ch == L'\n')
                {
                    break;
                }
                ++i;
            }
            if (i == pos)
            {
                break;
            }
            *endOut = i;
            ok = true;
        } while (false);

        return ok;
    }

    // Finds a top-level member named key inside a JSON object and returns its
    // raw value substring (verbatim, including quotes for strings, braces for
    // objects). Only scans the outermost object level.
    inline bool FindRawValue(const std::wstring& object, const std::wstring& key, std::wstring* rawValue)
    {
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
                std::wstring memberKey = object.substr(pos + 1, keyEnd - pos - 2);
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
        if (!FindRawValue(object, key, &raw))
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
