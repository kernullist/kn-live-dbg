#include "SnapshotJson.h"

#include <Windows.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>

namespace
{
    constexpr uint64_t kMaxSnapshotTextFileBytes =
        64ull * 1024ull * 1024ull;

    bool WideToUtf8(
        const std::wstring& value,
        std::string* result)
    {
        if (result == nullptr)
        {
            return false;
        }
        result->clear();

        if (value.empty())
        {
            return true;
        }

        if (value.size() >
            static_cast<size_t>(
                std::numeric_limits<int>::max()))
        {
            return false;
        }

        const int inputLength =
            static_cast<int>(value.size());
        const int required = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            value.data(),
            inputLength,
            nullptr,
            0,
            nullptr,
            nullptr);
        if (required <= 0)
        {
            return false;
        }

        result->resize(required);
        if (WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                value.data(),
                inputLength,
                result->data(),
                required,
                nullptr,
                nullptr) != required)
        {
            result->clear();
            return false;
        }
        return true;
    }

    bool Utf8ToWide(
        const std::string& value,
        std::wstring* result)
    {
        if (result == nullptr)
        {
            return false;
        }
        result->clear();

        if (value.empty())
        {
            return true;
        }

        if (value.size() >
            static_cast<size_t>(
                std::numeric_limits<int>::max()))
        {
            return false;
        }

        const int inputLength =
            static_cast<int>(value.size());
        const int required = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            value.data(),
            inputLength,
            nullptr,
            0);
        if (required <= 0)
        {
            return false;
        }

        result->resize(required);
        if (MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                value.data(),
                inputLength,
                result->data(),
                required) != required)
        {
            result->clear();
            return false;
        }
        return true;
    }

    std::wstring DirectoryFromPath(const std::wstring& path)
    {
        std::wstring directory;
        size_t slash = path.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            directory = path.substr(0, slash);
        }
        return directory;
    }

    bool EnsureDirectoryTree(const std::wstring& directory, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (directory.empty())
            {
                ok = true;
                break;
            }

            DWORD attrs = GetFileAttributesW(directory.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES)
            {
                ok = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
                if (!ok && error != nullptr)
                {
                    *error = L"path exists but is not a directory: " + directory;
                }
                break;
            }

            size_t start = 0;
            if (directory.size() >= 2 && directory[1] == L':')
            {
                start = 2;
            }

            while (start < directory.size())
            {
                size_t pos = directory.find_first_of(L"\\/", start + 1);
                std::wstring part = (pos == std::wstring::npos)
                    ? directory
                    : directory.substr(0, pos);
                if (!part.empty())
                {
                    DWORD partAttrs = GetFileAttributesW(part.c_str());
                    if (partAttrs == INVALID_FILE_ATTRIBUTES)
                    {
                        if (!CreateDirectoryW(part.c_str(), nullptr))
                        {
                            DWORD lastError = GetLastError();
                            if (lastError != ERROR_ALREADY_EXISTS)
                            {
                                if (error != nullptr)
                                {
                                    *error = L"CreateDirectoryW failed for " + part +
                                        L" gle=" + std::to_wstring(lastError);
                                }
                                break;
                            }
                        }
                    }
                    else if ((partAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        if (error != nullptr)
                        {
                            *error = L"path exists but is not a directory: " + part;
                        }
                        break;
                    }
                }

                if (pos == std::wstring::npos)
                {
                    ok = true;
                    break;
                }
                start = pos;
            }
        } while (false);

        return ok;
    }

    void AppendJsonStringArray(std::wstringstream& stream, const std::vector<std::wstring>& values)
    {
        stream << L"[";
        for (size_t i = 0; i < values.size(); ++i)
        {
            if (i != 0)
            {
                stream << L",";
            }
            stream << L"\"" << SnapshotJsonEscape(values[i]) << L"\"";
        }
        stream << L"]";
    }

    void AppendJsonStringMap(std::wstringstream& stream, const std::map<std::wstring, std::wstring>& values)
    {
        stream << L"{";
        bool first = true;
        for (const auto& item : values)
        {
            if (!first)
            {
                stream << L",";
            }
            first = false;
            stream << L"\"" << SnapshotJsonEscape(item.first) << L"\":\""
                   << SnapshotJsonEscape(item.second) << L"\"";
        }
        stream << L"}";
    }

    int HexDigitValue(wchar_t ch)
    {
        int value = -1;

        if (ch >= L'0' && ch <= L'9')
        {
            value = static_cast<int>(ch - L'0');
        }
        else if (ch >= L'a' && ch <= L'f')
        {
            value = static_cast<int>(ch - L'a' + 10);
        }
        else if (ch >= L'A' && ch <= L'F')
        {
            value = static_cast<int>(ch - L'A' + 10);
        }

        return value;
    }

    bool ParseJsonStringAt(const std::wstring& text, size_t quote, std::wstring* value, size_t* next)
    {
        bool ok = false;

        do
        {
            if (value == nullptr || quote >= text.size() || text[quote] != L'"')
            {
                break;
            }

            std::wstring parsed;
            for (size_t index = quote + 1; index < text.size(); ++index)
            {
                wchar_t ch = text[index];
                if (ch == L'"')
                {
                    *value = parsed;
                    if (next != nullptr)
                    {
                        *next = index + 1;
                    }
                    ok = true;
                    break;
                }
                if (ch == L'\\')
                {
                    if (index + 1 >= text.size())
                    {
                        break;
                    }
                    wchar_t esc = text[++index];
                    if (esc == L'"' || esc == L'\\' || esc == L'/')
                    {
                        parsed.push_back(esc);
                    }
                    else if (esc == L'b')
                    {
                        parsed.push_back(L'\b');
                    }
                    else if (esc == L'f')
                    {
                        parsed.push_back(L'\f');
                    }
                    else if (esc == L'n')
                    {
                        parsed.push_back(L'\n');
                    }
                    else if (esc == L'r')
                    {
                        parsed.push_back(L'\r');
                    }
                    else if (esc == L't')
                    {
                        parsed.push_back(L'\t');
                    }
                    else if (esc == L'u')
                    {
                        if (index + 4 >= text.size())
                        {
                            break;
                        }
                        uint32_t codepoint = 0;
                        bool valid = true;
                        for (size_t offset = 1; offset <= 4; ++offset)
                        {
                            int digit = HexDigitValue(text[index + offset]);
                            if (digit < 0)
                            {
                                valid = false;
                                break;
                            }
                            codepoint = (codepoint << 4) | static_cast<uint32_t>(digit);
                        }

                        if (!valid)
                        {
                            break;
                        }
                        if (codepoint >= 0xd800u &&
                            codepoint <= 0xdbffu)
                        {
                            if (index + 10 >= text.size() ||
                                text[index + 5] != L'\\' ||
                                text[index + 6] != L'u')
                            {
                                break;
                            }

                            uint32_t lowSurrogate = 0;
                            for (size_t offset = 7;
                                 offset <= 10;
                                 ++offset)
                            {
                                int digit =
                                    HexDigitValue(
                                        text[index + offset]);
                                if (digit < 0)
                                {
                                    valid = false;
                                    break;
                                }
                                lowSurrogate =
                                    (lowSurrogate << 4) |
                                    static_cast<uint32_t>(digit);
                            }
                            if (!valid ||
                                lowSurrogate < 0xdc00u ||
                                lowSurrogate > 0xdfffu)
                            {
                                break;
                            }

                            parsed.push_back(
                                static_cast<wchar_t>(
                                    codepoint));
                            parsed.push_back(
                                static_cast<wchar_t>(
                                    lowSurrogate));
                            index += 10;
                        }
                        else if (codepoint >= 0xdc00u &&
                                 codepoint <= 0xdfffu)
                        {
                            break;
                        }
                        else
                        {
                            parsed.push_back(
                                static_cast<wchar_t>(
                                    codepoint));
                            index += 4;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                else if (ch < 0x20)
                {
                    break;
                }
                else
                {
                    parsed.push_back(ch);
                }
            }
        } while (false);

        return ok;
    }

    constexpr size_t kMaxJsonNestingDepth = 128;

    bool IsJsonWhitespace(wchar_t value)
    {
        return value == L' ' ||
            value == L'\t' ||
            value == L'\r' ||
            value == L'\n';
    }

    void SkipJsonWhitespace(
        const std::wstring& text,
        size_t* index)
    {
        if (index == nullptr)
        {
            return;
        }
        while (*index < text.size() &&
               IsJsonWhitespace(text[*index]))
        {
            ++*index;
        }
    }

    bool ParseJsonValueAt(
        const std::wstring& text,
        size_t* index,
        size_t depth);

    bool ParseJsonNumberAt(
        const std::wstring& text,
        size_t* index)
    {
        if (index == nullptr || *index >= text.size())
        {
            return false;
        }

        size_t cursor = *index;
        if (text[cursor] == L'-')
        {
            ++cursor;
        }
        if (cursor >= text.size())
        {
            return false;
        }

        if (text[cursor] == L'0')
        {
            ++cursor;
            if (cursor < text.size() &&
                text[cursor] >= L'0' &&
                text[cursor] <= L'9')
            {
                return false;
            }
        }
        else if (text[cursor] >= L'1' &&
                 text[cursor] <= L'9')
        {
            do
            {
                ++cursor;
            } while (cursor < text.size() &&
                     text[cursor] >= L'0' &&
                     text[cursor] <= L'9');
        }
        else
        {
            return false;
        }

        if (cursor < text.size() && text[cursor] == L'.')
        {
            ++cursor;
            const size_t fractionStart = cursor;
            while (cursor < text.size() &&
                   text[cursor] >= L'0' &&
                   text[cursor] <= L'9')
            {
                ++cursor;
            }
            if (cursor == fractionStart)
            {
                return false;
            }
        }

        if (cursor < text.size() &&
            (text[cursor] == L'e' ||
             text[cursor] == L'E'))
        {
            ++cursor;
            if (cursor < text.size() &&
                (text[cursor] == L'+' ||
                 text[cursor] == L'-'))
            {
                ++cursor;
            }
            const size_t exponentStart = cursor;
            while (cursor < text.size() &&
                   text[cursor] >= L'0' &&
                   text[cursor] <= L'9')
            {
                ++cursor;
            }
            if (cursor == exponentStart)
            {
                return false;
            }
        }

        *index = cursor;
        return true;
    }

    bool ParseJsonObjectAt(
        const std::wstring& text,
        size_t* index,
        size_t depth)
    {
        if (index == nullptr ||
            *index >= text.size() ||
            text[*index] != L'{' ||
            depth > kMaxJsonNestingDepth)
        {
            return false;
        }

        size_t cursor = *index + 1;
        SkipJsonWhitespace(text, &cursor);
        if (cursor < text.size() &&
            text[cursor] == L'}')
        {
            *index = cursor + 1;
            return true;
        }

        std::set<std::wstring> keys;
        for (;;)
        {
            std::wstring key;
            size_t next = 0;
            if (!ParseJsonStringAt(
                    text,
                    cursor,
                    &key,
                    &next) ||
                !keys.insert(key).second)
            {
                return false;
            }

            cursor = next;
            SkipJsonWhitespace(text, &cursor);
            if (cursor >= text.size() ||
                text[cursor] != L':')
            {
                return false;
            }
            ++cursor;
            SkipJsonWhitespace(text, &cursor);
            if (!ParseJsonValueAt(
                    text,
                    &cursor,
                    depth + 1))
            {
                return false;
            }

            SkipJsonWhitespace(text, &cursor);
            if (cursor >= text.size())
            {
                return false;
            }
            if (text[cursor] == L'}')
            {
                *index = cursor + 1;
                return true;
            }
            if (text[cursor] != L',')
            {
                return false;
            }
            ++cursor;
            SkipJsonWhitespace(text, &cursor);
        }
    }

    bool ParseJsonArrayAt(
        const std::wstring& text,
        size_t* index,
        size_t depth)
    {
        if (index == nullptr ||
            *index >= text.size() ||
            text[*index] != L'[' ||
            depth > kMaxJsonNestingDepth)
        {
            return false;
        }

        size_t cursor = *index + 1;
        SkipJsonWhitespace(text, &cursor);
        if (cursor < text.size() &&
            text[cursor] == L']')
        {
            *index = cursor + 1;
            return true;
        }

        for (;;)
        {
            if (!ParseJsonValueAt(
                    text,
                    &cursor,
                    depth + 1))
            {
                return false;
            }
            SkipJsonWhitespace(text, &cursor);
            if (cursor >= text.size())
            {
                return false;
            }
            if (text[cursor] == L']')
            {
                *index = cursor + 1;
                return true;
            }
            if (text[cursor] != L',')
            {
                return false;
            }
            ++cursor;
            SkipJsonWhitespace(text, &cursor);
        }
    }

    bool ParseJsonValueAt(
        const std::wstring& text,
        size_t* index,
        size_t depth)
    {
        if (index == nullptr ||
            *index >= text.size() ||
            depth > kMaxJsonNestingDepth)
        {
            return false;
        }

        if (text[*index] == L'{')
        {
            return ParseJsonObjectAt(
                text,
                index,
                depth);
        }
        if (text[*index] == L'[')
        {
            return ParseJsonArrayAt(
                text,
                index,
                depth);
        }
        if (text[*index] == L'"')
        {
            std::wstring ignored;
            size_t next = 0;
            if (!ParseJsonStringAt(
                    text,
                    *index,
                    &ignored,
                    &next))
            {
                return false;
            }
            *index = next;
            return true;
        }

        const struct
        {
            const wchar_t* Text;
            size_t Length;
        } literals[] =
        {
            {L"true", 4},
            {L"false", 5},
            {L"null", 4}
        };
        for (const auto& literal : literals)
        {
            if (text.compare(
                    *index,
                    literal.Length,
                    literal.Text) == 0)
            {
                *index += literal.Length;
                return true;
            }
        }

        return ParseJsonNumberAt(text, index);
    }

    bool ValidateJsonDocument(
        const std::wstring& text)
    {
        size_t index = 0;
        SkipJsonWhitespace(text, &index);
        if (index >= text.size() ||
            text[index] != L'{' ||
            !ParseJsonValueAt(text, &index, 0))
        {
            return false;
        }
        SkipJsonWhitespace(text, &index);
        return index == text.size();
    }

    enum class JsonKeyLookup
    {
        Missing,
        Found,
        Invalid
    };

    JsonKeyLookup FindTopLevelJsonKey(
        const std::wstring& json,
        const std::wstring& key,
        size_t* colon)
    {
        int objectDepth = 0;
        int arrayDepth = 0;
        bool found = false;
        bool rootStarted = false;
        bool rootClosed = false;
        size_t foundColon = 0;

        for (size_t index = 0; index < json.size(); ++index)
        {
            wchar_t ch = json[index];
            if (rootClosed)
            {
                if (iswspace(ch) == 0)
                {
                    return JsonKeyLookup::Invalid;
                }
                continue;
            }
            if (ch == L'{')
            {
                if (!rootStarted)
                {
                    rootStarted = true;
                }
                else if (objectDepth == 0)
                {
                    return JsonKeyLookup::Invalid;
                }
                ++objectDepth;
            }
            else if (ch == L'}')
            {
                if (objectDepth == 0)
                {
                    return JsonKeyLookup::Invalid;
                }
                --objectDepth;
                if (objectDepth == 0)
                {
                    if (arrayDepth != 0)
                    {
                        return JsonKeyLookup::Invalid;
                    }
                    rootClosed = true;
                }
            }
            else if (ch == L'[')
            {
                if (!rootStarted || objectDepth == 0)
                {
                    return JsonKeyLookup::Invalid;
                }
                ++arrayDepth;
            }
            else if (ch == L']')
            {
                if (arrayDepth == 0)
                {
                    return JsonKeyLookup::Invalid;
                }
                --arrayDepth;
            }
            else if (ch == L'"')
            {
                if (!rootStarted || objectDepth == 0)
                {
                    return JsonKeyLookup::Invalid;
                }
                std::wstring parsed;
                size_t next = 0;
                if (!ParseJsonStringAt(json, index, &parsed, &next))
                {
                    return JsonKeyLookup::Invalid;
                }

                if (objectDepth == 1 && arrayDepth == 0)
                {
                    size_t probe = next;
                    while (probe < json.size() &&
                           iswspace(json[probe]) != 0)
                    {
                        ++probe;
                    }
                    if (probe < json.size() &&
                        json[probe] == L':' &&
                        parsed == key)
                    {
                        if (found)
                        {
                            return JsonKeyLookup::Invalid;
                        }
                        found = true;
                        foundColon = probe;
                    }
                }

                index = next - 1;
            }
            else if (!rootStarted && iswspace(ch) == 0)
            {
                return JsonKeyLookup::Invalid;
            }
        }

        if (!rootStarted ||
            !rootClosed ||
            objectDepth != 0 ||
            arrayDepth != 0)
        {
            return JsonKeyLookup::Invalid;
        }
        if (!found)
        {
            return JsonKeyLookup::Missing;
        }
        if (colon != nullptr)
        {
            *colon = foundColon;
        }
        return JsonKeyLookup::Found;
    }

    bool ExtractJsonStringValue(const std::wstring& json, const std::wstring& key, std::wstring* value)
    {
        bool ok = false;
        size_t colon = 0;

        do
        {
            if (value == nullptr ||
                FindTopLevelJsonKey(json, key, &colon) !=
                    JsonKeyLookup::Found)
            {
                break;
            }

            size_t quote = colon + 1;
            while (quote < json.size() && iswspace(json[quote]) != 0)
            {
                ++quote;
            }
            ok = ParseJsonStringAt(json, quote, value, nullptr);
        } while (false);

        return ok;
    }

    bool ExtractJsonBoolValue(const std::wstring& json, const std::wstring& key, bool* value)
    {
        bool ok = false;
        size_t colon = 0;

        do
        {
            if (value == nullptr ||
                FindTopLevelJsonKey(json, key, &colon) !=
                    JsonKeyLookup::Found)
            {
                break;
            }

            size_t start = colon + 1;
            while (start < json.size() && iswspace(json[start]) != 0)
            {
                ++start;
            }

            auto tokenEndsAt = [&json](size_t end)
            {
                return end >= json.size() ||
                    json[end] == L',' ||
                    json[end] == L'}' ||
                    json[end] == L']' ||
                    iswspace(json[end]) != 0;
            };

            if (json.compare(start, 4, L"true") == 0 &&
                tokenEndsAt(start + 4))
            {
                *value = true;
                ok = true;
            }
            else if (json.compare(start, 5, L"false") == 0 &&
                     tokenEndsAt(start + 5))
            {
                *value = false;
                ok = true;
            }
        } while (false);

        return ok;
    }

    bool ExtractJsonScalarValue(const std::wstring& json, const std::wstring& key, std::wstring* value)
    {
        bool ok = false;
        size_t colon = 0;

        do
        {
            if (value == nullptr ||
                FindTopLevelJsonKey(json, key, &colon) !=
                    JsonKeyLookup::Found)
            {
                break;
            }

            size_t start = colon + 1;
            while (start < json.size() &&
                   iswspace(json[start]) != 0)
            {
                ++start;
            }

            if (start < json.size() && json[start] == L'"')
            {
                ok = ParseJsonStringAt(
                    json,
                    start,
                    value,
                    nullptr);
                break;
            }

            size_t end = start;
            while (end < json.size() &&
                   json[end] != L',' &&
                   json[end] != L'}' &&
                   json[end] != L']' &&
                   iswspace(json[end]) == 0)
            {
                ++end;
            }

            if (end > start)
            {
                *value = json.substr(start, end - start);
                ok = true;
            }
        } while (false);

        return ok;
    }

    std::wstring ExtractJsonObjectValue(const std::wstring& json, const std::wstring& key)
    {
        std::wstring result;
        size_t colon = 0;

        do
        {
            if (FindTopLevelJsonKey(json, key, &colon) !=
                JsonKeyLookup::Found)
            {
                break;
            }

            size_t start = colon + 1;
            while (start < json.size() && iswspace(json[start]) != 0)
            {
                ++start;
            }
            if (start >= json.size() || json[start] != L'{')
            {
                break;
            }

            int depth = 0;
            bool inString = false;
            bool escaped = false;
            for (size_t index = start; index < json.size(); ++index)
            {
                wchar_t ch = json[index];
                if (inString)
                {
                    if (escaped)
                    {
                        escaped = false;
                    }
                    else if (ch == L'\\')
                    {
                        escaped = true;
                    }
                    else if (ch == L'"')
                    {
                        inString = false;
                    }
                    continue;
                }

                if (ch == L'"')
                {
                    inString = true;
                }
                else if (ch == L'{')
                {
                    ++depth;
                }
                else if (ch == L'}')
                {
                    --depth;
                    if (depth == 0)
                    {
                        result = json.substr(start, index - start + 1);
                        break;
                    }
                }
            }
        } while (false);

        return result;
    }

    bool ExtractJsonArrayObjects(
        const std::wstring& json,
        const std::wstring& key,
        std::vector<std::wstring>* objects)
    {
        if (objects == nullptr)
        {
            return false;
        }
        objects->clear();

        size_t colon = 0;
        if (FindTopLevelJsonKey(json, key, &colon) !=
            JsonKeyLookup::Found)
        {
            return false;
        }

        size_t cursor = colon + 1;
        SkipJsonWhitespace(json, &cursor);
        if (cursor >= json.size() ||
            json[cursor] != L'[')
        {
            return false;
        }
        ++cursor;
        SkipJsonWhitespace(json, &cursor);
        if (cursor < json.size() &&
            json[cursor] == L']')
        {
            return true;
        }

        for (;;)
        {
            if (cursor >= json.size() ||
                json[cursor] != L'{')
            {
                return false;
            }

            const size_t objectStart = cursor;
            if (!ParseJsonValueAt(json, &cursor, 0))
            {
                return false;
            }
            objects->push_back(
                json.substr(
                    objectStart,
                    cursor - objectStart));

            SkipJsonWhitespace(json, &cursor);
            if (cursor >= json.size())
            {
                return false;
            }
            if (json[cursor] == L']')
            {
                return true;
            }
            if (json[cursor] != L',')
            {
                return false;
            }
            ++cursor;
            SkipJsonWhitespace(json, &cursor);
        }
    }

    bool ExtractJsonStringArrayValues(
        const std::wstring& json,
        const std::wstring& key,
        std::vector<std::wstring>* values)
    {
        if (values == nullptr)
        {
            return false;
        }
        values->clear();

        size_t colon = 0;
        if (FindTopLevelJsonKey(json, key, &colon) !=
            JsonKeyLookup::Found)
        {
            return false;
        }

        size_t cursor = colon + 1;
        SkipJsonWhitespace(json, &cursor);
        if (cursor >= json.size() ||
            json[cursor] != L'[')
        {
            return false;
        }
        ++cursor;
        SkipJsonWhitespace(json, &cursor);
        if (cursor < json.size() &&
            json[cursor] == L']')
        {
            return true;
        }

        for (;;)
        {
            std::wstring value;
            size_t next = 0;
            if (!ParseJsonStringAt(
                    json,
                    cursor,
                    &value,
                    &next))
            {
                return false;
            }
            values->push_back(value);
            cursor = next;

            SkipJsonWhitespace(json, &cursor);
            if (cursor >= json.size())
            {
                return false;
            }
            if (json[cursor] == L']')
            {
                return true;
            }
            if (json[cursor] != L',')
            {
                return false;
            }
            ++cursor;
            SkipJsonWhitespace(json, &cursor);
        }
    }

    std::vector<std::wstring> ExtractJsonObjectKeys(const std::wstring& json)
    {
        std::vector<std::wstring> keys;
        bool inString = false;
        bool escaped = false;
        int depth = 0;

        for (size_t index = 0; index < json.size(); ++index)
        {
            wchar_t ch = json[index];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (ch == L'\\')
                {
                    escaped = true;
                }
                else if (ch == L'"')
                {
                    inString = false;
                }
                continue;
            }

            if (ch == L'{')
            {
                ++depth;
            }
            else if (ch == L'}')
            {
                --depth;
            }
            else if (ch == L'"' && depth == 1)
            {
                std::wstring key;
                size_t next = 0;
                if (ParseJsonStringAt(json, index, &key, &next))
                {
                    size_t probe = next;
                    while (probe < json.size() && iswspace(json[probe]) != 0)
                    {
                        ++probe;
                    }
                    if (probe < json.size() && json[probe] == L':')
                    {
                        keys.push_back(key);
                    }
                    index = next - 1;
                }
            }
            else if (ch == L'"')
            {
                inString = true;
            }
        }

        return keys;
    }

    bool ParseJsonStringMap(
        const std::wstring& objectText,
        std::map<std::wstring, std::wstring>* result)
    {
        if (result == nullptr ||
            objectText.empty() ||
            !ValidateJsonDocument(objectText))
        {
            return false;
        }
        result->clear();

        std::vector<std::wstring> keys = ExtractJsonObjectKeys(objectText);

        for (const std::wstring& key : keys)
        {
            std::wstring value;
            if (!ExtractJsonStringValue(
                    objectText,
                    key,
                    &value))
            {
                result->clear();
                return false;
            }
            (*result)[key] = value;
        }

        return true;
    }

    bool TryParseUint64Strict(const std::wstring& value, uint64_t* parsed)
    {
        if (parsed == nullptr || value.empty())
        {
            return false;
        }

        *parsed = 0;
        int base = 10;
        size_t index = 0;

        if (value.size() > 2 && value[0] == L'0' && (value[1] == L'x' || value[1] == L'X'))
        {
            base = 16;
            index = 2;
        }
        if (index >= value.size())
        {
            return false;
        }

        for (; index < value.size(); ++index)
        {
            wchar_t ch = value[index];
            uint32_t digit = 0;
            if (ch >= L'0' && ch <= L'9')
            {
                digit = static_cast<uint32_t>(ch - L'0');
            }
            else if (base == 16 && ch >= L'a' && ch <= L'f')
            {
                digit = static_cast<uint32_t>(ch - L'a' + 10);
            }
            else if (base == 16 && ch >= L'A' && ch <= L'F')
            {
                digit = static_cast<uint32_t>(ch - L'A' + 10);
            }
            else
            {
                return false;
            }
            if (*parsed >
                (std::numeric_limits<uint64_t>::max() - digit) /
                    static_cast<uint64_t>(base))
            {
                return false;
            }
            *parsed = (*parsed * static_cast<uint64_t>(base)) + digit;
        }

        return true;
    }

    bool JsonContainsKey(
        const std::wstring& json,
        const std::wstring& key)
    {
        return FindTopLevelJsonKey(json, key, nullptr) !=
            JsonKeyLookup::Missing;
    }

    bool ExtractOptionalJsonBoolStrict(
        const std::wstring& json,
        const std::wstring& key,
        bool* value)
    {
        return !JsonContainsKey(json, key) ||
            ExtractJsonBoolValue(json, key, value);
    }

    bool ExtractOptionalJsonUint64Strict(
        const std::wstring& json,
        const std::wstring& key,
        uint64_t* value,
        bool* present = nullptr)
    {
        if (present != nullptr)
        {
            *present = false;
        }
        if (!JsonContainsKey(json, key))
        {
            return true;
        }

        std::wstring text;
        if (!ExtractJsonScalarValue(json, key, &text) ||
            !TryParseUint64Strict(text, value))
        {
            return false;
        }
        if (present != nullptr)
        {
            *present = true;
        }
        return true;
    }

    bool SnapshotDocumentIdentitiesUnique(
        const SnapshotDocument& document,
        std::wstring* duplicate)
    {
        std::set<uint32_t> processIds;
        std::set<std::wstring> processIdentities;
        for (const SnapshotProcessRecord& process :
             document.Processes)
        {
            if (!processIds.insert(
                    process.ProcessId).second)
            {
                if (duplicate != nullptr)
                {
                    *duplicate =
                        L"process pid " +
                        std::to_wstring(
                            process.ProcessId);
                }
                return false;
            }
            if (!processIdentities.insert(
                    process.Identity).second)
            {
                if (duplicate != nullptr)
                {
                    *duplicate =
                        L"process identity " +
                        process.Identity;
                }
                return false;
            }
        }

        std::set<
            std::pair<
                std::wstring,
                std::wstring>> recordIdentities;
        for (const SnapshotRecord& record :
             document.Records)
        {
            if (!recordIdentities.insert(
                    {record.Domain,
                     record.Identity}).second)
            {
                if (duplicate != nullptr)
                {
                    *duplicate =
                        L"record identity " +
                        record.Domain +
                        L"/" +
                        record.Identity;
                }
                return false;
            }
        }
        return true;
    }
}

std::wstring SnapshotJsonEscape(const std::wstring& value)
{
    std::wstringstream stream;

    for (wchar_t ch : value)
    {
        switch (ch)
        {
        case L'\"':
            stream << L"\\\"";
            break;
        case L'\\':
            stream << L"\\\\";
            break;
        case L'\b':
            stream << L"\\b";
            break;
        case L'\f':
            stream << L"\\f";
            break;
        case L'\n':
            stream << L"\\n";
            break;
        case L'\r':
            stream << L"\\r";
            break;
        case L'\t':
            stream << L"\\t";
            break;
        default:
            if (ch < 0x20)
            {
                stream << L"\\u"
                       << std::hex
                       << std::nouppercase
                       << std::setw(4)
                       << std::setfill(L'0')
                       << static_cast<uint32_t>(ch)
                       << std::dec;
            }
            else
            {
                stream << ch;
            }
            break;
        }
    }

    return stream.str();
}

std::wstring BuildSnapshotJson(const SnapshotDocument& document)
{
    std::wstringstream json;
    json << L"{\n";
    json << L"  \"schema\":\"kn-live-dbg.snapshot.v1\",\n";
    json << L"  \"label\":\"" << SnapshotJsonEscape(document.Label) << L"\",\n";
    json << L"  \"timestamp_utc\":\"" << SnapshotJsonEscape(document.TimestampUtc) << L"\",\n";
    json << L"  \"same_boot_only\":" << (document.SameBootOnly ? L"true" : L"false") << L",\n";
    json << L"  \"boot_id\":\"" << SnapshotJsonEscape(document.BootId) << L"\",\n";
    json << L"  \"json_path\":\"" << SnapshotJsonEscape(document.JsonPath) << L"\",\n";
    json << L"  \"report_path\":\"" << SnapshotJsonEscape(document.ReportPath) << L"\",\n";
    json << L"  \"metadata\":";
    AppendJsonStringMap(json, document.Metadata);
    json << L",\n";

    json << L"  \"domain_warnings\":{";
    bool firstDomain = true;
    for (const auto& item : document.DomainWarnings)
    {
        if (!firstDomain)
        {
            json << L",";
        }
        firstDomain = false;
        json << L"\n    \"" << SnapshotJsonEscape(item.first) << L"\":";
        AppendJsonStringArray(json, item.second);
    }
    if (!document.DomainWarnings.empty())
    {
        json << L"\n  ";
    }
    json << L"},\n";

    json << L"  \"process_inventory\":[\n";
    for (size_t i = 0; i < document.Processes.size(); ++i)
    {
        const SnapshotProcessRecord& process = document.Processes[i];
        json << L"    {\"pid\":" << process.ProcessId
             << L",\"image\":\"" << SnapshotJsonEscape(process.ImageName)
             << L"\",\"identity\":\"" << SnapshotJsonEscape(process.Identity)
             << L"\",\"eprocess\":\"" << SnapshotHex(process.Eprocess, 16)
             << L"\",\"dtb\":\"" << SnapshotHex(process.DirectoryTableBase, 16)
             << L"\",\"user_dtb\":\"" << SnapshotHex(process.UserDirectoryTableBase, 16)
             << L"\",\"peb\":\"" << SnapshotHex(process.Peb, 16)
             << L"\",\"has_peb\":" << (process.HasPeb ? L"true" : L"false")
             << L",\"has_create_time\":" << (process.HasCreateTime ? L"true" : L"false")
             << L",\"create_time\":\"" << SnapshotHex(process.CreateTime, 16)
             << L"\",\"has_exit_time\":" << (process.HasExitTime ? L"true" : L"false")
             << L",\"exit_time\":\"" << SnapshotHex(process.ExitTime, 16)
             << L"\",\"has_active_threads\":" << (process.HasActiveThreads ? L"true" : L"false")
             << L",\"active_threads\":" << process.ActiveThreads
             << L"}";
        if (i + 1 != document.Processes.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ],\n";

    json << L"  \"records\":[\n";
    for (size_t i = 0; i < document.Records.size(); ++i)
    {
        const SnapshotRecord& record = document.Records[i];
        json << L"    {\"domain\":\"" << SnapshotJsonEscape(record.Domain)
             << L"\",\"identity\":\"" << SnapshotJsonEscape(record.Identity)
             << L"\",\"display\":\"" << SnapshotJsonEscape(record.Display)
             << L"\",\"risk\":\"" << SnapshotJsonEscape(record.Risk)
             << L"\",\"volatile\":" << (record.Volatile ? L"true" : L"false")
             << L",\"tags\":";
        AppendJsonStringArray(json, record.Tags);
        json << L",\"evidence\":";
        AppendJsonStringMap(json, record.Evidence);
        json << L"}";
        if (i + 1 != document.Records.size())
        {
            json << L",";
        }
        json << L"\n";
    }
    json << L"  ]\n";
    json << L"}\n";
    return json.str();
}

bool EnsureSnapshotDirectoryForFile(const std::wstring& path, std::wstring* error)
{
    return EnsureDirectoryTree(DirectoryFromPath(path), error);
}

bool WriteSnapshotTextFile(const std::wstring& path, const std::wstring& text, std::wstring* error)
{
    bool ok = false;
    std::string utf8;

    if (error != nullptr)
    {
        error->clear();
    }

    do
    {
        // Validate and convert before opening the destination.  Opening with
        // truncation first would destroy an existing snapshot when conversion
        // later rejects malformed UTF-16.
        if (!WideToUtf8(text, &utf8))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot text contains invalid UTF-16: " +
                    path;
            }
            break;
        }

        if (!EnsureSnapshotDirectoryForFile(path, error))
        {
            break;
        }

        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.good())
        {
            if (error != nullptr)
            {
                *error = L"failed to open file for write: " + path;
            }
            break;
        }

        file.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
        ok = file.good();
        if (!ok && error != nullptr)
        {
            *error = L"failed to write file: " + path;
        }
    } while (false);

    return ok;
}

bool ReadSnapshotTextFile(const std::wstring& path, std::wstring* text, std::wstring* error)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    if (error != nullptr)
    {
        error->clear();
    }
    if (text != nullptr)
    {
        text->clear();
    }

    do
    {
        if (text == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid output buffer";
            }
            break;
        }

        file = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error =
                    L"failed to open file: " +
                    path +
                    L" gle=" +
                    std::to_wstring(GetLastError());
            }
            break;
        }

        LARGE_INTEGER fileSize = {};
        if (!GetFileSizeEx(file, &fileSize) ||
            fileSize.QuadPart < 0)
        {
            if (error != nullptr)
            {
                *error =
                    L"failed to query snapshot file size: " +
                    path;
            }
            break;
        }
        if (static_cast<uint64_t>(fileSize.QuadPart) >
            kMaxSnapshotTextFileBytes)
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot file exceeds the 64 MiB safety limit: " +
                    path;
            }
            break;
        }

        std::string utf8(
            static_cast<size_t>(fileSize.QuadPart),
            '\0');
        size_t offset = 0;
        while (offset < utf8.size())
        {
            const DWORD requested = static_cast<DWORD>(
                std::min<size_t>(
                    utf8.size() - offset,
                    std::numeric_limits<DWORD>::max()));
            DWORD bytesRead = 0;
            if (!ReadFile(
                    file,
                    utf8.data() + offset,
                    requested,
                    &bytesRead,
                    nullptr) ||
                bytesRead == 0)
            {
                if (error != nullptr)
                {
                    *error =
                        L"failed to read complete snapshot file: " +
                        path;
                }
                break;
            }
            offset += bytesRead;
        }
        if (offset != utf8.size())
        {
            break;
        }

        if (!Utf8ToWide(utf8, text))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot file contains invalid UTF-8: " +
                    path;
            }
            break;
        }
        ok = true;
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    if (!ok && text != nullptr)
    {
        text->clear();
    }
    return ok;
}

bool WriteSnapshotJsonFile(const std::wstring& path, const SnapshotDocument& document, std::wstring* error)
{
    return WriteSnapshotTextFile(path, BuildSnapshotJson(document), error);
}

bool ReadSnapshotJsonFile(const std::wstring& path, SnapshotDocument* document, std::wstring* error)
{
    bool ok = false;
    std::wstring json;

    if (error != nullptr)
    {
        error->clear();
    }
    if (document != nullptr)
    {
        *document = SnapshotDocument{};
    }

    do
    {
        if (document == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid snapshot output buffer";
            }
            break;
        }

        if (!ReadSnapshotTextFile(path, &json, error))
        {
            break;
        }
        if (!ValidateJsonDocument(json))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot is not a valid duplicate-free JSON object: " +
                    path;
            }
            break;
        }

        document->JsonPath = path;
        if (!ExtractJsonStringValue(json, L"schema", &document->Schema) ||
            document->Schema != L"kn-live-dbg.snapshot.v1")
        {
            if (error != nullptr)
            {
                *error = L"unsupported or missing snapshot schema: " + path;
            }
            break;
        }
        if (!ExtractJsonStringValue(
                json,
                L"label",
                &document->Label) ||
            !ExtractJsonStringValue(
                json,
                L"timestamp_utc",
                &document->TimestampUtc) ||
            !ExtractJsonStringValue(
                json,
                L"boot_id",
                &document->BootId) ||
            !ExtractJsonStringValue(
                json,
                L"report_path",
                &document->ReportPath))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot contains a missing or non-string root field";
            }
            break;
        }
        if (!ExtractJsonBoolValue(
                json,
                L"same_boot_only",
                &document->SameBootOnly))
        {
            if (error != nullptr)
            {
                *error = L"snapshot same_boot_only is not a valid JSON boolean";
            }
            break;
        }

        const std::wstring metadataObject =
            ExtractJsonObjectValue(json, L"metadata");
        if (!ParseJsonStringMap(
                metadataObject,
                &document->Metadata))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot metadata must be an object of string values";
            }
            break;
        }

        std::wstring warningObject = ExtractJsonObjectValue(json, L"domain_warnings");
        if (warningObject.empty())
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot domain_warnings must be an object";
            }
            break;
        }
        bool domainWarningsValid = true;
        for (const std::wstring& key : ExtractJsonObjectKeys(warningObject))
        {
            std::vector<std::wstring> warnings;
            if (!ExtractJsonStringArrayValues(
                    warningObject,
                    key,
                    &warnings))
            {
                if (error != nullptr)
                {
                    *error =
                        L"snapshot domain warning values must be string arrays";
                }
                domainWarningsValid = false;
                break;
            }
            document->DomainWarnings[key] =
                std::move(warnings);
        }
        if (!domainWarningsValid)
        {
            break;
        }

        std::vector<std::wstring> processObjects;
        if (!ExtractJsonArrayObjects(
                json,
                L"process_inventory",
                &processObjects))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot process_inventory must be an array of objects";
            }
            break;
        }
        bool processInventoryValid = true;
        for (const std::wstring& object : processObjects)
        {
            SnapshotProcessRecord process = {};
            uint64_t parsed = 0;
            bool present = false;
            bool pebPresent = false;
            bool createTimePresent = false;
            bool exitTimePresent = false;
            if (!ExtractOptionalJsonUint64Strict(
                    object,
                    L"pid",
                    &parsed,
                    &present) ||
                !present ||
                parsed > std::numeric_limits<uint32_t>::max())
            {
                if (error != nullptr)
                {
                    *error = L"snapshot process pid is not a valid uint32";
                }
                processInventoryValid = false;
                break;
            }
            process.ProcessId =
                static_cast<uint32_t>(parsed);
            if (!ExtractJsonStringValue(
                    object,
                    L"image",
                    &process.ImageName) ||
                !ExtractJsonStringValue(
                    object,
                    L"identity",
                    &process.Identity) ||
                process.Identity.empty())
            {
                if (error != nullptr)
                {
                    *error =
                        L"snapshot process image/identity is missing or invalid";
                }
                processInventoryValid = false;
                break;
            }
            if (!ExtractOptionalJsonUint64Strict(
                    object,
                    L"eprocess",
                    &process.Eprocess) ||
                !ExtractOptionalJsonUint64Strict(
                    object,
                    L"dtb",
                    &process.DirectoryTableBase) ||
                !ExtractOptionalJsonUint64Strict(
                    object,
                    L"user_dtb",
                    &process.UserDirectoryTableBase) ||
                !ExtractOptionalJsonUint64Strict(
                    object,
                    L"peb",
                    &process.Peb,
                    &pebPresent) ||
                !ExtractOptionalJsonUint64Strict(
                    object,
                    L"create_time",
                    &process.CreateTime,
                    &createTimePresent) ||
                !ExtractOptionalJsonUint64Strict(
                    object,
                    L"exit_time",
                    &process.ExitTime,
                    &exitTimePresent))
            {
                if (error != nullptr)
                {
                    *error = L"snapshot process contains an invalid uint64 field";
                }
                processInventoryValid = false;
                break;
            }
            process.HasPeb = process.Peb != 0;
            if (!ExtractOptionalJsonBoolStrict(
                    object,
                    L"has_peb",
                    &process.HasPeb) ||
                (process.Peb != 0 && !process.HasPeb) ||
                !ExtractOptionalJsonBoolStrict(
                    object,
                    L"has_create_time",
                    &process.HasCreateTime) ||
                !ExtractOptionalJsonBoolStrict(
                    object,
                    L"has_exit_time",
                    &process.HasExitTime) ||
                !ExtractOptionalJsonBoolStrict(
                    object,
                    L"has_active_threads",
                    &process.HasActiveThreads) ||
                (process.HasPeb && !pebPresent) ||
                (process.HasCreateTime &&
                 (!createTimePresent ||
                  process.CreateTime == 0)) ||
                (process.HasExitTime &&
                 !exitTimePresent) ||
                (process.CreateTime != 0 &&
                 !process.HasCreateTime) ||
                (process.ExitTime != 0 &&
                 !process.HasExitTime))
            {
                if (error != nullptr)
                {
                    *error = L"snapshot process contains an invalid boolean field";
                }
                processInventoryValid = false;
                break;
            }
            parsed = 0;
            present = false;
            if (!ExtractOptionalJsonUint64Strict(
                    object,
                    L"active_threads",
                    &parsed,
                    &present) ||
                (present &&
                 parsed > std::numeric_limits<uint32_t>::max()))
            {
                if (error != nullptr)
                {
                    *error = L"snapshot process active_threads is not a valid uint32";
                }
                processInventoryValid = false;
                break;
            }
            if (present)
            {
                process.ActiveThreads = static_cast<uint32_t>(parsed);
            }
            if (present &&
                !process.HasActiveThreads &&
                process.ActiveThreads != 0)
            {
                if (error != nullptr)
                {
                    *error =
                        L"snapshot process active_threads conflicts with has_active_threads";
                }
                processInventoryValid = false;
                break;
            }
            if (process.HasActiveThreads &&
                !present)
            {
                if (error != nullptr)
                {
                    *error =
                        L"snapshot process has_active_threads requires active_threads";
                }
                processInventoryValid = false;
                break;
            }
            document->Processes.push_back(process);
        }
        if (!processInventoryValid)
        {
            break;
        }

        std::vector<std::wstring> recordObjects;
        if (!ExtractJsonArrayObjects(
                json,
                L"records",
                &recordObjects))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot records must be an array of objects";
            }
            break;
        }
        for (const std::wstring& object : recordObjects)
        {
            SnapshotRecord record;
            if (!ExtractJsonStringValue(
                    object,
                    L"domain",
                    &record.Domain) ||
                !ExtractJsonStringValue(
                    object,
                    L"identity",
                    &record.Identity) ||
                !ExtractJsonStringValue(
                    object,
                    L"display",
                    &record.Display) ||
                !ExtractJsonStringValue(
                    object,
                    L"risk",
                    &record.Risk) ||
                record.Domain.empty() ||
                record.Identity.empty())
            {
                if (error != nullptr)
                {
                    *error =
                        L"snapshot record contains a missing or invalid string field";
                }
                processInventoryValid = false;
                break;
            }

            const std::wstring normalizedRisk =
                SnapshotRiskNormalize(record.Risk);
            if (normalizedRisk != SnapshotToLower(record.Risk))
            {
                if (error != nullptr)
                {
                    *error =
                        L"snapshot record risk is not high, medium, low, or info";
                }
                processInventoryValid = false;
                break;
            }
            record.Risk = normalizedRisk;
            if (!ExtractJsonBoolValue(
                    object,
                    L"volatile",
                    &record.Volatile))
            {
                if (error != nullptr)
                {
                    *error = L"snapshot record volatile is not a valid JSON boolean";
                }
                processInventoryValid = false;
                break;
            }
            if (!ExtractJsonStringArrayValues(
                    object,
                    L"tags",
                    &record.Tags) ||
                !ParseJsonStringMap(
                    ExtractJsonObjectValue(
                        object,
                        L"evidence"),
                    &record.Evidence))
            {
                if (error != nullptr)
                {
                    *error =
                        L"snapshot record tags/evidence has an invalid type";
                }
                processInventoryValid = false;
                break;
            }
            document->Records.push_back(record);
        }
        if (!processInventoryValid)
        {
            break;
        }

        std::wstring duplicateIdentity;
        if (!SnapshotDocumentIdentitiesUnique(
                *document,
                &duplicateIdentity))
        {
            if (error != nullptr)
            {
                *error =
                    L"snapshot contains duplicate " +
                    duplicateIdentity;
            }
            break;
        }

        ok = true;
    } while (false);

    if (!ok && document != nullptr)
    {
        *document = SnapshotDocument{};
    }
    return ok;
}

bool SnapshotJsonStrictParsingSelfTest()
{
    std::string utf8;
    std::wstring wide;
    const std::wstring invalidUtf16(
        1,
        static_cast<wchar_t>(0xd800));
    const std::string invalidUtf8(
        "\xc0\xaf",
        2);
    if (!WideToUtf8(L"", &utf8) ||
        !utf8.empty() ||
        !Utf8ToWide("", &wide) ||
        !wide.empty() ||
        WideToUtf8(invalidUtf16, &utf8) ||
        Utf8ToWide(invalidUtf8, &wide))
    {
        return false;
    }

    wchar_t tempDirectory[MAX_PATH + 1] = {};
    wchar_t tempPath[MAX_PATH + 1] = {};
    const DWORD tempLength = GetTempPathW(
        static_cast<DWORD>(_countof(tempDirectory)),
        tempDirectory);
    if (tempLength == 0 ||
        tempLength >= _countof(tempDirectory) ||
        GetTempFileNameW(
            tempDirectory,
            L"ksj",
            0,
            tempPath) == 0)
    {
        return false;
    }

    bool fileSafetyOk = false;
    do
    {
        std::wstring fileError;
        const std::wstring sentinel = L"preserve-existing-snapshot";
        if (!WriteSnapshotTextFile(
                tempPath,
                sentinel,
                &fileError))
        {
            break;
        }
        if (WriteSnapshotTextFile(
                tempPath,
                invalidUtf16,
                &fileError))
        {
            break;
        }

        std::wstring preserved;
        if (!ReadSnapshotTextFile(
                tempPath,
                &preserved,
                &fileError) ||
            preserved != sentinel)
        {
            break;
        }

        if (!WriteSnapshotTextFile(
                tempPath,
                L"{\"schema\":",
                &fileError))
        {
            break;
        }
        SnapshotDocument failedDocument = {};
        failedDocument.Schema = L"must-be-cleared";
        failedDocument.JsonPath = L"must-be-cleared";
        failedDocument.Records.push_back(SnapshotRecord{});
        if (ReadSnapshotJsonFile(
                tempPath,
                &failedDocument,
                &fileError) ||
            !failedDocument.Schema.empty() ||
            !failedDocument.JsonPath.empty() ||
            !failedDocument.Records.empty())
        {
            break;
        }

        SnapshotDocument requiredFieldDocument = {};
        requiredFieldDocument.Label = L"selftest";
        requiredFieldDocument.TimestampUtc =
            L"2026-01-01T00:00:00Z";
        requiredFieldDocument.BootId = L"selftest-boot";
        SnapshotProcessRecord requiredFieldProcess = {};
        requiredFieldProcess.ProcessId = 1;
        requiredFieldProcess.Identity = L"pid:1";
        requiredFieldProcess.HasActiveThreads = true;
        requiredFieldProcess.ActiveThreads = 0;
        requiredFieldDocument.Processes.push_back(
            requiredFieldProcess);
        std::wstring missingActiveThreads =
            BuildSnapshotJson(requiredFieldDocument);
        const std::wstring activeThreadsField =
            L",\"active_threads\":0";
        const size_t activeThreadsOffset =
            missingActiveThreads.find(
                activeThreadsField);
        if (activeThreadsOffset ==
            std::wstring::npos)
        {
            break;
        }
        missingActiveThreads.erase(
            activeThreadsOffset,
            activeThreadsField.size());
        if (!WriteSnapshotTextFile(
                tempPath,
                missingActiveThreads,
                &fileError))
        {
            break;
        }
        SnapshotDocument missingRequiredField = {};
        if (ReadSnapshotJsonFile(
                tempPath,
                &missingRequiredField,
                &fileError))
        {
            break;
        }

        fileSafetyOk = true;
    } while (false);
    DeleteFileW(tempPath);
    if (!fileSafetyOk)
    {
        return false;
    }

    uint64_t value = 0;
    if (!TryParseUint64Strict(
            L"18446744073709551615",
            &value) ||
        value != std::numeric_limits<uint64_t>::max() ||
        !TryParseUint64Strict(L"0xffffffffffffffff", &value) ||
        value != std::numeric_limits<uint64_t>::max())
    {
        return false;
    }

    const std::wstring invalidNumbers[] =
    {
        L"",
        L"0x",
        L"-1",
        L"+1",
        L"1junk",
        L"18446744073709551616",
        L"0x10000000000000000"
    };
    for (const std::wstring& invalid : invalidNumbers)
    {
        if (TryParseUint64Strict(invalid, &value))
        {
            return false;
        }
    }

    bool flag = false;
    if (!ExtractJsonBoolValue(
            L"{\"flag\": true}",
            L"flag",
            &flag) ||
        !flag ||
        ExtractJsonBoolValue(
            L"{\"flag\": truejunk}",
            L"flag",
            &flag) ||
        ExtractJsonBoolValue(
            L"{\"flag\":true,\"flag\":false}",
            L"flag",
            &flag) ||
        ExtractJsonBoolValue(
            L"{\"flag\":true} trailing",
            L"flag",
            &flag) ||
        ExtractOptionalJsonBoolStrict(
            L"{\"flag\":true,\"flag\":false}",
            L"flag",
            &flag) ||
        ExtractOptionalJsonUint64Strict(
            L"{\"eprocess\":\"0x12junk\"}",
            L"eprocess",
            &value))
    {
        return false;
    }

    flag = false;
    if (!ExtractOptionalJsonBoolStrict(
            L"{\"image\":\"has_exit_time\"}",
            L"has_exit_time",
            &flag) ||
        flag ||
        !ExtractJsonBoolValue(
            L"{\"metadata\":{\"flag\":false},\"flag\":true}",
            L"flag",
            &flag) ||
        !flag)
    {
        return false;
    }

    flag = false;
    if (!ExtractOptionalJsonBoolStrict(
            L"{\"has_peb\":true,\"peb\":\"0x0\"}",
            L"has_peb",
            &flag) ||
        !flag)
    {
        return false;
    }

    const std::wstring validDocument =
        L"{\"objects\":[{\"id\":1},{\"id\":2}],"
        L"\"strings\":[\"a\",\"b\"],"
        L"\"map\":{\"key\":\"value\"}}";
    const std::wstring invalidDocuments[] =
    {
        L"{\"a\":1 \"b\":2}",
        L"{\"a\":1,}",
        L"{\"a\":[1,]}",
        L"{\"a\":{\"b\":1,\"b\":2}}",
        L"{\"a\":\"\\q\"}",
        L"{\"a\":\"\\ud800\"}",
        L"{\"a\":\"\\ud800\\u0041\"}",
        L"{\"a\":\"\\udc00\"}",
        std::wstring(L"{\"a\":\"") +
            static_cast<wchar_t>(1) +
            L"\"}",
        L"{\"a\":01}",
        L"{\"a\":1e}"
    };
    if (!ValidateJsonDocument(validDocument) ||
        !ValidateJsonDocument(
            L"{\"a\":\"\\ud83d\\ude00\"}"))
    {
        return false;
    }
    for (const std::wstring& invalid : invalidDocuments)
    {
        if (ValidateJsonDocument(invalid))
        {
            return false;
        }
    }

    std::vector<std::wstring> objects;
    std::vector<std::wstring> strings;
    std::map<std::wstring, std::wstring> stringMap;
    if (!ExtractJsonArrayObjects(
            validDocument,
            L"objects",
            &objects) ||
        objects.size() != 2 ||
        ExtractJsonArrayObjects(
            L"{\"objects\":[{\"id\":1},2]}",
            L"objects",
            &objects) ||
        !ExtractJsonStringArrayValues(
            validDocument,
            L"strings",
            &strings) ||
        strings.size() != 2 ||
        ExtractJsonStringArrayValues(
            L"{\"strings\":[\"a\",1]}",
            L"strings",
            &strings) ||
        !ParseJsonStringMap(
            L"{\"key\":\"value\"}",
            &stringMap) ||
        stringMap[L"key"] != L"value" ||
        ParseJsonStringMap(
            L"{\"key\":1}",
            &stringMap))
    {
        return false;
    }

    SnapshotDocument duplicateProcessId = {};
    SnapshotProcessRecord firstProcess = {};
    firstProcess.ProcessId = 10;
    firstProcess.Identity = L"process-a";
    SnapshotProcessRecord secondProcess = {};
    secondProcess.ProcessId = 10;
    secondProcess.Identity = L"process-b";
    duplicateProcessId.Processes =
        {firstProcess, secondProcess};
    std::wstring duplicate;
    if (SnapshotDocumentIdentitiesUnique(
            duplicateProcessId,
            &duplicate))
    {
        return false;
    }

    SnapshotDocument duplicateRecord = {};
    SnapshotRecord firstRecord = {};
    firstRecord.Domain = L"drivers";
    firstRecord.Identity = L"duplicate";
    duplicateRecord.Records =
        {firstRecord, firstRecord};
    if (SnapshotDocumentIdentitiesUnique(
            duplicateRecord,
            &duplicate))
    {
        return false;
    }

    return ExtractOptionalJsonUint64Strict(
            L"{\"eprocess\":\"0x1234\"}",
            L"eprocess",
            &value) &&
        value == 0x1234;
}
