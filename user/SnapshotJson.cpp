#include "SnapshotJson.h"

#include <Windows.h>

#include <fstream>
#include <iomanip>
#include <sstream>

namespace
{
    std::string WideToUtf8(const std::wstring& value)
    {
        std::string result;

        do
        {
            if (value.empty())
            {
                break;
            }

            int required = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (required <= 0)
            {
                break;
            }

            result.resize(required);
            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                &result[0],
                required,
                nullptr,
                nullptr);
        } while (false);

        return result;
    }

    std::wstring Utf8ToWide(const std::string& value)
    {
        std::wstring result;

        do
        {
            if (value.empty())
            {
                break;
            }

            int required = MultiByteToWideChar(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                nullptr,
                0);
            if (required <= 0)
            {
                break;
            }

            result.resize(required);
            MultiByteToWideChar(
                CP_UTF8,
                0,
                value.data(),
                static_cast<int>(value.size()),
                &result[0],
                required);
        } while (false);

        return result;
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
                if (ch == L'\\' && index + 1 < text.size())
                {
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
                    else if (esc == L'u' && index + 4 < text.size())
                    {
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

                        if (valid)
                        {
                            parsed.push_back(static_cast<wchar_t>(codepoint));
                            index += 4;
                        }
                        else
                        {
                            parsed.push_back(esc);
                        }
                    }
                    else
                    {
                        parsed.push_back(esc);
                    }
                }
                else
                {
                    parsed.push_back(ch);
                }
            }
        } while (false);

        return ok;
    }

    bool ExtractJsonStringValue(const std::wstring& json, const std::wstring& key, std::wstring* value)
    {
        bool ok = false;
        std::wstring pattern = L"\"" + key + L"\"";
        size_t pos = json.find(pattern);

        do
        {
            if (value == nullptr || pos == std::wstring::npos)
            {
                break;
            }

            size_t colon = json.find(L':', pos + pattern.size());
            if (colon == std::wstring::npos)
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
        std::wstring pattern = L"\"" + key + L"\"";
        size_t pos = json.find(pattern);

        do
        {
            if (value == nullptr || pos == std::wstring::npos)
            {
                break;
            }

            size_t colon = json.find(L':', pos + pattern.size());
            if (colon == std::wstring::npos)
            {
                break;
            }

            size_t start = colon + 1;
            while (start < json.size() && iswspace(json[start]) != 0)
            {
                ++start;
            }

            if (json.compare(start, 4, L"true") == 0)
            {
                *value = true;
                ok = true;
            }
            else if (json.compare(start, 5, L"false") == 0)
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
        std::wstring pattern = L"\"" + key + L"\"";
        size_t pos = json.find(pattern);

        do
        {
            if (value == nullptr || pos == std::wstring::npos)
            {
                break;
            }

            if (ExtractJsonStringValue(json, key, value))
            {
                ok = true;
                break;
            }

            size_t colon = json.find(L':', pos + pattern.size());
            if (colon == std::wstring::npos)
            {
                break;
            }

            size_t start = colon + 1;
            while (start < json.size() && iswspace(json[start]) != 0)
            {
                ++start;
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
        std::wstring pattern = L"\"" + key + L"\"";
        size_t pos = json.find(pattern);

        do
        {
            if (pos == std::wstring::npos)
            {
                break;
            }

            size_t colon = json.find(L':', pos + pattern.size());
            if (colon == std::wstring::npos)
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

    std::vector<std::wstring> ExtractJsonArrayObjects(const std::wstring& json, const std::wstring& key)
    {
        std::vector<std::wstring> objects;
        std::wstring pattern = L"\"" + key + L"\"";
        size_t pos = json.find(pattern);

        do
        {
            if (pos == std::wstring::npos)
            {
                break;
            }

            size_t bracket = json.find(L'[', pos + pattern.size());
            if (bracket == std::wstring::npos)
            {
                break;
            }

            int arrayDepth = 0;
            int objectDepth = 0;
            bool inString = false;
            bool escaped = false;
            size_t objectStart = std::wstring::npos;

            for (size_t index = bracket; index < json.size(); ++index)
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
                else if (ch == L'[')
                {
                    ++arrayDepth;
                }
                else if (ch == L']')
                {
                    --arrayDepth;
                    if (arrayDepth == 0)
                    {
                        break;
                    }
                }
                else if (ch == L'{')
                {
                    if (objectDepth == 0)
                    {
                        objectStart = index;
                    }
                    ++objectDepth;
                }
                else if (ch == L'}')
                {
                    --objectDepth;
                    if (objectDepth == 0 && objectStart != std::wstring::npos)
                    {
                        objects.push_back(json.substr(objectStart, index - objectStart + 1));
                        objectStart = std::wstring::npos;
                    }
                }
            }
        } while (false);

        return objects;
    }

    std::vector<std::wstring> ExtractJsonStringArrayValues(const std::wstring& json, const std::wstring& key)
    {
        std::vector<std::wstring> values;
        std::wstring pattern = L"\"" + key + L"\"";
        size_t pos = json.find(pattern);

        do
        {
            if (pos == std::wstring::npos)
            {
                break;
            }

            size_t bracket = json.find(L'[', pos + pattern.size());
            if (bracket == std::wstring::npos)
            {
                break;
            }

            bool inString = false;
            bool escaped = false;
            int depth = 0;
            for (size_t index = bracket; index < json.size(); ++index)
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

                if (ch == L'[')
                {
                    ++depth;
                }
                else if (ch == L']')
                {
                    --depth;
                    if (depth == 0)
                    {
                        break;
                    }
                }
                else if (ch == L'"')
                {
                    std::wstring value;
                    size_t next = 0;
                    if (ParseJsonStringAt(json, index, &value, &next))
                    {
                        values.push_back(value);
                        index = next - 1;
                    }
                }
            }
        } while (false);

        return values;
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

    std::map<std::wstring, std::wstring> ParseJsonStringMap(const std::wstring& objectText)
    {
        std::map<std::wstring, std::wstring> result;
        std::vector<std::wstring> keys = ExtractJsonObjectKeys(objectText);

        for (const std::wstring& key : keys)
        {
            std::wstring value;
            if (ExtractJsonScalarValue(objectText, key, &value))
            {
                result[key] = value;
            }
        }

        return result;
    }

    uint64_t ParseUint64Loose(const std::wstring& value)
    {
        uint64_t parsed = 0;
        int base = 10;
        size_t index = 0;

        if (value.size() > 2 && value[0] == L'0' && (value[1] == L'x' || value[1] == L'X'))
        {
            base = 16;
            index = 2;
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
                break;
            }
            parsed = (parsed * static_cast<uint64_t>(base)) + digit;
        }

        return parsed;
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
             << L"\",\"has_create_time\":" << (process.HasCreateTime ? L"true" : L"false")
             << L",\"create_time\":\"" << SnapshotHex(process.CreateTime, 16)
             << L"\"}";
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

    do
    {
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

        std::string utf8 = WideToUtf8(text);
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

        std::ifstream file(path, std::ios::binary);
        if (!file.good())
        {
            if (error != nullptr)
            {
                *error = L"failed to open file: " + path;
            }
            break;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        *text = Utf8ToWide(buffer.str());
        ok = true;
    } while (false);

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

        *document = SnapshotDocument{};
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
        ExtractJsonStringValue(json, L"label", &document->Label);
        ExtractJsonStringValue(json, L"timestamp_utc", &document->TimestampUtc);
        ExtractJsonStringValue(json, L"boot_id", &document->BootId);
        ExtractJsonStringValue(json, L"report_path", &document->ReportPath);
        ExtractJsonBoolValue(json, L"same_boot_only", &document->SameBootOnly);
        document->Metadata = ParseJsonStringMap(ExtractJsonObjectValue(json, L"metadata"));
        std::wstring warningObject = ExtractJsonObjectValue(json, L"domain_warnings");
        for (const std::wstring& key : ExtractJsonObjectKeys(warningObject))
        {
            document->DomainWarnings[key] = ExtractJsonStringArrayValues(warningObject, key);
        }

        std::vector<std::wstring> processObjects = ExtractJsonArrayObjects(json, L"process_inventory");
        for (const std::wstring& object : processObjects)
        {
            SnapshotProcessRecord process = {};
            std::wstring value;
            if (ExtractJsonScalarValue(object, L"pid", &value))
            {
                process.ProcessId = static_cast<uint32_t>(ParseUint64Loose(value));
            }
            ExtractJsonStringValue(object, L"image", &process.ImageName);
            ExtractJsonStringValue(object, L"identity", &process.Identity);
            if (ExtractJsonScalarValue(object, L"eprocess", &value))
            {
                process.Eprocess = ParseUint64Loose(value);
            }
            if (ExtractJsonScalarValue(object, L"dtb", &value))
            {
                process.DirectoryTableBase = ParseUint64Loose(value);
            }
            if (ExtractJsonScalarValue(object, L"user_dtb", &value))
            {
                process.UserDirectoryTableBase = ParseUint64Loose(value);
            }
            if (ExtractJsonScalarValue(object, L"peb", &value))
            {
                process.Peb = ParseUint64Loose(value);
                process.HasPeb = process.Peb != 0;
            }
            ExtractJsonBoolValue(object, L"has_create_time", &process.HasCreateTime);
            if (ExtractJsonScalarValue(object, L"create_time", &value))
            {
                process.CreateTime = ParseUint64Loose(value);
            }
            document->Processes.push_back(process);
        }

        std::vector<std::wstring> recordObjects = ExtractJsonArrayObjects(json, L"records");
        for (const std::wstring& object : recordObjects)
        {
            SnapshotRecord record;
            ExtractJsonStringValue(object, L"domain", &record.Domain);
            ExtractJsonStringValue(object, L"identity", &record.Identity);
            ExtractJsonStringValue(object, L"display", &record.Display);
            ExtractJsonStringValue(object, L"risk", &record.Risk);
            ExtractJsonBoolValue(object, L"volatile", &record.Volatile);
            record.Tags = ExtractJsonStringArrayValues(object, L"tags");
            record.Evidence = ParseJsonStringMap(ExtractJsonObjectValue(object, L"evidence"));
            if (!record.Domain.empty() && !record.Identity.empty())
            {
                document->Records.push_back(record);
            }
        }

        ok = true;
    } while (false);

    return ok;
}
