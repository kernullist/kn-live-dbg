#include "AiProvider.h"
#include "AiModelCatalog.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cwchar>
#include <iomanip>
#include <sstream>
#include <string>

static const wchar_t* kDefaultCodexBaseUrl = L"https://chatgpt.com/backend-api/codex";
static const wchar_t* kDefaultDeepSeekBaseUrl = L"https://api.deepseek.com";
static const wchar_t* kDefaultOpenRouterBaseUrl = L"https://openrouter.ai/api/v1";
static const wchar_t* kCodexOAuthTokenUrl = L"https://auth.openai.com/oauth/token";
static const wchar_t* kCodexOAuthClientId = L"app_EMoamEEZ73f0CkXaXp7hrann";

static std::wstring Trim(const std::wstring& value)
{
    size_t begin = 0;
    size_t end = value.size();

    while (begin < end && iswspace(value[begin]) != 0)
    {
        ++begin;
    }

    while (end > begin && iswspace(value[end - 1]) != 0)
    {
        --end;
    }

    return value.substr(begin, end - begin);
}

static std::wstring ToLowerString(const std::wstring& value)
{
    std::wstring result = value;

    for (wchar_t& ch : result)
    {
        ch = static_cast<wchar_t>(towlower(ch));
    }

    return result;
}

static bool NormalizeRemotePolicyName(const std::wstring& value, AiRemotePolicy* policy, std::wstring* normalized)
{
    bool ok = false;
    std::wstring text = ToLowerString(Trim(value));

    do
    {
        if (policy == nullptr)
        {
            break;
        }

        if (text.empty() || text == L"allow" || text == L"allow-remote" || text == L"remote" || text == L"online")
        {
            *policy = AiRemotePolicy::AllowRemote;
            if (normalized != nullptr)
            {
                *normalized = L"allow-remote";
            }
            ok = true;
        }
        else if (text == L"local" || text == L"local-only" || text == L"offline" || text == L"block-remote")
        {
            *policy = AiRemotePolicy::LocalOnly;
            if (normalized != nullptr)
            {
                *normalized = L"local-only";
            }
            ok = true;
        }
    } while (false);

    return ok;
}

static bool IsRemoteNetworkProvider(AiProviderKind provider)
{
    bool remote = false;

    if (provider == AiProviderKind::OpenAICodex ||
        provider == AiProviderKind::DeepSeek ||
        provider == AiProviderKind::OpenRouter)
    {
        remote = true;
    }

    return remote;
}

static std::wstring GetEnvString(const wchar_t* name)
{
    std::wstring value;
    DWORD required = GetEnvironmentVariableW(name, nullptr, 0);

    do
    {
        if (required == 0)
        {
            break;
        }

        std::wstring buffer(required, L'\0');
        DWORD written = GetEnvironmentVariableW(name, &buffer[0], required);
        if (written == 0 || written >= required)
        {
            break;
        }

        buffer.resize(written);
        value = Trim(buffer);
    } while (false);

    return value;
}

static std::wstring ExpandEnvironment(const std::wstring& value)
{
    std::wstring expanded = value;
    DWORD required = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);

    do
    {
        if (required == 0)
        {
            break;
        }

        std::wstring buffer(required, L'\0');
        DWORD written = ExpandEnvironmentStringsW(value.c_str(), &buffer[0], required);
        if (written == 0 || written > required)
        {
            break;
        }

        if (written > 0)
        {
            buffer.resize(written - 1);
            expanded = buffer;
        }
    } while (false);

    return expanded;
}

static std::wstring JoinPath(const std::wstring& left, const std::wstring& right)
{
    std::wstring result = left;

    if (!result.empty() && result.back() != L'\\' && result.back() != L'/')
    {
        result += L"\\";
    }

    result += right;
    return result;
}

static std::wstring UserProfilePath()
{
    std::wstring profile = GetEnvString(L"USERPROFILE");

    if (profile.empty())
    {
        std::wstring drive = GetEnvString(L"HOMEDRIVE");
        std::wstring path = GetEnvString(L"HOMEPATH");
        if (!drive.empty() && !path.empty())
        {
            profile = drive + path;
        }
    }

    return profile;
}

static bool ReadTextFileUtf8OrWide(const std::wstring& path, std::wstring* output)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        if (output == nullptr || path.empty())
        {
            break;
        }

        // This helper only reads credential/.env files. Reject reparse points
        // (symlinks/junctions) at the path so a planted link cannot redirect
        // the read to an arbitrary file and have its contents treated as an
        // access token or provider configuration.
        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            break;
        }

        file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            break;
        }

        LARGE_INTEGER size = {};
        if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 1024 * 1024)
        {
            break;
        }

        std::string bytes;
        bytes.resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        if (!bytes.empty() && !ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &read, nullptr))
        {
            break;
        }
        bytes.resize(read);
        if (bytes.empty())
        {
            output->clear();
            ok = true;
            break;
        }

        int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
        if (required <= 0)
        {
            required = MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
            if (required <= 0)
            {
                break;
            }

            std::wstring text(required, L'\0');
            MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), &text[0], required);
            *output = text;
            ok = true;
            break;
        }

        std::wstring text(required, L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), &text[0], required);
        *output = text;
        ok = true;
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return ok;
}

static std::string WideToUtf8(const std::wstring& value)
{
    std::string result;

    do
    {
        if (value.empty())
        {
            break;
        }

        int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0)
        {
            break;
        }

        result.resize(required);
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &result[0], required, nullptr, nullptr);
    } while (false);

    return result;
}

static std::wstring Utf8ToWide(const std::string& value)
{
    std::wstring result;

    do
    {
        if (value.empty())
        {
            break;
        }

        int required = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (required <= 0)
        {
            required = MultiByteToWideChar(CP_ACP, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
            if (required <= 0)
            {
                break;
            }

            result.resize(required);
            MultiByteToWideChar(CP_ACP, 0, value.data(), static_cast<int>(value.size()), &result[0], required);
            break;
        }

        result.resize(required);
        MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), &result[0], required);
    } while (false);

    return result;
}

static bool IsDotEnvName(const std::wstring& name)
{
    bool ok = !name.empty();

    for (wchar_t ch : name)
    {
        if ((ch >= L'A' && ch <= L'Z') ||
            (ch >= L'a' && ch <= L'z') ||
            (ch >= L'0' && ch <= L'9') ||
            ch == L'_')
        {
            continue;
        }

        ok = false;
        break;
    }

    return ok;
}

static std::wstring TrimUnquotedDotEnvValue(const std::wstring& value)
{
    std::wstring result = value;

    for (size_t index = 0; index < result.size(); ++index)
    {
        if (result[index] == L'#' && (index == 0 || iswspace(result[index - 1]) != 0))
        {
            result = result.substr(0, index);
            break;
        }
    }

    return Trim(result);
}

static std::wstring DecodeQuotedDotEnvValue(const std::wstring& value)
{
    std::wstring result;

    do
    {
        std::wstring text = Trim(value);
        if (text.size() < 2)
        {
            result = text;
            break;
        }

        wchar_t quote = text.front();
        if ((quote != L'\'' && quote != L'\"') || text.back() != quote)
        {
            result = TrimUnquotedDotEnvValue(text);
            break;
        }

        std::wstring inner = text.substr(1, text.size() - 2);
        if (quote == L'\'')
        {
            result = inner;
            break;
        }

        for (size_t index = 0; index < inner.size(); ++index)
        {
            wchar_t ch = inner[index];
            if (ch != L'\\' || index + 1 >= inner.size())
            {
                result += ch;
                continue;
            }

            wchar_t escaped = inner[++index];
            switch (escaped)
            {
            case L'n':
                result += L'\n';
                break;
            case L'r':
                result += L'\r';
                break;
            case L't':
                result += L'\t';
                break;
            case L'\"':
            case L'\\':
                result += escaped;
                break;
            default:
                result += escaped;
                break;
            }
        }
    } while (false);

    return result;
}

static bool ParseDotEnvLine(const std::wstring& line, std::wstring* name, std::wstring* value)
{
    bool ok = false;

    do
    {
        if (name == nullptr || value == nullptr)
        {
            break;
        }

        std::wstring text = Trim(line);
        if (!text.empty() && text.front() == static_cast<wchar_t>(0xfeff))
        {
            text.erase(text.begin());
            text = Trim(text);
        }

        if (text.empty() || text.front() == L'#')
        {
            break;
        }

        const std::wstring exportPrefix = L"export ";
        if (text.rfind(exportPrefix, 0) == 0)
        {
            text = Trim(text.substr(exportPrefix.size()));
        }

        size_t equals = text.find(L'=');
        if (equals == std::wstring::npos)
        {
            break;
        }

        std::wstring parsedName = Trim(text.substr(0, equals));
        if (!IsDotEnvName(parsedName))
        {
            break;
        }

        *name = parsedName;
        *value = DecodeQuotedDotEnvValue(text.substr(equals + 1));
        ok = true;
    } while (false);

    return ok;
}

static std::string JsonEscape(const std::wstring& value)
{
    std::string utf8 = WideToUtf8(value);
    std::ostringstream out;

    for (unsigned char ch : utf8)
    {
        switch (ch)
        {
        case '\"':
            out << "\\\"";
            break;
        case '\\':
            out << "\\\\";
            break;
        case '\b':
            out << "\\b";
            break;
        case '\f':
            out << "\\f";
            break;
        case '\n':
            out << "\\n";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\t':
            out << "\\t";
            break;
        default:
            if (ch < 0x20)
            {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch);
            }
            else
            {
                out << static_cast<char>(ch);
            }
            break;
        }
    }

    return out.str();
}

static bool ParseJsonStringAt(const std::wstring& text, size_t quote, std::wstring* value, size_t* next)
{
    bool ok = false;
    std::wstring result;

    do
    {
        if (value == nullptr || quote >= text.size() || text[quote] != L'\"')
        {
            break;
        }

        for (size_t index = quote + 1; index < text.size(); ++index)
        {
            wchar_t ch = text[index];
            if (ch == L'\"')
            {
                *value = result;
                if (next != nullptr)
                {
                    *next = index + 1;
                }
                ok = true;
                break;
            }

            if (ch != L'\\' || index + 1 >= text.size())
            {
                result += ch;
                continue;
            }

            wchar_t escaped = text[++index];
            switch (escaped)
            {
            case L'\"':
            case L'\\':
            case L'/':
                result += escaped;
                break;
            case L'b':
                result += L'\b';
                break;
            case L'f':
                result += L'\f';
                break;
            case L'n':
                result += L'\n';
                break;
            case L'r':
                result += L'\r';
                break;
            case L't':
                result += L'\t';
                break;
            case L'u':
                if (index + 4 < text.size())
                {
                    wchar_t* end = nullptr;
                    std::wstring hex = text.substr(index + 1, 4);
                    unsigned long code = wcstoul(hex.c_str(), &end, 16);
                    if (end != nullptr && *end == L'\0')
                    {
                        result += static_cast<wchar_t>(code);
                        index += 4;
                    }
                }
                break;
            default:
                result += escaped;
                break;
            }
        }
    } while (false);

    return ok;
}

static bool ExtractJsonString(const std::wstring& text, const std::wstring& key, std::wstring* value)
{
    bool ok = false;
    std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = 0;

    do
    {
        if (value == nullptr || key.empty())
        {
            break;
        }

        while ((pos = text.find(pattern, pos)) != std::wstring::npos)
        {
            size_t colon = text.find(L':', pos + pattern.size());
            if (colon == std::wstring::npos)
            {
                break;
            }

            size_t quote = colon + 1;
            while (quote < text.size() && iswspace(text[quote]) != 0)
            {
                ++quote;
            }

            if (quote < text.size() && text[quote] == L'\"')
            {
                ok = ParseJsonStringAt(text, quote, value, nullptr);
                break;
            }

            pos = colon + 1;
        }
    } while (false);

    return ok;
}

static std::wstring ExtractProviderError(const std::wstring& body)
{
    std::wstring message;

    if (!ExtractJsonString(body, L"message", &message))
    {
        message = Trim(body);
    }

    if (message.size() > 512)
    {
        message = message.substr(0, 512) + L"...";
    }

    return message;
}

static bool ExtractJsonObjectAt(
    const std::wstring& text,
    size_t openBrace,
    std::wstring* object,
    size_t* end)
{
    bool ok = false;

    do
    {
        if (object == nullptr || openBrace >= text.size() || text[openBrace] != L'{')
        {
            break;
        }

        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (size_t index = openBrace; index < text.size(); ++index)
        {
            wchar_t ch = text[index];
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
                else if (ch == L'\"')
                {
                    inString = false;
                }

                continue;
            }

            if (ch == L'\"')
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
                    *object = text.substr(openBrace, index - openBrace + 1);
                    if (end != nullptr)
                    {
                        *end = index + 1;
                    }

                    ok = true;
                    break;
                }
            }
        }
    } while (false);

    return ok;
}

static bool FindJsonKeyColon(
    const std::wstring& text,
    const std::wstring& key,
    size_t from,
    size_t* colon)
{
    bool ok = false;
    const std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = from;

    while ((pos = text.find(pattern, pos)) != std::wstring::npos)
    {
        size_t after = pos + pattern.size();
        while (after < text.size() && iswspace(text[after]) != 0)
        {
            ++after;
        }

        if (after < text.size() && text[after] == L':')
        {
            if (colon != nullptr)
            {
                *colon = after;
            }

            ok = true;
            break;
        }

        ++pos;
    }

    return ok;
}

static size_t SkipJsonWhitespace(const std::wstring& text, size_t index)
{
    while (index < text.size() && iswspace(text[index]) != 0)
    {
        ++index;
    }

    return index;
}

static bool FindDirectJsonKeyValue(
    const std::wstring& object,
    const std::wstring& key,
    size_t* valueIndex)
{
    bool ok = false;

    do
    {
        if (valueIndex == nullptr || object.empty() || object[0] != L'{' || key.empty())
        {
            break;
        }

        const std::wstring pattern = L"\"" + key + L"\"";
        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (size_t index = 0; index < object.size(); ++index)
        {
            const wchar_t ch = object[index];
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
                else if (ch == L'\"')
                {
                    inString = false;
                }

                continue;
            }

            if (ch == L'\"')
            {
                bool matchedKey = false;
                if (depth == 1 &&
                    index + pattern.size() <= object.size() &&
                    object.compare(index, pattern.size(), pattern) == 0)
                {
                    size_t after = SkipJsonWhitespace(object, index + pattern.size());
                    if (after < object.size() && object[after] == L':')
                    {
                        *valueIndex = SkipJsonWhitespace(object, after + 1);
                        matchedKey = true;
                        ok = *valueIndex < object.size();
                    }
                }

                if (matchedKey)
                {
                    break;
                }

                inString = true;
                continue;
            }

            if (ch == L'{')
            {
                ++depth;
            }
            else if (ch == L'}')
            {
                --depth;
                if (depth <= 0)
                {
                    break;
                }
            }
        }
    } while (false);

    return ok;
}

static bool ExtractDirectJsonString(
    const std::wstring& object,
    const std::wstring& key,
    std::wstring* value)
{
    bool ok = false;
    size_t valueIndex = 0;

    do
    {
        if (value == nullptr || !FindDirectJsonKeyValue(object, key, &valueIndex))
        {
            break;
        }

        if (object[valueIndex] != L'\"')
        {
            break;
        }

        ok = ParseJsonStringAt(object, valueIndex, value, nullptr);
    } while (false);

    return ok;
}

static bool IsReasoningPartType(const std::wstring& type)
{
    const std::wstring lowered = ToLowerString(Trim(type));
    return lowered.find(L"reason") != std::wstring::npos ||
           lowered.find(L"think") != std::wstring::npos;
}

static bool ExtractNamedJsonObject(
    const std::wstring& text,
    const std::wstring& key,
    std::wstring* object)
{
    bool ok = false;
    size_t colon = 0;

    do
    {
        if (!FindJsonKeyColon(text, key, 0, &colon))
        {
            break;
        }

        size_t open = SkipJsonWhitespace(text, colon + 1);
        if (!ExtractJsonObjectAt(text, open, object, nullptr))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ExtractFirstArrayObject(
    const std::wstring& text,
    const std::wstring& key,
    std::wstring* object)
{
    bool ok = false;
    size_t colon = 0;

    do
    {
        if (!FindJsonKeyColon(text, key, 0, &colon))
        {
            break;
        }

        size_t open = SkipJsonWhitespace(text, colon + 1);
        if (open >= text.size() || text[open] != L'[')
        {
            break;
        }

        size_t cursor = open + 1;
        while (cursor < text.size() && text[cursor] != L'{' && text[cursor] != L']')
        {
            ++cursor;
        }

        if (!ExtractJsonObjectAt(text, cursor, object, nullptr))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ExtractMessageContent(const std::wstring& message, std::wstring* content)
{
    bool ok = false;
    size_t value = 0;

    do
    {
        if (content == nullptr || !FindDirectJsonKeyValue(message, L"content", &value))
        {
            break;
        }

        if (message[value] == L'n')
        {
            break;
        }

        if (message[value] == L'\"')
        {
            ok = ParseJsonStringAt(message, value, content, nullptr);
            break;
        }

        if (message[value] != L'[')
        {
            break;
        }

        std::wstring combined;
        size_t cursor = value + 1;
        for (;;)
        {
            while (cursor < message.size() &&
                   message[cursor] != L'{' &&
                   message[cursor] != L']')
            {
                ++cursor;
            }

            if (cursor >= message.size() || message[cursor] == L']')
            {
                break;
            }

            std::wstring part;
            size_t end = 0;
            if (!ExtractJsonObjectAt(message, cursor, &part, &end))
            {
                break;
            }

            cursor = end;
            std::wstring type;
            ExtractDirectJsonString(part, L"type", &type);
            if (IsReasoningPartType(type))
            {
                continue;
            }

            std::wstring text;
            if (ExtractDirectJsonString(part, L"text", &text) && !Trim(text).empty())
            {
                combined += text;
            }
        }

        if (Trim(combined).empty())
        {
            break;
        }

        *content = combined;
        ok = true;
    } while (false);

    return ok;
}

static bool FinishReasonIsTruncated(const std::wstring& reason)
{
    std::wstring text = ToLowerString(Trim(reason));
    return text == L"length" ||
           text == L"max_tokens" ||
           text == L"max_output_tokens" ||
           text == L"incomplete";
}

static void ApplyFinishReasonFlag(const std::wstring& object, bool* truncated)
{
    if (truncated == nullptr)
    {
        return;
    }

    std::wstring reason;
    if (ExtractDirectJsonString(object, L"finish_reason", &reason) ||
        ExtractDirectJsonString(object, L"native_finish_reason", &reason) ||
        ExtractDirectJsonString(object, L"status", &reason))
    {
        if (FinishReasonIsTruncated(reason))
        {
            *truncated = true;
        }
    }
}

static bool ExtractAssistantFromOutputArray(const std::wstring& body, std::wstring* text)
{
    bool ok = false;
    size_t colon = 0;

    do
    {
        if (text == nullptr || !FindJsonKeyColon(body, L"output", 0, &colon))
        {
            break;
        }

        size_t open = SkipJsonWhitespace(body, colon + 1);
        if (open >= body.size() || body[open] != L'[')
        {
            break;
        }

        std::wstring combined;
        size_t cursor = open + 1;
        for (;;)
        {
            while (cursor < body.size() &&
                   body[cursor] != L'{' &&
                   body[cursor] != L']')
            {
                ++cursor;
            }

            if (cursor >= body.size() || body[cursor] == L']')
            {
                break;
            }

            std::wstring part;
            size_t end = 0;
            if (!ExtractJsonObjectAt(body, cursor, &part, &end))
            {
                break;
            }

            cursor = end;
            std::wstring type;
            ExtractDirectJsonString(part, L"type", &type);
            if (IsReasoningPartType(type))
            {
                continue;
            }

            std::wstring piece;
            const std::wstring lowered = ToLowerString(Trim(type));
            if (lowered == L"output_text" || lowered == L"text")
            {
                if (ExtractDirectJsonString(part, L"text", &piece) && !Trim(piece).empty())
                {
                    combined += piece;
                }

                continue;
            }

            if (ExtractMessageContent(part, &piece) && !Trim(piece).empty())
            {
                combined += piece;
            }
        }

        if (Trim(combined).empty())
        {
            break;
        }

        *text = combined;
        ok = true;
    } while (false);

    return ok;
}

static std::wstring ExtractAssistantText(const std::wstring& body, bool* truncated)
{
    std::wstring text;

    if (truncated != nullptr)
    {
        *truncated = false;
    }

    do
    {
        std::wstring choice;
        if (ExtractFirstArrayObject(body, L"choices", &choice))
        {
            ApplyFinishReasonFlag(choice, truncated);

            std::wstring message;
            if (ExtractNamedJsonObject(choice, L"message", &message))
            {
                if (ExtractMessageContent(message, &text) && !Trim(text).empty())
                {
                    break;
                }
            }
            else if (ExtractDirectJsonString(choice, L"text", &text) && !Trim(text).empty())
            {
                break;
            }
        }

        if (ExtractAssistantFromOutputArray(body, &text) && !Trim(text).empty())
        {
            ApplyFinishReasonFlag(body, truncated);
            break;
        }

        if (ExtractDirectJsonString(body, L"output_text", &text) && !Trim(text).empty())
        {
            ApplyFinishReasonFlag(body, truncated);
            break;
        }

        text.clear();
    } while (false);

    return Trim(text);
}

static std::wstring EnsureScheme(const std::wstring& value, const std::wstring& scheme)
{
    std::wstring result = Trim(value);

    if (!result.empty() && result.find(L"://") == std::wstring::npos)
    {
        result = scheme + L"://" + result;
    }

    while (!result.empty() && result.back() == L'/')
    {
        result.pop_back();
    }

    return result;
}

static bool EndsWithNoCase(const std::wstring& value, const std::wstring& suffix)
{
    bool result = false;

    if (value.size() >= suffix.size())
    {
        std::wstring tail = value.substr(value.size() - suffix.size());
        result = ToLowerString(tail) == ToLowerString(suffix);
    }

    return result;
}

static std::wstring OpenAICompatibleUrl(AiProviderKind provider, const std::wstring& baseUrl)
{
    std::wstring base = Trim(baseUrl);
    std::wstring url;

    if (provider == AiProviderKind::DeepSeek)
    {
        if (base.empty())
        {
            base = kDefaultDeepSeekBaseUrl;
        }
        base = EnsureScheme(base, L"https");
        if (EndsWithNoCase(base, L"/chat/completions") || EndsWithNoCase(base, L"/v1/chat/completions"))
        {
            url = base;
        }
        else if (EndsWithNoCase(base, L"/v1"))
        {
            url = base.substr(0, base.size() - 3) + L"/chat/completions";
        }
        else
        {
            url = base + L"/chat/completions";
        }
    }
    else
    {
        if (base.empty())
        {
            base = kDefaultOpenRouterBaseUrl;
        }
        base = EnsureScheme(base, L"https");
        if (EndsWithNoCase(base, L"/chat/completions") || EndsWithNoCase(base, L"/v1/chat/completions"))
        {
            url = base;
        }
        else if (EndsWithNoCase(base, L"/v1"))
        {
            url = base + L"/chat/completions";
        }
        else
        {
            url = base + L"/v1/chat/completions";
        }
    }

    return url;
}

static std::wstring CodexApiUrl(const std::wstring& baseUrl)
{
    std::wstring base = Trim(baseUrl);

    if (base.empty())
    {
        base = kDefaultCodexBaseUrl;
    }

    base = EnsureScheme(base, L"https");
    if (!EndsWithNoCase(base, L"/responses"))
    {
        base += L"/responses";
    }

    return base;
}

struct HttpResult
{
    uint32_t StatusCode;
    std::wstring Body;
};

static bool HttpRequest(
    const wchar_t* method,
    const std::wstring& url,
    const std::wstring& headers,
    const std::string& body,
    uint32_t timeoutSeconds,
    HttpResult* result,
    std::wstring* error)
{
    bool ok = false;
    HINTERNET session = nullptr;
    HINTERNET connect = nullptr;
    HINTERNET request = nullptr;
    std::wstring mutableUrl = url;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        URL_COMPONENTS parts = {};
        parts.dwStructSize = sizeof(parts);
        parts.dwSchemeLength = static_cast<DWORD>(-1);
        parts.dwHostNameLength = static_cast<DWORD>(-1);
        parts.dwUrlPathLength = static_cast<DWORD>(-1);
        parts.dwExtraInfoLength = static_cast<DWORD>(-1);

        if (!WinHttpCrackUrl(mutableUrl.data(), static_cast<DWORD>(mutableUrl.size()), 0, &parts))
        {
            if (error != nullptr)
            {
                *error = L"WinHttpCrackUrl failed";
            }
            break;
        }

        std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
        std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
        if (parts.dwExtraInfoLength > 0)
        {
            path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
        }
        if (path.empty())
        {
            path = L"/";
        }

        session = WinHttpOpen(L"KnLiveDbg/ai", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (session == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"WinHttpOpen failed";
            }
            break;
        }

        int timeout = static_cast<int>(std::max<uint32_t>(timeoutSeconds, 1) * 1000);
        WinHttpSetTimeouts(session, timeout, timeout, timeout, timeout);

        connect = WinHttpConnect(session, host.c_str(), parts.nPort, 0);
        if (connect == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"WinHttpConnect failed";
            }
            break;
        }

        DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
        const wchar_t* verb = (method != nullptr && method[0] != L'\0') ? method : L"POST";
        request = WinHttpOpenRequest(connect, verb, path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (request == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"WinHttpOpenRequest failed";
            }
            break;
        }

        DWORD bodySize = static_cast<DWORD>(body.size());
        const void* bodyData = body.empty() ? nullptr : body.data();
        if (!WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(headers.size()), const_cast<void*>(bodyData), bodySize, bodySize, 0))
        {
            if (error != nullptr)
            {
                *error = L"WinHttpSendRequest failed";
            }
            break;
        }

        if (!WinHttpReceiveResponse(request, nullptr))
        {
            if (error != nullptr)
            {
                *error = L"WinHttpReceiveResponse failed";
            }
            break;
        }

        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &statusCode, &statusSize, nullptr);

        std::string responseBytes;
        bool readOk = true;
        for (;;)
        {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available))
            {
                readOk = false;
                if (error != nullptr)
                {
                    *error = L"WinHttpQueryDataAvailable failed";
                }
                break;
            }

            if (available == 0)
            {
                break;
            }

            std::string chunk;
            chunk.resize(available);
            DWORD read = 0;
            if (!WinHttpReadData(request, &chunk[0], available, &read))
            {
                readOk = false;
                if (error != nullptr)
                {
                    *error = L"WinHttpReadData failed";
                }
                break;
            }

            if (read == 0)
            {
                break;
            }

            chunk.resize(read);
            responseBytes += chunk;
        }

        if (!readOk)
        {
            break;
        }

        result->StatusCode = statusCode;
        result->Body = Utf8ToWide(responseBytes);
        ok = true;
    } while (false);

    if (request != nullptr)
    {
        WinHttpCloseHandle(request);
    }
    if (connect != nullptr)
    {
        WinHttpCloseHandle(connect);
    }
    if (session != nullptr)
    {
        WinHttpCloseHandle(session);
    }

    return ok;
}

static bool HttpPost(
    const std::wstring& url,
    const std::wstring& headers,
    const std::string& body,
    uint32_t timeoutSeconds,
    HttpResult* result,
    std::wstring* error)
{
    return HttpRequest(L"POST", url, headers, body, timeoutSeconds, result, error);
}

static bool HttpGet(
    const std::wstring& url,
    const std::wstring& headers,
    uint32_t timeoutSeconds,
    HttpResult* result,
    std::wstring* error)
{
    return HttpRequest(L"GET", url, headers, std::string(), timeoutSeconds, result, error);
}

static std::wstring ExecutableDirectory()
{
    std::wstring directory;
    wchar_t path[MAX_PATH];
    DWORD written = GetModuleFileNameW(nullptr, path, MAX_PATH);

    do
    {
        if (written == 0 || written >= MAX_PATH)
        {
            break;
        }

        directory = path;
        size_t slash = directory.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            directory.clear();
            break;
        }

        directory.resize(slash);
    } while (false);

    return directory;
}

static std::wstring EncodeDotEnvValue(const std::wstring& value)
{
    std::wstring encoded = value;
    bool quote = false;

    for (wchar_t ch : value)
    {
        if (iswspace(ch) != 0 || ch == L'#' || ch == L'\"' || ch == L'\'')
        {
            quote = true;
            break;
        }
    }

    if (quote)
    {
        std::wstring escaped;
        escaped.push_back(L'\"');
        for (wchar_t ch : value)
        {
            if (ch == L'\\' || ch == L'\"')
            {
                escaped.push_back(L'\\');
            }

            escaped.push_back(ch);
        }

        escaped.push_back(L'\"');
        encoded = escaped;
    }

    return encoded;
}

static bool WriteTextFileUtf8(const std::wstring& path, const std::wstring& text, std::wstring* error)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        if (path.empty())
        {
            if (error != nullptr)
            {
                *error = L".env path is empty";
            }

            break;
        }

        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            if (error != nullptr)
            {
                *error = L".env path is a reparse point";
            }

            break;
        }

        std::string bytes = WideToUtf8(text);
        file = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"failed to write " + path;
            }

            break;
        }

        DWORD written = 0;
        if (!WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) ||
            written != bytes.size())
        {
            if (error != nullptr)
            {
                *error = L"failed to write " + path;
            }

            break;
        }

        ok = true;
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return ok;
}

static std::string UrlEncodeUtf8(const std::wstring& value)
{
    std::string input = WideToUtf8(value);
    std::ostringstream out;

    for (unsigned char ch : input)
    {
        if ((ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_' || ch == '.' || ch == '~')
        {
            out << static_cast<char>(ch);
        }
        else
        {
            out << '%' << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ch);
        }
    }

    return out.str();
}

bool AiProviderRuntime::ResolveCodexTokens(std::wstring* accessToken, std::wstring* refreshToken, std::wstring* source) const
{
    bool ok = false;

    do
    {
        if (accessToken == nullptr || refreshToken == nullptr)
        {
            break;
        }

        std::wstring valueSource;
        *accessToken = ConfigValue(L"KNLIVEDBG_CODEX_ACCESS_TOKEN", &valueSource);
        if (!accessToken->empty())
        {
            if (source != nullptr)
            {
                *source = valueSource;
            }
            ok = true;
            break;
        }

        *accessToken = ConfigValue(L"KERNFORGE_CODEX_ACCESS_TOKEN", &valueSource);
        if (!accessToken->empty())
        {
            if (source != nullptr)
            {
                *source = valueSource;
            }
            ok = true;
            break;
        }

        std::vector<std::wstring> paths;
        std::wstring configured = ConfigValue(L"KNLIVEDBG_CODEX_AUTH_FILE", nullptr);
        if (!configured.empty())
        {
            paths.push_back(ExpandEnvironment(configured));
        }
        configured = ConfigValue(L"KERNFORGE_CODEX_AUTH_FILE", nullptr);
        if (!configured.empty())
        {
            paths.push_back(ExpandEnvironment(configured));
        }

        std::wstring profile = UserProfilePath();
        if (!profile.empty())
        {
            paths.push_back(JoinPath(profile, L".kernforge\\codex_auth.json"));
            paths.push_back(JoinPath(profile, L".codex\\auth.json"));
        }

        for (const std::wstring& path : paths)
        {
            std::wstring text;
            if (!ReadTextFileUtf8OrWide(path, &text))
            {
                continue;
            }

            std::wstring access;
            std::wstring refresh;
            ExtractJsonString(text, L"access_token", &access);
            ExtractJsonString(text, L"refresh_token", &refresh);
            if (!Trim(access).empty() || !Trim(refresh).empty())
            {
                *accessToken = Trim(access);
                *refreshToken = Trim(refresh);
                if (source != nullptr)
                {
                    *source = path;
                }
                ok = true;
                break;
            }
        }
    } while (false);

    return ok;
}

static bool RefreshCodexAccessToken(
    const AiProviderSettings& settings,
    const std::wstring& refreshToken,
    std::wstring* accessToken,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (accessToken == nullptr || Trim(refreshToken).empty())
        {
            if (error != nullptr)
            {
                *error = L"missing OpenAI Codex OAuth refresh token";
            }
            break;
        }

        std::string body = "grant_type=refresh_token&refresh_token=" +
                           UrlEncodeUtf8(refreshToken) +
                           "&client_id=" +
                           UrlEncodeUtf8(kCodexOAuthClientId);

        std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n";
        HttpResult result = {};
        if (!HttpPost(kCodexOAuthTokenUrl, headers, body, settings.TimeoutSeconds, &result, error))
        {
            break;
        }

        if (result.StatusCode >= 300)
        {
            if (error != nullptr)
            {
                *error = L"OpenAI Codex OAuth refresh failed: " + ExtractProviderError(result.Body);
            }
            break;
        }

        std::wstring token;
        if (!ExtractJsonString(result.Body, L"access_token", &token) || Trim(token).empty())
        {
            if (error != nullptr)
            {
                *error = L"OpenAI Codex OAuth refresh returned no access token";
            }
            break;
        }

        *accessToken = Trim(token);
        ok = true;
    } while (false);

    return ok;
}

static std::wstring QuoteCommandLineArg(const std::wstring& value)
{
    std::wstring result = L"\"";
    size_t backslashes = 0;

    for (wchar_t ch : value)
    {
        if (ch == L'\\')
        {
            ++backslashes;
            continue;
        }

        if (ch == L'\"')
        {
            result.append(backslashes * 2 + 1, L'\\');
            result += ch;
            backslashes = 0;
            continue;
        }

        if (backslashes > 0)
        {
            result.append(backslashes, L'\\');
            backslashes = 0;
        }

        result += ch;
    }

    if (backslashes > 0)
    {
        result.append(backslashes * 2, L'\\');
    }

    result += L"\"";
    return result;
}

static bool WriteUtf8File(const std::wstring& path, const std::wstring& text)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            break;
        }

        std::string bytes = WideToUtf8(text);
        DWORD written = 0;
        if (!bytes.empty() && !WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr))
        {
            break;
        }

        ok = written == bytes.size();
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return ok;
}

static bool CreatePromptArgument(const std::wstring& prompt, std::wstring* argument, std::wstring* tempFile, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (argument == nullptr || tempFile == nullptr)
        {
            break;
        }

        if (prompt.size() <= 1024)
        {
            *argument = prompt;
            ok = true;
            break;
        }

        wchar_t tempPath[MAX_PATH] = {};
        wchar_t tempName[MAX_PATH] = {};
        if (GetTempPathW(MAX_PATH, tempPath) == 0 || GetTempFileNameW(tempPath, L"kna", 0, tempName) == 0)
        {
            if (error != nullptr)
            {
                *error = L"failed to allocate temporary Codex CLI prompt file";
            }
            break;
        }

        if (!WriteUtf8File(tempName, prompt + L"\n"))
        {
            if (error != nullptr)
            {
                *error = L"failed to write temporary Codex CLI prompt file";
            }
            break;
        }

        *tempFile = tempName;
        *argument = L"Read the complete KnLiveDbg AI request from this file, follow it, and return the final answer: " + *tempFile;
        ok = true;
    } while (false);

    return ok;
}

static bool ReadPipeAvailable(HANDLE pipe, std::string* output)
{
    bool ok = true;

    do
    {
        if (pipe == INVALID_HANDLE_VALUE || output == nullptr)
        {
            ok = false;
            break;
        }

        for (;;)
        {
            DWORD available = 0;
            if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
            {
                ok = false;
                break;
            }

            if (available == 0)
            {
                break;
            }

            char buffer[4096] = {};
            DWORD toRead = std::min<DWORD>(available, static_cast<DWORD>(sizeof(buffer)));
            DWORD read = 0;
            if (!ReadFile(pipe, buffer, toRead, &read, nullptr))
            {
                ok = false;
                break;
            }

            output->append(buffer, buffer + read);
        }
    } while (false);

    return ok;
}

static bool RunProcessCapture(
    const std::wstring& commandLine,
    uint32_t timeoutSeconds,
    std::wstring* output,
    uint32_t* exitCode,
    std::wstring* error)
{
    bool ok = false;
    HANDLE readPipe = INVALID_HANDLE_VALUE;
    HANDLE writePipe = INVALID_HANDLE_VALUE;
    HANDLE process = nullptr;
    HANDLE thread = nullptr;

    do
    {
        if (output == nullptr || exitCode == nullptr)
        {
            break;
        }

        SECURITY_ATTRIBUTES sa = {};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
        {
            if (error != nullptr)
            {
                *error = L"CreatePipe failed";
            }
            break;
        }
        SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdOutput = writePipe;
        startup.hStdError = writePipe;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION info = {};
        std::wstring mutableCommand = commandLine;
        if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info))
        {
            if (error != nullptr)
            {
                *error = L"CreateProcessW failed";
            }
            break;
        }

        process = info.hProcess;
        thread = info.hThread;
        CloseHandle(writePipe);
        writePipe = INVALID_HANDLE_VALUE;

        std::string bytes;
        DWORD waitResult = WAIT_TIMEOUT;
        DWORD timeoutMs = std::max<uint32_t>(timeoutSeconds, 1) * 1000;
        DWORD elapsed = 0;
        while (elapsed < timeoutMs)
        {
            ReadPipeAvailable(readPipe, &bytes);
            waitResult = WaitForSingleObject(process, 50);
            if (waitResult != WAIT_TIMEOUT)
            {
                break;
            }
            elapsed += 50;
        }

        if (waitResult == WAIT_TIMEOUT)
        {
            TerminateProcess(process, ERROR_TIMEOUT);
            if (error != nullptr)
            {
                *error = L"Codex CLI timed out";
            }
            break;
        }

        ReadPipeAvailable(readPipe, &bytes);

        DWORD processExit = 0;
        if (!GetExitCodeProcess(process, &processExit))
        {
            processExit = 1;
        }

        *exitCode = processExit;
        *output = Trim(Utf8ToWide(bytes));
        ok = true;
    } while (false);

    if (thread != nullptr)
    {
        CloseHandle(thread);
    }
    if (process != nullptr)
    {
        CloseHandle(process);
    }
    if (writePipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(writePipe);
    }
    if (readPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(readPipe);
    }

    return ok;
}

static std::wstring RenderPrompt(const AiCompletionRequest& request)
{
    std::wstringstream stream;

    stream << L"# KnLiveDbg AI request\n\n";
    stream << L"You are assisting a Windows kernel live-memory debugging operator. ";
    stream << L"Do not invent addresses or claim that a write happened unless command output proves it. ";
    stream << L"For write-like requests, provide a preview, risk notes, backup command, and verification command before any mutation.\n\n";
    if (!Trim(request.System).empty())
    {
        stream << L"## Session context\n\n";
        stream << request.System << L"\n\n";
    }
    stream << L"## Operator request\n\n";
    stream << request.Prompt << L"\n";

    return stream.str();
}

AiProviderRuntime::AiProviderRuntime()
{
    settings_.Provider = AiProviderKind::Disabled;
    settings_.RemotePolicy = AiRemotePolicy::AllowRemote;
    settings_.TimeoutSeconds = 120;
    ReloadFromEnvironment();
}

const AiProviderSettings& AiProviderRuntime::Settings() const
{
    return settings_;
}

std::wstring AiProviderRuntime::ConfigValue(const wchar_t* name, std::wstring* source) const
{
    std::wstring value;

    do
    {
        if (source != nullptr)
        {
            source->clear();
        }

        if (name == nullptr || name[0] == L'\0')
        {
            break;
        }

        value = GetEnvString(name);
        if (!value.empty())
        {
            if (source != nullptr)
            {
                *source = name;
            }
            break;
        }

        std::wstring key = name;
        for (const ConfigEntry& entry : dotEnvValues_)
        {
            if (entry.Name == key)
            {
                value = entry.Value;
                if (source != nullptr)
                {
                    *source = entry.Source;
                }
                break;
            }
        }
    } while (false);

    return value;
}

bool AiProviderRuntime::LoadDotEnvFiles(const std::vector<std::wstring>& paths, std::wstring* loadedPath, std::wstring* error)
{
    bool loaded = false;

    dotEnvValues_.clear();
    settings_.DotEnvPath.clear();

    do
    {
        for (const std::wstring& candidate : paths)
        {
            std::wstring path = Trim(candidate);
            if (path.empty())
            {
                continue;
            }

            std::wstring text;
            if (!ReadTextFileUtf8OrWide(path, &text))
            {
                continue;
            }

            size_t offset = 0;
            while (offset <= text.size())
            {
                size_t end = text.find_first_of(L"\r\n", offset);
                std::wstring line;
                if (end == std::wstring::npos)
                {
                    line = text.substr(offset);
                    offset = text.size() + 1;
                }
                else
                {
                    line = text.substr(offset, end - offset);
                    offset = end + 1;
                    if (offset < text.size() && text[end] == L'\r' && text[offset] == L'\n')
                    {
                        ++offset;
                    }
                }

                std::wstring name;
                std::wstring value;
                if (!ParseDotEnvLine(line, &name, &value))
                {
                    continue;
                }

                bool updated = false;
                for (ConfigEntry& entry : dotEnvValues_)
                {
                    if (entry.Name == name)
                    {
                        entry.Value = value;
                        entry.Source = name + L" from " + path;
                        updated = true;
                        break;
                    }
                }

                if (!updated)
                {
                    ConfigEntry entry = {};
                    entry.Name = name;
                    entry.Value = value;
                    entry.Source = name + L" from " + path;
                    dotEnvValues_.push_back(entry);
                }
            }

            settings_.DotEnvPath = path;
            loaded = true;
            break;
        }

        if (settings_.DotEnvWritePath.empty() && !paths.empty())
        {
            settings_.DotEnvWritePath = Trim(paths[0]);
        }

        ReloadFromEnvironment();
    } while (false);

    if (loadedPath != nullptr)
    {
        *loadedPath = settings_.DotEnvPath;
    }
    if (!loaded && error != nullptr)
    {
        error->clear();
    }

    return loaded;
}

void AiProviderRuntime::ReloadFromEnvironment()
{
    std::wstring provider = ConfigValue(L"KNLIVEDBG_AI_PROVIDER", nullptr);
    if (!provider.empty())
    {
        AiProviderKind kind = AiProviderKind::Disabled;
        std::wstring normalized;
        if (NormalizeProviderName(provider, &kind, &normalized))
        {
            settings_.Provider = kind;
        }
    }

    std::wstring policySource;
    std::wstring policyText = ConfigValue(L"KNLIVEDBG_AI_REMOTE_POLICY", &policySource);
    if (!policyText.empty())
    {
        AiRemotePolicy policy = AiRemotePolicy::AllowRemote;
        std::wstring normalized;
        if (NormalizeRemotePolicyName(policyText, &policy, &normalized))
        {
            settings_.RemotePolicy = policy;
            settings_.RemotePolicySource = policySource;
        }
    }
    else
    {
        settings_.RemotePolicy = AiRemotePolicy::AllowRemote;
        settings_.RemotePolicySource.clear();
    }

    settings_.Model = ConfigValue(L"KNLIVEDBG_AI_MODEL", nullptr);
    settings_.BaseUrl = ConfigValue(L"KNLIVEDBG_AI_BASE_URL", nullptr);
    settings_.CodexCliPath = ConfigValue(L"KNLIVEDBG_CODEX_CLI_PATH", nullptr);
    settings_.CodexAuthFile = ConfigValue(L"KNLIVEDBG_CODEX_AUTH_FILE", nullptr);
    settings_.ReasoningEffort = ConfigValue(L"KNLIVEDBG_AI_REASONING_EFFORT", nullptr);

    std::wstring timeoutText = ConfigValue(L"KNLIVEDBG_AI_TIMEOUT_SECONDS", nullptr);
    if (!timeoutText.empty())
    {
        wchar_t* end = nullptr;
        unsigned long parsed = wcstoul(timeoutText.c_str(), &end, 10);
        if (end != nullptr && *end == L'\0' && parsed > 0 && parsed <= 3600)
        {
            settings_.TimeoutSeconds = static_cast<uint32_t>(parsed);
        }
    }

    ApplyProviderDefaults(true);
    LoadCredentials();
}

bool AiProviderRuntime::SetProvider(const std::wstring& provider, std::wstring* error)
{
    bool ok = false;
    AiProviderKind kind = AiProviderKind::Disabled;
    std::wstring normalized;

    do
    {
        if (!NormalizeProviderName(provider, &kind, &normalized))
        {
            if (error != nullptr)
            {
                *error = L"unsupported AI provider";
            }
            break;
        }

        if (settings_.Provider == kind)
        {
            LoadCredentials();
            ok = true;
            break;
        }

        if (settings_.RemotePolicy == AiRemotePolicy::LocalOnly && IsRemoteNetworkProvider(kind))
        {
            if (error != nullptr)
            {
                *error = L"provider is blocked by local-only AI remote policy";
            }
            break;
        }

        settings_.Provider = kind;
        ApplyProviderDefaults(false);
        LoadCredentials();
        ok = true;
    } while (false);

    return ok;
}

void AiProviderRuntime::SetModel(const std::wstring& model)
{
    settings_.Model = Trim(model);
    ApplyProviderDefaults(true);
}

void AiProviderRuntime::SetBaseUrl(const std::wstring& baseUrl)
{
    settings_.BaseUrl = Trim(baseUrl);
    ApplyProviderDefaults(true);
}

void AiProviderRuntime::SetReasoningEffort(const std::wstring& effort)
{
    settings_.ReasoningEffort = Trim(effort);
}

bool AiProviderRuntime::SetRemotePolicy(const std::wstring& policy, std::wstring* error)
{
    bool ok = false;
    AiRemotePolicy parsed = AiRemotePolicy::AllowRemote;
    std::wstring normalized;

    do
    {
        if (!NormalizeRemotePolicyName(policy, &parsed, &normalized))
        {
            if (error != nullptr)
            {
                *error = L"usage: ai config policy <allow-remote|local-only>";
            }
            break;
        }

        settings_.RemotePolicy = parsed;
        settings_.RemotePolicySource = L"session";
        ok = true;
    } while (false);

    return ok;
}

std::wstring AiProviderRuntime::ProviderName() const
{
    std::wstring name = L"disabled";

    switch (settings_.Provider)
    {
    case AiProviderKind::CodexCli:
        name = L"openai-codex-cli";
        break;
    case AiProviderKind::OpenAICodex:
        name = L"openai-codex-subscription";
        break;
    case AiProviderKind::DeepSeek:
        name = L"deepseek";
        break;
    case AiProviderKind::OpenRouter:
        name = L"openrouter";
        break;
    default:
        break;
    }

    return name;
}

std::wstring AiProviderRuntime::RemotePolicyName() const
{
    std::wstring name = L"allow-remote";

    if (settings_.RemotePolicy == AiRemotePolicy::LocalOnly)
    {
        name = L"local-only";
    }

    return name;
}

std::wstring AiProviderRuntime::CredentialStatus() const
{
    std::wstring status = L"not required";

    if (settings_.Provider == AiProviderKind::DeepSeek || settings_.Provider == AiProviderKind::OpenRouter)
    {
        status = settings_.ApiKey.empty() ? L"missing api key" : L"api key from " + settings_.ApiKeySource;
    }
    else if (settings_.Provider == AiProviderKind::OpenAICodex)
    {
        std::wstring access;
        std::wstring refresh;
        std::wstring source;
        if (ResolveCodexTokens(&access, &refresh, &source))
        {
            status = source.empty() ? L"token available" : L"token from " + source;
        }
        else
        {
            status = L"missing Codex OAuth token";
        }
    }
    else if (settings_.Provider == AiProviderKind::CodexCli)
    {
        status = L"uses external codex executable";
    }

    return status;
}

std::wstring AiProviderRuntime::StatusText() const
{
    std::wstringstream stream;

    stream << L"ai provider: " << ProviderName() << L"\n";
    stream << L"model: " << (settings_.Model.empty() ? L"(default)" : settings_.Model) << L"\n";
    stream << L"base url: " << (settings_.BaseUrl.empty() ? L"(default)" : settings_.BaseUrl) << L"\n";
    stream << L"remote policy: " << RemotePolicyName();
    if (!settings_.RemotePolicySource.empty())
    {
        stream << L" from " << settings_.RemotePolicySource;
    }
    stream << L"\n";
    stream << L"credential: " << CredentialStatus() << L"\n";
    stream << L"dotenv: " << (settings_.DotEnvPath.empty() ? L"(none)" : settings_.DotEnvPath) << L"\n";
    stream << L"codex cli: " << (settings_.CodexCliPath.empty() ? L"codex" : settings_.CodexCliPath) << L"\n";
    if (!settings_.ReasoningEffort.empty())
    {
        stream << L"reasoning effort: " << settings_.ReasoningEffort << L"\n";
    }
    stream << L"timeout: " << settings_.TimeoutSeconds << L"s\n";
    if (AiModelCatalog::LiveModelCount() > 0)
    {
        stream << L"live models: " << AiModelCatalog::LiveModelCount() << L"\n";
    }

    return stream.str();
}

std::wstring AiProviderRuntime::HealthText() const
{
    std::wstringstream stream;
    const bool remoteBlocked =
        settings_.RemotePolicy == AiRemotePolicy::LocalOnly &&
        IsRemoteNetworkProvider(settings_.Provider);
    const bool missingKey =
        (settings_.Provider == AiProviderKind::DeepSeek ||
         settings_.Provider == AiProviderKind::OpenRouter) &&
        settings_.ApiKey.empty();
    const bool missingCodex =
        settings_.Provider == AiProviderKind::OpenAICodex &&
        CredentialStatus().find(L"missing") != std::wstring::npos;

    std::wstring state = L"ready";
    std::wstring next;
    if (settings_.Provider == AiProviderKind::Disabled)
    {
        state = L"off";
        next = L"ai use cloud";
        if (settings_.DotEnvPath.empty())
        {
            next += L"  (put .env next to KnLiveDbg.exe, not the repo root)";
        }
    }
    else if (remoteBlocked)
    {
        state = L"blocked";
        next = L"ai use private   or   ai config policy allow-remote";
    }
    else if (missingKey)
    {
        state = L"missing key";
        if (settings_.Provider == AiProviderKind::OpenRouter)
        {
            next = L"set KNLIVEDBG_OPENROUTER_API_KEY in the EXE-dir .env, then ai test";
        }
        else
        {
            next = L"set KNLIVEDBG_DEEPSEEK_API_KEY in the EXE-dir .env, then ai test";
        }
    }
    else if (missingCodex)
    {
        state = L"missing token";
        next = L"run codex login outside KnLiveDbg, then ai test";
    }
    else
    {
        next = L"ai test";
    }

    stream << L"AI: " << state << L"\n";

    AiPresetInfo preset = {};
    if (AiModelCatalog::DetectPreset(settings_.Provider, settings_.Model, &preset))
    {
        stream << L"  preset: " << preset.Name << L"\n";
    }

    stream << L"  using:  " << ProviderName();
    if (!settings_.Model.empty())
    {
        stream << L" / " << settings_.Model;
    }

    stream << L"\n";
    stream << L"  data:   " << RemotePolicyName() << L"\n";
    stream << L"  auth:   " << CredentialStatus() << L"\n";
    stream << L"  env:    " << (settings_.DotEnvPath.empty() ? L"(none next to KnLiveDbg.exe)" : settings_.DotEnvPath) << L"\n";
    if (AiModelCatalog::LiveModelCount() > 0)
    {
        stream << L"  live:   " << AiModelCatalog::LiveModelCount() << L" OpenRouter models cached\n";
    }

    stream << L"  next:   " << next << L"\n";
    return stream.str();
}

std::wstring AiProviderRuntime::ModelsText(const std::wstring& query) const
{
    return AiModelCatalog::ModelsText(settings_.Provider, settings_.Model, query);
}

bool AiProviderRuntime::ApplyUse(
    const std::wstring& spec,
    const std::wstring& modelOverride,
    std::wstring* error)
{
    bool ok = false;
    AiUseTarget target = {};

    do
    {
        if (!AiModelCatalog::Resolve(spec, &target, error))
        {
            break;
        }

        if (!Trim(modelOverride).empty())
        {
            AiUseTarget modelTarget = {};
            if (!AiModelCatalog::ResolveModel(modelOverride, &modelTarget, error))
            {
                break;
            }

            if (!AiModelCatalog::ModelFitsProvider(target.Provider, modelTarget, error))
            {
                break;
            }

            target.Model = modelTarget.Model;
            if (target.Preset.empty())
            {
                target.Provider = modelTarget.Provider;
            }
        }

        if (settings_.RemotePolicy == AiRemotePolicy::LocalOnly &&
            IsRemoteNetworkProvider(target.Provider))
        {
            if (error != nullptr)
            {
                *error = L"blocked by local-only policy. use: ai use private";
            }

            break;
        }

        if (settings_.Provider != target.Provider)
        {
            std::wstring providerName = AiModelCatalog::ProviderDisplayName(target.Provider);
            if (target.Provider == AiProviderKind::Disabled)
            {
                providerName = L"off";
            }

            if (!SetProvider(providerName, error))
            {
                break;
            }
        }

        if (target.Provider == AiProviderKind::Disabled)
        {
            settings_.Model.clear();
            settings_.BaseUrl.clear();
        }
        else if (!target.Model.empty())
        {
            SetModel(target.Model);
        }

        ok = true;
    } while (false);

    return ok;
}

bool AiProviderRuntime::SaveToDotEnv(std::wstring* savedPath, std::wstring* error)
{
    bool ok = false;
    std::wstring path = settings_.DotEnvWritePath.empty() ? settings_.DotEnvPath : settings_.DotEnvWritePath;

    do
    {
        if (path.empty())
        {
            std::wstring exeDir = ExecutableDirectory();
            if (exeDir.empty())
            {
                if (error != nullptr)
                {
                    *error = L"cannot locate KnLiveDbg.exe directory for .env";
                }

                break;
            }

            path = JoinPath(exeDir, L".env");
        }

        std::wstring existing;
        (void)ReadTextFileUtf8OrWide(path, &existing);

        std::wstring providerValue = ProviderName();
        if (providerValue == L"disabled")
        {
            providerValue = L"off";
        }

        std::vector<std::pair<std::wstring, std::wstring>> updates;
        updates.push_back({ L"KNLIVEDBG_AI_PROVIDER", providerValue });
        updates.push_back({ L"KNLIVEDBG_AI_MODEL", settings_.Model });
        updates.push_back({ L"KNLIVEDBG_AI_REMOTE_POLICY", RemotePolicyName() });

        std::vector<bool> written(updates.size(), false);
        std::wstring output;
        if (existing.empty())
        {
            output += L"# KnLiveDbg AI settings. This file is loaded from the EXE directory only.\n";
        }

        size_t offset = 0;
        while (offset <= existing.size())
        {
            size_t end = existing.find_first_of(L"\r\n", offset);
            std::wstring line;
            std::wstring newline = L"\n";
            if (end == std::wstring::npos)
            {
                line = existing.substr(offset);
                offset = existing.size() + 1;
            }
            else
            {
                line = existing.substr(offset, end - offset);
                if (end + 1 < existing.size() && existing[end] == L'\r' && existing[end + 1] == L'\n')
                {
                    newline = L"\r\n";
                    offset = end + 2;
                }
                else
                {
                    newline = existing.substr(end, 1);
                    offset = end + 1;
                }
            }

            std::wstring name;
            std::wstring value;
            bool replaced = false;
            if (ParseDotEnvLine(line, &name, &value))
            {
                for (size_t index = 0; index < updates.size(); ++index)
                {
                    if (updates[index].first == name)
                    {
                        output += name;
                        output += L"=";
                        output += EncodeDotEnvValue(updates[index].second);
                        output += newline;
                        written[index] = true;
                        replaced = true;
                        break;
                    }
                }
            }

            if (!replaced && !(offset > existing.size() && line.empty()))
            {
                output += line;
                if (offset <= existing.size())
                {
                    output += newline;
                }
            }
        }

        bool needLeadingNewline = !output.empty() && output.back() != L'\n';
        for (size_t index = 0; index < updates.size(); ++index)
        {
            if (written[index])
            {
                continue;
            }

            if (needLeadingNewline)
            {
                output += L"\n";
                needLeadingNewline = false;
            }

            output += updates[index].first;
            output += L"=";
            output += EncodeDotEnvValue(updates[index].second);
            output += L"\n";
        }

        const std::wstring tmpPath = path + L".tmp";
        if (!WriteTextFileUtf8(tmpPath, output, error))
        {
            break;
        }

        if (!MoveFileExW(tmpPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            DeleteFileW(tmpPath.c_str());
            if (error != nullptr)
            {
                *error = L"failed to replace " + path;
            }

            break;
        }

        for (const std::pair<std::wstring, std::wstring>& update : updates)
        {
            bool found = false;
            for (ConfigEntry& entry : dotEnvValues_)
            {
                if (entry.Name == update.first)
                {
                    entry.Value = update.second;
                    entry.Source = update.first + L" from " + path;
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                ConfigEntry entry = {};
                entry.Name = update.first;
                entry.Value = update.second;
                entry.Source = update.first + L" from " + path;
                dotEnvValues_.push_back(entry);
            }
        }

        if (savedPath != nullptr)
        {
            *savedPath = path;
        }

        settings_.DotEnvPath = path;
        settings_.DotEnvWritePath = path;
        ok = true;
    } while (false);

    return ok;
}

bool AiProviderRuntime::RefreshCloudModels(std::wstring* error)
{
    bool ok = false;

    do
    {
        if (settings_.RemotePolicy == AiRemotePolicy::LocalOnly)
        {
            if (error != nullptr)
            {
                *error = L"ai models refresh is blocked by local-only policy";
            }

            break;
        }

        std::wstring url = settings_.BaseUrl;
        if (settings_.Provider != AiProviderKind::OpenRouter || url.empty())
        {
            url = kDefaultOpenRouterBaseUrl;
        }

        url = Trim(url);
        while (!url.empty() && url.back() == L'/')
        {
            url.pop_back();
        }

        std::wstring lowered = ToLowerString(url);
        const wchar_t* suffixes[] = { L"/chat/completions", L"/models" };
        for (const wchar_t* suffix : suffixes)
        {
            size_t suffixLen = wcslen(suffix);
            if (lowered.size() >= suffixLen &&
                lowered.compare(lowered.size() - suffixLen, suffixLen, suffix) == 0)
            {
                url.resize(url.size() - suffixLen);
                lowered = ToLowerString(url);
            }
        }

        if (!url.empty() && url.back() == L'/')
        {
            url.pop_back();
        }

        url += L"/models";

        std::wstring headers = L"Accept: application/json\r\nHTTP-Referer: https://github.com/kernullist/kn-live-dbg\r\nX-Title: KnLiveDbg\r\n";
        std::wstring openRouterKey = settings_.ApiKey;
        if (settings_.Provider != AiProviderKind::OpenRouter || openRouterKey.empty())
        {
            openRouterKey = ConfigValue(L"KNLIVEDBG_OPENROUTER_API_KEY", nullptr);
            if (openRouterKey.empty())
            {
                openRouterKey = ConfigValue(L"OPENROUTER_API_KEY", nullptr);
            }
        }

        if (!openRouterKey.empty())
        {
            headers += L"Authorization: Bearer " + openRouterKey + L"\r\n";
        }

        HttpResult result = {};
        if (!HttpGet(url, headers, 30, &result, error))
        {
            break;
        }

        if (result.StatusCode >= 300)
        {
            if (error != nullptr)
            {
                *error = L"OpenRouter models HTTP " + std::to_wstring(result.StatusCode);
            }

            break;
        }

        std::vector<AiCloudModel> models;
        if (!AiModelCatalog::ParseOpenRouterModelsJson(result.Body, &models, error))
        {
            break;
        }

        if (models.empty())
        {
            if (error != nullptr)
            {
                *error = L"OpenRouter returned no usable text models";
            }

            break;
        }

        AiModelCatalog::SetLiveModels(models);
        ok = true;
    } while (false);

    return ok;
}

std::wstring AiProviderRuntime::AuthHelpText() const
{
    std::wstringstream stream;

    stream << L"AI auth sources:\n";
    stream << L"  .env file is loaded only from the executable directory\n";
    stream << L"  Prefer: ai use cloud | ai use grok | ai models refresh\n";
    stream << L"  KNLIVEDBG_AI_PROVIDER=openai-codex-cli|openai-codex-subscription|deepseek|openrouter\n";
    stream << L"  KNLIVEDBG_AI_REMOTE_POLICY=allow-remote|local-only\n";
    stream << L"  KNLIVEDBG_AI_MODEL=<model>\n";
    stream << L"  KNLIVEDBG_AI_BASE_URL=<provider base url>\n";
    stream << L"  KNLIVEDBG_DEEPSEEK_API_KEY or DEEPSEEK_API_KEY\n";
    stream << L"  KNLIVEDBG_OPENROUTER_API_KEY or OPENROUTER_API_KEY\n";
    stream << L"  KNLIVEDBG_CODEX_ACCESS_TOKEN or KERNFORGE_CODEX_ACCESS_TOKEN\n";
    stream << L"  KNLIVEDBG_CODEX_AUTH_FILE or KERNFORGE_CODEX_AUTH_FILE\n";
    stream << L"  default Codex auth files: %USERPROFILE%\\.kernforge\\codex_auth.json, %USERPROFILE%\\.codex\\auth.json\n";
    stream << L"  KNLIVEDBG_CODEX_CLI_PATH=<path to codex.exe>\n";
    stream << L"dotenv: " << (settings_.DotEnvPath.empty() ? L"(none loaded)" : settings_.DotEnvPath) << L"\n";
    stream << L"Run codex login outside KnLiveDbg when Codex OAuth credentials are missing.\n";

    return stream.str();
}

std::wstring AiProviderRuntime::PreviewText(const AiCompletionRequest& request) const
{
    std::wstringstream stream;

    stream << L"AI request preview\n";
    stream << L"provider: " << ProviderName() << L"\n";
    stream << L"model: " << (settings_.Model.empty() ? L"(default)" : settings_.Model) << L"\n";
    stream << L"base url: " << (settings_.BaseUrl.empty() ? L"(default)" : settings_.BaseUrl) << L"\n";
    stream << L"remote policy: " << RemotePolicyName() << L"\n";
    stream << L"credential: " << CredentialStatus() << L"\n";
    stream << L"system-bytes: " << WideToUtf8(request.System).size() << L"\n";
    stream << L"prompt-bytes: " << WideToUtf8(request.Prompt).size() << L"\n";
    stream << L"no request was sent\n";

    return stream.str();
}

bool AiProviderRuntime::Complete(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (response == nullptr)
        {
            break;
        }

        response->Text.clear();
        response->RawBody.clear();
        response->StatusCode = 0;
        response->Truncated = false;

        if (Trim(request.Prompt).empty())
        {
            if (error != nullptr)
            {
                *error = L"empty AI prompt";
            }
            break;
        }

        if (settings_.RemotePolicy == AiRemotePolicy::LocalOnly && IsRemoteNetworkProvider(settings_.Provider))
        {
            if (error != nullptr)
            {
                *error = L"AI provider is blocked by local-only remote policy";
            }
            break;
        }

        switch (settings_.Provider)
        {
        case AiProviderKind::CodexCli:
            ok = CompleteWithCodexCli(request, response, error);
            break;
        case AiProviderKind::OpenAICodex:
            ok = CompleteWithOpenAICodex(request, response, error);
            break;
        case AiProviderKind::DeepSeek:
        case AiProviderKind::OpenRouter:
            ok = CompleteWithOpenAICompatible(request, response, error);
            break;
        default:
            if (error != nullptr)
            {
                *error = L"AI provider is disabled; run ai use cloud or set KNLIVEDBG_AI_PROVIDER";
            }
            break;
        }
    } while (false);

    return ok;
}

std::vector<std::wstring> AiProviderRuntime::SupportedProviderNames()
{
    return {
        L"openai-codex-cli",
        L"openai-codex-subscription",
        L"deepseek",
        L"openrouter"
    };
}

bool AiProviderRuntime::NormalizeProviderName(const std::wstring& value, AiProviderKind* provider, std::wstring* normalized)
{
    bool ok = false;
    std::wstring text = ToLowerString(Trim(value));

    do
    {
        if (provider == nullptr)
        {
            break;
        }

        if (text == L"off" || text == L"none" || text == L"disabled")
        {
            *provider = AiProviderKind::Disabled;
            if (normalized != nullptr)
            {
                *normalized = L"disabled";
            }
            ok = true;
        }
        else if (text == L"codex" || text == L"codex-cli" || text == L"codex_cli" ||
                 text == L"openai-codex-cli" || text == L"openai_codex_cli")
        {
            *provider = AiProviderKind::CodexCli;
            if (normalized != nullptr)
            {
                *normalized = L"openai-codex-cli";
            }
            ok = true;
        }
        else if (text == L"chatgpt" || text == L"openai-codex" || text == L"openai_codex" ||
                 text == L"openai-codex-subscription" || text == L"codex-subscription")
        {
            *provider = AiProviderKind::OpenAICodex;
            if (normalized != nullptr)
            {
                *normalized = L"openai-codex-subscription";
            }
            ok = true;
        }
        else if (text == L"deepseek" || text == L"deepseek-api" || text == L"deepseek_api")
        {
            *provider = AiProviderKind::DeepSeek;
            if (normalized != nullptr)
            {
                *normalized = L"deepseek";
            }
            ok = true;
        }
        else if (text == L"openrouter" || text == L"open-router" || text == L"open_router")
        {
            *provider = AiProviderKind::OpenRouter;
            if (normalized != nullptr)
            {
                *normalized = L"openrouter";
            }
            ok = true;
        }
    } while (false);

    return ok;
}

void AiProviderRuntime::ApplyProviderDefaults(bool preserveModel)
{
    if (settings_.Provider == AiProviderKind::Disabled)
    {
        settings_.Model.clear();
        settings_.BaseUrl.clear();
        return;
    }

    if (!preserveModel)
    {
        settings_.BaseUrl.clear();
    }

    if (!preserveModel || settings_.Model.empty())
    {
        switch (settings_.Provider)
        {
        case AiProviderKind::CodexCli:
            settings_.Model = L"default";
            break;
        case AiProviderKind::OpenAICodex:
            settings_.Model = L"gpt-5.5";
            break;
        case AiProviderKind::DeepSeek:
            settings_.Model = L"deepseek-chat";
            break;
        case AiProviderKind::OpenRouter:
            settings_.Model = L"anthropic/claude-opus-5";
            break;
        default:
            settings_.Model.clear();
            break;
        }
    }

    if (settings_.Provider == AiProviderKind::OpenAICodex && settings_.BaseUrl.empty())
    {
        settings_.BaseUrl = kDefaultCodexBaseUrl;
    }
    else if (settings_.Provider == AiProviderKind::DeepSeek && settings_.BaseUrl.empty())
    {
        settings_.BaseUrl = kDefaultDeepSeekBaseUrl;
    }
    else if (settings_.Provider == AiProviderKind::OpenRouter && settings_.BaseUrl.empty())
    {
        settings_.BaseUrl = kDefaultOpenRouterBaseUrl;
    }
}

void AiProviderRuntime::LoadCredentials()
{
    settings_.ApiKey.clear();
    settings_.ApiKeySource.clear();

    if (settings_.Provider == AiProviderKind::DeepSeek)
    {
        std::wstring source;
        settings_.ApiKey = ConfigValue(L"KNLIVEDBG_DEEPSEEK_API_KEY", &source);
        settings_.ApiKeySource = source;
        if (settings_.ApiKey.empty())
        {
            settings_.ApiKey = ConfigValue(L"DEEPSEEK_API_KEY", &source);
            settings_.ApiKeySource = source;
        }
    }
    else if (settings_.Provider == AiProviderKind::OpenRouter)
    {
        std::wstring source;
        settings_.ApiKey = ConfigValue(L"KNLIVEDBG_OPENROUTER_API_KEY", &source);
        settings_.ApiKeySource = source;
        if (settings_.ApiKey.empty())
        {
            settings_.ApiKey = ConfigValue(L"OPENROUTER_API_KEY", &source);
            settings_.ApiKeySource = source;
        }
    }

    if (settings_.CodexCliPath.empty())
    {
        settings_.CodexCliPath = L"codex";
    }
}

bool AiProviderRuntime::CompleteWithCodexCli(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error) const
{
    bool ok = false;
    std::wstring tempFile;

    do
    {
        std::wstring rendered = RenderPrompt(request);
        std::wstring promptArg;
        if (!CreatePromptArgument(rendered, &promptArg, &tempFile, error))
        {
            break;
        }

        std::wstring executable = settings_.CodexCliPath.empty() ? L"codex" : settings_.CodexCliPath;
        std::wstring commandLine = QuoteCommandLineArg(executable) + L" exec";
        if (!settings_.Model.empty() && settings_.Model != L"default")
        {
            commandLine += L" -c ";
            commandLine += QuoteCommandLineArg(L"model=" + settings_.Model);
        }
        commandLine += L" ";
        commandLine += QuoteCommandLineArg(promptArg);

        std::wstring output;
        uint32_t exitCode = 1;
        if (!RunProcessCapture(commandLine, settings_.TimeoutSeconds, &output, &exitCode, error))
        {
            break;
        }

        if (exitCode != 0)
        {
            if (error != nullptr)
            {
                *error = L"Codex CLI exited with code " + std::to_wstring(exitCode);
                if (!output.empty())
                {
                    *error += L": " + output;
                }
            }
            break;
        }

        response->Text = output;
        response->RawBody = output;
        response->StatusCode = 0;
        ok = true;
    } while (false);

    if (!tempFile.empty())
    {
        DeleteFileW(tempFile.c_str());
    }

    return ok;
}

bool AiProviderRuntime::CompleteWithOpenAICompatible(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error) const
{
    bool ok = false;

    do
    {
        if (settings_.ApiKey.empty())
        {
            if (error != nullptr)
            {
                *error = ProviderName() + L" API key is missing; run ai auth";
            }
            break;
        }

        std::ostringstream body;
        body << "{";
        body << "\"model\":\"" << JsonEscape(settings_.Model) << "\",";
        body << "\"messages\":[";
        body << "{\"role\":\"system\",\"content\":\"" << JsonEscape(request.System) << "\"},";
        body << "{\"role\":\"user\",\"content\":\"" << JsonEscape(request.Prompt) << "\"}";
        body << "],";
        body << "\"temperature\":0.2,";
        body << "\"max_tokens\":8192";
        if (settings_.Provider == AiProviderKind::OpenRouter)
        {
            // TUI reports should not dump chain-of-thought. Disable reasoning
            // unless the operator set an effort, and never return reasoning
            // tokens even when the model still thinks internally.
            body << ",\"reasoning\":{";
            if (!settings_.ReasoningEffort.empty())
            {
                body << "\"effort\":\"" << JsonEscape(settings_.ReasoningEffort) << "\",";
            }
            else
            {
                body << "\"enabled\":false,";
            }

            body << "\"exclude\":true}";
        }
        else if (settings_.Provider == AiProviderKind::DeepSeek && !settings_.ReasoningEffort.empty())
        {
            body << ",\"reasoning_effort\":\"" << JsonEscape(settings_.ReasoningEffort) << "\"";
            body << ",\"thinking\":{\"type\":\"enabled\"}";
        }
        body << "}";

        std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer " + settings_.ApiKey + L"\r\n";
        if (settings_.Provider == AiProviderKind::OpenRouter)
        {
            headers += L"HTTP-Referer: https://github.com/kernullist/kn-live-dbg\r\nX-Title: KnLiveDbg\r\n";
        }

        HttpResult result = {};
        if (!HttpPost(OpenAICompatibleUrl(settings_.Provider, settings_.BaseUrl), headers, body.str(), settings_.TimeoutSeconds, &result, error))
        {
            break;
        }

        response->StatusCode = result.StatusCode;
        response->RawBody = result.Body;
        if (result.StatusCode >= 300)
        {
            if (error != nullptr)
            {
                *error = ProviderName() + L" API error " + std::to_wstring(result.StatusCode) + L": " + ExtractProviderError(result.Body);
            }
            break;
        }

        response->Text = ExtractAssistantText(result.Body, &response->Truncated);
        if (response->Text.empty())
        {
            if (error != nullptr)
            {
                if (response->Truncated)
                {
                    *error = ProviderName() + L" returned only truncated reasoning; try ai test or a non-reasoning model";
                }
                else
                {
                    *error = ProviderName() + L" returned no assistant text";
                }
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool AiProviderRuntime::CompleteWithOpenAICodex(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error) const
{
    bool ok = false;

    do
    {
        std::wstring access;
        std::wstring refresh;
        std::wstring source;
        if (!ResolveCodexTokens(&access, &refresh, &source))
        {
            if (error != nullptr)
            {
                *error = L"OpenAI Codex OAuth token is missing; run codex login outside KnLiveDbg or set KNLIVEDBG_CODEX_ACCESS_TOKEN";
            }
            break;
        }

        if (access.empty() && !RefreshCodexAccessToken(settings_, refresh, &access, error))
        {
            break;
        }

        std::ostringstream body;
        body << "{";
        body << "\"model\":\"" << JsonEscape(settings_.Model) << "\",";
        body << "\"instructions\":\"" << JsonEscape(request.System) << "\",";
        body << "\"input\":[{\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"" << JsonEscape(request.Prompt) << "\"}]}],";
        body << "\"store\":false,";
        body << "\"stream\":false";
        if (!settings_.ReasoningEffort.empty())
        {
            body << ",\"reasoning\":{\"effort\":\"" << JsonEscape(settings_.ReasoningEffort) << "\"}";
        }
        body << "}";

        std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer " + access + L"\r\nOriginator: codex_cli_rs\r\n";
        HttpResult result = {};
        if (!HttpPost(CodexApiUrl(settings_.BaseUrl), headers, body.str(), settings_.TimeoutSeconds, &result, error))
        {
            break;
        }

        if ((result.StatusCode == 401 || result.StatusCode == 403) && !refresh.empty())
        {
            std::wstring refreshed;
            if (RefreshCodexAccessToken(settings_, refresh, &refreshed, error))
            {
                headers = L"Content-Type: application/json\r\nAccept: application/json\r\nAuthorization: Bearer " + refreshed + L"\r\nOriginator: codex_cli_rs\r\n";
                result = {};
                if (!HttpPost(CodexApiUrl(settings_.BaseUrl), headers, body.str(), settings_.TimeoutSeconds, &result, error))
                {
                    break;
                }
            }
        }

        response->StatusCode = result.StatusCode;
        response->RawBody = result.Body;
        if (result.StatusCode >= 300)
        {
            if (error != nullptr)
            {
                *error = L"OpenAI Codex API error " + std::to_wstring(result.StatusCode) + L": " + ExtractProviderError(result.Body);
            }
            break;
        }

        response->Text = ExtractAssistantText(result.Body, &response->Truncated);
        if (response->Text.empty())
        {
            if (error != nullptr)
            {
                *error = L"OpenAI Codex returned no assistant text";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool AiProviderRuntime::ParseAssistantSelfTest()
{
    bool ok = false;

    do
    {
        bool truncated = false;
        const std::wstring reasoningOnly =
            L"{\"choices\":[{\"finish_reason\":\"length\",\"native_finish_reason\":\"length\","
            L"\"message\":{\"role\":\"assistant\",\"content\":\"\","
            L"\"reasoning\":\"We need to explain the output\","
            L"\"reasoning_details\":[{\"type\":\"reasoning.text\",\"text\":\"We need to explain the output\"}]}}]}";
        std::wstring text = ExtractAssistantText(reasoningOnly, &truncated);
        if (!text.empty() || !truncated)
        {
            break;
        }

        const std::wstring mixed =
            L"{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
            L"\"content\":\"## Findings\\n- UCPD.sys\","
            L"\"reasoning\":\"We need to explain the output\","
            L"\"reasoning_details\":[{\"type\":\"reasoning.text\",\"text\":\"We need to explain\"}]}}]}";
        truncated = true;
        text = ExtractAssistantText(mixed, &truncated);
        if (truncated || text != L"## Findings\n- UCPD.sys" || text.find(L"We need to") != std::wstring::npos)
        {
            break;
        }

        const std::wstring normal =
            L"{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\","
            L"\"content\":\"## Findings\\n- UCPD.sys and WdFilter.sys registered Process callbacks.\"}}]}";
        truncated = true;
        text = ExtractAssistantText(normal, &truncated);
        if (truncated || text.find(L"UCPD.sys") == std::wstring::npos || text.find(L"We need to") != std::wstring::npos)
        {
            break;
        }

        const std::wstring arrayContent =
            L"{\"choices\":[{\"message\":{\"content\":["
            L"{\"type\":\"reasoning\",\"text\":\"ignore me\"},"
            L"{\"type\":\"thinking\",\"text\":\"also ignore\"},"
            L"{\"type\":\"text\",\"text\":\"Hello \"},"
            L"{\"type\":\"text\",\"text\":\"world\"}]}}]}";
        truncated = false;
        text = ExtractAssistantText(arrayContent, &truncated);
        if (text != L"Hello world" || truncated)
        {
            break;
        }

        const std::wstring legacy =
            L"{\"choices\":[{\"text\":\"legacy completion\",\"finish_reason\":\"stop\"}]}";
        truncated = true;
        text = ExtractAssistantText(legacy, &truncated);
        if (truncated || text != L"legacy completion")
        {
            break;
        }

        const std::wstring outputArray =
            L"{\"status\":\"completed\",\"output\":["
            L"{\"type\":\"reasoning\",\"content\":[{\"type\":\"reasoning.text\",\"text\":\"ignore\"}]},"
            L"{\"type\":\"message\",\"role\":\"assistant\",\"content\":["
            L"{\"type\":\"output_text\",\"text\":\"Codex report\"}]}]}";
        truncated = true;
        text = ExtractAssistantText(outputArray, &truncated);
        if (truncated || text != L"Codex report")
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
