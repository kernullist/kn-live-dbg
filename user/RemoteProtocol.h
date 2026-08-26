#pragma once

// KNR1 framed JSON protocol for the remote operator session.
// v1 is cleartext TCP. See docs/REMOTE_OPERATOR_SESSION.md.

#include "McpJson.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace knremote
{
    static constexpr uint32_t kMagic = 0x31524E4B; // 'KNR1' little-endian
    static constexpr uint16_t kDefaultPort = 51767;
    static constexpr uint16_t kMcpPort = 51766;
    static constexpr uint32_t kMaxFrameBytes = 1024u * 1024u;
    static constexpr uint32_t kMaxCommandChars = 8192;
    static constexpr uint32_t kResultChunkBytes = 256u * 1024u;
    static constexpr uint32_t kInlineTruncateBytes = 8u * 1024u * 1024u;
    static constexpr DWORD kHeartbeatMs = 15000;
    static constexpr DWORD kDeadPeerMs = 60000;
    static constexpr DWORD kAuthDeadlineMs = 10000;
    static constexpr DWORD kFrameDeadlineMs = 60000;
    static constexpr int kAuthFailLockout = 5;
    static constexpr int kGlobalAuthLockout = 15;
    static constexpr size_t kMaxPending = 4;
    static constexpr int kPasswordMin = 5;
    static constexpr int kPasswordMax = 128;

    // Wrap-safe: true once GetTickCount has reached deadlineTick.
    inline bool DeadlineReached(DWORD deadlineTick)
    {
        return static_cast<int32_t>(GetTickCount() - deadlineTick) >= 0;
    }

    inline bool IntervalElapsed(DWORD startTick, DWORD intervalMs)
    {
        return static_cast<int32_t>(GetTickCount() - startTick) >=
               static_cast<int32_t>(intervalMs);
    }

    // Largest index in (offset, offset+maxBytes] that does not split a UTF-8
    // sequence. Used when chunking command-result stdout.
    inline size_t Utf8ChunkEnd(const std::string& utf8, size_t offset, size_t maxBytes)
    {
        if (offset >= utf8.size() || maxBytes == 0)
        {
            return offset;
        }
        size_t end = offset + maxBytes;
        if (end >= utf8.size())
        {
            return utf8.size();
        }
        while (end > offset &&
               (static_cast<unsigned char>(utf8[end]) & 0xC0) == 0x80)
        {
            --end;
        }
        if (end == offset)
        {
            return (offset + maxBytes < utf8.size()) ? (offset + maxBytes) : utf8.size();
        }
        return end;
    }

    // Do not split an ESC CSI sequence across command-result chunks.
    inline size_t ColorSafeChunkEnd(const std::string& utf8, size_t offset, size_t maxBytes)
    {
        const size_t end = Utf8ChunkEnd(utf8, offset, maxBytes);
        if (end <= offset)
        {
            return end;
        }

        size_t lastEsc = std::string::npos;
        for (size_t i = offset; i < end; ++i)
        {
            if (static_cast<unsigned char>(utf8[i]) == 0x1b)
            {
                lastEsc = i;
            }
        }
        if (lastEsc == std::string::npos)
        {
            return end;
        }

        bool terminated = false;
        for (size_t i = lastEsc + 1; i < end; ++i)
        {
            const unsigned char ch = static_cast<unsigned char>(utf8[i]);
            if (ch == 0x5B)
            {
                continue;
            }
            if (ch >= 0x40 && ch <= 0x7E)
            {
                terminated = true;
                break;
            }
        }
        if (terminated)
        {
            return end;
        }
        if (lastEsc > offset)
        {
            return lastEsc;
        }

        size_t limit = offset + 16;
        if (limit > utf8.size())
        {
            limit = utf8.size();
        }
        for (size_t i = offset + 1; i < limit; ++i)
        {
            const unsigned char ch = static_cast<unsigned char>(utf8[i]);
            if (ch == 0x5B)
            {
                continue;
            }
            if (ch >= 0x40 && ch <= 0x7E)
            {
                return i + 1;
            }
        }
        return end;
    }

    // ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004). False on pipes/files.
    inline bool EnableVirtualTerminalHandle(HANDLE handle)
    {
        DWORD mode = 0;
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        if (!GetConsoleMode(handle, &mode))
        {
            return false;
        }
        return SetConsoleMode(handle, mode | 0x0004) != FALSE;
    }

    inline bool EnableVirtualTerminalConsoles()
    {
        const bool outOk = EnableVirtualTerminalHandle(GetStdHandle(STD_OUTPUT_HANDLE));
        const bool errOk = EnableVirtualTerminalHandle(GetStdHandle(STD_ERROR_HANDLE));
        return outOk || errOk;
    }

    // Drop CSI SGR (and other CSI) so piped/file output stays readable.
    inline std::wstring StripVtSequences(const std::wstring& text)
    {
        std::wstring out;
        out.reserve(text.size());
        for (size_t i = 0; i < text.size(); ++i)
        {
            if (text[i] != 0x1b)
            {
                out.push_back(text[i]);
                continue;
            }
            if (i + 1 < text.size() && text[i + 1] == L'[')
            {
                i += 2;
                while (i < text.size())
                {
                    const wchar_t ch = text[i];
                    if (ch >= 0x40 && ch <= 0x7E)
                    {
                        break;
                    }
                    ++i;
                }
                continue;
            }
        }
        return out;
    }

    inline uint64_t UnixTimeMs()
    {
        FILETIME ft = {};
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER value = {};
        value.LowPart = ft.dwLowDateTime;
        value.HighPart = ft.dwHighDateTime;
        const uint64_t epochDiff = 116444736000000000ull;
        if (value.QuadPart < epochDiff)
        {
            return 0;
        }
        return (value.QuadPart - epochDiff) / 10000ull;
    }

    inline bool ConstantTimeEqual(const std::string& left, const std::string& right)
    {
        const size_t n = left.size() > right.size() ? left.size() : right.size();
        unsigned char acc = static_cast<unsigned char>(left.size() ^ right.size());
        for (size_t i = 0; i < n; ++i)
        {
            const unsigned char a = i < left.size() ? static_cast<unsigned char>(left[i]) : 0;
            const unsigned char b = i < right.size() ? static_cast<unsigned char>(right[i]) : 0;
            acc = static_cast<unsigned char>(acc | (a ^ b));
        }
        return acc == 0;
    }

    inline bool SanitizeRemotePassword(
        const std::wstring& raw,
        std::wstring* password,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (password == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid remote password output";
                }
                break;
            }

            password->clear();
            size_t begin = 0;
            while (begin < raw.size() && (raw[begin] == L' ' || raw[begin] == L'\t'))
            {
                ++begin;
            }
            size_t end = raw.size();
            while (end > begin && (raw[end - 1] == L' ' || raw[end - 1] == L'\t' ||
                                   raw[end - 1] == L'\r' || raw[end - 1] == L'\n'))
            {
                --end;
            }
            const std::wstring value = raw.substr(begin, end - begin);
            if (value.size() < static_cast<size_t>(kPasswordMin) ||
                value.size() > static_cast<size_t>(kPasswordMax))
            {
                if (error != nullptr)
                {
                    *error = L"remote password must be 5-128 printable ASCII characters without spaces";
                }
                break;
            }

            bool printable = true;
            for (wchar_t ch : value)
            {
                if (ch < 0x21 || ch > 0x7e)
                {
                    printable = false;
                    break;
                }
            }
            if (!printable)
            {
                if (error != nullptr)
                {
                    *error = L"remote password must be 5-128 printable ASCII characters without spaces";
                }
                break;
            }

            *password = value;
            ok = true;
        } while (false);

        return ok;
    }

    inline bool IsLoopbackBind(const std::wstring& bindAddress)
    {
        return bindAddress == L"127.0.0.1" ||
               bindAddress == L"loopback" ||
               bindAddress == L"localhost";
    }

    inline bool IsWildcardBind(const std::wstring& bindAddress)
    {
        return bindAddress.empty() ||
               bindAddress == L"0.0.0.0" ||
               bindAddress == L"*" ||
               bindAddress == L"+";
    }

    inline std::wstring NormalizeBindAddress(const std::wstring& bindAddress)
    {
        if (IsLoopbackBind(bindAddress))
        {
            return L"127.0.0.1";
        }
        if (IsWildcardBind(bindAddress))
        {
            return L"0.0.0.0";
        }
        return bindAddress;
    }

    inline bool ParseIpv4(const std::wstring& text, in_addr* addr)
    {
        bool ok = false;
        do
        {
            if (addr == nullptr || text.empty())
            {
                break;
            }
            const std::string utf8 = mcpjson::WideToUtf8(text);
            if (inet_pton(AF_INET, utf8.c_str(), addr) != 1)
            {
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    inline bool IsPrivateIpv4(const in_addr& addr)
    {
        const uint32_t host = ntohl(addr.s_addr);
        const uint32_t b1 = (host >> 24) & 0xffu;
        const uint32_t b2 = (host >> 16) & 0xffu;
        if (b1 == 10)
        {
            return true;
        }
        if (b1 == 127)
        {
            return true;
        }
        if (b1 == 169 && b2 == 254)
        {
            return true;
        }
        if (b1 == 172 && b2 >= 16 && b2 <= 31)
        {
            return true;
        }
        if (b1 == 192 && b2 == 168)
        {
            return true;
        }
        return false;
    }

    inline bool ParseHostPort(
        const std::wstring& text,
        std::wstring* host,
        uint16_t* port,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (host == nullptr || port == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"invalid connect output";
                }
                break;
            }

            const size_t colon = text.rfind(L':');
            if (colon == std::wstring::npos || colon == 0 || colon + 1 >= text.size())
            {
                if (error != nullptr)
                {
                    *error = L"usage: KnLiveDbg.exe --connect <ipv4>:<port>";
                }
                break;
            }

            const std::wstring ip = text.substr(0, colon);
            const std::wstring portText = text.substr(colon + 1);
            in_addr addr = {};
            if (!ParseIpv4(ip, &addr))
            {
                if (error != nullptr)
                {
                    *error = L"--connect requires an IPv4 literal";
                }
                break;
            }

            wchar_t* end = nullptr;
            const unsigned long parsed = wcstoul(portText.c_str(), &end, 10);
            if (end == portText.c_str() || (end != nullptr && *end != 0) ||
                parsed == 0 || parsed > 65535)
            {
                if (error != nullptr)
                {
                    *error = L"--connect port must be 1-65535";
                }
                break;
            }

            *host = ip;
            *port = static_cast<uint16_t>(parsed);
            ok = true;
        } while (false);

        return ok;
    }

    inline std::wstring Quote(const std::wstring& value)
    {
        std::wstring out = L"\"";
        out += mcpjson::Escape(value);
        out += L"\"";
        return out;
    }

    inline std::wstring MakeObject(
        const wchar_t* type,
        const std::wstring& id,
        const std::wstring& extra)
    {
        std::wstring json = L"{\"v\":1,\"type\":";
        json += Quote(type);
        json += L",\"id\":";
        json += Quote(id);
        json += L",\"ts\":";
        json += std::to_wstring(UnixTimeMs());
        if (!extra.empty())
        {
            json += L",";
            json += extra;
        }
        json += L"}";
        return json;
    }

    inline bool EncodeFrame(const std::wstring& json, std::string* bytes, std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (bytes == nullptr)
            {
                break;
            }
            const std::string body = mcpjson::WideToUtf8(json);
            if (body.size() > kMaxFrameBytes)
            {
                if (error != nullptr)
                {
                    *error = L"frame too large";
                }
                break;
            }
            bytes->clear();
            bytes->push_back(static_cast<char>(kMagic & 0xffu));
            bytes->push_back(static_cast<char>((kMagic >> 8) & 0xffu));
            bytes->push_back(static_cast<char>((kMagic >> 16) & 0xffu));
            bytes->push_back(static_cast<char>((kMagic >> 24) & 0xffu));
            const uint32_t length = static_cast<uint32_t>(body.size());
            bytes->push_back(static_cast<char>(length & 0xffu));
            bytes->push_back(static_cast<char>((length >> 8) & 0xffu));
            bytes->push_back(static_cast<char>((length >> 16) & 0xffu));
            bytes->push_back(static_cast<char>((length >> 24) & 0xffu));
            bytes->append(body);
            ok = true;
        } while (false);
        return ok;
    }

    inline bool DecodeHeader(
        const unsigned char header[8],
        uint32_t* length,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (header == nullptr || length == nullptr)
            {
                break;
            }
            const uint32_t magic =
                static_cast<uint32_t>(header[0]) |
                (static_cast<uint32_t>(header[1]) << 8) |
                (static_cast<uint32_t>(header[2]) << 16) |
                (static_cast<uint32_t>(header[3]) << 24);
            if (magic != kMagic)
            {
                if (error != nullptr)
                {
                    *error = L"bad magic";
                }
                break;
            }
            *length =
                static_cast<uint32_t>(header[4]) |
                (static_cast<uint32_t>(header[5]) << 8) |
                (static_cast<uint32_t>(header[6]) << 16) |
                (static_cast<uint32_t>(header[7]) << 24);
            if (*length == 0 || *length > kMaxFrameBytes)
            {
                if (error != nullptr)
                {
                    *error = L"invalid frame length";
                }
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    inline size_t FindKey(const std::wstring& json, const wchar_t* key)
    {
        std::wstring needle = L"\"";
        needle += key;
        needle += L"\"";
        size_t pos = 0;
        while (pos < json.size())
        {
            const size_t found = json.find(needle, pos);
            if (found == std::wstring::npos)
            {
                return std::wstring::npos;
            }
            size_t colon = found + needle.size();
            while (colon < json.size() && (json[colon] == L' ' || json[colon] == L'\t'))
            {
                ++colon;
            }
            if (colon < json.size() && json[colon] == L':')
            {
                return colon + 1;
            }
            pos = found + 1;
        }
        return std::wstring::npos;
    }

    inline bool GetStringField(const std::wstring& json, const wchar_t* key, std::wstring* value)
    {
        bool ok = false;
        do
        {
            if (value == nullptr)
            {
                break;
            }
            value->clear();
            size_t pos = FindKey(json, key);
            if (pos == std::wstring::npos)
            {
                break;
            }
            while (pos < json.size() && (json[pos] == L' ' || json[pos] == L'\t'))
            {
                ++pos;
            }
            if (pos >= json.size() || json[pos] != L'\"')
            {
                break;
            }
            ++pos;
            std::wstring out;
            bool terminated = false;
            while (pos < json.size())
            {
                wchar_t ch = json[pos++];
                if (ch == L'\\')
                {
                    if (pos >= json.size())
                    {
                        break;
                    }
                    wchar_t next = json[pos++];
                    if (next == L'\"' || next == L'\\' || next == L'/')
                    {
                        out.push_back(next);
                    }
                    else if (next == L'n')
                    {
                        out.push_back(L'\n');
                    }
                    else if (next == L'r')
                    {
                        out.push_back(L'\r');
                    }
                    else if (next == L't')
                    {
                        out.push_back(L'\t');
                    }
                    else if (next == L'u')
                    {
                        if (pos + 4 > json.size())
                        {
                            break;
                        }
                        unsigned int codepoint = 0;
                        bool hexOk = true;
                        for (int i = 0; i < 4; ++i)
                        {
                            const wchar_t hex = json[pos++];
                            codepoint <<= 4;
                            if (hex >= L'0' && hex <= L'9')
                            {
                                codepoint += static_cast<unsigned int>(hex - L'0');
                            }
                            else if (hex >= L'a' && hex <= L'f')
                            {
                                codepoint += static_cast<unsigned int>(hex - L'a' + 10);
                            }
                            else if (hex >= L'A' && hex <= L'F')
                            {
                                codepoint += static_cast<unsigned int>(hex - L'A' + 10);
                            }
                            else
                            {
                                hexOk = false;
                                break;
                            }
                        }
                        if (!hexOk)
                        {
                            break;
                        }
                        out.push_back(static_cast<wchar_t>(codepoint));
                    }
                    else
                    {
                        out.push_back(next);
                    }
                    continue;
                }
                if (ch == L'\"')
                {
                    terminated = true;
                    break;
                }
                out.push_back(ch);
            }
            if (!terminated)
            {
                break;
            }
            *value = out;
            ok = true;
        } while (false);
        return ok;
    }

    inline bool GetNumberField(const std::wstring& json, const wchar_t* key, int64_t* value)
    {
        bool ok = false;
        do
        {
            if (value == nullptr)
            {
                break;
            }
            size_t pos = FindKey(json, key);
            if (pos == std::wstring::npos)
            {
                break;
            }
            while (pos < json.size() && (json[pos] == L' ' || json[pos] == L'\t'))
            {
                ++pos;
            }
            wchar_t* end = nullptr;
            const long long parsed = wcstoll(json.c_str() + pos, &end, 10);
            if (end == json.c_str() + pos)
            {
                break;
            }
            *value = parsed;
            ok = true;
        } while (false);
        return ok;
    }

    inline bool GetBoolField(const std::wstring& json, const wchar_t* key, bool* value)
    {
        bool ok = false;
        do
        {
            if (value == nullptr)
            {
                break;
            }
            size_t pos = FindKey(json, key);
            if (pos == std::wstring::npos)
            {
                break;
            }
            while (pos < json.size() && (json[pos] == L' ' || json[pos] == L'\t'))
            {
                ++pos;
            }
            if (json.compare(pos, 4, L"true") == 0)
            {
                *value = true;
                ok = true;
                break;
            }
            if (json.compare(pos, 5, L"false") == 0)
            {
                *value = false;
                ok = true;
                break;
            }
        } while (false);
        return ok;
    }

    inline std::vector<std::wstring> SplitLine(const std::wstring& line)
    {
        std::vector<std::wstring> args;
        std::wstring current;
        for (wchar_t ch : line)
        {
            if (ch == L' ' || ch == L'\t')
            {
                if (!current.empty())
                {
                    args.push_back(current);
                    current.clear();
                }
            }
            else
            {
                current.push_back(ch);
            }
        }
        if (!current.empty())
        {
            args.push_back(current);
        }
        return args;
    }
}
