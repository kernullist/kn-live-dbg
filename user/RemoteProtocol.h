#pragma once

// KNR1 framed JSON protocol for the remote operator session.
// v1 is cleartext TCP. See docs/REMOTE_OPERATOR_SESSION.md.

#include "McpJson.h"
#include "CommandInput.h"

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
    static constexpr DWORD kAuthFirstByteMs = 1000;
    static constexpr DWORD kFrameDeadlineMs = 60000;
    static constexpr DWORD kCloseDrainMs = 500;
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

    inline void EnableTcpNoDelay(SOCKET sock)
    {
        if (sock == INVALID_SOCKET)
        {
            return;
        }
        BOOL nodelay = TRUE;
        setsockopt(
            sock,
            IPPROTO_TCP,
            TCP_NODELAY,
            reinterpret_cast<const char*>(&nodelay),
            sizeof(nodelay));
    }

    // Unread recv data plus SD_BOTH makes Windows RST, which drops the last
    // sent frame (auth-err / auth-ok) before the client can read it.
    inline void CloseTcpGraceful(SOCKET sock, DWORD drainMs)
    {
        if (sock == INVALID_SOCKET)
        {
            return;
        }
        shutdown(sock, SD_SEND);
        const DWORD deadline = GetTickCount() + drainMs;
        char sink[256];
        while (!DeadlineReached(deadline))
        {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(sock, &readSet);
            timeval timeout = {};
            timeout.tv_sec = 0;
            timeout.tv_usec = 50000;
            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready <= 0)
            {
                break;
            }
            const int n = recv(sock, sink, static_cast<int>(sizeof(sink)), 0);
            if (n <= 0)
            {
                break;
            }
        }
        closesocket(sock);
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
        size_t acc = left.size() ^ right.size();
        for (size_t i = 0; i < n; ++i)
        {
            const unsigned char a = i < left.size() ? static_cast<unsigned char>(left[i]) : 0;
            const unsigned char b = i < right.size() ? static_cast<unsigned char>(right[i]) : 0;
            acc |= static_cast<size_t>(a ^ b);
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
            if (addr == nullptr || text.empty() || text.find(L'\0') != std::wstring::npos)
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

            uint16_t parsed = 0;
            if (!commandinput::ParsePort(portText, &parsed))
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

    inline bool GetStringField(const std::wstring& json, const wchar_t* key, std::wstring* value)
    {
        return key != nullptr && mcpjson::GetString(json, key, value);
    }

    inline bool GetNumberField(const std::wstring& json, const wchar_t* key, int64_t* value)
    {
        bool ok = false;
        do
        {
            std::wstring raw;
            if (key == nullptr || value == nullptr || !mcpjson::FindRawValue(json, key, &raw) || raw.empty())
            {
                break;
            }
            const bool negative = raw[0] == L'-';
            uint64_t magnitude = 0;
            const uint64_t limit = static_cast<uint64_t>((std::numeric_limits<int64_t>::max)()) + (negative ? 1ull : 0ull);
            if (!commandinput::ParseDigits(negative ? raw.substr(1) : raw, 10, &magnitude) || magnitude > limit)
            {
                break;
            }
            *value = negative
                ? (magnitude == limit ? (std::numeric_limits<int64_t>::min)() : -static_cast<int64_t>(magnitude))
                : static_cast<int64_t>(magnitude);
            ok = true;
        } while (false);
        return ok;
    }

    inline bool GetBoolField(const std::wstring& json, const wchar_t* key, bool* value)
    {
        std::wstring raw;
        const bool ok = key != nullptr && value != nullptr && mcpjson::FindRawValue(json, key, &raw) &&
            (raw == L"true" || raw == L"false");
        if (ok)
        {
            *value = raw == L"true";
        }
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
