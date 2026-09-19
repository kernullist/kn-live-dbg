#pragma once

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace commandinput
{
    inline bool IsValidAddressRange(uint64_t address, uint64_t length)
    {
        return length != 0 && length - 1 <= (std::numeric_limits<uint64_t>::max)() - address;
    }

    inline bool ParseDigits(const std::wstring& text, uint32_t base, uint64_t* output)
    {
        bool ok = false;
        do
        {
            if (output == nullptr || text.empty() || base < 2 || base > 36)
            {
                break;
            }

            uint64_t parsed = 0;
            bool valid = true;
            for (wchar_t ch : text)
            {
                uint32_t digit = 36;
                if (ch >= L'0' && ch <= L'9')
                {
                    digit = static_cast<uint32_t>(ch - L'0');
                }
                else if (ch >= L'a' && ch <= L'z')
                {
                    digit = static_cast<uint32_t>(ch - L'a') + 10;
                }
                else if (ch >= L'A' && ch <= L'Z')
                {
                    digit = static_cast<uint32_t>(ch - L'A') + 10;
                }
                if (digit >= base || parsed > ((std::numeric_limits<uint64_t>::max)() - digit) / base)
                {
                    valid = false;
                    break;
                }
                parsed = parsed * base + digit;
            }
            if (!valid)
            {
                break;
            }
            *output = parsed;
            ok = true;
        } while (false);
        return ok;
    }

    inline bool ParseUnsigned(const std::wstring& value, uint32_t numberBase, uint64_t* output)
    {
        std::wstring text;
        size_t start = !value.empty() && (value[0] == L'L' || value[0] == L'l') ? 1 : 0;
        for (size_t index = start; index < value.size(); ++index)
        {
            if (value[index] != L'`')
            {
                text.push_back(value[index]);
            }
        }

        uint32_t base = numberBase == 0 ? 10 : numberBase;
        if (text.size() >= 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X'))
        {
            base = 16;
            text.erase(0, 2);
        }
        else if (text.size() >= 2 && text[0] == L'0' && (text[1] == L'n' || text[1] == L'N'))
        {
            base = 10;
            text.erase(0, 2);
        }
        else if (text.find_first_of(L"abcdefABCDEF") != std::wstring::npos)
        {
            base = 16;
        }
        return ParseDigits(text, base, output);
    }

    inline bool ParsePort(const std::wstring& text, uint16_t* port)
    {
        uint64_t value = 0;
        bool ok = port != nullptr && ParseDigits(text, 10, &value) && value > 0 && value <= 65535;
        if (ok)
        {
            *port = static_cast<uint16_t>(value);
        }
        return ok;
    }

    struct ListenerOptions
    {
        uint16_t Port = 0;
        std::wstring BindAddress = L"0.0.0.0";
        std::wstring Peer;
        bool AllowWrite = false;
    };

    inline bool ParseListenerOptions(
        const std::vector<std::wstring>& args,
        size_t first,
        bool remote,
        uint16_t defaultPort,
        ListenerOptions* output,
        std::wstring* error)
    {
        ListenerOptions parsed;
        parsed.Port = defaultPort;
        bool havePort = false;
        bool haveBind = false;
        bool havePeer = false;
        bool ok = output != nullptr;
        for (size_t index = first; ok && index < args.size(); ++index)
        {
            const std::wstring& arg = args[index];
            if (!remote && (arg == L"--allow-write" || arg == L"allow-write"))
            {
                ok = !parsed.AllowWrite;
                parsed.AllowWrite = true;
            }
            else if (arg == L"--loopback")
            {
                ok = !haveBind;
                haveBind = true;
                parsed.BindAddress = L"127.0.0.1";
            }
            else if (arg == L"--bind" || (remote && arg == L"--peer"))
            {
                const bool bind = arg == L"--bind";
                ok = !(bind ? haveBind : havePeer) && index + 1 < args.size();
                if (ok)
                {
                    const std::wstring& value = args[++index];
                    ok = !value.empty() && value[0] != L'-' && value.find(L'\0') == std::wstring::npos;
                    if (bind)
                    {
                        parsed.BindAddress = value;
                        haveBind = true;
                    }
                    else
                    {
                        parsed.Peer = value;
                        havePeer = true;
                    }
                }
            }
            else if (arg.rfind(L"--bind=", 0) == 0)
            {
                parsed.BindAddress = arg.substr(7);
                ok = !haveBind && !parsed.BindAddress.empty() &&
                    parsed.BindAddress.find(L'\0') == std::wstring::npos;
                haveBind = true;
            }
            else
            {
                ok = !havePort && ParsePort(arg, &parsed.Port);
                havePort = true;
            }
        }
        if (ok)
        {
            *output = parsed;
        }
        else if (error != nullptr)
        {
            *error = L"invalid or duplicate listener option; port must be decimal 1-65535 and options require values";
        }
        return ok;
    }

    inline std::wstring RawCommandTail(const std::wstring& line)
    {
        const size_t start = line.find_first_not_of(L" \t\r\n");
        const size_t end = start == std::wstring::npos ? start : line.find_first_of(L" \t\r\n", start);
        const size_t tail = end == std::wstring::npos ? end : line.find_first_not_of(L" \t\r\n", end);
        return tail == std::wstring::npos ? L"" : line.substr(tail);
    }
}
