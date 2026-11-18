#pragma once

#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "McpObserveGrant.h"

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
        bool ObserveOnly = false;
        bool Tls = false;
        std::wstring OperationJournalDirectory;
        std::vector<McpObserveGrant> Principals;
        uint32_t TargetSessionSeconds = 300;
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
        bool haveTargetTtl = false;
        std::map<std::wstring, McpObserveAccess> principalAccess;
        bool ok = output != nullptr;
        for (size_t index = first; ok && index < args.size(); ++index)
        {
            const std::wstring& arg = args[index];
            if (!remote && (arg == L"--allow-write" || arg == L"allow-write"))
            {
                ok = !parsed.AllowWrite;
                parsed.AllowWrite = true;
            }
            else if (!remote && arg == L"--observe")
            {
                ok = !parsed.ObserveOnly;
                parsed.ObserveOnly = true;
            }
            else if (!remote && arg == L"--tls")
            {
                ok = !parsed.Tls;
                parsed.Tls = true;
            }
            else if (!remote && (arg == L"--principal" || arg == L"--principal-target"))
            {
                const bool target = arg == L"--principal-target";
                const size_t values = target ? 5 : 2;
                ok = parsed.Principals.size() < 16 && args.size() - index > values;
                if (ok)
                {
                    McpObserveGrant grant{ args[index + 1], args[index + 2] };
                    if (target)
                    {
                        uint64_t pid = 0, created = 0;
                        ok = ParseDigits(args[index + 4], 10, &pid) && pid <= UINT32_MAX && std::to_wstring(pid) == args[index + 4] &&
                            ParseDigits(args[index + 5], 10, &created) && std::to_wstring(created) == args[index + 5];
                        if (ok) { grant.Target = ObservationIdentity{args[index + 3], static_cast<uint32_t>(pid), created}; }
                    }
                    parsed.Principals.push_back(std::move(grant));
                    index += values;
                }
            }
            else if (!remote && arg == L"--principal-access")
            {
                ok = args.size() - index > 2 && principalAccess.size() < 16;
                if (ok)
                {
                    const auto& fingerprint = args[++index];
                    const auto& name = args[++index];
                    McpObserveAccess access = McpObserveAccess::Both;
                    if (name == L"evidence") { access = McpObserveAccess::Evidence; }
                    else if (name == L"operations") { access = McpObserveAccess::Operations; }
                    else if (name != L"both") { ok = false; }
                    ok = ok && principalAccess.emplace(fingerprint, access).second;
                }
            }
            else if (!remote && arg == L"--target-ttl")
            {
                uint64_t seconds = 0;
                ok = !haveTargetTtl && index + 1 < args.size() && ParseDigits(args[++index], 10, &seconds) &&
                    seconds >= 1 && seconds <= 3600 && std::to_wstring(seconds) == args[index];
                haveTargetTtl = true;
                parsed.TargetSessionSeconds = static_cast<uint32_t>(seconds);
            }
            else if (!remote && arg == L"--journal")
            {
                ok = parsed.OperationJournalDirectory.empty() && index + 1 < args.size();
                if (ok)
                {
                    parsed.OperationJournalDirectory = args[++index];
                    ok = !parsed.OperationJournalDirectory.empty() && parsed.OperationJournalDirectory.front() != L'-' &&
                        parsed.OperationJournalDirectory.find(L'\0') == std::wstring::npos;
                }
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
        for (const auto& [fingerprint, access] : principalAccess)
        {
            auto at = std::find_if(parsed.Principals.begin(), parsed.Principals.end(),
                [&](const auto& grant) { return grant.Fingerprint == fingerprint; });
            if (at == parsed.Principals.end()) { ok = false; break; }
            at->Access = access;
        }
        if (!parsed.OperationJournalDirectory.empty() && !parsed.ObserveOnly) { ok = false; }
        if (parsed.Tls && (!parsed.ObserveOnly || parsed.Principals.empty())) { ok = false; }
        if (!parsed.Principals.empty() && (!parsed.ObserveOnly || !ValidMcpObserveGrants(parsed.Principals))) { ok = false; }
        if (haveTargetTtl && std::none_of(parsed.Principals.begin(), parsed.Principals.end(),
            [](const auto& grant) { return grant.Target.has_value(); })) { ok = false; }
        if (parsed.ObserveOnly)
        {
            ok = ok && !parsed.AllowWrite;
            if (!haveBind) { parsed.BindAddress = L"127.0.0.1"; }
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
