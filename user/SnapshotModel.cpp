#include "SnapshotModel.h"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <sstream>

std::wstring SnapshotToLower(const std::wstring& value)
{
    std::wstring result = value;

    for (wchar_t& ch : result)
    {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }

    return result;
}

std::wstring SnapshotHex(uint64_t value, uint32_t width)
{
    std::wstringstream stream;
    stream << L"0x";
    if (width != 0)
    {
        stream << std::setw(static_cast<int>(width)) << std::setfill(L'0');
    }
    stream << std::hex << std::nouppercase << value;
    return stream.str();
}

std::wstring SnapshotCurrentUtcTimestamp()
{
    SYSTEMTIME st = {};
    GetSystemTime(&st);

    std::wstringstream stream;
    stream << std::setfill(L'0')
           << std::setw(4) << st.wYear << L"-"
           << std::setw(2) << st.wMonth << L"-"
           << std::setw(2) << st.wDay << L"T"
           << std::setw(2) << st.wHour << L"-"
           << std::setw(2) << st.wMinute << L"-"
           << std::setw(2) << st.wSecond << L"-"
           << std::setw(3) << st.wMilliseconds << L"Z";
    return stream.str();
}

std::wstring SnapshotCurrentBootId()
{
    uint64_t bootFileTime = 0;

    do
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll != nullptr)
        {
            using NtQuerySystemInformationFn = LONG (WINAPI*)(ULONG, PVOID, ULONG, PULONG);
            auto query = reinterpret_cast<NtQuerySystemInformationFn>(
                GetProcAddress(ntdll, "NtQuerySystemInformation"));
            if (query != nullptr)
            {
                struct SystemTimeOfDayInformation
                {
                    LARGE_INTEGER BootTime;
                    LARGE_INTEGER CurrentTime;
                    LARGE_INTEGER TimeZoneBias;
                    ULONG TimeZoneId;
                    ULONG Reserved;
                    ULONGLONG BootTimeBias;
                    ULONGLONG SleepTimeBias;
                };

                SystemTimeOfDayInformation timeOfDay = {};
                LONG status = query(3, &timeOfDay, static_cast<ULONG>(sizeof(timeOfDay)), nullptr);
                if (status >= 0)
                {
                    bootFileTime = static_cast<uint64_t>(timeOfDay.BootTime.QuadPart);
                }
            }
        }

        if (bootFileTime == 0)
        {
            FILETIME nowFileTime = {};
            ULARGE_INTEGER now = {};
            GetSystemTimeAsFileTime(&nowFileTime);
            now.LowPart = nowFileTime.dwLowDateTime;
            now.HighPart = nowFileTime.dwHighDateTime;

            uint64_t uptime100ns = GetTickCount64() * 10000ull;
            if (now.QuadPart > uptime100ns)
            {
                bootFileTime = now.QuadPart - uptime100ns;
                bootFileTime = (bootFileTime / 10000000ull) * 10000000ull;
            }
        }
    } while (false);

    return bootFileTime == 0
        ? L"boot-unknown"
        : (L"boot-filetime:" + SnapshotHex(bootFileTime, 16));
}

std::wstring SnapshotSafeFileComponent(const std::wstring& value)
{
    std::wstring safe;

    for (wchar_t ch : value)
    {
        if ((ch >= L'a' && ch <= L'z') ||
            (ch >= L'A' && ch <= L'Z') ||
            (ch >= L'0' && ch <= L'9') ||
            ch == L'-' ||
            ch == L'_')
        {
            safe.push_back(ch);
        }
        else if (ch == L'.')
        {
            safe.push_back(L'-');
        }
        else if (ch == L' ' || ch == L'\t')
        {
            safe.push_back(L'-');
        }
    }

    if (safe.empty())
    {
        safe = L"snapshot";
    }

    return safe;
}

std::wstring SnapshotRiskNormalize(const std::wstring& risk)
{
    std::wstring lowered = SnapshotToLower(risk);
    std::wstring result = L"info";

    if (lowered == L"high" ||
        lowered == L"medium" ||
        lowered == L"low" ||
        lowered == L"info")
    {
        result = lowered;
    }

    return result;
}

uint32_t SnapshotRiskRank(const std::wstring& risk)
{
    uint32_t rank = 0;
    std::wstring normalized = SnapshotRiskNormalize(risk);

    if (normalized == L"low")
    {
        rank = 1;
    }
    else if (normalized == L"medium")
    {
        rank = 2;
    }
    else if (normalized == L"high")
    {
        rank = 3;
    }

    return rank;
}

std::wstring BuildSnapshotProcessIdentity(const SnapshotProcessRecord& process, std::vector<std::wstring>* warnings)
{
    std::wstringstream stream;
    std::wstring image = SnapshotToLower(process.ImageName);

    stream << L"pid:" << process.ProcessId << L":";
    if (process.HasCreateTime)
    {
        stream << L"ctime:" << SnapshotHex(process.CreateTime, 16);
    }
    else
    {
        stream << L"eprocess:" << SnapshotHex(process.Eprocess, 16);
        if (warnings != nullptr)
        {
            warnings->push_back(
                L"process create time unavailable; using pid+eprocess fallback for " +
                process.ImageName + L" pid=" + std::to_wstring(process.ProcessId));
        }
    }
    stream << L":image:" << image;
    return stream.str();
}

bool SnapshotRecordHasTag(const SnapshotRecord& record, const std::wstring& tag)
{
    bool found = false;
    std::wstring wanted = SnapshotToLower(tag);

    for (const std::wstring& item : record.Tags)
    {
        if (SnapshotToLower(item) == wanted)
        {
            found = true;
            break;
        }
    }

    return found;
}

std::vector<SnapshotDomainCount> BuildSnapshotDomainCounts(const SnapshotDocument& document)
{
    std::map<std::wstring, SnapshotDomainCount> byDomain;

    for (const SnapshotRecord& record : document.Records)
    {
        SnapshotDomainCount& count = byDomain[record.Domain];
        count.Domain = record.Domain;
        ++count.Records;

        std::wstring risk = SnapshotRiskNormalize(record.Risk);
        if (risk == L"high")
        {
            ++count.High;
        }
        else if (risk == L"medium")
        {
            ++count.Medium;
        }
        else if (risk == L"low")
        {
            ++count.Low;
        }
        else
        {
            ++count.Info;
        }
    }

    std::vector<SnapshotDomainCount> counts;
    for (const auto& item : byDomain)
    {
        counts.push_back(item.second);
    }

    std::sort(
        counts.begin(),
        counts.end(),
        [](const SnapshotDomainCount& a, const SnapshotDomainCount& b)
        {
            return a.Domain < b.Domain;
        });

    return counts;
}
