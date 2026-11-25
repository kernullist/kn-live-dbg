#include "SnapshotModel.h"
#include "ObservationWindows.h"

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

bool SnapshotHasBootGuid(const std::wstring& id)
{
    return id.size() == 32 && id.find_first_not_of(L"0123456789abcdef") == std::wstring::npos &&
        id.find_first_not_of(L'0') != std::wstring::npos;
}

std::wstring SnapshotCurrentBootId()
{
    const auto& guid = ObservationBootId();
    return SnapshotHasBootGuid(guid) ? guid : L"boot-unknown";
}

const wchar_t* SnapshotBootSourceName(SnapshotBootSource source)
{
    switch (source)
    {
    case SnapshotBootSource::LocalCapture: return L"local_capture";
    case SnapshotBootSource::NoReceipt: return L"receipt_missing";
    case SnapshotBootSource::UnverifiedReceipt: return L"receipt_unverified";
    case SnapshotBootSource::LocalReceipt: return L"local_receipt";
    default: return L"unspecified";
    }
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
