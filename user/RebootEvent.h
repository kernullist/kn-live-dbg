#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <optional>
#include <string>

struct SavedCrashStop
{
    ULONG code = 0;
    std::array<ULONG64, 4> args{};
    bool operator==(const SavedCrashStop& other) const { return code == other.code && args == other.args; }
    std::wstring Json() const;
};

struct SavedCrashClock
{
    int64_t systemTime = 0, upTime = 0;
    std::optional<ULONG> debuggerUnixSeconds, debuggerUptimeSeconds;
};

struct RebootTimeline
{
    enum class Order { Unknown, BeforeEvent, SameSecond, AfterEvent };
    Order order = Order::Unknown;
    std::wstring report;
};

struct RebootEventComparison
{
    const wchar_t* status = L"event_source_unavailable";
    std::wstring logDigest, metadata = L"null";
    uint64_t logBytes = 0, recordId = 0;
    std::optional<DWORD> win32Error;
    std::optional<ULONG> eventCode;
    std::optional<SavedCrashStop> eventStop;
    std::optional<bool> sameCode, sameStop;
    std::optional<uint64_t> xmlFileTime, typedFileTime;
    std::optional<DWORD> timeError;
    bool dumpQualified = false;
    std::wstring Json() const;
    std::wstring Hypothesis(const RebootTimeline* timing = nullptr) const;
};

// The saved System event parser accepts one Windows-rendered XML document.
void DecodeRebootEvent(const BYTE* xml, UINT byteCount, RebootEventComparison& comparison);
RebootEventComparison CompareSavedRebootEvent(const std::wstring& path, const std::wstring& pin,
    uint64_t recordId, const SavedCrashStop* qualifiedDumpStop, bool readTime = false);
RebootTimeline CompareRebootTime(const SavedCrashClock& dump, const RebootEventComparison& event);
