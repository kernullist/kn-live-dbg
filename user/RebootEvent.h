#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

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

struct RebootClockChange
{
    uint64_t recordId = 0;
    std::optional<unsigned> version;
    std::optional<uint64_t> oldTime, newTime, typedOldTime, typedNewTime;
    std::optional<DWORD> error;
    const wchar_t* status = L"clock_fields_unavailable";
    std::optional<int64_t> Delta() const;
};

struct RebootClockHistory
{
    static constexpr uint64_t MaxRecordIds = 8192;
    static bool ValidWindow(uint64_t first, uint64_t last)
    {
        return first && first <= last && last - first < MaxRecordIds;
    }
    uint64_t first, last;
    unsigned recordsRead = 0, scopedRecords = 0, unclassified = 0;
    const wchar_t* status = L"restart_record_unavailable";
    std::optional<DWORD> error;
    std::vector<RebootClockChange> changes;
    bool complete = false;
    std::wstring Json() const;
    std::wstring Hypothesis() const;
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
const wchar_t* DecodeRebootClockChange(const BYTE* xml, UINT byteCount, RebootClockChange& change);
RebootEventComparison CompareSavedRebootEvent(const std::wstring& path, const std::wstring& pin,
    uint64_t recordId, const SavedCrashStop* qualifiedDumpStop, bool readTime = false, RebootClockHistory* history = nullptr);
RebootTimeline CompareRebootTime(const SavedCrashClock& dump, const RebootEventComparison& event);
