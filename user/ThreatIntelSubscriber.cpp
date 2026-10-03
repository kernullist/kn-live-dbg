#include "ThreatIntelSubscriber.h"

#include <tdh.h>
#include <evntrace.h>
#include <evntcons.h>
#include <in6addr.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <combaseapi.h>
#include <rpc.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>
#include <exception>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "rpcrt4.lib")

// Microsoft-Windows-Threat-Intelligence
// {f4e1897c-bb5d-5668-f1d8-040f4d8dd344}
// clang-format off
static const GUID kThreatIntelligenceProviderGuid =
{ 0xf4e1897c, 0xbb5d, 0x5668, { 0xf1, 0xd8, 0x04, 0x0f, 0x4d, 0x8d, 0xd3, 0x44 } };
// clang-format on

static const wchar_t* kDefaultSessionName = L"KnLiveDbg-Ti";
static const wchar_t* kDefaultLogBaseName = L"ti-events";
static constexpr ULONGLONG kThreatIntelMatchAnyKeyword = 0;
static constexpr ULONGLONG kThreatIntelMatchAllKeyword = 0;

namespace
{
    bool AppendTiStackFrames(const uint8_t* data, size_t bytes, size_t addressBytes,
        std::vector<uint64_t>* frames)
    {
        constexpr size_t headerBytes = sizeof(ULONG64);
        constexpr size_t maximumFrames = 64;
        if (data == nullptr || frames == nullptr || (addressBytes != 4 && addressBytes != 8) ||
            bytes < headerBytes || (bytes - headerBytes) % addressBytes != 0)
        {
            return false;
        }
        // MatchId precedes Address[] in both SDK stack-extension formats.
        for (size_t offset = headerBytes; offset < bytes && frames->size() < maximumFrames; offset += addressBytes)
        {
            uint64_t address = 0;
            memcpy(&address, data + offset, addressBytes);
            if (address != 0)
            {
                frames->push_back(address);
            }
        }
        return true;
    }

    size_t TiScalarBytes(USHORT type, USHORT eventFlags)
    {
        switch (type)
        {
        case TDH_INTYPE_UINT8:
        case TDH_INTYPE_INT8:
            return 1;
        case TDH_INTYPE_UINT16:
        case TDH_INTYPE_INT16:
            return 2;
        case TDH_INTYPE_UINT32:
        case TDH_INTYPE_INT32:
        case TDH_INTYPE_HEXINT32:
        case TDH_INTYPE_BOOLEAN:
            return 4;
        case TDH_INTYPE_POINTER:
            return (eventFlags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 ? 4 : 8;
        case TDH_INTYPE_UINT64:
        case TDH_INTYPE_INT64:
        case TDH_INTYPE_HEXINT64:
        case TDH_INTYPE_FILETIME:
            return 8;
        case TDH_INTYPE_GUID:
            return sizeof(GUID);
        case TDH_INTYPE_SYSTEMTIME:
            return sizeof(SYSTEMTIME);
        default:
            return 0;
        }
    }

    std::wstring FormatGuid(const GUID& g)
    {
        wchar_t buf[64] = {};
        StringFromGUID2(g, buf, ARRAYSIZE(buf));
        return std::wstring(buf);
    }

    std::wstring FormatHex64(uint64_t value, int width = 0)
    {
        std::wstringstream ss;
        if (width > 0)
        {
            ss << std::hex << std::setw(width) << std::setfill(L'0') << value;
        }
        else
        {
            ss << std::hex << value;
        }
        return ss.str();
    }

    void AppendTiGenerationJson(std::wostream& line, const TiEventRecord& record)
    {
        // Strings preserve all FILETIME bits in consumers using JSON doubles.
        line << L",\"process_create_time\":\"0x" << FormatHex64(record.ProcessCreateTime) << L"\""
             << L",\"target_create_time\":\"0x" << FormatHex64(record.TargetProcessCreateTime) << L"\"";
    }

    std::wstring ToLowerInPlace(std::wstring s)
    {
        for (wchar_t& c : s)
        {
            if (c >= L'A' && c <= L'Z')
            {
                c = static_cast<wchar_t>(c + (L'a' - L'A'));
            }
        }
        return s;
    }

    template<typename Cache, typename IdentityReader, typename PathReader, typename LivenessReader>
    std::wstring ResolveTiImageGeneration(Cache* cache, uint32_t pid, uint64_t timestamp, uint64_t now,
        IdentityReader& identity, PathReader& path, LivenessReader& alive, uint64_t* validatedCreateTime = nullptr)
    {
        if (validatedCreateTime != nullptr)
        {
            *validatedCreateTime = 0;
        }
        uint64_t created = 0;
        if (!identity(&created) || created == 0)
        {
            cache->erase(pid);
            return {};
        }
        auto found = cache->find(pid);
        if (found != cache->end() && found->second.CreateTime != created)
        {
            cache->erase(found);
            found = cache->end();
        }
        if (timestamp != 0 && timestamp < created)
        {
            return {};
        }
        std::wstring resolved;
        if (found != cache->end() && (!found->second.Failed ||
            (now >= found->second.TickMs && now - found->second.TickMs < 1000)))
        {
            resolved = found->second.Path;
        }
        else
        {
            if (!path(&resolved))
            {
                resolved.clear();
            }
            typename Cache::mapped_type entry;
            entry.Path = resolved;
            entry.TickMs = now;
            entry.CreateTime = created;
            entry.Failed = resolved.empty();
            if (cache->size() >= 16384 && found == cache->end())
            {
                cache->clear();
            }
            (*cache)[pid] = std::move(entry);
        }
        if (!alive())
        {
            cache->erase(pid);
            resolved.clear();
        }
        if (validatedCreateTime != nullptr && !resolved.empty())
        {
            *validatedCreateTime = created;
        }
        return resolved;
    }

    bool TiImageMatchesNames(const std::wstring& path, const std::vector<std::wstring>& names)
    {
        const size_t slash = path.find_last_of(L"\\/");
        const std::wstring base = ToLowerInPlace(path.substr(slash == std::wstring::npos ? 0 : slash + 1));
        return !base.empty() && std::find(names.begin(), names.end(), base) != names.end();
    }

    bool TiProcessSelectionMatches(const TiEventRecord& record,
        const std::unordered_set<uint32_t>& pids, const std::vector<std::wstring>& names)
    {
        return (pids.empty() && names.empty()) || pids.count(record.ProcessId) != 0 ||
            (record.TargetProcessId != 0 && pids.count(record.TargetProcessId) != 0) ||
            TiImageMatchesNames(record.ImagePath, names) ||
            (record.TargetProcessId != 0 && TiImageMatchesNames(record.TargetImageBase, names));
    }

    std::wstring ExeDirectory()
    {
        wchar_t buf[MAX_PATH] = {};
        DWORD len = GetModuleFileNameW(nullptr, buf, ARRAYSIZE(buf));
        if (len == 0 || len >= ARRAYSIZE(buf))
        {
            return L".";
        }
        std::wstring path(buf, len);
        size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            return L".";
        }
        return path.substr(0, slash);
    }

    std::wstring TimestampUtcString(uint64_t fileTimeTicks)
    {
        // Convert FILETIME (100-ns ticks since 1601 UTC) to ISO8601 with ms.
        FILETIME ft = {};
        ft.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFFull);
        ft.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);
        SYSTEMTIME st = {};
        if (!FileTimeToSystemTime(&ft, &st))
        {
            return L"1970-01-01T00:00:00.000Z";
        }
        wchar_t buf[64] = {};
        swprintf_s(buf,
                    L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return std::wstring(buf);
    }

    std::wstring JsonEscape(const std::wstring& in)
    {
        std::wstring out;
        out.reserve(in.size() + 8);
        for (wchar_t c : in)
        {
            switch (c)
            {
                case L'"':  out += L"\\\""; break;
                case L'\\': out += L"\\\\"; break;
                case L'\b': out += L"\\b"; break;
                case L'\f': out += L"\\f"; break;
                case L'\n': out += L"\\n"; break;
                case L'\r': out += L"\\r"; break;
                case L'\t': out += L"\\t"; break;
                default:
                {
                    if (c < 0x20)
                    {
                        wchar_t esc[8] = {};
                        swprintf_s(esc, L"\\u%04x", static_cast<unsigned>(c));
                        out += esc;
                    }
                    else
                    {
                        out.push_back(c);
                    }
                    break;
                }
            }
        }
        return out;
    }

    std::string WideToUtf8(const std::wstring& w)
    {
        if (w.empty())
        {
            return std::string();
        }
        int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
        {
            return std::string();
        }
        std::string s(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], needed, nullptr, nullptr);
        return s;
    }

    std::wstring HexDumpFirstBytes(const uint8_t* data, size_t length, size_t maxBytes = 64)
    {
        std::wstringstream ss;
        size_t emit = (length < maxBytes) ? length : maxBytes;
        for (size_t i = 0; i < emit; ++i)
        {
            ss << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<unsigned>(data[i]);
        }
        if (length > emit)
        {
            ss << L"..";
        }
        return ss.str();
    }

    bool BuildRealtimeSessionProperties(
        const std::wstring& sessionName,
        std::vector<uint8_t>* blob)
    {
        const ULONG nameBytes = static_cast<ULONG>((sessionName.size() + 1) * sizeof(wchar_t));
        const ULONG totalBytes = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
        blob->assign(totalBytes, 0);

        EVENT_TRACE_PROPERTIES* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(blob->data());
        p->Wnode.BufferSize = totalBytes;
        p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // ClientContext = 2 -> SystemTime (FILETIME, 100-ns ticks since
        // 1601 UTC). Required so EventHeader.TimeStamp is directly usable by
        // FileTimeToSystemTime. With ClientContext = 1 (QPC) the value would
        // be raw QPC counts and our JSONL "ts" field would be garbage.
        p->Wnode.ClientContext = 2;
        UuidCreate(&p->Wnode.Guid);

        p->BufferSize = 64;          // 64 KB per ETW buffer
        p->MinimumBuffers = 8;
        p->MaximumBuffers = 64;
        p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        p->LogFileNameOffset = 0;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        std::memcpy(blob->data() + p->LoggerNameOffset, sessionName.c_str(), nameBytes);
        return true;
    }

    bool CompleteTraceGeneration(
        TiTraceLifecycle* lifecycle,
        uint64_t generation,
        uint32_t status,
        uint64_t tickMs)
    {
        if (lifecycle == nullptr || lifecycle->Generation != generation)
        {
            return false;
        }
        lifecycle->ThreadRunning = false;
        lifecycle->ExitStatusKnown = true;
        lifecycle->ExitStatus = status;
        lifecycle->ExitTickMs = tickMs;
        lifecycle->ExitAfterStopRequest = lifecycle->StopRequested;
        return true;
    }

    TiSequenceSnapshot SnapshotTiSequenceRange(
        const std::deque<TiEventRecord>& ring,
        uint64_t latestAssigned,
        uint64_t cursor,
        size_t maxCount)
    {
        TiSequenceSnapshot out;
        out.LatestAssignedSequence = latestAssigned;
        out.EarliestAvailableSequence = ring.empty() ? 0 : ring.front().Sequence;
        out.CursorAhead = cursor > latestAssigned;
        if (cursor != 0 && !out.CursorAhead)
        {
            if (ring.empty())
            {
                out.MissingBeforeFirst = latestAssigned - cursor;
            }
            else if (out.EarliestAvailableSequence > cursor)
            {
                out.MissingBeforeFirst = out.EarliestAvailableSequence - cursor - 1;
            }
        }
        for (const TiEventRecord& record : ring)
        {
            if (record.Sequence <= cursor)
            {
                continue;
            }
            if (maxCount != 0 && out.Records.size() >= maxCount)
            {
                out.HasMore = true;
                break;
            }
            out.Records.push_back(record);
        }
        return out;
    }
}

TiSubscriber::TiSubscriber() = default;

TiSubscriber::~TiSubscriber()
{
    std::wstring err;
    Stop(&err);
}

bool TiSubscriber::IsActive() const
{
    return Active.load();
}

std::wstring TiSubscriber::GetCachedImageOrResolve(uint32_t pid, uint64_t eventTimestamp,
    uint64_t* validatedCreateTime)
{
    if (validatedCreateTime != nullptr)
    {
        *validatedCreateTime = 0;
    }
    if (pid == 0)
    {
        return L"<idle>";
    }
    if (pid == 4)
    {
        return L"System";
    }

    struct ProcessHandleScope
    {
        HANDLE Value = nullptr;

        ~ProcessHandleScope()
        {
            if (Value != nullptr)
            {
                CloseHandle(Value);
            }
        }
    } process;
    auto readIdentity = [&](uint64_t* created)
    {
        process.Value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
        FILETIME create = {}, exit = {}, kernel = {}, user = {};
        const bool known = process.Value != nullptr &&
            GetProcessTimes(process.Value, &create, &exit, &kernel, &user) != FALSE &&
            WaitForSingleObject(process.Value, 0) == WAIT_TIMEOUT;
        if (known)
        {
            *created = (static_cast<uint64_t>(create.dwHighDateTime) << 32) | create.dwLowDateTime;
        }
        return known;
    };
    auto readPath = [&](std::wstring* path)
    {
        std::vector<wchar_t> buffer(32768, L'\0');
        DWORD length = static_cast<DWORD>(buffer.size());
        const bool known = QueryFullProcessImageNameW(process.Value, 0, buffer.data(), &length) != FALSE &&
            length != 0 && length < buffer.size();
        if (known)
        {
            path->assign(buffer.data(), length);
        }
        return known;
    };
    auto stillAlive = [&]()
    {
        return WaitForSingleObject(process.Value, 0) == WAIT_TIMEOUT;
    };

    // Every cache hit requires the current generation from this same handle.
    std::lock_guard<std::mutex> lock(ImageCacheMutex);
    return ResolveTiImageGeneration(&ImageCache, pid, eventTimestamp, GetTickCount64(),
        readIdentity, readPath, stillAlive, validatedCreateTime);
}

TiOptions TiSubscriber::CurrentOptions() const
{
    std::lock_guard<std::mutex> lock(StateMutex);
    return Options;
}

bool TiSubscriber::IsLiveOutputEnabled() const
{
    return LiveOutput.load();
}

void TiSubscriber::SetLiveOutput(bool enabled)
{
    LiveOutput.store(enabled);
}

bool TiSubscriber::Start(const TiOptions& options, std::wstring* error)
{
    std::lock_guard<std::mutex> stateLock(StateMutex);
    if (Active.load())
    {
        if (error != nullptr)
        {
            *error = L"subscriber already active";
        }
        return false;
    }

    // An exited ProcessTrace thread is still joinable and owns its handles.
    // Join and release it before replacing the thread or resetting counters.
    if (ProcessThread.joinable() || SessionHandle != 0 ||
        ProcessHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        StopLocked(nullptr);
    }

    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> traceLock(TraceMutex);
        generation = TraceLifecycle.Generation + 1;
        if (generation == 0)
        {
            generation = 1;
        }
        TraceLifecycle = TiTraceLifecycle{};
        TraceLifecycle.Generation = generation;
        std::lock_guard<std::mutex> ringLock(RingMutex);
        TraceLifecycle.FirstSequence = NextRingSequence;
    }
    const auto setStartStatus = [&](uint32_t status)
    {
        std::lock_guard<std::mutex> traceLock(TraceMutex);
        TraceLifecycle.StartStatus = status;
    };

    Options = options;
    if (Options.LogBaseName.empty())
    {
        Options.LogBaseName = kDefaultLogBaseName;
    }
    if (Options.LogDirectory.empty())
    {
        Options.LogDirectory = ExeDirectory();
    }
    if (Options.RingCapacity == 0)
    {
        Options.RingCapacity = 1u << 20;
    }
    if (Options.ThrottlePerSecond == 0)
    {
        Options.ThrottlePerSecond = 50;
    }

    SessionName = kDefaultSessionName;

    // Pre-populate watch state.
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        WatchPids.clear();
        WatchNamesLower.clear();
        for (uint32_t p : Options.WatchPids)
        {
            WatchPids.insert(p);
        }
        for (const std::wstring& n : Options.WatchNames)
        {
            WatchNamesLower.push_back(ToLowerInPlace(n));
        }
    }

    LiveOutput.store(Options.LiveOutputEnabled);
    ThrottleWindowStartMs.store(0);
    ThrottleWindowCount.store(0);
    ThrottleSuppressed.store(0);

    Stats.EventsReceived.store(0);
    Stats.EventsKept.store(0);
    Stats.EventsDropped.store(0);
    Stats.EventsSelfExcluded.store(0);
    Stats.EventsWatchMatched.store(0);
    Stats.EventsLogged.store(0);
    Stats.LogBytesWritten.store(0);
    Stats.LogRotations.store(0);
    Stats.EventsLost.store(0);
    Stats.StartTickMs.store(GetTickCount64());
    Stats.LastEventTickMs.store(0);

    // Snapshot the immutable-after-Start subset of options into atomics so
    // the ETW callback hot path does not race with API mutators.
    SelfPidSnapshot.store(Options.SelfPid);
    ExcludeSelfSnapshot.store(Options.ExcludeSelf);

    // Image cache fresh for the new session.
    {
        std::lock_guard<std::mutex> imgLock(ImageCacheMutex);
        ImageCache.clear();
    }

    // Tear down any leftover session with this name from a prior crash.
    {
        std::vector<uint8_t> stopBlob;
        BuildRealtimeSessionProperties(SessionName, &stopBlob);
        ControlTraceW(0, SessionName.c_str(),
                      reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBlob.data()),
                      EVENT_TRACE_CONTROL_STOP);
    }

    BuildRealtimeSessionProperties(SessionName, &SessionPropertiesBlob);
    EVENT_TRACE_PROPERTIES* props =
        reinterpret_cast<EVENT_TRACE_PROPERTIES*>(SessionPropertiesBlob.data());

    ULONG status = StartTraceW(&SessionHandle, SessionName.c_str(), props);
    if (status == ERROR_ALREADY_EXISTS)
    {
        ControlTraceW(0, SessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
        // StartTraceW mutates the props buffer on failure (writes back
        // session UUID etc.). Rebuild from scratch before retrying so the
        // second call does not see a half-initialised blob.
        BuildRealtimeSessionProperties(SessionName, &SessionPropertiesBlob);
        props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(SessionPropertiesBlob.data());
        status = StartTraceW(&SessionHandle, SessionName.c_str(), props);
    }
    if (status != ERROR_SUCCESS)
    {
        setStartStatus(status);
        if (error != nullptr)
        {
            *error = L"StartTraceW failed: " + std::to_wstring(status);
        }
        SessionHandle = 0;
        return false;
    }

    // Enable with stack tracing: the TI provider is manifest-based, so
    // callstacks are requested through ENABLE_TRACE_PARAMETERS with
    // EVENT_ENABLE_PROPERTY_STACK_TRACE in EnableTraceEx2 --- NOT via
    // TraceSetInformation with CLASSIC_EVENT_ID (that API is for classic
    // kernel events only and silently does nothing for manifest providers).
    ENABLE_TRACE_PARAMETERS enableParams = {};
    enableParams.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    enableParams.EnableProperty = 0;
    if (Options.EnableCallstacks)
    {
        enableParams.EnableProperty |= EVENT_ENABLE_PROPERTY_STACK_TRACE;
    }

    status = EnableTraceEx2(
        SessionHandle,
        &kThreatIntelligenceProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        kThreatIntelMatchAnyKeyword,
        kThreatIntelMatchAllKeyword,
        0,
        &enableParams);

    if (status != ERROR_SUCCESS)
    {
        setStartStatus(status);
        ControlTraceW(SessionHandle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        SessionHandle = 0;
        if (error != nullptr)
        {
            std::wstring extra;
            if (status == ERROR_ACCESS_DENIED)
            {
                extra = L" (Microsoft-Windows-Threat-Intelligence requires the consumer to "
                        L"be a PPL Antimalware process; run 'set-ppl-antimalware' first)";
            }
            *error = L"EnableTraceEx2 failed: " + std::to_wstring(status) + extra;
        }
        return false;
    }

    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName = const_cast<LPWSTR>(SessionName.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                                PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &TiSubscriber::EventRecordCallbackThunk;
    logfile.BufferCallback = &TiSubscriber::BufferCallbackThunk;
    logfile.Context = this;

    ProcessHandle = OpenTraceW(&logfile);
    if (ProcessHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        DWORD gle = GetLastError();
        setStartStatus(gle);
        EnableTraceEx2(SessionHandle, &kThreatIntelligenceProviderGuid,
                       EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                       TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
        ControlTraceW(SessionHandle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        SessionHandle = 0;
        if (error != nullptr)
        {
            *error = L"OpenTraceW failed (gle=" + std::to_wstring(gle) + L")";
        }
        return false;
    }

    ProcessTraceShouldExit.store(false);
    {
        std::lock_guard<std::mutex> traceLock(TraceMutex);
        TraceLifecycle.StartStatus = ERROR_SUCCESS;
        TraceLifecycle.ThreadRunning = true;
        Active.store(true);
    }
    try
    {
        ProcessThread = std::thread(&TiSubscriber::ProcessTraceThread, this, ProcessHandle, generation);
    }
    catch (const std::exception&)
    {
        {
            std::lock_guard<std::mutex> traceLock(TraceMutex);
            TraceLifecycle.StartStatus = ERROR_NOT_ENOUGH_MEMORY;
            TraceLifecycle.ThreadRunning = false;
            Active.store(false);
        }
        StopLocked(nullptr);
        if (error != nullptr)
        {
            *error = L"could not create TI trace consumer thread";
        }
        return false;
    }

    return true;
}

bool TiSubscriber::Stop(std::wstring* error)
{
    // Teardown any partial Start() state even when Active never became true
    // (e.g. CTRL_CLOSE after StartTraceW but before Active.store). Use a
    // dedicated lock so concurrent Stop calls serialize on resource cleanup.
    std::lock_guard<std::mutex> stateLock(StateMutex);

    return StopLocked(error);
}

bool TiSubscriber::StopLocked(std::wstring* error)
{

    bool wasActive = false;
    {
        std::lock_guard<std::mutex> traceLock(TraceMutex);
        TraceLifecycle.StopRequested = true;
        wasActive = Active.exchange(false);
        ProcessTraceShouldExit.store(true);
    }

    // Closing the process handle causes ProcessTrace to return.
    if (ProcessHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(ProcessHandle);
    }

    if (ProcessThread.joinable())
    {
        ProcessThread.join();
    }
    ProcessHandle = INVALID_PROCESSTRACE_HANDLE;

    // Disable provider and stop the session when Start opened one.
    if (SessionHandle != 0)
    {
        EnableTraceEx2(
            SessionHandle,
            &kThreatIntelligenceProviderGuid,
            EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            0, 0, 0, nullptr);

        if (!SessionPropertiesBlob.empty())
        {
            EVENT_TRACE_PROPERTIES* props =
                reinterpret_cast<EVENT_TRACE_PROPERTIES*>(SessionPropertiesBlob.data());
            ControlTraceW(SessionHandle, nullptr, props, EVENT_TRACE_CONTROL_STOP);
        }
        else
        {
            // Partial start may not have built SessionPropertiesBlob yet; still
            // try a name-based stop for leftover realtime sessions.
            std::vector<uint8_t> stopBlob;
            BuildRealtimeSessionProperties(SessionName.empty() ? kDefaultSessionName : SessionName, &stopBlob);
            ControlTraceW(
                0,
                (SessionName.empty() ? kDefaultSessionName : SessionName.c_str()),
                reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBlob.data()),
                EVENT_TRACE_CONTROL_STOP);
        }
        SessionHandle = 0;
    }
    else if (!wasActive)
    {
        // Best-effort: if Active never flipped but a named session may exist
        // from a half-started attempt, try stop-by-name.
        if (!SessionName.empty())
        {
            std::vector<uint8_t> stopBlob;
            BuildRealtimeSessionProperties(SessionName, &stopBlob);
            ControlTraceW(
                0,
                SessionName.c_str(),
                reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBlob.data()),
                EVENT_TRACE_CONTROL_STOP);
        }
    }

    // Close log file.
    {
        std::lock_guard<std::mutex> logLock(LogMutex);
        CloseLogLocked();
    }

    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

VOID WINAPI TiSubscriber::EventRecordCallbackThunk(PEVENT_RECORD eventRecord)
{
    if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
    {
        return;
    }
    TiSubscriber* self = reinterpret_cast<TiSubscriber*>(eventRecord->UserContext);
    self->OnEventRecord(eventRecord);
}

ULONG WINAPI TiSubscriber::BufferCallbackThunk(PEVENT_TRACE_LOGFILEW buffer)
{
    if (buffer == nullptr || buffer->Context == nullptr)
    {
        return TRUE;
    }
    TiSubscriber* self = reinterpret_cast<TiSubscriber*>(buffer->Context);
    self->Stats.EventsLost.store(buffer->EventsLost, std::memory_order_relaxed);
    return self->ProcessTraceShouldExit.load() ? FALSE : TRUE;
}

void TiSubscriber::ProcessTraceThread(TRACEHANDLE processHandle, uint64_t generation)
{
    // ProcessTrace blocks until CloseTrace is called or BufferCallback
    // returns FALSE. All event delivery happens via EventRecordCallback.
    const ULONG status = ProcessTrace(&processHandle, 1, nullptr, nullptr);
    std::lock_guard<std::mutex> traceLock(TraceMutex);
    if (CompleteTraceGeneration(&TraceLifecycle, generation, status, GetTickCount64()))
    {
        Active.store(false);
    }
}

void TiSubscriber::OnEventRecord(PEVENT_RECORD eventRecord)
{
    Stats.EventsReceived.fetch_add(1, std::memory_order_relaxed);
    Stats.LastEventTickMs.store(GetTickCount64(), std::memory_order_relaxed);

    uint32_t pid = eventRecord->EventHeader.ProcessId;

    // Self-exclude before anything else to prevent feedback loops.
    const uint32_t selfPid = SelfPidSnapshot.load(std::memory_order_relaxed);
    if (ExcludeSelfSnapshot.load(std::memory_order_relaxed) && pid == selfPid && selfPid != 0)
    {
        Stats.EventsSelfExcluded.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    TiEventRecord record;
    DecodeEvent(eventRecord, &record);

    // Stack extensions contain a MatchId followed by 32-bit or 64-bit addresses.
    if (Options.EnableCallstacks && eventRecord->ExtendedData != nullptr)
    {
        for (USHORT ei = 0; ei < eventRecord->ExtendedDataCount; ++ei)
        {
            EVENT_HEADER_EXTENDED_DATA_ITEM* ext =
                &eventRecord->ExtendedData[ei];
            if (ext->ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 && ext->DataPtr != 0)
            {
                AppendTiStackFrames(reinterpret_cast<const uint8_t*>(ext->DataPtr),
                    ext->DataSize, sizeof(ULONG), &record.CallstackAddresses);
            }
            else if (ext->ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 && ext->DataPtr != 0)
            {
                AppendTiStackFrames(reinterpret_cast<const uint8_t*>(ext->DataPtr),
                    ext->DataSize, sizeof(ULONGLONG), &record.CallstackAddresses);
            }
        }
    }

    // Pre-extract the cross-process target so the watch matcher and the
    // printer never walk the payload again. Prefer explicit target-ish field
    // names; never promote Parent/Source/Creator/Calling PIDs to TargetProcessId.
    auto FieldNameLower = [](const std::wstring& name) -> std::wstring
    {
        std::wstring lower;
        lower.reserve(name.size());
        for (wchar_t c : name)
        {
            if (c >= L'A' && c <= L'Z')
            {
                c = static_cast<wchar_t>(c + (L'a' - L'A'));
            }
            lower.push_back(c);
        }
        return lower;
    };
    auto ParsePidField = [](const TiPayloadField& f) -> uint32_t
    {
        if (f.Value.empty() || f.Value[0] == L'<')
        {
            return 0;
        }
        const wchar_t* str = f.Value.c_str();
        int base = 10;
        if (f.Value.size() >= 2 && f.Value[0] == L'0' &&
            (f.Value[1] == L'x' || f.Value[1] == L'X'))
        {
            base = 16;
        }
        wchar_t* end = nullptr;
        unsigned long long parsed = wcstoull(str, &end, base);
        if (end == str || parsed == 0 || parsed > 0xFFFFFFFFull)
        {
            return 0;
        }
        return static_cast<uint32_t>(parsed);
    };
    auto IsRejectedTargetName = [](const std::wstring& lower) -> bool
    {
        return lower.find(L"callingprocessid") != std::wstring::npos ||
            lower.find(L"parentprocessid") != std::wstring::npos ||
            lower.find(L"sourceprocessid") != std::wstring::npos ||
            lower.find(L"originalprocessid") != std::wstring::npos ||
            lower.find(L"creatorprocessid") != std::wstring::npos ||
            lower == L"processid"; // bare ProcessId usually means the caller
    };
    auto IsPreferredTargetName = [](const std::wstring& lower) -> bool
    {
        return lower == L"targetprocessid" ||
            lower == L"victimprocessid" ||
            lower == L"destinationprocessid" ||
            lower == L"remoteprocessid" ||
            lower.find(L"targetprocessid") != std::wstring::npos ||
            lower.find(L"victimprocessid") != std::wstring::npos ||
            lower.find(L"destinationprocessid") != std::wstring::npos ||
            lower.find(L"remoteprocessid") != std::wstring::npos;
    };

    uint32_t preferredTarget = 0;
    for (const TiPayloadField& f : record.Payload)
    {
        const std::wstring lower = FieldNameLower(f.Name);
        if (lower.find(L"processid") == std::wstring::npos)
        {
            continue;
        }
        if (IsRejectedTargetName(lower))
        {
            continue;
        }
        if (!IsPreferredTargetName(lower))
        {
            // Ambiguous *ProcessId* names are ignored: wrong victim attribution
            // is worse than missing target correlation.
            continue;
        }

        const uint32_t tpid = ParsePidField(f);
        if (tpid == 0 || tpid == record.ProcessId)
        {
            continue;
        }

        preferredTarget = tpid;
        break;
    }

    if (preferredTarget != 0)
    {
        record.TargetProcessId = preferredTarget;
        record.TargetImageBase = record.Timestamp != 0 ?
            BasenameLower(GetCachedImageOrResolve(preferredTarget, record.Timestamp,
                &record.TargetProcessCreateTime)) : std::wstring{};
    }

    RecordKeep(std::move(record));
}

bool TiSubscriber::DecodeEvent(PEVENT_RECORD eventRecord, TiEventRecord* out)
{
    const EVENT_HEADER& hdr = eventRecord->EventHeader;
    out->Timestamp = static_cast<uint64_t>(hdr.TimeStamp.QuadPart);
    out->ProcessId = hdr.ProcessId;
    out->ThreadId = hdr.ThreadId;
    out->TaskId = hdr.EventDescriptor.Task;
    out->Version = hdr.EventDescriptor.Version;
    out->Level = hdr.EventDescriptor.Level;
    out->Opcode = hdr.EventDescriptor.Opcode;
    out->Channel = hdr.EventDescriptor.Channel;
    out->Keyword = hdr.EventDescriptor.Keyword;
    out->ProcessCreateTime = 0;
    out->ImagePath = out->Timestamp != 0 ?
        GetCachedImageOrResolve(out->ProcessId, out->Timestamp, &out->ProcessCreateTime) : std::wstring{};

    bool tdhOk = DecodePayloadViaTdh(eventRecord, out);
    if (!tdhOk)
    {
        DecodePayloadAsRawHex(eventRecord, out);
    }

    return tdhOk;
}

bool TiSubscriber::DecodePayloadViaTdh(PEVENT_RECORD eventRecord, TiEventRecord* out)
{
    ULONG bufferSize = 0;
    ULONG status = TdhGetEventInformation(eventRecord, 0, nullptr, nullptr, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER)
    {
        return false;
    }

    std::vector<uint8_t> blob(bufferSize, 0);
    PTRACE_EVENT_INFO info = reinterpret_cast<PTRACE_EVENT_INFO>(blob.data());
    status = TdhGetEventInformation(eventRecord, 0, nullptr, info, &bufferSize);
    if (status != ERROR_SUCCESS)
    {
        return false;
    }

    auto readStringAt = [&](ULONG offset) -> std::wstring
    {
        if (offset == 0)
        {
            return std::wstring();
        }
        const wchar_t* p = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const uint8_t*>(info) + offset);
        return std::wstring(p);
    };

    out->TaskName = readStringAt(info->TaskNameOffset);
    out->OpcodeName = readStringAt(info->OpcodeNameOffset);

    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
    {
        EVENT_PROPERTY_INFO& pi = info->EventPropertyInfoArray[i];
        std::wstring propName = readStringAt(pi.NameOffset);

        // Skip struct-typed properties: pi.structType is active in the union
        // and reading pi.nonStructType.InType would yield garbage. A future
        // enhancement could recurse into the struct via pi.structType, but
        // for the Threat-Intelligence provider all top-level fields seen in
        // the wild are scalars or arrays of scalars.
        if (pi.Flags & PropertyStruct)
        {
            TiPayloadField field;
            field.Name = propName;
            field.Value = L"<struct>";
            field.TypeName = L"struct";
            out->Payload.push_back(std::move(field));
            continue;
        }

        // Determine array length: either fixed pi.count, or runtime via
        // PropertyParamCount referencing another field. For simplicity we
        // skip PropertyParamCount and use the static count.
        USHORT arrayCount = 1;
        if (pi.Flags & PropertyParamCount)
        {
            // Length comes from another field; conservatively treat as 1.
            arrayCount = 1;
        }
        else if (pi.count > 1)
        {
            arrayCount = pi.count;
        }
        if (arrayCount > 32)
        {
            arrayCount = 32; // cap to avoid pathological payloads
        }

        for (USHORT ai = 0; ai < arrayCount; ++ai)
        {
            PROPERTY_DATA_DESCRIPTOR dd = {};
            dd.PropertyName = reinterpret_cast<ULONGLONG>(propName.c_str());
            dd.ArrayIndex = ai;

            ULONG propSize = 0;
            status = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &dd, &propSize);
            if (status != ERROR_SUCCESS || propSize == 0)
            {
                TiPayloadField field;
                field.Name = (arrayCount > 1)
                    ? (propName + L"[" + std::to_wstring(ai) + L"]")
                    : propName;
                field.Value = L"<unavailable>";
                out->Payload.push_back(std::move(field));
                continue;
            }

            std::vector<uint8_t> propBuf(propSize, 0);
            status = TdhGetProperty(eventRecord, 0, nullptr, 1, &dd, propSize, propBuf.data());
            if (status != ERROR_SUCCESS)
            {
                TiPayloadField field;
                field.Name = (arrayCount > 1)
                    ? (propName + L"[" + std::to_wstring(ai) + L"]")
                    : propName;
                field.Value = L"<decode-error:" + std::to_wstring(status) + L">";
                out->Payload.push_back(std::move(field));
                continue;
            }

            const USHORT inType = pi.nonStructType.InType;
            const size_t scalarBytes = TiScalarBytes(inType, eventRecord->EventHeader.Flags);
            if (propBuf.size() < scalarBytes)
            {
                TiPayloadField field;
                field.Name = propName;
                field.Value = L"<short-scalar>";
                out->Payload.push_back(std::move(field));
                continue;
            }
        std::wstring value;
        std::wstring typeName;

        switch (inType)
        {
            case TDH_INTYPE_UNICODESTRING:
            {
                value.assign(reinterpret_cast<const wchar_t*>(propBuf.data()),
                              propSize / sizeof(wchar_t));
                // Trim trailing nulls.
                while (!value.empty() && value.back() == L'\0')
                {
                    value.pop_back();
                }
                typeName = L"unicode";
                break;
            }
            case TDH_INTYPE_ANSISTRING:
            {
                const char* s = reinterpret_cast<const char*>(propBuf.data());
                int len = static_cast<int>(strnlen_s(s, propSize));
                if (len <= 0)
                {
                    typeName = L"ansi";
                    break;
                }
                int needed = MultiByteToWideChar(CP_ACP, 0, s, len, nullptr, 0);
                if (needed > 0)
                {
                    value.resize(static_cast<size_t>(needed), L'\0');
                    MultiByteToWideChar(CP_ACP, 0, s, len, &value[0], needed);
                }
                typeName = L"ansi";
                break;
            }
            case TDH_INTYPE_UINT8:
            {
                value = std::to_wstring(propBuf[0]);
                typeName = L"u8";
                break;
            }
            case TDH_INTYPE_INT8:
            {
                int8_t v = *reinterpret_cast<const int8_t*>(propBuf.data());
                value = std::to_wstring(v);
                typeName = L"i8";
                break;
            }
            case TDH_INTYPE_UINT16:
            {
                uint16_t v = *reinterpret_cast<const uint16_t*>(propBuf.data());
                value = std::to_wstring(v);
                typeName = L"u16";
                break;
            }
            case TDH_INTYPE_INT16:
            {
                int16_t v = *reinterpret_cast<const int16_t*>(propBuf.data());
                value = std::to_wstring(v);
                typeName = L"i16";
                break;
            }
            case TDH_INTYPE_UINT32:
            case TDH_INTYPE_HEXINT32:
            {
                uint32_t v = *reinterpret_cast<const uint32_t*>(propBuf.data());
                if (inType == TDH_INTYPE_HEXINT32)
                {
                    value = L"0x" + FormatHex64(v, 8);
                    typeName = L"hex32";
                }
                else
                {
                    value = std::to_wstring(v);
                    typeName = L"u32";
                }
                break;
            }
            case TDH_INTYPE_INT32:
            {
                int32_t v = *reinterpret_cast<const int32_t*>(propBuf.data());
                value = std::to_wstring(v);
                typeName = L"i32";
                break;
            }
            case TDH_INTYPE_UINT64:
            case TDH_INTYPE_HEXINT64:
            case TDH_INTYPE_POINTER:
            {
                uint64_t v = 0;
                memcpy(&v, propBuf.data(), scalarBytes);
                if (inType == TDH_INTYPE_UINT64)
                {
                    value = std::to_wstring(v);
                    typeName = L"u64";
                }
                else
                {
                    value = L"0x" + FormatHex64(v, 16);
                    typeName = (inType == TDH_INTYPE_POINTER) ? L"ptr" : L"hex64";
                }
                break;
            }
            case TDH_INTYPE_INT64:
            {
                int64_t v = *reinterpret_cast<const int64_t*>(propBuf.data());
                value = std::to_wstring(v);
                typeName = L"i64";
                break;
            }
            case TDH_INTYPE_BOOLEAN:
            {
                uint32_t v = *reinterpret_cast<const uint32_t*>(propBuf.data());
                value = v ? L"true" : L"false";
                typeName = L"bool";
                break;
            }
            case TDH_INTYPE_GUID:
            {
                value = FormatGuid(*reinterpret_cast<const GUID*>(propBuf.data()));
                typeName = L"guid";
                break;
            }
            case TDH_INTYPE_FILETIME:
            {
                uint64_t v = *reinterpret_cast<const uint64_t*>(propBuf.data());
                value = TimestampUtcString(v);
                typeName = L"filetime";
                break;
            }
            case TDH_INTYPE_SYSTEMTIME:
            {
                const SYSTEMTIME* st = reinterpret_cast<const SYSTEMTIME*>(propBuf.data());
                wchar_t buf[64] = {};
                swprintf_s(buf,
                            L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                            st->wYear, st->wMonth, st->wDay,
                            st->wHour, st->wMinute, st->wSecond, st->wMilliseconds);
                value = buf;
                typeName = L"systemtime";
                break;
            }
            case TDH_INTYPE_BINARY:
            default:
            {
                value = L"0x" + HexDumpFirstBytes(propBuf.data(), propBuf.size(), 32);
                typeName = L"bytes(" + std::to_wstring(propBuf.size()) + L")";
                break;
            }
        }

            TiPayloadField field;
            field.Name = (arrayCount > 1)
                ? (propName + L"[" + std::to_wstring(ai) + L"]")
                : propName;
            field.Value = std::move(value);
            field.TypeName = std::move(typeName);
            out->Payload.push_back(std::move(field));
        }
    }

    out->DecodedByTdh = true;
    return true;
}

void TiSubscriber::DecodePayloadAsRawHex(PEVENT_RECORD eventRecord, TiEventRecord* out)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*>(eventRecord->UserData);
    size_t length = static_cast<size_t>(eventRecord->UserDataLength);
    out->RawPayloadHex = HexDumpFirstBytes(data, length, 256);
    out->DecodedByTdh = false;

    // Best-effort: if no task name, synthesize from EventDescriptor.
    if (out->TaskName.empty())
    {
        std::wstringstream ss;
        ss << L"Task" << out->TaskId;
        out->TaskName = ss.str();
    }
}

void TiSubscriber::RecordKeep(TiEventRecord&& record)
{
    bool watch = MatchesWatch(record);
    if (watch)
    {
        Stats.EventsWatchMatched.fetch_add(1, std::memory_order_relaxed);
    }

    // Always log to JSONL.
    WriteLogLine(record);

    // Push to ring (newest at back). Assign a monotonic Sequence under the
    // ring lock so timeline recent cursors can track arrival order instead of
    // ETW timestamps (which may arrive out of order).
    {
        std::lock_guard<std::mutex> ringLock(RingMutex);
        while (Ring.size() >= Options.RingCapacity)
        {
            Ring.pop_front();
            Stats.EventsDropped.fetch_add(1, std::memory_order_relaxed);
        }
        if (record.Sequence == 0)
        {
            record.Sequence = NextRingSequence++;
            if (NextRingSequence == 0)
            {
                NextRingSequence = 1; // skip 0 (0 means "unsequenced")
            }
        }
        Ring.push_back(record);
        Stats.EventsKept.fetch_add(1, std::memory_order_relaxed);
    }

    // Enqueue for live print only if watch matches AND live output enabled.
    if (watch && LiveOutput.load())
    {
        EnqueuePrint(std::move(record));
    }
}

bool TiSubscriber::MatchesWatch(const TiEventRecord& record)
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    // Empty selection matches all events. Numeric PID watches intentionally
    // follow that PID; name watches use only the event's validated identity.
    if (TiProcessSelectionMatches(record, WatchPids, WatchNamesLower))
    {
        return true;
    }

    // Driver/device payload names are event evidence, not PID promotions.
    return !WatchNamesLower.empty() && PayloadBasenameMatchesWatch(record, WatchNamesLower);
}

bool TiSubscriber::PayloadBasenameMatchesWatch(
    const TiEventRecord& record,
    const std::vector<std::wstring>& watchNamesLower)
{
    bool matched = false;

    do
    {
        if (watchNamesLower.empty())
        {
            break;
        }

        for (const TiPayloadField& field : record.Payload)
        {
            if (field.Value.empty() || field.Value[0] == L'<')
            {
                continue;
            }

            std::wstring nameLower = ToLowerInPlace(field.Name);
            std::wstring valueLower = ToLowerInPlace(field.Value);
            const bool driverishName =
                nameLower.find(L"driver") != std::wstring::npos ||
                nameLower.find(L"imagefilename") != std::wstring::npos ||
                nameLower.find(L"filename") != std::wstring::npos ||
                nameLower.find(L"device") != std::wstring::npos;
            const bool sysValue =
                valueLower.size() >= 4 &&
                valueLower.compare(valueLower.size() - 4, 4, L".sys") == 0;
            if (!driverishName && !sysValue)
            {
                continue;
            }

            std::wstring base = BasenameLower(field.Value);
            if (base.empty())
            {
                continue;
            }
            for (const std::wstring& watch : watchNamesLower)
            {
                if (base == watch)
                {
                    matched = true;
                    break;
                }
            }
            if (matched)
            {
                break;
            }
        }
    } while (false);

    return matched;
}

std::wstring TiSubscriber::BasenameLower(const std::wstring& path)
{
    if (path.empty())
    {
        return path;
    }
    size_t slash = path.find_last_of(L"\\/");
    std::wstring base = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
    return ToLowerInPlace(std::move(base));
}

void TiSubscriber::EnqueuePrint(TiEventRecord&& record)
{
    const uint32_t throttlePerSec = Options.ThrottlePerSecond;
    const uint64_t nowMs = GetTickCount64();
    const uint64_t windowStart = ThrottleWindowStartMs.load();

    if (windowStart == 0 || (nowMs - windowStart) >= 1000)
    {
        ThrottleWindowStartMs.store(nowMs);
        ThrottleWindowCount.store(0);
    }

    uint32_t inWindow = ThrottleWindowCount.fetch_add(1) + 1;
    if (inWindow > throttlePerSec)
    {
        ThrottleSuppressed.fetch_add(1);
        return;
    }

    std::lock_guard<std::mutex> printLock(PrintMutex);
    // Bound the print queue so a stalled reader doesn't grow it unboundedly.
    while (PrintQueue.size() > 1024)
    {
        PrintQueue.pop_front();
        ThrottleSuppressed.fetch_add(1);
    }
    PrintQueue.push_back(std::move(record));
}

std::vector<TiEventRecord> TiSubscriber::DrainPrintQueue(size_t maxCount)
{
    std::vector<TiEventRecord> out;
    std::lock_guard<std::mutex> printLock(PrintMutex);
    while (!PrintQueue.empty() && (maxCount == 0 || out.size() < maxCount))
    {
        out.push_back(std::move(PrintQueue.front()));
        PrintQueue.pop_front();
    }
    return out;
}

uint64_t TiSubscriber::ConsumeThrottleSuppressedCount()
{
    return ThrottleSuppressed.exchange(0);
}

std::wstring TiSubscriber::ResolveImageBasename(uint32_t pid)
{
    if (pid == 0)
    {
        return std::wstring();
    }
    std::wstring full = GetCachedImageOrResolve(pid);
    return BasenameLower(full);
}

std::vector<TiEventRecord> TiSubscriber::RecentSince(uint64_t minTimestampInclusive, size_t maxCount) const
{
    std::vector<TiEventRecord> out;
    std::lock_guard<std::mutex> lock(RingMutex);
    for (const TiEventRecord& item : Ring)
    {
        if (minTimestampInclusive != 0 && item.Timestamp < minTimestampInclusive)
        {
            continue;
        }
        out.push_back(item);
        if (maxCount != 0 && out.size() >= maxCount)
        {
            break;
        }
    }
    return out;
}

uint64_t TiSubscriber::PeekNextSequence() const
{
    std::lock_guard<std::mutex> lock(RingMutex);
    return NextRingSequence;
}

std::vector<TiEventRecord> TiSubscriber::RecentAfterSequence(uint64_t minSequenceExclusive, size_t maxCount) const
{
    return RecentAfterSequenceWithStatus(minSequenceExclusive, maxCount).Records;
}

TiSequenceSnapshot TiSubscriber::RecentAfterSequenceWithStatus(uint64_t minSequenceExclusive, size_t maxCount) const
{
    std::lock_guard<std::mutex> stateLock(StateMutex);
    std::lock_guard<std::mutex> traceLock(TraceMutex);
    std::lock_guard<std::mutex> lock(RingMutex);
    TiSequenceSnapshot snapshot = SnapshotTiSequenceRange(Ring, NextRingSequence - 1, minSequenceExclusive, maxCount);
    snapshot.Generation = TraceLifecycle.Generation;
    snapshot.GenerationFirstSequence = TraceLifecycle.FirstSequence;
    return snapshot;
}

std::vector<TiEventRecord> TiSubscriber::Recent(size_t maxCount, bool newestFirst) const
{
    std::vector<TiEventRecord> out;
    std::lock_guard<std::mutex> lock(RingMutex);
    if (Ring.empty())
    {
        return out;
    }
    size_t total = (maxCount == 0 || maxCount > Ring.size()) ? Ring.size() : maxCount;
    if (newestFirst)
    {
        out.reserve(total);
        for (size_t i = 0; i < total; ++i)
        {
            out.push_back(Ring[Ring.size() - 1 - i]);
        }
    }
    else
    {
        size_t start = Ring.size() - total;
        out.reserve(total);
        for (size_t i = start; i < Ring.size(); ++i)
        {
            out.push_back(Ring[i]);
        }
    }
    return out;
}

std::vector<TiEventRecord> TiSubscriber::FilterByPid(uint32_t pid, size_t maxCount) const
{
    std::vector<TiEventRecord> out;
    std::lock_guard<std::mutex> lock(RingMutex);
    for (auto it = Ring.rbegin(); it != Ring.rend(); ++it)
    {
        // Match caller or cross-process target so !ti by pid <victim> surfaces
        // WriteVM/AllocVM/etc. against that process (same as MatchesWatch).
        if (it->ProcessId == pid || it->TargetProcessId == pid)
        {
            out.push_back(*it);
            if (maxCount != 0 && out.size() >= maxCount)
            {
                break;
            }
        }
    }
    return out;
}

std::vector<TiEventRecord> TiSubscriber::FilterByTask(const std::wstring& taskName, size_t maxCount) const
{
    std::vector<TiEventRecord> out;
    std::wstring needle = ToLowerInPlace(taskName);
    std::lock_guard<std::mutex> lock(RingMutex);
    for (auto it = Ring.rbegin(); it != Ring.rend(); ++it)
    {
        std::wstring hay = ToLowerInPlace(it->TaskName);
        if (hay.find(needle) != std::wstring::npos)
        {
            out.push_back(*it);
            if (maxCount != 0 && out.size() >= maxCount)
            {
                break;
            }
        }
    }
    return out;
}

std::vector<TiEventRecord> TiSubscriber::Grep(const std::wstring& pattern, size_t maxCount) const
{
    std::vector<TiEventRecord> out;
    std::wstring needle = ToLowerInPlace(pattern);
    std::lock_guard<std::mutex> lock(RingMutex);
    for (auto it = Ring.rbegin(); it != Ring.rend(); ++it)
    {
        std::wstring hay;
        hay.reserve(256);
        hay += ToLowerInPlace(it->ImagePath);
        hay.push_back(L'|');
        hay += ToLowerInPlace(it->TaskName);
        for (const TiPayloadField& f : it->Payload)
        {
            hay.push_back(L'|');
            hay += ToLowerInPlace(f.Name);
            hay.push_back(L'=');
            hay += ToLowerInPlace(f.Value);
        }
        if (hay.find(needle) != std::wstring::npos)
        {
            out.push_back(*it);
            if (maxCount != 0 && out.size() >= maxCount)
            {
                break;
            }
        }
    }
    return out;
}

bool TiSubscriber::SaveTo(const std::wstring& path, std::wstring* error) const
{
    HANDLE h = CreateFileW(path.c_str(),
                            GENERIC_WRITE,
                            FILE_SHARE_READ,
                            nullptr,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        if (error != nullptr)
        {
            *error = L"could not open output file";
        }
        return false;
    }

    // Snapshot under the lock then release before the (slow) WriteFile pass,
    // so the ETW callback thread is not blocked for the duration of disk
    // I/O on a potentially-million-event ring.
    std::vector<TiEventRecord> snapshot;
    {
        std::lock_guard<std::mutex> lock(RingMutex);
        snapshot.reserve(Ring.size());
        for (const TiEventRecord& r : Ring)
        {
            snapshot.push_back(r);
        }
    }

    for (const TiEventRecord& r : snapshot)
    {
        std::wstringstream line;
        line << L"{\"ts\":\"" << JsonEscape(TimestampUtcString(r.Timestamp)) << L"\""
              << L",\"pid\":" << r.ProcessId
              << L",\"tid\":" << r.ThreadId
              << L",\"image\":\"" << JsonEscape(r.ImagePath) << L"\""
              << L",\"task_id\":" << r.TaskId
              << L",\"task\":\"" << JsonEscape(r.TaskName) << L"\""
              << L",\"opcode\":" << static_cast<unsigned>(r.Opcode)
              << L",\"level\":" << static_cast<unsigned>(r.Level)
              << L",\"keyword\":\"0x" << FormatHex64(r.Keyword) << L"\""
              << L",\"version\":" << r.Version;
        AppendTiGenerationJson(line, r);

        if (!r.Payload.empty())
        {
            line << L",\"payload\":{";
            bool first = true;
            for (const TiPayloadField& f : r.Payload)
            {
                if (!first)
                {
                    line << L",";
                }
                first = false;
                line << L"\"" << JsonEscape(f.Name) << L"\":\""
                      << JsonEscape(f.Value) << L"\"";
            }
            line << L"}";
        }

        if (!r.DecodedByTdh && !r.RawPayloadHex.empty())
        {
            line << L",\"raw\":\"" << JsonEscape(r.RawPayloadHex) << L"\"";
        }

        line << L"}\n";

        std::string utf8 = WideToUtf8(line.str());
        DWORD written = 0;
        WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    }
    CloseHandle(h);
    return true;
}

void TiSubscriber::Clear()
{
    std::lock_guard<std::mutex> lock(RingMutex);
    Ring.clear();
}

void TiSubscriber::Histogram(
    std::map<std::wstring, uint64_t>* byTaskName,
    std::map<std::wstring, uint64_t>* byImageBase,
    size_t* totalCounted) const
{
    if (byTaskName != nullptr) byTaskName->clear();
    if (byImageBase != nullptr) byImageBase->clear();
    if (totalCounted != nullptr) *totalCounted = 0;

    std::lock_guard<std::mutex> lock(RingMutex);
    for (const TiEventRecord& r : Ring)
    {
        if (byTaskName != nullptr)
        {
            const std::wstring& key = r.TaskName.empty()
                ? std::wstring(L"Task") + std::to_wstring(r.TaskId)
                : r.TaskName;
            (*byTaskName)[key]++;
        }
        if (byImageBase != nullptr)
        {
            std::wstring base;
            if (r.ImagePath.empty())
            {
                base = L"<unknown>";
            }
            else
            {
                size_t slash = r.ImagePath.find_last_of(L"\\/");
                base = (slash == std::wstring::npos)
                    ? r.ImagePath
                    : r.ImagePath.substr(slash + 1);
            }
            (*byImageBase)[base]++;
        }
    }
    if (totalCounted != nullptr)
    {
        *totalCounted = Ring.size();
    }
}

TiSubscriberStats TiSubscriber::SnapshotStats() const
{
    std::lock_guard<std::mutex> stateLock(StateMutex);
    TiSubscriberStats s;
    s.EventsReceived = Stats.EventsReceived.load(std::memory_order_relaxed);
    s.EventsKept = Stats.EventsKept.load(std::memory_order_relaxed);
    s.EventsDropped = Stats.EventsDropped.load(std::memory_order_relaxed);
    s.EventsSelfExcluded = Stats.EventsSelfExcluded.load(std::memory_order_relaxed);
    s.EventsWatchMatched = Stats.EventsWatchMatched.load(std::memory_order_relaxed);
    s.EventsLogged = Stats.EventsLogged.load(std::memory_order_relaxed);
    s.LogBytesWritten = Stats.LogBytesWritten.load(std::memory_order_relaxed);
    s.LogRotations = Stats.LogRotations.load(std::memory_order_relaxed);
    s.EventsLost = Stats.EventsLost.load(std::memory_order_relaxed);
    s.MatchAnyKeyword = kThreatIntelMatchAnyKeyword;
    s.MatchAllKeyword = kThreatIntelMatchAllKeyword;
    s.StartTickMs = Stats.StartTickMs.load(std::memory_order_relaxed);
    s.LastEventTickMs = Stats.LastEventTickMs.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> traceLock(TraceMutex);
        s.Trace = TraceLifecycle;
    }
    {
        std::lock_guard<std::mutex> ringLock(RingMutex);
        s.EarliestAvailableSequence = Ring.empty() ? 0 : Ring.front().Sequence;
        s.LatestAssignedSequence = NextRingSequence - 1;
    }
    return s;
}

bool ThreatIntelSubscriberSelfTest()
{
    struct FixtureImageCacheEntry
    {
        std::wstring Path;
        uint64_t TickMs = 0;
        uint64_t CreateTime = 0;
        bool Failed = false;
    };
    std::unordered_map<uint32_t, FixtureImageCacheEntry> imageCache;
    uint64_t created = 100;
    uint64_t now = 1000;
    bool identityKnown = true;
    bool pathKnown = true;
    bool processAlive = true;
    size_t identityReads = 0;
    size_t pathReads = 0;
    size_t liveReads = 0;
    uint64_t validatedCreated = 0;
    std::wstring currentPath = L"C:\\Games\\game.exe";
    auto readIdentity = [&](uint64_t* value)
    {
        ++identityReads;
        *value = created;
        return identityKnown;
    };
    auto readPath = [&](std::wstring* value)
    {
        ++pathReads;
        *value = currentPath;
        return pathKnown;
    };
    auto stillAlive = [&]()
    {
        ++liveReads;
        return processAlive;
    };
    auto resolve = [&](uint64_t timestamp)
    {
        validatedCreated = ~0ull;
        return ResolveTiImageGeneration(&imageCache, 100, timestamp, now, readIdentity, readPath, stillAlive,
            &validatedCreated);
    };
    const std::unordered_set<uint32_t> noPids;
    const std::unordered_set<uint32_t> explicitPids{100};
    const std::vector<std::wstring> names{L"game.exe"};
    TiEventRecord caller;
    caller.ProcessId = 100;
    caller.ImagePath = resolve(150);
    if (caller.ImagePath != currentPath || validatedCreated != 100 ||
        !TiProcessSelectionMatches(caller, noPids, names))
    {
        return false;
    }
    caller.ImagePath = resolve(175);
    if (pathReads != 1 || identityReads != 2 || liveReads != 2 || caller.ImagePath != currentPath ||
        validatedCreated != 100)
    {
        return false;
    }

    // Watched -> unwatched PID reuse must replace both path and name selection.
    created = 200;
    currentPath = L"C:\\Tools\\tool.exe";
    caller.ImagePath = resolve(250);
    TiEventRecord target;
    target.ProcessId = 999;
    target.TargetProcessId = 100;
    target.TargetImageBase = caller.ImagePath;
    if (caller.ImagePath != currentPath || pathReads != 2 || validatedCreated != 200 ||
        TiProcessSelectionMatches(caller, noPids, names) || TiProcessSelectionMatches(target, noPids, names))
    {
        return false;
    }

    // Unwatched -> watched reuse must work without a permanent PID promotion.
    created = 300;
    currentPath = L"C:\\Games\\game.exe";
    caller.ImagePath = resolve(350);
    target.TargetImageBase = caller.ImagePath;
    if (caller.ImagePath != currentPath || pathReads != 3 || validatedCreated != 300 ||
        !TiProcessSelectionMatches(caller, noPids, names) || !TiProcessSelectionMatches(target, noPids, names) ||
        TiProcessSelectionMatches(caller, noPids, std::vector<std::wstring>{L"other.exe"}))
    {
        return false;
    }

    caller.ProcessCreateTime = validatedCreated;
    caller.TargetProcessCreateTime = validatedCreated;
    std::wstringstream generationJson;
    AppendTiGenerationJson(generationJson, caller);
    if (generationJson.str() != L",\"process_create_time\":\"0x12c\",\"target_create_time\":\"0x12c\"")
    {
        return false;
    }

    // A delayed event from an older generation cannot borrow the current name.
    caller.ImagePath = resolve(250);
    target.TargetImageBase = caller.ImagePath;
    if (!caller.ImagePath.empty() || pathReads != 3 || validatedCreated != 0 ||
        TiProcessSelectionMatches(caller, noPids, names) || TiProcessSelectionMatches(target, noPids, names) ||
        !TiProcessSelectionMatches(caller, explicitPids, names) ||
        !TiProcessSelectionMatches(target, explicitPids, names))
    {
        return false;
    }
    identityKnown = false;
    caller.ImagePath = resolve(350);
    if (!caller.ImagePath.empty() || !imageCache.empty() || validatedCreated != 0 ||
        TiProcessSelectionMatches(caller, noPids, names))
    {
        return false;
    }

    identityKnown = true;
    caller.ImagePath = resolve(350);
    if (caller.ImagePath != currentPath || validatedCreated != 300)
    {
        return false;
    }
    created = 400;
    pathKnown = false;
    caller.ImagePath = resolve(450);
    if (!caller.ImagePath.empty() || validatedCreated != 0 || imageCache.size() != 1 || !imageCache.at(100).Failed ||
        imageCache.at(100).CreateTime != 400 || TiProcessSelectionMatches(caller, noPids, names))
    {
        return false;
    }
    const size_t failedPathReads = pathReads;
    pathKnown = true;
    ++now;
    if (!resolve(450).empty() || pathReads != failedPathReads || validatedCreated != 0)
    {
        return false;
    }
    now += 1000;
    if (resolve(450) != currentPath || pathReads != failedPathReads + 1 || validatedCreated != 400)
    {
        return false;
    }

    // Exit after identity/path capture invalidates even a positive cache hit.
    processAlive = false;
    if (!resolve(450).empty() || !imageCache.empty() || validatedCreated != 0)
    {
        return false;
    }
    processAlive = true;
    if (resolve(450) != currentPath || validatedCreated != 400)
    {
        return false;
    }
    created = 0;
    if (!resolve(450).empty() || !imageCache.empty() || validatedCreated != 0)
    {
        return false;
    }
    caller.ProcessCreateTime = validatedCreated;
    caller.TargetProcessCreateTime = validatedCreated;
    std::wstringstream unknownGenerationJson;
    AppendTiGenerationJson(unknownGenerationJson, caller);
    if (unknownGenerationJson.str() != L",\"process_create_time\":\"0x0\",\"target_create_time\":\"0x0\"")
    {
        return false;
    }

    std::vector<uint8_t> extension(8 + 65 * 8, 0);
    const uint64_t matchId = 0x00007fff12340000ull;
    memcpy(extension.data(), &matchId, 8);
    for (uint64_t index = 0; index < 65; ++index)
    {
        const uint64_t address = 0x100000 + index;
        memcpy(extension.data() + 8 + index * 8, &address, 8);
    }
    std::vector<uint64_t> frames;
    if (!AppendTiStackFrames(extension.data(), extension.size(), 8, &frames) || frames.size() != 64 ||
        frames.front() != 0x100000 || frames.back() != 0x10003f)
    {
        return false;
    }
    frames.clear();
    const uint32_t frame32 = 0x87654321;
    memcpy(extension.data() + 8, &frame32, 4);
    if (!AppendTiStackFrames(extension.data(), 12, 4, &frames) || frames != std::vector<uint64_t>{frame32} ||
        AppendTiStackFrames(extension.data(), 7, 4, &frames) ||
        AppendTiStackFrames(extension.data(), 13, 4, &frames) || frames.size() != 1 ||
        TiScalarBytes(TDH_INTYPE_POINTER, EVENT_HEADER_FLAG_32_BIT_HEADER) != 4 ||
        TiScalarBytes(TDH_INTYPE_POINTER, EVENT_HEADER_FLAG_64_BIT_HEADER) != 8 ||
        TiScalarBytes(TDH_INTYPE_GUID, 0) != 16)
    {
        return false;
    }
    TiTraceLifecycle trace;
    trace.Generation = 2;
    trace.ThreadRunning = true;
    if (CompleteTraceGeneration(&trace, 1, ERROR_CANCELLED, 100) || !trace.ThreadRunning)
    {
        return false;
    }
    if (!CompleteTraceGeneration(&trace, 2, ERROR_WMI_INSTANCE_NOT_FOUND, 200) ||
        trace.ThreadRunning || !trace.ExitStatusKnown || trace.ExitAfterStopRequest ||
        trace.ExitStatus != ERROR_WMI_INSTANCE_NOT_FOUND || trace.ExitTickMs != 200)
    {
        return false;
    }
    trace.Generation = 3;
    trace.ThreadRunning = true;
    trace.StopRequested = true;
    if (!CompleteTraceGeneration(&trace, 3, ERROR_CANCELLED, 300) || !trace.ExitAfterStopRequest)
    {
        return false;
    }

    std::deque<TiEventRecord> ring;
    for (uint64_t sequence = 8; sequence <= 12; ++sequence)
    {
        TiEventRecord record;
        record.Sequence = sequence;
        ring.push_back(record);
    }
    TiSequenceSnapshot snapshot = SnapshotTiSequenceRange(ring, 12, 5, 2);
    if (snapshot.MissingBeforeFirst != 2 || snapshot.Records.size() != 2 ||
        snapshot.Records[0].Sequence != 8 || snapshot.Records[1].Sequence != 9 ||
        !snapshot.HasMore || snapshot.CursorAhead || snapshot.EarliestAvailableSequence != 8)
    {
        return false;
    }
    snapshot = SnapshotTiSequenceRange(ring, 12, 9, 0);
    if (snapshot.MissingBeforeFirst != 0 || snapshot.Records.size() != 3 || snapshot.HasMore)
    {
        return false;
    }
    snapshot = SnapshotTiSequenceRange(ring, 12, 0, 1);
    if (snapshot.MissingBeforeFirst != 0 || snapshot.Records.size() != 1)
    {
        return false;
    }
    snapshot = SnapshotTiSequenceRange(ring, 12, 13, 1);
    if (!snapshot.CursorAhead || !snapshot.Records.empty() || snapshot.MissingBeforeFirst != 0)
    {
        return false;
    }
    ring.clear();
    snapshot = SnapshotTiSequenceRange(ring, 12, 9, 1);
    return snapshot.MissingBeforeFirst == 3 && snapshot.Records.empty() &&
        snapshot.EarliestAvailableSequence == 0 && snapshot.LatestAssignedSequence == 12;
}

bool TiSubscriber::AddWatchPid(uint32_t pid)
{
    if (pid == 0)
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(WatchMutex);
    WatchPids.insert(pid);
    return true;
}

bool TiSubscriber::RemoveWatchPid(uint32_t pid)
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    size_t erased = WatchPids.erase(pid);
    return erased > 0;
}

bool TiSubscriber::AddWatchName(const std::wstring& imageBase)
{
    std::wstring lower = ToLowerInPlace(imageBase);
    if (lower.empty())
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(WatchMutex);
    for (const std::wstring& existing : WatchNamesLower)
    {
        if (existing == lower)
        {
            return false;
        }
    }
    WatchNamesLower.push_back(std::move(lower));
    return true;
}

bool TiSubscriber::RemoveWatchName(const std::wstring& imageBase)
{
    std::wstring lower = ToLowerInPlace(imageBase);
    std::lock_guard<std::mutex> lock(WatchMutex);
    auto it = std::find(WatchNamesLower.begin(), WatchNamesLower.end(), lower);
    if (it == WatchNamesLower.end())
    {
        return false;
    }
    WatchNamesLower.erase(it);
    return true;
}

std::vector<std::wstring> TiSubscriber::SessionLogPaths() const
{
    std::lock_guard<std::mutex> lock(LogMutex);
    return OpenedLogPaths;
}

std::wstring TiSubscriber::BuildLogFilePath(int rotationIndex) const
{
    std::wstringstream ss;
    ss << Options.LogDirectory;
    if (!Options.LogDirectory.empty() &&
        Options.LogDirectory.back() != L'\\' &&
        Options.LogDirectory.back() != L'/')
    {
        ss << L"\\";
    }
    ss << Options.LogBaseName;
    if (rotationIndex == 0)
    {
        // Initial file uses a high-resolution timestamp + pid to avoid
        // collisions when the subscriber is restarted within the same second.
        SYSTEMTIME st = {};
        GetSystemTime(&st);
        wchar_t suffix[80] = {};
        swprintf_s(suffix, L"-%04u%02u%02u-%02u%02u%02u-%03u-%u",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    GetCurrentProcessId());
        ss << suffix << L".jsonl";
    }
    else
    {
        ss << L"." << rotationIndex << L".jsonl";
    }
    return ss.str();
}

bool TiSubscriber::EnsureLogOpenLocked()
{
    if (LogHandle != INVALID_HANDLE_VALUE)
    {
        return true;
    }

    LogActivePath = BuildLogFilePath(0);
    LogHandle = CreateFileW(LogActivePath.c_str(),
                             GENERIC_WRITE,
                             FILE_SHARE_READ,
                             nullptr,
                             CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (LogHandle == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    LogCurrentBytes = 0;
    LogActiveRotation = 0;
    OpenedLogPaths.push_back(LogActivePath);
    return true;
}

void TiSubscriber::CloseLogLocked()
{
    if (LogHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(LogHandle);
        LogHandle = INVALID_HANDLE_VALUE;
    }
}

void TiSubscriber::RotateLogLocked()
{
    CloseLogLocked();

    // Wrap the rotation index back to 1 when we have written LogRotateCount
    // files. The current path's rotation index is between 1 and
    // LogRotateCount inclusive. We delete the file at the next index (which
    // is the oldest by age) before opening it to keep the on-disk set
    // bounded.
    const uint32_t cap = (Options.LogRotateCount == 0) ? 1u : Options.LogRotateCount;
    int nextIndex = LogActiveRotation + 1;
    if (nextIndex > static_cast<int>(cap))
    {
        nextIndex = 1;
    }
    LogActiveRotation = nextIndex;
    LogActivePath = BuildLogFilePath(LogActiveRotation);
    OpenedLogPaths.push_back(LogActivePath);

    // Best-effort delete; the file may not exist yet on first wrap.
    DeleteFileW(LogActivePath.c_str());

    LogHandle = CreateFileW(LogActivePath.c_str(),
                             GENERIC_WRITE,
                             FILE_SHARE_READ,
                             nullptr,
                             CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (LogHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }
    LogCurrentBytes = 0;
    Stats.LogRotations.fetch_add(1, std::memory_order_relaxed);
}

bool TiSubscriber::WriteLogLine(const TiEventRecord& record)
{
    std::lock_guard<std::mutex> logLock(LogMutex);
    if (!EnsureLogOpenLocked())
    {
        return false;
    }

    std::wstringstream line;
    line << L"{\"ts\":\"" << JsonEscape(TimestampUtcString(record.Timestamp)) << L"\""
          << L",\"pid\":" << record.ProcessId
          << L",\"tid\":" << record.ThreadId
          << L",\"image\":\"" << JsonEscape(record.ImagePath) << L"\""
          << L",\"task_id\":" << record.TaskId
          << L",\"task\":\"" << JsonEscape(record.TaskName) << L"\""
          << L",\"opcode\":" << static_cast<unsigned>(record.Opcode)
          << L",\"level\":" << static_cast<unsigned>(record.Level)
          << L",\"keyword\":\"0x" << FormatHex64(record.Keyword) << L"\""
          << L",\"version\":" << record.Version;
    AppendTiGenerationJson(line, record);

    if (!record.Payload.empty())
    {
        line << L",\"payload\":{";
        bool first = true;
        for (const TiPayloadField& f : record.Payload)
        {
            if (!first)
            {
                line << L",";
            }
            first = false;
            line << L"\"" << JsonEscape(f.Name) << L"\":\""
                  << JsonEscape(f.Value) << L"\"";
        }
        line << L"}";
    }

    if (!record.DecodedByTdh && !record.RawPayloadHex.empty())
    {
        line << L",\"raw\":\"" << JsonEscape(record.RawPayloadHex) << L"\"";
    }

    line << L"}\n";

    std::string utf8 = WideToUtf8(line.str());
    const char* cursor = utf8.data();
    size_t remaining = utf8.size();
    DWORD totalWritten = 0;
    while (remaining > 0)
    {
        DWORD chunk = (remaining > 0x100000) ? 0x100000u : static_cast<DWORD>(remaining);
        DWORD written = 0;
        if (!WriteFile(LogHandle, cursor, chunk, &written, nullptr) || written == 0)
        {
            return false;
        }
        cursor += written;
        remaining -= written;
        totalWritten += written;
    }

    LogCurrentBytes += totalWritten;
    Stats.LogBytesWritten.fetch_add(totalWritten, std::memory_order_relaxed);
    Stats.EventsLogged.fetch_add(1, std::memory_order_relaxed);

    if (Options.LogRotateBytes > 0 && LogCurrentBytes >= Options.LogRotateBytes)
    {
        RotateLogLocked();
    }

    return true;
}
