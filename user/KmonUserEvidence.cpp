#include "KmonUserEvidence.h"

#include <ProcessSnapshot.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <dia2.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace
{
    constexpr uint64_t kUserMax = 0x00007fffffffffffULL;
    constexpr uint32_t kMaxSnapshotThreads = 16384;
    constexpr uint32_t kMaxSelectedThreads = 256;
    constexpr uint32_t kMaxSelectedModules = 128;
    constexpr uint32_t kMaxCallbacks = 256;
    constexpr uint32_t kMaxEnumeratedCallbacks = 4096;

    struct OwnedHandle
    {
        HANDLE Value = nullptr;

        ~OwnedHandle()
        {
            if (Value != nullptr && Value != INVALID_HANDLE_VALUE)
            {
                CloseHandle(Value);
            }
        }
    };

    struct OwnedSnapshot
    {
        HPSS Snapshot = nullptr;
        HPSSWALK Marker = nullptr;

        ~OwnedSnapshot()
        {
            if (Marker != nullptr)
            {
                PssWalkMarkerFree(Marker);
            }
            if (Snapshot != nullptr)
            {
                PssFreeSnapshot(GetCurrentProcess(), Snapshot);
            }
        }
    };

    uint64_t FileTimeValue(const FILETIME& value)
    {
        return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }

    bool UserRange(uint64_t start, uint64_t length)
    {
        return start >= 0x10000 && length != 0 && start <= kUserMax && length - 1 <= kUserMax - start;
    }

    bool ProcessGeneration(HANDLE process, uint64_t expected, uint64_t* actual)
    {
        FILETIME create = {}, exit = {}, kernel = {}, user = {};
        const bool ok = process != nullptr && expected != 0 &&
            GetProcessTimes(process, &create, &exit, &kernel, &user) != FALSE &&
            FileTimeValue(create) == expected && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
        if (actual != nullptr)
        {
            *actual = FileTimeValue(create);
        }
        return ok;
    }

    template<typename T, typename Key>
    std::vector<T> SelectAfter(const std::vector<T>& input, uint64_t after, size_t budget, Key key)
    {
        std::vector<T> sorted = input;
        std::sort(sorted.begin(), sorted.end(), [&](const T& a, const T& b)
        {
            return key(a) < key(b);
        });
        sorted.erase(std::unique(sorted.begin(), sorted.end(), [&](const T& a, const T& b)
        {
            return key(a) == key(b);
        }), sorted.end());
        std::vector<T> selected;
        if (!sorted.empty())
        {
            auto first = std::upper_bound(sorted.begin(), sorted.end(), after, [&](uint64_t value, const T& item)
            {
                return value < key(item);
            });
            size_t offset = static_cast<size_t>(first - sorted.begin()) % sorted.size();
            const size_t count = (std::min)(budget, sorted.size());
            selected.reserve(count);
            for (size_t i = 0; i < count; ++i)
            {
                selected.push_back(sorted[(offset + i) % sorted.size()]);
            }
        }
        return selected;
    }

    bool DecodeSnapshotContext(const void* buffer, size_t length, bool wow64, KmonThreadContextRecord* record)
    {
        bool ok = false;
        do
        {
            if (buffer == nullptr || record == nullptr)
            {
                break;
            }
            record->Wow64 = wow64;
            if (wow64)
            {
                if (length < sizeof(WOW64_CONTEXT))
                {
                    break;
                }
                WOW64_CONTEXT context = {};
                std::memcpy(&context, buffer, sizeof(context));
                if ((context.ContextFlags & 0x00ff0000UL) != WOW64_CONTEXT_i386)
                {
                    break;
                }
                record->ControlValid = (context.ContextFlags & WOW64_CONTEXT_CONTROL) == WOW64_CONTEXT_CONTROL;
                record->DebugValid = (context.ContextFlags & WOW64_CONTEXT_DEBUG_REGISTERS) == WOW64_CONTEXT_DEBUG_REGISTERS;
                record->InstructionPointer = context.Eip;
                record->StackPointer = context.Esp;
                record->DebugAddress = {context.Dr0, context.Dr1, context.Dr2, context.Dr3};
                record->DebugControl = context.Dr7;
            }
            else
            {
                if (length < sizeof(CONTEXT))
                {
                    break;
                }
                CONTEXT context = {};
                std::memcpy(&context, buffer, sizeof(context));
                if ((context.ContextFlags & 0x00ff0000UL) != CONTEXT_AMD64)
                {
                    break;
                }
                record->ControlValid = (context.ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL;
                record->DebugValid = (context.ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS;
                record->InstructionPointer = context.Rip;
                record->StackPointer = context.Rsp;
                record->DebugAddress = {context.Dr0, context.Dr1, context.Dr2, context.Dr3};
                record->DebugControl = context.Dr7;
            }
            ok = record->ControlValid && record->DebugValid;
        } while (false);
        return ok;
    }

    bool QueryFileFields(HANDLE file, KmonFileIdentity* result)
    {
        FILE_ID_INFO id = {};
        FILE_BASIC_INFO basic = {};
        FILE_STANDARD_INFO standard = {};
        FILE_ATTRIBUTE_TAG_INFO tag = {};
        const bool ok = GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) != FALSE &&
            GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) != FALSE &&
            GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) != FALSE &&
            GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) != FALSE &&
            !standard.Directory && standard.EndOfFile.QuadPart >= 0;
        if (ok)
        {
            result->VolumeSerial = id.VolumeSerialNumber;
            std::memcpy(result->FileId.data(), id.FileId.Identifier, result->FileId.size());
            result->CreationTime = static_cast<uint64_t>(basic.CreationTime.QuadPart);
            result->LastWriteTime = static_cast<uint64_t>(basic.LastWriteTime.QuadPart);
            result->ChangeTime = static_cast<uint64_t>(basic.ChangeTime.QuadPart);
            result->Size = static_cast<uint64_t>(standard.EndOfFile.QuadPart);
            result->Links = standard.NumberOfLinks;
            result->Attributes = basic.FileAttributes;
            result->ReparseTag = tag.ReparseTag;
            result->Stable = true;
        }
        return ok;
    }

    std::wstring OpenablePath(const std::wstring& path)
    {
        std::wstring result = path;
        if (result.compare(0, 4, L"\\??\\") == 0)
        {
            result.replace(0, 4, L"\\\\?\\");
        }
        else if (_wcsnicmp(result.c_str(), L"\\SystemRoot\\", 12) == 0)
        {
            wchar_t windows[MAX_PATH] = {};
            const UINT count = GetWindowsDirectoryW(windows, ARRAYSIZE(windows));
            if (count != 0 && count < ARRAYSIZE(windows))
            {
                result = std::wstring(windows, count) + result.substr(11);
            }
        }
        else if (_wcsnicmp(result.c_str(), L"\\Device\\", 8) == 0)
        {
            result = L"\\\\?\\GLOBALROOT" + result;
        }
        return result;
    }
}

bool CaptureKmonThreadSnapshot(
    uint32_t processId,
    uint64_t expectedCreateTime,
    uint32_t maxThreads,
    uint32_t afterThreadId,
    KmonThreadSnapshot* result,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        if (result == nullptr)
        {
            break;
        }
        *result = KmonThreadSnapshot{};
        if (processId <= 4 || expectedCreateTime == 0 || maxThreads == 0)
        {
            result->Coverage.Detail = L"snapshot requires a live process generation and a nonzero budget";
            break;
        }
        OwnedHandle process;
        process.Value = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
            PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | SYNCHRONIZE, FALSE, processId);
        if (!ProcessGeneration(process.Value, expectedCreateTime, &result->ProcessCreateTime))
        {
            result->Coverage.Detail = L"process snapshot access or generation validation failed";
            break;
        }
        BOOL wow64 = FALSE;
        if (!IsWow64Process(process.Value, &wow64))
        {
            result->Coverage.Detail = L"snapshot architecture is unavailable";
            break;
        }
        result->Wow64 = wow64 != FALSE;
        OwnedSnapshot snapshot;
        const DWORD contextFlags = wow64 ?
            (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_DEBUG_REGISTERS) :
            (CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS);
        const DWORD status = PssCaptureSnapshot(process.Value,
            static_cast<PSS_CAPTURE_FLAGS>(PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT),
            contextFlags, &snapshot.Snapshot);
        if (status != ERROR_SUCCESS)
        {
            result->Coverage.Detail = L"PSS context capture unavailable: " + std::to_wstring(status);
            break;
        }
        PSS_PROCESS_INFORMATION identity = {};
        PSS_THREAD_INFORMATION inventory = {};
        if (PssQuerySnapshot(snapshot.Snapshot, PSS_QUERY_PROCESS_INFORMATION, &identity, sizeof(identity)) != ERROR_SUCCESS ||
            identity.ProcessId != processId || FileTimeValue(identity.CreateTime) != expectedCreateTime ||
            PssQuerySnapshot(snapshot.Snapshot, PSS_QUERY_THREAD_INFORMATION, &inventory, sizeof(inventory)) != ERROR_SUCCESS ||
            inventory.ThreadsCaptured > kMaxSnapshotThreads ||
            PssWalkMarkerCreate(nullptr, &snapshot.Marker) != ERROR_SUCCESS)
        {
            result->Coverage.Detail = L"PSS identity, thread inventory, or bounded walk is unavailable";
            result->Coverage.Truncated = inventory.ThreadsCaptured > kMaxSnapshotThreads;
            break;
        }
        std::vector<KmonThreadContextRecord> contexts;
        DWORD walkStatus = ERROR_SUCCESS;
        uint32_t visited = 0;
        for (; visited <= kMaxSnapshotThreads; ++visited)
        {
            PSS_THREAD_ENTRY entry = {};
            walkStatus = PssWalkSnapshot(snapshot.Snapshot, PSS_WALK_THREADS, snapshot.Marker, &entry, sizeof(entry));
            if (walkStatus != ERROR_SUCCESS)
            {
                break;
            }
            if (entry.ProcessId != processId || entry.ThreadId == 0 ||
                (entry.Flags & PSS_THREAD_FLAGS_TERMINATED) != 0)
            {
                ++result->Coverage.Failures;
                continue;
            }
            KmonThreadContextRecord context;
            context.ThreadId = entry.ThreadId;
            context.CreateTime = FileTimeValue(entry.CreateTime);
            context.CaptureTime = FileTimeValue(entry.CaptureTime);
            if (!DecodeSnapshotContext(entry.ContextRecord, entry.SizeOfContextRecord, result->Wow64, &context))
            {
                ++result->Coverage.Failures;
            }
            contexts.push_back(context);
        }
        if (!ProcessGeneration(process.Value, expectedCreateTime, nullptr))
        {
            result->Coverage.Detail = L"process generation changed during PSS capture";
            break;
        }
        result->Threads = SelectAfter(contexts, afterThreadId,
            (std::min)(maxThreads, kMaxSelectedThreads), [](const KmonThreadContextRecord& item)
            {
                return static_cast<uint64_t>(item.ThreadId);
            });
        if (!result->Threads.empty())
        {
            result->NextThreadCursor = result->Threads.back().ThreadId;
        }
        result->Coverage.Available = true;
        result->Coverage.Truncated = result->Threads.size() < contexts.size() || visited > kMaxSnapshotThreads;
        result->Coverage.Complete = walkStatus == ERROR_NO_MORE_ITEMS && visited == inventory.ThreadsCaptured &&
            result->Coverage.Failures == 0 && !result->Coverage.Truncated;
        result->Coverage.Detail = result->Wow64 ? L"PSS WOW64 context records; unsupported layouts remain unknown" :
            L"PSS AMD64 context records";
        ok = true;
    } while (false);
    if (!ok && result != nullptr)
    {
        ++result->Coverage.Failures;
        if (error != nullptr)
        {
            *error = result->Coverage.Detail;
        }
    }
    return ok;
}

bool KmonSameFileObject(const KmonFileIdentity& left, const KmonFileIdentity& right)
{
    return left.Stable && right.Stable && left.VolumeSerial == right.VolumeSerial && left.FileId == right.FileId;
}

bool KmonSameFileGeneration(const KmonFileIdentity& left, const KmonFileIdentity& right)
{
    return KmonSameFileObject(left, right) && left.CreationTime == right.CreationTime &&
        left.LastWriteTime == right.LastWriteTime && left.ChangeTime == right.ChangeTime && left.Size == right.Size;
}

bool QueryKmonFileIdentity(const std::wstring& path, KmonFileIdentity* result, std::wstring* error)
{
    bool ok = false;
    do
    {
        if (result == nullptr)
        {
            break;
        }
        *result = KmonFileIdentity{};
        result->RequestedPath = path;
        if (path.empty() || path.size() > 32767)
        {
            break;
        }
        OwnedHandle file;
        const std::wstring openPath = OpenablePath(path);
        file.Value = CreateFileW(openPath.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (file.Value == INVALID_HANDLE_VALUE || !QueryFileFields(file.Value, result))
        {
            break;
        }
        std::vector<wchar_t> name(32768, 0);
        const DWORD count = GetFinalPathNameByHandleW(file.Value, name.data(), static_cast<DWORD>(name.size()),
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
        if (count == 0 || count >= name.size())
        {
            break;
        }
        result->FinalPath.assign(name.data(), count);
        OwnedHandle pathObject;
        pathObject.Value = CreateFileW(openPath.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        FILE_ATTRIBUTE_TAG_INFO pathTag = {};
        if (pathObject.Value != INVALID_HANDLE_VALUE &&
            GetFileInformationByHandleEx(pathObject.Value, FileAttributeTagInfo, &pathTag, sizeof(pathTag)))
        {
            result->PathAttributes = pathTag.FileAttributes;
            result->PathReparseTag = pathTag.ReparseTag;
            result->PathMetadataKnown = true;
        }
        KmonFileIdentity after;
        if (!QueryFileFields(file.Value, &after) || !KmonSameFileGeneration(*result, after) ||
            result->Links != after.Links || result->Attributes != after.Attributes || result->ReparseTag != after.ReparseTag)
        {
            break;
        }
        ok = true;
    } while (false);
    if (!ok && result != nullptr)
    {
        result->Stable = false;
        if (error != nullptr)
        {
            *error = L"file identity or generation could not be validated";
        }
    }
    return ok;
}

namespace
{
    const GUID kClrRuntime = {0xe13c0d23, 0xccbc, 0x4e12, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4}};
    const GUID kClrRundown = {0xa669021c, 0xc450, 0x4609, {0xa0, 0x35, 0x5a, 0xf5, 0x9a, 0xf4, 0xdf, 0x18}};

    template<typename T>
    bool EventInteger(PEVENT_RECORD event, const wchar_t* name, T* value)
    {
        PROPERTY_DATA_DESCRIPTOR property = {};
        property.PropertyName = reinterpret_cast<ULONGLONG>(name);
        property.ArrayIndex = ULONG_MAX;
        ULONG length = 0;
        return TdhGetPropertySize(event, 0, nullptr, 1, &property, &length) == ERROR_SUCCESS &&
            length == sizeof(T) &&
            TdhGetProperty(event, 0, nullptr, 1, &property, length, reinterpret_cast<PBYTE>(value)) == ERROR_SUCCESS;
    }

    enum class RuntimeEventAction
    {
        Ignore,
        Load,
        Unload
    };

    struct RuntimeRundownRequest
    {
        bool Pending = false;
        bool Attempted = false;
        uint64_t LastAttemptTick = 0;
    };

    bool BeginRuntimeRundownAttempt(RuntimeRundownRequest* request, uint64_t now)
    {
        const bool due = request->Pending &&
            (!request->Attempted || now - request->LastAttemptTick >= 2000);
        if (due)
        {
            request->Attempted = true;
            request->LastAttemptTick = now;
        }
        return due;
    }

    void FinishRuntimeRundownAttempt(RuntimeRundownRequest* request, bool success)
    {
        request->Pending = !success;
    }

    void QueueRuntimeRundown(RuntimeRundownRequest* request, bool added, std::atomic<bool>* invalidated)
    {
        const bool retry = invalidated->exchange(false);
        request->Pending = request->Pending || added || retry;
    }

    struct RuntimeSessionHealth
    {
        uint64_t Epoch = 0;
        ULONG QueryStatus = ERROR_NOT_READY;
        ULONG EventsLost = 0;
        ULONG BuffersLost = 0;
        bool Known = false;
    };

    bool UpdateRuntimeSessionHealth(RuntimeSessionHealth* health, uint64_t epoch,
        ULONG status, ULONG eventsLost, ULONG buffersLost)
    {
        const bool discontinuity = status != ERROR_SUCCESS || !health->Known ||
            health->Epoch != epoch || health->EventsLost != eventsLost || health->BuffersLost != buffersLost;
        health->Epoch = epoch;
        health->QueryStatus = status;
        health->Known = status == ERROR_SUCCESS;
        if (health->Known)
        {
            health->EventsLost = eventsLost;
            health->BuffersLost = buffersLost;
        }
        return discontinuity;
    }

    uint64_t RuntimeFileTimeNow()
    {
        FILETIME value = {};
        GetSystemTimePreciseAsFileTime(&value);
        return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }

    template<typename ProcessMap>
    void InvalidateRuntimeRanges(ProcessMap* processes, uint64_t timestamp,
        uint64_t* minimumTimestamp, std::atomic<bool>* rundownRequired)
    {
        for (auto& process : *processes)
        {
            process.second.Ranges.clear();
            if (process.second.Failures != UINT32_MAX)
            {
                ++process.second.Failures;
            }
        }
        *minimumTimestamp = (std::max)(*minimumTimestamp, timestamp);
        rundownRequired->store(true);
    }

    bool RuntimeEventWithinEpoch(uint64_t timestamp, uint64_t createTime, uint64_t minimumTimestamp)
    {
        return timestamp >= createTime && timestamp >= minimumTimestamp;
    }

    RuntimeEventAction RuntimeAction(bool rundown, uint16_t id, uint8_t version)
    {
        RuntimeEventAction action = RuntimeEventAction::Ignore;
        if (version <= 2)
        {
            if ((!rundown && (id == 141 || id == 143)) ||
                (rundown && (id == 137 || id == 138 || id == 143 || id == 144)))
            {
                action = RuntimeEventAction::Load;
            }
            else if (!rundown && (id == 142 || id == 144))
            {
                action = RuntimeEventAction::Unload;
            }
        }
        return action;
    }

    bool ApplyRuntimeRange(
        std::map<uint64_t, KmonRuntimeCodeRange>* ranges,
        const KmonRuntimeCodeRange& record,
        RuntimeEventAction action,
        size_t capacity,
        uint64_t* retentionFloor,
        bool* ambiguous)
    {
        *ambiguous = false;
        if (action == RuntimeEventAction::Ignore)
        {
            return true;
        }
        if (!UserRange(record.Start, record.Size))
        {
            *ambiguous = true;
            return false;
        }
        if (record.Timestamp <= *retentionFloor)
        {
            return false;
        }
        const auto pruneThrough = [&](uint64_t timestamp)
        {
            *retentionFloor = (std::max)(*retentionFloor, timestamp);
            for (auto it = ranges->begin(); it != ranges->end();)
            {
                if (it->second.Timestamp <= *retentionFloor)
                {
                    it = ranges->erase(it);
                }
                else
                {
                    ++it;
                }
            }
        };
        auto found = ranges->find(record.Start);
        if (found != ranges->end())
        {
            const KmonRuntimeCodeRange& previous = found->second;
            if (record.Timestamp < previous.Timestamp)
            {
                return true;
            }
            const bool sameMethod = previous.MethodId == record.MethodId &&
                previous.RuntimeInstance == record.RuntimeInstance && previous.ModuleId == record.ModuleId;
            const bool sameTime = previous.Timestamp == record.Timestamp;
            if ((sameTime && ((action == RuntimeEventAction::Load &&
                    (previous.Size == 0 || !sameMethod || previous.Size != record.Size)) ||
                    (action == RuntimeEventAction::Unload && (previous.Size != 0 || !sameMethod)))) ||
                (action == RuntimeEventAction::Unload && !sameMethod))
            {
                // Equal timestamps do not order events from different CPUs.
                // Retain a time fence even after recovery clears the cache.
                pruneThrough(record.Timestamp);
                *ambiguous = true;
                return true;
            }
            if (sameTime)
            {
                return true;
            }
            found->second = record;
            if (action == RuntimeEventAction::Unload)
            {
                found->second.Size = 0;
            }
            return true;
        }
        bool complete = true;
        if (capacity == 0)
        {
            pruneThrough(record.Timestamp);
            return false;
        }
        if (ranges->size() >= capacity)
        {
            complete = false;
            const auto oldest = std::min_element(ranges->begin(), ranges->end(), [](const auto& a, const auto& b)
            {
                return a.second.Timestamp < b.second.Timestamp;
            });
            pruneThrough(oldest->second.Timestamp);
            if (record.Timestamp <= *retentionFloor)
            {
                return false;
            }
        }
        KmonRuntimeCodeRange retained = record;
        if (action == RuntimeEventAction::Unload)
        {
            // An unload observed before its load still prevents resurrection
            // by a delayed load or rundown record for this address.
            retained.Size = 0;
        }
        (*ranges)[record.Start] = retained;
        return complete;
    }

    template<typename ProcessRanges>
    void ApplyRuntimeObservation(ProcessRanges* process, const KmonRuntimeCodeRange& record,
        RuntimeEventAction action, size_t capacity, std::atomic<bool>* lost)
    {
        bool ambiguous = false;
        if (!ApplyRuntimeRange(&process->Ranges, record, action, capacity, &process->RetentionFloor, &ambiguous))
        {
            process->Overflow = true;
        }
        if (ambiguous)
        {
            // Snapshot and health maintenance use the existing epoch fence and
            // fresh-rundown recovery path before exposing retained provenance.
            lost->store(true);
        }
    }
}

struct KmonUserRuntimeTracker::Impl
{
    struct ProcessRanges
    {
        uint64_t Created = 0;
        uint64_t LastWatchTick = 0;
        bool Overflow = false;
        uint32_t Failures = 0;
        uint64_t RetentionFloor = 0;
        std::map<uint64_t, KmonRuntimeCodeRange> Ranges;
    };

    std::mutex LifecycleMutex;
    std::mutex DataMutex;
    std::map<uint32_t, ProcessRanges> Processes;
    std::vector<uint8_t> Properties;
    std::wstring SessionName;
    TRACEHANDLE Session = 0;
    TRACEHANDLE Consumer = INVALID_PROCESSTRACE_HANDLE;
    std::thread Worker;
    std::atomic<bool> Active{false};
    std::atomic<bool> Lost{false};
    std::atomic<bool> RundownRequired{false};
    std::atomic<ULONG> ConsumerStatus{ERROR_NOT_READY};
    RuntimeSessionHealth Health;
    uint64_t SessionEpoch = 0;
    uint64_t MinimumEventTimestamp = 0;
    uint64_t LastHealthPollTick = 0;
    bool HealthPollAttempted = false;
    RuntimeRundownRequest Rundown;

    static void WINAPI EventCallback(PEVENT_RECORD event)
    {
        auto* self = static_cast<Impl*>(event->UserContext);
        if (self != nullptr)
        {
            try
            {
                self->Consume(event);
            }
            catch (...)
            {
                self->Lost.store(true);
            }
        }
    }

    bool PollHealthLocked(std::wstring* error)
    {
        const uint64_t tick = GetTickCount64();
        if (HealthPollAttempted && tick - LastHealthPollTick < 2000)
        {
            std::lock_guard<std::mutex> lock(DataMutex);
            return Health.Known;
        }
        HealthPollAttempted = true;
        LastHealthPollTick = tick;
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(Properties.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(Properties.size());
        const ULONG status = ControlTraceW(Session, SessionName.c_str(), properties, EVENT_TRACE_CONTROL_QUERY);
        const uint64_t timestamp = RuntimeFileTimeNow();
        {
            std::lock_guard<std::mutex> lock(DataMutex);
            const bool changed = UpdateRuntimeSessionHealth(&Health, SessionEpoch, status,
                properties->EventsLost, properties->RealTimeBuffersLost);
            const bool callbackFailed = Lost.exchange(false);
            if (changed || callbackFailed)
            {
                InvalidateRuntimeRanges(&Processes, timestamp, &MinimumEventTimestamp, &RundownRequired);
            }
        }
        if (status != ERROR_SUCCESS && error != nullptr)
        {
            *error = L"CLR ETW session health query failed: " + std::to_wstring(status);
        }
        return status == ERROR_SUCCESS;
    }

    void RequestRundownLocked(bool added)
    {
        QueueRuntimeRundown(&Rundown, added, &RundownRequired);
        if (BeginRuntimeRundownAttempt(&Rundown, GetTickCount64()))
        {
            const ULONG enabled = EnableTraceEx2(Session, &kClrRundown, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE, 0x70, 0, 0, nullptr);
            const ULONG captured = enabled == ERROR_SUCCESS ?
                EnableTraceEx2(Session, &kClrRundown, EVENT_CONTROL_CODE_CAPTURE_STATE,
                    TRACE_LEVEL_VERBOSE, 0x70, 0, 0, nullptr) : enabled;
            const bool success = enabled == ERROR_SUCCESS && captured == ERROR_SUCCESS;
            FinishRuntimeRundownAttempt(&Rundown, success);
            if (!success)
            {
                std::lock_guard<std::mutex> lock(DataMutex);
                for (auto& process : Processes)
                {
                    if (process.second.Failures != UINT32_MAX)
                    {
                        ++process.second.Failures;
                    }
                }
            }
        }
    }

    void Consume(PEVENT_RECORD event)
    {
        const bool rundown = IsEqualGUID(event->EventHeader.ProviderId, kClrRundown) != FALSE;
        if (!rundown && !IsEqualGUID(event->EventHeader.ProviderId, kClrRuntime))
        {
            return;
        }
        const RuntimeEventAction action = RuntimeAction(rundown, event->EventHeader.EventDescriptor.Id,
            event->EventHeader.EventDescriptor.Version);
        if (action == RuntimeEventAction::Ignore)
        {
            return;
        }
        std::lock_guard<std::mutex> lock(DataMutex);
        auto found = Processes.find(event->EventHeader.ProcessId);
        if (found == Processes.end() || !Health.Known)
        {
            return;
        }
        const uint64_t timestamp = static_cast<uint64_t>(event->EventHeader.TimeStamp.QuadPart);
        if (!RuntimeEventWithinEpoch(timestamp, found->second.Created, MinimumEventTimestamp))
        {
            return;
        }
        KmonRuntimeCodeRange record;
        record.Timestamp = timestamp;
        uint32_t size = 0;
        const bool decoded = EventInteger(event, L"MethodStartAddress", &record.Start) &&
            EventInteger(event, L"MethodSize", &size) &&
            EventInteger(event, L"MethodID", &record.MethodId) &&
            EventInteger(event, L"ModuleID", &record.ModuleId) &&
            EventInteger(event, L"MethodFlags", &record.MethodFlags) &&
            EventInteger(event, L"ClrInstanceID", &record.RuntimeInstance);
        record.Size = size;
        if (!decoded)
        {
            ++found->second.Failures;
            // An undecodable unload can invalidate any retained method range.
            Lost.store(true);
        }
        else
        {
            ApplyRuntimeObservation(&found->second, record, action, 4096, &Lost);
        }
    }

    void StopLocked()
    {
        Active.store(false);
        if (Session != 0)
        {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(Properties.data());
            ControlTraceW(Session, SessionName.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
            Session = 0;
        }
        if (Consumer != INVALID_PROCESSTRACE_HANDLE)
        {
            CloseTrace(Consumer);
            Consumer = INVALID_PROCESSTRACE_HANDLE;
        }
        if (Worker.joinable())
        {
            Worker.join();
        }
        std::lock_guard<std::mutex> lock(DataMutex);
        Processes.clear();
        Rundown = {};
        Lost.store(false);
        RundownRequired.store(false);
        Health.Known = false;
        MinimumEventTimestamp = 0;
        HealthPollAttempted = false;
    }
};

KmonUserRuntimeTracker::KmonUserRuntimeTracker() : impl_(std::make_unique<Impl>())
{
}

KmonUserRuntimeTracker::~KmonUserRuntimeTracker()
{
    Stop();
}

bool KmonUserRuntimeTracker::Start(std::wstring* error)
{
    std::lock_guard<std::mutex> lock(impl_->LifecycleMutex);
    bool ok = impl_->Active.load();
    do
    {
        if (ok)
        {
            ok = impl_->PollHealthLocked(error);
            if (ok)
            {
                impl_->RequestRundownLocked(false);
            }
            break;
        }
        impl_->StopLocked();
        impl_->SessionName = L"KnLiveDbg-ClrEvidence-" + std::to_wstring(GetCurrentProcessId()) +
            L"-" + std::to_wstring(reinterpret_cast<uintptr_t>(impl_.get()));
        impl_->Properties.assign(sizeof(EVENT_TRACE_PROPERTIES) +
            (impl_->SessionName.size() + 1) * sizeof(wchar_t), 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(impl_->Properties.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(impl_->Properties.size());
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.ClientContext = 2;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->BufferSize = 64;
        properties->MinimumBuffers = 4;
        properties->MaximumBuffers = 32;
        properties->FlushTimer = 1;
        ULONG status = StartTraceW(&impl_->Session, impl_->SessionName.c_str(), properties);
        if (status != ERROR_SUCCESS)
        {
            impl_->Session = 0;
            if (error != nullptr)
            {
                *error = L"CLR ETW session unavailable: " + std::to_wstring(status);
            }
            break;
        }
        EVENT_TRACE_LOGFILEW logfile = {};
        logfile.LoggerName = const_cast<LPWSTR>(impl_->SessionName.c_str());
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = &Impl::EventCallback;
        logfile.Context = impl_.get();
        impl_->Consumer = OpenTraceW(&logfile);
        if (impl_->Consumer == INVALID_PROCESSTRACE_HANDLE)
        {
            break;
        }
        status = EnableTraceEx2(impl_->Session, &kClrRuntime, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE, 0x30, 0, 0, nullptr);
        if (status != ERROR_SUCCESS)
        {
            break;
        }
        // Rundown is positive provenance only; a missing range is never a
        // malicious verdict. Registration occurs before requesting a rundown.
        {
            std::lock_guard<std::mutex> dataLock(impl_->DataMutex);
            ++impl_->SessionEpoch;
            UpdateRuntimeSessionHealth(&impl_->Health, impl_->SessionEpoch, ERROR_SUCCESS, 0, 0);
            impl_->MinimumEventTimestamp = RuntimeFileTimeNow();
            impl_->LastHealthPollTick = GetTickCount64();
            impl_->HealthPollAttempted = true;
        }
        impl_->ConsumerStatus.store(ERROR_IO_PENDING);
        impl_->Active.store(true);
        Impl* state = impl_.get();
        const TRACEHANDLE consumer = impl_->Consumer;
        try
        {
            impl_->Worker = std::thread([state, consumer]()
            {
                TRACEHANDLE handle = consumer;
                state->ConsumerStatus.store(ProcessTrace(&handle, 1, nullptr, nullptr));
                state->Active.store(false);
            });
        }
        catch (...)
        {
            impl_->Active.store(false);
            break;
        }
        ok = true;
    } while (false);
    if (!ok)
    {
        impl_->StopLocked();
        if (error != nullptr && error->empty())
        {
            *error = L"CLR ETW consumer could not start";
        }
    }
    return ok;
}

void KmonUserRuntimeTracker::Stop()
{
    std::lock_guard<std::mutex> lock(impl_->LifecycleMutex);
    impl_->StopLocked();
}

bool KmonUserRuntimeTracker::WatchProcess(uint32_t processId, uint64_t createTime)
{
    bool accepted = false;
    bool added = false;
    std::lock_guard<std::mutex> lifecycle(impl_->LifecycleMutex);
    if (processId > 4 && createTime != 0 && impl_->Active.load())
    {
        {
            std::lock_guard<std::mutex> lock(impl_->DataMutex);
            const uint64_t tick = GetTickCount64();
            for (auto it = impl_->Processes.begin(); it != impl_->Processes.end();)
            {
                if (tick - it->second.LastWatchTick > 300000)
                {
                    it = impl_->Processes.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            auto found = impl_->Processes.find(processId);
            bool evicted = false;
            if (found == impl_->Processes.end() && impl_->Processes.size() >= 256)
            {
                auto oldest = std::min_element(impl_->Processes.begin(), impl_->Processes.end(), [](const auto& a, const auto& b)
                {
                    return a.second.LastWatchTick < b.second.LastWatchTick;
                });
                impl_->Processes.erase(oldest);
                evicted = true;
            }
            auto& process = impl_->Processes[processId];
            added = process.Created != createTime;
            if (added)
            {
                process = Impl::ProcessRanges{};
                process.Created = createTime;
                process.Overflow = evicted;
            }
            process.LastWatchTick = tick;
            accepted = true;
        }
        impl_->RequestRundownLocked(added);
    }
    return accepted;
}

void KmonUserRuntimeTracker::Snapshot(
    uint32_t processId,
    uint64_t createTime,
    std::vector<KmonRuntimeCodeRange>* ranges,
    KmonEvidenceCoverage* coverage)
{
    if (ranges != nullptr && coverage != nullptr)
    {
        ranges->clear();
        *coverage = KmonEvidenceCoverage{};
        std::lock_guard<std::mutex> lifecycleLock(impl_->LifecycleMutex);
        if (impl_->Active.load())
        {
            if (impl_->PollHealthLocked(nullptr))
            {
                impl_->RequestRundownLocked(false);
            }
        }
        std::lock_guard<std::mutex> lock(impl_->DataMutex);
        if (impl_->Lost.exchange(false))
        {
            InvalidateRuntimeRanges(&impl_->Processes, RuntimeFileTimeNow(),
                &impl_->MinimumEventTimestamp, &impl_->RundownRequired);
        }
        const auto found = impl_->Processes.find(processId);
        coverage->Available = impl_->Active.load() && impl_->Health.Known && found != impl_->Processes.end() &&
            found->second.Created == createTime;
        if (coverage->Available)
        {
            for (const auto& range : found->second.Ranges)
            {
                if (range.second.Size != 0)
                {
                    ranges->push_back(range.second);
                }
            }
            coverage->Truncated = found->second.Overflow;
            coverage->Failures = found->second.Failures;
        }
        coverage->Detail = L"CLR epoch=" + std::to_wstring(impl_->Health.Epoch) +
            L" query_status=" + std::to_wstring(impl_->Health.QueryStatus) +
            L" consumer_status=" + std::to_wstring(impl_->ConsumerStatus.load()) +
            L" events_lost=" + std::to_wstring(impl_->Health.EventsLost) +
            L" buffers_lost=" + std::to_wstring(impl_->Health.BuffersLost) +
            L"; observed method ranges only; missing, V8, and Wasm ranges remain unknown";
    }
}

namespace
{
    using EvidenceReader = std::function<bool(uint64_t, void*, uint32_t)>;

    struct PeEvidenceLayout
    {
        uint32_t ImageSize = 0;
        uint32_t TimeDateStamp = 0;
        uint32_t PointerSize = 0;
        IMAGE_DATA_DIRECTORY Tls = {};
        GUID PdbGuid = {};
        uint32_t PdbAge = 0;
        bool PdbIdentityKnown = false;
    };

    bool ImageRange(const ProcessUserModuleRange& module, uint64_t rva, uint64_t length)
    {
        return UserRange(module.Base, module.Size) && rva < module.Size && length <= module.Size - rva;
    }

    bool ReadPeLayout(const EvidenceReader& read, const ProcessUserModuleRange& module, PeEvidenceLayout* result)
    {
        bool ok = false;
        do
        {
            IMAGE_DOS_HEADER dos = {};
            if (!ImageRange(module, 0, sizeof(dos)) || !read(module.Base, &dos, sizeof(dos)) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos) || dos.e_lfanew > 0x100000)
            {
                break;
            }
            struct NtPrefix
            {
                DWORD Signature;
                IMAGE_FILE_HEADER File;
            } prefix = {};
            const uint64_t ntRva = static_cast<uint32_t>(dos.e_lfanew);
            if (!ImageRange(module, ntRva, sizeof(prefix)) ||
                !read(module.Base + ntRva, &prefix, sizeof(prefix)) || prefix.Signature != IMAGE_NT_SIGNATURE)
            {
                break;
            }
            const uint64_t optionalRva = ntRva + sizeof(prefix);
            WORD magic = 0;
            if (!ImageRange(module, optionalRva, prefix.File.SizeOfOptionalHeader) ||
                !read(module.Base + optionalRva, &magic, sizeof(magic)))
            {
                break;
            }
            IMAGE_DATA_DIRECTORY debug = {};
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && prefix.File.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64))
            {
                IMAGE_OPTIONAL_HEADER64 optional = {};
                if (!read(module.Base + optionalRva, &optional, sizeof(optional)) ||
                    optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
                {
                    break;
                }
                result->PointerSize = 8;
                result->ImageSize = optional.SizeOfImage;
                result->Tls = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                debug = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            }
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && prefix.File.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32))
            {
                IMAGE_OPTIONAL_HEADER32 optional = {};
                if (!read(module.Base + optionalRva, &optional, sizeof(optional)) ||
                    optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
                {
                    break;
                }
                result->PointerSize = 4;
                result->ImageSize = optional.SizeOfImage;
                result->Tls = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                debug = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            }
            else
            {
                break;
            }
            if (result->ImageSize == 0 || result->ImageSize != module.Size)
            {
                break;
            }
            result->TimeDateStamp = prefix.File.TimeDateStamp;
            if (debug.Size != 0 && debug.Size <= sizeof(IMAGE_DEBUG_DIRECTORY) * 64 &&
                debug.Size % sizeof(IMAGE_DEBUG_DIRECTORY) == 0 && ImageRange(module, debug.VirtualAddress, debug.Size))
            {
                for (uint32_t offset = 0; offset < debug.Size; offset += sizeof(IMAGE_DEBUG_DIRECTORY))
                {
                    IMAGE_DEBUG_DIRECTORY entry = {};
                    if (!read(module.Base + debug.VirtualAddress + offset, &entry, sizeof(entry)))
                    {
                        break;
                    }
                    if (entry.Type == IMAGE_DEBUG_TYPE_CODEVIEW && entry.SizeOfData >= 24 &&
                        ImageRange(module, entry.AddressOfRawData, 24))
                    {
                        std::array<uint8_t, 24> codeview = {};
                        if (read(module.Base + entry.AddressOfRawData, codeview.data(), static_cast<uint32_t>(codeview.size())) &&
                            std::memcmp(codeview.data(), "RSDS", 4) == 0)
                        {
                            std::memcpy(&result->PdbGuid, codeview.data() + 4, sizeof(GUID));
                            std::memcpy(&result->PdbAge, codeview.data() + 20, sizeof(uint32_t));
                            result->PdbIdentityKnown = result->PdbAge != 0;
                            break;
                        }
                    }
                }
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool ReadPointer(const EvidenceReader& read, uint64_t address, uint32_t width, uint64_t* value)
    {
        *value = 0;
        return (width == 4 || width == 8) && UserRange(address, width) && read(address, value, width);
    }

    void PrepareCallbackContinuation(KmonUserCallbackContinuation* continuation, uint32_t processId, uint64_t createTime)
    {
        if (continuation->ProcessId != processId || continuation->CreateTime != createTime)
        {
            *continuation = {};
            continuation->ProcessId = processId;
            continuation->CreateTime = createTime;
        }
        continuation->Evicted = false;
    }

    std::vector<KmonUserAddressEvidence> SelectCallbackEvidence(
        const std::vector<KmonUserAddressEvidence>& pending, uint32_t budget,
        KmonUserEvidenceKind kind, uint64_t module, uint64_t table,
        KmonUserCallbackContinuation* continuation, KmonEvidenceCoverage* coverage)
    {
        uint64_t after = 0;
        if (continuation != nullptr)
        {
            for (const auto& saved : continuation->Cursors)
            {
                if (saved.Kind == kind && saved.ModuleBase == module && saved.TableAddress == table)
                {
                    after = saved.AfterRecord;
                    break;
                }
            }
        }
        auto selected = SelectAfter(pending, after, budget, [](const KmonUserAddressEvidence& record)
        {
            return record.RecordAddress;
        });
        coverage->Truncated = coverage->Truncated || selected.size() < pending.size();
        if (continuation != nullptr)
        {
            auto& cursors = continuation->Cursors;
            cursors.erase(std::remove_if(cursors.begin(), cursors.end(), [&](const KmonUserCallbackCursor& saved)
            {
                return saved.Kind == kind && saved.ModuleBase == module && saved.TableAddress == table;
            }), cursors.end());
            if (!selected.empty() && selected.size() < pending.size())
            {
                if (cursors.size() >= 512)
                {
                    cursors.erase(cursors.begin());
                    continuation->Evicted = true;
                    coverage->Truncated = true;
                }
                cursors.push_back({ kind, module, table, selected.back().RecordAddress });
            }
        }
        return selected;
    }

    void CollectTlsCallbacks(const EvidenceReader& read, const ProcessUserModuleRange& module,
        uint32_t budget, std::vector<KmonUserAddressEvidence>* records, KmonEvidenceCoverage* coverage,
        KmonUserCallbackContinuation* continuation = nullptr)
    {
        PeEvidenceLayout pe;
        if (!ReadPeLayout(read, module, &pe))
        {
            ++coverage->Failures;
            return;
        }
        if (pe.Tls.VirtualAddress == 0 && pe.Tls.Size == 0)
        {
            return;
        }
        const uint32_t directorySize = pe.PointerSize == 8 ? sizeof(IMAGE_TLS_DIRECTORY64) : sizeof(IMAGE_TLS_DIRECTORY32);
        if (pe.Tls.Size < directorySize || !ImageRange(module, pe.Tls.VirtualAddress, directorySize))
        {
            ++coverage->Failures;
            return;
        }
        const uint64_t callbackField = module.Base + pe.Tls.VirtualAddress + pe.PointerSize * 3;
        uint64_t table = 0;
        if (!ReadPointer(read, callbackField, pe.PointerSize, &table))
        {
            ++coverage->Failures;
            return;
        }
        if (table == 0)
        {
            return;
        }
        std::vector<KmonUserAddressEvidence> pending;
        bool terminated = false;
        for (uint32_t i = 0; i <= kMaxEnumeratedCallbacks; ++i)
        {
            uint64_t callback = 0, verify = 0;
            const uint64_t offset = static_cast<uint64_t>(i) * pe.PointerSize;
            if (!UserRange(table, offset + pe.PointerSize) ||
                !ReadPointer(read, table + offset, pe.PointerSize, &callback))
            {
                ++coverage->Failures;
                break;
            }
            if (callback == 0)
            {
                terminated = true;
                break;
            }
            if (i == kMaxEnumeratedCallbacks)
            {
                coverage->Truncated = true;
                break;
            }
            if (!UserRange(callback, 1) || !ReadPointer(read, table + offset, pe.PointerSize, &verify) || verify != callback)
            {
                ++coverage->Failures;
                break;
            }
            KmonUserAddressEvidence evidence;
            evidence.Kind = KmonUserEvidenceKind::TlsCallback;
            evidence.Address = callback;
            evidence.RecordAddress = table + offset;
            evidence.ModuleBase = module.Base;
            evidence.Provenance = pe.PointerSize == 8 ? L"PE32+ TLS directory and revalidated callback slot" :
                L"PE32 TLS directory and revalidated callback slot";
            pending.push_back(std::move(evidence));
        }
        uint64_t tableAfter = 0;
        if (!ReadPointer(read, callbackField, pe.PointerSize, &tableAfter) || tableAfter != table)
        {
            ++coverage->Failures;
        }
        else
        {
            const auto selected = SelectCallbackEvidence(pending, budget, KmonUserEvidenceKind::TlsCallback,
                module.Base, table, continuation, coverage);
            records->insert(records->end(), selected.begin(), selected.end());
        }
        if (!terminated)
        {
            coverage->Complete = false;
        }
    }

    bool HandlerLayoutMatches(const KmonVectoredHandlerLayout& layout, const PeEvidenceLayout& pe)
    {
        return pe.PdbIdentityKnown && layout.PdbAge != 0 &&
            IsEqualGUID(layout.PdbGuid, pe.PdbGuid) && layout.PdbAge == pe.PdbAge &&
            layout.ImageSize == pe.ImageSize && layout.TimeDateStamp == pe.TimeDateStamp &&
            layout.PointerSize == pe.PointerSize && !layout.SymbolProvenance.empty() &&
            layout.EntrySize >= pe.PointerSize * 3 && layout.EntrySize <= 0x1000 &&
            layout.EntryLinkOffset <= layout.EntrySize - pe.PointerSize * 2 &&
            layout.HandlerOffset <= layout.EntrySize - pe.PointerSize &&
            layout.ListHeadRva < pe.ImageSize && pe.PointerSize * 2 <= pe.ImageSize - layout.ListHeadRva;
    }

    using RemoteDecoder = std::function<bool(uint64_t, uint64_t*)>;

    bool WalkHandlers(const EvidenceReader& read, const RemoteDecoder& decode,
        const KmonVectoredHandlerLayout& layout, uint32_t budget,
        std::vector<KmonUserAddressEvidence>* records, KmonEvidenceCoverage* coverage,
        KmonUserCallbackContinuation* continuation = nullptr)
    {
        bool complete = false;
        do
        {
            const uint64_t head = layout.ModuleBase + layout.ListHeadRva;
            uint64_t first = 0, tail = 0;
            if (!ReadPointer(read, head, layout.PointerSize, &first) ||
                !ReadPointer(read, head + layout.PointerSize, layout.PointerSize, &tail))
            {
                break;
            }
            uint64_t current = first, previous = head;
            std::set<uint64_t> visited;
            std::vector<KmonUserAddressEvidence> pending;
            bool failed = false;
            while (current != head)
            {
                if (pending.size() >= kMaxEnumeratedCallbacks)
                {
                    coverage->Truncated = true;
                    break;
                }
                uint64_t next = 0, back = 0, encoded = 0;
                if (!UserRange(current, layout.PointerSize * 2) || current < layout.EntryLinkOffset ||
                    !visited.insert(current).second ||
                    !ReadPointer(read, current, layout.PointerSize, &next) ||
                    !ReadPointer(read, current + layout.PointerSize, layout.PointerSize, &back) || back != previous ||
                    !ReadPointer(read, current - layout.EntryLinkOffset + layout.HandlerOffset, layout.PointerSize, &encoded))
                {
                    failed = true;
                    break;
                }
                uint64_t verifyNext = 0, verifyBack = 0, verifyHandler = 0;
                if (!ReadPointer(read, current, layout.PointerSize, &verifyNext) ||
                    !ReadPointer(read, current + layout.PointerSize, layout.PointerSize, &verifyBack) ||
                    !ReadPointer(read, current - layout.EntryLinkOffset + layout.HandlerOffset, layout.PointerSize, &verifyHandler) ||
                    verifyNext != next || verifyBack != back || verifyHandler != encoded)
                {
                    failed = true;
                    break;
                }
                KmonUserAddressEvidence evidence;
                evidence.Kind = layout.ContinueHandler ? KmonUserEvidenceKind::VectoredContinueHandler :
                    KmonUserEvidenceKind::VectoredExceptionHandler;
                evidence.Address = encoded;
                evidence.RecordAddress = current - layout.EntryLinkOffset;
                evidence.ModuleBase = layout.ModuleBase;
                evidence.Provenance = layout.SymbolProvenance;
                pending.push_back(std::move(evidence));
                previous = current;
                current = next;
            }
            uint64_t finalFirst = 0, finalTail = 0;
            if (failed || !ReadPointer(read, head, layout.PointerSize, &finalFirst) ||
                !ReadPointer(read, head + layout.PointerSize, layout.PointerSize, &finalTail) ||
                first != finalFirst || tail != finalTail || (current == head && previous != tail))
            {
                break;
            }
            const auto selected = SelectCallbackEvidence(pending, budget,
                layout.ContinueHandler ? KmonUserEvidenceKind::VectoredContinueHandler : KmonUserEvidenceKind::VectoredExceptionHandler,
                layout.ModuleBase, head, continuation, coverage);
            bool decodedComplete = true;
            for (KmonUserAddressEvidence evidence : selected)
            {
                uint64_t handler = evidence.Address;
                uint64_t encodedAfter = 0;
                if ((layout.Encoded && !decode(evidence.Address, &handler)) || !UserRange(handler, 1) ||
                    !ReadPointer(read, evidence.RecordAddress + layout.HandlerOffset, layout.PointerSize, &encodedAfter) ||
                    encodedAfter != evidence.Address)
                {
                    decodedComplete = false;
                    continue;
                }
                evidence.Address = handler;
                records->push_back(std::move(evidence));
            }
            complete = current == head && selected.size() == pending.size() && decodedComplete;
            if (!decodedComplete)
            {
                ++coverage->Failures;
            }
        } while (false);
        if (!complete && !coverage->Truncated)
        {
            ++coverage->Failures;
        }
        return complete;
    }

    template<typename T>
    struct OwnedCom
    {
        T* Value = nullptr;
        ~OwnedCom()
        {
            if (Value != nullptr)
            {
                Value->Release();
            }
        }
    };

    struct OwnedComApartment
    {
        HRESULT Status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        ~OwnedComApartment()
        {
            if (SUCCEEDED(Status))
            {
                CoUninitialize();
            }
        }
    };

    bool DiaOne(IDiaSession* session, IDiaSymbol* parent, DWORD tag, const wchar_t* name, IDiaSymbol** symbol)
    {
        OwnedCom<IDiaEnumSymbols> found;
        LONG count = 0;
        ULONG fetched = 0;
        return SUCCEEDED(session->findChildren(parent, static_cast<enum SymTagEnum>(tag), name, nsCaseSensitive, &found.Value)) &&
            SUCCEEDED(found.Value->get_Count(&count)) && count == 1 &&
            found.Value->Next(1, symbol, &fetched) == S_OK && fetched == 1;
    }

    bool DiaMember(IDiaSession* session, IDiaSymbol* type, const wchar_t* name, uint32_t* offset, uint64_t* length)
    {
        OwnedCom<IDiaSymbol> member;
        OwnedCom<IDiaSymbol> memberType;
        LONG signedOffset = 0;
        ULONGLONG size = 0;
        const bool ok = DiaOne(session, type, SymTagData, name, &member.Value) &&
            SUCCEEDED(member.Value->get_offset(&signedOffset)) && signedOffset >= 0 &&
            SUCCEEDED(member.Value->get_type(&memberType.Value)) &&
            SUCCEEDED(memberType.Value->get_length(&size));
        if (ok)
        {
            *offset = static_cast<uint32_t>(signedOffset);
            *length = size;
        }
        return ok;
    }

    bool CreateEvidenceDia(IDiaDataSource** source)
    {
        bool ok = SUCCEEDED(CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IDiaDataSource), reinterpret_cast<void**>(source)));
        if (!ok)
        {
            // SymbolEngine already loads its DIA dependency from a trusted
            // application/VS path. Reuse only that loaded module.
            HMODULE module = GetModuleHandleW(L"msdia140.dll");
            if (module != nullptr)
            {
                using FactoryFunction = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, LPVOID*);
                auto factoryFunction = reinterpret_cast<FactoryFunction>(GetProcAddress(module, "DllGetClassObject"));
                OwnedCom<IClassFactory> factory;
                if (factoryFunction != nullptr && SUCCEEDED(factoryFunction(CLSID_DiaSource, IID_IClassFactory,
                        reinterpret_cast<void**>(&factory.Value))))
                {
                    ok = SUCCEEDED(factory.Value->CreateInstance(nullptr, __uuidof(IDiaDataSource),
                        reinterpret_cast<void**>(source)));
                }
            }
        }
        return ok;
    }

    bool ResolveHandlerLayouts(const EvidenceReader& read, const ProcessUserModuleRange& module,
        const std::wstring& symbolPath, std::vector<KmonVectoredHandlerLayout>* layouts)
    {
        bool ok = false;
        const OwnedComApartment apartment;
        do
        {
            PeEvidenceLayout pe;
            if (!ReadPeLayout(read, module, &pe) || !pe.PdbIdentityKnown || pe.PointerSize != 8 || module.ImagePath.empty())
            {
                break;
            }
            OwnedCom<IDiaDataSource> source;
            OwnedCom<IDiaSession> session;
            OwnedCom<IDiaSymbol> global;
            GUID guid = {};
            DWORD age = 0;
            const std::wstring path = OpenablePath(module.ImagePath);
            if (!CreateEvidenceDia(&source.Value) || FAILED(source.Value->loadDataForExe(path.c_str(), symbolPath.c_str(), nullptr)) ||
                FAILED(source.Value->openSession(&session.Value)) || FAILED(session.Value->get_globalScope(&global.Value)) ||
                FAILED(global.Value->get_guid(&guid)) || FAILED(global.Value->get_age(&age)) ||
                !IsEqualGUID(guid, pe.PdbGuid) || age != pe.PdbAge)
            {
                break;
            }
            OwnedCom<IDiaSymbol> lists;
            OwnedCom<IDiaSymbol> listType;
            OwnedCom<IDiaSymbol> entryType;
            DWORD listRva = 0;
            ULONGLONG entrySize = 0;
            uint32_t linkOffset = 0, handlerOffset = 0;
            uint64_t linkSize = 0, handlerSize = 0;
            if (!DiaOne(session.Value, global.Value, SymTagData, L"LdrpVectorHandlerList", &lists.Value) ||
                FAILED(lists.Value->get_relativeVirtualAddress(&listRva)) || FAILED(lists.Value->get_type(&listType.Value)) ||
                !DiaOne(session.Value, global.Value, SymTagUDT, L"_RTL_VECTORED_HANDLER_ENTRY", &entryType.Value) ||
                FAILED(entryType.Value->get_length(&entrySize)) || entrySize > 0x1000 ||
                !DiaMember(session.Value, entryType.Value, L"ListEntry", &linkOffset, &linkSize) || linkSize != 16 ||
                !DiaMember(session.Value, entryType.Value, L"EncodedHandler", &handlerOffset, &handlerSize) || handlerSize != 8)
            {
                break;
            }
            const wchar_t* names[] = {L"ExceptionList", L"ContinueList"};
            std::vector<KmonVectoredHandlerLayout> resolved;
            for (size_t i = 0; i < ARRAYSIZE(names); ++i)
            {
                uint32_t offset = 0;
                uint64_t size = 0;
                if (!DiaMember(session.Value, listType.Value, names[i], &offset, &size) || size != 16 ||
                    offset > UINT32_MAX - listRva)
                {
                    break;
                }
                KmonVectoredHandlerLayout layout;
                layout.ModuleBase = module.Base;
                layout.ImageSize = pe.ImageSize;
                layout.TimeDateStamp = pe.TimeDateStamp;
                layout.PdbGuid = guid;
                layout.PdbAge = age;
                layout.ListHeadRva = listRva + offset;
                layout.EntryLinkOffset = linkOffset;
                layout.HandlerOffset = handlerOffset;
                layout.EntrySize = static_cast<uint32_t>(entrySize);
                layout.PointerSize = pe.PointerSize;
                layout.Encoded = true;
                layout.ContinueHandler = i == 1;
                layout.SymbolProvenance = L"exact DIA GUID/age; LdrpVectorHandlerList; typed EncodedHandler; DecodeRemotePointer";
                if (!HandlerLayoutMatches(layout, pe))
                {
                    break;
                }
                resolved.push_back(std::move(layout));
            }
            if (resolved.size() == 2)
            {
                layouts->insert(layouts->end(), resolved.begin(), resolved.end());
                ok = true;
            }
        } while (false);
        return ok;
    }

    bool ResolveCachedHandlerLayouts(const EvidenceReader& read, const ProcessUserModuleRange& module,
        const std::wstring& symbolPath, std::vector<KmonVectoredHandlerLayout>* layouts)
    {
        struct CacheEntry
        {
            uint64_t Tick = 0;
            std::vector<KmonVectoredHandlerLayout> Layouts;
        };
        static std::mutex cacheMutex;
        static std::map<std::wstring, CacheEntry> cache;
        PeEvidenceLayout pe;
        bool ok = false;
        if (ReadPeLayout(read, module, &pe) && pe.PdbIdentityKnown)
        {
            wchar_t guid[64] = {};
            StringFromGUID2(pe.PdbGuid, guid, ARRAYSIZE(guid));
            const std::wstring key = std::wstring(guid) + L":" + std::to_wstring(pe.PdbAge) +
                L":" + std::to_wstring(pe.TimeDateStamp) + L":" + std::to_wstring(pe.ImageSize);
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto found = cache.find(key);
            if (found == cache.end() || (found->second.Layouts.empty() && GetTickCount64() - found->second.Tick > 60000))
            {
                if (found == cache.end() && cache.size() >= 64)
                {
                    auto oldest = std::min_element(cache.begin(), cache.end(), [](const auto& a, const auto& b)
                    {
                        return a.second.Tick < b.second.Tick;
                    });
                    cache.erase(oldest);
                }
                CacheEntry entry;
                entry.Tick = GetTickCount64();
                ResolveHandlerLayouts(read, module, symbolPath, &entry.Layouts);
                cache[key] = std::move(entry);
                found = cache.find(key);
            }
            for (KmonVectoredHandlerLayout layout : found->second.Layouts)
            {
                layout.ModuleBase = module.Base;
                layouts->push_back(std::move(layout));
            }
            ok = !found->second.Layouts.empty();
        }
        return ok;
    }

    bool ValidateEvidenceTarget(DeviceClient& device, SymbolEngine& symbols, const ProcessTriageTarget& target)
    {
        bool ok = false;
        do
        {
            if (target.ProcessId <= 4 || !target.HasCreateTime || target.CreateTime == 0 ||
                target.Eprocess < 0xffff800000000000ULL)
            {
                break;
            }
            TypeFieldInfo pid = {}, created = {};
            if (!symbols.FindField(L"nt!_EPROCESS", L"UniqueProcessId", &pid, nullptr) ||
                !symbols.FindField(L"nt!_EPROCESS", L"CreateTime", &created, nullptr) ||
                pid.Offset > 0x10000 || created.Offset > 0x10000 ||
                target.Eprocess > UINT64_MAX - 0x10008)
            {
                break;
            }
            std::vector<uint8_t> pidBytes, createdBytes;
            uint64_t processId = 0, createTime = 0;
            if (!device.ReadMemory(target.Eprocess + pid.Offset, sizeof(processId), &pidBytes, nullptr) || pidBytes.size() != sizeof(processId) ||
                !device.ReadMemory(target.Eprocess + created.Offset, sizeof(createTime), &createdBytes, nullptr) || createdBytes.size() != sizeof(createTime))
            {
                break;
            }
            std::memcpy(&processId, pidBytes.data(), sizeof(processId));
            std::memcpy(&createTime, createdBytes.data(), sizeof(createTime));
            ok = processId == target.ProcessId && createTime == target.CreateTime;
        } while (false);
        return ok;
    }

    bool ExecutableProtection(uint32_t protection)
    {
        const uint32_t value = protection & 0xff;
        return value == PAGE_EXECUTE || value == PAGE_EXECUTE_READ ||
            value == PAGE_EXECUTE_READWRITE || value == PAGE_EXECUTE_WRITECOPY;
    }

    void AppendApcAddressEvidence(const ProcessApcEntryRecord& apc, uint32_t threadId,
        std::vector<KmonUserAddressEvidence>* addresses)
    {
        if (apc.HasNormalRoutine && UserRange(apc.NormalRoutine, 1))
        {
            KmonUserAddressEvidence evidence;
            evidence.Kind = KmonUserEvidenceKind::UserApcRoutine;
            evidence.Address = apc.NormalRoutine;
            evidence.RecordAddress = apc.KapcAddress;
            evidence.ThreadId = threadId;
            evidence.Provenance = L"PDB KAPC.NormalRoutine in user queue; revalidated thread generation";
            addresses->push_back(std::move(evidence));
        }
        if (ProcessApcUserRoutineIsArgumentCandidate(apc) && UserRange(apc.UserRoutine, 1))
        {
            KmonUserAddressEvidence evidence;
            evidence.Kind = KmonUserEvidenceKind::UserApcArgumentCandidate;
            evidence.Address = apc.UserRoutine;
            evidence.RecordAddress = apc.KapcAddress;
            evidence.ThreadId = threadId;
            evidence.Provenance = L"APC argument candidate in " + apc.UserRoutineSource +
                L"; not a validated dispatch routine or execution proof";
            addresses->push_back(std::move(evidence));
        }
    }

    bool EvidenceImageOwnerMatches(
        const ProcessUserModuleRange& module, uint64_t address,
        const MEMORY_BASIC_INFORMATION& memory)
    {
        return memory.State == MEM_COMMIT && memory.Type == MEM_IMAGE &&
            reinterpret_cast<uint64_t>(memory.AllocationBase) == module.Base &&
            UserRange(module.Base, module.Size) && address >= module.Base && address - module.Base < module.Size;
    }

    template<typename Query>
    void ClassifyEvidenceMapping(Query query, const KmonUserEvidenceOptions& options,
        bool moduleInventoryValid, KmonUserAddressEvidence* evidence)
    {
        evidence->OwnershipKnown = false;
        evidence->InLoaderModule = false;
        evidence->PrivateExecutable = false;
        evidence->GuardPage = false;
        evidence->Protection = 0;
        evidence->MemoryType = 0;
        evidence->AllocationBase = 0;
        MEMORY_BASIC_INFORMATION memory = {};
        if (query(evidence->Address, &memory))
        {
            evidence->OwnershipKnown = moduleInventoryValid;
            evidence->Protection = memory.Protect;
            evidence->MemoryType = memory.Type;
            evidence->AllocationBase = reinterpret_cast<uint64_t>(memory.AllocationBase);
            evidence->GuardPage = (memory.Protect & PAGE_GUARD) != 0;
            evidence->PrivateExecutable = memory.State == MEM_COMMIT && memory.Type == MEM_PRIVATE && ExecutableProtection(memory.Protect);
            for (const auto& module : options.UserModules)
            {
                if (EvidenceImageOwnerMatches(module, evidence->Address, memory))
                {
                    evidence->InLoaderModule = true;
                    break;
                }
            }
        }
        else
        {
            for (const auto& vad : options.VadRecords)
            {
                if (evidence->Address >= vad.StartAddress && evidence->Address <= vad.EndAddress)
                {
                    for (const auto& range : vad.EffectiveProtectionRanges)
                    {
                        if (evidence->Address >= range.StartAddress && evidence->Address <= range.EndAddress)
                        {
                            evidence->Protection = range.Protection;
                            evidence->MemoryType = range.Type;
                            evidence->GuardPage = (range.Protection & PAGE_GUARD) != 0;
                            evidence->PrivateExecutable = range.Committed && range.Executable &&
                                range.Type == MEM_PRIVATE && vad.HasPrivateMemory && vad.PrivateMemory;
                            // A VAD sample has no image allocation identity. Only
                            // a positively observed private mapping proves non-ownership.
                            evidence->OwnershipKnown = range.Committed && range.Type == MEM_PRIVATE &&
                                vad.HasPrivateMemory && vad.PrivateMemory;
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    void ClassifyEvidenceAddress(HANDLE process, const KmonUserEvidenceOptions& options,
        bool moduleInventoryValid, const std::vector<KmonRuntimeCodeRange>& runtime,
        KmonUserAddressEvidence* evidence)
    {
        ClassifyEvidenceMapping([&](uint64_t address, MEMORY_BASIC_INFORMATION* memory)
        {
            return process != nullptr &&
                VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), memory, sizeof(*memory)) == sizeof(*memory);
        }, options, moduleInventoryValid, evidence);
        for (const auto& range : runtime)
        {
            if (range.Size != 0 && evidence->Address >= range.Start && evidence->Address - range.Start < range.Size)
            {
                evidence->RuntimeRangeObserved = true;
                break;
            }
        }
    }
}

bool CollectKmonUserEvidence(DeviceClient& device, SymbolEngine& symbols,
    const KmonUserEvidenceOptions& options, KmonUserEvidenceResult* result, std::wstring* error)
{
    bool ok = false;
    do
    {
        if (result == nullptr)
        {
            break;
        }
        *result = KmonUserEvidenceResult{};
        result->ProcessId = options.Target.ProcessId;
        result->ProcessCreateTime = options.Target.CreateTime;
        if (!ValidateEvidenceTarget(device, symbols, options.Target))
        {
            break;
        }
        if (options.CallbackContinuation != nullptr)
        {
            PrepareCallbackContinuation(options.CallbackContinuation, options.Target.ProcessId, options.Target.CreateTime);
        }
        OwnedHandle process;
        process.Value = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, options.Target.ProcessId);
        if (process.Value != nullptr && !ProcessGeneration(process.Value, options.Target.CreateTime, nullptr))
        {
            break;
        }
        const EvidenceReader read = [&](uint64_t address, void* buffer, uint32_t length)
        {
            bool readOk = false;
            do
            {
                if (!UserRange(address, length))
                {
                    break;
                }
                if (process.Value != nullptr)
                {
                    uint64_t cursor = address;
                    bool readable = true;
                    while (cursor - address < length)
                    {
                        MEMORY_BASIC_INFORMATION memory = {};
                        if (VirtualQueryEx(process.Value, reinterpret_cast<LPCVOID>(cursor), &memory, sizeof(memory)) != sizeof(memory) ||
                            memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
                        {
                            readable = false;
                            break;
                        }
                        const uint64_t base = reinterpret_cast<uint64_t>(memory.BaseAddress);
                        if (!UserRange(base, memory.RegionSize) || cursor < base || cursor - base >= memory.RegionSize)
                        {
                            readable = false;
                            break;
                        }
                        cursor += (std::min)(static_cast<uint64_t>(length) - (cursor - address), memory.RegionSize - (cursor - base));
                    }
                    if (!readable)
                    {
                        break;
                    }
                }
                else
                {
                    bool readable = false;
                    for (const auto& vad : options.VadRecords)
                    {
                        for (const auto& range : vad.EffectiveProtectionRanges)
                        {
                            if (range.Committed && (range.Protection & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
                                address >= range.StartAddress && address <= range.EndAddress &&
                                length - 1 <= range.EndAddress - address)
                            {
                                readable = true;
                                break;
                            }
                        }
                        if (readable)
                        {
                            break;
                        }
                    }
                    if (!readable)
                    {
                        break;
                    }
                }
                std::vector<uint8_t> bytes;
                if (device.ReadProcessVirtual(options.Target.ProcessId, options.Target.Eprocess, options.Target.CreateTime,
                        address, length, &bytes, nullptr) && bytes.size() == length)
                {
                    std::memcpy(buffer, bytes.data(), length);
                    readOk = true;
                }
            } while (false);
            return readOk;
        };
        if (options.RuntimeTracker != nullptr)
        {
            options.RuntimeTracker->WatchProcess(options.Target.ProcessId, options.Target.CreateTime);
            options.RuntimeTracker->Snapshot(options.Target.ProcessId, options.Target.CreateTime,
                &result->RuntimeRanges, &result->RuntimeCoverage);
        }
        else
        {
            result->RuntimeCoverage.Detail = L"CLR runtime tracker is not active; V8 and Wasm ownership unknown";
        }
        if (options.CaptureContexts)
        {
            CaptureKmonThreadSnapshot(options.Target.ProcessId, options.Target.CreateTime,
                options.MaxThreads, options.ThreadCursor, &result->Snapshot, nullptr);
            result->NextThreadCursor = result->Snapshot.NextThreadCursor;
            for (const auto& context : result->Snapshot.Threads)
            {
                if (context.ControlValid && UserRange(context.InstructionPointer, 1))
                {
                    KmonUserAddressEvidence evidence;
                    evidence.Kind = KmonUserEvidenceKind::SnapshotInstructionPointer;
                    evidence.Address = context.InstructionPointer;
                    evidence.ThreadId = context.ThreadId;
                    evidence.Provenance = context.Wow64 ? L"PSS WOW64 control context" : L"PSS AMD64 control context";
                    result->Addresses.push_back(std::move(evidence));
                }
                if (context.DebugValid)
                {
                    for (uint32_t index = 0; index < 4; ++index)
                    {
                        if ((context.DebugControl & (3ULL << (index * 2))) == 0 || !UserRange(context.DebugAddress[index], 1))
                        {
                            continue;
                        }
                        KmonUserAddressEvidence evidence;
                        evidence.Kind = KmonUserEvidenceKind::HardwareBreakpoint;
                        evidence.Address = context.DebugAddress[index];
                        evidence.ThreadId = context.ThreadId;
                        evidence.DebugRegister = index;
                        evidence.DebugCondition = static_cast<uint32_t>((context.DebugControl >> (16 + index * 4)) & 3);
                        evidence.Provenance = context.Wow64 ? L"PSS WOW64 debug context" : L"PSS AMD64 debug context";
                        result->Addresses.push_back(std::move(evidence));
                    }
                }
            }
        }
        else
        {
            result->Snapshot.Coverage.Detail = L"PSS capture was not requested for this target";
        }
        if (options.CollectKernelExecution)
        {
            ProcessExecutionScanOptions scanOptions;
            scanOptions.Target = options.Target;
            scanOptions.UserModules = options.UserModules;
            scanOptions.UserModuleEnumerationComplete = options.UserModulesComplete;
            scanOptions.VadRecords = options.VadRecords;
            scanOptions.ThreadBudget = options.MaxThreads;
            scanOptions.AfterThreadId = options.KernelThreadCursor;
            ProcessExecutionScanResult execution;
            ProcessTriageScanner scanner(device, symbols);
            const bool collected = scanner.ScanExecutionEvidence(scanOptions, &execution, nullptr);
            if (collected)
            {
                result->NextKernelThreadCursor = execution.NextThreadCursor;
                for (const auto& thread : execution.Records)
                {
                    if (thread.SavedContextStable && UserRange(thread.SavedInstructionPointer, 1))
                    {
                        KmonUserAddressEvidence evidence;
                        evidence.Kind = KmonUserEvidenceKind::SavedTrapInstructionPointer;
                        evidence.Address = thread.SavedInstructionPointer;
                        evidence.RecordAddress = thread.TrapFrame;
                        evidence.ThreadId = static_cast<uint32_t>(thread.ThreadId);
                        evidence.Provenance = L"PDB trap frame; identity and pointer revalidated; saved RIP, not a live context";
                        result->Addresses.push_back(std::move(evidence));
                    }
                    for (const auto& queue : thread.ApcQueues)
                    {
                        for (const auto& apc : queue.Entries)
                        {
                            AppendApcAddressEvidence(apc, static_cast<uint32_t>(thread.ThreadId), &result->Addresses);
                        }
                    }
                }
            }
            result->ApcCoverage.Available = collected && execution.ApcLayoutAvailable;
            result->ApcCoverage.Truncated = execution.Truncated;
            result->ApcCoverage.Failures = execution.ApcFailures + (collected ? 0U : 1U);
            result->ApcCoverage.Complete = result->ApcCoverage.Available && execution.InventoryComplete &&
                !execution.Truncated && execution.ApcFailures == 0;
            result->ApcCoverage.Detail = L"bounded live user APC queues; delivered or transient APCs may be absent";
            result->SavedContextCoverage.Available = collected && execution.SavedContextLayoutAvailable;
            result->SavedContextCoverage.Truncated = execution.Truncated;
            result->SavedContextCoverage.Failures = execution.SavedContextFailures + (collected ? 0U : 1U);
            result->SavedContextCoverage.Complete = result->SavedContextCoverage.Available && execution.InventoryComplete &&
                !execution.Truncated && execution.SavedContextFailures == 0;
            result->SavedContextCoverage.Detail = L"saved trap RIP only; no stack unwind or continuous instruction trace";
        }
        bool modulesValid = options.UserModulesComplete;
        std::vector<ProcessUserModuleRange> modules;
        for (const auto& module : options.UserModules)
        {
            if (UserRange(module.Base, module.Size))
            {
                modules.push_back(module);
            }
            else
            {
                modulesValid = false;
            }
        }
        const auto selectedModules = SelectAfter(modules, options.ModuleCursor,
            (std::min)(options.MaxModules, kMaxSelectedModules), [](const ProcessUserModuleRange& module)
            {
                return module.Base;
            });
        const uint32_t callbackBudget = (std::min)(options.MaxCallbacks, kMaxCallbacks);
        result->TlsCoverage.Available = !modules.empty() || modulesValid;
        result->TlsCoverage.Complete = modulesValid;
        result->TlsCoverage.Truncated = selectedModules.size() < modules.size();
        for (const auto& module : selectedModules)
        {
            result->NextModuleCursor = module.Base;
            CollectTlsCallbacks(read, module, callbackBudget, &result->Addresses, &result->TlsCoverage,
                options.CallbackContinuation);
        }
        result->TlsCoverage.Complete = result->TlsCoverage.Complete &&
            !result->TlsCoverage.Truncated && result->TlsCoverage.Failures == 0;
        result->TlsCoverage.Detail = L"PE TLS callback tables; callbacks need not be currently executing";
        std::vector<KmonVectoredHandlerLayout> layouts = options.HandlerLayouts;
        if (layouts.empty() && options.ResolveHandlerSymbols)
        {
            for (const auto& module : modules)
            {
                const size_t slash = module.ImagePath.find_last_of(L"\\/");
                const std::wstring leaf = module.ImageName.empty() ? module.ImagePath.substr(slash == std::wstring::npos ? 0 : slash + 1) :
                    module.ImageName;
                if (_wcsicmp(leaf.c_str(), L"ntdll.dll") == 0)
                {
                    ResolveCachedHandlerLayouts(read, module, symbols.SymbolPath(), &layouts);
                    break;
                }
            }
        }
        using DecodeRemotePointerFn = HRESULT (WINAPI*)(HANDLE, PVOID, PVOID*);
        DecodeRemotePointerFn decodeRemotePointer = nullptr;
        for (const wchar_t* library : {L"kernel32.dll", L"kernelbase.dll"})
        {
            HMODULE module = GetModuleHandleW(library);
            if (module != nullptr)
            {
                decodeRemotePointer = reinterpret_cast<DecodeRemotePointerFn>(GetProcAddress(module, "DecodeRemotePointer"));
                if (decodeRemotePointer != nullptr)
                {
                    break;
                }
            }
        }
        bool haveVeh = false, haveVch = false;
        for (const auto& layout : layouts)
        {
            if (layouts.size() > 4)
            {
                result->HandlerCoverage.Truncated = true;
                break;
            }
            ProcessUserModuleRange module;
            module.Base = layout.ModuleBase;
            module.Size = layout.ImageSize;
            PeEvidenceLayout pe;
            if (!ReadPeLayout(read, module, &pe) || !HandlerLayoutMatches(layout, pe))
            {
                ++result->HandlerCoverage.Failures;
                continue;
            }
            const RemoteDecoder decode = [&](uint64_t encoded, uint64_t* decoded)
            {
                PVOID value = nullptr;
                const bool decodedOk = layout.PointerSize == 8 && process.Value != nullptr && decodeRemotePointer != nullptr &&
                    SUCCEEDED(decodeRemotePointer(process.Value, reinterpret_cast<PVOID>(encoded), &value));
                if (decodedOk)
                {
                    *decoded = reinterpret_cast<uint64_t>(value);
                }
                return decodedOk;
            };
            if (layout.Encoded && (process.Value == nullptr || layout.PointerSize != 8 || decodeRemotePointer == nullptr))
            {
                ++result->HandlerCoverage.Failures;
                continue;
            }
            result->HandlerCoverage.Available = true;
            const bool complete = WalkHandlers(read, decode, layout, callbackBudget, &result->Addresses, &result->HandlerCoverage,
                options.CallbackContinuation);
            haveVeh = haveVeh || (!layout.ContinueHandler && complete);
            haveVch = haveVch || (layout.ContinueHandler && complete);
        }
        result->HandlerCoverage.Complete = haveVeh && haveVch && result->HandlerCoverage.Failures == 0 && !result->HandlerCoverage.Truncated;
        result->HandlerCoverage.Detail = result->HandlerCoverage.Available ?
            L"exact image/PDB handler lists; concurrent list mutation remains incomplete" :
            L"exact ntdll handler types or remote pointer decoding unavailable; no guessed offsets";
        result->FileCoverage.Available = QueryKmonFileIdentity(options.ImagePath, &result->ImageIdentity, nullptr);
        result->FileCoverage.Complete = result->FileCoverage.Available;
        result->FileCoverage.Failures = result->FileCoverage.Available ? 0 : 1;
        result->FileCoverage.Detail = L"opened path object identity; not a claim that this object backs the existing image section";
        result->CallbackCursorEvicted = options.CallbackContinuation != nullptr && options.CallbackContinuation->Evicted;
        for (auto& evidence : result->Addresses)
        {
            ClassifyEvidenceAddress(process.Value, options, modulesValid, result->RuntimeRanges, &evidence);
        }
        result->IdentityStable = ValidateEvidenceTarget(device, symbols, options.Target) &&
            (process.Value == nullptr || ProcessGeneration(process.Value, options.Target.CreateTime, nullptr));
        if (!result->IdentityStable)
        {
            result->Addresses.clear();
            result->Snapshot.Threads.clear();
            result->Snapshot.Coverage.Complete = false;
            ++result->Snapshot.Coverage.Failures;
            result->RuntimeRanges.clear();
            result->RuntimeCoverage.Available = false;
            break;
        }
        ok = true;
    } while (false);
    if (!ok && error != nullptr)
    {
        *error = L"user evidence target generation could not be validated";
    }
    return ok;
}

bool KmonUserEvidenceSelfTest()
{
    bool ok = false;
    do
    {
        RuntimeSessionHealth health;
        if (!UpdateRuntimeSessionHealth(&health, 1, ERROR_SUCCESS, 0, 0) || !health.Known ||
            UpdateRuntimeSessionHealth(&health, 1, ERROR_SUCCESS, 0, 0) ||
            !UpdateRuntimeSessionHealth(&health, 1, ERROR_SUCCESS, 1, 0) ||
            UpdateRuntimeSessionHealth(&health, 1, ERROR_SUCCESS, 1, 0) ||
            !UpdateRuntimeSessionHealth(&health, 1, ERROR_SUCCESS, 1, 1) ||
            !UpdateRuntimeSessionHealth(&health, 1, ERROR_SUCCESS, 0, 0) ||
            !UpdateRuntimeSessionHealth(&health, 1, ERROR_ACCESS_DENIED, 0, 0) || health.Known ||
            !UpdateRuntimeSessionHealth(&health, 1, ERROR_SUCCESS, 0, 0) || !health.Known ||
            !UpdateRuntimeSessionHealth(&health, 2, ERROR_SUCCESS, 0, 0) || health.Epoch != 2)
        {
            break;
        }
        struct RuntimeProcessFixture
        {
            uint32_t Failures = 0;
            std::map<uint64_t, KmonRuntimeCodeRange> Ranges;
        };
        std::map<uint32_t, RuntimeProcessFixture> runtimeProcesses;
        runtimeProcesses[10].Ranges[0x100000].Size = 0x100;
        runtimeProcesses[11].Ranges[0x200000].Size = 0x100;
        runtimeProcesses[11].Failures = UINT32_MAX;
        uint64_t minimumEventTime = 100;
        std::atomic<bool> rundownRequired{false};
        InvalidateRuntimeRanges(&runtimeProcesses, 200, &minimumEventTime, &rundownRequired);
        if (!runtimeProcesses[10].Ranges.empty() || !runtimeProcesses[11].Ranges.empty() ||
            runtimeProcesses[10].Failures != 1 || runtimeProcesses[11].Failures != UINT32_MAX ||
            minimumEventTime != 200 || !rundownRequired.load() ||
            RuntimeEventWithinEpoch(199, 50, minimumEventTime) ||
            RuntimeEventWithinEpoch(200, 201, minimumEventTime) ||
            !RuntimeEventWithinEpoch(200, 50, minimumEventTime))
        {
            break;
        }
        RuntimeRundownRequest recovery;
        QueueRuntimeRundown(&recovery, false, &rundownRequired);
        if (!recovery.Pending || rundownRequired.load() || !BeginRuntimeRundownAttempt(&recovery, 100))
        {
            break;
        }
        FinishRuntimeRundownAttempt(&recovery, true);
        InvalidateRuntimeRanges(&runtimeProcesses, 150, &minimumEventTime, &rundownRequired);
        QueueRuntimeRundown(&recovery, false, &rundownRequired);
        if (minimumEventTime != 200 || !recovery.Pending || BeginRuntimeRundownAttempt(&recovery, 101) ||
            !BeginRuntimeRundownAttempt(&recovery, 2100))
        {
            break;
        }
        RuntimeRundownRequest rundown;
        rundown.Pending = true;
        if (!BeginRuntimeRundownAttempt(&rundown, 100))
        {
            break;
        }
        FinishRuntimeRundownAttempt(&rundown, true);
        rundown.Pending = true;
        if (BeginRuntimeRundownAttempt(&rundown, 101) || !rundown.Pending ||
            !BeginRuntimeRundownAttempt(&rundown, 2100))
        {
            break;
        }
        FinishRuntimeRundownAttempt(&rundown, false);
        if (!rundown.Pending || BeginRuntimeRundownAttempt(&rundown, 2101) ||
            !BeginRuntimeRundownAttempt(&rundown, 4100))
        {
            break;
        }
        FinishRuntimeRundownAttempt(&rundown, true);
        if (rundown.Pending || BeginRuntimeRundownAttempt(&rundown, 6100))
        {
            break;
        }
        ProcessApcEntryRecord apc;
        apc.HasNormalRoutine = true;
        apc.NormalRoutine = 0x100100;
        apc.UserRoutine = 0x200100;
        apc.UserRoutineSource = L"system_argument1";
        std::vector<KmonUserAddressEvidence> apcAddresses;
        AppendApcAddressEvidence(apc, 50, &apcAddresses);
        if (apcAddresses.size() != 2 || apcAddresses[0].Kind != KmonUserEvidenceKind::UserApcRoutine ||
            apcAddresses[0].Address != apc.NormalRoutine ||
            apcAddresses[1].Kind != KmonUserEvidenceKind::UserApcArgumentCandidate ||
            apcAddresses[1].Address != apc.UserRoutine)
        {
            break;
        }
        apc.UserRoutine = apc.NormalRoutine;
        apc.UserRoutineSource = L"normal_routine";
        apcAddresses.clear();
        AppendApcAddressEvidence(apc, 50, &apcAddresses);
        if (apcAddresses.size() != 1 || apcAddresses[0].Kind != KmonUserEvidenceKind::UserApcRoutine)
        {
            break;
        }
        apc.HasNormalRoutine = false;
        apcAddresses.clear();
        AppendApcAddressEvidence(apc, 50, &apcAddresses);
        if (!apcAddresses.empty())
        {
            break;
        }
        KmonUserEvidenceOptions ownerOptions;
        ProcessUserModuleRange forged;
        forged.Base = 0x100000;
        forged.Size = 0x100000;
        ownerOptions.UserModules.push_back(forged);
        MEMORY_BASIC_INFORMATION mapping = {};
        mapping.State = MEM_COMMIT;
        mapping.Type = MEM_PRIVATE;
        mapping.Protect = PAGE_EXECUTE_READ;
        mapping.AllocationBase = reinterpret_cast<PVOID>(0x180000);
        const auto queryMapping = [&](uint64_t, MEMORY_BASIC_INFORMATION* output)
        {
            *output = mapping;
            return true;
        };
        KmonUserAddressEvidence address;
        address.Address = 0x180100;
        ClassifyEvidenceMapping(queryMapping, ownerOptions, true, &address);
        if (!address.OwnershipKnown || address.InLoaderModule || !address.PrivateExecutable)
        {
            break;
        }
        mapping.Type = MEM_IMAGE;
        ClassifyEvidenceMapping(queryMapping, ownerOptions, true, &address);
        if (address.InLoaderModule || address.PrivateExecutable)
        {
            break;
        }
        mapping.AllocationBase = reinterpret_cast<PVOID>(forged.Base);
        ClassifyEvidenceMapping(queryMapping, ownerOptions, true, &address);
        if (!address.InLoaderModule || address.PrivateExecutable)
        {
            break;
        }
        mapping.Type = MEM_MAPPED;
        ClassifyEvidenceMapping(queryMapping, ownerOptions, true, &address);
        if (address.InLoaderModule)
        {
            break;
        }
        const auto unavailableMapping = [](uint64_t, MEMORY_BASIC_INFORMATION*)
        {
            return false;
        };
        ClassifyEvidenceMapping(unavailableMapping, ownerOptions, true, &address);
        if (address.OwnershipKnown || address.InLoaderModule || address.PrivateExecutable)
        {
            break;
        }
        ProcessVadRecord fallbackVad;
        fallbackVad.StartAddress = 0x180000;
        fallbackVad.EndAddress = 0x180FFF;
        fallbackVad.HasPrivateMemory = true;
        fallbackVad.PrivateMemory = true;
        ProcessVadProtectionRange fallbackRange;
        fallbackRange.StartAddress = fallbackVad.StartAddress;
        fallbackRange.EndAddress = fallbackVad.EndAddress;
        fallbackRange.Committed = true;
        fallbackRange.Executable = true;
        fallbackRange.Type = MEM_IMAGE;
        fallbackRange.Protection = PAGE_EXECUTE_READ;
        fallbackVad.EffectiveProtectionRanges.push_back(fallbackRange);
        ownerOptions.VadRecords.push_back(fallbackVad);
        ClassifyEvidenceMapping(unavailableMapping, ownerOptions, true, &address);
        if (address.OwnershipKnown || address.InLoaderModule || address.PrivateExecutable)
        {
            break;
        }
        ownerOptions.VadRecords.back().EffectiveProtectionRanges.back().Type = MEM_PRIVATE;
        ClassifyEvidenceMapping(unavailableMapping, ownerOptions, true, &address);
        if (!address.OwnershipKnown || address.InLoaderModule || !address.PrivateExecutable)
        {
            break;
        }
        CONTEXT native = {};
        native.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
        native.Rip = 0x123400;
        native.Rsp = 0x234500;
        native.Dr0 = 0x345600;
        native.Dr7 = 1;
        KmonThreadContextRecord decoded;
        if (!DecodeSnapshotContext(&native, sizeof(native), false, &decoded) || decoded.InstructionPointer != native.Rip ||
            decoded.DebugAddress[0] != native.Dr0 || decoded.Wow64 ||
            DecodeSnapshotContext(&native, sizeof(native) - 1, false, &decoded) ||
            DecodeSnapshotContext(&native, sizeof(native), true, &decoded))
        {
            break;
        }
        WOW64_CONTEXT wow64 = {};
        wow64.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_DEBUG_REGISTERS;
        wow64.Eip = 0x123400;
        wow64.Esp = 0x234500;
        wow64.Dr3 = 0x345600;
        wow64.Dr7 = 1ULL << 6;
        if (!DecodeSnapshotContext(&wow64, sizeof(wow64), true, &decoded) || !decoded.Wow64 ||
            decoded.DebugAddress[3] != wow64.Dr3 || DecodeSnapshotContext(&wow64, sizeof(wow64), false, &decoded))
        {
            break;
        }
        native.ContextFlags = CONTEXT_CONTROL;
        decoded = {};
        if (DecodeSnapshotContext(&native, sizeof(native), false, &decoded) || decoded.DebugValid || !decoded.ControlValid)
        {
            break;
        }
        std::vector<uint32_t> ids;
        for (uint32_t tid = 1; tid <= 300; ++tid)
        {
            ids.push_back(tid);
        }
        std::set<uint32_t> seen;
        uint64_t cursor = 0;
        for (uint32_t pass = 0; pass < 5; ++pass)
        {
            const auto selected = SelectAfter(ids, cursor, 64, [](uint32_t tid)
            {
                return static_cast<uint64_t>(tid);
            });
            seen.insert(selected.begin(), selected.end());
            cursor = selected.back();
        }
        if (seen.size() != ids.size() || !SelectAfter(ids, 0, 0, [](uint32_t tid)
            {
                return static_cast<uint64_t>(tid);
            }).empty())
        {
            break;
        }
        KmonFileIdentity first, alias;
        first.Stable = true;
        first.VolumeSerial = 3;
        first.FileId[15] = 7;
        first.ChangeTime = 100;
        first.FinalPath = L"C:\\first.exe";
        alias = first;
        alias.FinalPath = L"C:\\hardlink.exe";
        if (!KmonSameFileObject(first, alias) || !KmonSameFileGeneration(first, alias))
        {
            break;
        }
        ++alias.ChangeTime;
        if (!KmonSameFileObject(first, alias) || KmonSameFileGeneration(first, alias))
        {
            break;
        }
        alias.FileId[15] = 8;
        if (KmonSameFileObject(first, alias))
        {
            break;
        }
        std::map<uint64_t, KmonRuntimeCodeRange> ranges;
        uint64_t retentionFloor = 0;
        bool rangeAmbiguous = false;
        const auto applyRange = [&](const KmonRuntimeCodeRange& record, RuntimeEventAction action, size_t capacity)
        {
            return ApplyRuntimeRange(&ranges, record, action, capacity, &retentionFloor, &rangeAmbiguous);
        };
        KmonRuntimeCodeRange method;
        method.Start = 0x100000;
        method.Size = 0x100;
        method.MethodId = 11;
        method.RuntimeInstance = 2;
        method.Timestamp = 100;
        if (RuntimeAction(false, 141, 2) != RuntimeEventAction::Load ||
            RuntimeAction(false, 136, 1) != RuntimeEventAction::Ignore ||
            RuntimeAction(true, 144, 1) != RuntimeEventAction::Load ||
            !applyRange(method, RuntimeEventAction::Load, 2))
        {
            break;
        }
        method.Timestamp = 110;
        if (!applyRange(method, RuntimeEventAction::Unload, 2) || ranges.begin()->second.Size != 0)
        {
            break;
        }
        method.Timestamp = 105;
        if (!applyRange(method, RuntimeEventAction::Load, 2) || ranges.begin()->second.Size != 0)
        {
            break;
        }
        method.Timestamp = 120;
        applyRange(method, RuntimeEventAction::Load, 2);
        method.Start += 0x1000;
        method.Timestamp = 121;
        applyRange(method, RuntimeEventAction::Load, 2);
        method.Start += 0x1000;
        method.Timestamp = 122;
        if (applyRange(method, RuntimeEventAction::Load, 2) || ranges.size() != 2 ||
            ranges.find(method.Start) == ranges.end() || retentionFloor != 120)
        {
            break;
        }

        struct RuntimeOrderingFixture
        {
            uint32_t Failures = 0;
            bool Overflow = false;
            uint64_t RetentionFloor = 0;
            std::map<uint64_t, KmonRuntimeCodeRange> Ranges;
        };
        const auto orderingEvent = [](uint64_t timestamp, uint64_t start = 0x100000, uint64_t methodId = 11)
        {
            KmonRuntimeCodeRange record;
            record.Start = start;
            record.Size = 0x100;
            record.MethodId = methodId;
            record.RuntimeInstance = 2;
            record.Timestamp = timestamp;
            return record;
        };
        std::map<uint32_t, RuntimeOrderingFixture> orderedProcesses;
        auto& ordered = orderedProcesses[10];
        std::atomic<bool> orderingLost{false};
        ApplyRuntimeObservation(&ordered, orderingEvent(110), RuntimeEventAction::Unload, 2, &orderingLost);
        ApplyRuntimeObservation(&ordered, orderingEvent(105), RuntimeEventAction::Load, 2, &orderingLost);
        if (orderingLost.load() || ordered.Ranges.size() != 1 || ordered.Ranges.begin()->second.Size != 0)
        {
            break;
        }
        ApplyRuntimeObservation(&ordered, orderingEvent(110), RuntimeEventAction::Load, 2, &orderingLost);
        if (!orderingLost.load() || !ordered.Ranges.empty() || ordered.RetentionFloor != 110)
        {
            break;
        }
        uint64_t orderingFence = 0;
        std::atomic<bool> orderingRundown{false};
        InvalidateRuntimeRanges(&orderedProcesses, 111, &orderingFence, &orderingRundown);
        RuntimeRundownRequest orderingRecovery;
        QueueRuntimeRundown(&orderingRecovery, false, &orderingRundown);
        orderingLost.store(false);
        ApplyRuntimeObservation(&ordered, orderingEvent(110), RuntimeEventAction::Load, 2, &orderingLost);
        if (!ordered.Ranges.empty() || orderingFence != 111 || !orderingRecovery.Pending ||
            !BeginRuntimeRundownAttempt(&orderingRecovery, 100))
        {
            break;
        }
        ApplyRuntimeObservation(&ordered, orderingEvent(120), RuntimeEventAction::Load, 2, &orderingLost);
        if (ordered.Ranges.size() != 1 || ordered.Ranges.begin()->second.Size == 0 || orderingLost.load())
        {
            break;
        }
        ApplyRuntimeObservation(&ordered, orderingEvent(120), RuntimeEventAction::Unload, 2, &orderingLost);
        if (!orderingLost.load() || !ordered.Ranges.empty() || ordered.RetentionFloor != 120)
        {
            break;
        }
        ordered = {};
        orderingLost.store(false);
        ApplyRuntimeObservation(&ordered, orderingEvent(100), RuntimeEventAction::Load, 2, &orderingLost);
        ApplyRuntimeObservation(&ordered, orderingEvent(100), RuntimeEventAction::Load, 2, &orderingLost);
        if (ordered.Ranges.size() != 1 || ordered.Ranges.begin()->second.Size == 0 || orderingLost.load())
        {
            break;
        }
        ApplyRuntimeObservation(&ordered, orderingEvent(100, 0x100000, 12), RuntimeEventAction::Load, 2, &orderingLost);
        if (!orderingLost.load() || !ordered.Ranges.empty())
        {
            break;
        }
        ordered = {};
        orderingLost.store(false);
        ApplyRuntimeObservation(&ordered, orderingEvent(100), RuntimeEventAction::Unload, 2, &orderingLost);
        ApplyRuntimeObservation(&ordered, orderingEvent(200, 0x200000), RuntimeEventAction::Load, 2, &orderingLost);
        ApplyRuntimeObservation(&ordered, orderingEvent(300, 0x300000), RuntimeEventAction::Load, 2, &orderingLost);
        ApplyRuntimeObservation(&ordered, orderingEvent(90), RuntimeEventAction::Load, 2, &orderingLost);
        if (!ordered.Overflow || ordered.RetentionFloor != 100 || ordered.Ranges.size() != 2 ||
            ordered.Ranges.find(0x100000) != ordered.Ranges.end() || orderingLost.load())
        {
            break;
        }
        ApplyRuntimeObservation(&ordered, orderingEvent(400, 0x200000, 12), RuntimeEventAction::Unload, 2, &orderingLost);
        if (!orderingLost.load() || !ordered.Ranges.empty() || ordered.RetentionFloor != 400)
        {
            break;
        }
        std::vector<uint8_t> memory(0x4000, 0);
        ProcessUserModuleRange module;
        module.Base = 0x100000;
        module.Size = memory.size();
        auto write = [&](size_t offset, const void* data, size_t length)
        {
            std::memcpy(memory.data() + offset, data, length);
        };
        IMAGE_DOS_HEADER dos = {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        write(0, &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 nt = {};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.FileHeader.TimeDateStamp = 99;
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage = static_cast<uint32_t>(memory.size());
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {0x300, sizeof(IMAGE_TLS_DIRECTORY64)};
        write(0x80, &nt, sizeof(nt));
        IMAGE_TLS_DIRECTORY64 tls = {};
        tls.AddressOfCallBacks = module.Base + 0x800;
        write(0x300, &tls, sizeof(tls));
        uint64_t callbacks[] = {0x500000, 0x600000, 0};
        write(0x800, callbacks, sizeof(callbacks));
        const EvidenceReader reader = [&](uint64_t address, void* output, uint32_t length)
        {
            const bool valid = address >= module.Base && address - module.Base <= memory.size() &&
                length <= memory.size() - static_cast<size_t>(address - module.Base);
            if (valid)
            {
                std::memcpy(output, memory.data() + (address - module.Base), length);
            }
            return valid;
        };
        std::vector<KmonUserAddressEvidence> records;
        KmonEvidenceCoverage coverage;
        coverage.Complete = true;
        CollectTlsCallbacks(reader, module, 2, &records, &coverage);
        if (records.size() != 2 || coverage.Failures != 0 || coverage.Truncated || records[1].Address != callbacks[1])
        {
            break;
        }
        records.clear();
        coverage = {};
        CollectTlsCallbacks(reader, module, 1, &records, &coverage);
        if (records.size() != 1 || !coverage.Truncated)
        {
            break;
        }
        uint32_t tableReads = 0;
        const EvidenceReader changingTable = [&](uint64_t address, void* output, uint32_t length)
        {
            const bool read = reader(address, output, length);
            if (read && address == module.Base + 0x300 + 24 && ++tableReads == 2)
            {
                const uint64_t replacement = module.Base + 0x900;
                std::memcpy(output, &replacement, length);
            }
            return read;
        };
        records.clear();
        coverage = {};
        CollectTlsCallbacks(changingTable, module, 2, &records, &coverage);
        if (!records.empty() || coverage.Failures == 0)
        {
            break;
        }
        KmonUserCallbackContinuation callbackCursor;
        PrepareCallbackContinuation(&callbackCursor, 123, 100);
        std::vector<uint64_t> manyCallbacks(34, 0);
        for (size_t index = 0; index < 33; ++index)
        {
            manyCallbacks[index] = 0x500000 + index * 0x1000;
        }
        write(0x800, manyCallbacks.data(), manyCallbacks.size() * sizeof(uint64_t));
        for (uint32_t pass = 0; pass < 2; ++pass)
        {
            records.clear();
            coverage = {};
            CollectTlsCallbacks(reader, module, 32, &records, &coverage, &callbackCursor);
            if (records.size() != 32 || !coverage.Truncated || coverage.Failures != 0 ||
                (pass == 1 && records.front().Address != manyCallbacks[32]))
            {
                return false;
            }
        }
        if (callbackCursor.Cursors.size() != 1)
        {
            break;
        }
        PrepareCallbackContinuation(&callbackCursor, 123, 100);
        if (callbackCursor.Cursors.size() != 1)
        {
            break;
        }
        PrepareCallbackContinuation(&callbackCursor, 123, 101);
        if (!callbackCursor.Cursors.empty())
        {
            break;
        }
        KmonVectoredHandlerLayout layout;
        layout.ModuleBase = module.Base;
        layout.PointerSize = 8;
        layout.ListHeadRva = 0x1000;
        layout.EntrySize = 24;
        layout.HandlerOffset = 16;
        layout.Encoded = true;
        layout.SymbolProvenance = L"fixture exact layout";
        uint64_t head = module.Base + layout.ListHeadRva;
        uint64_t entry = module.Base + 0x1100;
        uint64_t links[] = {entry, entry};
        uint64_t handler[] = {head, head, 0x700000};
        write(0x1000, links, sizeof(links));
        write(0x1100, handler, sizeof(handler));
        const RemoteDecoder decoder = [](uint64_t encoded, uint64_t* value)
        {
            *value = encoded;
            return true;
        };
        records.clear();
        coverage = {};
        if (!WalkHandlers(reader, decoder, layout, 4, &records, &coverage) || records.size() != 1 || records[0].Address != handler[2])
        {
            break;
        }
        handler[0] = entry;
        write(0x1100, handler, sizeof(handler));
        records.clear();
        coverage = {};
        if (WalkHandlers(reader, decoder, layout, 4, &records, &coverage) || !records.empty() || coverage.Failures == 0)
        {
            break;
        }
        // A stable 33rd handler must be selected on the second visit.
        std::vector<uint64_t> handlerEntries;
        for (uint32_t index = 0; index < 33; ++index)
        {
            handlerEntries.push_back(module.Base + 0x1100 + index * 0x20);
        }
        links[0] = handlerEntries.front();
        links[1] = handlerEntries.back();
        write(0x1000, links, sizeof(links));
        for (size_t index = 0; index < handlerEntries.size(); ++index)
        {
            uint64_t item[] =
            {
                index + 1 == handlerEntries.size() ? head : handlerEntries[index + 1],
                index == 0 ? head : handlerEntries[index - 1],
                0x700000 + index * 0x1000
            };
            write(static_cast<size_t>(handlerEntries[index] - module.Base), item, sizeof(item));
        }
        for (uint32_t kind = 0; kind < 2; ++kind)
        {
            layout.ContinueHandler = kind != 0;
            for (uint32_t pass = 0; pass < 2; ++pass)
            {
                records.clear();
                coverage = {};
                if (WalkHandlers(reader, decoder, layout, 32, &records, &coverage, &callbackCursor) ||
                    records.size() != 32 || !coverage.Truncated || coverage.Failures != 0 ||
                    (pass == 1 && records.front().RecordAddress != handlerEntries.back()))
                {
                    return false;
                }
            }
        }
        // An empty list releases its continuation instead of retaining a
        // stale pointer. VEH and VCH maintain independent keys.
        links[0] = head;
        links[1] = head;
        write(0x1000, links, sizeof(links));
        records.clear();
        coverage = {};
        if (!WalkHandlers(reader, decoder, layout, 32, &records, &coverage, &callbackCursor) ||
            !records.empty() || callbackCursor.Cursors.size() != 1)
        {
            break;
        }
        layout.ContinueHandler = false;
        if (!WalkHandlers(reader, decoder, layout, 32, &records, &coverage, &callbackCursor) ||
            !callbackCursor.Cursors.empty())
        {
            break;
        }
        std::vector<KmonUserAddressEvidence> pending(33);
        for (size_t index = 0; index < pending.size(); ++index)
        {
            pending[index].RecordAddress = 0x200000 + index * 0x20;
        }
        coverage = {};
        const auto batch = SelectCallbackEvidence(pending, 32, KmonUserEvidenceKind::TlsCallback,
            module.Base, 0x200000, &callbackCursor, &coverage);
        pending.erase(pending.begin() + 31);
        const auto churn = SelectCallbackEvidence(pending, 1, KmonUserEvidenceKind::TlsCallback,
            module.Base, 0x200000, &callbackCursor, &coverage);
        if (batch.size() != 32 || churn.size() != 1 || churn.front().RecordAddress != 0x200400)
        {
            break;
        }
        for (uint64_t key = 1; key <= 513; ++key)
        {
            SelectCallbackEvidence(pending, 1, KmonUserEvidenceKind::TlsCallback,
                module.Base, 0x300000 + key * 0x1000, &callbackCursor, &coverage);
        }
        if (callbackCursor.Cursors.size() != 512 || !callbackCursor.Evicted || !coverage.Truncated)
        {
            break;
        }
        PeEvidenceLayout identity;
        identity.PdbIdentityKnown = true;
        identity.PdbAge = 1;
        identity.ImageSize = 0x4000;
        identity.PointerSize = 8;
        layout.ImageSize = identity.ImageSize;
        layout.PdbAge = identity.PdbAge;
        if (!HandlerLayoutMatches(layout, identity))
        {
            break;
        }
        layout.PdbAge = 2;
        if (HandlerLayoutMatches(layout, identity))
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
}
