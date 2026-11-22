#pragma once

#include "../shared/HandoffEvents.h"
#include <wct.h>
#include <algorithm>
#include <array>
#include <cstddef>

namespace handoff
{
    constexpr ULONG NotCalled = 0xffffffffu;

    inline LONGLONG Tick()
    {
        LARGE_INTEGER value{};
        return QueryPerformanceCounter(&value) ? value.QuadPart : 0;
    }

    inline ULONG WriteEvent(REGHANDLE provider, const GUID& activity, const EVENT_DESCRIPTOR& desc, const void* data = nullptr, ULONG bytes = 0)
    {
        EVENT_DATA_DESCRIPTOR payload{};
        if (bytes) { EventDataDescCreate(&payload, data, bytes); }
        return EventWriteTransfer(provider, &desc, &activity, nullptr, bytes ? 1 : 0, bytes ? &payload : nullptr);
    }

    struct DispatchReading
    {
        ULONG64 status = NotCalled, begin = 0, end = 0, switches = 0, reasons = 0, cycles = 0, retries = 0;

        void Read(HANDLE profile)
        {
            PERFORMANCE_DATA data{};
            data.Size = sizeof(data);
            data.Version = PERFORMANCE_DATA_VERSION;
            begin = Tick();
            status = ReadThreadProfilingData(profile, READ_THREAD_PROFILING_FLAG_DISPATCHING, &data);
            end = Tick();
            if (!status)
            {
                switches = data.ContextSwitchCount;
                reasons = data.WaitReasonBitMap;
                cycles = data.CycleTime;
                retries = data.RetryCount;
            }
        }
    };

    struct DispatchEvent
    {
        ULONG64 version = 1, enable = NotCalled, disable = NotCalled, callBegin = 0, callEnd = 0;
        DispatchReading before, after;
    };
    static_assert(sizeof(DispatchEvent) == 19 * sizeof(ULONG64));

    class DispatchWindow
    {
        HANDLE profile{};
    public:
        DispatchEvent event;
        void Begin()
        {
            event.enable = EnableThreadProfiling(GetCurrentThread(), THREAD_PROFILING_FLAG_DISPATCH, 0, &profile);
            if (!event.enable) { event.before.Read(profile); }
        }
        void End(ULONG64 begin, ULONG64 end)
        {
            event.callBegin = begin;
            event.callEnd = end;
            if (!event.enable)
            {
                event.after.Read(profile);
                event.disable = DisableThreadProfiling(profile);
                if (!event.disable) { profile = nullptr; }
            }
        }
        ~DispatchWindow() { if (profile && !event.enable) { DisableThreadProfiling(profile); } }
    };

    // The caller holds the worker handle until this observer has exited.
    class JoinObserver
    {
        HANDLE events[2]{}, ready{}, thread{}, worker{};
        REGHANDLE provider{};
        GUID activity{};
        DWORD caller = 0, tid = 0, views = 0, setup = NotCalled, open = NotCalled, error = 0, stopReason = 0;

        ULONG Mark(USHORT id, UCHAR opcode, USHORT task, const void* data = nullptr, ULONG length = 0)
        {
            const EVENT_DESCRIPTOR desc{id, 2, 0, TRACE_LEVEL_INFORMATION, opcode, task, 0};
            return WriteEvent(provider, activity, desc, data, length);
        }

        ULONG Sample(HWCT session)
        {
            auto status = Mark(18, 1, 8);
            if (status) { return status; }
            std::array<WAITCHAIN_NODE_INFO, WCT_MAX_NODE_COUNT> nodes{};
            DWORD count = static_cast<DWORD>(nodes.size());
            BOOL cycle = FALSE;
            const auto before = WaitForSingleObject(worker, 0);
            const auto begin = Tick();
            const bool ok = GetThreadWaitChain(session, 0, 0, caller, &count, nodes.data(), &cycle) != FALSE;
            const auto queryError = ok ? ERROR_SUCCESS : GetLastError();
            const auto end = Tick();
            const auto after = WaitForSingleObject(worker, 0);
            const DWORD retained = (ok || queryError == ERROR_MORE_DATA || queryError == ERROR_TOO_MANY_THREADS) ?
                (std::min)(count, static_cast<DWORD>(nodes.size())) : 0;
            std::array<ULONG64, 10 + WCT_MAX_NODE_COUNT * 6> words{
                1, views + 1u, before, after, static_cast<ULONG64>(begin), static_cast<ULONG64>(end), queryError,
                static_cast<ULONG64>(cycle != FALSE), count, retained};
            static_assert(sizeof(words) <= handoff_events::MaxPayload);
            size_t offset = 10;
            for (DWORD i = 0; i < retained; ++i)
            {
                const auto& node = nodes[i];
                words[offset] = node.ObjectType;
                words[offset + 1] = node.ObjectStatus;
                if (node.ObjectType == WctThreadType)
                {
                    words[offset + 2] = node.ThreadObject.ProcessId;
                    words[offset + 3] = node.ThreadObject.ThreadId;
                    words[offset + 4] = node.ThreadObject.WaitTime;
                    words[offset + 5] = node.ThreadObject.ContextSwitches;
                }
                offset += 6;
            }
            status = Mark(19, 2, 8, words.data(), static_cast<ULONG>(offset * sizeof(ULONG64)));
            if (!status) { ++views; }
            return status;
        }

        DWORD Observe()
        {
            HWCT session = OpenThreadWaitChainSession(0, nullptr);
            open = session ? ERROR_SUCCESS : GetLastError();
            SetEvent(ready);
            if (!session) { stopReason = 3; error = open; return open; }
            DWORD wait = WaitForMultipleObjects(2, events, FALSE, 5000);
            while (wait == WAIT_OBJECT_0 + 1)
            {
                error = Sample(session);
                if (error || views == handoff_events::MaxViews) { break; }
                wait = WaitForSingleObject(events[0], handoff_events::ViewSpacingMs);
                if (wait == WAIT_TIMEOUT) { wait = WAIT_OBJECT_0 + 1; }
            }
            if (wait == WAIT_FAILED) { error = GetLastError(); }
            if (wait == WAIT_TIMEOUT) { error = ERROR_TIMEOUT; }
            stopReason = error ? 3 : views == handoff_events::MaxViews ? 2 : 1;
            CloseThreadWaitChainSession(session);
            return error;
        }

        static DWORD WINAPI Entry(void* context) { return static_cast<JoinObserver*>(context)->Observe(); }

    public:
        ULONG Start(REGHANDLE registration, const GUID& id, DWORD callerTid, HANDLE workerHandle)
        {
            provider = registration; activity = id; caller = callerTid; worker = workerHandle;
            const auto marker = Mark(20, 1, 9);
            if (marker) { return marker; }
            for (auto& gate : events)
            {
                gate = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (!gate) { setup = GetLastError(); return ERROR_SUCCESS; }
            }
            ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ready) { setup = GetLastError(); return ERROR_SUCCESS; }
            thread = CreateThread(nullptr, 0, Entry, this, 0, &tid);
            setup = thread ? ERROR_SUCCESS : GetLastError();
            if (thread)
            {
                const auto wait = WaitForSingleObject(ready, 5000);
                if (wait != WAIT_OBJECT_0) { setup = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError(); Stop(); }
            }
            return ERROR_SUCCESS;
        }

        void Arm() { if (thread && !setup && !SetEvent(events[1])) { setup = GetLastError(); } }
        void Stop() { if (thread && !SetEvent(events[0])) { setup = GetLastError(); } }
        ULONG Finish()
        {
            Stop();
            if (thread && WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) { return GetLastError(); }
            if (thread) { CloseHandle(thread); thread = nullptr; }
            const std::array<ULONG64, 7> words{1, setup, open, error, stopReason, tid, views};
            return Mark(21, 2, 9, words.data(), static_cast<ULONG>(sizeof(words)));
        }
        ~JoinObserver()
        {
            if (thread) { Stop(); WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }
            if (ready) { CloseHandle(ready); }
            for (auto gate : events) { if (gate) { CloseHandle(gate); } }
        }
    };
}
