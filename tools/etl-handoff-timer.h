#pragma once

#include "etl-handoff-dispatch.h"

namespace handoff
{
    inline ULONG TimerMarker(REGHANDLE provider, const GUID& activity, USHORT id)
    {
        const USHORT task = id < 24 ? 10 : 11;
        const UCHAR opcode = id == 22 || id == 24 ? 1 : 2;
        const EVENT_DESCRIPTOR descriptor{id, 1, 0, TRACE_LEVEL_INFORMATION, opcode, task, 0};
        return WriteEvent(provider, activity, descriptor);
    }

    // The worker is held at its release gate until the observer has probed the unarmed timer.
    class TimerObserver
    {
        HANDLE ready{}, thread{}, objects[2]{};
        REGHANDLE provider{};
        GUID activity{};
        static constexpr DWORD MaxProbes = 40;

        DWORD Observe()
        {
            for (DWORD i = 0; i < MaxProbes; ++i)
            {
                auto status = TimerMarker(provider, activity, 24);
                if (status) { return status; }
                const auto sample = WaitForSingleObject(objects[0], 0);
                if (sample == WAIT_FAILED) { return GetLastError(); }
                if (sample != WAIT_TIMEOUT && sample != WAIT_OBJECT_0) { return ERROR_INVALID_DATA; }
                status = TimerMarker(provider, activity, sample == WAIT_TIMEOUT ? 25 : 26);
                if (status) { return status; }
                ++samples;
                if (!i && !SetEvent(ready)) { return GetLastError(); }
                if (sample == WAIT_OBJECT_0) { return ERROR_SUCCESS; }
                if (i + 1 == MaxProbes) { return ERROR_TIMEOUT; }
                // The worker handle also wakes us on worker failure. The timer wins ties.
                // Both arms use the same sampling schedule, including the bounded final wait.
                const DWORD spacing = i < 4 ? 5 : i < 16 ? 15 : i + 2 == MaxProbes ? 5000 : 40;
                const auto wake = WaitForMultipleObjects(2, objects, FALSE, spacing);
                if (wake == WAIT_FAILED) { return GetLastError(); }
                if (wake == WAIT_OBJECT_0 + 1) { return ERROR_INVALID_DATA; }
                if (wake != WAIT_OBJECT_0 && wake != WAIT_TIMEOUT) { return ERROR_INVALID_DATA; }
            }
            return ERROR_INVALID_DATA;
        }

        static DWORD WINAPI Entry(void* context) { return static_cast<TimerObserver*>(context)->Observe(); }

    public:
        DWORD tid = 0, samples = 0;

        ULONG Start(REGHANDLE registration, const GUID& id, HANDLE timer, HANDLE worker)
        {
            provider = registration;
            activity = id;
            objects[0] = timer;
            objects[1] = worker;
            ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!ready) { return GetLastError(); }
            thread = CreateThread(nullptr, 0, Entry, this, 0, &tid);
            if (!thread) { return GetLastError(); }
            const HANDLE startup[]{ready, thread};
            const DWORD result = WaitForMultipleObjects(2, startup, FALSE, 5000);
            if (result == WAIT_OBJECT_0) { return ERROR_SUCCESS; }
            if (result == WAIT_OBJECT_0 + 1) { return Finish(); }
            return result == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
        }

        ULONG Finish()
        {
            if (!thread) { return ERROR_SUCCESS; }
            if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) { return GetLastError(); }
            DWORD code = 0;
            if (!GetExitCodeThread(thread, &code)) { return GetLastError(); }
            CloseHandle(thread);
            thread = nullptr;
            return code;
        }

        ~TimerObserver()
        {
            if (thread) { WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }
            if (ready) { CloseHandle(ready); }
        }
    };
}
