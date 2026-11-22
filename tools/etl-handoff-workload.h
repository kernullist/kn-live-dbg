#pragma once

#include <Windows.h>
#include <evntprov.h>
#include <objbase.h>
#include <array>
#include <cstdint>
#include <iostream>
#include <string>

namespace handoff
{
    constexpr GUID Provider{0x4dc673b7, 0xfb3f, 0x4099, {0x95, 0x2a, 0x37, 0xda, 0xc2, 0x7c, 0xf1, 0x94}};
    constexpr uint32_t WorkerSalt = 0x9e3779b9u;

    struct Config
    {
        GUID activity{};
        uint32_t seed = 0, steps = 0, delayMs = 0, callerDelayMs = 0;
        bool probeJoin = false;

        static bool Number(const wchar_t* input, uint32_t maximum, uint32_t& value)
        {
            value = 0;
            if (!*input || (*input == L'0' && input[1])) { return false; }
            for (; *input; ++input)
            {
                if (*input < L'0' || *input > L'9') { return false; }
                auto digit = static_cast<uint32_t>(*input - L'0');
                if (digit > maximum || value > (maximum - digit) / 10) { return false; }
                value = 10 * value + digit;
            }
            return true;
        }

        bool Parse(wchar_t** args)
        {
            const std::wstring id(args[0]);
            return id.size() == 36 && SUCCEEDED(CLSIDFromString((L"{" + id + L"}").c_str(), &activity)) &&
                !IsEqualGUID(activity, GUID_NULL) && Number(args[1], UINT32_MAX, seed) &&
                Number(args[2], 1000000, steps) && steps && Number(args[3], 1000, delayMs);
        }
    };

    inline uint32_t Calculate(uint32_t seed, uint32_t steps)
    {
        while (steps--) { seed = 1664525u * seed + 1013904223u; }
        return seed;
    }

    struct Handle
    {
        HANDLE value{};
        explicit Handle(HANDLE handle) : value(handle) {}
        ~Handle() { if (value) { CloseHandle(value); } }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
    };

    inline uint64_t Time(FILETIME value)
    {
        return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
    }

    inline LONGLONG Tick()
    {
        LARGE_INTEGER value{};
        return QueryPerformanceCounter(&value) ? value.QuadPart : 0;
    }

    struct Bracket
    {
        LONGLONG begin = 0, end = 0;
        void Json() const { std::wcout << L"[\"" << begin << L"\",\"" << end << L"\"]"; }
    };

    inline ULONG Wait(HANDLE handle)
    {
        const DWORD result = WaitForSingleObject(handle, 5000);
        if (result == WAIT_OBJECT_0) { return ERROR_SUCCESS; }
        if (result == WAIT_FAILED) { return GetLastError(); }
        return result == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_INVALID_DATA;
    }

    struct Trial
    {
        Config settings{};
        REGHANDLE registration{};
        HANDLE go{}, timer{};
        DWORD callerTid{}, workerTid{};
        uint32_t callerResult{}, workerResult{};
        uint64_t processCreated{}, workerCreated{}, workerExited{};
        LONGLONG frequency{};
        std::array<Bracket, 14> markers{};
        Bracket joinCall{}, timerCall{}, callerDelayCall{};
        std::array<Bracket, 2> probeCalls{};
        std::array<DWORD, 2> probeResults{};

        ULONG Mark(size_t index, USHORT eventId = 0)
        {
            const EVENT_DESCRIPTOR descriptor{eventId ? eventId : static_cast<USHORT>(index + 1), 1, 0, TRACE_LEVEL_INFORMATION,
                static_cast<UCHAR>(1 + index % 2), static_cast<USHORT>(1 + index / 2), 0};
            auto& span = markers[index];
            span.begin = Tick();
            const auto status = EventWriteTransfer(registration, &descriptor, &settings.activity, nullptr, 0, nullptr);
            span.end = Tick();
            return status;
        }

        ULONG Probe(HANDLE worker, size_t slot)
        {
            const size_t marker = 10 + 2 * slot;
            auto status = Mark(marker);
            if (status) { return status; }
            probeCalls[slot].begin = Tick();
            const DWORD result = WaitForSingleObject(worker, 0);
            const DWORD error = result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
            probeCalls[slot].end = Tick();
            if (result != WAIT_TIMEOUT && result != WAIT_OBJECT_0) { return error ? error : ERROR_INVALID_DATA; }
            probeResults[slot] = result;
            // The Stop descriptor in the original ETL identifies the observed state.
            return Mark(marker + 1, static_cast<USHORT>(result == WAIT_OBJECT_0 ? 16 + slot : marker + 2));
        }

        static DWORD WINAPI Worker(void* context)
        {
            auto& trial = *static_cast<Trial*>(context);
            auto status = Wait(trial.go);
            if (!status) { status = trial.Mark(4); }
            if (!status)
            {
                trial.workerResult = Calculate(trial.settings.seed ^ WorkerSalt, trial.settings.steps);
                status = trial.Mark(6);
            }
            if (!status)
            {
                LARGE_INTEGER due{};
                due.QuadPart = trial.settings.delayMs ? -10000LL * trial.settings.delayMs : -1;
                if (!SetWaitableTimer(trial.timer, &due, 0, nullptr, nullptr, FALSE)) { return GetLastError(); }
                trial.timerCall.begin = Tick();
                status = Wait(trial.timer);
                trial.timerCall.end = Tick();
            }
            if (!status) { status = trial.Mark(7); }
            return status ? status : trial.Mark(5);
        }

        ULONG Run(REGHANDLE provider)
        {
            registration = provider;
            LARGE_INTEGER hz{};
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!QueryPerformanceFrequency(&hz) || !GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
            { return GetLastError(); }
            frequency = hz.QuadPart;
            processCreated = Time(created);
            callerTid = GetCurrentThreadId();
            Handle release(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (!release.value) { return GetLastError(); }
            Handle alarm(CreateWaitableTimerW(nullptr, FALSE, nullptr));
            if (!alarm.value) { return GetLastError(); }
            go = release.value;
            timer = alarm.value;
            Handle worker(CreateThread(nullptr, 0, Worker, this, 0, &workerTid));
            if (!worker.value) { return GetLastError(); }

            auto status = Mark(0);
            if (!SetEvent(go) && !status) { status = GetLastError(); }
            if (!status) { status = Mark(2); }
            if (!status) { callerResult = Calculate(settings.seed, settings.steps); status = Mark(3); }
            if (!status && settings.callerDelayMs)
            {
                callerDelayCall.begin = Tick();
                Sleep(settings.callerDelayMs);
                callerDelayCall.end = Tick();
            }
            if (!status && settings.probeJoin) { status = Probe(worker.value, 0); }
            if (!status) { status = Mark(8); }
            if (!status && settings.probeJoin) { status = Probe(worker.value, 1); }
            joinCall.begin = Tick();
            const auto joined = Wait(worker.value);
            joinCall.end = Tick();
            if (joined)
            {
                // The worker owns references to this stack frame until its thread has exited.
                WaitForSingleObject(worker.value, INFINITE);
                if (!status) { status = joined; }
            }
            if (!status) { status = Mark(9); }
            if (!status) { status = Mark(1); }
            DWORD completion = 0;
            if (!status && (!GetExitCodeThread(worker.value, &completion) ||
                !GetThreadTimes(worker.value, &created, &exited, &kernel, &user))) { status = GetLastError(); }
            if (!status) { workerCreated = Time(created); workerExited = Time(exited); }
            return status ? status : completion;
        }

        void Json(const std::wstring& activity) const
        {
            std::wcout << L",\"schema\":\"kn.owned_etl_handoff." << (settings.probeJoin ? L"v2" : L"v1") << L"\",\"activity_id\":\"" << activity
                << L"\",\"seed\":" << settings.seed << L",\"steps\":" << settings.steps << L",\"delay_ms\":" << settings.delayMs
                << L",\"caller_result\":" << callerResult << L",\"worker_result\":" << workerResult
                << L",\"pid\":" << GetCurrentProcessId() << L",\"process_created\":\"" << processCreated
                << L"\",\"caller_tid\":" << callerTid << L",\"joined_tid\":" << workerTid << L",\"worker_created\":\"" << workerCreated
                << L"\",\"worker_exited\":\"" << workerExited << L"\",\"frequency\":\"" << frequency << L"\",\"write_brackets\":[";
            const size_t count = settings.probeJoin ? markers.size() : 10;
            for (size_t i = 0; i < count; ++i) { if (i) { std::wcout << L','; } markers[i].Json(); }
            std::wcout << L"],\"join_call\":"; joinCall.Json();
            std::wcout << L",\"timer_call\":"; timerCall.Json();
            if (settings.probeJoin)
            {
                std::wcout << L",\"caller_delay_ms\":" << settings.callerDelayMs << L",\"caller_delay_call\":";
                if (settings.callerDelayMs) { callerDelayCall.Json(); } else { std::wcout << L"null"; }
                std::wcout << L",\"join_probes\":[";
                for (size_t i = 0; i < probeCalls.size(); ++i)
                {
                    if (i) { std::wcout << L','; }
                    std::wcout << L"{\"wait_result\":" << probeResults[i] << L",\"call\":";
                    probeCalls[i].Json();
                    std::wcout << L'}';
                }
                std::wcout << L']';
            }
        }
    };
}
