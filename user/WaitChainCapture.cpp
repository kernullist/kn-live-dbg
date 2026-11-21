#include "WaitChainCapture.h"
#include "CommandInput.h"

#include <Windows.h>
#include <wct.h>
#include <algorithm>
#include <array>
#include <iostream>
#include <memory>
#include <optional>
#include <vector>

namespace
{
    struct CloseObject { void operator()(void* h) const { CloseHandle(h); } };
    struct CloseSession { void operator()(void* h) const { CloseThreadWaitChainSession(h); } };
    using Handle = std::unique_ptr<void, CloseObject>;
    using Session = std::unique_ptr<void, CloseSession>;

    struct Signal { DWORD result, error; ULONGLONG tick; };
    struct Pin
    {
        Handle handle;
        DWORD requested = 0, id = 0, pid = 0, error = 0;
        ULONGLONG created = 0;
        const char* failure = nullptr;
        std::optional<Signal> initial, before, after;
    };

    std::optional<Signal> Sample(const Pin& pin)
    {
        if (pin.failure || !pin.handle) { return {}; }
        const DWORD result = WaitForSingleObject(pin.handle.get(), 0);
        const DWORD error = result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
        return Signal{result, error, GetTickCount64()};
    }

    Pin OpenPin(DWORD id, bool thread)
    {
        Pin p;
        p.requested = id;
        p.handle.reset(thread ? OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, id) :
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, id));
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!p.handle) { p.failure = "open"; }
        else if (!(p.id = thread ? GetThreadId(p.handle.get()) : GetProcessId(p.handle.get()))) { p.failure = "id"; }
        else if (!(p.pid = thread ? GetProcessIdOfThread(p.handle.get()) : p.id)) { p.failure = "owner"; }
        else if (!(thread ? GetThreadTimes(p.handle.get(), &created, &exited, &kernel, &user) :
                            GetProcessTimes(p.handle.get(), &created, &exited, &kernel, &user))) { p.failure = "times"; }
        if (p.failure) { p.error = GetLastError(); }
        else { p.created = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime; }
        p.initial = Sample(p);
        return p;
    }

    bool Bound(const Pin& p, DWORD pid, uint64_t created, const std::optional<Signal>& signal)
    {
        return !p.failure && p.id == p.requested && p.pid == pid && p.created == created &&
            signal && signal->result == WAIT_TIMEOUT;
    }

    std::optional<ULONGLONG> Counter()
    {
        LARGE_INTEGER value{};
        if (QueryPerformanceCounter(&value) && value.QuadPart >= 0) { return static_cast<ULONGLONG>(value.QuadPart); }
        return {};
    }

    struct Query
    {
        std::array<WAITCHAIN_NODE_INFO, WCT_MAX_NODE_COUNT> nodes{};
        DWORD count = WCT_MAX_NODE_COUNT, retained = 0, error = 0;
        bool ok = false;
        BOOL cycle = FALSE;
        ULONGLONG start = 0, end = 0;
        DWORD reader = 0;
        std::optional<ULONGLONG> beginQpc, endQpc;
    };

    Query ReadChain(HWCT session, DWORD tid, bool timed = false)
    {
        Query q;
        q.start = GetTickCount64();
        if (timed) { q.reader = GetCurrentThreadId(); q.beginQpc = Counter(); }
        q.ok = GetThreadWaitChain(session, 0, 0, tid, &q.count, q.nodes.data(), &q.cycle) != FALSE;
        if (!q.ok) { q.error = GetLastError(); }
        if (timed) { q.endQpc = Counter(); }
        q.end = GetTickCount64();
        if (q.ok || q.error == ERROR_MORE_DATA || q.error == ERROR_TOO_MANY_THREADS)
        {
            q.retained = (std::min)(q.count, static_cast<DWORD>(q.nodes.size()));
        }
        return q;
    }

    void WriteSignal(const std::optional<Signal>& s)
    {
        if (!s) { std::cout << "null"; return; }
        std::cout << "{\"tick\":" << s->tick << ",\"result\":" << s->result << ",\"error\":"
                  << (s->result == WAIT_FAILED ? std::to_string(s->error) : "null") << '}';
    }

    void WritePin(const Pin& p)
    {
        std::cout << "{\"requested\":" << p.requested << ",\"id\":" << p.id << ",\"pid\":" << p.pid
                  << ",\"created\":\"" << p.created << "\",\"failure\":";
        if (p.failure) { std::cout << '"' << p.failure << '"'; }
        else { std::cout << "null"; }
        std::cout << ",\"error\":" << (p.failure ? std::to_string(p.error) : "null") << ",\"initial\":";
        WriteSignal(p.initial);
        std::cout << ",\"before\":";
        WriteSignal(p.before);
        std::cout << ",\"after\":";
        WriteSignal(p.after);
        std::cout << '}';
    }

    void WriteQuery(const std::optional<Query>& query)
    {
        if (!query) { std::cout << "null"; return; }
        const auto& q = *query;
        std::cout << "{\"start\":" << q.start << ",\"end\":" << q.end << ",\"ok\":" << (q.ok ? "true" : "false")
                  << ",\"error\":" << (q.ok ? "null" : std::to_string(q.error)) << ",\"reported\":" << q.count
                  << ",\"cycle\":" << (q.ok ? (q.cycle ? "true" : "false") : "null") << ",\"nodes\":[";
        for (DWORD i = 0; i < q.retained; ++i)
        {
            const auto& n = q.nodes[i];
            if (i) { std::cout << ','; }
            std::cout << "{\"type\":" << static_cast<DWORD>(n.ObjectType) << ",\"status\":" << static_cast<DWORD>(n.ObjectStatus);
            if (n.ObjectType == WctThreadType)
            {
                std::cout << ",\"pid\":" << n.ThreadObject.ProcessId << ",\"tid\":" << n.ThreadObject.ThreadId
                          << ",\"wait_time\":" << n.ThreadObject.WaitTime << ",\"context_switches\":" << n.ThreadObject.ContextSwitches;
            }
            std::cout << '}';
        }
        std::cout << "]}";
    }

    struct Source
    {
        DWORD pid, tid;
        uint64_t pc, tc;
        Pin process;
        std::vector<Pin> threads;
        Session session;
        bool attempted = false;
        DWORD sessionError = 0;
        std::optional<Query> discovery;

        Source(DWORD processId, uint64_t processTime, DWORD threadId, uint64_t threadTime)
            : pid(processId), tid(threadId), pc(processTime), tc(threadTime), process(OpenPin(pid, false))
        {
            if (!Bound(process, pid, pc, process.initial)) { return; }
            threads.emplace_back(OpenPin(tid, true));
            if (!Bound(threads.front(), pid, tc, threads.front().initial)) { return; }

            attempted = true;
            session.reset(OpenThreadWaitChainSession(0, nullptr));
            if (!session) { sessionError = GetLastError(); return; }
            discovery = ReadChain(session.get(), tid);
            for (DWORD i = 0; i < discovery->retained; ++i)
            {
                const auto& n = discovery->nodes[i];
                if (n.ObjectType != WctThreadType || n.ThreadObject.ProcessId != pid || !n.ThreadObject.ThreadId) { continue; }
                const auto owner = n.ThreadObject.ThreadId;
                if (std::none_of(threads.begin(), threads.end(), [owner](const Pin& p) { return p.requested == owner; }))
                {
                    threads.emplace_back(OpenPin(owner, true));
                }
            }
        }

        void Fence(std::optional<Signal> Pin::*member)
        {
            process.*member = Sample(process);
            for (auto& t : threads) { t.*member = Sample(t); }
        }

        bool Eligible() const
        {
            return session && Bound(process, pid, pc, process.before) && Bound(threads.front(), pid, tc, threads.front().before);
        }

        void Write(const std::optional<Query>& query) const
        {
            std::cout << "{\"schema\":\"kn.wait_chain.v1\",\"source\":\"windows_wct\",\"clock\":\"GetTickCount64_ms\",\"flags\":0"
                      << ",\"node_limit\":" << WCT_MAX_NODE_COUNT << ",\"requested\":{\"pid\":" << pid << ",\"process_created\":\"" << pc
                      << "\",\"tid\":" << tid << ",\"thread_created\":\"" << tc << "\"},\"process\":";
            WritePin(process);
            std::cout << ",\"threads\":[";
            for (size_t i = 0; i < threads.size(); ++i) { if (i) { std::cout << ','; } WritePin(threads[i]); }
            std::cout << "],\"session\":";
            if (!attempted) { std::cout << "null"; }
            else { std::cout << "{\"ok\":" << (session ? "true" : "false") << ",\"error\":" << (session ? "null" : std::to_string(sessionError)) << '}'; }
            std::cout << ",\"discovery\":";
            WriteQuery(discovery);
            std::cout << ",\"query\":";
            WriteQuery(query);
            std::cout << '}';
        }
    };

    struct PairWork
    {
        SYNCHRONIZATION_BARRIER barrier{};
        const Source& peer;
        std::optional<Query>& output;
    };

    void CALLBACK ReadPeer(PTP_CALLBACK_INSTANCE, void* context, PTP_WORK)
    {
        auto& job = *static_cast<PairWork*>(context);
        EnterSynchronizationBarrier(&job.barrier, 0);
        job.output = ReadChain(job.peer.session.get(), job.peer.tid, true);
    }

    struct Dispatch
    {
        const char* mode;
        const char* failure = nullptr;
        DWORD error = 0;
    };

    Dispatch ReadPair(const std::array<Source, 2>& sources, std::array<std::optional<Query>, 2>& out)
    {
        Dispatch dispatch{"single"};
        if (sources[0].Eligible() && sources[1].Eligible())
        {
            PairWork job{{}, sources[1], out[1]};
            // Nothing enters the barrier before both resources are available.
            PTP_WORK work = CreateThreadpoolWork(ReadPeer, &job, nullptr);
            if (!work) { dispatch = {"serial_fallback", "create_work", GetLastError()}; }
            else if (!InitializeSynchronizationBarrier(&job.barrier, 2, -1))
            {
                dispatch = {"serial_fallback", "initialize_barrier", GetLastError()};
                CloseThreadpoolWork(work);
            }
            else
            {
                SubmitThreadpoolWork(work);
                EnterSynchronizationBarrier(&job.barrier, 0);
                out[0] = ReadChain(sources[0].session.get(), sources[0].tid, true);
                WaitForThreadpoolWorkCallbacks(work, FALSE);
                CloseThreadpoolWork(work);
                DeleteSynchronizationBarrier(&job.barrier);
                return {"parallel"};
            }
        }
        for (size_t i = 0; i < sources.size(); ++i)
        {
            if (sources[i].Eligible()) { out[i] = ReadChain(sources[i].session.get(), sources[i].tid, true); }
        }
        return !out[0] && !out[1] ? Dispatch{"unavailable"} : dispatch;
    }

    void WriteCounter(const std::optional<ULONGLONG>& n)
    {
        if (n) { std::cout << '"' << *n << '"'; }
        else { std::cout << "null"; }
    }

    int WriteSeries(std::array<Source, 2>& sources, DWORD count, DWORD pauseMs)
    {
        LARGE_INTEGER frequency{};
        FILETIME birth{}, exitTime{}, kernel{}, user{};
        const BOOL identified = GetProcessTimes(GetCurrentProcess(), &birth, &exitTime, &kernel, &user);
        const ULONGLONG generation = (static_cast<ULONGLONG>(birth.dwHighDateTime) << 32) | birth.dwLowDateTime;
        std::cout << "{\"schema\":\"kn.wait_series.v1\",\"planned_rounds\":" << count << ",\"pause_ms\":" << pauseMs
                  << ",\"collector\":{\"pid\":" << GetCurrentProcessId() << ",\"created\":";
        WriteCounter(identified && generation ? std::optional<ULONGLONG>(generation) : std::nullopt);
        std::cout << ",\"coordinator_tid\":" << GetCurrentThreadId() << "},\"qpc_hz\":";
        if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0) { WriteCounter(frequency.QuadPart); }
        else { WriteCounter(std::nullopt); }
        std::cout << ",\"rounds\":[\n";

        HANDLE waitTarget = nullptr;
        for (DWORD round = 0; round < count; ++round)
        {
            if (round) { std::cout << ','; }
            std::cout << "{\"pause\":";
            if (waitTarget)
            {
                const auto start = GetTickCount64();
                const DWORD result = WaitForSingleObject(waitTarget, pauseMs);
                const DWORD error = result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
                std::cout << "{\"start\":" << start << ",\"signal\":";
                WriteSignal(Signal{result, error, GetTickCount64()});
                std::cout << '}';
            }
            else { std::cout << "null"; }

            for (auto& source : sources) { source.Fence(&Pin::before); }
            std::array<std::optional<Query>, 2> results;
            const auto begin = Counter();
            const Dispatch dispatch = ReadPair(sources, results);
            const auto end = Counter();
            for (auto& source : sources) { source.Fence(&Pin::after); }

            std::cout << ",\"begin_qpc\":";
            WriteCounter(begin);
            std::cout << ",\"end_qpc\":";
            WriteCounter(end);
            std::cout << ",\"dispatch\":\"" << dispatch.mode << "\",\"failure\":";
            if (dispatch.failure) { std::cout << "{\"stage\":\"" << dispatch.failure << "\",\"win32_error\":" << dispatch.error << '}'; }
            else { std::cout << "null"; }
            std::cout << ",\"views\":[";
            for (size_t i = 0; i < sources.size(); ++i)
            {
                if (i) { std::cout << ','; }
                std::cout << "{\"timing\":";
                if (results[i])
                {
                    const auto& q = *results[i];
                    std::cout << "{\"reader_tid\":" << q.reader << ",\"begin\":";
                    WriteCounter(q.beginQpc);
                    std::cout << ",\"end\":";
                    WriteCounter(q.endQpc);
                    std::cout << '}';
                }
                else { std::cout << "null"; }
                std::cout << ",\"receipt\":";
                sources[i].Write(results[i]);
                std::cout << '}';
            }
            std::cout << "]}\n" << std::flush;
            if (!std::cout) { return 1; }
            if (!results[0] && !results[1]) { break; }
            waitTarget = sources[results[0] ? 0 : 1].process.handle.get();
        }
        std::cout << "]}\n" << std::flush;
        return std::cout ? 0 : 1;
    }

    bool Decimal(const std::wstring& arg, uint64_t max, uint64_t* out)
    {
        return commandinput::ParseDigits(arg, 10, out) && *out && *out <= max;
    }
}

int RunWaitChainCapture(const std::vector<std::wstring>& args)
{
    const bool series = args.size() == 9 && args[4] == L"--corroborate";
    uint64_t pid = 0, pc = 0, tid = 0, tc = 0, peer = 0, peerTime = 0, count = 0, pause = 0;
    if ((!series && args.size() != 4) || !Decimal(args[0], MAXDWORD, &pid) || !Decimal(args[1], UINT64_MAX, &pc) ||
        !Decimal(args[2], MAXDWORD, &tid) || !Decimal(args[3], UINT64_MAX, &tc) ||
        (series && (!Decimal(args[5], MAXDWORD, &peer) || peer == tid || !Decimal(args[6], UINT64_MAX, &peerTime) ||
                    !Decimal(args[7], 8, &count) || count < 2 || !Decimal(args[8], 5000, &pause))))
    {
        std::cerr << "usage: --wait-chain <pid> <process-creation-filetime> <tid> <thread-creation-filetime>"
                     " [--corroborate <peer-tid> <peer-creation-filetime> <rounds 2..8> <pause-ms 1..5000>] (decimal)\n";
        return 2;
    }
    Source first(static_cast<DWORD>(pid), pc, static_cast<DWORD>(tid), tc);
    if (series)
    {
        std::array<Source, 2> sources{std::move(first), Source(static_cast<DWORD>(pid), pc, static_cast<DWORD>(peer), peerTime)};
        return WriteSeries(sources, static_cast<DWORD>(count), static_cast<DWORD>(pause));
    }
    first.Fence(&Pin::before);
    std::optional<Query> query;
    if (first.Eligible()) { query = ReadChain(first.session.get(), first.tid); }
    first.Fence(&Pin::after);
    first.Write(query);
    std::cout << '\n' << std::flush;
    return std::cout ? 0 : 1;
}
