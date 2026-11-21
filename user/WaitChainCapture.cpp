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

    struct Query
    {
        std::array<WAITCHAIN_NODE_INFO, WCT_MAX_NODE_COUNT> nodes{};
        DWORD count = WCT_MAX_NODE_COUNT, retained = 0, error = 0;
        bool ok = false;
        BOOL cycle = FALSE;
        ULONGLONG start = 0, end = 0;
    };

    Query ReadChain(HWCT session, DWORD tid)
    {
        Query q;
        q.start = GetTickCount64();
        q.ok = GetThreadWaitChain(session, 0, 0, tid, &q.count, q.nodes.data(), &q.cycle) != FALSE;
        if (!q.ok) { q.error = GetLastError(); }
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
}

int RunWaitChainCapture(const std::vector<std::wstring>& args)
{
    uint64_t pid64 = 0, pc = 0, tid64 = 0, tc = 0;
    if (args.size() != 4 || !commandinput::ParseDigits(args[0], 10, &pid64) || !pid64 || pid64 > MAXDWORD ||
        !commandinput::ParseDigits(args[1], 10, &pc) || !pc || !commandinput::ParseDigits(args[2], 10, &tid64) ||
        !tid64 || tid64 > MAXDWORD || !commandinput::ParseDigits(args[3], 10, &tc) || !tc)
    {
        std::cerr << "usage: --wait-chain <pid> <process-creation-filetime> <tid> <thread-creation-filetime> (decimal)\n";
        return 2;
    }
    const auto pid = static_cast<DWORD>(pid64), tid = static_cast<DWORD>(tid64);
    Pin process = OpenPin(pid, false);
    std::vector<Pin> threads;
    Session session;
    bool attempted = false;
    DWORD sessionError = 0;
    std::optional<Query> discovery, query;
    if (Bound(process, pid, pc, process.initial))
    {
        threads.emplace_back(OpenPin(tid, true));
        if (Bound(threads.front(), pid, tc, threads.front().initial))
        {
            attempted = true;
            session.reset(OpenThreadWaitChainSession(0, nullptr));
            if (!session) { sessionError = GetLastError(); }
            else
            {
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
        }
    }
    process.before = Sample(process);
    for (auto& t : threads) { t.before = Sample(t); }
    if (session && Bound(process, pid, pc, process.before) && Bound(threads.front(), pid, tc, threads.front().before))
    {
        query = ReadChain(session.get(), tid);
    }
    process.after = Sample(process);
    for (auto& t : threads) { t.after = Sample(t); }

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
    std::cout << "}\n";
    std::cout.flush();
    return std::cout ? 0 : 1;
}
