#include "../user/IrpRetentionPolicy.h"
#include <atomic>
#include <cstdio>
#include <iostream>
#include <thread>

namespace
{
    unsigned Checks = 0, Failures = 0;
    void Check(bool ok, const char* name)
    {
        ++Checks;
        if (!ok) { ++Failures; std::fprintf(stderr, "[irp.retention] FAIL %s\n", name); }
    }
    IrpRetentionRequest State(wchar_t value) { return {{std::wstring(64, value)}, false, false}; }
    struct Work { unsigned Id = 0; std::shared_ptr<IrpRetentionPolicy::Ticket> Retention; };
}

int main()
{
    using C = IrpRetentionClass;
    using S = IrpRetentionStream;
    constexpr auto M = IrpRetentionPolicy::MiB;
    const IrpRetentionRequest gap{}, routine{{}, false, false}, unkeyed{{}, true, true};
    {
        IrpRetentionPolicy policy;
        IrpRetentionQueue<Work> queue;
        std::vector<std::shared_ptr<IrpRetentionPolicy::Ticket>> held;
        Check(!queue.Push({0, std::make_shared<IrpRetentionPolicy::Ticket>()}), "unarmed-ticket-rejected");
        for (unsigned i = 0; i < 4; ++i)
        {
            auto ticket = policy.Acquire(i < 2 ? unkeyed : i == 2 ? gap : routine, 1);
            Check(ticket && queue.Push({i + 1, ticket}), "separate-class-capacity");
            held.push_back(std::move(ticket));
        }
        for (const auto& request : {unkeyed, gap, routine}) { Check(!policy.Acquire(request, 1), "no-cross-class-slot-borrowing"); }
        for (unsigned expected : {1u, 3u, 4u, 2u})
        {
            Work work;
            Check(queue.Pop(&work) && work.Id == expected, "round-robin-service-for-all-lanes");
            work.Retention->Finish(true);
        }
        Check(queue.Size() == 0 && policy.MemoryHeld() == 4 && !policy.Acquire(routine, 0), "writer-held-ticket-retains-slot-and-bytes");
        held.clear();
        Check(policy.MemoryHeld() == 0 && policy.Acquire(routine, 80 * M), "last-owner-releases-entire-artifact-charge");
    }
    {
        IrpRetentionPolicy policy(IrpRetentionPolicy::DefaultLimits(), 1);
        auto first = policy.Acquire(State(L'a'), 0);
        auto pending = policy.Acquire(State(L'a'), 0);
        Check(first && first->Class() == C::FirstState && pending && pending->Class() == C::Routine, "pending-identical-state-does-not-occupy-another-first-slot");
        first->Finish(false); first.reset(); pending->Finish(false); pending.reset();
        first = policy.Acquire(State(L'a'), 0);
        Check(first && first->Class() == C::FirstState, "failed-capture-reference-or-journal-keeps-first-priority");
        first->Finish(true); first->Finish(false); first.reset();
        pending = policy.Acquire(State(L'a'), 0);
        Check(pending && pending->Class() == C::Routine, "complete-publication-demotes-identical-state");
        pending.reset();
        Check(!policy.Acquire(State(L'b'), 0), "key-pressure-denies-without-false-repeat-demotion");
        auto unknown = policy.Acquire(unkeyed, 0);
        Check(unknown && unknown->Class() == C::FirstState, "unkeyed-state-does-not-join-saved-keys");
        Check(!policy.Acquire(State(L'z'), 0), "invalid-state-key-rejected");
        auto excessive = State(L'a'); excessive.StateKeys.resize(257, excessive.StateKeys[0]);
        Check(!policy.Acquire(excessive, 0), "key-input-bound-precedes-sort-dedup");
        IrpRetentionPolicy fresh;
        auto next = fresh.Acquire(State(L'a'), 0);
        Check(next && next->Class() == C::FirstState, "saved-state-does-not-cross-session");
    }
    {
        IrpRetentionPolicy policy;
        std::atomic<bool> start{false};
        std::vector<std::thread> workers;
        for (unsigned i = 0; i < 9; ++i)
        {
            workers.emplace_back([&, i]
            {
                while (!start.load()) { std::this_thread::yield(); }
                for (unsigned j = 0; j < 1000; ++j)
                {
                    auto ticket = policy.Acquire(i % 3 == 0 ? unkeyed : i % 3 == 1 ? gap : routine, 1);
                    if (ticket) { ticket->Finish(j % 2 == 0); }
                }
            });
        }
        start.store(true);
        for (auto& worker : workers) { worker.join(); }
        Check(policy.MemoryHeld() == 0, "concurrent-admission-drains-all-reservations");
        std::wcout << L"{\"concurrent\":" << policy.Json() << L"}\n";
    }
    IrpRetentionPolicy accounting;
    auto first = accounting.Acquire(State(L'a'), 80 * M);
    auto ordinary = accounting.Acquire(routine, 80 * M);
    auto failure = accounting.Acquire(gap, 80 * M);
    Check(first && ordinary && failure && accounting.MemoryHeld() == 240 * M, "all-lanes-can-retain-maximum-artifact-independently");
    Check(!accounting.Acquire(State(L'b'), 1) && !accounting.Acquire(routine, 1) && !accounting.Acquire(gap, 1), "bounded-memory-and-slots-without-borrowing");
    first->Finish(true); ordinary->Finish(false); failure->Finish(true);
    first.reset(); ordinary.reset(); failure.reset();
    ordinary = accounting.Acquire(State(L'a'), 0); ordinary->Finish(true); ordinary.reset();
    { auto abandoned = accounting.Acquire(State(L'b'), 0); }
    accounting.RecordUnavailable(); accounting.RecordUnavailable(true);
    Check(accounting.Consume(C::FirstState, S::Capture, 17) && accounting.Consume(C::FirstState, S::Reference, 64 * M), "charge-successful-physical-files");
    Check(accounting.Consume(C::Routine, S::Capture, 32 * M) && !accounting.Consume(C::Routine, S::Capture, 1), "routine-cannot-borrow-first-or-gap-file-budget");
    Check(accounting.Remaining(C::ObservationGap, S::Capture) == 32 * M && accounting.Remaining(C::FirstState, S::Capture) == 64 * M - 17,
        "first-and-gap-file-reserves-survive-routine-exhaustion");
    std::wcout << L"{\"accounting\":" << accounting.Json() << L"}\n";
    std::fprintf(stderr, "[irp.retention] checks=%u failed=%u\n", Checks, Failures);
    return Failures ? 1 : 0;
}
