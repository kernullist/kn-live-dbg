#include "../user/ImageRetentionPolicy.h"
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
        if (!ok) { ++Failures; std::fprintf(stderr, "[retention.selftest] FAIL %s\n", name); }
    }
    ImageRetentionRequest Difference(wchar_t value)
    {
        ImageRetentionRequest r; r.DifferenceKeys.push_back(std::wstring(64, value)); return r;
    }
    struct Work { unsigned Id = 0; std::shared_ptr<ImageRetentionPolicy::Ticket> Retention; };
}
int main()
{
    using C = ImageRetentionClass;
    using S = ImageRetentionStream;
    constexpr auto M = ImageRetentionPolicy::MiB;
    const ImageRetentionRequest gap{{}, true, false}, unknown{{}, false, true};
    {
        ImageRetentionPolicy policy;
        ImageRetentionQueue<Work> queue;
        std::vector<std::shared_ptr<ImageRetentionPolicy::Ticket>> tickets;
        for (unsigned i = 0; i < 8; ++i)
        {
            auto t = policy.Acquire(i < 4 ? unknown : i < 6 ? gap : ImageRetentionRequest{}, 0);
            Check(t != nullptr && queue.Push({i + 1, t}), "independent-class-slot");
            tickets.push_back(std::move(t));
        }
        for (const auto& r : {unknown, gap, ImageRetentionRequest{}})
            { Check(!policy.Acquire(r, 0), "full-class-rejected-without-eviction"); }
        for (unsigned expected : {1u, 5u, 7u, 2u, 6u, 8u, 3u, 4u})
        {
            Work out;
            Check(queue.Pop(&out) && out.Id == expected, "round-robin-does-not-starve-gap-or-routine");
            out.Retention->Finish(true);
        }
        Check(queue.Size() == 0 && !policy.Acquire({}, 0), "in-flight-holder-keeps-reservation-after-pop");
        tickets.clear();
        { auto temporary = policy.Acquire({}, 64 * M); Check(temporary != nullptr, "released-slot-admits-next-reference"); }
        Check(policy.ReferenceHeld() == 0, "last-owner-releases-reservation");
    }
    {
        ImageRetentionPolicy policy(ImageRetentionPolicy::DefaultLimits(), 1);
        auto first = policy.Acquire(Difference(L'a'), 1);
        auto pending = policy.Acquire(Difference(L'a'), 2);
        Check(first && first->Class == C::FirstDifference && pending && pending->Class == C::Routine, "pending-repeat-is-not-another-first");
        first->Finish(false); first.reset();
        pending->Finish(false); pending.reset();
        first = policy.Acquire(Difference(L'a'), 0);
        Check(first && first->Class == C::FirstDifference, "failed-original-retries-with-first-priority");
        first->Finish(true); first->Finish(false); first.reset();
        Check(!policy.Acquire(Difference(L'b'), 0), "saved-key-capacity-denies-new-keys-without-demotion");
        auto repeat = policy.Acquire(Difference(L'a'), 0);
        Check(repeat && repeat->Class == C::Routine, "complete-key-selects-repeat-class");
        Check(policy.Acquire(unknown, 0) != nullptr, "unknown-identity-does-not-join-saved-key");
        auto invalid = Difference(L'z');
        Check(!policy.Acquire(invalid, 0), "invalid-key-rejected");
    }
    {
        ImageRetentionPolicy policy;
        std::atomic<bool> start{false};
        std::vector<std::thread> workers;
        for (unsigned i = 0; i < 9; ++i)
        {
            workers.emplace_back([&, i]
            {
                while (!start.load()) { std::this_thread::yield(); }
                for (unsigned j = 0; j < 1000; ++j)
                {
                    auto ticket = policy.Acquire(i % 3 == 0 ? unknown : i % 3 == 1 ? gap : ImageRetentionRequest{}, 1);
                    if (ticket) { ticket->Finish(j % 2 == 0); }
                }
            });
        }
        start.store(true);
        for (auto& thread : workers) { thread.join(); }
        Check(policy.ReferenceHeld() == 0, "concurrent-admission-releases-all-reference-charges");
        std::wcout << L"{\"concurrent\":" << policy.Json() << L"}\n";
    }
    ImageRetentionPolicy accounting;
    auto first = accounting.Acquire(Difference(L'a'), 64 * M);
    auto ordinary = accounting.Acquire({}, 64 * M);
    auto failure = accounting.Acquire(gap, 64 * M);
    Check(first && ordinary && failure && accounting.ReferenceHeld() == 192 * M, "each-class-can-retain-one-largest-reference");
    Check(!accounting.Acquire(Difference(L'b'), 1) && !accounting.Acquire({}, 1) && !accounting.Acquire(gap, 1), "reference-pressure-does-not-borrow-another-class");
    first->Finish(true); ordinary->Finish(false); failure->Finish(true);
    first.reset(); ordinary.reset(); failure.reset();
    ordinary = accounting.Acquire(Difference(L'a'), 0); ordinary->Finish(true); ordinary.reset();
    { auto abandoned = accounting.Acquire(Difference(L'b'), 0); }
    Check(accounting.Consume(C::FirstDifference, S::Reads, 17) && accounting.Consume(C::FirstDifference, S::Reference, 64 * M), "charge-successful-named-bytes");
    Check(accounting.Consume(C::Routine, S::Reads, 32 * M) && !accounting.Consume(C::Routine, S::Reads, 1), "partition-disk-boundary");
    Check(accounting.Remaining(C::ObservationGap, S::Reads) == 32 * M && accounting.Remaining(C::FirstDifference, S::Recipe) == 64 * M,
        "other-streams-and-classes-retain-their-reserve");
    std::wcout << L"{\"accounting\":" << accounting.Json() << L"}\n";
    std::fprintf(stderr, "[retention.selftest] checks=%u failed=%u\n", Checks, Failures);
    return Failures == 0 ? 0 : 1;
}
