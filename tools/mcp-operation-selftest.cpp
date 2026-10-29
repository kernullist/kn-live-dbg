#include "../user/McpOperation.h"
#include <atomic>
#include <iostream>
#include <thread>

namespace
{
    unsigned Checks = 0;
    unsigned Failures = 0;

    void Check(bool ok, const char* name)
    {
        ++Checks;
        if (!ok)
        {
            ++Failures;
            std::cerr << "FAIL " << name << "\n";
        }
    }

    std::wstring Id(unsigned number)
    {
        wchar_t value[33] = {};
        swprintf_s(value, L"%032x", number);
        return value;
    }

    void Emit(const McpOperationLedger& ledger, unsigned number)
    {
        McpOperationSnapshot snapshot;
        Check(ledger.Get(Id(number), &snapshot), "emitted-record-exists");
        std::cout << mcpjson::WideToUtf8(McpOperationJson(snapshot)) << "\n";
    }
}

int main()
{
    McpOperationLedger ledger;
    Check(!ledger.Begin(L"x", L"fixture", 1) && !ledger.Begin(Id(1), L"", 1) &&
        !ledger.Begin(Id(1), std::wstring(513, L'x'), 1), "reject-invalid-admission");
    Check(ledger.Begin(Id(1), L"fixture.cancel", 10), "admit-queued");
    Emit(ledger, 1);
    Check(!ledger.Begin(Id(1), L"fixture.duplicate", 11), "duplicate-id-never-readmitted");
    Check(!ledger.Complete(Id(1), false, false, 12), "never-complete-undispatched");
    Check(ledger.CancelQueued(Id(1), 20) && !ledger.Start(Id(1), 21), "cancel-before-dispatch");
    Emit(ledger, 1);

    Check(ledger.Begin(Id(2), L"fixture.late", 30) && ledger.Start(Id(2), 31), "start-operation");
    Emit(ledger, 2);
    Check(!ledger.CancelQueued(Id(2), 32) && !ledger.Start(Id(2), 32), "running-cannot-be-cancelled-or-started-again");
    ledger.WaitEnded(Id(2));
    Emit(ledger, 2);
    Check(ledger.Complete(Id(2), false, false, 40), "late-success");
    ledger.WaitEnded(Id(2));
    Check(!ledger.Complete(Id(2), true, true, 41), "duplicate-completion-ignored");
    Emit(ledger, 2);

    Check(ledger.Begin(Id(3), L"fixture.failed", 50) && ledger.Start(Id(3), 51) &&
        ledger.Complete(Id(3), true, false, 60), "reported-engine-failure");
    Emit(ledger, 3);
    Check(ledger.Begin(Id(4), L"fixture.exception", 70) && ledger.Start(Id(4), 71) &&
        ledger.Complete(Id(4), true, true, 80), "exception-remains-unknown-after-engine-finished");
    Emit(ledger, 4);

    // Keep an old running job while recycling every finished record. A
    // timeout must not make the old job eligible for eviction.
    Check(ledger.Begin(Id(5), L"fixture.active", 90) && ledger.Start(Id(5), 91), "retention-active-admitted");
    ledger.WaitEnded(Id(5));
    bool retentionOk = true;
    for (unsigned index = 6; index < 800; ++index)
    {
        retentionOk = ledger.Begin(Id(index), L"fixture.retention", 100 + index) &&
            ledger.CancelQueued(Id(index), 100 + index) && retentionOk;
    }
    McpOperationSnapshot snapshot;
    Check(retentionOk && ledger.Get(Id(5), &snapshot) && snapshot.State == L"unknown_outcome" &&
        !snapshot.Finished && !ledger.Get(Id(1), &snapshot) && ledger.Get(Id(799), &snapshot),
        "bounded-retention-preserves-active-and-replaces-oldest-finished");
    Check(ledger.Complete(Id(5), true, false, 1000), "old-active-job-can-still-complete");

    ledger.Reset();
    Check(!ledger.Get(Id(799), &snapshot), "restart-forgets-previous-metadata");
    bool fullOk = true;
    for (unsigned index = 0; index < McpOperationLedger::Capacity; ++index)
    {
        fullOk = ledger.Begin(Id(index), L"fixture.capacity", 1) && fullOk;
    }
    Check(fullOk && !ledger.Begin(Id(900), L"fixture.rejected", 2), "all-active-capacity-denies-new-work");
    Check(ledger.CancelQueued(Id(100), 3) && ledger.Begin(Id(900), L"fixture.new", 4) &&
        !ledger.Get(Id(100), &snapshot) && ledger.Get(Id(0), &snapshot), "only-finished-slot-can-be-reused");

    // Release both transitions together. Either ordering must preserve the
    // engine's final failure; waiter timeout cannot downgrade it afterwards.
    bool racesOk = true;
    for (unsigned iteration = 0; iteration < 128; ++iteration)
    {
        ledger.Reset();
        racesOk = ledger.Begin(Id(1), L"fixture.race", 1) && ledger.Start(Id(1), 2) && racesOk;
        std::atomic<bool> start{false};
        std::thread waiter([&]()
        {
            while (!start.load())
            {
                std::this_thread::yield();
            }
            ledger.WaitEnded(Id(1));
        });
        std::thread engine([&]()
        {
            while (!start.load())
            {
                std::this_thread::yield();
            }
            ledger.Complete(Id(1), true, false, 3);
        });
        start.store(true);
        waiter.join();
        engine.join();
        racesOk = ledger.Get(Id(1), &snapshot) && snapshot.Finished && snapshot.State == L"failed" && racesOk;
    }
    Check(racesOk, "completion-versus-timeout-race-preserves-final-state");
    std::cerr << "mcp operation controls: " << Checks << " checks, " << Failures << " failures\n";
    return Failures == 0 ? 0 : 1;
}
