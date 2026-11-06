#include "../user/ProcessObservationSource.h"
#include "../user/ReadReceiptJson.h"
#include <future>
#include <iostream>
#include <thread>

namespace
{
    unsigned Checks = 0, Failures = 0;
    void Check(bool value, const char* name)
    {
        ++Checks;
        if (!value) { ++Failures; std::cerr << "FAIL " << name << "\n"; }
    }

    class Source final : public IObservationSource
    {
    public:
        ObservationSourceCapabilities Caps;
        std::atomic<unsigned> Calls{0};
        std::function<ObservationReadResult(const ObservationReadRequest&)> Action;
        explicit Source(const wchar_t* id = L"synthetic:primary")
        {
            Caps.SourceId = id;
            Caps.Consistency = L"single_read";
            Action = [](const auto& request)
            {
                ObservationReadResult result;
                result.NativeStatusDomain = L"ntstatus";
                result.NativeStatus = 0;
                result.Spans.push_back({request.Address, request.Length, ObservationReadState::Complete,
                    std::vector<uint8_t>(request.Length, 0x51)});
                return result;
            };
        }
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
        {
            ++Calls;
            return Action(request);
        }
    };

    auto Operation(const wchar_t* id, ObservationOperationBudget budget = {}, ObservationReadOperation::Clock clock = {})
    {
        return clock ? std::make_shared<ObservationReadOperation>(id, L"synthetic:target", L"synthetic:as", budget, clock) :
            std::make_shared<ObservationReadOperation>(id, L"synthetic:target", L"synthetic:as", budget);
    }

    ObservationReadRequest Request(const IObservationSource& source, uint64_t address = 0x11000, uint32_t size = 32)
    {
        ObservationReadRequest request;
        request.SourceId = source.Capabilities().SourceId;
        request.Address = address;
        request.Length = size;
        request.ByteBudget = size;
        return request;
    }

    void Emit(const std::shared_ptr<ObservationReadOperation>& operation)
    {
        std::cout << mcpjson::WideToUtf8(ObservationReadSetJson(operation->Snapshot())) << "\n";
    }
}

int main()
{
    Source source;
    auto operation = Operation(L"admission");
    RecordingObservationSource recorded(source, operation);
    auto request = Request(recorded);
    auto read = recorded.Read(request);
    Check(read.State == ObservationReadState::Complete && read.ReadReceiptId == 1 && read.OperationId == L"admission",
        "successful-read-gets-operation-sequence");
    request.SourceId = L"wrong:source";
    Check(recorded.Read(request).State == ObservationReadState::IdentityChanged, "source-mismatch-receipt");
    request = Request(recorded);
    request.ByteBudget = 31;
    Check(recorded.Read(request).State == ObservationReadState::BudgetDeferred, "per-read-budget-receipt");
    request = Request(recorded);
    request.Length = 4097;
    Check(recorded.Read(request).State == ObservationReadState::Unsupported, "oversize-receipt-without-provider");
    request = Request(recorded);
    request.Address = UINT64_MAX - 16;
    Check(recorded.Read(request).State == ObservationReadState::Unsupported, "overflow-receipt");
    request = Request(recorded);
    source.Caps.MayChangeResidency = true;
    Check(recorded.Read(request).State == ObservationReadState::PolicyDenied, "residency-policy-receipt");
    std::atomic<bool> cancel{true};
    request.Cancellation = &cancel;
    Check(recorded.Read(request).State == ObservationReadState::Cancelled, "cancellation-receipt");
    const auto admitted = operation->Snapshot();
    Check(admitted.TotalAttempts == 7 && admitted.Reads.size() == 7 && source.Calls == 1 &&
        admitted.ChargedSourceCalls == 1 && admitted.ChargedBytes == 32, "denied-attempts-preserved-without-source-charge");
    Check(admitted.Reads.back().Request.Cancellation == nullptr, "receipt-does-not-retain-caller-cancellation-pointer");
    Emit(operation);
    source.Caps.MayChangeResidency = false;

    operation = Operation(L"partial-and-fallback");
    RecordingObservationSource primary(source, operation);
    Source secondary(L"synthetic:secondary");
    RecordingObservationSource fallback(secondary, operation);
    source.Action = [](const auto& item)
    {
        ObservationReadResult result;
        result.NativeStatusDomain = L"ntstatus";
        result.NativeStatus = 0x8000000d; // Synthetic STATUS_PARTIAL_COPY control.
        result.Spans = {{item.Address, item.Length / 2, ObservationReadState::Complete, std::vector<uint8_t>(item.Length / 2, 0x41)},
            {item.Address + item.Length / 2, item.Length - item.Length / 2, ObservationReadState::Failed, {}}};
        return result;
    };
    std::vector<uint8_t> bytes{1};
    Check(!ReadObservationExact(primary, 0x11000, 32, &bytes) && bytes.empty(), "partial-never-enters-parser");
    auto sparse = operation->Snapshot();
    Check(sparse.Reads[0].Result.State == ObservationReadState::Partial && sparse.Reads[0].Result.Spans[0].Bytes.size() == 16 &&
        sparse.Reads[0].Result.NativeStatus == 0x8000000d, "partial-and-native-error-remain-recorded");
    request = Request(fallback);
    request.FallbackFromReceipt = 1;
    request.FallbackReason = L"explicit_alternate_source";
    Check(fallback.Read(request).State == ObservationReadState::PolicyDenied && secondary.Calls == 0,
        "fallback-requires-explicit-permission");
    request.AllowFallback = true;
    read = fallback.Read(request);
    Check(read.State == ObservationReadState::Complete && read.SourceId == secondary.Caps.SourceId &&
        operation->Snapshot().Reads[2].FallbackPermitted, "fallback-links-failed-attempt-and-keeps-actual-source");
    request.FallbackFromReceipt = read.ReadReceiptId;
    Check(fallback.Read(request).State == ObservationReadState::PolicyDenied, "complete-or-same-source-is-not-fallback");
    request.FallbackFromReceipt = 1;
    request.Address += 16;
    Check(fallback.Read(request).State == ObservationReadState::PolicyDenied, "fallback-must-match-original-range");
    request.Address -= 16;
    request.FallbackFromReceipt = 999;
    Check(fallback.Read(request).State == ObservationReadState::PolicyDenied, "unknown-fallback-receipt-denied");
    Emit(operation);

    ObservationOperationBudget budget;
    budget.MaximumBytes = 64;
    budget.MaximumSourceCalls = 2;
    operation = Operation(L"shared-budget", budget);
    RecordingObservationSource failedSource(source, operation), otherSource(secondary, operation);
    Check(!ReadObservationExact(failedSource, 0x11000, 32, &bytes), "failed-attempt-consumes-budget");
    Check(ReadObservationExact(otherSource, 0x11000, 32, &bytes), "other-source-shares-remaining-budget");
    request = Request(otherSource);
    request.ByteBudget = UINT64_MAX;
    Check(otherSource.Read(request).State == ObservationReadState::BudgetDeferred &&
        operation->Snapshot().ChargedBytes == 64, "fresh-per-read-budget-cannot-reset-operation-budget");
    Emit(operation);

    budget.MaximumBytes = 0x10000;
    budget.MaximumSourceCalls = 1;
    operation = Operation(L"range-budget", budget);
    RecordingObservationSource range(secondary, operation);
    Check(!ReadObservationRange(range, 0x11000, 8192, &bytes, 8192) && bytes.empty(),
        "later-operation-denial-discards-parser-assembly");
    const auto chunks = operation->Snapshot();
    Check(chunks.Reads.size() == 2 && chunks.Reads[0].Result.Spans[0].Bytes.size() == 4096 &&
        chunks.Reads[1].Result.State == ObservationReadState::BudgetDeferred, "earlier-chunk-survives-parser-rejection");
    Emit(operation);

    budget.MaximumSourceCalls = 10;
    budget.MaximumReceipts = 2;
    operation = Operation(L"receipt-capacity", budget);
    RecordingObservationSource bounded(secondary, operation);
    request = Request(bounded);
    bounded.Read(request);
    bounded.Read(request);
    const auto beforeOverflow = secondary.Calls.load();
    Check(bounded.Read(request).State == ObservationReadState::BudgetDeferred && secondary.Calls == beforeOverflow,
        "receipt-capacity-stops-unrecorded-source-work");
    Check(operation->Snapshot().UnrecordedAttempts == 1 && operation->Snapshot().TotalAttempts == 3,
        "receipt-overflow-has-explicit-gap-denominator");
    Emit(operation);

    budget = {};
    budget.MaximumStoredSpans = 8;
    operation = Operation(L"span-budget", budget);
    Source fragmented;
    fragmented.Action = [](const auto& item)
    {
        ObservationReadResult result;
        for (uint32_t i = 0; i < item.Length; ++i)
        {
            result.Spans.push_back({item.Address + i, 1, ObservationReadState::Complete, {0x51}});
        }
        return result;
    };
    RecordingObservationSource fragments(fragmented, operation);
    Check(ReadObservationExact(fragments, 0x11000, 8, &bytes), "bounded-sparse-span-control");
    Check(fragments.Read(Request(fragments, 0x11000, 1)).State == ObservationReadState::BudgetDeferred &&
        fragmented.Calls == 1 && operation->Snapshot().StoredSpans == 8 && operation->Snapshot().ReservedSpanSlots == 0,
        "metadata-budget-prevents-unbounded-sparse-storage");
    Emit(operation);

    uint64_t now = 100;
    budget = {};
    budget.MaximumElapsedMs = 10;
    operation = Operation(L"deadline", budget, [&] { return now; });
    RecordingObservationSource timed(secondary, operation);
    secondary.Action = [&](const auto& item)
    {
        now = 111;
        ObservationReadResult result;
        result.Spans.push_back({item.Address, item.Length, ObservationReadState::Complete, std::vector<uint8_t>(item.Length, 0x51)});
        return result;
    };
    request = Request(timed);
    Check(timed.Read(request).State == ObservationReadState::Complete && operation->Snapshot().Reads[0].DeadlineExceeded,
        "in-flight-read-is-not-pretended-interruptible");
    Check(timed.Read(request).State == ObservationReadState::BudgetDeferred, "elapsed-parser-source-time-blocks-next-read");
    now = 99;
    Check(timed.Read(request).State == ObservationReadState::BudgetDeferred, "backwards-clock-does-not-reset-budget");
    Emit(operation);

    operation = Operation(L"cancel-during-read");
    RecordingObservationSource cancelling(secondary, operation);
    secondary.Action = [&](const auto& item)
    {
        operation->Cancel();
        ObservationReadResult result;
        result.Spans.push_back({item.Address, item.Length, ObservationReadState::Complete, std::vector<uint8_t>(item.Length, 0x51)});
        return result;
    };
    Check(!ReadObservationExact(cancelling, 0x11000, 32, &bytes) && bytes.empty(), "operation-cancellation-stops-parser-consumption");
    const auto cancelled = operation->Snapshot();
    Check(cancelled.Reads[0].Result.State == ObservationReadState::Complete && cancelled.Reads[0].Result.CancellationObserved &&
        cancelled.Reads[0].Result.Spans[0].Bytes.size() == 32, "cancel-keeps-original-complete-receipt");
    Check(cancelling.Read(Request(cancelling)).State == ObservationReadState::Cancelled, "cancelled-operation-denies-further-reads");
    Emit(operation);

    for (bool replace : {false, true})
    {
        Source bad;
        operation = Operation(replace ? L"source-replaced" : L"malformed");
        RecordingObservationSource checked(bad, operation);
        bad.Action = [&](const auto& item)
        {
            ObservationReadResult result;
            result.NativeStatusDomain = L"win32";
            result.NativeStatus = 299;
            result.Spans.push_back({item.Address, item.Length, ObservationReadState::Complete, {0x51}});
            if (replace) { bad.Caps.SourceId = L"synthetic:replacement"; }
            return result;
        };
        read = checked.Read(Request(checked));
        Check(read.State == (replace ? ObservationReadState::IdentityChanged : ObservationReadState::Failed) && read.Spans.empty() &&
            read.NativeStatusDomain == L"win32" && read.NativeStatus == 299 && !read.ValidationReason.empty(),
            "rejected-byte-view-retains-original-status-and-validation-reason");
        Emit(operation);
    }

    Source denied;
    operation = Operation(L"delegated-denial");
    RecordingObservationSource nested(denied, operation);
    denied.Action = [](const auto&)
    {
        ObservationReadResult result;
        result.State = ObservationReadState::PolicyDenied;
        result.NativeStatusDomain = L"hresult";
        result.NativeStatus = 0x80070005;
        return result;
    };
    read = nested.Read(Request(nested));
    Check(read.State == ObservationReadState::PolicyDenied && read.NativeStatus == 0x80070005 && read.Spans.empty(),
        "delegated-empty-denial-is-not-rewritten");

    Source throwing;
    operation = Operation(L"abandoned");
    RecordingObservationSource exception(throwing, operation);
    throwing.Action = [](const auto&) -> ObservationReadResult { throw std::runtime_error("synthetic"); };
    try { exception.Read(Request(exception)); Check(false, "exception-must-propagate"); }
    catch (const std::runtime_error&) { Check(true, "source-exception-propagates"); }
    Check(operation->Snapshot().Reads[0].Abandoned && !operation->Snapshot().Reads[0].Completed,
        "unwinding-keeps-abandoned-attempt-without-success");
    Check(operation->Snapshot().ReservedSpanSlots == 0, "unwinding-releases-span-reservation");
    Emit(operation);

    // Observe an in-flight call before a second source consumes the last quota.
    // No sleeps or assumed actor order; completion order differs from admission.
    Source concurrentA(L"synthetic:concurrent-a"), concurrentB(L"synthetic:concurrent-b");
    budget = {};
    budget.MaximumSourceCalls = 2;
    operation = Operation(L"concurrent", budget);
    RecordingObservationSource first(concurrentA, operation), second(concurrentB, operation);
    std::promise<void> entered, release;
    auto observed = entered.get_future();
    auto released = release.get_future().share();
    const auto action = concurrentA.Action;
    concurrentA.Action = [&](const auto& item)
    {
        entered.set_value();
        if (released.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
        {
            throw std::runtime_error("release timeout");
        }
        return action(item);
    };
    auto worker = std::async(std::launch::async, [&] { return first.Read(Request(first)); });
    const bool running = observed.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    Check(running, "first-source-observed-in-flight");
    read = second.Read(Request(second));
    auto pending = operation->Snapshot();
    Check(running && pending.Reads.size() == 2 && !pending.Reads[0].Completed && pending.Reads[1].Completed &&
        read.ReadReceiptId == 2, "receipt-order-is-admission-not-completion");
    Emit(operation);
    Check(second.Read(Request(second)).State == ObservationReadState::BudgetDeferred,
        "concurrent-sources-cannot-overspend-operation");
    release.set_value();
    Check(worker.get().ReadReceiptId == 1, "first-completion-keeps-reserved-receipt-id");
    Emit(operation);

    // Independent owned Win32 byte/error oracle, including caller handle close.
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) { return 1; }
    const auto creation = (uint64_t{created.dwHighDateTime} << 32) | created.dwLowDateTime;
    auto* pages = static_cast<uint8_t*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (pages == nullptr) { return 1; }
    memset(pages, 0x5a, 8192);
    HANDLE original = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    ProcessObservationSource live(original, GetCurrentProcessId(), creation, {});
    if (original != nullptr) { CloseHandle(original); }
    operation = Operation(L"owned-process");
    RecordingObservationSource owned(live, operation);
    Check(ReadObservationExact(owned, reinterpret_cast<uint64_t>(pages), 64, &bytes, true) &&
        bytes == std::vector<uint8_t>(64, 0x5a), "owned-read-after-original-handle-close");
    DWORD old = 0;
    Check(VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &old) != FALSE, "owned-hole-created");
    SIZE_T transferred = 0;
    uint8_t scratch[32]{};
    const auto direct = ReadProcessMemory(GetCurrentProcess(), pages + 4096, scratch, sizeof(scratch), &transferred);
    const auto directError = GetLastError();
    Check(!ReadObservationRange(owned, reinterpret_cast<uint64_t>(pages), 8192, &bytes, 8192, true) && bytes.empty(),
        "owned-hole-preserves-early-read-but-rejects-parser-range");
    const auto real = operation->Snapshot();
    Check(!direct && real.Reads.size() == 3 && real.Reads.back().Result.NativeStatus == directError &&
        real.Reads.back().Result.NativeStatusDomain == L"win32" && real.Reads[1].Result.Spans[0].Bytes.size() == 4096,
        "owned-original-error-and-earlier-bytes-retained");
    Check(VirtualFree(pages, 0, MEM_RELEASE) != FALSE, "owned-allocation-cleaned-up");
    Check(real.Reads[0].Result.Spans[0].Bytes == std::vector<uint8_t>(64, 0x5a), "receipt-outlives-original-memory");
    Emit(operation);

    bool rejected = false;
    budget.MaximumBytes = UINT64_MAX;
    try { Operation(L"unbounded", budget); } catch (const std::invalid_argument&) { rejected = true; }
    Check(rejected, "unbounded-operation-contract-rejected");
    std::cerr << "read receipt controls: " << Checks << " checks, " << Failures << " failures\n";
    return Failures == 0 ? 0 : 1;
}
