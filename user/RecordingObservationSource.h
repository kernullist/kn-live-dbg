#pragma once

#include "ObservationSource.h"
#include <functional>
#include <mutex>
#include <stdexcept>

struct ObservationOperationBudget
{
    uint64_t MaximumBytes = 1024 * 1024;
    uint32_t MaximumSourceCalls = 1024;
    uint32_t MaximumReceipts = 2048;
    uint32_t MaximumStoredSpans = 65536;
    uint64_t MaximumElapsedMs = 5000;
};

struct ObservationReadReceipt
{
    uint64_t Sequence = 0;
    ObservationSourceCapabilities Source;
    ObservationReadRequest Request; // Cancellation is always null in saved data.
    ObservationReadResult Result;
    bool SourceInvoked = false;
    bool Completed = false;
    bool Abandoned = false;
    bool DeadlineExceeded = false;
    bool FallbackPermitted = false;
    std::wstring AdmissionReason;
};

struct ObservationReadSet
{
    std::wstring OperationId;
    std::wstring TargetId;
    std::wstring AddressSpaceId;
    ObservationOperationBudget Budget;
    uint64_t StartedTick = 0;
    uint64_t SnapshotTick = 0;
    uint64_t TotalAttempts = 0;
    uint64_t UnrecordedAttempts = 0;
    uint64_t ChargedBytes = 0;
    uint32_t ChargedSourceCalls = 0;
    uint32_t StoredSpans = 0;
    uint32_t ReservedSpanSlots = 0;
    bool Cancelled = false;
    bool DeadlineExceeded = false;
    std::vector<ObservationReadReceipt> Reads;
};

// Budgets and receipts are shared across sources, retries and parser calls.
// The recorder owns operation state, not source handles or their lifecycle.
class ObservationReadOperation final
{
public:
    using Clock = std::function<uint64_t()>;

    ObservationReadOperation(std::wstring operationId, std::wstring targetId,
        std::wstring addressSpaceId, ObservationOperationBudget budget = {}, Clock clock = Now)
        : Tick(std::move(clock))
    {
        if (operationId.empty() || targetId.empty() || addressSpaceId.empty() ||
            operationId.size() > 256 || targetId.size() > 2048 || addressSpaceId.size() > 2048 ||
            budget.MaximumBytes > 16 * 1024 * 1024 || budget.MaximumSourceCalls > 4096 ||
            budget.MaximumReceipts == 0 || budget.MaximumReceipts > 4096 || budget.MaximumStoredSpans > 65536 || !Tick)
        {
            throw std::invalid_argument("invalid bounded observation operation");
        }
        Data.OperationId = std::move(operationId);
        Data.TargetId = std::move(targetId);
        Data.AddressSpaceId = std::move(addressSpaceId);
        Data.Budget = budget;
        Data.StartedTick = Tick();
    }

    void Cancel() { Cancelled.store(true); }

    ObservationReadSet Snapshot() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        auto copy = Data;
        // Includes allocation failures while reserving a receipt, before any
        // source call. Such exceptions must never leave a complete read set.
        copy.UnrecordedAttempts = copy.TotalAttempts - copy.Reads.size();
        copy.SnapshotTick = Tick();
        copy.Cancelled = Cancelled.load();
        copy.DeadlineExceeded = Expired(copy.SnapshotTick);
        return copy;
    }

private:
    friend class RecordingObservationSource;

    static uint64_t Now()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    bool Expired(uint64_t now) const
    {
        // A backwards clock is unusable evidence, never a renewed budget.
        return now < Data.StartedTick || now - Data.StartedTick >= Data.Budget.MaximumElapsedMs;
    }

    class Scope final : public ObservationReadScope
    {
    public:
        Scope(std::shared_ptr<ObservationReadOperation> operation,
            const ObservationReadRequest& request, const ObservationSourceCapabilities& source)
            : Operation(std::move(operation))
        {
            auto& op = *Operation;
            std::lock_guard<std::mutex> lock(op.Mutex);
            if (op.Data.TotalAttempts != UINT64_MAX) { ++op.Data.TotalAttempts; }
            if (op.Data.Reads.size() == op.Data.Budget.MaximumReceipts ||
                request.SourceId.size() > 2048 || source.SourceId.size() > 2048 ||
                source.Consistency.size() > 256 || request.FallbackReason.size() > 1024)
            {
                if (op.Data.UnrecordedAttempts != UINT64_MAX) { ++op.Data.UnrecordedAttempts; }
                return;
            }
            ObservationReadReceipt receipt;
            receipt.Sequence = op.Data.TotalAttempts;
            receipt.Source = source;
            receipt.Request = request;
            receipt.Request.Cancellation = nullptr;
            receipt.AdmissionReason = L"source_admission";
            if (request.FallbackFromReceipt != 0)
            {
                const auto from = std::find_if(op.Data.Reads.begin(), op.Data.Reads.end(), [&](const auto& prior)
                {
                    return prior.Sequence == request.FallbackFromReceipt;
                });
                receipt.FallbackPermitted = request.AllowFallback && !request.FallbackReason.empty() &&
                    from != op.Data.Reads.end() && from->Completed && !from->Result.CancellationObserved &&
                    from->Source.SourceId != source.SourceId && from->Request.Address == request.Address &&
                    from->Request.Length == request.Length &&
                    (from->Result.State == ObservationReadState::Failed || from->Result.State == ObservationReadState::Partial ||
                        from->Result.State == ObservationReadState::NotCaptured || from->Result.State == ObservationReadState::NotPresent ||
                        from->Result.State == ObservationReadState::Unsupported);
            }
            op.Data.Reads.push_back(std::move(receipt));
            Index = op.Data.Reads.size() - 1;
        }

        ~Scope() override
        {
            if (!Finished && Index != NoIndex)
            {
                std::lock_guard<std::mutex> lock(Operation->Mutex);
                auto& receipt = Operation->Data.Reads[Index];
                receipt.Abandoned = true;
                receipt.Result.Spans.clear();
                if (ReservedSpans != 0) { Operation->Data.ReservedSpanSlots -= ReservedSpans; }
            }
        }

        bool Admit(ObservationReadResult* result) override
        {
            auto& op = *Operation;
            std::lock_guard<std::mutex> lock(op.Mutex);
            if (Index == NoIndex)
            {
                result->State = ObservationReadState::BudgetDeferred;
                return false;
            }
            auto& receipt = op.Data.Reads[Index];
            const auto deny = [&](ObservationReadState state, const wchar_t* reason)
            {
                receipt.AdmissionReason = reason;
                result->State = state;
                return false;
            };
            if (op.Cancelled.load())
            {
                return deny(ObservationReadState::Cancelled, L"operation_cancelled");
            }
            if (receipt.Request.FallbackFromReceipt != 0 && !receipt.FallbackPermitted)
            {
                return deny(ObservationReadState::PolicyDenied, L"fallback_not_permitted");
            }
            if (op.Expired(op.Tick()))
            {
                return deny(ObservationReadState::BudgetDeferred, L"operation_deadline");
            }
            if (op.Data.ChargedSourceCalls == op.Data.Budget.MaximumSourceCalls ||
                receipt.Request.Length > op.Data.Budget.MaximumBytes - op.Data.ChargedBytes)
            {
                return deny(ObservationReadState::BudgetDeferred, L"operation_read_budget");
            }
            // Reserve the worst case (one sparse span per byte) before source
            // invocation. Refund unused slots on completion, including faults.
            if (receipt.Request.Length > op.Data.Budget.MaximumStoredSpans - op.Data.StoredSpans - op.Data.ReservedSpanSlots)
            {
                return deny(ObservationReadState::BudgetDeferred, L"operation_span_budget");
            }
            receipt.AdmissionReason = L"delegated_to_source";
            ++op.Data.ChargedSourceCalls;
            op.Data.ChargedBytes += receipt.Request.Length;
            ReservedSpans = receipt.Request.Length;
            op.Data.ReservedSpanSlots += ReservedSpans;
            receipt.SourceInvoked = true;
            return true;
        }

        void Complete(ObservationReadResult* result) override
        {
            auto& op = *Operation;
            std::lock_guard<std::mutex> lock(op.Mutex);
            result->CancellationObserved = result->CancellationObserved || op.Cancelled.load();
            result->OperationId = op.Data.OperationId;
            if (Index != NoIndex)
            {
                auto& receipt = op.Data.Reads[Index];
                result->ReadReceiptId = receipt.Sequence;
                receipt.DeadlineExceeded = op.Expired(op.Tick());
                receipt.Result = *result;
                op.Data.ReservedSpanSlots -= ReservedSpans;
                ReservedSpans = 0;
                op.Data.StoredSpans += static_cast<uint32_t>(result->Spans.size());
                receipt.Completed = true;
            }
            Finished = true;
        }

    private:
        static constexpr size_t NoIndex = SIZE_MAX;
        std::shared_ptr<ObservationReadOperation> Operation;
        size_t Index = NoIndex;
        bool Finished = false;
        uint32_t ReservedSpans = 0;
    };

    const Clock Tick;
    mutable std::mutex Mutex;
    std::atomic<bool> Cancelled{false};
    ObservationReadSet Data;
};

class RecordingObservationSource final : public IObservationSource
{
public:
    RecordingObservationSource(IObservationSource& source, std::shared_ptr<ObservationReadOperation> operation)
        : Source(source), Operation(std::move(operation))
    {
        if (Operation == nullptr) { throw std::invalid_argument("observation operation required"); }
    }

    const ObservationSourceCapabilities& Capabilities() const override { return Source.Capabilities(); }

protected:
    std::unique_ptr<ObservationReadScope> BeginReadScope(const ObservationReadRequest& request,
        const ObservationSourceCapabilities& source) override
    {
        return std::make_unique<ObservationReadOperation::Scope>(Operation, request, source);
    }

    ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
    {
        return Source.Read(request);
    }

private:
    IObservationSource& Source;
    const std::shared_ptr<ObservationReadOperation> Operation;
};
