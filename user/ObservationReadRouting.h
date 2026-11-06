#pragma once

#include "RecordingObservationSource.h"

struct ObservationParserRead
{
    uint64_t Address = 0;
    uint32_t Length = 0;
    uint64_t PrimaryReceipt = 0;
    uint64_t ReturnedReceipt = 0;
    bool Accepted = false;
    std::wstring BeforeGuard = L"not_requested";
    std::wstring AfterGuard = L"not_requested";
    std::wstring Reason;
};

struct ObservationRoutedReadSet
{
    ObservationReadSet Attempts;
    std::vector<ObservationParserRead> ParserReads;
    uint64_t UnrecordedParserCalls = 0;
};

// All sources and the lazy fallback are owned by the caller. Calls and source
// lifecycle changes must be serialized. Target labels are declarations, not
// qualification; each adapter must enforce the expected target generation.
struct ObservationReadRouting
{
    IObservationSource* Primary = nullptr;
    std::function<IObservationSource*()> Fallback;
    std::wstring TargetId;
    std::wstring AddressSpaceId;
    bool AllowResidencyChanges = false;
    bool AllowFallback = false;
    std::function<bool(uint64_t, size_t)> BeforeRead;
    std::function<bool(uint64_t, size_t)> AfterRead;
};

// No handle is a source-unavailable observation, not proof that a PID changed.
// A separate fallback adapter must still qualify the expected process identity.
class UnavailableObservationSource final : public IObservationSource
{
public:
    explicit UnavailableObservationSource(ObservationSourceCapabilities caps) : Caps(std::move(caps))
    {
        Caps.Consistency = L"source_not_opened";
        Caps.MayChangeResidency = false;
    }
    const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
protected:
    ObservationReadResult ReadSpans(const ObservationReadRequest&) override
    {
        ObservationReadResult result;
        result.State = ObservationReadState::Unsupported;
        result.ValidationReason = L"primary_source_unavailable";
        result.BackendContract = L"declared_unavailable_source";
        result.BackendCopyAttemptKnown = true;
        return result;
    }
private:
    ObservationSourceCapabilities Caps;
};

inline bool ObservationFallbackEligible(const ObservationReadResult& read)
{
    return read.ReadReceiptId != 0 && !read.CancellationObserved && !read.OperationDeadlineExceeded &&
        (read.State == ObservationReadState::Failed || read.State == ObservationReadState::Partial ||
            read.State == ObservationReadState::NotCaptured || read.State == ObservationReadState::NotPresent ||
            read.State == ObservationReadState::Unsupported);
}

class ObservationReadRouter final
{
public:
    ObservationReadRouter(ObservationReadRouting routing, std::shared_ptr<ObservationReadOperation> operation,
        const std::atomic<bool>* cancellation = nullptr)
        : Routing(std::move(routing)), Operation(std::move(operation)), Cancellation(cancellation)
    {
        if (Routing.Primary == nullptr || Operation == nullptr ||
            !Operation->MatchesTarget(Routing.TargetId, Routing.AddressSpaceId))
        {
            throw std::invalid_argument("matching target and primary source required");
        }
        PrimaryContract = Routing.Primary->Capabilities();
        Limit = Operation->Snapshot().Budget.MaximumReceipts;
    }

    bool ReadExact(uint64_t address, size_t length, std::vector<uint8_t>* bytes)
    {
        if (bytes == nullptr) { return false; }
        bytes->clear();
        if (Calls.size() == Limit)
        {
            if (UnrecordedCalls != UINT64_MAX) { ++UnrecordedCalls; }
            return false;
        }
        // Reserve a parser-call record before any source invocation.
        ObservationParserRead pending;
        pending.Address = address;
        pending.Length = length <= UINT32_MAX ? static_cast<uint32_t>(length) : 0;
        Calls.push_back(std::move(pending));
        auto& call = Calls.back();
        call.Reason = L"invalid_parser_range";
        if (length == 0 || length > 4096 || address > UINT64_MAX - length) { return false; }
        if (Routing.BeforeRead)
        {
            if (Interrupted())
            {
                call.BeforeGuard = L"not_run";
                call.Reason = L"operation_interrupted_before_guard";
                return false;
            }
            call.BeforeGuard = L"incomplete";
            call.Reason = L"before_read_guard_incomplete";
            call.BeforeGuard = Routing.BeforeRead(address, length) ? L"passed" : L"failed";
            if (call.BeforeGuard != L"passed") { call.Reason = L"before_read_guard_failed"; return false; }
        }
        call.Reason = L"primary_contract_changed";
        if (!SameObservationSourceContract(PrimaryContract, Routing.Primary->Capabilities())) { return false; }
        ObservationReadRequest request;
        request.SourceId = PrimaryContract.SourceId;
        request.Address = address;
        request.Length = static_cast<uint32_t>(length);
        request.ByteBudget = length;
        request.AllowResidencyChanges = Routing.AllowResidencyChanges;
        request.Cancellation = Cancellation;
        RecordingObservationSource primary(*Routing.Primary, Operation);
        call.Reason = L"primary_incomplete";
        auto result = primary.Read(request);
        call.PrimaryReceipt = call.ReturnedReceipt = result.ReadReceiptId;
        call.Reason = L"primary_result";
        if (Routing.AllowFallback && Routing.Fallback && ObservationFallbackEligible(result))
        {
            if (Interrupted()) { call.Reason = L"operation_interrupted_before_fallback"; return false; }
            IObservationSource* fallback = nullptr;
            try { fallback = Routing.Fallback(); }
            catch (const std::exception&) { call.Reason = L"fallback_initialization_failed"; return false; }
            if (fallback == nullptr)
            {
                call.Reason = L"fallback_unavailable";
            }
            else
            {
                const auto caps = fallback->Capabilities();
                auto comparable = caps;
                comparable.SourceId = PrimaryContract.SourceId;
                comparable.Consistency = PrimaryContract.Consistency;
                comparable.MaximumReadBytes = PrimaryContract.MaximumReadBytes;
                comparable.MayChangeResidency = PrimaryContract.MayChangeResidency;
                // Equal numeric addresses in different domains/descriptors or
                // user/kernel policies cannot be substituted for one another.
                if (caps.SourceId.empty() || caps.SourceId == PrimaryContract.SourceId ||
                    !SameObservationSourceContract(comparable, PrimaryContract))
                {
                    call.Reason = L"fallback_contract_mismatch";
                }
                else
                {
                    request.SourceId = caps.SourceId;
                    request.AllowFallback = true;
                    request.FallbackFromReceipt = result.ReadReceiptId;
                    request.FallbackReason = L"primary_exact_read_unavailable";
                    RecordingObservationSource secondary(*fallback, Operation);
                    call.Reason = L"fallback_incomplete";
                    result = secondary.Read(request);
                    call.ReturnedReceipt = result.ReadReceiptId;
                    call.Reason = L"explicit_fallback_result";
                }
            }
        }
        if (result.State != ObservationReadState::Complete || result.CancellationObserved ||
            result.OperationDeadlineExceeded || result.ReadReceiptId == 0) { return false; }
        if (Routing.AfterRead)
        {
            call.AfterGuard = L"incomplete";
            call.Reason = L"after_read_guard_incomplete";
            call.AfterGuard = Routing.AfterRead(address, length) ? L"passed" : L"failed";
            if (call.AfterGuard != L"passed") { call.Reason = L"after_read_guard_failed"; return false; }
        }
        if (Interrupted())
        {
            call.Reason = L"operation_interrupted_after_read";
            return false;
        }
        for (const auto& span : result.Spans) { bytes->insert(bytes->end(), span.Bytes.begin(), span.Bytes.end()); }
        if (bytes->size() != length) { bytes->clear(); return false; }
        call.Accepted = true;
        call.Reason = call.ReturnedReceipt == call.PrimaryReceipt ? L"primary_result" : L"explicit_fallback_result";
        return true;
    }

    ObservationRoutedReadSet Snapshot() const { return {Operation->Snapshot(), Calls, UnrecordedCalls}; }

private:
    bool Interrupted() const
    {
        return (Cancellation != nullptr && Cancellation->load()) || Operation->DeadlineExceededOrCancelled();
    }

    ObservationReadRouting Routing;
    const std::shared_ptr<ObservationReadOperation> Operation;
    const std::atomic<bool>* Cancellation;
    ObservationSourceCapabilities PrimaryContract;
    size_t Limit = 0;
    std::vector<ObservationParserRead> Calls;
    uint64_t UnrecordedCalls = 0;
};
