#pragma once

#include "AddressSpaceDescriptor.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

enum class ObservationReadState
{
    Complete,
    Partial,
    NotCaptured,
    NotPresent,
    Failed,
    Conflict,
    Skipped,
    PolicyDenied,
    IdentityChanged,
    Unsupported,
    BudgetDeferred,
    Cancelled
};

enum class ObservationAddressDomain { Virtual, Physical };

struct ObservationSourceCapabilities
{
    std::wstring SourceId;
    std::wstring Consistency;
    AddressSpaceDescriptor AddressSpace;
    uint32_t MaximumReadBytes = 4096;
    bool KernelOnly = false;
    bool UserOnly = false;
    bool MayChangeResidency = false;
    ObservationAddressDomain AddressDomain = ObservationAddressDomain::Virtual;
};

inline bool SameObservationSourceContract(const ObservationSourceCapabilities& a, const ObservationSourceCapabilities& b)
{
    return a.SourceId == b.SourceId && a.Consistency == b.Consistency && a.AddressDomain == b.AddressDomain &&
        a.MaximumReadBytes == b.MaximumReadBytes && a.KernelOnly == b.KernelOnly && a.UserOnly == b.UserOnly &&
        a.MayChangeResidency == b.MayChangeResidency && a.AddressSpace.VirtualAddressBits == b.AddressSpace.VirtualAddressBits &&
        a.AddressSpace.PointerBytes == b.AddressSpace.PointerBytes && a.AddressSpace.PhysicalAddressBits == b.AddressSpace.PhysicalAddressBits &&
        a.AddressSpace.LegacyAssumed == b.AddressSpace.LegacyAssumed && a.AddressSpace.UserMaximum == b.AddressSpace.UserMaximum &&
        a.AddressSpace.KernelMinimum == b.AddressSpace.KernelMinimum;
}

inline bool ObservationRangeSupported(const ObservationSourceCapabilities& caps, uint64_t address, uint64_t length)
{
    if (length == 0 || address > UINT64_MAX - length) { return false; }
    if (caps.AddressDomain == ObservationAddressDomain::Physical)
    {
        const auto bits = caps.AddressSpace.PhysicalAddressBits;
        return !caps.KernelOnly && !caps.UserOnly && bits >= 32 && bits <= 52 &&
            address < (uint64_t{1} << bits) && length <= (uint64_t{1} << bits) - address;
    }
    return caps.AddressDomain == ObservationAddressDomain::Virtual && caps.AddressSpace.Valid() &&
        (!caps.UserOnly || caps.AddressSpace.UserRange(address, length)) &&
        (caps.AddressSpace.KernelRange(address, length) || (!caps.KernelOnly && caps.AddressSpace.UserRange(address, length)));
}

struct ObservationReadRequest
{
    std::wstring SourceId;
    uint64_t Address = 0;
    uint32_t Length = 0;
    uint64_t ByteBudget = 0;
    bool AllowResidencyChanges = false;
    const std::atomic<bool>* Cancellation = nullptr;
    // A recorder interprets this explicit link; sources never initiate fallback.
    uint64_t FallbackFromReceipt = 0;
    std::wstring FallbackReason;
    bool AllowFallback = false;
};

struct ObservationReadSpan
{
    uint64_t Address = 0;
    uint32_t RequestedBytes = 0;
    ObservationReadState State = ObservationReadState::NotCaptured;
    std::vector<uint8_t> Bytes;
};

struct ObservationReadResult
{
    std::vector<ObservationReadSpan> Spans;
    ObservationReadState State = ObservationReadState::Failed;
    std::wstring SourceId;
    std::wstring Consistency;
    std::wstring ClockDomain = L"collector_steady_clock_ms";
    uint64_t StartedTick = 0;
    uint64_t EndedTick = 0;
    bool SideEffectsPossible = false;
    bool CancellationObserved = false;
    bool OperationDeadlineExceeded = false;
    bool IdentityRevalidated = false;
    // Legacy DeviceClient reads do not expose the original NTSTATUS.
    std::wstring NativeStatusDomain = L"unavailable";
    uint32_t NativeStatus = 0;
    bool TransferredBytesKnown = false;
    uint32_t TransferredBytes = 0;
    bool TransportAttempted = false;
    bool TransportSucceeded = false;
    uint32_t TransportStatus = 0;
    bool BackendCopyAttemptKnown = false;
    bool BackendCopyAttempted = false;
    uint32_t NativeReadKind = 0;
    uint32_t DriverAbi = 0;
    uint64_t SourceEpoch = 0;
    std::wstring BackendContract;
    std::wstring ValidationReason;
    std::wstring OperationId;
    uint64_t ReadReceiptId = 0;
};

// Optional operation scope around the common admission path. Admission failures
// also reach Complete, so parser rejection cannot erase their receipts.
class ObservationReadScope
{
public:
    virtual ~ObservationReadScope() = default;
    virtual bool Admit(ObservationReadResult* result) = 0;
    virtual void Complete(ObservationReadResult* result) = 0;
};

class IObservationSource
{
public:
    virtual ~IObservationSource() = default;
    virtual const ObservationSourceCapabilities& Capabilities() const = 0;

    // All adapters pass through the same bounded, read-only admission path.
    ObservationReadResult Read(const ObservationReadRequest& request)
    {
        const auto tick = []()
        {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        };
        ObservationReadResult result;
        const auto caps = Capabilities();
        const uint64_t started = tick();
        auto scope = BeginReadScope(request, caps);
        bool attempted = false;
        do
        {
            if (request.Cancellation != nullptr && request.Cancellation->load())
            {
                result.State = ObservationReadState::Cancelled;
                break;
            }
            if (caps.SourceId.empty() || request.SourceId != caps.SourceId)
            {
                result.State = ObservationReadState::IdentityChanged;
                break;
            }
            if (request.Length == 0 || request.Length > 4096 || request.Length > caps.MaximumReadBytes ||
                !ObservationRangeSupported(caps, request.Address, request.Length))
            {
                result.State = ObservationReadState::Unsupported;
                break;
            }
            if (request.Length > request.ByteBudget)
            {
                result.State = ObservationReadState::BudgetDeferred;
                break;
            }
            if (caps.MayChangeResidency && !request.AllowResidencyChanges)
            {
                result.State = ObservationReadState::PolicyDenied;
                break;
            }
            if (scope != nullptr && !scope->Admit(&result))
            {
                break;
            }
            attempted = true;
            result = ReadSpans(request);
            if (!SameObservationSourceContract(Capabilities(), caps))
            {
                result.Spans.clear();
                result.IdentityRevalidated = false;
                result.ValidationReason = L"source_changed_during_read";
                result.State = ObservationReadState::IdentityChanged;
                break;
            }
            if (!ValidateSpans(request, &result))
            {
                result.Spans.clear();
                result.IdentityRevalidated = false;
                result.ValidationReason = L"malformed_source_spans";
                result.State = ObservationReadState::Failed;
            }
        } while (false);
        result.SourceId = caps.SourceId;
        result.Consistency = caps.Consistency;
        result.StartedTick = started;
        result.EndedTick = tick();
        result.SideEffectsPossible = attempted && caps.MayChangeResidency;
        result.CancellationObserved = result.CancellationObserved ||
            (request.Cancellation != nullptr && request.Cancellation->load());
        if (scope != nullptr)
        {
            scope->Complete(&result);
        }
        return result;
    }

protected:
    virtual std::unique_ptr<ObservationReadScope> BeginReadScope(
        const ObservationReadRequest&, const ObservationSourceCapabilities&)
    {
        return {};
    }
    virtual ObservationReadResult ReadSpans(const ObservationReadRequest& request) = 0;

private:
    static bool ValidateSpans(const ObservationReadRequest& request, ObservationReadResult* result)
    {
        if (result->Spans.empty())
        {
            // A delegated admission failure has no byte spans. It cannot be
            // promoted to complete/partial, but its original denial survives.
            return result->State >= ObservationReadState::NotCaptured && result->State <= ObservationReadState::Cancelled;
        }
        if (result->Spans.size() > request.Length)
        {
            return false;
        }
        uint32_t consumed = 0;
        const auto firstState = result->Spans.front().State;
        bool same = true;
        for (const auto& span : result->Spans)
        {
            if (span.RequestedBytes == 0 || span.RequestedBytes > request.Length - consumed ||
                span.Address != request.Address + consumed || span.State == ObservationReadState::Partial ||
                span.State < ObservationReadState::Complete || span.State > ObservationReadState::Cancelled ||
                (span.State == ObservationReadState::Complete ? span.Bytes.size() != span.RequestedBytes : !span.Bytes.empty()))
            {
                return false;
            }
            same = same && span.State == firstState;
            consumed += span.RequestedBytes;
        }
        result->State = same ? firstState : ObservationReadState::Partial;
        return consumed == request.Length;
    }
};

inline bool ReadObservationExact(IObservationSource& source, uint64_t address, size_t length,
    std::vector<uint8_t>* bytes, bool allowResidencyChanges = false, const std::atomic<bool>* cancellation = nullptr)
{
    if (bytes == nullptr)
    {
        return false;
    }
    bytes->clear();
    if (length == 0 || length > 4096)
    {
        return false;
    }
    ObservationReadRequest request;
    request.SourceId = source.Capabilities().SourceId;
    request.Address = address;
    request.Length = static_cast<uint32_t>(length);
    request.ByteBudget = length;
    request.AllowResidencyChanges = allowResidencyChanges;
    request.Cancellation = cancellation;
    const auto result = source.Read(request);
    if (result.State != ObservationReadState::Complete || result.CancellationObserved || result.OperationDeadlineExceeded)
    {
        return false;
    }
    for (const auto& span : result.Spans)
    {
        bytes->insert(bytes->end(), span.Bytes.begin(), span.Bytes.end());
    }
    return bytes->size() == length;
}

// Parser compatibility helper. Multiple reads are not an atomic snapshot.
// Bind every chunk to one source and discard the assembled bytes on any gap.
inline bool ReadObservationRange(IObservationSource& source, uint64_t address, size_t length,
    std::vector<uint8_t>* bytes, uint64_t byteBudget, bool allowResidencyChanges = false,
    const std::atomic<bool>* cancellation = nullptr)
{
    if (bytes == nullptr)
    {
        return false;
    }
    bytes->clear();
    const auto caps = source.Capabilities();
    if (length == 0 || length > 0x20000 || length > byteBudget || caps.MaximumReadBytes == 0 ||
        !ObservationRangeSupported(caps, address, length))
    {
        return false;
    }
    std::vector<uint8_t> assembled;
    assembled.reserve(length);
    while (assembled.size() < length)
    {
        if (!SameObservationSourceContract(caps, source.Capabilities()))
        {
            return false;
        }
        ObservationReadRequest request;
        request.SourceId = caps.SourceId;
        request.Address = address + assembled.size();
        request.Length = static_cast<uint32_t>((std::min)(length - assembled.size(),
            static_cast<size_t>((std::min)(caps.MaximumReadBytes, uint32_t{4096}))));
        request.ByteBudget = byteBudget - assembled.size();
        request.AllowResidencyChanges = allowResidencyChanges;
        request.Cancellation = cancellation;
        const auto result = source.Read(request);
        if (result.State != ObservationReadState::Complete || result.CancellationObserved || result.OperationDeadlineExceeded)
        {
            return false;
        }
        for (const auto& span : result.Spans)
        {
            assembled.insert(assembled.end(), span.Bytes.begin(), span.Bytes.end());
        }
    }
    *bytes = std::move(assembled);
    return true;
}
