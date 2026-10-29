#pragma once

#include "AddressSpaceDescriptor.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>

enum class ObservationReadState
{
    Complete,
    Partial,
    NotCaptured,
    Failed,
    Conflict,
    Skipped,
    PolicyDenied,
    IdentityChanged,
    Unsupported,
    BudgetDeferred,
    Cancelled
};

struct ObservationSourceCapabilities
{
    std::wstring SourceId;
    std::wstring Consistency;
    AddressSpaceDescriptor AddressSpace;
    uint32_t MaximumReadBytes = 4096;
    bool KernelOnly = false;
    bool MayChangeResidency = false;
};

struct ObservationReadRequest
{
    std::wstring SourceId;
    uint64_t Address = 0;
    uint32_t Length = 0;
    uint64_t ByteBudget = 0;
    bool AllowResidencyChanges = false;
    const std::atomic<bool>* Cancellation = nullptr;
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
    bool IdentityRevalidated = false;
    // Current DeviceClient methods do not expose the original native status.
    std::wstring NativeStatusDomain = L"unavailable";
    uint32_t NativeStatus = 0;
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
                request.Address > UINT64_MAX - request.Length ||
                !caps.AddressSpace.Valid() ||
                (!caps.AddressSpace.KernelRange(request.Address, request.Length) &&
                    (caps.KernelOnly || !caps.AddressSpace.UserRange(request.Address, request.Length))))
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
            attempted = true;
            result = ReadSpans(request);
            if (Capabilities().SourceId != caps.SourceId)
            {
                result = {};
                result.State = ObservationReadState::IdentityChanged;
                break;
            }
            if (!ValidateSpans(request, &result))
            {
                result = {};
                result.State = ObservationReadState::Failed;
            }
        } while (false);
        result.SourceId = caps.SourceId;
        result.Consistency = caps.Consistency;
        result.StartedTick = started;
        result.EndedTick = tick();
        result.SideEffectsPossible = attempted && caps.MayChangeResidency;
        result.CancellationObserved = request.Cancellation != nullptr && request.Cancellation->load();
        return result;
    }

protected:
    virtual ObservationReadResult ReadSpans(const ObservationReadRequest& request) = 0;

private:
    static bool ValidateSpans(const ObservationReadRequest& request, ObservationReadResult* result)
    {
        if (result->Spans.empty() || result->Spans.size() > request.Length)
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
    if (result.State != ObservationReadState::Complete || result.CancellationObserved)
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
        address > UINT64_MAX - length || (!caps.AddressSpace.KernelRange(address, length) &&
            (caps.KernelOnly || !caps.AddressSpace.UserRange(address, length))))
    {
        return false;
    }
    std::vector<uint8_t> assembled;
    assembled.reserve(length);
    while (assembled.size() < length)
    {
        ObservationReadRequest request;
        request.SourceId = caps.SourceId;
        request.Address = address + assembled.size();
        request.Length = static_cast<uint32_t>((std::min)(length - assembled.size(),
            static_cast<size_t>((std::min)(caps.MaximumReadBytes, uint32_t{4096}))));
        request.ByteBudget = byteBudget - assembled.size();
        request.AllowResidencyChanges = allowResidencyChanges;
        request.Cancellation = cancellation;
        const auto result = source.Read(request);
        if (result.State != ObservationReadState::Complete || result.CancellationObserved)
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
