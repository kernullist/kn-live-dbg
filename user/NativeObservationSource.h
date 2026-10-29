#pragma once

#include "DeviceClient.h"
#include "ObservationSource.h"

// The caller owns the device and serializes its lifecycle with scanner work.
// A source never owns a mutation capability or exposes an arbitrary IOCTL.
class NativeObservationSource final : public IObservationSource
{
public:
    explicit NativeObservationSource(DeviceClient& device) : Device(device), Epoch(device.ObservationEpoch())
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        if (Epoch != 0 && GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        {
            const uint64_t creation = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            Caps.SourceId = L"native_kernel:" + std::to_wstring(GetCurrentProcessId()) + L":" +
                std::to_wstring(creation) + L":" + std::to_wstring(Epoch);
        }
        Caps.Consistency = L"single_read";
        Caps.AddressSpace = device.AddressSpace();
        Caps.KernelOnly = true;
        Caps.MayChangeResidency = true;
    }

    const ObservationSourceCapabilities& Capabilities() const override
    {
        return Caps;
    }

protected:
    ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
    {
        ObservationReadResult result;
        ObservationReadSpan span;
        span.Address = request.Address;
        span.RequestedBytes = request.Length;
        span.State = ObservationReadState::IdentityChanged;
        if (SameConnection())
        {
            std::vector<uint8_t> bytes;
            const bool read = Device.ReadMemory(request.Address, request.Length, &bytes, nullptr);
            if (SameConnection())
            {
                span.State = ObservationReadState::Failed;
                if (read && !bytes.empty() && bytes.size() <= request.Length)
                {
                    span.RequestedBytes = static_cast<uint32_t>(bytes.size());
                    span.State = ObservationReadState::Complete;
                    span.Bytes = std::move(bytes);
                    if (span.RequestedBytes < request.Length)
                    {
                        const auto copied = span.RequestedBytes;
                        result.Spans.push_back(std::move(span));
                        span = {};
                        span.Address = request.Address + copied;
                        span.RequestedBytes = request.Length - copied;
                        span.State = ObservationReadState::Failed;
                    }
                }
            }
        }
        result.Spans.push_back(std::move(span));
        return result;
    }

private:
    bool SameConnection() const
    {
        const auto current = Device.AddressSpace();
        const auto& captured = Caps.AddressSpace;
        return Epoch != 0 && Device.ObservationEpoch() == Epoch && current.Valid() &&
            current.VirtualAddressBits == captured.VirtualAddressBits && current.PointerBytes == captured.PointerBytes &&
            current.PhysicalAddressBits == captured.PhysicalAddressBits && current.LegacyAssumed == captured.LegacyAssumed &&
            current.UserMaximum == captured.UserMaximum && current.KernelMinimum == captured.KernelMinimum;
    }

    DeviceClient& Device;
    const uint64_t Epoch;
    ObservationSourceCapabilities Caps;
};
