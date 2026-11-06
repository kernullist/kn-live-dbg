#pragma once

#include "DeviceClient.h"
#include "ObservationSource.h"

// The caller owns the device and serializes its lifecycle with scanner work.
// A source never owns a mutation capability or exposes an arbitrary IOCTL.
class NativeObservationSource final : public IObservationSource
{
public:
    explicit NativeObservationSource(DeviceClient& device)
        : NativeObservationSource(device, KNDBG_READ_OBSERVATION_KERNEL, 0, 0, 0) {}

    NativeObservationSource(DeviceClient& device, uint32_t pid, uint64_t eprocess, uint64_t creation)
        : NativeObservationSource(device, KNDBG_READ_OBSERVATION_PROCESS, pid, eprocess, creation) {}

private:
    NativeObservationSource(DeviceClient& device, uint32_t kind, uint32_t pid, uint64_t eprocess, uint64_t creation)
        : Device(device), Epoch(device.ObservationEpoch()), Kind(kind), Pid(pid), Eprocess(eprocess), Creation(creation)
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        if (Epoch != 0 && GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        {
            const uint64_t collectorCreation = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
            Caps.SourceId = L"native_kernel:" + std::to_wstring(GetCurrentProcessId()) + L":" +
                std::to_wstring(collectorCreation) + L":" + std::to_wstring(Epoch);
        }
        Caps.Consistency = L"single_read";
        Caps.AddressSpace = device.AddressSpace();
        Caps.KernelOnly = kind == KNDBG_READ_OBSERVATION_KERNEL;
        Caps.UserOnly = kind == KNDBG_READ_OBSERVATION_PROCESS;
        Caps.MayChangeResidency = true;
        if (Caps.UserOnly)
        {
            if (pid == 0 || eprocess == 0 || creation == 0) { Caps.SourceId.clear(); }
            else if (!Caps.SourceId.empty())
            {
                Caps.SourceId += L":process:" + std::to_wstring(pid) + L":" + std::to_wstring(eprocess) + L":" + std::to_wstring(creation);
            }
        }
    }

public:
    const ObservationSourceCapabilities& Capabilities() const override
    {
        return Caps;
    }

protected:
    ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
    {
        ObservationReadResult result;
        if (!SameConnection())
        {
            result.State = ObservationReadState::IdentityChanged;
            return result;
        }
        KNDBG_OBSERVATION_READ_REQUEST input{};
        input.Size = sizeof(input);
        input.Version = KNDBG_READ_OBSERVATION_VERSION;
        input.Kind = Kind;
        input.Flags = request.AllowResidencyChanges ? KNDBG_READ_OBSERVATION_ALLOW_RESIDENCY : 0;
        input.ProcessId = Pid;
        input.ExpectedEprocess = Eprocess;
        input.ExpectedCreateTime = Creation;
        input.Address = request.Address;
        input.Length = request.Length;
        input.SourceEpoch = Epoch;
        result = NativeObservationReadResult(request.Address, request.Length, Device.ReadObservation(input));
        if (!SameConnection())
        {
            result.Spans.clear();
            result.State = ObservationReadState::IdentityChanged;
            result.IdentityRevalidated = false;
            result.ValidationReason = L"native_source_changed";
        }
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
    const uint32_t Kind;
    const uint32_t Pid;
    const uint64_t Eprocess;
    const uint64_t Creation;
    ObservationSourceCapabilities Caps;
};
