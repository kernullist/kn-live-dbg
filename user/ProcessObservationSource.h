#pragma once

#include <Windows.h>
#include <memory>
#include "ObservationSource.h"
#include "ProcessMappingObservation.h"

// Byte reads are bound to an owned duplicate of one process object. This is
// not an atomic process snapshot or a qualification of its object layouts.
class ProcessObservationSource final : public IObservationSource, public IProcessMappingObserver
{
public:
    ProcessObservationSource(HANDLE process, uint32_t pid, uint64_t creation,
        const AddressSpaceDescriptor& addressSpace) : Pid(pid), Creation(creation)
    {
        Caps.AddressSpace = addressSpace;
        Caps.Consistency = L"handle_bound_single_read";
        Caps.UserOnly = true;
        Caps.MayChangeResidency = true;
        do
        {
            if (process == nullptr || pid == 0 || creation == 0 || !addressSpace.Valid())
            {
                break;
            }
            HANDLE duplicate = nullptr;
            if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &duplicate,
                0, FALSE, DUPLICATE_SAME_ACCESS))
            {
                break;
            }
            Process.reset(duplicate);
            if (!SameIdentity())
            {
                break;
            }
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
            {
                break;
            }
            Caps.SourceId = L"process_handle:" + std::to_wstring(GetCurrentProcessId()) + L":" +
                std::to_wstring(TimeValue(created)) + L":" + std::to_wstring(Pid) + L":" +
                std::to_wstring(Creation) + L":" + std::to_wstring(addressSpace.VirtualAddressBits) + L":" +
                std::to_wstring(addressSpace.UserMaximum) + L":" + (addressSpace.LegacyAssumed ? L"assumed" : L"declared");
        } while (false);
    }

    ProcessObservationSource(const ProcessObservationSource&) = delete;
    ProcessObservationSource& operator=(const ProcessObservationSource&) = delete;

    const ObservationSourceCapabilities& Capabilities() const override
    {
        return Caps;
    }

    ProcessMappingObservation ObserveMapping(uint64_t address, uint32_t length,
        const std::atomic<bool>* cancellation = nullptr) override
    {
        ProcessMappingObservation out;
        out.SourceId = Caps.SourceId; out.Address = address; out.Length = length;
        out.StartedTick = ProcessMappingTick();
        do
        {
            if (Caps.SourceId.empty() || !SameIdentity()) { out.Status = L"identity_changed"; break; }
            if (sizeof(MEMORY_BASIC_INFORMATION) != ProcessMappingQueryBytes || !length || length > 4096 ||
                !ObservationRangeSupported(Caps, address, length))
                { out.Status = L"unsupported"; break; }
            uint64_t cursor = address;
            while (cursor < address + length)
            {
                if (cancellation && cancellation->load()) { out.Status = L"cancelled"; break; }
                // A <=4096-byte range intersects at most two native Windows pages.
                if (out.Queries.size() == 2) { out.Status = L"malformed_result"; break; }
                MEMORY_BASIC_INFORMATION info{};
                ProcessMappingQuery query;
                query.Address = cursor;
                query.ReturnedBytes = VirtualQueryEx(Process.get(), reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info));
                query.NativeStatusKnown = query.ReturnedBytes == 0;
                if (query.NativeStatusKnown) { query.NativeStatus = GetLastError(); }
                if (query.ReturnedBytes == sizeof(info))
                {
                    query.RegionBase = reinterpret_cast<uint64_t>(info.BaseAddress);
                    query.RegionBytes = info.RegionSize;
                    query.State = info.State;
                    // MEM_FREE has no defined allocation/type/protection fields;
                    // MEM_RESERVE has no defined current protection field.
                    if (info.State != MEM_FREE)
                    {
                        query.AllocationBase = reinterpret_cast<uint64_t>(info.AllocationBase);
                        query.AllocationProtect = info.AllocationProtect;
                        query.Type = info.Type;
                        if (info.State == MEM_COMMIT) { query.Protect = info.Protect; }
                    }
                }
                out.Queries.push_back(query);
                if (!query.ReturnedBytes) { out.Status = L"query_failed"; break; }
                if (query.ReturnedBytes != sizeof(info) || query.RegionBase > cursor ||
                    !query.RegionBytes || query.RegionBase > UINT64_MAX - query.RegionBytes ||
                    query.RegionBase + query.RegionBytes <= cursor)
                    { out.Status = L"malformed_result"; break; }
                cursor = (std::min)(address + length, query.RegionBase + query.RegionBytes);
            }
            if (!SameIdentity()) { out.Status = L"identity_changed"; break; }
            out.IdentityRevalidated = true;
            if (cursor == address + length) { out.Status = L"complete"; }
        } while (false);
        out.EndedTick = ProcessMappingTick();
        return out;
    }

protected:
    ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
    {
        ObservationReadResult result;
        ObservationReadSpan span;
        span.Address = request.Address;
        span.RequestedBytes = request.Length;
        span.State = ObservationReadState::IdentityChanged;
        if (SameIdentity())
        {
            std::vector<uint8_t> bytes(request.Length);
            SIZE_T copied = 0;
            const BOOL read = ReadProcessMemory(Process.get(), reinterpret_cast<LPCVOID>(request.Address),
                bytes.data(), bytes.size(), &copied);
            result.NativeStatusDomain = L"win32";
            result.NativeStatus = read ? ERROR_SUCCESS : GetLastError();
            result.BackendCopyAttemptKnown = true;
            result.BackendCopyAttempted = true;
            result.BackendContract = L"win32_read_process_memory";
            result.TransferredBytesKnown = copied <= request.Length;
            result.TransferredBytes = result.TransferredBytesKnown ? static_cast<uint32_t>(copied) : 0;
            if (SameIdentity())
            {
                result.IdentityRevalidated = true;
                span.State = ObservationReadState::Failed;
                // Failed/short copies are not admitted as a valid prefix.
                if (read && copied == request.Length)
                {
                    span.State = ObservationReadState::Complete;
                    span.Bytes = std::move(bytes);
                }
            }
        }
        result.Spans.push_back(std::move(span));
        return result;
    }

private:
    struct CloseProcess
    {
        void operator()(void* handle) const
        {
            CloseHandle(handle);
        }
    };

    static uint64_t TimeValue(const FILETIME& time)
    {
        return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    }

    bool SameIdentity() const
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        // Exit time is undefined for a live process. The retained handle pins
        // the object; matching identity does not assert current liveness.
        return Process != nullptr && GetProcessId(Process.get()) == Pid &&
            GetProcessTimes(Process.get(), &created, &exited, &kernel, &user) && TimeValue(created) == Creation;
    }

    std::unique_ptr<void, CloseProcess> Process;
    const uint32_t Pid;
    const uint64_t Creation;
    ObservationSourceCapabilities Caps;
};
