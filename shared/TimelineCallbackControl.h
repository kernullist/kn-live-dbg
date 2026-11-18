#pragma once

#include "KnLiveDbgIoctl.h"
#include <string.h>

// Called under the timeline control mutex. Publish atomically updates the mask
// exposed to status readers and to the event-delivery gate.
namespace timeline_callbacks
{
    constexpr KNDBG_UINT32 Process = KNDBG_TIMELINE_STATUS_PROCESS_CALLBACK;
    constexpr KNDBG_UINT32 Image = KNDBG_TIMELINE_STATUS_IMAGE_CALLBACK;
    constexpr KNDBG_UINT32 Thread = KNDBG_TIMELINE_STATUS_THREAD_CALLBACK;
    constexpr KNDBG_UINT32 Active = KNDBG_TIMELINE_STATUS_ACTIVE;
    constexpr KNDBG_UINT32 Registered = Process | Image | Thread;
    constexpr KNDBG_UINT32 ProcedureNotFound = 0xc000007au;
    constexpr KNDBG_UINT32 Unsuccessful = 0xc0000001u;
    // A failed stop can leave three residual removals before three installation
    // calls and two rollback calls in a single subsequent start.
    static_assert(KNDBG_TIMELINE_MAX_CALLBACK_CALLS >= 3 + 3 + 2);

    inline KNDBG_UINT32 Prepare(const void* buffer, KNDBG_UINT32 inputBytes, KNDBG_UINT32 outputBytes, bool writable,
        KNDBG_TIMELINE_CONTROL_RECEIPT& receipt, bool& detailed)
    {
        constexpr KNDBG_UINT32 invalid = 0xc000000du, tooSmall = 0xc0000023u, denied = 0xc0000022u;
        detailed = false;
        if (!buffer || inputBytes < sizeof(receipt.Request)) { return invalid; }
        memcpy(&receipt.Request, buffer, sizeof(receipt.Request));
        const auto& request = receipt.Request;
        if (request.Size < sizeof(request) || request.Size > inputBytes) { return invalid; }
        if (outputBytes < sizeof(request)) { return tooSmall; }
        if (!writable || request.Acknowledge != KNDBG_WRITE_ACK_MAGIC) { return denied; }
        if (request.Size == sizeof(request) || request.Flags != KNDBG_TIMELINE_CONTROL_WANT_RECEIPT) { return 0; }
        if (request.Size != sizeof(KNDBG_TIMELINE_RECEIPT_REQUEST)) { return invalid; }
        KNDBG_TIMELINE_RECEIPT_REQUEST extended{};
        memcpy(&extended, buffer, sizeof(extended));
        if (extended.Version != KNDBG_TIMELINE_CONTROL_RECEIPT_VERSION || extended.ReceiptSize != sizeof(receipt) || !extended.RequestId)
        { return invalid; }
        if (outputBytes < sizeof(receipt)) { return tooSmall; }
        receipt.Size = sizeof(receipt);
        receipt.Version = extended.Version;
        receipt.RequestId = extended.RequestId;
        detailed = true;
        return 0;
    }

    inline KNDBG_UINT32 Failure(KNDBG_UINT32 status)
    {
        return (status & 0x80000000u) ? status : Unsuccessful;
    }

    template <typename Call>
    KNDBG_UINT32 Invoke(KNDBG_TIMELINE_CONTROL_RECEIPT& receipt, KNDBG_UINT32 flag, bool remove, Call& call)
    {
        auto& entry = receipt.Calls[receipt.CallCount++];
        entry.CallbackFlag = flag;
        entry.Remove = remove ? 1u : 0u;
        entry.NtStatus = call(flag, remove, entry.RequestedUtcFileTime, entry.ReturnedUtcFileTime);
        return entry.NtStatus;
    }

    template <typename Call, typename Publish>
    KNDBG_UINT32 Stop(KNDBG_TIMELINE_CONTROL_RECEIPT& receipt, Call& call, Publish& publish)
    {
        receipt.AfterFlags &= ~Active;
        publish(receipt.AfterFlags);
        KNDBG_UINT32 failure = 0;
        const KNDBG_UINT32 order[] = {Thread, Process, Image};
        for (auto flag : order)
        {
            if (!(receipt.AfterFlags & flag)) { continue; }
            const KNDBG_UINT32 status = Invoke(receipt, flag, true, call);
            if (status == 0 || (flag != Process && status == ProcedureNotFound))
            {
                receipt.AfterFlags &= ~flag;
                publish(receipt.AfterFlags);
            }
            else if (!failure) { failure = Failure(status); }
        }
        return failure;
    }

    template <typename Call, typename Publish>
    KNDBG_UINT32 Start(KNDBG_TIMELINE_CONTROL_RECEIPT& receipt, Call& call, Publish& publish)
    {
        if (receipt.AfterFlags == (Registered | Active)) { return 0; }
        if (receipt.AfterFlags & Registered)
        {
            const auto cleanup = Stop(receipt, call, publish);
            if (cleanup) { return cleanup; }
        }
        const KNDBG_UINT32 order[] = {Process, Image, Thread};
        for (auto flag : order)
        {
            const KNDBG_UINT32 status = Invoke(receipt, flag, false, call);
            if (status)
            {
                Stop(receipt, call, publish);
                return Failure(status);
            }
            receipt.AfterFlags |= flag;
            publish(receipt.AfterFlags);
        }
        receipt.AfterFlags |= Active;
        publish(receipt.AfterFlags);
        return 0;
    }
}
