#pragma once

#include "KnLiveDbgIoctl.h"
#include <stddef.h>

static_assert(sizeof(KNDBG_OBSERVATION_READ_REQUEST) == 64, "read request ABI");
static_assert(offsetof(KNDBG_OBSERVATION_READ_RESPONSE, Data) == 96, "read response ABI");

inline bool KnDbgObservationReadShapeValid(const KNDBG_OBSERVATION_READ_REQUEST& r)
{
    if (r.Size != sizeof(r) || r.Version != KNDBG_READ_OBSERVATION_VERSION || r.Reserved != 0 ||
        r.Reserved2 != 0 || r.SourceEpoch == 0 || r.Length == 0 || r.Length > KNDBG_READ_OBSERVATION_MAX_BYTES ||
        r.Address > ~KNDBG_UINT64{0} - r.Length || r.Kind < KNDBG_READ_OBSERVATION_KERNEL || r.Kind > KNDBG_READ_OBSERVATION_PHYSICAL)
    {
        return false;
    }
    if (r.Kind == KNDBG_READ_OBSERVATION_PROCESS)
    {
        if (r.ProcessId == 0 || r.ExpectedEprocess == 0 || r.ExpectedCreateTime == 0) { return false; }
    }
    else if (r.ProcessId != 0 || r.ExpectedEprocess != 0 || r.ExpectedCreateTime != 0)
    {
        return false;
    }
    return r.Kind == KNDBG_READ_OBSERVATION_PHYSICAL ? r.Flags == 0 :
        (r.Flags & ~KNDBG_READ_OBSERVATION_ALLOW_RESIDENCY) == 0;
}

inline bool KnDbgObservationReadResponseBound(const KNDBG_OBSERVATION_READ_REQUEST& request,
    const KNDBG_OBSERVATION_READ_RESPONSE& response, size_t returned)
{
    const auto& echo = response.Request;
    const KNDBG_UINT32 flags = KNDBG_READ_OBSERVATION_COPY_ATTEMPTED | KNDBG_READ_OBSERVATION_IDENTITY_VALIDATED |
        KNDBG_READ_OBSERVATION_IDENTITY_MISMATCH | KNDBG_READ_OBSERVATION_POLICY_DENIED;
    const bool mismatch = (response.ResultFlags & KNDBG_READ_OBSERVATION_IDENTITY_MISMATCH) != 0;
    const bool denied = (response.ResultFlags & KNDBG_READ_OBSERVATION_POLICY_DENIED) != 0;
    if ((mismatch || denied) && (response.Transferred != 0 || (response.RawStatus & 0x80000000u) == 0 ||
        (mismatch ? response.ResultFlags != KNDBG_READ_OBSERVATION_IDENTITY_MISMATCH || request.Kind != KNDBG_READ_OBSERVATION_PROCESS :
            response.ResultFlags != KNDBG_READ_OBSERVATION_POLICY_DENIED)))
    {
        return false;
    }
    return KnDbgObservationReadShapeValid(request) && response.Size == offsetof(KNDBG_OBSERVATION_READ_RESPONSE, Data) &&
        response.Version == KNDBG_READ_OBSERVATION_VERSION && response.DriverAbi == KNDBG_ABI_VERSION &&
        response.Reserved == 0 && response.StatusDomain == KNDBG_STATUS_DOMAIN_NTSTATUS && (response.ResultFlags & ~flags) == 0 &&
        response.Transferred <= request.Length && returned == response.Size + response.Transferred &&
        echo.Size == request.Size && echo.Version == request.Version && echo.Flags == request.Flags && echo.Kind == request.Kind &&
        echo.ProcessId == request.ProcessId && echo.Reserved == 0 && echo.Reserved2 == 0 &&
        echo.ExpectedEprocess == request.ExpectedEprocess && echo.ExpectedCreateTime == request.ExpectedCreateTime &&
        echo.Address == request.Address && echo.Length == request.Length && echo.SourceEpoch == request.SourceEpoch &&
        ((response.ResultFlags & KNDBG_READ_OBSERVATION_IDENTITY_VALIDATED) == 0 || request.Kind == KNDBG_READ_OBSERVATION_PROCESS) &&
        (response.Transferred == 0 || ((response.ResultFlags & KNDBG_READ_OBSERVATION_COPY_ATTEMPTED) != 0 &&
            (request.Kind != KNDBG_READ_OBSERVATION_PROCESS || (response.ResultFlags & KNDBG_READ_OBSERVATION_IDENTITY_VALIDATED) != 0)));
}
