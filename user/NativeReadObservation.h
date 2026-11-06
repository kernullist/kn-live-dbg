#pragma once

#include <Windows.h>
#include "../shared/KnLiveDbgReadObservation.h"
#include "ObservationSource.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

struct NativeReadObservation
{
    bool Legacy = false;
    bool TransportAttempted = false;
    bool TransportSucceeded = false;
    uint32_t TransportStatus = 0;
    bool ResponseValidated = false;
    bool CopyAttempted = false;
    bool IdentityValidated = false;
    bool TransferredKnown = false;
    uint32_t Requested = 0;
    uint32_t Transferred = 0;
    uint32_t DriverAbi = 0;
    uint32_t Kind = 0;
    uint64_t SourceEpoch = 0;
    std::wstring Contract = L"unavailable";
    std::wstring StatusDomain = L"unavailable";
    uint32_t RawStatus = 0;
    std::wstring Rejection;
    std::vector<uint8_t> Bytes;
};

// Production transport orchestration is also exercised with an owned responder.
// An advertised extension failure never triggers an unrecorded legacy retry.
template<typename Transport>
NativeReadObservation ReadNativeObservation(const KNDBG_OBSERVATION_READ_REQUEST& request,
    bool extended, Transport transport)
{
    NativeReadObservation result;
    result.Requested = request.Length;
    result.SourceEpoch = request.SourceEpoch;
    result.Kind = request.Kind;
    result.Legacy = !extended;
    result.Contract = extended ? L"abi17_read_observation_v1" : L"abi17_legacy_raw_ntstatus_unavailable";
    if (!KnDbgObservationReadShapeValid(request))
    {
        result.Rejection = L"invalid_native_read_request";
        return result;
    }
    if (request.Kind != KNDBG_READ_OBSERVATION_PHYSICAL &&
        (request.Flags & KNDBG_READ_OBSERVATION_ALLOW_RESIDENCY) == 0)
    {
        result.Rejection = L"residency_consent_required";
        return result;
    }
    const DWORD header = extended ? static_cast<DWORD>(offsetof(KNDBG_OBSERVATION_READ_RESPONSE, Data)) :
        request.Kind == KNDBG_READ_OBSERVATION_PROCESS ? static_cast<DWORD>(offsetof(KNDBG_PROCESS_VIRTUAL_READ_REQUEST, Data)) :
        static_cast<DWORD>(offsetof(KNDBG_READ_REQUEST, Data));
    const DWORD outputLength = header + request.Length;
    std::vector<uint8_t> buffer(outputLength);
    DWORD code = IOCTL_KNDBG_READ_OBSERVATION;
    DWORD inputLength = sizeof(request);
    if (extended)
    {
        std::memcpy(buffer.data(), &request, sizeof(request));
    }
    else if (request.Kind == KNDBG_READ_OBSERVATION_PROCESS)
    {
        code = IOCTL_KNDBG_READ_PROCESS_VIRTUAL;
        KNDBG_PROCESS_VIRTUAL_READ_REQUEST legacy{};
        legacy.Size = header;
        legacy.ProcessId = request.ProcessId;
        legacy.ExpectedEprocess = request.ExpectedEprocess;
        legacy.ExpectedCreateTime = request.ExpectedCreateTime;
        legacy.Address = request.Address;
        legacy.Length = request.Length;
        inputLength = header;
        std::memcpy(buffer.data(), &legacy, header);
    }
    else
    {
        code = request.Kind == KNDBG_READ_OBSERVATION_PHYSICAL ? IOCTL_KNDBG_READ_PHYSICAL : IOCTL_KNDBG_READ_VIRTUAL;
        KNDBG_READ_REQUEST legacy{};
        legacy.Size = header;
        legacy.Address = request.Address;
        legacy.Length = request.Length;
        inputLength = header;
        std::memcpy(buffer.data(), &legacy, header);
    }
    DWORD returned = 0, error = ERROR_SUCCESS;
    result.TransportAttempted = true;
    result.TransportSucceeded = transport(code, buffer.data(), inputLength, outputLength, &returned, &error);
    result.TransportStatus = error;
    if (!result.TransportSucceeded)
    {
        result.StatusDomain = L"win32";
        result.RawStatus = error;
        result.Rejection = L"native_transport_failed";
        return result;
    }
    if (error != ERROR_SUCCESS || returned < header || returned > outputLength)
    {
        result.Rejection = L"invalid_native_read_response";
        return result;
    }
    uint32_t copied = 0;
    if (extended)
    {
        KNDBG_OBSERVATION_READ_RESPONSE response{};
        std::memcpy(&response, buffer.data(), header);
        if (!KnDbgObservationReadResponseBound(request, response, returned))
        {
            result.Rejection = L"invalid_native_read_response";
            return result;
        }
        result.StatusDomain = L"ntstatus";
        result.RawStatus = response.RawStatus;
        result.CopyAttempted = (response.ResultFlags & KNDBG_READ_OBSERVATION_COPY_ATTEMPTED) != 0;
        result.IdentityValidated = (response.ResultFlags & KNDBG_READ_OBSERVATION_IDENTITY_VALIDATED) != 0;
        result.DriverAbi = response.DriverAbi;
        copied = response.Transferred;
        if ((response.ResultFlags & KNDBG_READ_OBSERVATION_IDENTITY_MISMATCH) != 0)
        {
            result.Rejection = L"native_process_identity_mismatch";
        }
        else if ((response.ResultFlags & KNDBG_READ_OBSERVATION_POLICY_DENIED) != 0)
        {
            result.Rejection = L"native_read_policy_denied";
        }
    }
    else if (request.Kind == KNDBG_READ_OBSERVATION_PROCESS)
    {
        KNDBG_PROCESS_VIRTUAL_READ_REQUEST response{};
        std::memcpy(&response, buffer.data(), header);
        if (response.Size != outputLength || response.Flags != 0 || response.Reserved != 0 || response.Reserved2 != 0 ||
            response.ProcessId != request.ProcessId || response.ExpectedEprocess != request.ExpectedEprocess ||
            response.ExpectedCreateTime != request.ExpectedCreateTime || response.Address != request.Address ||
            response.Length != request.Length || returned != outputLength)
        {
            result.Rejection = L"invalid_legacy_read_response";
            return result;
        }
        copied = response.Length;
        result.IdentityValidated = true;
    }
    else
    {
        KNDBG_READ_REQUEST response{};
        std::memcpy(&response, buffer.data(), header);
        if (response.Size != outputLength || response.Reserved != 0 || response.Flags != 0 ||
            response.Address != request.Address || response.Length > request.Length || returned != header + response.Length)
        {
            result.Rejection = L"invalid_legacy_read_response";
            return result;
        }
        copied = response.Length;
    }
    result.ResponseValidated = true;
    result.TransferredKnown = true;
    result.Transferred = copied;
    if (!extended)
    {
        result.CopyAttempted = true;
        result.DriverAbi = KNDBG_ABI_VERSION; // Caller must qualify the version before using this transport.
    }
    result.Bytes.assign(buffer.begin() + header, buffer.begin() + header + copied);
    if (extended && ((result.RawStatus == 0) != (copied == request.Length)))
    {
        // Keep the bound raw response for diagnostics; it cannot be parser input.
        result.Rejection = L"native_status_length_mismatch";
    }
    return result;
}

inline ObservationReadResult NativeObservationReadResult(uint64_t address, uint32_t length, const NativeReadObservation& native)
{
    ObservationReadResult result;
    result.NativeStatusDomain = native.StatusDomain;
    result.NativeStatus = native.RawStatus;
    result.TransferredBytesKnown = native.TransferredKnown;
    result.TransferredBytes = native.Transferred;
    result.TransportAttempted = native.TransportAttempted;
    result.TransportSucceeded = native.TransportSucceeded;
    result.TransportStatus = native.TransportStatus;
    result.BackendCopyAttemptKnown = native.ResponseValidated;
    result.BackendCopyAttempted = native.CopyAttempted;
    result.NativeReadKind = native.Kind;
    result.DriverAbi = native.DriverAbi;
    result.SourceEpoch = native.SourceEpoch;
    result.BackendContract = native.Contract;
    result.IdentityRevalidated = native.IdentityValidated;
    result.ValidationReason = native.Rejection;
    ObservationReadSpan span{address, length, ObservationReadState::Failed, {}};
    if (native.Rejection == L"native_source_changed" || native.Rejection == L"native_source_not_qualified" ||
        native.Rejection == L"native_process_identity_mismatch")
    {
        span.State = ObservationReadState::IdentityChanged;
    }
    else if (native.Rejection == L"residency_consent_required" || native.Rejection == L"native_read_policy_denied")
    {
        span.State = ObservationReadState::PolicyDenied;
    }
    else if (native.Rejection.empty() && native.ResponseValidated && native.Transferred != 0 &&
        native.Transferred <= length && native.Bytes.size() == native.Transferred)
    {
        span.RequestedBytes = native.Transferred;
        span.State = ObservationReadState::Complete;
        span.Bytes = native.Bytes;
        if (native.Transferred < length)
        {
            result.Spans.push_back(std::move(span));
            span = {address + native.Transferred, length - native.Transferred, ObservationReadState::Failed, {}};
        }
    }
    result.Spans.push_back(std::move(span));
    result.State = result.Spans.size() == 1 ? result.Spans[0].State : ObservationReadState::Partial;
    return result;
}
