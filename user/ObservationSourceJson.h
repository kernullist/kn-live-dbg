#pragma once

#include "ObservationSource.h"
#include "McpJson.h"

inline const wchar_t* ObservationReadStateName(ObservationReadState state)
{
    switch (state)
    {
    case ObservationReadState::Complete: return L"complete";
    case ObservationReadState::Partial: return L"partial";
    case ObservationReadState::NotCaptured: return L"not_captured";
    case ObservationReadState::NotPresent: return L"not_present";
    case ObservationReadState::Failed: return L"read_failed";
    case ObservationReadState::Conflict: return L"conflict";
    case ObservationReadState::Skipped: return L"skipped";
    case ObservationReadState::PolicyDenied: return L"policy_denied";
    case ObservationReadState::IdentityChanged: return L"identity_changed";
    case ObservationReadState::Unsupported: return L"unsupported";
    case ObservationReadState::BudgetDeferred: return L"budget_deferred";
    case ObservationReadState::Cancelled: return L"cancelled";
    default: return L"unsupported";
    }
}

inline std::wstring ObservationReadJson(const ObservationSourceCapabilities& caps,
    const ObservationReadRequest& request, const ObservationReadResult& result)
{
    std::wstring json = L"{\"schema\":\"kn.observation_read.v1\",\"status\":" +
        mcpjson::Quote(ObservationReadStateName(result.State)) + L",\"source_id\":" + mcpjson::Quote(result.SourceId) +
        L",\"consistency\":" + mcpjson::Quote(result.Consistency) + L",\"address\":" + mcpjson::Quote(std::to_wstring(request.Address)) +
        L",\"requested_bytes\":" + std::to_wstring(request.Length) + L",\"address_domain\":" +
        mcpjson::Quote(caps.AddressDomain == ObservationAddressDomain::Physical ? L"physical" : L"virtual") +
        L",\"physical_address_bits\":" + (caps.AddressSpace.PhysicalAddressBits == 0 ? std::wstring(L"null") : std::to_wstring(caps.AddressSpace.PhysicalAddressBits)) +
        L",\"virtual_address_bits\":" + (caps.AddressDomain == ObservationAddressDomain::Physical ? std::wstring(L"null") : std::to_wstring(caps.AddressSpace.VirtualAddressBits)) + L",\"clock_domain\":" + mcpjson::Quote(result.ClockDomain) +
        L",\"started_tick\":" + mcpjson::Quote(std::to_wstring(result.StartedTick)) +
        L",\"ended_tick\":" + mcpjson::Quote(std::to_wstring(result.EndedTick)) +
        L",\"side_effects_possible\":" + (result.SideEffectsPossible ? L"true" : L"false") +
        L",\"cancellation_observed\":" + (result.CancellationObserved ? L"true" : L"false") +
        L",\"operation_deadline_exceeded\":" + (result.OperationDeadlineExceeded ? L"true" : L"false") +
        L",\"identity_revalidated\":" + (result.IdentityRevalidated ? L"true" : L"false") +
        L",\"native_status_domain\":" + mcpjson::Quote(result.NativeStatusDomain) +
        L",\"native_status\":" + (result.NativeStatusDomain == L"unavailable" ? std::wstring(L"null") : std::to_wstring(result.NativeStatus)) +
        L",\"transferred_bytes\":" + (result.TransferredBytesKnown ? std::to_wstring(result.TransferredBytes) : std::wstring(L"null")) +
        L",\"transport_status_domain\":" + mcpjson::Quote(result.TransportAttempted ? L"win32" : L"unavailable") +
        L",\"transport_status\":" + (result.TransportAttempted ? std::to_wstring(result.TransportStatus) : std::wstring(L"null")) +
        L",\"transport_succeeded\":" + (result.TransportAttempted ? (result.TransportSucceeded ? std::wstring(L"true") : std::wstring(L"false")) : std::wstring(L"null")) +
        L",\"backend_copy_attempted\":" + (result.BackendCopyAttemptKnown ? (result.BackendCopyAttempted ? std::wstring(L"true") : std::wstring(L"false")) : std::wstring(L"null")) +
        L",\"native_read_kind\":" + (result.NativeReadKind == 0 ? std::wstring(L"null") : std::to_wstring(result.NativeReadKind)) +
        L",\"driver_abi\":" + (result.DriverAbi == 0 ? std::wstring(L"null") : std::to_wstring(result.DriverAbi)) +
        L",\"source_epoch\":" + mcpjson::Quote(std::to_wstring(result.SourceEpoch)) +
        L",\"backend_contract\":" + mcpjson::Quote(result.BackendContract) +
        L",\"validation_reason\":" + mcpjson::Quote(result.ValidationReason) +
        L",\"operation_id\":" + mcpjson::Quote(result.OperationId) +
        L",\"read_receipt_id\":" + mcpjson::Quote(std::to_wstring(result.ReadReceiptId)) +
        L",\"collector_authenticated\":false,\"spans\":[";
    for (const auto& span : result.Spans)
    {
        if (&span != &result.Spans.front())
        {
            json += L",";
        }
        std::wstring hex;
        for (const auto byte : span.Bytes)
        {
            hex += L"0123456789abcdef"[byte >> 4];
            hex += L"0123456789abcdef"[byte & 15];
        }
        json += L"{\"address\":" + mcpjson::Quote(std::to_wstring(span.Address)) +
            L",\"requested_bytes\":" + std::to_wstring(span.RequestedBytes) + L",\"state\":" +
            mcpjson::Quote(ObservationReadStateName(span.State)) + L",\"bytes_hex\":" + mcpjson::Quote(hex) + L"}";
    }
    return json + L"]}";
}
