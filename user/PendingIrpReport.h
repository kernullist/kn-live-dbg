#pragma once

#include "PendingIrpScanner.h"
#include "McpJson.h"

// Graph IDs are local to one observation. Address equality does not join
// objects between reports or establish a referenced allocation lifetime.
inline std::wstring PendingIrpObservationJson(const PendingIrpRequestObservation& request,
    const PendingIrpScanResult& scan)
{
    const auto number = [](uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    };
    const auto flag = [](const std::optional<bool>& value)
    {
        return value.has_value() ? (*value ? L"true" : L"false") : L"null";
    };
    const auto pointer = [&](const std::optional<uint64_t>& value)
    {
        return value.has_value() ? number(*value) : L"null";
    };
    std::wstring out = L"{\"schema\":\"kn.irp_observation.v1\",\"policy\":\"repeated-snapshot-v1\"";
    out += L",\"state\":\"RequestObserved\",\"outcome\":\"UnknownOutcome\",\"transitions\":[]";
    out += L",\"atomic\":false,\"referenced_lifetime\":false,\"execution_observed\":false";
    out += L",\"actor_attributed\":false,\"deadlock_established\":false,\"global_inventory\":false";
    out += L",\"identity_scope\":\"single_observation\",\"clock\":\"collector_boot_tick_ms\"";
    out += L",\"started_tick_ms\":" + number(scan.ScanStartedTickMs);
    out += L",\"finished_tick_ms\":" + number(scan.ScanFinishedTickMs);
    out += L",\"enumeration_complete\":" + std::wstring(scan.CoverageComplete ? L"true" : L"false");
    out += L",\"threads_visited\":" + std::to_wstring(scan.ThreadsVisited);
    out += L",\"irps_inspected\":" + std::to_wstring(scan.IrpsInspected);
    out += L",\"unstable_observations\":" + std::to_wstring(scan.UnstableObservations);
    out += L",\"virtual_address_bits\":" + std::to_wstring(scan.AddressSpace.VirtualAddressBits);
    out += L",\"address_format_assumed\":" + std::wstring(scan.AddressSpace.LegacyAssumed ? L"true" : L"false");
    out += L",\"layout_from_pdb\":" + std::wstring(scan.LayoutFromPdb ? L"true" : L"false");
    out += L",\"coverage_scope\":" + mcpjson::Quote(scan.CoverageScope);
    out += L",\"pid\":" + std::to_wstring(request.Thread.ProcessId);
    out += L",\"tid\":" + std::to_wstring(request.Thread.ThreadId);
    out += L",\"thread_create_time\":" + number(request.ThreadCreateTime);
    out += L",\"thread_time_format\":\"windows_filetime\",\"process_create_time\":null";
    out += L",\"irp\":" + number(request.Irp) + L",\"thread\":" + number(request.Thread.ThreadObject);
    out += L",\"cancel_flag\":" + std::wstring(flag(request.CancelFlag));
    out += L",\"pending_returned\":" + std::wstring(flag(request.PendingReturned));
    out += L",\"io_status\":" + (request.IoStatus.has_value() ? std::to_wstring(*request.IoStatus) : L"null");
    out += L",\"stack_count\":" + std::to_wstring(request.StackCount);
    out += L",\"current_location\":" + std::to_wstring(request.CurrentLocation);
    out += L",\"stacks_total\":" + std::to_wstring(request.Stacks.size());
    out += L",\"stacks_truncated\":" + std::wstring(request.Stacks.size() > 64 ? L"true" : L"false");
    std::wstring nodes = L"[{\"id\":\"thread\",\"kind\":\"thread_observation\",\"address\":" +
        number(request.Thread.ThreadObject) + L"},{\"id\":\"request\",\"kind\":\"irp_observation\",\"address\":" + number(request.Irp) + L"}";
    std::wstring edges = L"[{\"from\":\"thread\",\"to\":\"request\",\"kind\":\"thread_list_member_observed\"}";
    out += L",\"stacks\":[";
    for (size_t i = 0; i < request.Stacks.size() && i < 64; ++i)
    {
        if (i != 0)
        {
            out += L",";
        }
        const auto& stack = request.Stacks[i];
        const std::wstring id = L"stack_" + std::to_wstring(i);
        const bool completionRegistered = (stack.Control & 0xe0) != 0 && stack.CompletionRoutine != 0;
        out += L"{\"index\":" + std::to_wstring(stack.Index) + L",\"address\":" + number(stack.Address);
        out += L",\"major\":" + std::to_wstring(stack.MajorFunction) + L",\"minor\":" + std::to_wstring(stack.MinorFunction);
        out += L",\"control\":" + std::to_wstring(stack.Control) + L",\"context\":" + number(stack.Context);
        out += L",\"completion\":" + number(stack.CompletionRoutine);
        out += L",\"completion_registered\":" + std::wstring(completionRegistered ? L"true" : L"false");
        out += L",\"device\":" + pointer(stack.DeviceObject) + L",\"file\":" + pointer(stack.FileObject) + L"}";
        nodes += L",{\"id\":" + mcpjson::Quote(id) + L",\"kind\":\"stack_location_observation\",\"address\":" + number(stack.Address) + L"}";
        edges += L",{\"from\":\"request\",\"to\":" + mcpjson::Quote(id) + L",\"kind\":\"stack_location_observed\"}";
        const auto reference = [&](const wchar_t* suffix, const wchar_t* kind, std::optional<uint64_t> address)
        {
            if (!address.has_value() || !scan.AddressSpace.KernelRange(*address, 1))
            {
                return;
            }
            const std::wstring target = id + suffix;
            nodes += L",{\"id\":" + mcpjson::Quote(target) + L",\"kind\":" + mcpjson::Quote(kind) +
                L",\"address\":" + number(*address) + L",\"object_validated\":false}";
            edges += L",{\"from\":" + mcpjson::Quote(id) + L",\"to\":" + mcpjson::Quote(target) +
                L",\"kind\":\"pointer_reference_observed\"}";
        };
        reference(L"_device", L"device_pointer", stack.DeviceObject);
        reference(L"_file", L"file_pointer", stack.FileObject);
        if (completionRegistered)
        {
            reference(L"_completion", L"completion_pointer", stack.CompletionRoutine);
        }
    }
    out += L"],\"graph\":{\"id_scope\":\"single_observation\",\"nodes\":" + nodes + L"],\"edges\":" + edges + L"]}";
    out += L",\"missing_evidence\":[\"referenced_request_lifetime\",\"dispatch_completion_events\",\"atomic_wait_graph\"]}";
    return out;
}
