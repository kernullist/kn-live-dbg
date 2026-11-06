#pragma once

#include "RecordingObservationSource.h"
#include "ObservationSourceJson.h"

inline std::wstring ObservationReadSetJson(const ObservationReadSet& set)
{
    const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
    const auto b = [](bool value) { return value ? L"true" : L"false"; };
    uint64_t pending = 0, abandoned = 0, validBytes = 0;
    for (const auto& read : set.Reads)
    {
        pending += !read.Completed && !read.Abandoned;
        abandoned += read.Abandoned;
        if (read.Completed)
        {
            for (const auto& span : read.Result.Spans) { validBytes += span.Bytes.size(); }
        }
    }
    const bool complete = set.TotalAttempts == set.Reads.size() && set.UnrecordedAttempts == 0 && pending == 0 && abandoned == 0;
    std::wstring json = L"{\"schema\":\"kn.read_set.v1\",\"operation_id\":" + mcpjson::Quote(set.OperationId) +
        L",\"target_id\":" + mcpjson::Quote(set.TargetId) + L",\"address_space_id\":" + mcpjson::Quote(set.AddressSpaceId) +
        L",\"target_binding\":\"caller_declared_not_qualified_by_recorder\",\"clock_domain\":\"collector_steady_clock_ms\","
        L"\"started_tick\":" + n(set.StartedTick) + L",\"snapshot_tick\":" + n(set.SnapshotTick) +
        L",\"attempts\":" + n(set.TotalAttempts) + L",\"receipts_saved\":" + n(set.Reads.size()) +
        L",\"unrecorded_attempts\":" + n(set.UnrecordedAttempts) + L",\"pending_receipts\":" + n(pending) +
        L",\"abandoned_receipts\":" + n(abandoned) + L",\"recording_complete\":" + b(complete) +
        L",\"charged_source_calls\":" + n(set.ChargedSourceCalls) + L",\"charged_requested_bytes\":" + n(set.ChargedBytes) +
        L",\"stored_spans\":" + n(set.StoredSpans) + L",\"reserved_span_slots\":" + n(set.ReservedSpanSlots) +
        L",\"stored_valid_bytes_with_repeats\":" + n(validBytes) + L",\"cancelled\":" + b(set.Cancelled) +
        L",\"deadline_exceeded\":" + b(set.DeadlineExceeded) +
        L",\"budget\":{\"maximum_bytes\":" + n(set.Budget.MaximumBytes) +
        L",\"maximum_source_calls\":" + n(set.Budget.MaximumSourceCalls) +
        L",\"maximum_receipts\":" + n(set.Budget.MaximumReceipts) +
        L",\"maximum_stored_spans\":" + n(set.Budget.MaximumStoredSpans) +
        L",\"maximum_elapsed_ms\":" + n(set.Budget.MaximumElapsedMs) + L"},"
        L"\"collector_authenticated\":false,\"execution_observed\":false,\"mapping_lifetime_bound\":false,"
        L"\"consistency\":\"ordered_attempts_not_atomic_snapshot\",\"reads\":[";
    for (const auto& read : set.Reads)
    {
        if (&read != &set.Reads.front()) { json += L","; }
        const auto& space = read.Source.AddressSpace;
        json += L"{\"sequence\":" + n(read.Sequence) + L",\"completed\":" + b(read.Completed) +
            L",\"abandoned\":" + b(read.Abandoned) + L",\"source_invoked\":" + b(read.SourceInvoked) +
            L",\"deadline_exceeded\":" + b(read.DeadlineExceeded) + L",\"admission_reason\":" + mcpjson::Quote(read.AdmissionReason) +
            L",\"requested_source_id\":" + mcpjson::Quote(read.Request.SourceId) +
            L",\"source_id_at_admission\":" + mcpjson::Quote(read.Source.SourceId) +
            L",\"address\":" + n(read.Request.Address) + L",\"requested_bytes\":" + n(read.Request.Length) +
            L",\"per_read_byte_budget\":" + n(read.Request.ByteBudget) +
            L",\"residency_consent\":" + b(read.Request.AllowResidencyChanges) +
            L",\"address_shape\":{\"virtual_bits\":" + n(space.VirtualAddressBits) +
            L",\"pointer_bytes\":" + n(space.PointerBytes) + L",\"physical_bits\":" +
            (space.PhysicalAddressBits == 0 ? std::wstring(L"null") : n(space.PhysicalAddressBits)) +
            L",\"legacy_assumed\":" + b(space.LegacyAssumed) + L",\"user_maximum\":" + n(space.UserMaximum) +
            L",\"kernel_minimum\":" + n(space.KernelMinimum) + L"},\"fallback\":";
        if (read.Request.FallbackFromReceipt == 0)
        {
            json += L"null";
        }
        else
        {
            json += L"{\"from_receipt\":" + n(read.Request.FallbackFromReceipt) +
                L",\"reason\":" + mcpjson::Quote(read.Request.FallbackReason) +
                L",\"permission_requested\":" + b(read.Request.AllowFallback) +
                L",\"permitted\":" + b(read.FallbackPermitted) + L"}";
        }
        json += L",\"read\":" + (read.Completed ? ObservationReadJson(read.Source, read.Request, read.Result) : L"null") + L"}";
    }
    return json + L"]}";
}
