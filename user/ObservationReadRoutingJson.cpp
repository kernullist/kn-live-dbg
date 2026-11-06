#include "ObservationReadRoutingJson.h"
#include "ObservationReadSetParser.h"
#include "BoundedObservationJson.h"
#include <map>

using namespace bounded_observation_json;

namespace
{
    bool ValidSpans(const ObservationReadRequest& q, const ObservationReadResult& r)
    {
        if (r.Spans.empty()) { return r.State >= ObservationReadState::NotCaptured && r.State <= ObservationReadState::Cancelled; }
        uint64_t consumed = 0;
        bool same = true;
        for (const auto& span : r.Spans)
        {
            if (span.RequestedBytes == 0 || span.RequestedBytes > q.Length - consumed || span.Address != q.Address + consumed ||
                span.State == ObservationReadState::Partial || span.State < ObservationReadState::Complete || span.State > ObservationReadState::Cancelled ||
                (span.State == ObservationReadState::Complete ? span.Bytes.size() != span.RequestedBytes : !span.Bytes.empty())) { return false; }
            consumed += span.RequestedBytes;
            same &= span.State == r.Spans.front().State;
        }
        return consumed == q.Length && r.State == (same ? r.Spans.front().State : ObservationReadState::Partial);
    }

    bool ValidAttempts(const ObservationReadSet& set)
    {
        const auto& b = set.Budget;
        if (!Text(set.OperationId, 256) || !Text(set.TargetId, 2048) || !Text(set.AddressSpaceId, 2048) ||
            b.MaximumBytes > 16 * 1024 * 1024 || b.MaximumSourceCalls > 4096 || b.MaximumReceipts == 0 || b.MaximumReceipts > 4096 ||
            b.MaximumStoredSpans > 65536 || b.MaximumElapsedMs == 0 || b.MaximumElapsedMs > 60000 ||
            set.Reads.size() > b.MaximumReceipts || set.TotalAttempts != set.Reads.size() || set.UnrecordedAttempts != 0 ||
            set.ReservedSpanSlots != 0 || set.SnapshotTick < set.StartedTick || set.ChargedBytes > b.MaximumBytes ||
            set.ChargedSourceCalls > b.MaximumSourceCalls || set.StoredSpans > b.MaximumStoredSpans ||
            set.DeadlineExceeded != (set.SnapshotTick - set.StartedTick >= b.MaximumElapsedMs)) { return false; }
        uint64_t bytes = 0, calls = 0, spans = 0, tick = set.StartedTick;
        std::map<std::wstring, ObservationSourceCapabilities> contracts;
        for (size_t i = 0; i < set.Reads.size(); ++i)
        {
            const auto& receipt = set.Reads[i];
            const auto& s = receipt.Source;
            const auto& q = receipt.Request;
            const auto& r = receipt.Result;
            if (receipt.Sequence != i + 1 || !receipt.Completed || receipt.Abandoned ||
                !Text(s.SourceId, 1024) || !Text(s.Consistency, 128) || s.AddressDomain != ObservationAddressDomain::Virtual ||
                !s.AddressSpace.Valid() || (s.UserOnly && s.KernelOnly) || s.MaximumReadBytes == 0 || s.MaximumReadBytes > 4096 ||
                q.Cancellation != nullptr || q.SourceId != s.SourceId || q.Length == 0 || q.Length > 4096 || q.Address > UINT64_MAX - q.Length ||
                q.ByteBudget > 16 * 1024 * 1024 || r.SourceId != s.SourceId || r.Consistency != s.Consistency ||
                r.ReadReceiptId != receipt.Sequence || r.OperationId != set.OperationId || r.ClockDomain != L"collector_steady_clock_ms" ||
                r.StartedTick < tick || r.EndedTick < r.StartedTick || r.EndedTick > set.SnapshotTick ||
                (receipt.DeadlineExceeded && !r.OperationDeadlineExceeded) ||
                r.SideEffectsPossible != (receipt.SourceInvoked && s.MayChangeResidency) ||
                !Text(receipt.AdmissionReason, 128) || !Text(r.NativeStatusDomain, 64) || !Text(r.BackendContract, 256, true) ||
                !Text(r.ValidationReason, 256, true) || !ValidSpans(q, r) ||
                (!r.TransferredBytesKnown && r.TransferredBytes != 0) || (r.TransferredBytesKnown && r.TransferredBytes > q.Length) ||
                (!r.TransportAttempted && (r.TransportSucceeded || r.TransportStatus != 0)) ||
                (!r.BackendCopyAttemptKnown && r.BackendCopyAttempted) || (r.NativeStatusDomain == L"unavailable" && r.NativeStatus != 0)) { return false; }
            const auto contract = contracts.emplace(s.SourceId, s);
            if (!contract.second && !SameObservationSourceContract(contract.first->second, s)) { return false; }
            if (receipt.SourceInvoked)
            {
                if (receipt.AdmissionReason != L"delegated_to_source" || q.Length > q.ByteBudget || q.Length > s.MaximumReadBytes ||
                    !ObservationRangeSupported(s, q.Address, q.Length) || (s.MayChangeResidency && !q.AllowResidencyChanges)) { return false; }
                bytes += q.Length;
                ++calls;
            }
            else if (!r.Spans.empty() || r.IdentityRevalidated || r.TransferredBytesKnown || r.TransportAttempted ||
                r.BackendCopyAttemptKnown || r.NativeStatusDomain != L"unavailable") { return false; }
            spans += r.Spans.size();
            tick = r.EndedTick;
        }
        return bytes == set.ChargedBytes && calls == set.ChargedSourceCalls && spans == set.StoredSpans;
    }
}

bool ValidObservationRoutedReadSet(const ObservationRoutedReadSet& routed)
{
    const auto& set = routed.Attempts;
    if (routed.UnrecordedParserCalls != 0 || routed.ParserReads.size() > set.Budget.MaximumReceipts || !ValidAttempts(set)) { return false; }
    size_t cursor = 0;
    for (const auto& call : routed.ParserReads)
    {
        if (call.Length == 0 || call.Length > 4096 || call.Address > UINT64_MAX - call.Length || !Text(call.Reason, 128) ||
            (call.BeforeGuard != L"not_requested" && call.BeforeGuard != L"not_run" && call.BeforeGuard != L"passed" && call.BeforeGuard != L"failed") ||
            (call.AfterGuard != L"not_requested" && call.AfterGuard != L"passed" && call.AfterGuard != L"failed")) { return false; }
        if (call.PrimaryReceipt == 0)
        {
            if (call.ReturnedReceipt != 0 || call.Accepted || call.AfterGuard != L"not_requested") { return false; }
            continue;
        }
        if (cursor == set.Reads.size() || call.PrimaryReceipt != cursor + 1 ||
            (call.BeforeGuard != L"not_requested" && call.BeforeGuard != L"passed")) { return false; }
        const auto& primary = set.Reads[cursor++];
        if (primary.Request.FallbackFromReceipt != 0 || primary.Request.AllowFallback || primary.FallbackPermitted ||
            !primary.Request.FallbackReason.empty() || primary.Request.Address != call.Address || primary.Request.Length != call.Length) { return false; }
        const ObservationReadReceipt* returned = &primary;
        if (call.ReturnedReceipt != call.PrimaryReceipt)
        {
            if (cursor == set.Reads.size() || call.ReturnedReceipt != cursor + 1 || !ObservationFallbackEligible(primary.Result)) { return false; }
            returned = &set.Reads[cursor++];
            auto comparable = returned->Source;
            comparable.SourceId = primary.Source.SourceId;
            comparable.Consistency = primary.Source.Consistency;
            comparable.MaximumReadBytes = primary.Source.MaximumReadBytes;
            comparable.MayChangeResidency = primary.Source.MayChangeResidency;
            if (!SameObservationSourceContract(comparable, primary.Source) || returned->Source.SourceId == primary.Source.SourceId ||
                returned->Request.Address != call.Address || returned->Request.Length != call.Length ||
                returned->Request.FallbackFromReceipt != primary.Sequence || !returned->Request.AllowFallback || !returned->FallbackPermitted ||
                returned->Request.FallbackReason != L"primary_exact_read_unavailable") { return false; }
        }
        if (call.Accepted && (returned->Result.State != ObservationReadState::Complete || returned->Result.CancellationObserved ||
            returned->Result.OperationDeadlineExceeded || (call.AfterGuard != L"not_requested" && call.AfterGuard != L"passed") ||
            call.Reason != (returned == &primary ? L"primary_result" : L"explicit_fallback_result"))) { return false; }
    }
    return cursor == set.Reads.size();
}

bool ParseObservationRoutedReadSet(const std::wstring& json, ObservationRoutedReadSet* out)
{
    if (out == nullptr || json.size() > 2 * 1024 * 1024 || !mcpjson::ValidateDocument(json)) { return false; }
    ObservationRoutedReadSet set;
    std::wstring attempts;
    std::vector<std::wstring> rows;
    if (!Number(json, L"unrecorded_parser_calls", &set.UnrecordedParserCalls) ||
        !mcpjson::FindRawValue(json, L"attempts", &attempts) || !ParseObservationReadSet(attempts, 4096, &set.Attempts) ||
        !Array(json, L"parser_reads", 4096, &rows)) { return false; }
    for (const auto& row : rows)
    {
        ObservationParserRead call;
        if (!Number(row, L"address", &call.Address) || !Number(row, L"length", &call.Length) ||
            !Number(row, L"primary_receipt", &call.PrimaryReceipt) || !Number(row, L"returned_receipt", &call.ReturnedReceipt) ||
            !Boolean(row, L"accepted", &call.Accepted) || !mcpjson::GetString(row, L"before_guard", &call.BeforeGuard) ||
            !mcpjson::GetString(row, L"after_guard", &call.AfterGuard) || !mcpjson::GetString(row, L"reason", &call.Reason)) { return false; }
        set.ParserReads.push_back(std::move(call));
    }
    if (!ValidObservationRoutedReadSet(set) || ObservationRoutedReadSetJson(set) != json) { return false; }
    *out = std::move(set);
    return true;
}
