#include "ImageRecipeReadSet.h"
#include "ReadReceiptJson.h"
#include "ObservationReadSetParser.h"
#include "BoundedObservationJson.h"
#include <limits>

namespace
{
    bool Text(const std::wstring& text, size_t limit, bool empty = false)
    {
        return (empty || !text.empty()) && text.size() <= limit && text.find(L'\0') == std::wstring::npos &&
            mcpjson::SanitizeUtf16(text) == text;
    }
    using Object = bounded_observation_json::IndexedObject;
    bool Raw(const Object& object, const wchar_t* key, std::wstring* value)
    { return object.Raw(key, value); }
    bool Raw(const Object& object, const wchar_t* key, Object* value)
    {
        std::wstring raw;
        return object.Raw(key, &raw) && value->Parse(raw);
    }
    bool String(const Object& object, const wchar_t* key, std::wstring* value)
    {
        std::wstring raw;
        if (!object.Raw(key, &raw) || raw.empty() || raw.front() != L'"') { return false; }
        *value = mcpjson::Unescape(raw);
        return true;
    }
    template<class T> bool Number(const Object& json, const wchar_t* key, T* value,
        bool quoted = true, bool nullable = false, bool* known = nullptr)
    {
        std::wstring text;
        if (!Raw(json, key, &text)) { return false; }
        if (known != nullptr) { *known = text != L"null"; }
        if (nullable && text == L"null") { *value = 0; return true; }
        if (quoted && !String(json, key, &text)) { return false; }
        if (text.empty() || text.size() > 20) { return false; }
        uint64_t number = 0;
        for (const auto c : text)
        {
            if (c < L'0' || c > L'9' || number > (UINT64_MAX - (c - L'0')) / 10) { return false; }
            number = number * 10 + c - L'0';
        }
        if (number > (std::numeric_limits<T>::max)()) { return false; }
        *value = static_cast<T>(number);
        return true;
    }
    bool Boolean(const Object& json, const wchar_t* key, bool* value, bool nullable = false, bool* known = nullptr)
    {
        std::wstring raw;
        if (!Raw(json, key, &raw)) { return false; }
        if (known != nullptr) { *known = raw != L"null"; }
        if (nullable && raw == L"null") { *value = false; return true; }
        if (raw != L"true" && raw != L"false") { return false; }
        *value = raw == L"true";
        return true;
    }
    bool Array(const Object& object, const wchar_t* key, size_t limit, std::vector<std::wstring>* rows)
    { return object.Rows(key, limit, rows); }
    bool State(const Object& json, const wchar_t* key, ObservationReadState* value)
    {
        std::wstring name;
        if (!String(json, key, &name)) { return false; }
        for (int i = 0; i <= static_cast<int>(ObservationReadState::Cancelled); ++i)
        {
            if (name == ObservationReadStateName(static_cast<ObservationReadState>(i)))
            {
                *value = static_cast<ObservationReadState>(i);
                return true;
            }
        }
        return false;
    }
    bool Result(const std::wstring& encoded, ObservationReadResult* r)
    {
        Object json;
        if (!json.Parse(encoded)) { return false; }
        if (!State(json, L"status", &r->State) || !String(json, L"source_id", &r->SourceId) ||
            !String(json, L"consistency", &r->Consistency) || !String(json, L"clock_domain", &r->ClockDomain) ||
            !Number(json, L"started_tick", &r->StartedTick) || !Number(json, L"ended_tick", &r->EndedTick) ||
            !Boolean(json, L"side_effects_possible", &r->SideEffectsPossible) ||
            !Boolean(json, L"cancellation_observed", &r->CancellationObserved) ||
            !Boolean(json, L"operation_deadline_exceeded", &r->OperationDeadlineExceeded) ||
            !Boolean(json, L"identity_revalidated", &r->IdentityRevalidated) ||
            !String(json, L"native_status_domain", &r->NativeStatusDomain) ||
            !Number(json, L"native_status", &r->NativeStatus, false, true) ||
            !Number(json, L"transferred_bytes", &r->TransferredBytes, false, true, &r->TransferredBytesKnown) ||
            !Number(json, L"transport_status", &r->TransportStatus, false, true, &r->TransportAttempted) ||
            !Boolean(json, L"transport_succeeded", &r->TransportSucceeded, true) ||
            !Boolean(json, L"backend_copy_attempted", &r->BackendCopyAttempted, true, &r->BackendCopyAttemptKnown) ||
            !Number(json, L"native_read_kind", &r->NativeReadKind, false, true) ||
            !Number(json, L"driver_abi", &r->DriverAbi, false, true) ||
            !Number(json, L"source_epoch", &r->SourceEpoch) || !String(json, L"backend_contract", &r->BackendContract) ||
            !String(json, L"validation_reason", &r->ValidationReason) || !String(json, L"operation_id", &r->OperationId) ||
            !Number(json, L"read_receipt_id", &r->ReadReceiptId)) { return false; }
        std::vector<std::wstring> spans;
        if (!Array(json, L"spans", 4096, &spans)) { return false; }
        size_t total = 0;
        for (const auto& spanJson : spans)
        {
            Object row;
            if (!row.Parse(spanJson)) { return false; }
            ObservationReadSpan span;
            std::wstring hex;
            if (!Number(row, L"address", &span.Address) || !Number(row, L"requested_bytes", &span.RequestedBytes, false) ||
                !State(row, L"state", &span.State) || !String(row, L"bytes_hex", &hex) || hex.size() > 8192 ||
                hex.size() % 2 != 0 || hex.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
                total + hex.size() / 2 > 4096) { return false; }
            const auto digit = [](wchar_t c) { return c <= L'9' ? c - L'0' : c - L'a' + 10; };
            for (size_t i = 0; i < hex.size(); i += 2)
            {
                span.Bytes.push_back(static_cast<uint8_t>((digit(hex[i]) << 4) | digit(hex[i + 1])));
            }
            total += span.Bytes.size();
            r->Spans.push_back(std::move(span));
        }
        return true;
    }
}

bool ValidImageRecipeReadSet(const ImageVerificationRecipe& p)
{
    const auto& set = p.ReadSet;
    const auto& b = set.Budget;
    if (!Text(set.OperationId, 256) || !Text(set.TargetId, 2048) || !Text(set.AddressSpaceId, 2048) ||
        set.Reads.empty() || set.Reads.size() > ImageRecipeMaxReads || set.Reads.size() != p.Reads.size() ||
        set.TotalAttempts != set.Reads.size() || set.UnrecordedAttempts != 0 || set.ReservedSpanSlots != 0 ||
        set.SnapshotTick < set.StartedTick || set.DeadlineExceeded || b.MaximumElapsedMs == 0 ||
        b.MaximumElapsedMs > 60000 || set.SnapshotTick - set.StartedTick >= b.MaximumElapsedMs ||
        b.MaximumBytes > ImageRecipeReadBudget || b.MaximumSourceCalls > ImageRecipeMaxReads ||
        b.MaximumReceipts == 0 || b.MaximumReceipts > ImageRecipeMaxReads || b.MaximumStoredSpans > 65536 ||
        set.Reads.size() > b.MaximumReceipts || set.ChargedBytes > b.MaximumBytes ||
        set.ChargedSourceCalls > b.MaximumSourceCalls || set.StoredSpans > b.MaximumStoredSpans) { return false; }
    const auto& caps = set.Reads.front().Source;
    if (caps.SourceId != p.SourceId || caps.Consistency != p.SourceConsistency ||
        caps.AddressDomain != ObservationAddressDomain::Virtual || !caps.AddressSpace.Valid() ||
        caps.AddressSpace.VirtualAddressBits != p.VirtualAddressBits || caps.MaximumReadBytes == 0 ||
        caps.MaximumReadBytes > 4096 || (caps.KernelOnly && caps.UserOnly)) { return false; }
    uint64_t bytes = 0, spans = 0, calls = 0, tick = set.StartedTick;
    for (size_t i = 0; i < set.Reads.size(); ++i)
    {
        const auto& receipt = set.Reads[i];
        const auto& q = receipt.Request;
        const auto& r = receipt.Result;
        const auto& projected = p.Reads[i];
        if (receipt.Sequence != i + 1 || !receipt.Completed || receipt.Abandoned || receipt.DeadlineExceeded ||
            receipt.FallbackPermitted || q.FallbackFromReceipt != 0 || q.AllowFallback || !q.FallbackReason.empty() ||
            q.Cancellation != nullptr || !SameObservationSourceContract(caps, receipt.Source) ||
            q.SourceId != caps.SourceId || q.Address != projected.Address || q.Length != projected.Length ||
            q.ByteBudget > ImageRecipeReadBudget || r.SourceId != caps.SourceId || r.Consistency != caps.Consistency ||
            r.OperationId != set.OperationId || r.ReadReceiptId != receipt.Sequence || r.OperationDeadlineExceeded ||
            r.StartedTick < tick || r.EndedTick < r.StartedTick || r.EndedTick > set.SnapshotTick ||
            r.SideEffectsPossible != (receipt.SourceInvoked && caps.MayChangeResidency) ||
            (receipt.SourceInvoked && (q.Length > q.ByteBudget || !ObservationRangeSupported(caps, q.Address, q.Length) ||
                q.Length > caps.MaximumReadBytes || (caps.MayChangeResidency && !q.AllowResidencyChanges))) ||
            !Text(receipt.AdmissionReason, 128) || !Text(r.BackendContract, 256, true) || !Text(r.ValidationReason, 256, true) ||
            (!r.TransferredBytesKnown && r.TransferredBytes != 0) || (r.TransferredBytesKnown && r.TransferredBytes > q.Length) ||
            (!r.TransportAttempted && (r.TransportSucceeded || r.TransportStatus != 0)) ||
            (!r.BackendCopyAttemptKnown && r.BackendCopyAttempted) ||
            (r.NativeStatusDomain == L"unavailable" && r.NativeStatus != 0) ||
            ObservationReadJson(caps, q, r) != ObservationReadJson(caps, q, projected.Result)) { return false; }
        if (receipt.SourceInvoked)
        {
            if (receipt.AdmissionReason != L"delegated_to_source") { return false; }
            bytes += q.Length;
            ++calls;
        }
        else if (!r.Spans.empty() || r.IdentityRevalidated || r.TransferredBytesKnown || r.TransportAttempted ||
            r.BackendCopyAttemptKnown || r.NativeStatusDomain != L"unavailable" ||
            r.State == ObservationReadState::Complete || r.State == ObservationReadState::Partial)
        {
            return false;
        }
        spans += r.Spans.size();
        tick = r.EndedTick;
    }
    return bytes == set.ChargedBytes && calls == set.ChargedSourceCalls && spans == set.StoredSpans;
}

bool ParseObservationReadSet(const std::wstring& json, size_t maximumReceipts, ObservationReadSet* resultSet, size_t maximumCharacters)
{
    bounded_observation_json::IndexedObject object;
    if (resultSet == nullptr || maximumReceipts > 4096 || maximumCharacters > 16 * 1024 * 1024 ||
        json.size() > maximumCharacters || !object.Parse(json)) { return false; }
    ObservationReadSet set;
    Object budget;
    std::vector<std::wstring> rows;
    if (!String(object, L"operation_id", &set.OperationId) || !String(object, L"target_id", &set.TargetId) ||
        !String(object, L"address_space_id", &set.AddressSpaceId) || !Number(object, L"started_tick", &set.StartedTick) ||
        !Number(object, L"snapshot_tick", &set.SnapshotTick) || !Number(object, L"attempts", &set.TotalAttempts) ||
        !Number(object, L"unrecorded_attempts", &set.UnrecordedAttempts) ||
        !Number(object, L"charged_source_calls", &set.ChargedSourceCalls) || !Number(object, L"charged_requested_bytes", &set.ChargedBytes) ||
        !Number(object, L"stored_spans", &set.StoredSpans) || !Number(object, L"reserved_span_slots", &set.ReservedSpanSlots) ||
        !Boolean(object, L"cancelled", &set.Cancelled) || !Boolean(object, L"deadline_exceeded", &set.DeadlineExceeded) ||
        !Raw(object, L"budget", &budget) || !Number(budget, L"maximum_bytes", &set.Budget.MaximumBytes) ||
        !Number(budget, L"maximum_source_calls", &set.Budget.MaximumSourceCalls) ||
        !Number(budget, L"maximum_receipts", &set.Budget.MaximumReceipts) ||
        !Number(budget, L"maximum_stored_spans", &set.Budget.MaximumStoredSpans) ||
        !Number(budget, L"maximum_elapsed_ms", &set.Budget.MaximumElapsedMs) ||
        !object.Rows(L"reads", maximumReceipts, &rows)) { return false; }
    for (const auto& encoded : rows)
    {
        Object row;
        if (!row.Parse(encoded)) { return false; }
        ObservationReadReceipt receipt;
        auto& q = receipt.Request;
        auto& s = receipt.Source;
        auto& a = s.AddressSpace;
        Object contract, shape;
        std::wstring domain, result, fallback;
        if (!Number(row, L"sequence", &receipt.Sequence) || !Boolean(row, L"completed", &receipt.Completed) ||
            !Boolean(row, L"abandoned", &receipt.Abandoned) || !Boolean(row, L"source_invoked", &receipt.SourceInvoked) ||
            !Boolean(row, L"deadline_exceeded", &receipt.DeadlineExceeded) || !String(row, L"admission_reason", &receipt.AdmissionReason) ||
            !String(row, L"requested_source_id", &q.SourceId) || !String(row, L"source_id_at_admission", &s.SourceId) ||
            !Number(row, L"address", &q.Address) || !Number(row, L"requested_bytes", &q.Length) ||
            !Number(row, L"per_read_byte_budget", &q.ByteBudget) || !Boolean(row, L"residency_consent", &q.AllowResidencyChanges) ||
            !String(row, L"address_domain", &domain) || domain != L"virtual" || !Raw(row, L"source_contract", &contract) ||
            !String(contract, L"consistency", &s.Consistency) || !Number(contract, L"maximum_read_bytes", &s.MaximumReadBytes) ||
            !Boolean(contract, L"kernel_only", &s.KernelOnly) || !Boolean(contract, L"user_only", &s.UserOnly) ||
            !Boolean(contract, L"may_change_residency", &s.MayChangeResidency) || !Raw(row, L"address_shape", &shape) ||
            !Number(shape, L"virtual_bits", &a.VirtualAddressBits) || !Number(shape, L"pointer_bytes", &a.PointerBytes) ||
            !Number(shape, L"physical_bits", &a.PhysicalAddressBits, true, true) || !Boolean(shape, L"legacy_assumed", &a.LegacyAssumed) ||
            !Number(shape, L"user_maximum", &a.UserMaximum) || !Number(shape, L"kernel_minimum", &a.KernelMinimum) ||
            !Raw(row, L"fallback", &fallback) || !Raw(row, L"read", &result) || !Result(result, &receipt.Result)) { return false; }
        Object fallbackObject;
        if (fallback != L"null" && (!fallbackObject.Parse(fallback) || !Number(fallbackObject, L"from_receipt", &q.FallbackFromReceipt) ||
            !String(fallbackObject, L"reason", &q.FallbackReason) || !Boolean(fallbackObject, L"permission_requested", &q.AllowFallback) ||
            !Boolean(fallbackObject, L"permitted", &receipt.FallbackPermitted))) { return false; }
        set.Reads.push_back(std::move(receipt));
    }
    if (ObservationReadSetJson(set) != json) { return false; }
    *resultSet = std::move(set);
    return true;
}

bool ParseImageRecipeReadSet(const std::wstring& json, ImageVerificationRecipe* p)
{
    if (!ParseObservationReadSet(json, ImageRecipeMaxReads, &p->ReadSet)) { return false; }
    for (const auto& receipt : p->ReadSet.Reads)
    {
        p->Reads.push_back({receipt.Request.Address, receipt.Request.Length, receipt.Result});
    }
    // The v2 policy remains single-source and rejects all fallback declarations.
    return ValidImageRecipeReadSet(*p);
}
