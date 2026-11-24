#include "ProcessImageSourceReceipt.h"
#include "BoundedObservationJson.h"
#include "ImageClaimPublication.h"

namespace
{
    namespace json = bounded_observation_json;
    using json::N;
    constexpr DWORD CaptureAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

    std::wstring IdentityJson(const ProcessHandleIdentity& id)
    {
        return L"{\"pid\":" + N(id.Pid) + L",\"creation_filetime\":" + N(id.Created) +
            L",\"win32_status\":" + N(id.Error) + L"}";
    }

    bool ParseIdentity(const std::wstring& value, ProcessHandleIdentity& id)
    {
        return json::Number(value, L"pid", &id.Pid) && json::Number(value, L"creation_filetime", &id.Created) &&
            json::Number(value, L"win32_status", &id.Error) && (!id.Created || (id.Pid && !id.Error));
    }

    std::wstring ActionJson(const ProcessHandleAction& a)
    {
        const auto call = a.Call == ProcessHandleCall::Open ? L"open" : a.Call == ProcessHandleCall::Duplicate ? L"duplicate" : L"close";
        std::wstring row = L"{\"call\":" + mcpjson::Quote(call) + L",\"sequence\":" + N(a.Sequence) +
            L",\"acquisition_id\":" + N(a.AcquisitionId) + L",\"parent_acquisition_id\":" + N(a.ParentAcquisitionId) +
            L",\"requested_filetime\":" + N(a.RequestedUtc) + L",\"returned_filetime\":" + N(a.ReturnedUtc) +
            L",\"succeeded\":" + json::B(a.Succeeded) + L",\"win32_status\":" + N(a.Status);
        if (a.Call == ProcessHandleCall::Open) { row += L",\"requested_access\":" + N(a.DesiredAccess); }
        if (a.Call == ProcessHandleCall::Duplicate) { row += L",\"same_access\":true"; }
        if (a.Call != ProcessHandleCall::Close && a.Succeeded) { row += L",\"bound_identity\":" + IdentityJson(a.Bound); }
        return row + L"}";
    }

    bool ParseAction(const std::wstring& row, ProcessHandleAction& a)
    {
        std::wstring call, identity;
        if (!mcpjson::GetString(row, L"call", &call) || !json::Number(row, L"sequence", &a.Sequence) ||
            !json::Number(row, L"acquisition_id", &a.AcquisitionId) || !json::Number(row, L"parent_acquisition_id", &a.ParentAcquisitionId) ||
            !json::Number(row, L"requested_filetime", &a.RequestedUtc) || !json::Number(row, L"returned_filetime", &a.ReturnedUtc) ||
            !json::Boolean(row, L"succeeded", &a.Succeeded) || !json::Number(row, L"win32_status", &a.Status)) { return false; }
        if (call == L"open") { a.Call = ProcessHandleCall::Open; }
        else if (call == L"duplicate") { a.Call = ProcessHandleCall::Duplicate; }
        else if (call == L"close") { a.Call = ProcessHandleCall::Close; }
        else { return false; }
        if (a.Call == ProcessHandleCall::Open && !json::Number(row, L"requested_access", &a.DesiredAccess)) { return false; }
        if (a.Call != ProcessHandleCall::Close && a.Succeeded &&
            (!mcpjson::FindRawValue(row, L"bound_identity", &identity) || !ParseIdentity(identity, a.Bound))) { return false; }
        return true;
    }

    // The duplicate pins the same kernel process object. A close reports the
    // original acquisition id and its own native result, without another bind.
    bool CloseOf(const ProcessHandleAction& close, const ProcessHandleAction& acquisition)
    {
        return close.Call == ProcessHandleCall::Close && close.AcquisitionId == acquisition.AcquisitionId &&
            close.ParentAcquisitionId == acquisition.ParentAcquisitionId;
    }

    const wchar_t* Outcome(const ProcessImageSourceReceipt& r)
    {
        const auto& a = r.Actions;
        if (!r.RequestedPid || !r.RequestedCreation || a.empty() || a.size() > 4) { return nullptr; }
        for (size_t i = 0; i < a.size(); ++i)
        {
            const auto& step = a[i];
            if (step.Sequence != i + 1 || !step.RequestedUtc || !step.ReturnedUtc || (step.Succeeded && step.Status) ||
                (step.Call != ProcessHandleCall::Close && step.AcquisitionId != (step.Succeeded ? step.Sequence : 0))) { return nullptr; }
            if (step.Call != ProcessHandleCall::Close && step.Succeeded && step.Bound.Created &&
                (step.Bound.Pid != r.RequestedPid || step.Bound.Error)) { return nullptr; }
        }
        const auto& open = a.front();
        if (open.Call != ProcessHandleCall::Open || open.ParentAcquisitionId || open.DesiredAccess != CaptureAccess) { return nullptr; }
        const bool queried = r.CollectorQuery.Pid != 0;
        if (!queried && (r.CollectorQuery.Created || r.CollectorQuery.Error || !r.SourceId.empty())) { return nullptr; }
        if (!open.Succeeded) { return a.size() == 1 && !r.UserMaximum && !queried ? L"open_failed" : nullptr; }
        if (!CloseOf(a.back(), open)) { return nullptr; }
        AddressSpaceDescriptor space;
        space.UserMaximum = r.UserMaximum;
        if (!space.Valid()) { return a.size() == 2 && !queried ? L"address_shape_unsupported" : nullptr; }
        if (a.size() < 3) { return nullptr; }
        const auto& dup = a[1];
        if (dup.Call != ProcessHandleCall::Duplicate || dup.ParentAcquisitionId != open.AcquisitionId) { return nullptr; }
        if (!dup.Succeeded) { return a.size() == 3 && !queried ? L"duplicate_failed" : nullptr; }
        if (a.size() != 4 || !CloseOf(a[2], dup) ||
            (open.Bound.Pid && dup.Bound.Pid && open.Bound.Pid != dup.Bound.Pid) ||
            (open.Bound.Created && dup.Bound.Created && open.Bound.Created != dup.Bound.Created)) { return nullptr; }
        if (dup.Bound.Error || !dup.Bound.Pid || (dup.Bound.Pid == r.RequestedPid && !dup.Bound.Created))
            { return !queried ? L"target_identity_unavailable" : nullptr; }
        if (dup.Bound.Pid != r.RequestedPid || dup.Bound.Created != r.RequestedCreation)
            { return !queried ? L"target_generation_mismatch" : nullptr; }
        if (!queried) { return nullptr; }
        if (r.CollectorQuery.Error || !r.CollectorQuery.Created)
            { return r.SourceId.empty() ? L"collector_identity_unavailable" : nullptr; }
        const auto expected = L"process_handle:" + std::to_wstring(r.CollectorQuery.Pid) + L":" +
            std::to_wstring(r.CollectorQuery.Created) + L":" + std::to_wstring(r.RequestedPid) + L":" +
            std::to_wstring(r.RequestedCreation) + L":48:" + std::to_wstring(r.UserMaximum) + L":assumed";
        return r.SourceId == expected ? L"ready" : nullptr;
    }

    bool ParseReceipt(const std::wstring& raw, ProcessImageSourceReceipt& r)
    {
        std::wstring collector;
        std::vector<std::wstring> rows;
        if (raw.size() > 8192 || !json::Number(raw, L"requested_pid", &r.RequestedPid) ||
            !json::Number(raw, L"requested_creation_filetime", &r.RequestedCreation) ||
            !json::Number(raw, L"user_maximum", &r.UserMaximum) || !mcpjson::GetString(raw, L"source_id", &r.SourceId) ||
            !mcpjson::FindRawValue(raw, L"collector_identity_query", &collector) ||
            (collector != L"null" && !ParseIdentity(collector, r.CollectorQuery)) ||
            !json::Array(raw, L"handle_actions", 4, &rows)) { return false; }
        for (const auto& row : rows) { if (!ParseAction(row, r.Actions.emplace_back())) { return false; } }
        return Outcome(r) && ProcessImageSourceReceiptJson(r) == raw;
    }
}

std::wstring ProcessImageSourceReceiptJson(const ProcessImageSourceReceipt& r)
{
    const auto state = Outcome(r);
    std::wstring rows = L"[";
    unsigned acquired = 0, closed = 0;
    for (const auto& a : r.Actions)
    {
        if (rows.size() > 1) { rows += L","; }
        rows += ActionJson(a);
        if (a.Succeeded)
        {
            if (a.Call == ProcessHandleCall::Close) { ++closed; } else { ++acquired; }
        }
    }
    return L"{\"schema\":\"kn.process_image_source.v1\",\"status\":" + mcpjson::Quote(state ? state : L"incomplete") +
        L",\"requested_pid\":" + N(r.RequestedPid) + L",\"requested_creation_filetime\":" + N(r.RequestedCreation) +
        L",\"user_maximum\":" + N(r.UserMaximum) + L",\"collector_identity_query\":" +
        (r.CollectorQuery.Pid ? IdentityJson(r.CollectorQuery) : L"null") + L",\"source_id\":" + mcpjson::Quote(r.SourceId) +
        L",\"acquired\":" + N(acquired) + L",\"closed\":" + N(closed) + L",\"handle_actions\":" + rows + L"]}";
}

const wchar_t* ParseProcessImageCaptureReport(const std::wstring& page, ProcessImageCaptureReport& report)
{
    json::IndexedObject doc;
    std::wstring raw, recorded, openStatus, claim;
    if (!doc.Parse(page) || doc.String(L"schema") != L"kn.image_capture.v3") { return L"report_invalid"; }
    if (!doc.Raw(L"source_initialization", &raw)) { return L"source_receipt_missing"; }
    const auto fieldIs = [&](const wchar_t* key, const wchar_t* expected)
    {
        std::wstring value;
        return doc.Raw(key, &value) && value == expected;
    };
    if (!fieldIs(L"collector_authenticated", L"false") || !fieldIs(L"execution_observed", L"false") ||
        !fieldIs(L"residency_consent", L"true")) { return L"report_invalid"; }
    ProcessImageSourceReceipt r;
    if (!ParseReceipt(raw, r) || !doc.Raw(L"original_claim_recorded", &recorded) ||
        !doc.Raw(L"open_status", &openStatus) || openStatus != std::to_wstring(r.Actions.front().Status) ||
        !doc.Raw(L"result", &claim)) { return L"source_receipt_invalid"; }
    const auto status = doc.String(L"status");
    const bool published = status == L"recorded" || status == L"interrupted";
    if ((!published && status != L"failed") || recorded != json::B(published)) { return L"report_invalid"; }
    if (!published)
    {
        if (claim != L"null" || doc.String(L"policy") != ImageRecipePolicy) { return L"report_invalid"; }
        for (auto key : {L"recipe_sha256", L"source_id", L"operation_id", L"reference_sha256", L"target_id", L"consistency"})
            { if (!fieldIs(key, L"\"\"")) { return L"report_invalid"; } }
    }
    const auto digest = [&](const wchar_t* key)
    {
        const auto text = doc.String(key);
        return text.size() == 64 && text.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    };
    if (published && (r.SourceId.empty() || r.SourceId != doc.String(L"source_id") ||
        doc.String(L"target_id") != L"process:" + std::to_wstring(r.RequestedPid) + L":" + std::to_wstring(r.RequestedCreation) ||
        !digest(L"recipe_sha256") || !digest(L"reference_sha256") || doc.String(L"operation_id").empty() || claim == L"null"))
        { return L"report_invalid"; }
    report.ReceiptJson = std::move(raw);
    report.CaptureStatus = status;
    report.SourceStatus = Outcome(r);
    report.SourceId = std::move(r.SourceId);
    report.TargetId = doc.String(L"target_id");
    report.OperationId = doc.String(L"operation_id");
    report.ReferenceSha256 = doc.String(L"reference_sha256");
    report.RecipeSha256 = doc.String(L"recipe_sha256");
    report.Policy = doc.String(L"policy");
    report.Consistency = doc.String(L"consistency");
    report.Result = std::move(claim);
    return nullptr;
}
