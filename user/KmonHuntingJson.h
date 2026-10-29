#pragma once

#include "KmonHunting.h"
#include "McpJson.h"

inline std::wstring KmonHuntReferenceJson(const KmonHuntReference& row)
{
    const auto& context = row.Context;
    const auto& identity = context.Identity;
    std::wstring out = L"{\"id\":" + std::to_wstring(row.Id);
    out += L",\"boot_id\":" + mcpjson::Quote(identity.BootId);
    out += L",\"pid\":" + std::to_wstring(identity.ProcessId);
    out += L",\"create_time\":" + mcpjson::Quote(std::to_wstring(identity.CreateTime));
    out += L",\"eprocess\":" + mcpjson::Quote(std::to_wstring(identity.Eprocess));
    out += L",\"session_id\":" + std::to_wstring(identity.SessionId);
    out += L",\"session_known\":" + std::wstring(identity.SessionKnown ? L"true" : L"false");
    out += L",\"address\":" + mcpjson::Quote(std::to_wstring(row.Address));
    out += L",\"root\":" + mcpjson::Quote(std::to_wstring(row.Root));
    out += L",\"slot\":" + mcpjson::Quote(std::to_wstring(row.Slot));
    out += L",\"role\":" + mcpjson::Quote(row.Role);
    out += L",\"ownership\":" + mcpjson::Quote(CodeOwnershipName(context.Ownership));
    out += L",\"source\":" + mcpjson::Quote(context.Source);
    out += L",\"dependency_group\":" + mcpjson::Quote(context.DependencyGroup);
    out += L",\"mapping_generation\":" + std::to_wstring(context.MappingGeneration);
    out += L",\"observed_ms\":" + std::to_wstring(context.MonotonicMs);
    if (context.ArrivalSequence != 0)
    {
        out += L",\"arrival_ms\":" + mcpjson::Quote(std::to_wstring(context.ArrivalMonotonicMs));
        out += L",\"arrival_sequence\":" + mcpjson::Quote(std::to_wstring(context.ArrivalSequence));
    }
    out += L",\"observed_at\":" + mcpjson::Quote(std::to_wstring(context.Timestamp));
    out += L",\"reference_at\":" + mcpjson::Quote(std::to_wstring(row.ReferenceTimestamp));
    out += L",\"page_sha256\":" + mcpjson::Quote(row.PageSha256);
    out += L",\"page_comparable\":" + std::wstring(row.PageComparable ? L"true" : L"false");
    out += L",\"slot_stable\":" + std::wstring(row.SlotStable ? L"true" : L"false");
    out += L",\"page_executable_verified\":" + std::wstring(row.PageExecutableVerified ? L"true" : L"false");
    out += L",\"pfn_known\":" + std::wstring(context.PfnKnown ? L"true" : L"false");
    out += L",\"pfn\":" + mcpjson::Quote(std::to_wstring(context.Pfn));
    out += L",\"execution_observed\":false}";
    return out;
}

inline std::wstring KmonHuntReceiptJson(const KmonHuntReceipt& receipt)
{
    return L"{\"schema\":\"kmon.receipt.v1\",\"current_disposition\":" + mcpjson::Quote(receipt.Disposition) +
        L",\"arrival_inferred\":" + std::wstring(receipt.ArrivalInferred ? L"true" : L"false") +
        L",\"reference\":" + KmonHuntReferenceJson(receipt.Reference) + L"}";
}

inline std::wstring KmonHuntCasesJson(const std::vector<KmonHuntCase>& cases, uint64_t now, uint64_t evicted, uint64_t rejected,
    const wchar_t* inputMode = L"live_observations")
{
    std::wstring out = L"{\"schema\":\"kmon.hunt.v1\",\"claim\":\"investigation_leads\",\"communication_proven\":false";
    out += L",\"input_mode\":" + mcpjson::Quote(inputMode);
    out += L",\"generated_ms\":" + std::to_wstring(now);
    out += L",\"expires_after_ms\":30000,\"evidence_evicted\":" + std::to_wstring(evicted);
    out += L",\"evidence_rejected\":" + std::to_wstring(rejected) + L",\"cases\":[";
    bool first = true;
    for (const auto& item : cases)
    {
        if (!first)
        {
            out += L",";
        }
        first = false;
        out += L"{\"kind\":" + mcpjson::Quote(item.Kind);
        out += L",\"relation\":" + mcpjson::Quote(ObservationRelationName(item.Relation));
        out += L",\"primary\":" + KmonHuntReferenceJson(item.Primary);
        if (item.HasRelated)
        {
            out += L",\"related\":" + KmonHuntReferenceJson(item.Related);
        }
        out += L"}";
    }
    out += L"]}";
    return out;
}

inline std::wstring KmonHuntQueryJson(const KmonHuntQueryPage& page, const KmonHuntFilter& filter,
    uint64_t evicted, uint64_t rejected, const wchar_t* inputMode = L"live_observations")
{
    auto out = KmonHuntCasesJson(page.Cases, page.AsOfMs, evicted, rejected, inputMode);
    out.pop_back();
    out += L",\"query_schema\":\"kmon.case_query.v1\",\"query_scope\":\"retained_fresh_references\"";
    out += L",\"query_status\":" + mcpjson::Quote(page.Status);
    out += L",\"query_epoch\":" + mcpjson::Quote(std::to_wstring(page.Epoch));
    out += L",\"query_revision\":" + mcpjson::Quote(std::to_wstring(page.Revision));
    out += L",\"candidate_limit\":" + std::to_wstring(page.Limit);
    out += L",\"filter_pid\":" + (filter.HasPid ? std::to_wstring(filter.ProcessId) : L"null");
    out += L",\"filter_role\":" + mcpjson::Quote(filter.Role);
    const bool ok = page.Status == L"ok";
    out += L",\"matched_case_count\":" + (ok ? std::to_wstring(page.Matched) : L"null");
    out += L",\"returned_case_count\":" + std::to_wstring(page.Cases.size());
    out += L",\"page_offset\":" + std::to_wstring(page.Offset);
    out += L",\"omitted_by_budget\":" + (ok ? std::to_wstring(page.Omitted()) : L"null");
    out += L",\"complete_within_query_scope\":" + std::wstring(page.Complete() ? L"true" : L"false");
    out += L",\"next_cursor\":" + (page.NextCursor.empty() ? L"null" : mcpjson::Quote(page.NextCursor));
    out += L",\"underlying_index_retention\":{\"reference_capacity\":" + std::to_wstring(page.ReferenceCapacity);
    out += L",\"retained_references\":" + std::to_wstring(page.RetainedReferences) + L",\"freshness_ms\":30000}}";
    return out;
}
