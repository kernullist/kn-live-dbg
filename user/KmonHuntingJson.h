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
    out += L",\"address\":" + mcpjson::Quote(std::to_wstring(row.Address));
    out += L",\"root\":" + mcpjson::Quote(std::to_wstring(row.Root));
    out += L",\"slot\":" + mcpjson::Quote(std::to_wstring(row.Slot));
    out += L",\"role\":" + mcpjson::Quote(row.Role);
    out += L",\"ownership\":" + mcpjson::Quote(CodeOwnershipName(context.Ownership));
    out += L",\"source\":" + mcpjson::Quote(context.Source);
    out += L",\"dependency_group\":" + mcpjson::Quote(context.DependencyGroup);
    out += L",\"mapping_generation\":" + std::to_wstring(context.MappingGeneration);
    out += L",\"observed_ms\":" + std::to_wstring(context.MonotonicMs);
    out += L",\"observed_at\":" + mcpjson::Quote(std::to_wstring(context.Timestamp));
    out += L",\"reference_at\":" + mcpjson::Quote(std::to_wstring(row.ReferenceTimestamp));
    out += L",\"page_sha256\":" + mcpjson::Quote(row.PageSha256);
    out += L",\"page_comparable\":" + std::wstring(row.PageComparable ? L"true" : L"false");
    out += L",\"slot_stable\":" + std::wstring(row.SlotStable ? L"true" : L"false");
    out += L",\"pfn_known\":" + std::wstring(context.PfnKnown ? L"true" : L"false");
    out += L",\"pfn\":" + mcpjson::Quote(std::to_wstring(context.Pfn));
    out += L",\"execution_observed\":false}";
    return out;
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
