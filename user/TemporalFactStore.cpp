#include "TemporalFactStore.h"
#include "BoundedObservationJson.h"
#include "KmonHuntingJson.h"
#include <set>

using namespace bounded_observation_json;

namespace
{
    constexpr const wchar_t* Policy = L"kn.local_temporal_candidate.v1";
    constexpr size_t MaximumBundles = 32;

    std::wstring Hash(const std::wstring& value)
    {
        const auto bytes = mcpjson::WideToUtf8(value);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }
    bool Digest(const std::wstring& value)
    {
        return value.size() == 64 && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    }
    std::wstring Raw(const std::wstring& value, const wchar_t* key)
    {
        std::wstring result;
        return mcpjson::FindRawValue(value, key, &result) ? result : L"null";
    }
    std::wstring Strings(const std::vector<std::wstring>& values)
    {
        std::wstring result = L"[";
        for (const auto& value : values)
        {
            if (result.size() > 1) { result += L","; }
            result += mcpjson::Quote(value);
        }
        return result + L"]";
    }
    bool SameAddressContract(const AddressSpaceDescriptor& a, const AddressSpaceDescriptor& b)
    {
        return a.VirtualAddressBits == b.VirtualAddressBits && a.PointerBytes == b.PointerBytes &&
            a.PhysicalAddressBits == b.PhysicalAddressBits && a.UserMaximum == b.UserMaximum &&
            a.KernelMinimum == b.KernelMinimum && a.LegacyAssumed == b.LegacyAssumed;
    }
    struct Decision
    {
        std::wstring Status, Order = L"unestablished";
        std::vector<std::wstring> Missing, Conflicts;
        uint64_t Gap = 0;
        bool ClockQualified = false;
    };
    // Versioned rules evaluate the original observations pairwise. There is no
    // union-find merge: unknown optional assertions cannot bridge known ones.
    Decision Join(const EvidenceBundle& a, const EvidenceBundle& b, uint64_t maximumGap)
    {
        Decision d;
        const auto& x = a.Receipt.Reference.Context;
        const auto& y = b.Receipt.Reference.Context;
        const auto& i = x.Identity;
        const auto& j = y.Identity;
        if (a.Origin.Empty() || b.Origin.Empty()) { d.Missing.push_back(L"recorded_collector_binding"); }
        else
        {
            if (a.Origin.CollectorScope != b.Origin.CollectorScope || a.CollectionId != b.CollectionId)
            { d.Conflicts.push_back(L"different_collector_namespace"); }
            if (a.Origin.LocalBootId != b.Origin.LocalBootId) { d.Conflicts.push_back(L"different_local_target_boot"); }
            if (a.Origin.NativeEpoch != b.Origin.NativeEpoch) { d.Conflicts.push_back(L"source_connection_changed"); }
            d.ClockQualified = a.Origin.CollectorScope == b.Origin.CollectorScope && a.CollectionId == b.CollectionId &&
                a.Origin.LocalBootId == b.Origin.LocalBootId;
        }
        if (!i.SameCanonicalKey(j)) { d.Conflicts.push_back(L"different_target_process_generation"); }
        if (i.Eprocess != j.Eprocess)
        {
            if (i.Eprocess == 0 || j.Eprocess == 0) { d.Missing.push_back(L"matching_object_identity_assertions"); }
            else { d.Conflicts.push_back(L"conflicting_object_identity_assertions"); }
        }
        if (i.SessionKnown != j.SessionKnown) { d.Missing.push_back(L"matching_session_assertions"); }
        else if (i.SessionKnown && i.SessionId != j.SessionId) { d.Conflicts.push_back(L"conflicting_session_assertions"); }
        if (!SameAddressContract(x.AddressSpace, y.AddressSpace)) { d.Conflicts.push_back(L"different_address_contract"); }
        for (const auto* value : {&a, &b})
        {
            if (!value->ReferenceConsistent || value->Receipt.Disposition == L"identity_conflict" ||
                value->Receipt.Disposition == L"future_event" || value->Receipt.Disposition == L"prior_process_instance")
            { d.Missing.push_back(L"consistent_original_reference"); break; }
        }
        if (d.ClockQualified)
        {
            if (a.CaptureEndedMs < b.CaptureStartedMs)
            { d.Order = L"left_before_right"; d.Gap = b.CaptureStartedMs - a.CaptureEndedMs; }
            else if (b.CaptureEndedMs < a.CaptureStartedMs)
            { d.Order = L"right_before_left"; d.Gap = a.CaptureStartedMs - b.CaptureEndedMs; }
            else { d.Order = L"overlapping_recorded_intervals"; }
            if (d.Gap > maximumGap) { d.Conflicts.push_back(L"outside_requested_recorded_gap"); }
        }
        else { d.Missing.push_back(L"common_recorded_clock_namespace"); }
        d.Status = !d.Conflicts.empty() ? L"contradicted" : !d.Missing.empty() ? L"unfulfilled" : L"supported";
        return d;
    }
    std::wstring DecisionJson(const std::wstring& queryDigest, const std::wstring& left, const std::wstring& right,
        const EvidenceBundle& a, const EvidenceBundle& b, const Decision& d)
    {
        const auto& x = a.Receipt.Reference;
        const auto& y = b.Receipt.Reference;
        const auto id = L"relation:" + Hash(std::wstring(Policy) + L":" + queryDigest + L":" + left + L":" + right);
        if (id.size() != 73) { return {}; }
        return L"{\"id\":" + mcpjson::Quote(id) + L",\"left\":" + mcpjson::Quote(left) + L",\"right\":" + mcpjson::Quote(right) +
            L",\"kind\":\"temporal_candidate\",\"status\":" + mcpjson::Quote(d.Status) + L",\"policy\":" + mcpjson::Quote(Policy) +
            L",\"unfulfilled_requirements\":" + Strings(d.Missing) + L",\"contradictions\":" + Strings(d.Conflicts) +
            L",\"recorded_order\":" + mcpjson::Quote(d.Order) + L",\"recorded_gap_ms\":" + (d.ClockQualified ? N(d.Gap) : L"null") +
            L",\"similarity_only\":{\"same_address\":" + B(x.Address == y.Address) +
            L",\"same_mapping_generation_label\":" + B(x.Context.MappingGeneration != 0 && x.Context.MappingGeneration == y.Context.MappingGeneration) +
            L",\"same_pfn\":" + B(x.Context.PfnKnown && y.Context.PfnKnown && x.Context.Pfn == y.Context.Pfn) +
            L",\"same_recorded_page_hash\":" + B(!x.PageSha256.empty() && x.PageSha256 == y.PageSha256) +
            L"},\"mapping_lifetime_bound\":false,\"changed_between_established\":false,\"execution_established\":false,"
            L"\"write_established\":false,\"causality_established\":false,\"continuous_observation_established\":false,\"exact_wall_clock_gap_established\":false}";
    }
}

TemporalFactStore LoadTemporalFactStore(const std::vector<std::wstring>& paths,
    const std::atomic<bool>* cancellation, uint64_t timeBudgetMs)
{
    TemporalFactStore out;
    out.Requested = paths.size();
    if (paths.size() < 2 || paths.size() > MaximumBundles || timeBudgetMs > 120000)
    { out.State = L"invalid_input_scope"; return out; }
    const auto started = GetTickCount64();
    const auto stop = [&]()
    {
        if (cancellation != nullptr && cancellation->load()) { out.State = L"cancelled"; return true; }
        if (timeBudgetMs == 0 || GetTickCount64() - started >= timeBudgetMs) { out.State = L"input_budget_deferred"; return true; }
        return false;
    };
    size_t bytes = 0;
    std::set<std::wstring> observed;
    for (const auto& path : paths)
    {
        if (stop()) { out.Rows.clear(); return out; }
        TemporalFactStore::Observation row;
        size_t read = 0;
        row.Path = path;
        if (!LoadEvidenceBundle(path, &row.Bundle, nullptr, &row.Digest, EvidenceBundleMaxJsonBytes, &read) || !Digest(row.Digest))
        { out.State = L"input_unavailable_or_corrupt"; out.Issue = L"input:" + std::to_wstring(out.Rows.size()); out.Rows.clear(); return out; }
        bytes += read;
        if (bytes > MaximumBundles * EvidenceBundleMaxJsonBytes)
        { out.State = L"input_budget_deferred"; out.Rows.clear(); return out; }
        const auto canonical = EvidenceBundleJson(row.Bundle);
        if (canonical.empty()) { out.State = L"identity_hash_unavailable"; out.Rows.clear(); return out; }
        const auto payload = Raw(canonical, L"payload");
        row.OriginJson = Raw(payload, L"origin");
        row.ReferenceJson = Raw(Raw(payload, L"receipt"), L"reference");
        row.Id = L"observation:" + Hash(canonical);
        if (row.Id.size() != 76) { out.State = L"identity_hash_unavailable"; out.Rows.clear(); return out; }
        if (!observed.insert(row.Id).second)
        { out.State = L"duplicate_observation"; out.Rows.clear(); return out; }
        out.Rows.push_back(std::move(row));
    }
    if (stop()) { out.Rows.clear(); return out; }
    std::sort(out.Rows.begin(), out.Rows.end(), [](const auto& a, const auto& b) { return a.Id < b.Id; });
    std::wstring identity = std::wstring(Policy) + L":";
    for (const auto& row : out.Rows) { identity += row.Id + L":" + row.Digest + L";"; }
    out.Digest = Hash(identity);
    if (!Digest(out.Digest)) { out.State = L"identity_hash_unavailable"; out.Rows.clear(); return out; }
    out.State = L"materialized";
    return out;
}

TemporalFactPage QueryTemporalFacts(const TemporalFactStore& store, const TemporalFactQuery& query)
{
    TemporalFactPage out;
    if (store.State != L"materialized") { out.Status = store.State; return out; }
    if (query.Limit == 0 || query.Limit > 128 || query.MaximumGapMs > 300000 || query.TimeBudgetMs > 5000 || query.Cursor.size() > 180)
    { out.Status = L"invalid_query"; return out; }
    const auto started = GetTickCount64();
    const auto stop = [&]()
    {
        if (query.Cancellation != nullptr && query.Cancellation->load()) { out.Status = L"cancelled"; return true; }
        if (query.TimeBudgetMs == 0 || GetTickCount64() - started >= query.TimeBudgetMs) { out.Status = L"query_budget_deferred"; return true; }
        return false;
    };
    if (stop()) { return out; }
    out.TotalPairs = store.Rows.size() * (store.Rows.size() - 1) / 2;
    out.QueryDigest = Hash(store.Digest + L":" + std::to_wstring(query.MaximumGapMs) + L":" + std::to_wstring(query.Limit));
    if (!Digest(out.QueryDigest)) { out.Status = L"identity_hash_unavailable"; return out; }
    const auto prefix = L"ktf1:" + store.Digest + L":" + out.QueryDigest + L":";
    if (!query.Cursor.empty())
    {
        uint64_t offset = 0;
        if (query.Cursor.rfind(prefix, 0) != 0 || !Number(L"{\"n\":" + mcpjson::Quote(query.Cursor.substr(prefix.size())) + L"}", L"n", &offset) ||
            query.Cursor.substr(prefix.size()) != std::to_wstring(offset) ||
            offset >= out.TotalPairs || offset % query.Limit != 0)
        { out.Status = L"stale_or_invalid_cursor"; return out; }
        out.Offset = static_cast<size_t>(offset);
    }
    size_t position = 0;
    std::wstring decisions = L"[";
    for (size_t i = 0; i < store.Rows.size(); ++i)
    {
        for (size_t j = i + 1; j < store.Rows.size(); ++j, ++position)
        {
            if (stop()) { out.Returned = out.Supported = 0; return out; }
            if (position < out.Offset || position - out.Offset >= query.Limit) { continue; }
            const auto& a = store.Rows[i];
            const auto& b = store.Rows[j];
            const auto decision = Join(a.Bundle, b.Bundle, query.MaximumGapMs);
            if (out.Returned != 0) { decisions += L","; }
            const auto json = DecisionJson(out.QueryDigest, a.Id, b.Id, a.Bundle, b.Bundle, decision);
            if (json.empty()) { out.Status = L"identity_hash_unavailable"; out.Returned = out.Supported = 0; return out; }
            decisions += json;
            ++out.Returned;
            if (decision.Status == L"supported") { ++out.Supported; }
        }
    }
    if (stop()) { out.Returned = out.Supported = 0; return out; }
    out.Decisions = decisions + L"]";
    if (out.Offset + out.Returned < out.TotalPairs) { out.NextCursor = prefix + std::to_wstring(out.Offset + out.Returned); }
    out.Status = L"ok";
    return out;
}

std::wstring TemporalFactsJson(const TemporalFactStore& store, const TemporalFactQuery& query, const TemporalFactPage& page)
{
    std::wstring observations = L"[";
    for (const auto& row : store.Rows)
    {
        if (observations.size() > 1) { observations += L","; }
        const auto& context = row.Bundle.Receipt.Reference.Context;
        observations += L"{\"id\":" + mcpjson::Quote(row.Id) + L",\"evidence_id\":" + mcpjson::Quote(L"bundle_payload:" + row.Digest) +
            L",\"source_path\":" + mcpjson::Quote(row.Path) + L",\"origin\":" + row.OriginJson +
            L",\"collection_id\":" + mcpjson::Quote(row.Bundle.CollectionId) + L",\"reference\":" + row.ReferenceJson +
            L",\"reference_representation\":\"normalized_legacy_compatible\"" +
            L",\"capture_begin_tick\":" + N(row.Bundle.CaptureStartedMs) + L",\"capture_end_tick\":" + N(row.Bundle.CaptureEndedMs) +
            L",\"event_filetime\":" + N(context.Timestamp) + L",\"event_tick\":" + N(context.MonotonicMs) +
            L",\"arrival_tick\":" + N(context.ArrivalMonotonicMs) + L",\"arrival_sequence\":" + N(context.ArrivalSequence) +
            L",\"publication_time\":null,\"reference_consistent\":" + B(row.Bundle.ReferenceConsistent) +
            L",\"read_set_complete\":" + B(EvidenceReadSetComplete(row.Bundle)) + L",\"json_pointer\":\"/payload\"}";
    }
    observations += L"]";
    return L"{\"schema\":\"kn.temporal_facts.v1\",\"policy\":" + mcpjson::Quote(Policy) +
        L",\"status\":" + mcpjson::Quote(page.Status) + L",\"store_status\":" + mcpjson::Quote(store.State) +
        L",\"issue\":" + mcpjson::Quote(store.Issue) + L",\"store_digest\":" + mcpjson::Quote(store.Digest) +
        L",\"query_digest\":" + mcpjson::Quote(page.QueryDigest) + L",\"requested_inputs\":" + N(store.Requested) +
        L",\"accepted_inputs\":" + N(store.Rows.size()) + L",\"maximum_recorded_gap_ms\":" + N(query.MaximumGapMs) +
        L",\"offset\":" + N(page.Offset) + L",\"total_pairs\":" + N(page.TotalPairs) + L",\"returned_pairs\":" + N(page.Returned) +
        L",\"supported_candidates_in_page\":" + N(page.Supported) + L",\"next_cursor\":" + mcpjson::Quote(page.NextCursor) +
        L",\"observations\":" + observations + L",\"decisions\":" + page.Decisions +
        L",\"collector_authenticated\":false,\"target_coverage_established\":false,\"cross_collector_bridge_established\":false,"
        L"\"mapping_lifetime_bound\":false,\"causality_established\":false,\"current_state_established\":false,\"continuous_observation_established\":false,"
        L"\"query_scope\":\"explicit_bundle_membership\",\"time_scope\":\"historical_recorded_api_ticks\"}";
}
