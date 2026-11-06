#include "ImageSweepGraph.h"
#include "ImageSweepReplayEvidence.h"
#include "ImageVerificationRecipe.h"
#include "AnalystSnapshot.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <algorithm>

using namespace bounded_observation_json;

namespace
{
    constexpr size_t MaximumNodes = 256, MaximumEdges = 512, MaximumDetailsBytes = 2 * 1024 * 1024;
    constexpr const wchar_t* Policy = L"kn.image_sweep_graph.original.v1";
    std::wstring Hash(const std::wstring& text)
    {
        const auto bytes = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }
    std::wstring Raw(const std::wstring& json, const wchar_t* key)
    {
        std::wstring value;
        mcpjson::FindRawValue(json, key, &value);
        return value;
    }
    std::wstring Provenance(const std::wstring& artifact, const std::wstring& pointer,
        uint64_t ordinal, uint64_t start, uint64_t end)
    {
        return L"{\"evidence_id\":" + mcpjson::Quote(artifact) + L",\"json_pointer\":" + mcpjson::Quote(pointer) +
            L",\"slice_ordinal\":" + N(ordinal) + L",\"started_tick\":" + N(start) + L",\"ended_tick\":" + N(end) +
            L",\"context_ref\":\"#/context\",\"clock_domain\":\"collector_steady_clock_ms\","
            L"\"interval_semantics\":\"observation_window_not_mapping_lifetime\"}";
    }
    std::wstring Ranges(const std::vector<ObservationRange>& ranges, uint64_t base = 0)
    {
        std::wstring json = L"[";
        for (const auto& range : ranges)
        {
            if (json.size() > 1) { json += L","; }
            json += L"{\"address\":" + N(base + range.Address) + L",\"length\":" + N(range.Size) + L"}";
        }
        return json + L"]";
    }
    std::wstring Lookup(const std::map<std::wstring, std::wstring>& values, const std::wstring& key)
    {
        const auto found = values.find(key);
        return found == values.end() ? L"null" : found->second;
    }
}

ImageSweepGraph BuildImageSweepGraph(const std::wstring& path)
{
    const auto failure = [](const std::wstring& status)
    {
        ImageSweepGraph graph;
        graph.Facts.Status = status;
        return graph;
    };
    // Bound the projection before expensive replay. Bind the actual replay to
    // this exact digest too, so replacement cannot bypass this admission check.
    std::wstring json, expectedDigest;
    ImageSweepManifest manifest;
    if (!ReadAnalystSnapshot(path, &json, nullptr, ImageRecipeMaxBytes, nullptr, true) ||
        !ParseImageSweepManifest(json, &manifest) || !mcpjson::GetString(json, L"manifest_sha256", &expectedDigest))
    {
        return failure(L"manifest_unavailable_or_corrupt");
    }
    uint64_t nodes = 4, edges = 2;
    for (const auto& row : manifest.Slices)
    {
        nodes += 2 + (row.RawWritten ? 1 : 0) + row.RangeCount;
        edges += 4 + (row.RawWritten ? 1 : 0) + row.RangeCount;
    }
    if (nodes > MaximumNodes || edges > MaximumEdges) { return failure(L"graph_budget_exceeded"); }
    ImageSweepReplayEvidence verified;
    const auto replay = ReplayImageSweepManifest(path, nullptr, &verified, expectedDigest);
    if (replay.Status != L"replayed") { return failure(replay.Status); }
    if (verified.ManifestSha256 != expectedDigest) { return failure(L"manifest_changed_during_graph_replay"); }
    ImageSweepGraph result;
    auto& graph = result.Facts;
    graph.SourceDigest = verified.ManifestSha256;
    const auto proofDigest = Hash(replay.Proof);
    if (proofDigest.size() != 64) { return failure(L"identity_hash_unavailable"); }
    graph.Digest = Hash(std::wstring(Policy) + L":" + graph.SourceDigest + L":" + proofDigest);
    if (graph.Digest.size() != 64) { return failure(L"identity_hash_unavailable"); }
    result.Assessment = replay.Proof;
    result.Context = L"{\"state\":\"historical\",\"target_identity_scope\":\"collector_declared\","
        L"\"mapping_lifetime\":\"unestablished\",\"source_scope\":\"original_recipe_read_receipts\","
        L"\"clock_domain\":\"collector_steady_clock_ms\",\"target\":" + Raw(replay.RecordedResult, L"sweep") +
        L",\"publication_membership\":" + replay.CurrentResult + L"}";
    size_t detailBytes = mcpjson::WideToUtf8(result.Context).size() + mcpjson::WideToUtf8(result.Assessment).size();
    bool valid = true;
    const auto account = [&](const std::wstring& value)
    {
        const auto bytes = mcpjson::WideToUtf8(value).size();
        if (detailBytes > MaximumDetailsBytes || bytes > MaximumDetailsBytes - detailBytes) { valid = false; }
        else { detailBytes += bytes; }
    };
    const auto node = [&](const wchar_t* kind, const wchar_t* state, const std::wstring& key,
        const std::wstring& provenance, const std::wstring& details = L"{}", ObservationRange range = {})
    {
        EvidenceGraphNode value;
        value.Kind = kind; value.State = state; value.Role = kind;
        value.Id = L"n:" + Hash(graph.Digest + L":" + kind + L":" + key);
        value.HasAddress = range.Size != 0; value.Address = range.Address; value.Size = range.Size;
        valid &= value.Id.size() == 66;
        account(provenance); account(details);
        if (!valid) { return std::wstring(); }
        result.NodeProvenance.emplace(value.Id, provenance);
        result.NodeDetails.emplace(value.Id, details);
        graph.Nodes.push_back(value);
        return value.Id;
    };
    const auto edge = [&](const std::wstring& from, const std::wstring& to, const wchar_t* basis, const std::wstring& provenance)
    {
        EvidenceGraphEdge value;
        value.From = from; value.To = to; value.Kind = L"derived_from"; value.Basis = basis;
        value.Id = L"e:" + Hash(graph.Digest + L":" + from + L":" + to + L":" + basis);
        valid &= value.Id.size() == 66;
        account(provenance);
        if (!valid) { return; }
        result.EdgeProvenance.emplace(value.Id, provenance);
        graph.Edges.push_back(std::move(value));
    };
    const auto& s = verified.Manifest.Sweep;
    const auto sweepEvidence = L"manifest:" + graph.SourceDigest;
    const auto sweepProvenance = Provenance(sweepEvidence, L"/payload", 0, s.StartedTick, verified.Manifest.LastEndedTick);
    graph.Root = node(L"sweep_assessment", L"original_policy_replayed", L"assessment", sweepProvenance, L"{\"assessment_ref\":\"#/assessment\"}");
    const auto artifact = node(L"sweep_manifest", L"retained_verified", L"manifest", sweepProvenance);
    const auto targetProvenance = Provenance(sweepEvidence, L"/payload/sweep", 0, s.StartedTick, verified.Manifest.LastEndedTick);
    const auto target = node(L"target_context", L"collector_declared", L"target", targetProvenance);
    const auto reference = node(L"reference_artifact", L"R-retained", verified.ReferenceSha256,
        Provenance(L"reference:" + verified.ReferenceSha256, L"", 0, s.StartedTick, verified.Manifest.LastEndedTick));
    edge(graph.Root, artifact, L"original_sweep_replay", sweepProvenance);
    edge(artifact, target, L"recorded_target_context", targetProvenance);
    if (!valid) { return failure(L"graph_budget_or_projection_failed"); }
    for (size_t i = 0; i < verified.Slices.size(); ++i)
    {
        const auto& slice = verified.Slices[i];
        const auto& row = slice.Publication;
        const auto key = std::to_wstring(row.Ordinal);
        const auto prefix = L"/payload/slices/" + std::to_wstring(i);
        const auto membership = Provenance(sweepEvidence, prefix, row.Ordinal, row.StartedTick, row.EndedTick);
        const auto recipeEvidence = L"recipe:" + row.RecipeSha256;
        const auto recipeProvenance = Provenance(recipeEvidence, L"/payload", row.Ordinal, row.StartedTick, row.EndedTick);
        const auto recipe = node(L"slice_recipe", L"original_policy_replayed", key, recipeProvenance,
            L"{\"policy\":" + mcpjson::Quote(slice.Policy) + L"}");
        const auto observation = node(L"slice_observation", L"replayed_non_atomic", key, membership,
            L"{\"read_set_id\":" + N(row.ReadSetId) + L",\"start_range\":" + N(row.StartRange) +
            L",\"range_count\":" + N(row.RangeCount) + L",\"observed_filetime\":" + N(row.ObservedFileTime) +
            L",\"raw_archive_published\":" + B(row.RawWritten) + L"}");
        edge(graph.Root, observation, L"replayed_slice_contribution", recipeProvenance);
        edge(observation, artifact, L"retained_sweep_membership", membership);
        edge(observation, recipe, L"original_slice_policy_and_inputs", recipeProvenance);
        edge(recipe, reference, L"exact_retained_reference",
            Provenance(recipeEvidence, L"/payload/reference_sha256", row.Ordinal, row.StartedTick, row.EndedTick));
        if (row.RawWritten)
        {
            const auto raw = node(L"read_archive", L"retained_verified", key,
                Provenance(L"raw:" + row.RawPayloadSha256, L"/payload", row.Ordinal, row.StartedTick, row.EndedTick));
            edge(recipe, raw, L"verified_original_read_set_agreement", membership);
        }
        if (!valid) { return failure(L"graph_budget_or_projection_failed"); }
        for (size_t n = 0; n < slice.Pages.size(); ++n)
        {
            const auto& page = slice.Pages[n];
            const auto& coverage = page.Coverage;
            uint64_t changed = 0;
            for (const auto& range : page.Changes) { changed += range.Size; }
            const bool qualified = slice.TargetReferenceQualified && coverage.InventoryAvailable;
            const auto state = !qualified || coverage.FailedBytes != 0 ? L"inconclusive" : changed != 0 ? L"changed_bytes_established" :
                coverage.ComparedBytes == coverage.RequestedBytes ? L"matches_retained_reference" : L"incomplete_comparison";
            const auto provenance = Provenance(recipeEvidence, L"/payload/recorded_result/" + std::to_wstring(n),
                row.Ordinal, row.StartedTick, row.EndedTick);
            const auto details = L"{\"schedule_range_index\":" + N(row.StartRange + n) +
                L",\"target_reference_qualified\":" + B(qualified) +
                L",\"requested_bytes\":" + N(coverage.RequestedBytes) + L",\"compared_bytes\":" + N(coverage.ComparedBytes) +
                L",\"changed_bytes\":" + N(changed) + L",\"excluded_bytes\":" + N(coverage.SkippedBytes) +
                L",\"unreadable_bytes\":" + N(coverage.FailedBytes) + L",\"compared_ranges\":" + Ranges(coverage.Compared) +
                L",\"changed_ranges\":" + Ranges(page.Changes, s.ImageBase) + L",\"excluded_ranges\":" + Ranges(coverage.Skipped) +
                L",\"unreadable_ranges\":" + Ranges(coverage.Failed) + L"}";
            const auto comparison = node(L"executable_range_comparison", state, key + L":" + std::to_wstring(n), provenance,
                details, {s.ImageBase + page.Rva, coverage.RequestedBytes});
            edge(comparison, observation, L"recomputed_range_comparison", provenance);
            if (!valid) { return failure(L"graph_budget_or_projection_failed"); }
        }
    }
    if (!valid || graph.Nodes.size() != nodes || graph.Edges.size() != edges ||
        graph.Nodes.size() > MaximumNodes || graph.Edges.size() > MaximumEdges) { return failure(L"graph_budget_or_projection_failed"); }
    std::sort(graph.Nodes.begin(), graph.Nodes.end(), [](const auto& a, const auto& b) { return a.Id < b.Id; });
    std::sort(graph.Edges.begin(), graph.Edges.end(), [](const auto& a, const auto& b) { return a.Id < b.Id; });
    graph.Status = L"materialized";
    return result;
}

std::wstring ImageSweepGraphJson(const ImageSweepGraph& result, const EvidenceGraphQuery& query, const EvidenceGraphPage& page)
{
    const auto& graph = result.Facts;
    std::wstring json = L"{\"schema\":\"kn.image_sweep_graph.v1\",\"policy\":" + mcpjson::Quote(Policy) +
        L",\"status\":" + mcpjson::Quote(page.Status) + L",\"graph_status\":" + mcpjson::Quote(graph.Status) +
        L",\"graph_digest\":" + mcpjson::Quote(graph.Digest) + L",\"query_digest\":" + mcpjson::Quote(page.QueryDigest) +
        L",\"source_manifest_sha256\":" + mcpjson::Quote(graph.SourceDigest) +
        L",\"root\":" + mcpjson::Quote(query.Node.empty() ? graph.Root : query.Node) +
        L",\"scope\":\"one_retained_temporal_sweep\",\"layer\":\"replayed_comparison_and_provenance\",\"direction\":\"both\","
        L"\"cross_source_joins\":false,\"live_reads\":false,\"collector_authenticated\":false,\"atomic_snapshot\":false,"
        L"\"execution_observed\":false,\"writer_attributed\":false,\"approved_reference\":false,\"complete_system_inventory\":false,"
        L"\"image_verification_replayed\":" + B(graph.Status == L"materialized") +
        L",\"endpoints_may_be_on_other_pages\":true,\"depth\":" + N(query.Depth) + L",\"record_limit\":" + N(query.Limit) +
        L",\"offset\":" + N(page.Offset) + L",\"total_records\":" + (page.Status == L"ok" ? N(page.TotalRecords) : L"null") +
        L",\"next_cursor\":" + (page.NextCursor.empty() ? L"null" : mcpjson::Quote(page.NextCursor)) +
        L",\"query_budget_ms\":" + N(query.TimeBudgetMs) + L",\"query_budget_scope\":\"materialized_traversal_only\","
        L"\"materialization_limits\":{\"nodes\":256,\"edges\":512,\"detail_bytes\":2097152,\"replay_input_bytes\":268435456},"
        L"\"context\":" + (result.Context.empty() ? L"null" : result.Context) +
        L",\"assessment\":" + (result.Assessment.empty() ? L"null" : result.Assessment) + L",\"nodes\":[";
    bool first = true;
    for (const auto& node : page.Nodes)
    {
        if (!first) { json += L","; } first = false;
        json += L"{\"id\":" + mcpjson::Quote(node.Id) + L",\"kind\":" + mcpjson::Quote(node.Kind) +
            L",\"state\":" + mcpjson::Quote(node.State) + L",\"address\":" + (node.HasAddress ? N(node.Address) : L"null") +
            L",\"length\":" + (node.HasAddress ? N(node.Size) : L"null") + L",\"provenance\":" + Lookup(result.NodeProvenance, node.Id) +
            L",\"details\":" + Lookup(result.NodeDetails, node.Id) + L"}";
    }
    json += L"],\"edges\":["; first = true;
    for (const auto& edge : page.Edges)
    {
        if (!first) { json += L","; } first = false;
        json += L"{\"id\":" + mcpjson::Quote(edge.Id) + L",\"from\":" + mcpjson::Quote(edge.From) + L",\"to\":" +
            mcpjson::Quote(edge.To) + L",\"kind\":" + mcpjson::Quote(edge.Kind) + L",\"basis\":" + mcpjson::Quote(edge.Basis) +
            L",\"provenance\":" + Lookup(result.EdgeProvenance, edge.Id) + L"}";
    }
    return json + L"],\"unfulfilled_requirements\":[\"qualified_cross_bundle_mapping_lifetimes\",\"approved_reference_provenance\","
        L"\"execution_observation\",\"independent_causal_evidence_for_writer_attribution\"]}";
}
