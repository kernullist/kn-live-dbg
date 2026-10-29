#include "EvidenceGraph.h"
#include "KmonHuntingJson.h"
#include "McpJson.h"

namespace
{
    std::wstring N(uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    }

    std::wstring Strings(const std::vector<std::wstring>& values)
    {
        std::wstring json = L"[";
        for (const auto& value : values)
        {
            if (json.size() > 1)
            {
                json += L",";
            }
            json += mcpjson::Quote(value);
        }
        return json + L"]";
    }
}

std::wstring EvidenceGraphJson(const EvidenceGraph& graph, const EvidenceGraphQuery& query, const EvidenceGraphPage& page)
{
    const auto& reference = graph.Receipt.Reference;
    const auto& context = reference.Context;
    std::wstring json = L"{\"schema\":\"kn.evidence_graph.v1\",\"policy\":\"kn.bundle_graph.v1\",\"status\":" +
        mcpjson::Quote(page.Status) + L",\"graph_status\":" + mcpjson::Quote(graph.Status) + L",\"graph_digest\":" + mcpjson::Quote(graph.Digest) +
        L",\"query_digest\":" + mcpjson::Quote(page.QueryDigest) + L",\"source_evidence_id\":" + mcpjson::Quote(graph.SourceDigest) +
        L",\"root\":" + mcpjson::Quote(query.Node.empty() ? graph.Root : query.Node) + L",\"layer\":\"fact\","
        L"\"scope\":\"one_retained_bundle\",\"direction\":\"both\",\"cross_source_joins\":false,\"live_reads\":false,"
        L"\"collector_authenticated\":false,\"complete_system_inventory\":false,\"execution_observed\":false,"
        L"\"image_verification_replayed\":false,\"endpoints_may_be_on_other_pages\":true,\"depth\":" + N(query.Depth) +
        L",\"record_limit\":" + N(query.Limit) + L",\"offset\":" + N(page.Offset) + L",\"total_records\":" +
        (page.Status == L"ok" ? N(page.TotalRecords) : L"null") +
        L",\"next_cursor\":" + (page.NextCursor.empty() ? L"null" : mcpjson::Quote(page.NextCursor)) +
        L",\"query_budget_ms\":" + N(query.TimeBudgetMs) + L",\"query_budget_scope\":\"materialized_traversal_only\","
        L"\"materialization_limits\":{\"file_bytes\":2097152,\"spans\":128,\"nodes\":256,\"edges\":512},\"context\":";
    if (graph.SourceDigest.empty())
    {
        json += L"null";
    }
    else
    {
        json += L"{\"source_id\":" + mcpjson::Quote(L"bundle:" + graph.SourceDigest) +
        L",\"source\":" + mcpjson::Quote(context.Source) + L",\"acquisition\":" + mcpjson::Quote(graph.Acquisition) +
        L",\"state\":\"historical\",\"layout_identity\":\"unavailable\",\"security_domain\":\"unavailable\","
        L"\"dependency_group\":" + mcpjson::Quote(context.DependencyGroup) + L",\"capture_clock\":\"collector_monotonic_ms\","
        L"\"capture_started_ms\":" + N(graph.CaptureStartedMs) + L",\"capture_ended_ms\":" + N(graph.CaptureEndedMs) +
        L",\"original_comparison_coverage\":" + (graph.RecordedCoverageJson.empty() ? L"null" : graph.RecordedCoverageJson) +
        L",\"reference_consistent\":" + (graph.ReferenceConsistent ? L"true" : L"false") +
        L",\"capture_truncated\":" + (graph.CaptureTruncated ? L"true" : L"false") +
        L",\"retained_read_set_complete\":" + (graph.ReadSetComplete ? L"true" : L"false") +
        L",\"original_receipt\":" + KmonHuntReceiptJson(graph.Receipt) + L"}";
    }
    json += L",\"nodes\":[";
    bool first = true;
    for (const auto& node : page.Nodes)
    {
        if (!first)
        {
            json += L",";
        }
        first = false;
        json += L"{\"id\":" + mcpjson::Quote(node.Id) + L",\"kind\":" + mcpjson::Quote(node.Kind) +
            L",\"state\":" + mcpjson::Quote(node.State) + L",\"role\":" + mcpjson::Quote(node.Role) +
            L",\"context_ref\":\"#/context\",\"address\":" + (node.HasAddress ? N(node.Address) : L"null") +
            L",\"length\":" + (node.HasAddress ? N(node.Size) : L"null") + L",\"bytes_sha256\":" +
            (node.BytesSha256.empty() ? L"null" : mcpjson::Quote(node.BytesSha256)) +
            L",\"span_index\":" + (node.SpanIndex == SIZE_MAX ? L"null" : N(node.SpanIndex)) + L"}";
    }
    json += L"],\"edges\":[";
    first = true;
    for (const auto& edge : page.Edges)
    {
        if (!first)
        {
            json += L",";
        }
        first = false;
        json += L"{\"id\":" + mcpjson::Quote(edge.Id) + L",\"from\":" + mcpjson::Quote(edge.From) +
            L",\"to\":" + mcpjson::Quote(edge.To) + L",\"kind\":" + mcpjson::Quote(edge.Kind) +
            L",\"basis\":" + mcpjson::Quote(edge.Basis) + L",\"context_ref\":\"#/context\","
            L"\"evidence_id\":" + mcpjson::Quote(graph.SourceDigest) + L",\"receipt_id\":" + N(reference.Id) +
            L",\"coverage_requirement\":" + mcpjson::Quote(edge.Kind == L"references" ? L"exact_retained_reference_bytes" : L"recorded_metadata_or_span") +
            L",\"span_refs\":[";
        for (size_t i = 0; i < edge.SpanIndices.size(); ++i)
        {
            if (i != 0)
            {
                json += L",";
            }
            json += mcpjson::Quote(L"bundle:" + graph.SourceDigest + L"#span:" + std::to_wstring(edge.SpanIndices[i]));
        }
        json += L"]}";
    }
    return json + L"],\"gaps\":" + Strings(graph.Gaps) +
        L",\"unfulfilled_requirements\":[\"typed_layout_for_object_semantics\",\"execution_telemetry_for_execution_edges\","
        L"\"independent_causal_evidence_for_writer_attribution\",\"qualified_scope_for_cross_bundle_joins\"]}";
}
