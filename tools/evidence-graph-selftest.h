#pragma once

#include "../user/EvidenceGraph.h"
#include <set>

namespace evidence_graph_test
{
    inline EvidenceGraph Build(const EvidenceBundle& bundle)
    {
        std::wstring digest;
        mcpjson::GetString(EvidenceBundleJson(bundle), L"payload_sha256", &digest);
        return BuildEvidenceGraph(bundle, digest);
    }

    inline size_t References(const EvidenceGraph& graph)
    {
        return static_cast<size_t>(std::count_if(graph.Edges.begin(), graph.Edges.end(), [](const auto& edge)
        {
            return edge.Kind == L"references";
        }));
    }

    template<typename Check>
    void Run(Check check, const std::wstring& directory, const EvidenceBundle& fixture)
    {
        const auto graph = Build(fixture);
        EvidenceGraphQuery query;
        query.Depth = 8;
        query.Limit = 128;
        const auto full = QueryEvidenceGraph(graph, query);
        check(graph.Status == L"materialized" && full.Status == L"ok" && graph.Nodes.size() == 6 && graph.Edges.size() == 6 &&
            full.TotalRecords == 12 && full.NextCursor.empty(), "graph materializes retained spans and one static pointer");
        const auto json = EvidenceGraphJson(graph, query, full);
        check(mcpjson::ValidateDocument(json) && json == EvidenceGraphJson(Build(fixture), query, full),
            "graph identities and JSON are deterministic");
        check(json.find(L"observed_executing") == std::wstring::npos && json.find(L"caused_by") == std::wstring::npos &&
            json.find(L"\"execution_observed\":false") != std::wstring::npos &&
            json.find(L"\"layout_identity\":\"unavailable\"") != std::wstring::npos,
            "graph does not elevate static references or unknown layouts");
        const auto pointer = std::find_if(graph.Edges.begin(), graph.Edges.end(), [](const auto& edge)
        {
            return edge.Basis == L"reconstructed_static_pointer";
        });
        check(pointer != graph.Edges.end() && pointer->SpanIndices == std::vector<size_t>{1},
            "pointer edge names the exact retained source span");
        check(graph.ReadSetComplete && graph.ReferenceConsistent && !graph.CaptureTruncated &&
            mcpjson::ValidateDocument(graph.RecordedCoverageJson), "graph preserves the original coverage and capture contract");
        query.Depth = 0;
        auto page = QueryEvidenceGraph(graph, query);
        check(page.Status == L"ok" && page.Nodes.size() == 1 && page.Nodes[0].Id == graph.Root && page.Edges.empty(),
            "depth zero returns only the selected node");
        query.Node = pointer == graph.Edges.end() ? L"missing" : pointer->From;
        query.Depth = 1;
        page = QueryEvidenceGraph(graph, query);
        check(page.Status == L"ok" && page.Nodes.size() == 3 && page.Edges.size() == 2,
            "address-scoped traversal keeps one-hop provenance and references");
        query.Node.clear();
        query.Depth = 8;
        query.Limit = 3;
        page = QueryEvidenceGraph(graph, query);
        const auto firstCursor = page.NextCursor;
        std::set<std::wstring> nodes, edges;
        size_t offset = 0, pages = 0;
        do
        {
            page = QueryEvidenceGraph(graph, query);
            check(page.Status == L"ok" && page.Offset == offset && page.Nodes.size() + page.Edges.size() <= query.Limit,
                "record page obeys shared node and edge budget");
            for (const auto& node : page.Nodes)
            {
                check(nodes.insert(node.Id).second, "continuation does not repeat nodes");
            }
            for (const auto& edge : page.Edges)
            {
                check(edges.insert(edge.Id).second, "continuation does not repeat edges");
            }
            offset += page.Nodes.size() + page.Edges.size();
            query.Cursor = page.NextCursor;
            ++pages;
        }
        while (!query.Cursor.empty() && pages < 20);
        check(pages == 4 && nodes.size() == graph.Nodes.size() && edges.size() == graph.Edges.size(),
            "pagination crosses node-to-edge boundary without omissions");
        query.Cursor = firstCursor;
        query.Limit = 4;
        check(QueryEvidenceGraph(graph, query).Status == L"stale_or_invalid_cursor", "cursor rejects changed limit");
        query.Limit = 3;
        query.Depth = 7;
        check(QueryEvidenceGraph(graph, query).Status == L"stale_or_invalid_cursor", "cursor rejects changed depth");
        query.Depth = 8;
        query.Node = graph.Nodes[0].Id == graph.Root ? graph.Nodes[1].Id : graph.Nodes[0].Id;
        check(QueryEvidenceGraph(graph, query).Status == L"stale_or_invalid_cursor", "cursor rejects changed query root");
        query.Node.clear();
        for (const auto suffix : {L"00", L"-1", L"18446744073709551616", L"12", L"13", L"3:1"})
        {
            query.Cursor = firstCursor.substr(0, firstCursor.rfind(L':') + 1) + suffix;
            check(QueryEvidenceGraph(graph, query).Status == L"stale_or_invalid_cursor", "invalid cursor offsets fail closed");
        }
        query.Cursor = firstCursor;
        for (unsigned kind = 0; kind < 5; ++kind)
        {
            auto other = fixture;
            auto& context = other.Receipt.Reference.Context;
            if (kind == 0)
            {
                ++context.Identity.CreateTime;
            }
            else if (kind == 1)
            {
                context.Identity.BootId = L"other_fixture_boot";
            }
            else if (kind == 2)
            {
                context.Source = L"independent_fixture";
            }
            else if (kind == 3)
            {
                ++context.MappingGeneration;
            }
            else
            {
                other.Spans[0].Bytes[1] ^= 1;
            }
            const auto changed = Build(other);
            check(changed.Status == L"materialized" && changed.Digest != graph.Digest &&
                QueryEvidenceGraph(changed, query).Status == L"stale_or_invalid_cursor",
                "source lifetime mapping and content changes invalidate cursor");
            check(std::none_of(changed.Nodes.begin(), changed.Nodes.end(), [&](const auto& node)
            {
                return nodes.count(node.Id) != 0;
            }), "reused PID and address never merge across bundles");
        }
        query.Cursor.clear();
        query.TimeBudgetMs = 0;
        page = QueryEvidenceGraph(graph, query);
        check(page.Status == L"query_budget_deferred" && page.Nodes.empty() && page.Edges.empty() && page.NextCursor.empty(),
            "zero traversal budget returns no partial success");
        std::atomic<bool> cancel{true};
        query.Cancellation = &cancel;
        check(QueryEvidenceGraph(graph, query).Status == L"cancelled", "cancellation takes precedence over traversal budget");
        query.Cancellation = nullptr;
        query.TimeBudgetMs = 5001;
        check(QueryEvidenceGraph(graph, query).Status == L"invalid_query_or_graph", "excessive query budget rejected");
        query = EvidenceGraphQuery{};
        query.Depth = 9;
        check(QueryEvidenceGraph(graph, query).Status == L"invalid_query_or_graph", "depth overflow rejected");
        query.Depth = 2;
        for (const auto limit : {size_t{0}, size_t{129}, SIZE_MAX})
        {
            query.Limit = limit;
            check(QueryEvidenceGraph(graph, query).Status == L"invalid_query_or_graph", "record limit overflow rejected");
        }
        query = EvidenceGraphQuery{};
        query.Node = L"unknown";
        check(QueryEvidenceGraph(graph, query).Status == L"node_not_found", "unknown node is not empty success");
        query = EvidenceGraphQuery{};
        for (unsigned kind = 0; kind < 6; ++kind)
        {
            auto partial = fixture;
            if (kind == 0)
            {
                partial.Spans[1].Bytes.clear();
                partial.Spans[1].State = L"read_failed";
            }
            else if (kind == 1)
            {
                partial.Spans[1].Bytes[0] ^= 1;
            }
            else if (kind == 2)
            {
                partial.Spans.push_back(partial.Spans[1]);
                partial.Spans.back().Bytes[0] ^= 1;
            }
            else if (kind == 3)
            {
                partial.ReferenceConsistent = false;
            }
            else if (kind == 4)
            {
                partial.Receipt.Reference.SlotStable = false;
            }
            else
            {
                partial.Receipt.Disposition = L"identity_conflict";
                partial.Receipt.Reference.Id = 0;
            }
            const auto uncertain = Build(partial);
            check(uncertain.Status == L"materialized" && References(uncertain) == 0,
                "missing changed conflicting unstable and wrong-identity pointers do not become references");
        }
        auto chain = fixture;
        chain.Spans[0].Bytes[0] = 0xE9;
        const int32_t self = -5;
        std::memcpy(chain.Spans[0].Bytes.data() + 1, &self, sizeof(self));
        const auto cyclic = Build(chain);
        const auto cyclePage = QueryEvidenceGraph(cyclic, query);
        check(References(cyclic) == 2 && cyclePage.Status == L"ok" &&
            std::count(cyclic.Gaps.begin(), cyclic.Gaps.end(), L"cycle") == 1,
            "self-referencing static branch terminates and preserves cycle gap");
        auto unknown = fixture;
        unknown.Spans[0].Bytes[0] = 0xFF;
        unknown.Spans[0].Bytes[1] = 0xE0;
        check(References(Build(unknown)) == 1, "unresolved register target never creates a branch edge");
        auto indirect = fixture;
        indirect.Spans[0].Bytes[0] = 0xFF;
        indirect.Spans[0].Bytes[1] = 0x25;
        const int32_t slotDisplacement = 0x1000 - 6;
        std::memcpy(indirect.Spans[0].Bytes.data() + 2, &slotDisplacement, sizeof(slotDisplacement));
        const auto indirectGraph = Build(indirect);
        const auto branch = std::find_if(indirectGraph.Edges.begin(), indirectGraph.Edges.end(), [](const auto& edge)
        {
            return edge.Basis == L"decoded_static_transfer";
        });
        check(References(indirectGraph) == 2 && branch != indirectGraph.Edges.end() &&
            branch->SpanIndices == std::vector<size_t>{0, 1}, "indirect branch retains both instruction and slot evidence");
        auto incomplete = fixture;
        incomplete.CaptureTruncated = true;
        incomplete.Spans.push_back({0x13000, 32, L"target_head", L"read_failed", {}});
        const auto incompleteGraph = Build(incomplete);
        check(incompleteGraph.CaptureTruncated && !incompleteGraph.ReadSetComplete && References(incompleteGraph) == 1 &&
            !incompleteGraph.Gaps.empty(), "unrelated missing reads remain gaps without erasing independently retained pointer facts");
        auto maximal = fixture;
        while (maximal.Spans.size() < EvidenceBundleMaxSpans)
        {
            maximal.Spans.push_back({0x20000 + maximal.Spans.size() * 4096, 32, L"target_head", L"valid", std::vector<uint8_t>(32, 0xC3)});
        }
        const auto large = Build(maximal);
        query.Depth = 8;
        query.Limit = 128;
        const auto largePage = QueryEvidenceGraph(large, query);
        check(large.Status == L"materialized" && largePage.Status == L"ok" && largePage.TotalRecords > 256 &&
            !largePage.NextCursor.empty() && largePage.Nodes.size() + largePage.Edges.size() == 128,
            "maximum admitted span count still has bounded continuation");
        auto future = fixture;
        future.Receipt.Disposition = L"future_event";
        future.Receipt.Reference.Id = 0;
        future.Receipt.Reference.Context.MonotonicMs = 120;
        check(Build(future).Status == L"materialized" && References(Build(future)) == 0, "future-event receipt does not establish references");
        auto extended = fixture;
        auto& reference = extended.Receipt.Reference;
        reference.Context.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(5);
        reference.Address = reference.Root = 0x0010000000011000ull;
        reference.Slot = reference.Root + 0x1000;
        reference.Context.Coverage.Compared[0].Address = reference.Root;
        extended.Spans[0].Address = reference.Root;
        extended.Spans[1].Address = reference.Slot;
        std::memcpy(extended.Spans[1].Bytes.data(), &reference.Root, sizeof(reference.Root));
        check(Build(extended).Status == L"materialized" && References(Build(extended)) == 1, "LA57 graph retains extended canonical references");
        reference.Context.AddressSpace = {};
        check(Build(extended).Status != L"materialized", "LA57 input cannot be decoded under LA48 contract");
        check(BuildEvidenceGraph(fixture, L"untrusted").Status != L"materialized", "invalid source identity rejected");
        for (unsigned kind = 0; kind < 5; ++kind)
        {
            auto corrupt = graph;
            if (kind == 0)
            {
                corrupt.Nodes.push_back(corrupt.Nodes[0]);
            }
            else if (kind == 1)
            {
                corrupt.Edges[0].To = L"unknown";
            }
            else if (kind == 2)
            {
                corrupt.Edges[0].Kind = L"observed_executing";
            }
            else if (kind == 3)
            {
                corrupt.Edges.push_back(corrupt.Edges[0]);
            }
            else
            {
                corrupt.Nodes.resize(257);
            }
            query.Depth = 0;
            check(QueryEvidenceGraph(corrupt, query).Status == L"invalid_query_or_graph",
                "malformed graphs are rejected even without expansion");
        }
        std::wstring error, digest;
        EvidenceBundle restored;
        const auto path = directory + L"\\graph.kncase";
        check(SaveEvidenceBundle(path, fixture, &error) && LoadEvidenceBundle(path, &restored, &error, &digest) &&
            BuildEvidenceGraph(restored, digest).Digest == graph.Digest, "graph identity survives file and process reconstruction");
    }
}
