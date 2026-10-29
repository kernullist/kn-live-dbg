#include "EvidenceGraph.h"
#include "ContentHash.h"
#include "McpJson.h"
#include <map>
#include <set>

namespace
{
    constexpr size_t MaximumNodes = 256, MaximumEdges = 512;
    constexpr const wchar_t* Policy = L"kn.bundle_graph.v1";

    std::wstring Hash(const std::wstring& text)
    {
        const auto bytes = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }

    bool Digest(const std::wstring& text)
    {
        return text.size() == 64 && text.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    }

    bool Number(const std::wstring& text, size_t* value)
    {
        if (text.empty() || text.size() > 20 || (text.size() > 1 && text[0] == L'0'))
        {
            return false;
        }
        *value = 0;
        for (const auto c : text)
        {
            if (c < L'0' || c > L'9' || *value > (SIZE_MAX - (c - L'0')) / 10)
            {
                return false;
            }
            *value = *value * 10 + c - L'0';
        }
        return true;
    }
}

EvidenceGraph BuildEvidenceGraph(const EvidenceBundle& bundle, const std::wstring& sourceDigest)
{
    EvidenceGraph graph;
    const auto canonical = EvidenceBundleJson(bundle);
    if (!Digest(sourceDigest) || canonical.empty())
    {
        return graph;
    }
    // Include normalized content as well as the original (possibly legacy) source digest.
    const auto normalizedDigest = Hash(canonical);
    if (!Digest(normalizedDigest))
    {
        return graph;
    }
    graph.Digest = Hash(std::wstring(Policy) + L":" + sourceDigest + L":" + normalizedDigest);
    if (!Digest(graph.Digest))
    {
        return graph;
    }
    graph.SourceDigest = sourceDigest;
    graph.Receipt = bundle.Receipt;
    graph.Acquisition = bundle.Acquisition;
    std::wstring payload;
    if (!mcpjson::FindRawValue(canonical, L"payload", &payload) ||
        !mcpjson::FindRawValue(payload, L"observation_coverage", &graph.RecordedCoverageJson))
    {
        return graph;
    }
    graph.ReferenceConsistent = bundle.ReferenceConsistent;
    graph.CaptureTruncated = bundle.CaptureTruncated;
    graph.ReadSetComplete = EvidenceReadSetComplete(bundle);
    graph.CaptureStartedMs = bundle.CaptureStartedMs;
    graph.CaptureEndedMs = bundle.CaptureEndedMs;
    const auto& reference = bundle.Receipt.Reference;
    const auto& context = reference.Context;
    const auto id = [&](const wchar_t* kind, const std::wstring& key)
    {
        return std::wstring(kind) + L":" + Hash(graph.Digest + L":" + kind + L":" + key);
    };
    const auto node = [&](EvidenceGraphNode value, const std::wstring& key)
    {
        value.Id = id(L"n", value.Kind + L":" + key);
        const auto found = std::find_if(graph.Nodes.begin(), graph.Nodes.end(), [&](const auto& existing)
        {
            return existing.Id == value.Id;
        });
        if (found == graph.Nodes.end())
        {
            graph.Nodes.push_back(value);
        }
        return value.Id;
    };
    const auto edge = [&](const std::wstring& from, const std::wstring& to, const wchar_t* kind,
        const wchar_t* basis, std::vector<size_t> spans)
    {
        EvidenceGraphEdge value;
        value.From = from;
        value.To = to;
        value.Kind = kind;
        value.Basis = basis;
        value.SpanIndices = std::move(spans);
        value.Id = id(L"e", from + L":" + to + L":" + kind + L":" + basis);
        if (std::none_of(graph.Edges.begin(), graph.Edges.end(), [&](const auto& existing)
            {
                return existing.Id == value.Id;
            }))
        {
            graph.Edges.push_back(std::move(value));
        }
    };
    EvidenceGraphNode artifact;
    artifact.Kind = L"evidence";
    artifact.State = L"retained_unauthenticated";
    graph.Root = node(artifact, sourceDigest);
    EvidenceGraphNode subject;
    subject.Kind = context.Identity.ProcessId == 0 ? L"address_space" : L"process";
    subject.State = L"recorded_identity";
    const auto subjectId = node(subject, L"subject");
    edge(graph.Root, subjectId, L"derived_from", L"recorded_context_identity", {});
    for (size_t i = 0; i < bundle.Spans.size(); ++i)
    {
        const auto& span = bundle.Spans[i];
        EvidenceGraphNode raw;
        raw.Kind = L"memory_range";
        raw.State = span.State;
        raw.Role = span.Role;
        raw.HasAddress = true;
        raw.Address = span.Address;
        raw.Size = span.RequestedBytes;
        raw.SpanIndex = i;
        raw.BytesSha256 = span.Bytes.empty() ? L"" : ContentHash::Bytes(span.Bytes);
        if (!span.Bytes.empty() && !Digest(raw.BytesSha256))
        {
            graph.Status = L"identity_hash_unavailable";
            return graph;
        }
        const auto rawId = node(raw, L"span:" + std::to_wstring(i));
        edge(rawId, graph.Root, L"derived_from", L"retained_read_span", {i});
    }
    const auto sourceSpans = [&](uint64_t address, uint64_t length)
    {
        std::vector<size_t> indices;
        for (size_t i = 0; i < bundle.Spans.size(); ++i)
        {
            const auto& span = bundle.Spans[i];
            if (span.State == L"valid" && ObservationRange{span.Address, span.RequestedBytes}.Overlaps({address, length}))
            {
                indices.push_back(i);
            }
        }
        return indices;
    };
    const auto addressNode = [&](uint64_t address)
    {
        EvidenceGraphNode value;
        value.Kind = L"memory_address";
        value.HasAddress = true;
        value.Address = address;
        value.Size = 1;
        value.Role = L"static_reference_address";
        std::vector<uint8_t> bytes;
        value.State = EvidenceRead(bundle, address, 1, &bytes) ? L"captured_address" : L"address_only";
        const auto result = node(value, std::to_wstring(address));
        edge(result, graph.Root, L"derived_from", L"recorded_address", sourceSpans(address, 1));
        return result;
    };
    const auto canonicalAddress = [&](uint64_t address)
    {
        return context.AddressSpace.UserRange(address, 1) || context.AddressSpace.KernelRange(address, 1);
    };
    const auto replay = ReplayEvidence(bundle);
    graph.Gaps = replay.Gaps;
    if (reference.Slot != 0 && KmonPointerReference(reference.Role) && !reference.SlotStable)
    {
        graph.Gaps.push_back(L"original_slot_stability_unconfirmed");
    }
    const bool qualified = bundle.ReferenceConsistent && reference.SlotStable &&
        bundle.Receipt.Disposition != L"identity_conflict" && bundle.Receipt.Disposition != L"future_event";
    if (reference.Slot != 0 && KmonPointerReference(reference.Role) && qualified && replay.Chain.ReferenceStable)
    {
        const auto target = reference.Root == 0 ? reference.Address : reference.Root;
        if (canonicalAddress(reference.Slot) && canonicalAddress(target))
        {
            const auto slotNode = addressNode(reference.Slot);
            const auto targetNode = addressNode(target);
            edge(slotNode, targetNode,
                L"references", L"reconstructed_static_pointer", sourceSpans(reference.Slot, 8));
        }
    }
    // Branch edges describe decoded references in retained bytes, never execution.
    if (bundle.ReferenceConsistent && bundle.Receipt.Disposition != L"identity_conflict" &&
        bundle.Receipt.Disposition != L"future_event")
    {
        for (const auto& hop : replay.Chain.Hops)
        {
            if (hop.Target == 0 || hop.Bytes.empty() || !canonicalAddress(hop.Address) || !canonicalAddress(hop.Target))
            {
                continue;
            }
            auto spans = sourceSpans(hop.Address, hop.Bytes.size());
            if (hop.Slot != 0)
            {
                const auto pointerSpans = sourceSpans(hop.Slot, 8);
                spans.insert(spans.end(), pointerSpans.begin(), pointerSpans.end());
                std::sort(spans.begin(), spans.end());
                spans.erase(std::unique(spans.begin(), spans.end()), spans.end());
            }
            const auto originNode = addressNode(hop.Address);
            const auto targetNode = addressNode(hop.Target);
            edge(originNode, targetNode,
                L"references", L"decoded_static_transfer", std::move(spans));
        }
    }
    if (graph.Nodes.size() > MaximumNodes || graph.Edges.size() > MaximumEdges)
    {
        graph.Nodes.clear();
        graph.Edges.clear();
        graph.Status = L"graph_budget_exceeded";
        return graph;
    }
    std::sort(graph.Nodes.begin(), graph.Nodes.end(), [](const auto& a, const auto& b)
    {
        return a.Id < b.Id;
    });
    std::sort(graph.Edges.begin(), graph.Edges.end(), [](const auto& a, const auto& b)
    {
        return a.Id < b.Id;
    });
    for (const auto& value : graph.Nodes)
    {
        if (value.Id.size() != 66 || !Digest(value.Id.substr(2)))
        {
            graph.Status = L"identity_hash_unavailable";
            return graph;
        }
    }
    for (const auto& value : graph.Edges)
    {
        if (value.Id.size() != 66 || !Digest(value.Id.substr(2)))
        {
            graph.Status = L"identity_hash_unavailable";
            return graph;
        }
    }
    graph.Status = L"materialized";
    return graph;
}

EvidenceGraphPage QueryEvidenceGraph(const EvidenceGraph& graph, const EvidenceGraphQuery& query)
{
    EvidenceGraphPage page;
    if (graph.Status != L"materialized" || !Digest(graph.Digest) || graph.Nodes.size() > MaximumNodes || graph.Edges.size() > MaximumEdges ||
        query.Depth > 8 || query.Limit == 0 || query.Limit > 128 || query.TimeBudgetMs > 5000)
    {
        page.Status = L"invalid_query_or_graph";
        return page;
    }
    const uint64_t started = GetTickCount64();
    const auto stop = [&]()
    {
        if (query.Cancellation != nullptr && query.Cancellation->load())
        {
            page.Status = L"cancelled";
            return true;
        }
        if (query.TimeBudgetMs == 0 || GetTickCount64() - started >= query.TimeBudgetMs)
        {
            page.Status = L"query_budget_deferred";
            return true;
        }
        return false;
    };
    if (stop())
    {
        return page;
    }
    const auto root = query.Node.empty() ? graph.Root : query.Node;
    std::map<std::wstring, size_t> nodes;
    for (size_t i = 0; i < graph.Nodes.size(); ++i)
    {
        if (!nodes.emplace(graph.Nodes[i].Id, i).second)
        {
            page.Status = L"invalid_query_or_graph";
            return page;
        }
    }
    if (nodes.count(root) == 0)
    {
        page.Status = L"node_not_found";
        return page;
    }
    std::set<std::wstring> edgeIds;
    for (const auto& edge : graph.Edges)
    {
        if ((edge.Kind != L"derived_from" && edge.Kind != L"references") || nodes.count(edge.From) == 0 ||
            nodes.count(edge.To) == 0 || !edgeIds.insert(edge.Id).second)
        {
            page.Status = L"invalid_query_or_graph";
            return page;
        }
    }
    page.QueryDigest = Hash(graph.Digest + L":" + root + L":" + std::to_wstring(query.Depth) + L":" + std::to_wstring(query.Limit));
    if (!Digest(page.QueryDigest))
    {
        page.Status = L"identity_hash_unavailable";
        return page;
    }
    const auto prefix = L"kg1:" + graph.Digest + L":" + page.QueryDigest + L":";
    if (!query.Cursor.empty() && (query.Cursor.rfind(prefix, 0) != 0 ||
        !Number(query.Cursor.substr(prefix.size()), &page.Offset)))
    {
        page.Status = L"stale_or_invalid_cursor";
        return page;
    }
    std::vector<std::pair<std::wstring, size_t>> pending{{root, 0}};
    std::set<std::wstring> visited{root};
    std::set<size_t> edges;
    for (size_t at = 0; at < pending.size(); ++at)
    {
        if (stop())
        {
            return page;
        }
        const auto current = pending[at];
        if (current.second == query.Depth)
        {
            continue;
        }
        for (size_t i = 0; i < graph.Edges.size(); ++i)
        {
            const auto& edge = graph.Edges[i];
            if (edge.From != current.first && edge.To != current.first)
            {
                continue;
            }
            edges.insert(i);
            const auto next = edge.From == current.first ? edge.To : edge.From;
            if (visited.insert(next).second)
            {
                pending.push_back({next, current.second + 1});
            }
        }
    }
    page.TotalRecords = pending.size() + edges.size();
    if (page.Offset > page.TotalRecords || (page.Offset == page.TotalRecords && !query.Cursor.empty()))
    {
        page.Status = L"stale_or_invalid_cursor";
        return page;
    }
    const auto end = (std::min)(page.TotalRecords, page.Offset + query.Limit);
    size_t position = 0;
    for (const auto& entry : pending)
    {
        if (position >= page.Offset && position < end)
        {
            page.Nodes.push_back(graph.Nodes[nodes.at(entry.first)]);
        }
        ++position;
    }
    for (const auto index : edges)
    {
        if (position >= page.Offset && position < end)
        {
            page.Edges.push_back(graph.Edges[index]);
        }
        ++position;
    }
    if (stop())
    {
        page.Nodes.clear();
        page.Edges.clear();
        return page;
    }
    if (end < page.TotalRecords)
    {
        page.NextCursor = prefix + std::to_wstring(end);
    }
    page.Status = L"ok";
    return page;
}
