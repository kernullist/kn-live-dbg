#include "EvidenceGraph.h"
#include "ContentHash.h"
#include "McpJson.h"
#include <map>
#include <set>

namespace
{
    constexpr size_t MaximumNodes = 256, MaximumEdges = 512;
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
