#include "TimelineModel.h"

#include "McpJson.h"

#include <cwctype>

namespace
{
    void AppendJsonStringMap(std::wstring* out, const std::map<std::wstring, std::wstring>& values)
    {
        bool first = true;
        *out += L"{";
        for (const auto& item : values)
        {
            if (!first)
            {
                *out += L",";
            }
            first = false;
            *out += mcpjson::Quote(item.first);
            *out += L":";
            *out += mcpjson::Quote(item.second);
        }
        *out += L"}";
    }

    void AppendJsonCounterMap(std::wstring* out, const std::map<std::wstring, uint64_t>& values)
    {
        bool first = true;
        *out += L"{";
        for (const auto& item : values)
        {
            if (!first)
            {
                *out += L",";
            }
            first = false;
            *out += mcpjson::Quote(item.first);
            *out += L":";
            *out += std::to_wstring(item.second);
        }
        *out += L"}";
    }
}

std::wstring TimelineToLower(const std::wstring& value)
{
    std::wstring out = value;
    for (wchar_t& ch : out)
    {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }
    return out;
}

std::wstring TimelineEventToJson(const TimelineEvent& event)
{
    std::wstring out = L"{\"eventId\":" + std::to_wstring(event.EventId);

    if (event.TimestampFileTime != 0)
    {
        out += L",\"timestampFileTime\":" + std::to_wstring(event.TimestampFileTime);
    }
    if (!event.TimestampUtc.empty())
    {
        out += L",\"timestampUtc\":" + mcpjson::Quote(event.TimestampUtc);
    }

    out += L",\"source\":" + mcpjson::Quote(event.Source);
    out += L",\"domain\":" + mcpjson::Quote(event.Domain);
    out += L",\"action\":" + mcpjson::Quote(event.Action);

    if (event.ProcessId != 0)
    {
        out += L",\"pid\":" + std::to_wstring(event.ProcessId);
    }
    if (event.ThreadId != 0)
    {
        out += L",\"tid\":" + std::to_wstring(event.ThreadId);
    }
    if (event.TargetProcessId != 0)
    {
        out += L",\"targetPid\":" + std::to_wstring(event.TargetProcessId);
    }
    if (!event.Entity.empty())
    {
        out += L",\"entity\":" + mcpjson::Quote(event.Entity);
    }
    if (!event.Summary.empty())
    {
        out += L",\"summary\":" + mcpjson::Quote(event.Summary);
    }
    if (!event.Risk.empty())
    {
        out += L",\"risk\":" + mcpjson::Quote(event.Risk);
    }
    if (!event.Confidence.empty())
    {
        out += L",\"confidence\":" + mcpjson::Quote(event.Confidence);
    }

    out += L",\"evidence\":";
    AppendJsonStringMap(&out, event.Evidence);
    out += L"}";
    return out;
}

std::wstring BuildTimelineEventsJson(
    const std::vector<TimelineEvent>& events,
    const TimelineQueryOptions& options,
    uint64_t totalStored)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.timeline.v1\"";
    out += L",\"count\":" + std::to_wstring(events.size());
    out += L",\"totalStored\":" + std::to_wstring(totalStored);
    out += L",\"limit\":" + std::to_wstring(options.Limit);
    if (!options.Source.empty())
    {
        out += L",\"source\":" + mcpjson::Quote(options.Source);
    }
    if (!options.Domain.empty())
    {
        out += L",\"domain\":" + mcpjson::Quote(options.Domain);
    }
    if (options.HasProcessId)
    {
        out += L",\"pid\":" + std::to_wstring(options.ProcessId);
    }
    out += L",\"newestFirst\":";
    out += options.NewestFirst ? L"true" : L"false";
    out += L",\"events\":[";
    for (size_t i = 0; i < events.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        out += TimelineEventToJson(events[i]);
    }
    out += L"]}";
    return out;
}

std::wstring BuildTimelineStatusJson(const TimelineStats& stats)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.timeline-status.v1\"";
    out += L",\"stored\":" + std::to_wstring(stats.Stored);
    out += L",\"capacity\":" + std::to_wstring(stats.Capacity);
    out += L",\"nextEventId\":" + std::to_wstring(stats.NextEventId);
    out += L",\"dropped\":" + std::to_wstring(stats.Dropped);
    out += L",\"bySource\":";
    AppendJsonCounterMap(&out, stats.BySource);
    out += L",\"byDomain\":";
    AppendJsonCounterMap(&out, stats.ByDomain);
    out += L"}";
    return out;
}

std::wstring BuildTimelineJsonl(const std::vector<TimelineEvent>& events)
{
    std::wstring out;
    for (const TimelineEvent& event : events)
    {
        out += TimelineEventToJson(event);
        out += L"\n";
    }
    return out;
}

std::wstring BuildTimelineGraphJson(const TimelineGraphResult& graph)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.timeline-graph.v1\"";
    out += L",\"totalEvents\":" + std::to_wstring(graph.TotalEvents);
    out += L",\"matchedEvents\":" + std::to_wstring(graph.MatchedEvents);
    out += L",\"truncated\":";
    out += graph.Truncated ? L"true" : L"false";
    out += L",\"limit\":" + std::to_wstring(graph.Options.Limit);
    if (!graph.Options.Source.empty())
    {
        out += L",\"source\":" + mcpjson::Quote(graph.Options.Source);
    }
    if (!graph.Options.Domain.empty())
    {
        out += L",\"domain\":" + mcpjson::Quote(graph.Options.Domain);
    }
    if (!graph.Options.Image.empty())
    {
        out += L",\"image\":" + mcpjson::Quote(graph.Options.Image);
    }
    if (graph.Options.HasProcessId)
    {
        out += L",\"pid\":" + std::to_wstring(graph.Options.ProcessId);
    }
    out += L",\"newestFirst\":";
    out += graph.Options.NewestFirst ? L"true" : L"false";

    out += L",\"nodes\":[";
    for (size_t i = 0; i < graph.Nodes.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        const TimelineGraphNode& node = graph.Nodes[i];
        out += L"{\"id\":" + mcpjson::Quote(node.Id);
        out += L",\"kind\":" + mcpjson::Quote(node.Kind);
        out += L",\"label\":" + mcpjson::Quote(node.Label);
        out += L",\"eventCount\":" + std::to_wstring(node.EventCount);
        out += L"}";
    }
    out += L"]";

    out += L",\"edges\":[";
    for (size_t i = 0; i < graph.Edges.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        const TimelineGraphEdge& edge = graph.Edges[i];
        out += L"{\"from\":" + mcpjson::Quote(edge.From);
        out += L",\"to\":" + mcpjson::Quote(edge.To);
        out += L",\"kind\":" + mcpjson::Quote(edge.Kind);
        out += L",\"eventCount\":" + std::to_wstring(edge.EventCount);
        if (edge.FirstEventId != 0)
        {
            out += L",\"firstEventId\":" + std::to_wstring(edge.FirstEventId);
        }
        if (edge.LastEventId != 0)
        {
            out += L",\"lastEventId\":" + std::to_wstring(edge.LastEventId);
        }
        out += L"}";
    }
    out += L"]}";
    return out;
}

std::wstring BuildTimelineReconcileJson(const TimelineReconcileResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.timeline-reconcile.v1\"";
    out += L",\"snapshotLabel\":" + mcpjson::Quote(result.SnapshotLabel);
    out += L",\"timelineEvents\":" + std::to_wstring(result.TimelineEvents);
    out += L",\"snapshotProcesses\":" + std::to_wstring(result.SnapshotProcesses);
    out += L",\"snapshotRecords\":" + std::to_wstring(result.SnapshotRecords);
    out += L",\"liveDropped\":" + std::to_wstring(result.LiveDropped);
    out += L",\"truncated\":";
    out += result.Truncated ? L"true" : L"false";
    out += L",\"limit\":" + std::to_wstring(result.Options.Limit);
    if (!result.Options.Source.empty())
    {
        out += L",\"source\":" + mcpjson::Quote(result.Options.Source);
    }
    if (!result.Options.Domain.empty())
    {
        out += L",\"domain\":" + mcpjson::Quote(result.Options.Domain);
    }
    if (result.Options.HasProcessId)
    {
        out += L",\"pid\":" + std::to_wstring(result.Options.ProcessId);
    }

    out += L",\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[i]);
    }
    out += L"]";

    out += L",\"findings\":[";
    for (size_t i = 0; i < result.Findings.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        const TimelineReconcileFinding& finding = result.Findings[i];
        out += L"{\"kind\":" + mcpjson::Quote(finding.Kind);
        out += L",\"domain\":" + mcpjson::Quote(finding.Domain);
        out += L",\"subject\":" + mcpjson::Quote(finding.Subject);
        out += L",\"risk\":" + mcpjson::Quote(finding.Risk);
        out += L",\"confidence\":" + mcpjson::Quote(finding.Confidence);
        out += L",\"summary\":" + mcpjson::Quote(finding.Summary);
        if (finding.EventId != 0)
        {
            out += L",\"eventId\":" + std::to_wstring(finding.EventId);
        }
        if (finding.ProcessId != 0)
        {
            out += L",\"pid\":" + std::to_wstring(finding.ProcessId);
        }
        out += L",\"evidence\":";
        AppendJsonStringMap(&out, finding.Evidence);
        out += L"}";
    }
    out += L"]}";
    return out;
}

std::wstring BuildTimelineAnalysisJson(const TimelineAnalysisResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.timeline-analysis.v1\"";
    out += L",\"totalEvents\":" + std::to_wstring(result.TotalEvents);
    out += L",\"limit\":" + std::to_wstring(result.Limit);
    out += L",\"truncated\":";
    out += result.Truncated ? L"true" : L"false";
    out += L",\"findings\":[";
    for (size_t i = 0; i < result.Findings.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        const TimelineAnalysisFinding& finding = result.Findings[i];
        out += L"{\"kind\":" + mcpjson::Quote(finding.Kind);
        out += L",\"risk\":" + mcpjson::Quote(finding.Risk);
        out += L",\"confidence\":" + mcpjson::Quote(finding.Confidence);
        out += L",\"summary\":" + mcpjson::Quote(finding.Summary);
        if (finding.FirstEventId != 0)
        {
            out += L",\"firstEventId\":" + std::to_wstring(finding.FirstEventId);
        }
        if (finding.LastEventId != 0)
        {
            out += L",\"lastEventId\":" + std::to_wstring(finding.LastEventId);
        }
        if (finding.ProcessId != 0)
        {
            out += L",\"pid\":" + std::to_wstring(finding.ProcessId);
        }
        if (finding.ThreadId != 0)
        {
            out += L",\"tid\":" + std::to_wstring(finding.ThreadId);
        }
        if (finding.TargetProcessId != 0)
        {
            out += L",\"targetPid\":" + std::to_wstring(finding.TargetProcessId);
        }
        out += L",\"evidence\":";
        AppendJsonStringMap(&out, finding.Evidence);
        out += L"}";
    }
    out += L"]}";
    return out;
}
