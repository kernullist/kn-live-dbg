#include "TimelineStore.h"

#include "SnapshotJson.h"

#include <algorithm>
#include <cerrno>
#include <cwchar>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace
{
    constexpr size_t kMinTimelineCapacity = 1024;
    constexpr size_t kMaxTimelineCapacity = 1u << 22;

    std::wstring HexU64(uint64_t value)
    {
        std::wstringstream stream;
        stream << L"0x" << std::hex << value << std::dec;
        return stream.str();
    }

    std::wstring TiTaskText(const TiEventRecord& event)
    {
        std::wstring text = event.TaskName;
        if (text.empty())
        {
            text = L"Task" + std::to_wstring(static_cast<uint32_t>(event.TaskId));
        }
        return text;
    }

    bool ParsePidFromText(const std::wstring& text, uint32_t* pid)
    {
        bool ok = false;
        do
        {
            if (pid == nullptr || text.empty())
            {
                break;
            }

            wchar_t* end = nullptr;
            errno = 0;
            unsigned long long value = wcstoull(text.c_str(), &end, 0);
            if (end == text.c_str() || *end != L'\0' || errno == ERANGE)
            {
                break;
            }
            if (value == 0 || value > 0xffffffffull)
            {
                break;
            }

            *pid = static_cast<uint32_t>(value);
            ok = true;
        } while (false);

        return ok;
    }

    uint32_t SnapshotRecordPid(const SnapshotRecord& record)
    {
        uint32_t pid = 0;
        static const wchar_t* kPidKeys[] =
        {
            L"pid",
            L"process_id",
            L"owner_pid",
            L"target_pid",
            L"source_pid"
        };

        for (const wchar_t* key : kPidKeys)
        {
            auto it = record.Evidence.find(key);
            if (it != record.Evidence.end() && ParsePidFromText(it->second, &pid))
            {
                break;
            }
        }

        return pid;
    }

    std::wstring SnapshotRecordSummary(const SnapshotRecord& record)
    {
        std::wstring summary = record.Display;
        if (summary.empty())
        {
            summary = record.Identity;
        }
        if (summary.empty())
        {
            summary = record.Domain;
        }
        return summary;
    }

    void AddEvidenceIfPresent(
        std::map<std::wstring, std::wstring>* evidence,
        const std::wstring& key,
        const std::wstring& value)
    {
        if (evidence != nullptr && !value.empty())
        {
            (*evidence)[key] = value;
        }
    }

    std::wstring GraphNodeId(const std::wstring& kind, const std::wstring& label)
    {
        return TimelineToLower(kind) + L":" + TimelineToLower(label);
    }

    std::wstring ProcessLabel(uint32_t pid)
    {
        return std::to_wstring(pid);
    }

    struct TimelineImageRef
    {
        std::wstring Value;
        bool LinkSourceProcess = false;
        bool LinkTargetProcess = false;
    };

    bool EvidenceValueByKey(
        const TimelineEvent& event,
        const std::wstring& key,
        std::wstring* value)
    {
        bool found = false;
        std::wstring wanted = TimelineToLower(key);

        for (const auto& item : event.Evidence)
        {
            if (TimelineToLower(item.first) == wanted)
            {
                if (value != nullptr)
                {
                    *value = item.second;
                }
                found = true;
                break;
            }
        }

        return found;
    }

    void AddImageRef(
        std::map<std::wstring, TimelineImageRef>* refs,
        const std::wstring& value,
        bool linkSourceProcess,
        bool linkTargetProcess)
    {
        if (refs != nullptr && !value.empty())
        {
            std::wstring key = TimelineToLower(value);
            auto it = refs->find(key);
            if (it == refs->end())
            {
                TimelineImageRef ref = {};
                ref.Value = value;
                it = refs->insert(std::make_pair(key, ref)).first;
            }
            it->second.LinkSourceProcess = it->second.LinkSourceProcess || linkSourceProcess;
            it->second.LinkTargetProcess = it->second.LinkTargetProcess || linkTargetProcess;
        }
    }

    std::vector<TimelineImageRef> TimelineEventImageRefs(const TimelineEvent& event)
    {
        std::map<std::wstring, TimelineImageRef> refs;
        std::vector<TimelineImageRef> values;
        std::wstring value;

        if (EvidenceValueByKey(event, L"image", &value))
        {
            AddImageRef(&refs, value, true, false);
        }
        if (EvidenceValueByKey(event, L"image_path", &value))
        {
            AddImageRef(&refs, value, true, false);
        }
        if (EvidenceValueByKey(event, L"target_image", &value))
        {
            AddImageRef(&refs, value, false, true);
        }
        if (TimelineToLower(event.Domain) == L"process")
        {
            AddImageRef(&refs, event.Entity, true, false);
        }

        for (const auto& item : refs)
        {
            values.push_back(item.second);
        }

        return values;
    }

    bool TimelineEventMatchesImage(const TimelineEvent& event, const std::wstring& image)
    {
        bool matched = false;
        std::wstring needle = TimelineToLower(image);

        do
        {
            if (needle.empty())
            {
                matched = true;
                break;
            }

            std::vector<TimelineImageRef> images = TimelineEventImageRefs(event);
            for (const TimelineImageRef& imageRef : images)
            {
                if (TimelineToLower(imageRef.Value).find(needle) != std::wstring::npos)
                {
                    matched = true;
                    break;
                }
            }
            if (matched)
            {
                break;
            }

            if (TimelineToLower(event.Entity).find(needle) != std::wstring::npos ||
                TimelineToLower(event.Summary).find(needle) != std::wstring::npos)
            {
                matched = true;
                break;
            }

            for (const auto& item : event.Evidence)
            {
                if (TimelineToLower(item.second).find(needle) != std::wstring::npos)
                {
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    bool TimelineEventMatchesGraphQuery(
        const TimelineEvent& event,
        const TimelineGraphQueryOptions& options)
    {
        bool matched = true;

        if (!options.Source.empty() &&
            TimelineToLower(event.Source) != TimelineToLower(options.Source))
        {
            matched = false;
        }
        if (matched &&
            !options.Domain.empty() &&
            TimelineToLower(event.Domain) != TimelineToLower(options.Domain))
        {
            matched = false;
        }
        if (matched &&
            options.HasProcessId &&
            event.ProcessId != options.ProcessId &&
            event.TargetProcessId != options.ProcessId)
        {
            matched = false;
        }
        if (matched &&
            !options.Image.empty() &&
            !TimelineEventMatchesImage(event, options.Image))
        {
            matched = false;
        }

        return matched;
    }

    void AddGraphNode(
        std::map<std::wstring, TimelineGraphNode>* nodes,
        std::set<std::wstring>* eventNodes,
        const std::wstring& kind,
        const std::wstring& label)
    {
        if (nodes != nullptr && eventNodes != nullptr && !label.empty())
        {
            std::wstring id = GraphNodeId(kind, label);
            auto it = nodes->find(id);
            if (it == nodes->end())
            {
                TimelineGraphNode node = {};
                node.Id = id;
                node.Kind = kind;
                node.Label = label;
                it = nodes->insert(std::make_pair(id, node)).first;
            }
            if (eventNodes->insert(id).second)
            {
                ++it->second.EventCount;
            }
        }
    }

    void AddGraphEdge(
        std::map<std::wstring, TimelineGraphEdge>* edges,
        std::set<std::wstring>* eventEdges,
        const std::wstring& from,
        const std::wstring& to,
        const std::wstring& kind,
        uint64_t eventId)
    {
        if (edges != nullptr &&
            eventEdges != nullptr &&
            !from.empty() &&
            !to.empty() &&
            from != to)
        {
            std::wstring key = from + L"\n" + to + L"\n" + kind;
            auto it = edges->find(key);
            if (it == edges->end())
            {
                TimelineGraphEdge edge = {};
                edge.From = from;
                edge.To = to;
                edge.Kind = kind;
                it = edges->insert(std::make_pair(key, edge)).first;
            }
            if (eventEdges->insert(key).second)
            {
                ++it->second.EventCount;
                if (it->second.FirstEventId == 0 || eventId < it->second.FirstEventId)
                {
                    it->second.FirstEventId = eventId;
                }
                if (eventId > it->second.LastEventId)
                {
                    it->second.LastEventId = eventId;
                }
            }
        }
    }

    bool TryGetEvidencePid(const TimelineEvent& event, const std::wstring& key, uint32_t* pid)
    {
        bool ok = false;
        std::wstring value;

        if (EvidenceValueByKey(event, key, &value))
        {
            ok = ParsePidFromText(value, pid);
        }

        return ok;
    }

    void AddTimelineGraphEvent(
        const TimelineEvent& event,
        std::map<std::wstring, TimelineGraphNode>* nodes,
        std::map<std::wstring, TimelineGraphEdge>* edges)
    {
        std::set<std::wstring> eventNodes;
        std::set<std::wstring> eventEdges;

        std::wstring sourceLabel = event.Source.empty() ? L"<unknown>" : event.Source;
        std::wstring domainLabel = event.Domain.empty() ? L"<unknown>" : event.Domain;
        std::wstring sourceId = GraphNodeId(L"source", sourceLabel);
        std::wstring domainId = GraphNodeId(L"domain", domainLabel);
        AddGraphNode(nodes, &eventNodes, L"source", sourceLabel);
        AddGraphNode(nodes, &eventNodes, L"domain", domainLabel);
        AddGraphEdge(edges, &eventEdges, sourceId, domainId, L"source-domain", event.EventId);

        std::wstring processId;
        if (event.ProcessId != 0)
        {
            std::wstring label = ProcessLabel(event.ProcessId);
            processId = GraphNodeId(L"process", label);
            AddGraphNode(nodes, &eventNodes, L"process", label);
            AddGraphEdge(edges, &eventEdges, sourceId, processId, L"source-observes-process", event.EventId);
            AddGraphEdge(
                edges,
                &eventEdges,
                processId,
                domainId,
                TimelineToLower(event.Source) == L"snapshot" ? L"snapshot-record" : L"process-domain",
                event.EventId);
        }

        std::wstring targetProcessId;
        if (event.TargetProcessId != 0)
        {
            std::wstring label = ProcessLabel(event.TargetProcessId);
            targetProcessId = GraphNodeId(L"process", label);
            AddGraphNode(nodes, &eventNodes, L"process", label);
            AddGraphEdge(edges, &eventEdges, sourceId, targetProcessId, L"source-observes-process", event.EventId);
            if (!processId.empty())
            {
                AddGraphEdge(
                    edges,
                    &eventEdges,
                    processId,
                    targetProcessId,
                    TimelineToLower(event.Source) == L"ti" ? L"ti-targets-process" : L"targets-process",
                    event.EventId);
            }
        }

        uint32_t parentPid = 0;
        if (event.ProcessId != 0 &&
            (TryGetEvidencePid(event, L"parent_pid", &parentPid) ||
             TryGetEvidencePid(event, L"ppid", &parentPid) ||
             TryGetEvidencePid(event, L"parent_process_id", &parentPid) ||
             TryGetEvidencePid(event, L"inherited_from_pid", &parentPid) ||
             TryGetEvidencePid(event, L"creator_pid", &parentPid)) &&
            parentPid != event.ProcessId)
        {
            std::wstring parentLabel = ProcessLabel(parentPid);
            std::wstring parentId = GraphNodeId(L"process", parentLabel);
            AddGraphNode(nodes, &eventNodes, L"process", parentLabel);
            AddGraphEdge(edges, &eventEdges, parentId, processId, L"parent-child", event.EventId);
        }

        std::vector<TimelineImageRef> images = TimelineEventImageRefs(event);
        for (const TimelineImageRef& imageRef : images)
        {
            std::wstring imageId = GraphNodeId(L"image", imageRef.Value);
            AddGraphNode(nodes, &eventNodes, L"image", imageRef.Value);
            AddGraphEdge(edges, &eventEdges, sourceId, imageId, L"source-observes-image", event.EventId);
            if (!processId.empty() && imageRef.LinkSourceProcess)
            {
                AddGraphEdge(edges, &eventEdges, processId, imageId, L"process-loads-image", event.EventId);
            }
            if (!targetProcessId.empty() && imageRef.LinkTargetProcess)
            {
                AddGraphEdge(edges, &eventEdges, targetProcessId, imageId, L"process-loads-image", event.EventId);
            }
        }
    }
}

TimelineStore::TimelineStore() :
    TimelineStore(262144)
{
}

TimelineStore::TimelineStore(size_t capacity)
{
    SetCapacity(capacity);
}

void TimelineStore::Clear()
{
    std::lock_guard<std::mutex> lock(Mutex);
    Events.clear();
    NextEventId = 1;
    DroppedEvents = 0;
}

void TimelineStore::SetCapacity(size_t capacity)
{
    std::lock_guard<std::mutex> lock(Mutex);
    if (capacity < kMinTimelineCapacity)
    {
        capacity = kMinTimelineCapacity;
    }
    if (capacity > kMaxTimelineCapacity)
    {
        capacity = kMaxTimelineCapacity;
    }

    MaxEvents = capacity;
    while (Events.size() > MaxEvents)
    {
        Events.pop_front();
        ++DroppedEvents;
    }
}

size_t TimelineStore::Capacity() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return MaxEvents;
}

uint64_t TimelineStore::Dropped() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return DroppedEvents;
}

TimelineIngestResult TimelineStore::IngestThreatIntel(
    const std::vector<TiEventRecord>& events,
    const std::wstring& mode)
{
    TimelineIngestResult result = {};
    result.SourceRecords = events.size();

    std::lock_guard<std::mutex> lock(Mutex);
    uint64_t beforeDropped = DroppedEvents;

    for (const TiEventRecord& item : events)
    {
        TimelineEvent event = {};
        event.TimestampFileTime = item.Timestamp;
        event.Source = L"ti";
        event.Domain = L"threat-intelligence";
        event.Action = L"event";
        event.ProcessId = item.ProcessId;
        event.ThreadId = item.ThreadId;
        event.TargetProcessId = item.TargetProcessId;
        event.Entity = TiTaskText(item);
        event.Summary = TiTaskText(item);
        if (!item.ImagePath.empty())
        {
            event.Summary += L" image=" + item.ImagePath;
        }
        if (item.TargetProcessId != 0)
        {
            event.Summary += L" target_pid=" + std::to_wstring(item.TargetProcessId);
        }
        event.Risk = L"info";
        event.Confidence = item.DecodedByTdh ? L"tdh-decoded" : L"raw";
        event.Evidence[L"mode"] = mode;
        event.Evidence[L"task_id"] = std::to_wstring(static_cast<uint32_t>(item.TaskId));
        event.Evidence[L"level"] = std::to_wstring(static_cast<uint32_t>(item.Level));
        event.Evidence[L"opcode"] = std::to_wstring(static_cast<uint32_t>(item.Opcode));
        event.Evidence[L"channel"] = std::to_wstring(static_cast<uint32_t>(item.Channel));
        if (item.Keyword != 0)
        {
            event.Evidence[L"keyword"] = HexU64(item.Keyword);
        }
        AddEvidenceIfPresent(&event.Evidence, L"task_name", item.TaskName);
        AddEvidenceIfPresent(&event.Evidence, L"opcode_name", item.OpcodeName);
        AddEvidenceIfPresent(&event.Evidence, L"image_path", item.ImagePath);
        AddEvidenceIfPresent(&event.Evidence, L"target_image", item.TargetImageBase);
        AddEvidenceIfPresent(&event.Evidence, L"raw_payload_hex", item.RawPayloadHex);

        size_t payloadLimit = std::min<size_t>(item.Payload.size(), 16);
        for (size_t index = 0; index < payloadLimit; ++index)
        {
            std::wstring key = L"payload." + item.Payload[index].Name;
            if (!item.Payload[index].Value.empty())
            {
                event.Evidence[key] = item.Payload[index].Value;
            }
        }
        if (item.Payload.size() > payloadLimit)
        {
            event.Evidence[L"payload_truncated"] = std::to_wstring(item.Payload.size() - payloadLimit);
        }

        AddEventLocked(std::move(event));
        ++result.Added;
    }

    result.Dropped = DroppedEvents - beforeDropped;
    return result;
}

TimelineIngestResult TimelineStore::IngestSnapshot(
    const SnapshotDocument& document,
    const std::wstring& sourceName)
{
    TimelineIngestResult result = {};
    result.SourceRecords = document.Processes.size() + document.Records.size();

    std::lock_guard<std::mutex> lock(Mutex);
    uint64_t beforeDropped = DroppedEvents;

    for (const SnapshotProcessRecord& process : document.Processes)
    {
        TimelineEvent event = {};
        event.TimestampUtc = document.TimestampUtc;
        event.Source = L"snapshot";
        event.Domain = L"process";
        event.Action = L"observed";
        event.ProcessId = process.ProcessId;
        event.Entity = process.Identity.empty() ? process.ImageName : process.Identity;
        event.Summary = L"snapshot process " + process.ImageName;
        event.Risk = L"info";
        event.Confidence = L"snapshot";
        event.Evidence[L"source"] = sourceName;
        AddEvidenceIfPresent(&event.Evidence, L"label", document.Label);
        AddEvidenceIfPresent(&event.Evidence, L"boot_id", document.BootId);
        AddEvidenceIfPresent(&event.Evidence, L"image", process.ImageName);
        AddEvidenceIfPresent(&event.Evidence, L"identity", process.Identity);
        if (process.Eprocess != 0)
        {
            event.Evidence[L"eprocess"] = HexU64(process.Eprocess);
        }
        if (process.DirectoryTableBase != 0)
        {
            event.Evidence[L"dtb"] = HexU64(process.DirectoryTableBase);
        }
        if (process.UserDirectoryTableBase != 0)
        {
            event.Evidence[L"user_dtb"] = HexU64(process.UserDirectoryTableBase);
        }
        if (process.HasCreateTime)
        {
            event.Evidence[L"create_time"] = std::to_wstring(process.CreateTime);
        }

        AddEventLocked(std::move(event));
        ++result.Added;
    }

    for (const SnapshotRecord& record : document.Records)
    {
        TimelineEvent event = {};
        event.TimestampUtc = document.TimestampUtc;
        event.Source = L"snapshot";
        event.Domain = record.Domain.empty() ? L"snapshot" : record.Domain;
        event.Action = L"observed";
        event.ProcessId = SnapshotRecordPid(record);
        event.Entity = record.Identity;
        event.Summary = SnapshotRecordSummary(record);
        event.Risk = record.Risk.empty() ? L"info" : record.Risk;
        event.Confidence = record.Volatile ? L"volatile-snapshot" : L"snapshot";
        event.Evidence = record.Evidence;
        event.Evidence[L"source"] = sourceName;
        AddEvidenceIfPresent(&event.Evidence, L"label", document.Label);
        AddEvidenceIfPresent(&event.Evidence, L"boot_id", document.BootId);
        AddEvidenceIfPresent(&event.Evidence, L"display", record.Display);
        if (!record.Tags.empty())
        {
            std::wstring tags;
            for (size_t i = 0; i < record.Tags.size(); ++i)
            {
                if (i > 0)
                {
                    tags += L",";
                }
                tags += record.Tags[i];
            }
            event.Evidence[L"tags"] = tags;
        }

        AddEventLocked(std::move(event));
        ++result.Added;
    }

    for (const auto& item : document.DomainWarnings)
    {
        for (const std::wstring& warning : item.second)
        {
            result.Warnings.push_back(item.first + L": " + warning);
        }
    }

    result.Dropped = DroppedEvents - beforeDropped;
    return result;
}

TimelineIngestResult TimelineStore::IngestEvents(
    const std::vector<TimelineEvent>& events)
{
    TimelineIngestResult result = {};
    result.SourceRecords = events.size();

    std::lock_guard<std::mutex> lock(Mutex);
    uint64_t beforeDropped = DroppedEvents;
    for (const TimelineEvent& item : events)
    {
        TimelineEvent event = item;
        AddEventLocked(std::move(event));
        ++result.Added;
    }

    result.Dropped = DroppedEvents - beforeDropped;
    return result;
}

std::vector<TimelineEvent> TimelineStore::Query(const TimelineQueryOptions& options) const
{
    std::vector<TimelineEvent> out;
    std::lock_guard<std::mutex> lock(Mutex);

    auto matches = [&options](const TimelineEvent& event) -> bool
    {
        bool matched = true;
        if (!options.Source.empty() &&
            TimelineToLower(event.Source) != TimelineToLower(options.Source))
        {
            matched = false;
        }
        if (matched &&
            !options.Domain.empty() &&
            TimelineToLower(event.Domain) != TimelineToLower(options.Domain))
        {
            matched = false;
        }
        if (matched &&
            options.HasProcessId &&
            event.ProcessId != options.ProcessId &&
            event.TargetProcessId != options.ProcessId)
        {
            matched = false;
        }
        return matched;
    };

    size_t limit = options.Limit;
    if (options.NewestFirst)
    {
        for (auto it = Events.rbegin(); it != Events.rend(); ++it)
        {
            if (matches(*it))
            {
                out.push_back(*it);
                if (limit != 0 && out.size() >= limit)
                {
                    break;
                }
            }
        }
    }
    else
    {
        for (const TimelineEvent& event : Events)
        {
            if (matches(event))
            {
                out.push_back(event);
                if (limit != 0 && out.size() >= limit)
                {
                    break;
                }
            }
        }
    }

    return out;
}

std::vector<TimelineEvent> TimelineStore::AllEvents() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return std::vector<TimelineEvent>(Events.begin(), Events.end());
}

TimelineGraphResult TimelineStore::BuildGraph(const TimelineGraphQueryOptions& options) const
{
    TimelineGraphResult result = {};
    result.Options = options;
    std::map<std::wstring, TimelineGraphNode> nodes;
    std::map<std::wstring, TimelineGraphEdge> edges;
    std::vector<TimelineEvent> events;

    {
        std::lock_guard<std::mutex> lock(Mutex);
        events.assign(Events.begin(), Events.end());
    }
    result.TotalEvents = events.size();

    auto handleEvent = [&result, &nodes, &edges, &options](const TimelineEvent& event) -> bool
    {
        bool keepGoing = true;
        if (TimelineEventMatchesGraphQuery(event, options))
        {
            if (options.Limit != 0 && result.MatchedEvents >= options.Limit)
            {
                result.Truncated = true;
                keepGoing = false;
            }
            else
            {
                AddTimelineGraphEvent(event, &nodes, &edges);
                ++result.MatchedEvents;
            }
        }
        return keepGoing;
    };

    if (options.NewestFirst)
    {
        for (auto it = events.rbegin(); it != events.rend(); ++it)
        {
            if (!handleEvent(*it))
            {
                break;
            }
        }
    }
    else
    {
        for (const TimelineEvent& event : events)
        {
            if (!handleEvent(event))
            {
                break;
            }
        }
    }

    for (const auto& item : nodes)
    {
        result.Nodes.push_back(item.second);
    }
    for (const auto& item : edges)
    {
        result.Edges.push_back(item.second);
    }

    return result;
}

TimelineStats TimelineStore::GetStats() const
{
    TimelineStats stats = {};
    std::lock_guard<std::mutex> lock(Mutex);

    stats.Stored = Events.size();
    stats.Capacity = MaxEvents;
    stats.NextEventId = NextEventId;
    stats.Dropped = DroppedEvents;
    for (const TimelineEvent& event : Events)
    {
        ++stats.BySource[event.Source.empty() ? L"<unknown>" : event.Source];
        ++stats.ByDomain[event.Domain.empty() ? L"<unknown>" : event.Domain];
    }

    return stats;
}

bool TimelineStore::ExportJsonl(const std::wstring& path, std::wstring* error) const
{
    std::vector<TimelineEvent> events = AllEvents();
    return WriteSnapshotTextFile(path, BuildTimelineJsonl(events), error);
}

void TimelineStore::AddEventLocked(TimelineEvent event)
{
    event.EventId = NextEventIdLocked();
    Events.push_back(std::move(event));
    while (Events.size() > MaxEvents)
    {
        Events.pop_front();
        ++DroppedEvents;
    }
}

uint64_t TimelineStore::NextEventIdLocked()
{
    uint64_t eventId = NextEventId;
    ++NextEventId;
    return eventId;
}
