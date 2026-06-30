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

    void AppendEventKeyPart(std::wstring* key, const std::wstring& value)
    {
        if (key != nullptr)
        {
            *key += std::to_wstring(value.size());
            *key += L":";
            *key += value;
            *key += L"|";
        }
    }

    void AppendEventKeyPart(std::wstring* key, uint64_t value)
    {
        AppendEventKeyPart(key, std::to_wstring(value));
    }

    bool TimelineEventKeySkipsEvidence(const std::wstring& name)
    {
        bool skip = false;
        std::wstring lowered = TimelineToLower(name);

        if (lowered == L"mode" || lowered == L"source")
        {
            skip = true;
        }

        return skip;
    }

    std::wstring TimelineEventKey(const TimelineEvent& event)
    {
        std::wstring key;

        AppendEventKeyPart(&key, event.TimestampFileTime);
        AppendEventKeyPart(&key, event.TimestampUtc);
        AppendEventKeyPart(&key, event.Source);
        AppendEventKeyPart(&key, event.Domain);
        AppendEventKeyPart(&key, event.Action);
        AppendEventKeyPart(&key, event.ProcessId);
        AppendEventKeyPart(&key, event.ThreadId);
        AppendEventKeyPart(&key, event.TargetProcessId);
        AppendEventKeyPart(&key, event.Entity);
        AppendEventKeyPart(&key, event.Summary);
        AppendEventKeyPart(&key, event.Risk);
        AppendEventKeyPart(&key, event.Confidence);

        for (const auto& item : event.Evidence)
        {
            if (!TimelineEventKeySkipsEvidence(item.first))
            {
                AppendEventKeyPart(&key, item.first);
                AppendEventKeyPart(&key, item.second);
            }
        }

        return key;
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

    bool SnapshotEvidenceValueByKey(
        const SnapshotRecord& record,
        const std::wstring& key,
        std::wstring* value)
    {
        bool found = false;
        std::wstring wanted = TimelineToLower(key);

        for (const auto& item : record.Evidence)
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

    bool SnapshotRecordPid(const SnapshotRecord& record, const std::wstring& key, uint32_t* pid)
    {
        bool ok = false;
        std::wstring value;

        if (SnapshotEvidenceValueByKey(record, key, &value))
        {
            ok = ParsePidFromText(value, pid);
        }

        return ok;
    }

    uint32_t SnapshotRecordAnyPid(const SnapshotRecord& record)
    {
        uint32_t pid = 0;
        static const wchar_t* kKeys[] =
        {
            L"pid",
            L"process_id",
            L"owner_pid",
            L"target_pid",
            L"source_pid"
        };

        for (const wchar_t* key : kKeys)
        {
            if (SnapshotRecordPid(record, key, &pid))
            {
                break;
            }
        }

        return pid;
    }

    void AddLowerNonEmpty(std::set<std::wstring>* values, const std::wstring& value)
    {
        if (values != nullptr && !value.empty())
        {
            values->insert(TimelineToLower(value));
        }
    }

    void AddLowerImageVariants(std::set<std::wstring>* values, const std::wstring& value)
    {
        if (values != nullptr && !value.empty())
        {
            std::wstring lowered = TimelineToLower(value);
            values->insert(lowered);

            size_t slash = lowered.find_last_of(L"\\/");
            if (slash != std::wstring::npos && slash + 1 < lowered.size())
            {
                values->insert(lowered.substr(slash + 1));
            }
        }
    }

    void AddSnapshotRecordImages(const SnapshotRecord& record, std::set<std::wstring>* images)
    {
        std::wstring value;
        if (SnapshotEvidenceValueByKey(record, L"image", &value))
        {
            AddLowerImageVariants(images, value);
        }
        if (SnapshotEvidenceValueByKey(record, L"image_path", &value))
        {
            AddLowerImageVariants(images, value);
        }
        if (SnapshotEvidenceValueByKey(record, L"target_image", &value))
        {
            AddLowerImageVariants(images, value);
        }
        if (SnapshotEvidenceValueByKey(record, L"path", &value))
        {
            AddLowerImageVariants(images, value);
        }
    }

    bool TimelineEventMatchesReconcile(
        const TimelineEvent& event,
        const TimelineReconcileOptions& options)
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
    }

    uint32_t ReconcileRiskRank(const std::wstring& risk)
    {
        uint32_t rank = 0;
        std::wstring lowered = TimelineToLower(risk);
        if (lowered == L"critical" || lowered == L"high")
        {
            rank = 3;
        }
        else if (lowered == L"medium")
        {
            rank = 2;
        }
        else if (lowered == L"low")
        {
            rank = 1;
        }
        return rank;
    }

    void AddReconcileFinding(
        std::vector<TimelineReconcileFinding>* findings,
        TimelineReconcileFinding finding,
        uint64_t liveDropped)
    {
        if (findings != nullptr)
        {
            if (liveDropped != 0 && finding.Confidence != L"event-backed")
            {
                finding.Confidence = L"loss-limited";
                finding.Evidence[L"live_dropped"] = std::to_wstring(liveDropped);
            }
            findings->push_back(std::move(finding));
        }
    }

    bool ReconcileFindingLess(
        const TimelineReconcileFinding& a,
        const TimelineReconcileFinding& b)
    {
        uint32_t ra = ReconcileRiskRank(a.Risk);
        uint32_t rb = ReconcileRiskRank(b.Risk);
        if (ra != rb)
        {
            return ra > rb;
        }
        if (a.Kind != b.Kind)
        {
            return a.Kind < b.Kind;
        }
        if (a.Domain != b.Domain)
        {
            return a.Domain < b.Domain;
        }
        return a.Subject < b.Subject;
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
    EventKeysInOrder.clear();
    EventKeys.clear();
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
        DropOldestEventLocked();
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

        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
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

        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
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

        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
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
        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
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

TimelineReconcileResult TimelineStore::ReconcileSnapshot(
    const SnapshotDocument& document,
    const TimelineReconcileOptions& options) const
{
    TimelineReconcileResult result = {};
    result.Options = options;
    result.SnapshotLabel = document.Label.empty() ? L"<snapshot>" : document.Label;
    result.SnapshotProcesses = document.Processes.size();
    result.SnapshotRecords = document.Records.size();
    result.LiveDropped = options.LiveDropped;

    std::set<uint32_t> snapshotPids;
    std::set<std::wstring> snapshotImages;
    for (const SnapshotProcessRecord& process : document.Processes)
    {
        if (process.ProcessId != 0)
        {
            snapshotPids.insert(process.ProcessId);
        }
        AddLowerImageVariants(&snapshotImages, process.ImageName);
    }
    for (const SnapshotRecord& record : document.Records)
    {
        uint32_t pid = SnapshotRecordAnyPid(record);
        if (pid != 0)
        {
            snapshotPids.insert(pid);
        }
        AddSnapshotRecordImages(record, &snapshotImages);
    }

    std::vector<TimelineEvent> events = AllEvents();
    result.TimelineEvents = events.size();
    std::set<uint32_t> eventPids;
    std::set<std::wstring> eventImages;
    for (const TimelineEvent& event : events)
    {
        if (!TimelineEventMatchesReconcile(event, options))
        {
            continue;
        }
        if (event.ProcessId != 0)
        {
            eventPids.insert(event.ProcessId);
        }
        if (event.TargetProcessId != 0)
        {
            eventPids.insert(event.TargetProcessId);
        }
        std::vector<TimelineImageRef> images = TimelineEventImageRefs(event);
        for (const TimelineImageRef& image : images)
        {
            AddLowerImageVariants(&eventImages, image.Value);
        }

        if (event.ProcessId != 0 &&
            event.Action != L"process-exit" &&
            snapshotPids.find(event.ProcessId) == snapshotPids.end())
        {
            TimelineReconcileFinding finding = {};
            finding.Kind = L"event-without-snapshot-process";
            finding.Domain = event.Domain;
            finding.Subject = L"pid:" + std::to_wstring(event.ProcessId);
            finding.Risk = event.Action == L"image-load" ? L"medium" : L"low";
            finding.Confidence = L"event-backed";
            finding.Summary = L"timeline event has no matching process in snapshot";
            finding.EventId = event.EventId;
            finding.ProcessId = event.ProcessId;
            finding.Evidence[L"action"] = event.Action;
            finding.Evidence[L"source"] = event.Source;
            AddEvidenceIfPresent(&finding.Evidence, L"entity", event.Entity);
            AddReconcileFinding(&result.Findings, std::move(finding), options.LiveDropped);
        }

        for (const TimelineImageRef& image : images)
        {
            if (!image.Value.empty() && snapshotImages.find(TimelineToLower(image.Value)) == snapshotImages.end())
            {
                TimelineReconcileFinding finding = {};
                finding.Kind = L"event-without-snapshot-image";
                finding.Domain = event.Domain;
                finding.Subject = image.Value;
                finding.Risk = event.Action == L"image-load" ? L"medium" : L"low";
                finding.Confidence = L"event-backed";
                finding.Summary = L"timeline image evidence has no matching image in snapshot";
                finding.EventId = event.EventId;
                finding.ProcessId = event.ProcessId;
                finding.Evidence[L"action"] = event.Action;
                finding.Evidence[L"source"] = event.Source;
                AddReconcileFinding(&result.Findings, std::move(finding), options.LiveDropped);
            }
        }
    }

    for (const SnapshotRecord& record : document.Records)
    {
        if (!options.Domain.empty() &&
            TimelineToLower(record.Domain) != TimelineToLower(options.Domain))
        {
            continue;
        }
        if (ReconcileRiskRank(record.Risk) < 2)
        {
            continue;
        }

        uint32_t pid = SnapshotRecordAnyPid(record);
        if (options.HasProcessId && pid != options.ProcessId)
        {
            continue;
        }

        bool pidSeen = pid != 0 && eventPids.find(pid) != eventPids.end();
        std::set<std::wstring> recordImages;
        AddSnapshotRecordImages(record, &recordImages);
        bool imageSeen = recordImages.empty();
        for (const std::wstring& image : recordImages)
        {
            if (eventImages.find(image) != eventImages.end())
            {
                imageSeen = true;
                break;
            }
        }

        if (!pidSeen && !imageSeen)
        {
            TimelineReconcileFinding finding = {};
            finding.Kind = L"snapshot-record-without-event";
            finding.Domain = record.Domain;
            finding.Subject = record.Identity.empty() ? record.Display : record.Identity;
            finding.Risk = record.Risk.empty() ? L"medium" : record.Risk;
            finding.Confidence = L"no-live-event";
            finding.Summary = L"snapshot state has no matching timeline event";
            finding.ProcessId = pid;
            AddEvidenceIfPresent(&finding.Evidence, L"display", record.Display);
            AddEvidenceIfPresent(&finding.Evidence, L"identity", record.Identity);
            AddReconcileFinding(&result.Findings, std::move(finding), options.LiveDropped);
        }
    }

    if (options.LiveDropped != 0)
    {
        result.Warnings.push_back(
            L"live event ring reported dropped events; absence findings are confidence-limited");
    }
    for (const auto& item : document.DomainWarnings)
    {
        for (const std::wstring& warning : item.second)
        {
            result.Warnings.push_back(item.first + L": " + warning);
        }
    }

    std::sort(result.Findings.begin(), result.Findings.end(), ReconcileFindingLess);
    if (options.Limit != 0 && result.Findings.size() > options.Limit)
    {
        result.Findings.resize(options.Limit);
        result.Truncated = true;
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

bool TimelineStore::AddEventLocked(TimelineEvent event)
{
    bool added = false;
    std::wstring key = TimelineEventKey(event);
    if (EventKeys.find(key) != EventKeys.end())
    {
        return false;
    }

    event.EventId = NextEventIdLocked();
    Events.push_back(std::move(event));
    EventKeys.insert(key);
    EventKeysInOrder.push_back(key);
    while (Events.size() > MaxEvents)
    {
        DropOldestEventLocked();
        ++DroppedEvents;
    }

    added = true;
    return added;
}

void TimelineStore::DropOldestEventLocked()
{
    if (!Events.empty())
    {
        Events.pop_front();
    }
    if (!EventKeysInOrder.empty())
    {
        EventKeys.erase(EventKeysInOrder.front());
        EventKeysInOrder.pop_front();
    }
}

uint64_t TimelineStore::NextEventIdLocked()
{
    uint64_t eventId = NextEventId;
    ++NextEventId;
    return eventId;
}
