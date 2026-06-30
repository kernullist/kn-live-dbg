#include "TimelineStore.h"

#include "SnapshotJson.h"

#include <algorithm>
#include <cerrno>
#include <cwchar>
#include <map>
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
