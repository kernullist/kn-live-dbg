#include "TimelineSelfTest.h"

#include "SnapshotDiff.h"
#include "TimelineDashboard.h"
#include "TimelineStore.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <iostream>
#include <string>
#include <vector>

namespace
{
    struct SelfTestContext
    {
        uint32_t Passed = 0;
        uint32_t Failed = 0;
    };

    void Check(
        SelfTestContext* context,
        bool condition,
        const wchar_t* name)
    {
        do
        {
            if (context == nullptr)
            {
                break;
            }

            if (condition)
            {
                ++context->Passed;
                std::wcout << L"[timeline.selftest] PASS " << name << L"\n";
            }
            else
            {
                ++context->Failed;
                std::wcerr << L"[timeline.selftest] FAIL " << name << L"\n";
            }
        } while (false);
    }

    TimelineEvent MakeProcessEvent(
        uint32_t pid,
        const std::wstring& image)
    {
        TimelineEvent event = {};
        event.Source = L"live";
        event.Domain = L"process";
        event.Action = L"process-create";
        event.ProcessId = pid;
        event.Entity = image;
        event.Summary = L"process create " + image;
        event.Risk = L"info";
        event.Confidence = L"event-backed";
        event.Evidence[L"image"] = image;
        return event;
    }

    TimelineEvent MakeImageEvent(
        uint32_t pid,
        const std::wstring& image)
    {
        TimelineEvent event = {};
        event.Source = L"live";
        event.Domain = L"image";
        event.Action = L"image-load";
        event.ProcessId = pid;
        event.Entity = image;
        event.Summary = L"image load " + image;
        event.Risk = L"medium";
        event.Confidence = L"event-backed";
        event.Evidence[L"image"] = image;
        return event;
    }

    TimelineEvent MakeKernelLiveEvent(
        uint64_t timestamp,
        const std::wstring& domain,
        const std::wstring& action,
        uint32_t pid,
        uint32_t tid,
        const std::wstring& entity)
    {
        TimelineEvent event = {};
        event.TimestampFileTime = timestamp;
        event.Source = L"kernel-live";
        event.Domain = domain;
        event.Action = action;
        event.ProcessId = pid;
        event.ThreadId = tid;
        event.Entity = entity;
        event.Summary = action + L" pid=" + std::to_wstring(pid);
        if (tid != 0)
        {
            event.Summary += L" tid=" + std::to_wstring(tid);
        }
        event.Risk = L"info";
        event.Confidence = L"kernel-callback";
        return event;
    }

    TimelineEvent MakeSemanticEvent(
        uint64_t timestamp,
        const std::wstring& source,
        const std::wstring& domain,
        const std::wstring& action,
        uint32_t pid,
        uint32_t targetPid,
        const std::wstring& entity,
        const std::wstring& risk)
    {
        TimelineEvent event = {};
        event.TimestampFileTime = timestamp;
        event.Source = source;
        event.Domain = domain;
        event.Action = action;
        event.ProcessId = pid;
        event.TargetProcessId = targetPid;
        event.Entity = entity;
        event.Summary = action + L" " + entity;
        event.Risk = risk;
        event.Confidence = L"fixture";
        return event;
    }

    uint64_t g_tiTestSequence = 1;

    TiEventRecord MakeTiEvent(
        uint64_t timestamp,
        uint32_t pid,
        uint32_t targetPid,
        const std::wstring& taskName,
        const std::wstring& image)
    {
        TiEventRecord event = {};
        event.Sequence = g_tiTestSequence++;
        event.Timestamp = timestamp;
        event.ProcessId = pid;
        event.ThreadId = 44;
        event.TargetProcessId = targetPid;
        event.TaskId = 77;
        event.TaskName = taskName;
        event.ImagePath = image;
        event.TargetImageBase = L"target.exe";
        event.DecodedByTdh = true;

        TiPayloadField field = {};
        field.Name = L"Operation";
        field.Value = taskName;
        field.TypeName = L"UnicodeString";
        event.Payload.push_back(field);

        return event;
    }

    void AddTiPayloadField(
        TiEventRecord* event,
        const std::wstring& name,
        const std::wstring& value,
        const std::wstring& typeName)
    {
        if (event != nullptr)
        {
            TiPayloadField field = {};
            field.Name = name;
            field.Value = value;
            field.TypeName = typeName;
            event->Payload.push_back(field);
        }
    }

    SnapshotDocument MakeSnapshotFixture()
    {
        SnapshotDocument document = {};
        document.Schema = L"kn-live-dbg.snapshot.v1";
        document.Label = L"timeline-selftest";
        document.TimestampUtc = L"2026-06-30T00:00:00Z";
        document.BootId = L"boot-selftest";

        SnapshotProcessRecord process = {};
        process.ProcessId = 100;
        process.ImageName = L"clean.exe";
        process.Identity = L"pid:100 clean.exe";
        document.Processes.push_back(process);

        SnapshotRecord record = {};
        record.Domain = L"image";
        record.Identity = L"hidden.dll";
        record.Display = L"hidden image evidence";
        record.Risk = L"high";
        record.Evidence[L"pid"] = L"300";
        record.Evidence[L"image"] = L"hidden.dll";
        document.Records.push_back(record);

        document.DomainWarnings[L"image"].push_back(L"fixture warning");
        return document;
    }

    bool HasGraphNode(
        const TimelineGraphResult& graph,
        const std::wstring& kind,
        const std::wstring& label)
    {
        bool found = false;
        for (const TimelineGraphNode& node : graph.Nodes)
        {
            if (node.Kind == kind && node.Label == label)
            {
                found = true;
                break;
            }
        }
        return found;
    }

    bool HasGraphEdgeKind(
        const TimelineGraphResult& graph,
        const std::wstring& kind)
    {
        bool found = false;
        for (const TimelineGraphEdge& edge : graph.Edges)
        {
            if (edge.Kind == kind)
            {
                found = true;
                break;
            }
        }
        return found;
    }

    bool HasReconcileFinding(
        const TimelineReconcileResult& result,
        const std::wstring& kind,
        uint32_t pid,
        const std::wstring& subject,
        const std::wstring& confidence)
    {
        bool found = false;
        for (const TimelineReconcileFinding& finding : result.Findings)
        {
            if (finding.Kind == kind &&
                (pid == 0 || finding.ProcessId == pid) &&
                (subject.empty() || finding.Subject == subject) &&
                (confidence.empty() || finding.Confidence == confidence))
            {
                found = true;
                break;
            }
        }
        return found;
    }

    bool HasAnalysisFinding(
        const TimelineAnalysisResult& result,
        const std::wstring& kind)
    {
        bool found = false;
        for (const TimelineAnalysisFinding& finding : result.Findings)
        {
            if (finding.Kind == kind)
            {
                found = true;
                break;
            }
        }
        return found;
    }

    bool HasEventEvidence(
        const std::vector<TimelineEvent>& events,
        const std::wstring& key,
        const std::wstring& value)
    {
        bool found = false;
        for (const TimelineEvent& event : events)
        {
            auto it = event.Evidence.find(key);
            if (it != event.Evidence.end() && (value.empty() || it->second == value))
            {
                found = true;
                break;
            }
        }
        return found;
    }

    bool HasEventEvidencePair(
        const std::vector<TimelineEvent>& events,
        const std::wstring& firstKey,
        const std::wstring& firstValue,
        const std::wstring& secondKey,
        const std::wstring& secondValue)
    {
        bool found = false;
        for (const TimelineEvent& event : events)
        {
            auto firstIt = event.Evidence.find(firstKey);
            auto secondIt = event.Evidence.find(secondKey);
            if (firstIt != event.Evidence.end() &&
                secondIt != event.Evidence.end() &&
                (firstValue.empty() || firstIt->second == firstValue) &&
                (secondValue.empty() || secondIt->second == secondValue))
            {
                found = true;
                break;
            }
        }
        return found;
    }
}

int RunTimelineSelfTest()
{
    int exitCode = 1;
    SelfTestContext context = {};

    do
    {
        TimelineStore store(1024);

        std::vector<TimelineEvent> events;
        events.push_back(MakeProcessEvent(100, L"clean.exe"));
        events.push_back(MakeImageEvent(200, L"ghost.dll"));

        TimelineIngestResult ingest = store.IngestEvents(events);
        TimelineStats stats = store.GetStats();
        Check(&context, ingest.Added == 2 && stats.Stored == 2, L"ingest-counts");

        TimelineIngestResult duplicateIngest = store.IngestEvents(events);
        stats = store.GetStats();
        Check(
            &context,
            duplicateIngest.SourceRecords == 2 &&
                duplicateIngest.Added == 0 &&
                stats.Stored == 2,
            L"ingest-deduplicates-repeat-events");

        std::vector<TiEventRecord> tiEvents;
        tiEvents.push_back(MakeTiEvent(1000, 400, 500, L"KERNEL_THREATINT_TASK_ALLOCVM", L"suspect.exe"));
        AddTiPayloadField(&tiEvents.back(), L"BaseAddress", L"0x0000000012340000", L"ptr");
        AddTiPayloadField(&tiEvents.back(), L"RegionSize", L"8192", L"u64");
        AddTiPayloadField(&tiEvents.back(), L"Protection", L"PAGE_EXECUTE_READWRITE", L"u32");
        AddTiPayloadField(&tiEvents.back(), L"AllocationType", L"MEM_COMMIT|MEM_RESERVE", L"u32");
        tiEvents.push_back(MakeTiEvent(2000, 400, 500, L"KERNEL_THREATINT_TASK_WRITEVM", L"suspect.exe"));
        AddTiPayloadField(&tiEvents.back(), L"DesiredAccess", L"0x001F0FFF", L"hex32");
        AddTiPayloadField(&tiEvents.back(), L"StartAddress", L"0x0000000012350000", L"ptr");

        TimelineIngestResult tiIngest = store.IngestThreatIntel(tiEvents, L"recent");
        stats = store.GetStats();
        Check(
            &context,
            tiIngest.SourceRecords == 2 &&
                tiIngest.Added == 2 &&
                stats.BySource[L"ti"] == 2 &&
                stats.ByDomain[L"threat-intelligence"] == 2,
            L"ti-ingest-counts");

        TimelineQueryOptions tiQuery = {};
        tiQuery.Source = L"ti";
        tiQuery.Domain = L"threat-intelligence";
        tiQuery.HasProcessId = true;
        tiQuery.ProcessId = 400;
        tiQuery.Limit = 10;
        tiQuery.NewestFirst = false;
        std::vector<TimelineEvent> tiFiltered = store.Query(tiQuery);
        Check(
            &context,
            tiFiltered.size() == 2 &&
                tiFiltered[0].Action == L"KERNEL_THREATINT_TASK_ALLOCVM" &&
                tiFiltered[0].Risk == L"warning" &&
                tiFiltered[0].Evidence[L"memory_address"] == L"0x0000000012340000" &&
                tiFiltered[0].Evidence[L"allocation_size"] == L"8192" &&
                tiFiltered[0].Evidence[L"protection"] == L"PAGE_EXECUTE_READWRITE" &&
                tiFiltered[0].Evidence[L"allocation_type"] == L"MEM_COMMIT|MEM_RESERVE" &&
                tiFiltered[0].Evidence[L"payload.BaseAddress"] == L"0x0000000012340000" &&
                tiFiltered[0].Evidence[L"payload_type.BaseAddress"] == L"ptr" &&
                tiFiltered[1].Action == L"KERNEL_THREATINT_TASK_WRITEVM" &&
                tiFiltered[1].Risk == L"critical" &&
                tiFiltered[1].Evidence[L"desired_access"] == L"0x001F0FFF" &&
                tiFiltered[1].Evidence[L"start_address"] == L"0x0000000012350000" &&
                tiFiltered[1].Evidence[L"classification_reason"] == L"writevm",
            L"ti-classification-action-risk");

        // Re-present the already-ingested seq=1 record plus a newer seq event.
        // Sequence cursor must skip seq<=cursor while still accepting the new one,
        // even if a later synthetic batch reused an older timestamp.
        std::vector<TiEventRecord> repeatedTiEvents;
        repeatedTiEvents.push_back(tiEvents[0]); // same Sequence as first ingest
        repeatedTiEvents.push_back(MakeTiEvent(3000, 401, 500, L"KERNEL_THREATINT_TASK_OPENPROCESS", L"tool.exe"));
        TimelineIngestResult tiCursorIngest = store.IngestThreatIntel(repeatedTiEvents, L"recent");
        Check(
            &context,
            tiCursorIngest.SourceRecords == 1 &&
                tiCursorIngest.Added == 1 &&
                !tiCursorIngest.Warnings.empty(),
            L"ti-recent-cursor-skips-older-records");

        TimelineIngestResult tiBoundaryRepeat = store.IngestThreatIntel(repeatedTiEvents, L"recent");
        Check(
            &context,
            tiBoundaryRepeat.SourceRecords == 0 &&
                tiBoundaryRepeat.Added == 0 &&
                !tiBoundaryRepeat.Warnings.empty(),
            L"ti-recent-cursor-skips-boundary-records");

        TimelineIngestResult tiAllIngest = store.IngestThreatIntel(repeatedTiEvents, L"all");
        Check(
            &context,
            tiAllIngest.SourceRecords == 2 &&
                tiAllIngest.Added == 0,
            L"ti-all-rescans-ring-with-dedupe");

        // Out-of-order ETW timestamp must not be skipped when Sequence advances.
        TimelineStore oooStore(1024);
        std::vector<TiEventRecord> oooFirst;
        oooFirst.push_back(MakeTiEvent(5000, 410, 500, L"KERNEL_THREATINT_TASK_ALLOCVM", L"ooo.exe"));
        Check(
            &context,
            oooStore.IngestThreatIntel(oooFirst, L"recent").Added == 1,
            L"ti-ooo-cursor-seed");
        std::vector<TiEventRecord> oooLate;
        TiEventRecord late = MakeTiEvent(1000, 411, 500, L"KERNEL_THREATINT_TASK_WRITEVM", L"ooo.exe");
        oooLate.push_back(late);
        TimelineIngestResult oooIngest = oooStore.IngestThreatIntel(oooLate, L"recent");
        Check(
            &context,
            oooIngest.SourceRecords == 1 &&
                oooIngest.Added == 1 &&
                late.Timestamp < oooFirst[0].Timestamp,
            L"ti-sequence-cursor-accepts-earlier-timestamp");

        TimelineQueryOptions query = {};
        query.Source = L"live";
        query.Domain = L"process";
        query.HasProcessId = true;
        query.ProcessId = 100;
        query.Limit = 10;
        query.NewestFirst = false;

        std::vector<TimelineEvent> filtered = store.Query(query);
        Check(
            &context,
            filtered.size() == 1 &&
                filtered[0].EventId == 1 &&
                filtered[0].ProcessId == 100,
            L"query-source-domain-pid");

        TimelineGraphQueryOptions graphOptions = {};
        graphOptions.Limit = 10;
        graphOptions.NewestFirst = false;
        TimelineGraphResult graph = store.BuildGraph(graphOptions);
        Check(&context, HasGraphNode(graph, L"process", L"100"), L"graph-process-node");
        Check(&context, HasGraphNode(graph, L"image", L"ghost.dll"), L"graph-image-node");
        Check(&context, HasGraphEdgeKind(graph, L"process-loads-image"), L"graph-image-edge");

        TimelineStore semanticStore(1024);
        std::vector<TimelineEvent> semanticEvents;
        TimelineEvent cross = MakeSemanticEvent(
            400000000,
            L"sensor",
            L"process",
            L"WriteVirtualMemory",
            900,
            901,
            L"writer.exe",
            L"info");
        cross.Evidence[L"boot_id"] = L"boot-semantic";
        semanticEvents.push_back(cross);

        TimelineEvent network = MakeSemanticEvent(
            401000000,
            L"sensor",
            L"network",
            L"tcp-connect",
            900,
            0,
            L"",
            L"warning");
        network.Evidence[L"remote_ip"] = L"203.0.113.10";
        network.Evidence[L"remote_port"] = L"443";
        semanticEvents.push_back(network);

        TimelineEvent dns = MakeSemanticEvent(
            402000000,
            L"sensor",
            L"dns",
            L"dns-query",
            900,
            0,
            L"",
            L"warning");
        dns.Evidence[L"dns_query"] = L"stage.example.test";
        semanticEvents.push_back(dns);

        TimelineEvent file = MakeSemanticEvent(
            403000000,
            L"sensor",
            L"file",
            L"file-write",
            900,
            0,
            L"",
            L"info");
        file.Evidence[L"file_path"] = L"C:\\Users\\Public\\dropper.exe";
        semanticEvents.push_back(file);

        TimelineEvent registry = MakeSemanticEvent(
            404000000,
            L"sensor",
            L"registry",
            L"set-value",
            900,
            0,
            L"",
            L"info");
        registry.Evidence[L"registry_key"] = L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Bad";
        semanticEvents.push_back(registry);

        TimelineEvent service = MakeSemanticEvent(
            405000000,
            L"sensor",
            L"service",
            L"create-service",
            900,
            0,
            L"",
            L"info");
        service.Evidence[L"service_name"] = L"BadSvc";
        semanticEvents.push_back(service);

        TimelineEvent task = MakeSemanticEvent(
            406000000,
            L"sensor",
            L"scheduled-task",
            L"register-task",
            900,
            0,
            L"",
            L"info");
        task.Evidence[L"task_name"] = L"\\BadTask";
        semanticEvents.push_back(task);

        TimelineEvent wmi = MakeSemanticEvent(
            407000000,
            L"sensor",
            L"wmi",
            L"consumer-binding",
            900,
            0,
            L"",
            L"info");
        wmi.Evidence[L"wmi_consumer"] = L"BadConsumer";
        semanticEvents.push_back(wmi);

        TimelineEvent memory = MakeSemanticEvent(
            408000000,
            L"sensor",
            L"vad",
            L"RW->RX protect",
            900,
            0,
            L"",
            L"info");
        memory.Evidence[L"vad_address"] = L"0x000001234000";
        memory.Evidence[L"protection"] = L"RW->RX";
        semanticEvents.push_back(memory);

        TimelineEvent remoteThread = MakeSemanticEvent(
            409000000,
            L"kernel-live",
            L"thread",
            L"thread-create",
            900,
            0,
            L"pid:900 tid:60000",
            L"info");
        remoteThread.ThreadId = 60000;
        remoteThread.Evidence[L"creator_pid"] = L"901";
        remoteThread.Evidence[L"creator_tid"] = L"70000";
        remoteThread.Evidence[L"source_pid"] = L"901";
        remoteThread.Evidence[L"target_pid"] = L"900";
        remoteThread.Evidence[L"remote_thread"] = L"true";
        remoteThread.Evidence[L"cross_process_operation"] = L"createremotethread";
        semanticEvents.push_back(remoteThread);

        TimelineIngestResult semanticIngest = semanticStore.IngestEvents(semanticEvents);
        Check(&context, semanticIngest.Added == semanticEvents.size(), L"semantic-ingest-counts");

        SnapshotDiffResult diffFixture = {};
        diffFixture.BaselineLabel = L"before";
        diffFixture.CurrentLabel = L"after";
        SnapshotDiffFinding diffFinding = {};
        diffFinding.Kind = L"added";
        diffFinding.NewRecord.Domain = L"drivers";
        diffFinding.NewRecord.Identity = L"bad.sys dispatch hook";
        diffFinding.NewRecord.Display = L"bad.sys dispatch hook";
        diffFinding.NewRecord.Risk = L"high";
        diffFinding.NewRecord.Evidence[L"pid"] = L"900";
        diffFixture.Findings.push_back(diffFinding);
        SnapshotDiffFinding registryDiffFinding = {};
        registryDiffFinding.Kind = L"added";
        registryDiffFinding.NewRecord.Domain = L"registry";
        registryDiffFinding.NewRecord.Identity = L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Bad";
        registryDiffFinding.NewRecord.Display = L"Run key added";
        registryDiffFinding.NewRecord.Risk = L"high";
        registryDiffFinding.NewRecord.Evidence[L"pid"] = L"900";
        registryDiffFinding.NewRecord.Evidence[L"key_path"] =
            L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Bad";
        diffFixture.Findings.push_back(registryDiffFinding);
        TimelineIngestResult diffIngest = semanticStore.IngestSnapshotDiff(diffFixture, L"selftest");
        Check(&context, diffIngest.Added == 2, L"snapshot-diff-ingest");

        std::vector<TimelineEvent> semanticStored = semanticStore.AllEvents();
        Check(
            &context,
            HasEventEvidence(semanticStored, L"process_instance_id", L"boot:boot-semantic|pid:900") &&
                HasEventEvidence(semanticStored, L"process_instance_id_basis", L"pid-only") &&
                HasEventEvidence(semanticStored, L"cross_process_operation", L"writevm") &&
                HasEventEvidence(semanticStored, L"network_endpoint", L"203.0.113.10:443") &&
                HasEventEvidence(semanticStored, L"file_executable", L"true") &&
                HasEventEvidence(semanticStored, L"registry_persistence", L"true") &&
                HasEventEvidence(semanticStored, L"remote_thread", L"true") &&
                HasEventEvidencePair(
                    semanticStored,
                    L"snapshot_diff_subject",
                    L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Bad",
                    L"analysis_family",
                    L"snapshot-diff"),
            L"semantic-normalization-evidence");

        TimelineGraphQueryOptions semanticGraphOptions = {};
        semanticGraphOptions.Limit = 64;
        semanticGraphOptions.NewestFirst = false;
        TimelineGraphResult semanticGraph = semanticStore.BuildGraph(semanticGraphOptions);
        Check(
            &context,
            HasGraphEdgeKind(semanticGraph, L"cross-process-writevm") &&
                HasGraphEdgeKind(semanticGraph, L"process-connects-host") &&
                HasGraphEdgeKind(semanticGraph, L"process-queries-dns") &&
                HasGraphEdgeKind(semanticGraph, L"process-touches-file") &&
                HasGraphEdgeKind(semanticGraph, L"process-modifies-registry") &&
                HasGraphEdgeKind(semanticGraph, L"process-controls-service") &&
                HasGraphEdgeKind(semanticGraph, L"process-controls-task") &&
                HasGraphEdgeKind(semanticGraph, L"process-controls-wmi") &&
                HasGraphEdgeKind(semanticGraph, L"process-changes-memory") &&
                HasGraphEdgeKind(semanticGraph, L"cross-process-createremotethread"),
            L"semantic-graph-edges");

        TimelineAnalysisResult semanticAnalysis = semanticStore.AnalyzeLiveSignals(64);
        Check(
            &context,
                HasAnalysisFinding(semanticAnalysis, L"cross-process-manipulation") &&
                HasAnalysisFinding(semanticAnalysis, L"network-near-suspicious-activity") &&
                HasAnalysisFinding(semanticAnalysis, L"network-dns-activity") &&
                HasAnalysisFinding(semanticAnalysis, L"executable-file-artifact") &&
                HasAnalysisFinding(semanticAnalysis, L"registry-persistence-change") &&
                HasAnalysisFinding(semanticAnalysis, L"service-persistence-change") &&
                HasAnalysisFinding(semanticAnalysis, L"scheduled-task-change") &&
                HasAnalysisFinding(semanticAnalysis, L"wmi-persistence-change") &&
                HasAnalysisFinding(semanticAnalysis, L"memory-executable-transition") &&
                HasAnalysisFinding(semanticAnalysis, L"snapshot-diff-milestone"),
            L"semantic-analysis-findings");

        TimelineStore analysisStore(1024);
        std::vector<TimelineEvent> analysisEvents;
        analysisEvents.push_back(MakeKernelLiveEvent(100000000, L"process", L"process-create", 700, 0, L"blink.exe"));
        analysisEvents.push_back(MakeKernelLiveEvent(115000000, L"process", L"process-exit", 700, 0, L"blink.exe"));
        analysisEvents.push_back(MakeKernelLiveEvent(120000000, L"thread", L"thread-create", 700, 9001, L"pid:700 tid:9001"));
        analysisEvents.push_back(MakeKernelLiveEvent(122000000, L"thread", L"thread-exit", 700, 9001, L"pid:700 tid:9001"));
        analysisEvents.push_back(MakeKernelLiveEvent(130000000, L"image", L"image-load", 800, 0, L"inject.dll"));
        analysisEvents.push_back(MakeKernelLiveEvent(131000000, L"thread", L"thread-create", 800, 9002, L"pid:800 tid:9002"));
        analysisStore.IngestEvents(analysisEvents);
        Check(
            &context,
            HasEventEvidence(analysisStore.AllEvents(), L"process_image_context", L"inject.dll"),
            L"thread-event-process-image-context");
        std::vector<TiEventRecord> analysisTiEvents;
        analysisTiEvents.push_back(MakeTiEvent(129000000, 400, 800, L"KERNEL_THREATINT_TASK_WRITEVM", L"suspect.exe"));
        analysisStore.IngestThreatIntel(analysisTiEvents, L"all");
        TimelineAnalysisResult analysis = analysisStore.AnalyzeLiveSignals(16);
        Check(
            &context,
            HasAnalysisFinding(analysis, L"short-lived-process") &&
                HasAnalysisFinding(analysis, L"short-lived-thread") &&
                HasAnalysisFinding(analysis, L"ti-near-thread-activity") &&
                HasAnalysisFinding(analysis, L"ti-near-image-load"),
            L"analysis-live-findings");
        std::wstring analysisJson = BuildTimelineAnalysisJson(analysis);
        Check(
            &context,
            analysisJson.find(L"kn-live-dbg.timeline-analysis.v1") != std::wstring::npos &&
                analysisJson.find(L"short-lived-process") != std::wstring::npos &&
                analysisJson.find(L"ti-near-thread-activity") != std::wstring::npos,
            L"analysis-json-schema");

        TimelineDashboardDocument dashboard = {};
        dashboard.Stats = store.GetStats();
        dashboard.Analysis = analysis;
        dashboard.Events = store.AllEvents();
        std::vector<TimelineEvent> semanticDashboardEvents = semanticStore.AllEvents();
        for (const TimelineEvent& event : semanticDashboardEvents)
        {
            dashboard.Events.push_back(event);
            ++dashboard.Stats.BySource[event.Source.empty() ? L"<unknown>" : event.Source];
            ++dashboard.Stats.ByDomain[event.Domain.empty() ? L"<unknown>" : event.Domain];
        }
        dashboard.Stats.Stored = static_cast<uint64_t>(dashboard.Events.size());
        dashboard.GeneratedUtc = L"2026-06-30T00:00:00Z";
        dashboard.Warnings.push_back(L"self-test dashboard warning");
        dashboard.TotalStored = dashboard.Stats.Stored;
        dashboard.MaxEvents = 10000;
        dashboard.HasLiveStatus = true;
        dashboard.LiveFlags =
            KNDBG_TIMELINE_STATUS_ACTIVE |
            KNDBG_TIMELINE_STATUS_PROCESS_CALLBACK |
            KNDBG_TIMELINE_STATUS_IMAGE_CALLBACK |
            KNDBG_TIMELINE_STATUS_THREAD_CALLBACK;
        dashboard.LiveCapacity = 4096;
        dashboard.LiveQueued = 64;
        dashboard.LiveDropped = 1;
        dashboard.LiveNextSequence = 42;
        dashboard.AutoDrainRunning = true;
        dashboard.AutoDrainBatches = 3;
        dashboard.AutoDrainEvents = 10;
        dashboard.AutoDrainAdded = 9;
        std::wstring dashboardHtml = BuildTimelineDashboardHtml(dashboard);
        Check(
            &context,
            dashboardHtml.find(L"kn-live-dbg.timeline-dashboard.v1") != std::wstring::npos &&
                dashboardHtml.find(L"kn-live-dbg.timeline-analysis.v1") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"pidFilter\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"imageFilter\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"taskFilter\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"analystFocus\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"tiFocus\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"findingFocus\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"exportJsonl\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"snapshotStatus\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"statusGenerated\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"liveMode\"") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"autoDrainState\"") != std::wstring::npos &&
                dashboardHtml.find(L"\"threadCallback\":true") != std::wstring::npos &&
                dashboardHtml.find(L"function exportJsonl()") != std::wstring::npos &&
                dashboardHtml.find(L"function renderLiveStatus") != std::wstring::npos &&
                dashboardHtml.find(L"function renderAnalystFocus") != std::wstring::npos &&
                dashboardHtml.find(L"function isMemorySignal") != std::wstring::npos &&
                dashboardHtml.find(L"RWX VAlloc is not present") != std::wstring::npos &&
                dashboardHtml.find(L"Injection-relevant activity present") != std::wstring::npos &&
                dashboardHtml.find(L"function renderFindings") != std::wstring::npos &&
                dashboardHtml.find(L"function renderEvidenceFields") != std::wstring::npos &&
                dashboardHtml.find(L"Evidence Fields") != std::wstring::npos &&
                dashboardHtml.find(L"evidence-table") != std::wstring::npos &&
                dashboardHtml.find(L"function selectableFindingEventId") != std::wstring::npos &&
                dashboardHtml.find(L"function relatedEvents") != std::wstring::npos &&
                dashboardHtml.find(L"function timelineScale") != std::wstring::npos &&
                dashboardHtml.find(L"markerPosition(scale, item.index, events.length)") != std::wstring::npos &&
                dashboardHtml.find(L"self-test dashboard warning") != std::wstring::npos &&
                dashboardHtml.find(L"function relationshipLabel") != std::wstring::npos &&
                dashboardHtml.find(L"function relationshipHint") != std::wstring::npos &&
                dashboardHtml.find(L"Relationship graph") != std::wstring::npos &&
                dashboardHtml.find(L"Existing process baseline") != std::wstring::npos &&
                dashboardHtml.find(L"data-ti-task") != std::wstring::npos &&
                dashboardHtml.find(L"View: generated snapshot") != std::wstring::npos &&
                dashboardHtml.find(L"id=\"appWindow\"") != std::wstring::npos &&
                dashboardHtml.find(L"data-view=\"events\"") != std::wstring::npos &&
                dashboardHtml.find(L"data-view=\"relationships\"") != std::wstring::npos &&
                dashboardHtml.find(L"data-view=\"evidence\"") != std::wstring::npos &&
                dashboardHtml.find(L"class=\"events-panel\"") != std::wstring::npos &&
                dashboardHtml.find(L"class=\"relationships-panel\"") != std::wstring::npos &&
                dashboardHtml.find(L"mode-events") != std::wstring::npos &&
                dashboardHtml.find(L"mode-relationships") != std::wstring::npos &&
                dashboardHtml.find(L"mode-evidence") != std::wstring::npos &&
                dashboardHtml.find(L"function setDashboardMode") != std::wstring::npos &&
                dashboardHtml.find(L"function applyDashboardMode") != std::wstring::npos &&
                dashboardHtml.find(L"function focusDashboardTarget") == std::wstring::npos &&
                dashboardHtml.find(L"--left-width") != std::wstring::npos &&
                dashboardHtml.find(L"--side-width") != std::wstring::npos &&
                dashboardHtml.find(L"--timeline-height") != std::wstring::npos &&
                dashboardHtml.find(L"--relationships-width") != std::wstring::npos &&
                dashboardHtml.find(L"data-resize=\"left\"") != std::wstring::npos &&
                dashboardHtml.find(L"data-resize=\"side\"") != std::wstring::npos &&
                dashboardHtml.find(L"data-resize=\"timeline\"") != std::wstring::npos &&
                dashboardHtml.find(L"data-resize=\"relationships\"") != std::wstring::npos &&
                dashboardHtml.find(L"function initSplitters") != std::wstring::npos &&
                dashboardHtml.find(L"function resizeValue") != std::wstring::npos &&
                dashboardHtml.find(L"height: 100vh") != std::wstring::npos &&
                dashboardHtml.find(L"overflow-y: auto") != std::wstring::npos &&
                dashboardHtml.find(L"grid-template-rows: auto auto minmax(0, 1fr)") != std::wstring::npos &&
                dashboardHtml.find(L"grid-template-rows: auto minmax(0, 1fr)") != std::wstring::npos &&
                dashboardHtml.find(L"min-width: 1360px") != std::wstring::npos &&
                dashboardHtml.find(L"min-width: 1532px") != std::wstring::npos &&
                dashboardHtml.find(L"<div>Target</div>") != std::wstring::npos &&
                dashboardHtml.find(L"function eventSearchText") != std::wstring::npos &&
                dashboardHtml.find(L"function eventPidValues") != std::wstring::npos &&
                dashboardHtml.find(L"function targetPidValue") != std::wstring::npos &&
                dashboardHtml.find(L"function sourcePidValue") != std::wstring::npos &&
                dashboardHtml.find(L"function attachEventSelectionHandlers") != std::wstring::npos &&
                dashboardHtml.find(L"role=\\\"button\\\" tabindex=\\\"0\\\" data-event-id") != std::wstring::npos &&
                dashboardHtml.find(L"grid-template-columns: 52px 86px minmax(0, 1fr)") != std::wstring::npos &&
                dashboardHtml.find(L"overflow-wrap: anywhere") != std::wstring::npos &&
                dashboardHtml.find(L"class=\\\"related-summary\\\"") != std::wstring::npos &&
                dashboardHtml.find(L"function hasValue") != std::wstring::npos &&
                dashboardHtml.find(L"function entityCorrelationValues") != std::wstring::npos &&
                dashboardHtml.find(L"remote_thread") != std::wstring::npos &&
                dashboardHtml.find(L"Creator PID") != std::wstring::npos &&
                dashboardHtml.find(L"\"targetPid\":900") != std::wstring::npos &&
                dashboardHtml.find(L"\"creator_pid\":\"901\"") != std::wstring::npos &&
                dashboardHtml.find(L"cross-process-") != std::wstring::npos &&
                dashboardHtml.find(L"process-connects-host") != std::wstring::npos &&
                dashboardHtml.find(L"Related Events") != std::wstring::npos &&
                dashboardHtml.find(L"application/jsonl;charset=utf-8") != std::wstring::npos &&
                dashboardHtml.find(L"KERNEL_THREATINT_TASK_WRITEVM") != std::wstring::npos &&
                dashboardHtml.find(L"payload.BaseAddress") != std::wstring::npos &&
                dashboardHtml.find(L"payload_type.BaseAddress") != std::wstring::npos &&
                dashboardHtml.find(L"allocation_size") != std::wstring::npos &&
                dashboardHtml.find(L"ghost.dll") != std::wstring::npos &&
                dashboardHtml.find(L"https://") == std::wstring::npos,
            L"dashboard-html-self-contained");

        SnapshotDocument snapshot = MakeSnapshotFixture();
        TimelineReconcileOptions reconcileOptions = {};
        reconcileOptions.Limit = 10;
        reconcileOptions.LiveDropped = 7;
        TimelineReconcileResult reconcile = store.ReconcileSnapshot(snapshot, reconcileOptions);

        Check(
            &context,
            HasReconcileFinding(
                reconcile,
                L"event-without-snapshot-process",
                200,
                L"pid:200",
                L"event-backed"),
            L"reconcile-event-process-miss");
        Check(
            &context,
            HasReconcileFinding(
                reconcile,
                L"event-without-snapshot-image",
                200,
                L"ghost.dll",
                L"event-backed"),
            L"reconcile-event-image-miss");
        Check(
            &context,
            HasReconcileFinding(
                reconcile,
                L"snapshot-record-without-event",
                300,
                L"hidden.dll",
                L"loss-limited"),
            L"reconcile-snapshot-miss-loss-limited");
        Check(&context, !reconcile.Warnings.empty(), L"reconcile-warning-propagation");

        std::wstring json = BuildTimelineReconcileJson(reconcile);
        Check(
            &context,
            json.find(L"kn-live-dbg.timeline-reconcile.v1") != std::wstring::npos &&
                json.find(L"\"liveDropped\":7") != std::wstring::npos,
            L"reconcile-json-schema");

        std::wcout << L"[timeline.selftest] passed=" << context.Passed
                   << L" failed=" << context.Failed << L"\n";
        if (context.Failed == 0)
        {
            exitCode = 0;
        }
    } while (false);

    return exitCode;
}
