#include "TimelineSelfTest.h"

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

    TiEventRecord MakeTiEvent(
        uint64_t timestamp,
        uint32_t pid,
        uint32_t targetPid,
        const std::wstring& taskName,
        const std::wstring& image)
    {
        TiEventRecord event = {};
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
        tiEvents.push_back(MakeTiEvent(2000, 400, 500, L"KERNEL_THREATINT_TASK_WRITEVM", L"suspect.exe"));

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
                tiFiltered[1].Action == L"KERNEL_THREATINT_TASK_WRITEVM" &&
                tiFiltered[1].Risk == L"critical" &&
                tiFiltered[1].Evidence[L"classification_reason"] == L"writevm",
            L"ti-classification-action-risk");

        std::vector<TiEventRecord> repeatedTiEvents;
        repeatedTiEvents.push_back(MakeTiEvent(1000, 400, 500, L"KERNEL_THREATINT_TASK_ALLOCVM", L"suspect.exe"));
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

        TimelineStore analysisStore(1024);
        std::vector<TimelineEvent> analysisEvents;
        analysisEvents.push_back(MakeKernelLiveEvent(100000000, L"process", L"process-create", 700, 0, L"blink.exe"));
        analysisEvents.push_back(MakeKernelLiveEvent(115000000, L"process", L"process-exit", 700, 0, L"blink.exe"));
        analysisEvents.push_back(MakeKernelLiveEvent(120000000, L"thread", L"thread-create", 700, 9001, L"pid:700 tid:9001"));
        analysisEvents.push_back(MakeKernelLiveEvent(122000000, L"thread", L"thread-exit", 700, 9001, L"pid:700 tid:9001"));
        analysisEvents.push_back(MakeKernelLiveEvent(130000000, L"image", L"image-load", 800, 0, L"inject.dll"));
        analysisEvents.push_back(MakeKernelLiveEvent(131000000, L"thread", L"thread-create", 800, 9002, L"pid:800 tid:9002"));
        analysisStore.IngestEvents(analysisEvents);
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
        dashboard.GeneratedUtc = L"2026-06-30T00:00:00Z";
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
                dashboardHtml.find(L"function renderFindings") != std::wstring::npos &&
                dashboardHtml.find(L"function selectableFindingEventId") != std::wstring::npos &&
                dashboardHtml.find(L"function relatedEvents") != std::wstring::npos &&
                dashboardHtml.find(L"Related Events") != std::wstring::npos &&
                dashboardHtml.find(L"application/jsonl;charset=utf-8") != std::wstring::npos &&
                dashboardHtml.find(L"KERNEL_THREATINT_TASK_WRITEVM") != std::wstring::npos &&
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
