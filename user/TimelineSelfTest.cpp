#include "TimelineSelfTest.h"

#include "TimelineStore.h"

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
