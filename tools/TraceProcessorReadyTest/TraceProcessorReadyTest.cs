// Independent test reader for two Microsoft TraceProcessor CPU tables.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Web.Script.Serialization;
using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Cpu;

internal static class ReadyRows
{
    private static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;

    private static string Tick(TraceTimestamp time)
    {
        return time.HasValue && !time.IsPartial && time.Context.ClockType == TraceClockType.PerformanceCounter
            ? time.Value.RawValue.ToString(Invariant) : null;
    }

    private static string Tick(TraceTimestamp? time)
    {
        return time.HasValue ? Tick(time.Value) : null;
    }

    private static string Key(int target, int cpu, TraceTimestamp time)
    {
        return target.ToString(Invariant) + "," + cpu.ToString(Invariant) + "," + Tick(time);
    }

    private static int Main(string[] args)
    {
        if (args.Length < 2) { return 2; }
        var requested = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 1; i < args.Length; ++i) { requested.Add(args[i]); }
        var readyRows = new List<object>();
        var activityRows = new List<object>();
        string toolkit = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wpt");
        var settings = new TraceProcessorSettings { ToolkitPath = toolkit, CatalogPath = Path.Combine(toolkit, "Catalog"),
            AllowLostEvents = false, AllowTimeInversion = false };
        using (var trace = TraceProcessor.Create(args[0], settings))
        {
            var cpu = trace.UseCpuSchedulingData();
            var ready = trace.UseReadyThreadData();
            trace.Process();
            int row = 0;
            foreach (var e in ready.Result.ReadyThreadEvents)
            {
                ++row;
                string key = Key(e.ReadiedThreadId, e.Processor, e.Timestamp);
                if (!requested.Contains(key)) { continue; }
                var origin = e.AsReadyThreadEvent2();
                readyRows.Add(new { row, key, source_tid = origin.ReadyingThreadId, source_pid = origin.ReadyingProcess?.Id,
                    dpc = e.IsExecutingDeferredProcedureCall, direct = e.IsDirectSwitchAttempt });
            }
            row = 0;
            foreach (var a in cpu.Result.ThreadActivity)
            {
                ++row;
                var e = a.ReadyThreadEvent;
                if (e == null || a.SwitchIn == null) { continue; }
                string key = Key(e.ReadiedThreadId, e.Processor, e.Timestamp);
                if (!requested.Contains(key)) { continue; }
                activityRows.Add(new { row, key, target_tid = a.SwitchIn.ThreadId, target_pid = a.Thread?.ProcessId,
                    source_tid = a.ReadyingThread?.Id, source_pid = a.ReadyingProcess?.Id,
                    source_created = Tick(a.ReadyingThread?.CreateTime), source_exited = Tick(a.ReadyingThread?.ExitTime),
                    previous_out = a.PreviousActivity == null ? null : Tick(a.PreviousActivity.StopTime),
                    switch_in = Tick(a.StartTime), switch_in_cpu = a.Processor });
            }
            Console.WriteLine(new JavaScriptSerializer().Serialize(new { ready_total = ready.Result.ReadyThreadEvents.Count,
                activity_total = cpu.Result.ThreadActivity.Count, ready_rows = readyRows, activity_rows = activityRows }));
        }
        return 0;
    }
}
