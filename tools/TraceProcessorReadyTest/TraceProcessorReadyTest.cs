// Resolve selected ready events against Microsoft TraceProcessor CPU tables.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
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
        return unchecked((uint)target).ToString(Invariant) + "," + cpu.ToString(Invariant) + "," + Tick(time);
    }

    private static void Retain(List<object> rows, object row, int limit, ref bool complete)
    {
        if (rows.Count < limit) { rows.Add(row); }
        else { complete = false; }
    }

    private static int Main(string[] args)
    {
        try { return Run(args); }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.GetType().FullName);
            return 1;
        }
    }

    private static int Run(string[] args)
    {
        if (args.Length < 2) { return 2; }
        var requested = new HashSet<string>(StringComparer.Ordinal);
        bool context = args[1] == "--cpu-context";
        int first = context ? 2 : 1;
        if (context && (args.Length == first || args.Length - first > 128)) { return 2; }
        var byCpu = new Dictionary<int, List<KeyValuePair<long, string>>>();
        for (int i = first; i < args.Length; ++i)
        {
            if (!requested.Add(args[i])) { if (context) { return 2; } continue; }
            if (!context) { continue; }
            string[] parts = args[i].Split(',');
            uint tid;
            int processor;
            long time;
            if (parts.Length != 3 || !UInt32.TryParse(parts[0], NumberStyles.None, Invariant, out tid) ||
                !Int32.TryParse(parts[1], NumberStyles.None, Invariant, out processor) || processor > 65535 ||
                !Int64.TryParse(parts[2], NumberStyles.AllowLeadingSign, Invariant, out time) ||
                args[i] != tid.ToString(Invariant) + "," + processor.ToString(Invariant) + "," + time.ToString(Invariant))
            { return 2; }
            if (!byCpu.ContainsKey(processor)) { byCpu.Add(processor, new List<KeyValuePair<long, string>>()); }
            byCpu[processor].Add(new KeyValuePair<long, string>(time, args[i]));
        }
        int limit = context ? 2 * requested.Count : Int32.MaxValue;
        bool complete = true;
        var readyRows = new List<object>();
        var activityRows = new List<object>();
        string toolkit = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wpt");
        var settings = new TraceProcessorSettings { ToolkitPath = toolkit, CatalogPath = Path.Combine(toolkit, "Catalog"),
            AllowLostEvents = false, AllowTimeInversion = false };
        using (var source = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.Read))
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
                Retain(readyRows, new { row, key, source_tid = (uint?)origin.ReadyingThreadId, source_pid = (uint?)origin.ReadyingProcess?.Id,
                    dpc = e.IsExecutingDeferredProcedureCall, direct = e.IsDirectSwitchAttempt }, limit, ref complete);
            }
            row = 0;
            foreach (var a in cpu.Result.ThreadActivity)
            {
                ++row;
                var e = a.ReadyThreadEvent;
                if (e == null || a.SwitchIn == null) { continue; }
                string key = Key(e.ReadiedThreadId, e.Processor, e.Timestamp);
                if (!requested.Contains(key)) { continue; }
                Retain(activityRows, new { row, key, target_tid = unchecked((uint)a.SwitchIn.ThreadId), target_pid = (uint?)a.Thread?.ProcessId,
                    source_tid = (uint?)a.ReadyingThread?.Id, source_pid = (uint?)a.ReadyingProcess?.Id,
                    source_created = Tick(a.ReadyingThread?.CreateTime), source_exited = Tick(a.ReadyingThread?.ExitTime),
                    previous_out = a.PreviousActivity == null ? null : Tick(a.PreviousActivity.StopTime),
                    switch_in = Tick(a.StartTime), switch_in_cpu = a.Processor }, limit, ref complete);
            }
            if (context)
            {
                var slices = new List<object>();
                row = 0;
                foreach (var slice in cpu.Result.CpuTimeSlices)
                {
                    ++row;
                    List<KeyValuePair<long, string>> keys;
                    if (!byCpu.TryGetValue(slice.Processor, out keys)) { continue; }
                    string begin = Tick(slice.StartTime), end = Tick(slice.StopTime);
                    if (begin == null || end == null) { continue; }
                    long lo = slice.StartTime.Value.RawValue, hi = slice.StopTime.Value.RawValue;
                    foreach (var point in keys)
                    {
                        if (lo < point.Key && point.Key < hi)
                        {
                            Retain(slices, new { row, key = point.Value, cpu = slice.Processor,
                                source_tid = (uint?)slice.Thread?.Id, source_pid = (uint?)slice.Process?.Id,
                                switch_in = begin, switch_out = end }, limit, ref complete);
                        }
                    }
                }
                var loaded = Array.FindAll(AppDomain.CurrentDomain.GetAssemblies(), assembly =>
                    !assembly.IsDynamic && File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, assembly.GetName().Name + ".dll")));
                var inputKeys = new string[args.Length - first];
                Array.Copy(args, first, inputKeys, 0, inputKeys.Length);
                string digest;
                using (var hasher = SHA256.Create())
                {
                    digest = BitConverter.ToString(hasher.ComputeHash(source)).Replace("-", "").ToLowerInvariant();
                }
                Console.WriteLine(new JavaScriptSerializer().Serialize(new { schema = "kn.traceprocessor_ready_contexts.v1",
                    source_sha256 = digest, source_bytes = source.Length, requested_keys = inputKeys,
                    loaded_processing_modules = TraceProcessorModules.Loaded(toolkit, loaded),
                    complete, ready_total = ready.Result.ReadyThreadEvents.Count, activity_total = cpu.Result.ThreadActivity.Count,
                    slice_total = cpu.Result.CpuTimeSlices.Count, ready_rows = readyRows, activity_rows = activityRows, cpu_slices = slices }));
                return 0;
            }
            Console.WriteLine(new JavaScriptSerializer().Serialize(new { ready_total = ready.Result.ReadyThreadEvents.Count,
                activity_total = cpu.Result.ThreadActivity.Count, ready_rows = readyRows, activity_rows = activityRows }));
        }
        return 0;
    }
}
