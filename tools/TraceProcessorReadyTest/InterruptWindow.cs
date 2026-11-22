using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Cpu;

internal static class InterruptWindow
{
    private const int Limit = 2048;
    private static readonly CultureInfo Culture = CultureInfo.InvariantCulture;

    // The interrupt table exposes trace-relative nanoseconds even when the raw QPC value is unavailable.
    private static bool Bounds(TraceTimestamp start, TraceTimestamp stop, out long lo, out long hi)
    {
        lo = hi = 0;
        if (!start.HasValue || !stop.HasValue || start.Context.ClockType != TraceClockType.PerformanceCounter ||
            stop.Context.ClockType != TraceClockType.PerformanceCounter) { return false; }
        lo = start.RelativeTimestamp.Nanoseconds;
        hi = stop.RelativeTimestamp.Nanoseconds;
        return lo <= hi;
    }

    internal static int Run(string[] args)
    {
        uint pid, tid;
        long begin, end;
        if (args.Length != 6 || !UInt32.TryParse(args[2], NumberStyles.None, Culture, out pid) ||
            !UInt32.TryParse(args[3], NumberStyles.None, Culture, out tid) ||
            !Int64.TryParse(args[4], NumberStyles.AllowLeadingSign, Culture, out begin) ||
            !Int64.TryParse(args[5], NumberStyles.AllowLeadingSign, Culture, out end) || begin >= end ||
            pid == 0 || pid == UInt32.MaxValue || tid == 0 || tid == UInt32.MaxValue) { return 2; }
        string kit = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wpt");
        var settings = new TraceProcessorSettings { ToolkitPath = kit, CatalogPath = Path.Combine(kit, "Catalog"),
            AllowLostEvents = false, AllowTimeInversion = false };
        using (var source = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var trace = TraceProcessor.Create(args[0], settings))
        {
            if (source.Length < 1 || source.Length > 512L * 1024 * 1024) { return 2; }
            var schedule = trace.UseCpuSchedulingData();
            var interrupts = trace.UseInterruptHandlingData();
            var metadata = trace.UseMetadata();
            var clock = trace.UseTraceTimestampContext();
            trace.Process();
            if (clock.IsPartial || clock.ClockType != TraceClockType.PerformanceCounter ||
                metadata.ClockType != TraceClockType.PerformanceCounter) { return 1; }
            long left = clock.GetRelativeTimestamp(new TraceTimestampValue(begin)).Nanoseconds;
            long right = clock.GetRelativeTimestamp(new TraceTimestampValue(end)).Nanoseconds;
            var cpus = new SortedSet<int>();
            var slices = new List<object>();
            int selected = 0, unresolvedSlices = 0;
            var table = schedule.Result.CpuTimeSlices;
            for (int i = 0; i < table.Count; ++i)
            {
                var s = table[i];
                if ((uint?)s.Thread?.Id != tid || (uint?)s.Process?.Id != pid) { continue; }
                long lo, hi;
                if (!Bounds(s.StartTime, s.StopTime, out lo, out hi)) { ++unresolvedSlices; continue; }
                if (hi <= left || lo >= right || lo == hi) { continue; }
                if (s.StartTime.IsPartial || s.StopTime.IsPartial || s.Processor < 0 || s.Processor > UInt16.MaxValue)
                { ++unresolvedSlices; continue; }
                cpus.Add(s.Processor);
                if (++selected <= Limit)
                {
                    slices.Add(new { row = i + 1, cpu = s.Processor, pid, tid,
                        start_qpc = s.StartTime.Value.RawValue.ToString(Culture), stop_qpc = s.StopTime.Value.RawValue.ToString(Culture),
                        start_ns = lo.ToString(Culture), stop_ns = hi.ToString(Culture) });
                }
            }
            var data = interrupts.Result;
            var fragments = new List<object>();
            int matches = 0, unresolvedInterrupts = 0;
            for (int i = 0; i < data.Activity.Count; ++i)
            {
                var a = data.Activity[i];
                var e = a.Interval;
                bool unknownCpu = e.Processor < 0 || e.Processor > UInt16.MaxValue;
                if (cpus.Count == 0 || (!unknownCpu && !cpus.Contains(e.Processor))) { continue; }
                long parentStart, parentStop;
                if (!Bounds(e.StartTime, e.StopTime, out parentStart, out parentStop)) { ++unresolvedInterrupts; continue; }
                if (parentStop <= left || parentStart >= right || parentStart == parentStop) { continue; }
                if (unknownCpu || a.Fragments == null || a.Fragments.Count == 0) { ++unresolvedInterrupts; continue; }
                long previous = parentStart;
                for (int j = 0; j < a.Fragments.Count; ++j)
                {
                    var f = a.Fragments[j];
                    long lo, hi;
                    if (!Bounds(f.StartTime, f.StopTime, out lo, out hi) || lo < previous || hi > parentStop)
                    { ++unresolvedInterrupts; break; }
                    previous = hi;
                    if (hi <= left || lo >= right || lo == hi) { continue; }
                    if (++matches <= Limit)
                    {
                        fragments.Add(new { row = i + 1, fragment = j + 1, fragment_count = a.Fragments.Count,
                            cpu = e.Processor, kind = e.Type.ToString(), parent_start_ns = parentStart.ToString(Culture),
                            parent_stop_ns = parentStop.ToString(Culture), start_ns = lo.ToString(Culture), stop_ns = hi.ToString(Culture) });
                    }
                }
            }
            string pin;
            using (var hasher = SHA256.Create())
            { pin = BitConverter.ToString(hasher.ComputeHash(source)).Replace("-", "").ToLowerInvariant(); }
            var loaded = Array.FindAll(AppDomain.CurrentDomain.GetAssemblies(), assembly =>
                !assembly.IsDynamic && File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, assembly.GetName().Name + ".dll")));
            Console.WriteLine(new JavaScriptSerializer().Serialize(new { schema = "kn.traceprocessor_interrupt_window.v1",
                source_sha256 = pin, source_bytes = source.Length,
                query_filter = new { pid, tid, start_qpc = begin.ToString(Culture), stop_qpc = end.ToString(Culture), processors = cpus },
                loaded_processing_modules = TraceProcessorModules.Loaded(kit, loaded),
                clock = new { kind = clock.ClockType.ToString(), reference_qpc = clock.ReferenceValue.RawValue.ToString(Culture),
                    reference_ns = clock.GetRelativeTimestamp(clock.ReferenceValue).Nanoseconds.ToString(Culture),
                    frequency = metadata.PerformanceCounterFrequency.Hertz.ToString(Culture), start_ns = left.ToString(Culture),
                    stop_ns = right.ToString(Culture), lost_events = metadata.LostEventCount, lost_buffers = metadata.LostBufferCount },
                slice_table_rows = table.Count, activity_table_rows = data.Activity.Count,
                dpc_table_rows = data.DeferredProcedureCalls.Count, isr_table_rows = data.InterruptServiceRoutines.Count,
                row_limit = Limit, matched_slices = selected, matched_fragments = matches,
                unresolved_slices = unresolvedSlices, unresolved_interrupts = unresolvedInterrupts, slices, fragments }));
            return 0;
        }
    }
}
