using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Disk;

internal static class TraceProcessorDisk
{
    private const int Limit = 2048;
    private static readonly CultureInfo Culture = CultureInfo.InvariantCulture;
    private static readonly Guid[] Providers = { new Guid("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c") };

    private sealed class Selection
    {
        internal readonly Dictionary<ulong, int> First = new Dictionary<ulong, int>();
        internal bool Overflow;

        internal void Include(ulong packet)
        {
            if (packet == 0 || First.ContainsKey(packet)) { return; }
            if (First.Count == Limit) { Overflow = true; return; }
            First.Add(packet, 0);
        }
    }

    private sealed class DiskEvents
    {
        internal int Total, Invalid, Unassigned, Matches;
        internal readonly List<object> Rows = new List<object>();

        internal void Observe(TraceEvent e, uint target, Selection keys, bool collect)
        {
            int op = e.IsClassic ? e.Id : e.Opcode.GetValueOrDefault(-1);
            if (op < 10 || op > 15) { return; }
            ++Total;
            var data = e.Data;
            var flags = e.Flags;
            var sizeFlag = flags & (TraceEventHeaderFlags.Has32BitHeader | TraceEventHeaderFlags.Has64BitHeader);
            int width = sizeFlag == TraceEventHeaderFlags.Has32BitHeader ? 4 : 8;
            bool transfer = op == 10 || op == 11;
            int size = transfer ? 32 + 2 * width : op == 14 ? 16 + width : width;
            if (!e.IsClassic || (sizeFlag != TraceEventHeaderFlags.Has32BitHeader && sizeFlag != TraceEventHeaderFlags.Has64BitHeader) ||
                (flags & (TraceEventHeaderFlags.StringOnly | TraceEventHeaderFlags.TraceMessage)) != 0 ||
                (e.Version != 2 && e.Version != 3) || data.Length != size + (e.Version == 3 ? 4 : 0) ||
                !e.Timestamp.HasValue || e.Timestamp.IsPartial || e.Timestamp.Context.ClockType != TraceClockType.PerformanceCounter)
            { ++Invalid; return; }
            int offset = transfer ? 24 + width : op == 14 ? 16 : 0;
            ulong packet = width == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)) :
                BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset));
            uint tid = e.Version == 3 ? BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(size)) : 0;
            if (packet == 0 || tid == 0 || tid == UInt32.MaxValue) { ++Unassigned; }
            if (!collect)
            {
                if (tid == target) { keys.Include(packet); }
                return;
            }
            int first;
            if (!keys.First.TryGetValue(packet, out first)) { return; }
            if (first == 0) { first = Total; keys.First[packet] = first; }
            if (++Matches <= Limit)
            {
                Rows.Add(new { disk_ordinal = Total, packet_first_ordinal = first, opcode = op, version = e.Version,
                    pointer_bytes = width, logger_id = e.LoggerId, cpu = e.Processor, issuing_tid = tid,
                    raw_timestamp = e.Timestamp.Value.RawValue.ToString(Culture), relative_ns = e.Timestamp.RelativeTimestamp.Nanoseconds.ToString(Culture) });
            }
        }
    }

    private sealed class ActivityRow
    {
        internal int Row, Disk;
        internal long Start, Stop, Bytes;
        internal ulong Packet;
        internal string Operation, Source;

        internal object Project(Selection keys)
        {
            int first;
            keys.First.TryGetValue(Packet, out first);
            return new { table_row = Row, packet_first_ordinal = first, operation = Operation, io_source = Source,
                start_ns = Start.ToString(Culture), stop_ns = Stop.ToString(Culture), disk = Disk, size_bytes = Bytes.ToString(Culture) };
        }
    }

    private static int Main(string[] args)
    {
        try { return Run(args); }
        catch (Exception error) { Console.Error.WriteLine(error.GetType().FullName); return 1; }
    }

    private static int Run(string[] args)
    {
        uint pid, tid;
        long start, stop;
        if (args.Length != 5 || !UInt32.TryParse(args[1], NumberStyles.None, Culture, out pid) ||
            !UInt32.TryParse(args[2], NumberStyles.None, Culture, out tid) ||
            !Int64.TryParse(args[3], NumberStyles.AllowLeadingSign, Culture, out start) ||
            !Int64.TryParse(args[4], NumberStyles.AllowLeadingSign, Culture, out stop) || stop <= start ||
            pid == 0 || pid == UInt32.MaxValue || tid == 0 || tid == UInt32.MaxValue) { return 2; }
        string kit = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wpt");
        var settings = new TraceProcessorSettings { ToolkitPath = kit, CatalogPath = Path.Combine(kit, "Catalog"),
            AllowLostEvents = false, AllowTimeInversion = false };
        using (var file = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (file.Length < 1 || file.Length > 512L * 1024 * 1024) { return 2; }
            var keys = new Selection();
            var first = new DiskEvents();
            var history = new DiskEvents();
            var selected = new List<ActivityRow>();
            object clock, modules;
            int total, matches = 0, unplaced = 0;
            using (var trace = TraceProcessor.Create(args[0], settings))
            {
                var context = trace.UseTraceTimestampContext();
                var metadata = trace.UseMetadata();
                var disk = trace.UseDiskIOData();
                trace.Use(Providers, c => first.Observe(c.Event, tid, keys, false));
                trace.Process();
                if (context.IsPartial || context.ClockType != TraceClockType.PerformanceCounter ||
                    metadata.ClockType != TraceClockType.PerformanceCounter) { return 1; }
                long left = context.GetRelativeTimestamp(new TraceTimestampValue(start)).Nanoseconds;
                long right = context.GetRelativeTimestamp(new TraceTimestampValue(stop)).Nanoseconds;
                clock = new { kind = context.ClockType.ToString(), frequency = metadata.PerformanceCounterFrequency.Hertz.ToString(Culture),
                    reference_qpc = context.ReferenceValue.RawValue.ToString(Culture),
                    reference_ns = context.GetRelativeTimestamp(context.ReferenceValue).Nanoseconds.ToString(Culture),
                    start_ns = left.ToString(Culture), stop_ns = right.ToString(Culture),
                    lost_events = metadata.LostEventCount, lost_buffers = metadata.LostBufferCount };
                var table = disk.Result.Activity;
                total = table.Count;
                for (int i = 0; i < total; ++i)
                {
                    var r = table[i];
                    if ((uint?)r.IssuingThread?.Id != tid || (uint?)r.IssuingProcess?.Id != pid) { continue; }
                    var a = r.InitializeTime;
                    var b = r.CompleteTime;
                    if (!a.HasValue || !b.HasValue || a.Context.ClockType != context.ClockType || b.Context.ClockType != context.ClockType)
                    { ++unplaced; continue; }
                    long lo = a.RelativeTimestamp.Nanoseconds, hi = b.RelativeTimestamp.Nanoseconds;
                    if (hi < lo) { ++unplaced; continue; }
                    if (Math.Max(left, lo) >= Math.Min(right, hi)) { continue; }
                    ulong packet = unchecked((ulong)r.PacketAddress.Value);
                    keys.Include(packet);
                    if (++matches <= Limit)
                    {
                        selected.Add(new ActivityRow { Row = i + 1, Packet = packet, Start = lo, Stop = hi, Disk = r.Disk,
                            Bytes = r.Size.Bytes, Operation = r.IOType.ToString().ToLowerInvariant(), Source = r.Source.ToString() });
                    }
                }
                var assemblies = Array.FindAll(AppDomain.CurrentDomain.GetAssemblies(), a =>
                    !a.IsDynamic && File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, a.GetName().Name + ".dll")));
                modules = TraceProcessorModules.Loaded(kit, assemblies);
            }
            // Replay every occurrence of the selected packet values, including reuse by other issuers.
            using (var trace = TraceProcessor.Create(args[0], settings))
            {
                trace.Use(Providers, c => history.Observe(c.Event, tid, keys, true));
                trace.Process();
            }
            if (first.Total != history.Total || first.Invalid != history.Invalid || first.Unassigned != history.Unassigned) { return 1; }
            string pin;
            using (var sha = SHA256.Create()) { pin = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant(); }
            Console.WriteLine(new JavaScriptSerializer().Serialize(new { schema = "kn.traceprocessor_disk_requests.v1",
                source_sha256 = pin, source_bytes = file.Length, clock, loaded_processing_modules = modules,
                query_filter = new { pid, tid, start_qpc = start.ToString(Culture), stop_qpc = stop.ToString(Culture) },
                disk_events = history.Total, invalid_events = history.Invalid, unassigned_events = history.Unassigned,
                activity_rows = total, matched_activities = matches, unplaced_activities = unplaced, matched_events = history.Matches,
                selected_packets = keys.First.Count, packet_limit_hit = keys.Overflow, row_limit = Limit,
                events = history.Rows, activities = selected.ConvertAll(r => r.Project(keys)) }));
            return 0;
        }
    }
}
