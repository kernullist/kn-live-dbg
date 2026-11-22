using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Disk;

internal static class FileOperationContext
{
    private static readonly Guid FileProvider = new Guid("90cbdc39-4a3e-11d1-84f4-0000f80464e3");
    private static readonly CultureInfo Culture = CultureInfo.InvariantCulture;
    private const int Limit = 128;

    private static string Text(long n) { return n.ToString(Culture); }
    private static string Relation(ulong a, ulong b) { return a == 0 || b == 0 ? "unreported" : a == b ? "equal" : "different"; }

    private sealed class DiskRow
    {
        internal int Row;
        internal string Operation;
        internal long Start, Stop;
        internal ulong Packet, File;
        internal object Project() { return new { table_row = Row, operation = Operation, start_ns = Text(Start), stop_ns = Text(Stop) }; }
    }

    private sealed class FileRow
    {
        internal int Row, Opcode, BeginRecord, EndRecord, BeginCount, EndCount;
        internal string Operation;
        internal long Start, Stop;
        internal ulong Packet, File;
        internal uint Status;
        internal long? Requested, Actual;
        internal uint? Flags;
        internal ulong? Offset;
        internal bool Conflict;
        internal readonly List<DiskRow> Enclosed = new List<DiskRow>();

        internal object Project()
        {
            return new { table_row = Row, operation = Operation, start_ns = Text(Start), stop_ns = Text(Stop),
                begin_record = BeginRecord, end_record = EndRecord, begin_matches = BeginCount, end_matches = EndCount,
                packet_conflict = Conflict, ntstatus = Status, requested_bytes = Requested?.ToString(Culture),
                actual_bytes = Actual?.ToString(Culture), io_flags = Flags, file_offset = Offset?.ToString(Culture),
                enclosed = Enclosed.OrderBy(d => d.Row).Select(d => new { disk_table_row = d.Row, packet_value = Relation(Packet, d.Packet),
                    file_object_value = Relation(File, d.File) }).ToArray() };
        }
    }

    private sealed class PacketHistory
    {
        private int possiblyOpen, lastOpaque = -1;

        internal void ObserveOpaque(int record)
        {
            if (lastOpaque == record) { return; }
            lastOpaque = record;
            ++possiblyOpen;
        }

        internal void Observe(List<FileRow> rows, int op, long at, int record)
        {
            foreach (var f in rows)
            {
                if (at < f.Start || at > f.Stop) { continue; }
                if (op == f.Opcode && at == f.Start)
                {
                    f.BeginRecord = record;
                    ++f.BeginCount;
                    if (possiblyOpen != 0) { f.Conflict = true; }
                }
                else if (op == 76 && at == f.Stop)
                {
                    f.EndRecord = record;
                    ++f.EndCount;
                    if (possiblyOpen != 1) { f.Conflict = true; }
                }
                else { f.Conflict = true; }
            }
            if (op == 76)
            {
                if (possiblyOpen > 0) { --possiblyOpen; }
            }
            else { ++possiblyOpen; }
        }
    }

    private sealed class WatchedPacket
    {
        internal readonly List<FileRow> Rows = new List<FileRow>();
        private readonly Dictionary<int, PacketHistory> streams = new Dictionary<int, PacketHistory>();

        internal PacketHistory Stream(int key)
        {
            PacketHistory history;
            if (!streams.TryGetValue(key, out history)) { streams.Add(key, history = new PacketHistory()); }
            return history;
        }
    }

    private sealed class Window
    {
        internal uint Pid, Tid;
        internal long Left, Right;
        internal int Unplaced, DiskCount, FileCount, Links, Records, RawFiles, Ends;
        internal readonly List<DiskRow> Disks = new List<DiskRow>();
        internal readonly List<FileRow> Files = new List<FileRow>();
        private readonly Dictionary<ulong, WatchedPacket> watched = new Dictionary<ulong, WatchedPacket>();

        internal void SelectDisks(IReadOnlyList<IDiskActivity> rows)
        {
            for (int i = 0; i < rows.Count; ++i)
            {
                var r = rows[i];
                if ((uint?)r.IssuingThread?.Id != Tid || (uint?)r.IssuingProcess?.Id != Pid) { continue; }
                if (!r.InitializeTime.HasValue || !r.CompleteTime.HasValue || r.InitializeTime.Context.ClockType != TraceClockType.PerformanceCounter ||
                    r.CompleteTime.Context.ClockType != TraceClockType.PerformanceCounter) { ++Unplaced; continue; }
                long lo = r.InitializeTime.RelativeTimestamp.Nanoseconds, hi = r.CompleteTime.RelativeTimestamp.Nanoseconds;
                if (hi < lo) { ++Unplaced; continue; }
                if (Math.Max(lo, Left) >= Math.Min(hi, Right)) { continue; }
                if (++DiskCount <= Limit)
                {
                    Disks.Add(new DiskRow { Row = i+1, Operation = r.IOType.ToString().ToLowerInvariant(), Start = lo, Stop = hi,
                        Packet = unchecked((ulong)r.PacketAddress.Value), File = unchecked((ulong)r.FileObject.Value) });
                }
            }
        }

        internal void SelectFiles<T>(IReadOnlyList<T> rows, string operation, int opcode) where T : IFileActivity
        {
            var targets = Disks.Where(d => d.Operation == operation).OrderBy(d => d.Start).ToArray();
            if (targets.Length == 0 || DiskCount > Limit) { return; }
            for (int i = 0; i < rows.Count; ++i)
            {
                var r = rows[i];
                if ((uint?)r.IssuingThread?.Id != Tid || (uint?)r.IssuingProcess?.Id != Pid) { continue; }
                if (!r.StartTime.HasValue || !r.StopTime.HasValue || r.StartTime.Context.ClockType != TraceClockType.PerformanceCounter ||
                    r.StopTime.Context.ClockType != TraceClockType.PerformanceCounter) { ++Unplaced; continue; }
                long lo = r.StartTime.RelativeTimestamp.Nanoseconds, hi = r.StopTime.RelativeTimestamp.Nanoseconds;
                if (hi < lo) { ++Unplaced; continue; }
                if (hi <= Left || lo >= Right || hi < targets[0].Start || lo > targets[targets.Length-1].Start) { continue; }
                FileRow f = null;
                foreach (var d in targets)
                {
                    if (d.Start > hi) { break; }
                    if (d.Start < lo || d.Stop > hi) { continue; }
                    if (f == null)
                    {
                        ++FileCount;
                        f = new FileRow { Row = i+1, Opcode = opcode, Operation = operation, Start = lo, Stop = hi,
                            Packet = unchecked((ulong)r.PacketObject.Value), File = unchecked((ulong)r.FileObject.Value),
                            Status = unchecked((uint)r.ErrorCode) };
                        var read = r as IReadFileActivity;
                        var write = r as IWriteFileActivity;
                        if (read != null) { f.Offset = unchecked((ulong)read.Offset.Value); f.Flags = (uint)read.PacketFlags;
                            f.Requested = read.RequestedSize.Bytes; f.Actual = read.ActualSize.Bytes; }
                        if (write != null) { f.Offset = unchecked((ulong)write.Offset.Value); f.Flags = (uint)write.PacketFlags;
                            f.Requested = write.RequestedSize.Bytes; f.Actual = write.ActualSize.Bytes; }
                        if (FileCount <= Limit) { Files.Add(f); }
                    }
                    if (++Links <= Limit) { f.Enclosed.Add(d); }
                }
            }
        }

        internal void Prepare()
        {
            foreach (var f in Files)
            {
                if (f.Packet == 0) { f.Conflict = true; continue; }
                WatchedPacket packet;
                if (!watched.TryGetValue(f.Packet, out packet)) { watched.Add(f.Packet, packet = new WatchedPacket()); }
                packet.Rows.Add(f);
            }
        }

        internal void Observe(TraceEvent e)
        {
            ++Records;
            if (e.ProviderId != FileProvider) { return; }
            ++RawFiles;
            int op = e.IsClassic ? e.Id : -1;
            if (op == 76) { ++Ends; }
            if (watched.Count == 0 || op == 0 || op == 32 || op == 35 || op == 36) { return; }
            if (!e.Timestamp.HasValue || e.Timestamp.IsPartial || e.Timestamp.Context.ClockType != TraceClockType.PerformanceCounter)
            { ++Unplaced; return; }
            long at = e.Timestamp.RelativeTimestamp.Nanoseconds;
            var size = e.Flags & (TraceEventHeaderFlags.Has32BitHeader | TraceEventHeaderFlags.Has64BitHeader);
            if ((size != TraceEventHeaderFlags.Has32BitHeader && size != TraceEventHeaderFlags.Has64BitHeader) ||
                (e.Flags & (TraceEventHeaderFlags.StringOnly | TraceEventHeaderFlags.TraceMessage)) != 0)
            { ++Unplaced; return; }
            int width = size == TraceEventHeaderFlags.Has32BitHeader ? 4 : 8, offset = op == 67 || op == 68 ? 8 : 0;
            var data = e.Data;
            int stream = ((int)e.LoggerId << 1) | (width == 8 ? 1 : 0);
            WatchedPacket target;
            if (e.Version != 3 || op < 64 || op > 77)
            {
                // An opaque record can disqualify a generation, but can never establish one.
                foreach (var f in Files) { if (f.Start <= at && at <= f.Stop) { f.Conflict = true; } }
                for (int i = 0; i <= data.Length-width; i += 4)
                {
                    ulong value = width == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i)) :
                        BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i));
                    if (watched.TryGetValue(value, out target)) { target.Stream(stream).ObserveOpaque(Records); }
                }
                return;
            }
            if (data.Length < (op == 76 ? 2*width+4 : offset+2*width+4)) { ++Unplaced; return; }
            ulong packet = width == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset)) :
                BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(offset));
            if (watched.TryGetValue(packet, out target)) { target.Stream(stream).Observe(target.Rows, op, at, Records); }
        }
    }

    internal static int Run(string[] args)
    {
        uint pid, tid;
        long start, stop;
        if (!uint.TryParse(args[2], NumberStyles.None, Culture, out pid) || !uint.TryParse(args[3], NumberStyles.None, Culture, out tid) ||
            pid == 0 || tid == 0 || pid == uint.MaxValue || tid == uint.MaxValue ||
            !long.TryParse(args[4], NumberStyles.AllowLeadingSign, Culture, out start) ||
            !long.TryParse(args[5], NumberStyles.AllowLeadingSign, Culture, out stop) || start >= stop) { return 2; }
        string kit = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wpt");
        var settings = new TraceProcessorSettings { ToolkitPath = kit, CatalogPath = Path.Combine(kit, "Catalog"),
            AllowLostEvents = false, AllowTimeInversion = false };
        using (var input = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (input.Length < 1 || input.Length > 512L*1024*1024) { return 2; }
            var window = new Window { Pid = pid, Tid = tid };
            object clock, counts, modules;
            using (var trace = TraceProcessor.Create(args[0], settings))
            {
                var time = trace.UseTraceTimestampContext();
                var info = trace.UseMetadata();
                var disk = trace.UseDiskIOData();
                var files = trace.UseFileIOData();
                trace.Process();
                if (time.IsPartial || time.ClockType != TraceClockType.PerformanceCounter || time.ClockType != info.ClockType) { return 1; }
                window.Left = time.GetRelativeTimestamp(new TraceTimestampValue(start)).Nanoseconds;
                window.Right = time.GetRelativeTimestamp(new TraceTimestampValue(stop)).Nanoseconds;
                clock = new { kind = time.ClockType.ToString(), frequency = Text(info.PerformanceCounterFrequency.Hertz),
                    reference_qpc = Text(time.ReferenceValue.RawValue), reference_ns = Text(time.GetRelativeTimestamp(time.ReferenceValue).Nanoseconds),
                    start_ns = Text(window.Left), stop_ns = Text(window.Right), lost_events = info.LostEventCount, lost_buffers = info.LostBufferCount };
                var f = files.Result;
                counts = new { disk = disk.Result.Activity.Count, read = f.ReadFileActivity.Count, write = f.WriteFileActivity.Count, flush = f.FlushFileActivity.Count };
                window.SelectDisks(disk.Result.Activity);
                window.SelectFiles(f.ReadFileActivity, "read", 67);
                window.SelectFiles(f.WriteFileActivity, "write", 68);
                window.SelectFiles(f.FlushFileActivity, "flush", 73);
                var assemblies = Array.FindAll(AppDomain.CurrentDomain.GetAssemblies(), a =>
                    !a.IsDynamic && File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, a.GetName().Name + ".dll")));
                modules = TraceProcessorModules.Loaded(kit, assemblies);
            }
            window.Prepare();
            using (var trace = TraceProcessor.Create(args[0], settings))
            { trace.Use(c => window.Observe(c.Event)); trace.Process(); }
            string pin;
            using (var sha = SHA256.Create()) { pin = BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant(); }
            Console.WriteLine(new JavaScriptSerializer().Serialize(new { schema = "kn.traceprocessor_file_operations.v1",
                source_sha256 = pin, source_bytes = input.Length, clock, loaded_processing_modules = modules,
                query_filter = new { pid, tid, start_qpc = Text(start), stop_qpc = Text(stop) }, table_counts = counts,
                records_seen = window.Records, file_records = window.RawFiles, operation_ends = window.Ends,
                matched_disks = window.DiskCount, matched_files = window.FileCount, matched_links = window.Links, unplaced = window.Unplaced,
                row_limit = Limit, disks = window.Disks.Select(d => d.Project()).ToArray(), files = window.Files.Select(f => f.Project()).ToArray() }));
            return 0;
        }
    }
}
