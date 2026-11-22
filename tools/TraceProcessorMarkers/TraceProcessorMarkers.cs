using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Events;
using Microsoft.Windows.EventTracing.Processes;

internal static class TraceProcessorMarkers
{
    private const int RowLimit = 128;
    private const int MaxRecords = 2000000;

    private static int Main(string[] args)
    {
        Guid provider, activity;
        uint pid = 0, tid = 0;
        byte channel = 0;
        ushort task = 0;
        long begin = 0, end = 0;
        var style = NumberStyles.None;
        var culture = CultureInfo.InvariantCulture;
        bool wholeActivity = args.Length == 4 && args[3] == "--all-markers";
        if ((!wholeActivity && args.Length != 9) || !Guid.TryParseExact(args[1], "D", out provider) || provider == Guid.Empty ||
            !Guid.TryParseExact(args[2], "D", out activity) || activity == Guid.Empty ||
            (!wholeActivity && (!UInt32.TryParse(args[3], style, culture, out pid) || !UInt32.TryParse(args[4], style, culture, out tid) ||
             !Byte.TryParse(args[5], style, culture, out channel) || !UInt16.TryParse(args[6], style, culture, out task) ||
             !Int64.TryParse(args[7], style, culture, out begin) || !Int64.TryParse(args[8], style, culture, out end) ||
             begin <= 0 || end <= begin)))
        {
            return 2;
        }

        try
        {
            using (var source = new FileStream(args[0], FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var sha = SHA256.Create())
            {
                if (source.Length < 1 || source.Length > 512L * 1024 * 1024)
                {
                    return 2;
                }
                var pin = BitConverter.ToString(sha.ComputeHash(source)).Replace("-", "").ToLowerInvariant();
                var toolkit = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wpt");
                var settings = new TraceProcessorSettings {
                    ToolkitPath = toolkit, CatalogPath = Path.Combine(toolkit, "Catalog"),
                    AllowLostEvents = false, AllowTimeInversion = false
                };
                using (var trace = TraceProcessor.Create(args[0], settings))
                {
                    var metadata = wholeActivity ? trace.UseMetadata() : null;
                    var clock = wholeActivity ? trace.UseTraceTimestampContext() : null;
                    var pending = trace.UseGenericEvents(new[] { provider });
                    trace.Process();
                    var table = pending.Result.Events;
                    if (table.Count > MaxRecords)
                    {
                        return 1;
                    }
                    var rows = new List<object>();
                    int activityMarkers = 0, scoped = 0, matched = 0;
                    for (int i = 0; i < table.Count; ++i)
                    {
                        var e = table[i];
                        if (e.ProviderId != provider)
                        {
                            return 1;
                        }
                        if (e.ActivityId != activity || (e.Opcode != 1 && e.Opcode != 2))
                        {
                            continue;
                        }
                        ++activityMarkers;
                        if (!wholeActivity && (unchecked((uint)e.ProcessId) != pid || unchecked((uint)e.ThreadId) != tid ||
                            e.Channel != channel || e.Task != task))
                        {
                            continue;
                        }
                        ++scoped;
                        var stamp = e.Timestamp;
                        if (!wholeActivity && stamp.HasValue && !stamp.IsPartial && stamp.Context.ClockType == TraceClockType.PerformanceCounter &&
                            (stamp.Value.RawValue < begin || stamp.Value.RawValue > end))
                        {
                            continue;
                        }
                        ++matched;
                        if (rows.Count == RowLimit)
                        {
                            continue;
                        }
                        rows.Add(new {
                            table_row = i + 1, provider_guid = e.ProviderId.ToString("D"), activity_id = e.ActivityId.ToString("D"),
                            event_id = e.Id, version = e.Version, channel = e.Channel, task = e.Task, opcode = e.Opcode,
                            header_process_id = unchecked((uint)e.ProcessId), header_thread_id = unchecked((uint)e.ThreadId),
                            clock_type = stamp.HasValue ? stamp.Context.ClockType.ToString() : null,
                            timestamp_partial = stamp.IsPartial,
                            raw_timestamp = stamp.HasValue ? stamp.Value.RawValue.ToString(CultureInfo.InvariantCulture) : null
                        });
                    }

                    object filter = wholeActivity ? (object)new { opcodes = new[] { 1, 2 } } :
                        new { header_process_id = pid, header_thread_id = tid, channel = channel, task = task,
                              begin_raw = begin.ToString(culture), end_raw = end.ToString(culture) };
                    var result = new Dictionary<string, object> {
                        { "schema", wholeActivity ? "kn.traceprocessor_activity_markers.v1" : "kn.traceprocessor_activity_rows.v1" },
                        { "source_sha256", pin }, { "source_bytes", source.Length }, { "table", "IGenericEventDataSource.Events" },
                        { "provider_guid", provider.ToString("D") }, { "activity_id", activity.ToString("D") }, { "query_filter", filter },
                        { "loaded_processing_modules", TraceProcessorModules.Loaded(toolkit, new[] {
                            typeof(TraceProcessor).Assembly, typeof(IGenericEvent).Assembly, typeof(IProcess).Assembly }) },
                        { "provider_rows", table.Count }, { "activity_marker_rows", activityMarkers }, { "scoped_marker_rows", scoped },
                        { "matched_rows", matched }, { "row_limit", RowLimit }, { "rows", rows }
                    };
                    if (wholeActivity)
                    {
                        result.Add("trace_metadata", new {
                            clock_type = metadata.ClockType.ToString(), context_clock_type = clock.ClockType.ToString(),
                            timestamp_context_partial = clock.IsPartial, performance_counter_hz = metadata.PerformanceCounterFrequency.Hertz.ToString(culture),
                            lost_events = metadata.LostEventCount, lost_buffers = metadata.LostBufferCount });
                    }
                    Console.WriteLine(new JavaScriptSerializer().Serialize(result));
                    return 0;
                }
            }
        }
        catch (Exception error)
        {
            // Keep diagnostic text from incorporating source paths or trace payloads.
            Console.Error.WriteLine(error.GetType().FullName);
            return 1;
        }
    }
}
