"""Bind disk packet lifetimes to original ETW records and intersect them with a marked thread's scheduler history."""
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict

from etl_activity_waits import MAX_RECORDS, candidate, tick
from etl_traceprocessor import verify_modules
from owned_module_benchmark import check, decimal, fields, uint

LIMIT = 2048
MAX_PAGES = 64
MAX_INTERSECTIONS = 8192
OPERATIONS = {10: "read", 11: "write", 12: "read", 13: "write", 14: "flush", 15: "flush"}
STARTS = (12, 13, 15)
STATES = ("on_cpu", "waiting_before_ready", "ready_to_dispatch", "other_off_cpu")


class Unavailable(ValueError):
    """A recorded coverage limit prevents a whole-window measurement."""


def projection(doc, common, w):
    fields(doc, "schema source_sha256 source_bytes clock loaded_processing_modules query_filter disk_events invalid_events "
           "unassigned_events activity_rows matched_activities unplaced_activities matched_events selected_packets packet_limit_hit "
           "row_limit events activities", "disk SDK projection")
    a, b = w["start"], w["stop"]
    expected = dict(pid=a["header_process_id"], tid=a["header_thread_id"], start_qpc=a["raw_timestamp"], stop_qpc=b["raw_timestamp"])
    check(doc["schema"] == "kn.traceprocessor_disk_requests.v1" and doc["source_sha256"] == common["source_sha256"] and
          uint(doc["source_bytes"]) == common["source_bytes"] and doc["query_filter"] == expected and
          uint(doc["query_filter"]["pid"]) == expected["pid"] and uint(doc["query_filter"]["tid"]) == expected["tid"],
          "disk source or thread filter differs")
    verify_modules(doc["loaded_processing_modules"], ("Disk", "Processes", "Processing"),
                   {"Microsoft.Windows.EventTracing.Cpu.dll", "Microsoft.Windows.EventTracing.Metadata.dll", "System.Memory.dll",
                    "System.Buffers.dll", "System.Numerics.Vectors.dll", "System.Runtime.CompilerServices.Unsafe.dll",
                    "System.Security.Principal.Windows.dll"})
    clock = doc["clock"]
    fields(clock, "kind frequency reference_qpc reference_ns start_ns stop_ns lost_events lost_buffers", "disk SDK clock")
    hz = decimal(common["clock"]["header_perf_frequency"])
    if clock["kind"] != "PerformanceCounter" or decimal(clock["frequency"]) != hz or uint(clock["lost_events"]) or uint(clock["lost_buffers"]):
        raise Unavailable("disk_clock_or_loss_unqualified")
    ref, ref_ns = tick(clock["reference_qpc"]), tick(clock["reference_ns"])

    def mapped(raw, ns):
        check(abs((tick(raw)-ref)*1_000_000_000 - (tick(ns)-ref_ns)*hz) < hz, "inconsistent disk time mapping")

    mapped(expected["start_qpc"], clock["start_ns"])
    mapped(expected["stop_qpc"], clock["stop_ns"])
    total = uint(doc["disk_events"], MAX_RECORDS)
    activity_total = uint(doc["activity_rows"], MAX_RECORDS)
    event_count, activity_count = uint(doc["matched_events"], total), uint(doc["matched_activities"], activity_total)
    check(type(doc["events"]) is list and type(doc["activities"]) is list and uint(doc["row_limit"]) == LIMIT and
          len(doc["events"]) == min(LIMIT, event_count) and len(doc["activities"]) == min(LIMIT, activity_count) and
          type(doc["packet_limit_hit"]) is bool, "invalid disk projection extent")
    if doc["packet_limit_hit"] or max(event_count, activity_count) > LIMIT:
        raise Unavailable("disk_row_limit")
    if uint(doc["invalid_events"], total) or uint(doc["unassigned_events"], total) or uint(doc["unplaced_activities"], activity_total):
        raise Unavailable("disk_events_unqualified")
    packets = defaultdict(list)
    last = 0
    for e in doc["events"]:
        fields(e, "disk_ordinal packet_first_ordinal opcode version pointer_bytes logger_id cpu issuing_tid raw_timestamp relative_ns", "disk event")
        ordinal = uint(e["disk_ordinal"], total)
        first = uint(e["packet_first_ordinal"], ordinal)
        check(last < ordinal and first and (first in packets or first == ordinal) and uint(e["opcode"]) in OPERATIONS and
              uint(e["version"]) == 3 and uint(e["pointer_bytes"]) in (4, 8) and 0 < uint(e["issuing_tid"]) < 0xffffffff, "invalid disk endpoint")
        uint(e["cpu"], 65535)
        uint(e["logger_id"], 65535)
        mapped(e["raw_timestamp"], e["relative_ns"])
        packets[first].append(e)
        last = ordinal
    if len(packets) != uint(doc["selected_packets"], LIMIT):
        raise Unavailable("disk_packet_history_missing")
    activities = {}
    last = 0
    for r in doc["activities"]:
        fields(r, "table_row packet_first_ordinal operation io_source start_ns stop_ns disk size_bytes", "disk activity row")
        row = uint(r["table_row"], activity_total)
        key = (uint(r["packet_first_ordinal"], total), r["operation"], tick(r["start_ns"]), tick(r["stop_ns"]))
        check(last < row and key[0] in packets and key[1] in ("read", "write", "flush") and
              max(key[2], tick(clock["start_ns"])) < min(key[3], tick(clock["stop_ns"])) and
              type(r["io_source"]) is str and 0 < len(r["io_source"]) <= 64, "invalid disk activity")
        uint(r["disk"], 0xffffffff)
        decimal(r["size_bytes"])
        if key in activities:
            raise Unavailable("ambiguous_disk_activity")
        activities[key] = r
        last = row
    return packets, activities


def pairs(w, packets, activities):
    marker = w["start"]
    tid = marker["header_thread_id"]
    left, right = tick(marker["raw_timestamp"]), tick(w["stop"]["raw_timestamp"])
    bounds = w["thread_evidence"]
    birth, death = (tick(bounds[k]["raw_timestamp"]) for k in ("before", "after"))
    result = []
    for first, history in packets.items():
        group = []
        depth = 0
        previous, last_closed = None, birth
        for e in history:
            at = tick(e["raw_timestamp"])
            check(previous is None or previous <= at, "reversed packet history")
            previous = at
            group.append(e)
            if e["opcode"] in STARTS:
                depth += 1
                continue
            depth = max(0, depth-1)
            if depth:
                continue
            start = group[0]
            lo = tick(start["raw_timestamp"]) if start["opcode"] in STARTS else last_closed
            if any(x["issuing_tid"] == tid for x in group) and max(left, lo) < min(right, at):
                if len(group) == 1:
                    raise Unavailable("disk_initiation_missing")
                if len(group) != 2 or OPERATIONS[start["opcode"]] != OPERATIONS[e["opcode"]]:
                    raise Unavailable("ambiguous_disk_packet_history")
                if not (start["issuing_tid"] == e["issuing_tid"] == tid and start["logger_id"] == e["logger_id"] == marker["logger_id"] and
                        start["pointer_bytes"] == e["pointer_bytes"] and birth < lo < at < death):
                    raise Unavailable("disk_issuer_lifetime_unconfirmed")
                key = (first, OPERATIONS[e["opcode"]], tick(start["relative_ns"]), tick(e["relative_ns"]))
                activity = activities.pop(key, None)
                if activity is None:
                    raise Unavailable("disk_table_pair_unconfirmed")
                result.append((start, e, activity))
            last_closed = at
            group = []
        if any(e["issuing_tid"] == tid for e in group) and tick(group[0]["raw_timestamp"]) < right:
            raise Unavailable("disk_completion_missing")
    if activities:
        raise Unavailable("disk_table_pair_unconfirmed")
    return sorted(result, key=lambda triple: triple[0]["disk_ordinal"])


def native_endpoints(query, doc, common, tid, pages):
    total = doc["disk_events"]
    raw = {r["disk_ordinal"]: r for r in doc["events"]}
    if total > MAX_PAGES * 128:
        raise Unavailable("disk_page_limit")
    selected = {}
    counts = Counter()
    operations = None
    previous = 0
    for cursor in range(0, max(1, total), 128):
        q = query(cursor, 128)
        pages.append(q)
        p = q["page"]
        if p is None or q["reader"]["exit_code"] != 0 or p["status"] != "read":
            raise Unavailable("disk_native_reader_unavailable")
        count = min(128, total-cursor)
        check(p["schema"] == "kn.etl_disk_io.v1" and p["provider_guid"] == "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c" and
              p["event_id"] == 0 and p["opcodes"] == list(OPERATIONS) and p["versions"] == [2, 3] and
              all(p[k] == common[k] for k in ("source_sha256", "source_bytes", "clock", "log_header",
              "records_seen", "buffers_processed", "buffer_comparison", "loss_marker_records")) and uint(p["unsupported_disk_records"]) == 0 and
              uint(p["decoded_disk_records"]) == total and p["response_ticks_per_second"] == common["clock"]["header_perf_frequency"] and
              uint(p["after"]) == cursor and type(p["disk_events"]) is list and len(p["disk_events"]) == count and
              p["next_after"] == (cursor+count if cursor+count < total else None), "native disk table or page differs")
        if cursor == 0:
            operations = p["operations"]
        check(type(operations) is list and len(operations) == 3 and p["operations"] == operations, "native disk totals changed")
        for n, r in enumerate(p["disk_events"], cursor+1):
            record = uint(r["record_ordinal"], common["records_seen"])
            op = uint(r["opcode"])
            check(previous < record and uint(r["disk_event_ordinal"]) == n and uint(r["version"]) == 3 and
                  op in OPERATIONS and r["operation"] == OPERATIONS[op] and r["phase"] == ("initiation" if op in STARTS else "completion") and
                  r["cpu_field"] in ("processor_number", "processor_index") and
                  0 < uint(r["reported_issuing_tid"]) < 0xffffffff, "unqualified native disk row")
            counts[op] += 1
            previous = record
            if n not in raw:
                check(r["reported_issuing_tid"] != tid, "SDK omitted an endpoint for the marked TID")
                continue
            e = raw[n]
            check(all(r[k] == e[k] for k in ("opcode", "version", "cpu", "pointer_bytes", "logger_id", "raw_timestamp")) and
                  r["reported_issuing_tid"] == e["issuing_tid"], "native and SDK disk histories differ")
            selected[n] = r
    check([(o["operation"], uint(o["initiations"]), uint(o["completions"])) for o in operations] ==
          [(OPERATIONS[a], counts[a], counts[b]) for a, b in ((12, 10), (13, 11), (15, 14))], "native disk totals differ from rows")
    check(selected.keys() == raw.keys(), "missing native disk history")
    return selected


def bind(w, selected, native):
    bounds = w["thread_evidence"]
    birth, death = (bounds[k]["record_ordinal"] for k in ("before", "after"))
    requests = []
    for start, stop, activity in selected:
        a, b = (native[e["disk_ordinal"]] for e in (start, stop))
        check(birth < a["record_ordinal"] < b["record_ordinal"] < death and a["cpu_field"] == b["cpu_field"] and
              uint(b["disk_number"]) == activity["disk"] and (b["transfer_bytes"] is None if b["operation"] == "flush" else
              uint(b["transfer_bytes"]) == decimal(activity["size_bytes"])), "disk lifetime or completion fields differ")
        duration = tick(b["raw_timestamp"]) - tick(a["raw_timestamp"])
        requests.append(dict(table_row=activity["table_row"], packet_first_ordinal=start["packet_first_ordinal"], operation=b["operation"],
                             init_record=a["record_ordinal"], complete_record=b["record_ordinal"], init_disk_ordinal=start["disk_ordinal"],
                             complete_disk_ordinal=stop["disk_ordinal"], start_qpc=a["raw_timestamp"], stop_qpc=b["raw_timestamp"],
                             elapsed_ticks=str(duration), reported_response_ticks=str(decimal(b["high_res_response_ticks"])),
                             following_ready_in_wait=None))
    return requests


class DiskTimeline:
    def __init__(self, requests, window):
        self.requests = requests
        self.left, self.right = (tick(window[k]["raw_timestamp"]) for k in ("start", "stop"))
        self.cursor = self.left
        self.edges = []
        for r in requests:
            self.edges.append((max(self.left, tick(r["start_qpc"])), 1, r["table_row"]))
            self.edges.append((min(self.right, tick(r["stop_qpc"])), 0, r["table_row"]))
        self.edges.sort()
        self.completions = sorted(requests, key=lambda r: tick(r["stop_qpc"]))
        self.completion_times = [tick(r["stop_qpc"]) for r in self.completions]
        self.index = self.cells = 0
        self.active = set()
        self.totals = dict.fromkeys(STATES, 0)
        self.overlaps = []

    def piece(self, lo, hi, state, a, b, ready):
        check(lo == self.cursor and lo <= hi <= self.right, "discontinuous disk scheduler partition")
        while lo < hi:
            while self.index < len(self.edges) and self.edges[self.index][0] == lo:
                _, enter, row = self.edges[self.index]
                if enter:
                    self.active.add(row)
                else:
                    self.active.remove(row)
                self.index += 1
            end = min(hi, self.edges[self.index][0]) if self.index < len(self.edges) else hi
            check(end > lo, "invalid disk request boundary")
            if self.active:
                self.cells += len(self.active)
                if self.cells > MAX_INTERSECTIONS:
                    raise Unavailable("disk_intersection_limit")
                self.totals[state] += end-lo
                self.overlaps.append(dict(start_qpc=str(lo), stop_qpc=str(end), state=state, table_rows=sorted(self.active),
                                          switch_start_record=a, switch_stop_record=b, ready_record=ready))
            lo = end
        self.cursor = hi

    def account(self, window, waits):
        off = iter(waits)
        for interval in window["intervals"]:
            lo, hi = tick(interval["overlap_start_raw"]), tick(interval["overlap_end_raw"])
            a, b = interval["start"]["record_ordinal"], interval["end"]["record_ordinal"]
            if interval["relation"] == "running_on_cpu":
                self.piece(lo, hi, "on_cpu", a, b, None)
                continue
            wait = next(off)
            r = candidate(interval)
            if r and wait["dispatch_relation"] in ("waiting_ready_switch_in", "ready_switch_in"):
                ready_at = tick(r["raw_timestamp"])
                pivot = min(hi, max(lo, ready_at))
                state = "waiting_before_ready" if wait["dispatch_relation"] == "waiting_ready_switch_in" else "other_off_cpu"
                if state == "waiting_before_ready" and lo <= ready_at < hi:
                    first = bisect_left(self.completion_times, lo)
                    last = bisect_right(self.completion_times, ready_at)
                    for request in self.completions[first:last]:
                        if a < request["complete_record"] < r["record_ordinal"] < b:
                            request["following_ready_in_wait"] = dict(switch_out_record=a, ready_record=r["record_ordinal"],
                                switch_in_record=b, gap_ticks=str(ready_at-tick(request["stop_qpc"])))
                self.piece(lo, pivot, state, a, b, r["record_ordinal"])
                self.piece(pivot, hi, "ready_to_dispatch", a, b, r["record_ordinal"])
            else:
                self.piece(lo, hi, "other_off_cpu", a, b, None)

    def finish(self):
        total = sum(self.totals.values())
        union = 0
        covered_until = self.left
        for start, stop in sorted((max(self.left, tick(r["start_qpc"])), min(self.right, tick(r["stop_qpc"]))) for r in self.requests):
            check(start < stop, "disk request outside the marker window")
            union += max(0, stop-max(covered_until, start))
            covered_until = max(covered_until, stop)
        check(self.cursor == self.right and total == union <= self.right-self.left, "incomplete disk scheduler accounting")
        return dict(requests=self.requests, request_union_ticks=str(total), **{k+"_ticks": str(v) for k, v in self.totals.items()}, overlaps=self.overlaps)


def prepare(sdk_query, native_query, common, w):
    result = dict(status="disk_sdk_unavailable", sdk_query=sdk_query, native_pages=[], summary=None)
    doc = sdk_query["page"]
    if doc is None or sdk_query["reader"]["exit_code"] != 0:
        return result, None
    try:
        packets, activities = projection(doc, common, w)
        native = native_endpoints(native_query, doc, common, w["start"]["header_thread_id"], result["native_pages"])
        if not doc["disk_events"]:
            raise Unavailable("disk_events_unobserved")
        selected = pairs(w, packets, activities)
        timeline = DiskTimeline(bind(w, selected, native), w)
        return result, timeline
    except Unavailable as exc:
        result["status"] = str(exc)
    except (ValueError, KeyError, TypeError, RecursionError):
        result["status"] = "inconsistent_disk_evidence"
    return result, None
