"""Decode the owned dispatch counters and time-bounded Windows wait-chain queries in a pinned ETL."""
import re
import struct

from owned_module_benchmark import check, decimal, fields, uint


U32 = (1 << 32) - 1
MAX_QPC = (1 << 63) - 1
THREAD, THREAD_WAIT, BLOCKED, OWNED = 8, 6, 3, 6
MAX_VIEWS = 8


def words(row):
    payload = row["handoff_payload"]
    fields(payload, "payload_bytes payload_hex", "scheduling payload")
    n, raw = uint(payload["payload_bytes"], 1024), payload["payload_hex"]
    check(n and n % 8 == 0 and type(raw) is str and len(raw) == 2*n and re.fullmatch("[a-f0-9]+", raw),
          "invalid scheduling payload extent")
    values = struct.unpack("<" + "Q"*(n//8), bytes.fromhex(raw))
    check(values[0] == 1, "unknown scheduling payload version")
    return values


def reading(raw):
    status, lo, hi, switches, reasons, cycles, retries = raw
    uint(status, U32)
    uint(switches, U32)
    uint(retries, U32)
    if status == U32:
        check(not any(raw[1:]), "unissued dispatch read has data")
    else:
        check(0 < lo <= hi <= MAX_QPC, "invalid dispatch read clock")
        check(not status or not any(raw[3:]), "failed dispatch read has counters")
    return dict(win32_status=status, begin_qpc=str(lo), end_qpc=str(hi), context_switches=switches,
                wait_reason_bitmap=str(reasons), cycle_time=str(cycles), retry_count=retries)


def profile(row, call, start_write_end, stop_write_begin):
    raw = words(row)
    check(len(raw) == 19 and tuple(raw[3:5]) == call, "dispatch call differs from recorded wait")
    enable, disable = (uint(v, U32) for v in raw[1:3])
    before, after = reading(raw[5:12]), reading(raw[12:19])
    result = dict(status="unavailable", stop_record=row["event"]["record_ordinal"], enable_win32=enable, disable_win32=disable,
                  before=before, after=after, switch_delta=None, cycle_delta=None, interval_wait_reasons=None)
    if enable:
        check(disable == U32 and before["win32_status"] == after["win32_status"] == U32, "unopened dispatch profile was used")
        return result
    check(disable != U32 and before["win32_status"] != U32 and after["win32_status"] != U32, "incomplete dispatch lifecycle")
    check(start_write_end <= int(before["begin_qpc"]) <= int(before["end_qpc"]) <= call[0] and
          call[1] <= int(after["begin_qpc"]) <= int(after["end_qpc"]) <= stop_write_begin, "dispatch readings do not enclose the call")
    if disable or before["win32_status"] or after["win32_status"]:
        return result
    switches = after["context_switches"] - before["context_switches"]
    cycles = int(after["cycle_time"]) - int(before["cycle_time"])
    if switches < 0 or cycles < 0:
        result["status"] = "counter_discontinuity"
        return result
    result.update(status="measured", switch_delta=switches, cycle_delta=str(cycles), interval_wait_reasons=after["wait_reason_bitmap"])
    return result


def view(start, stop, slot, join, pid, caller, worker):
    raw = words(stop)
    check(len(raw) >= 10 and raw[1] == slot, "out-of-order wait-chain result")
    before, after, lo, hi, status, cycle, reported, count = raw[2:10]
    for value in (before, after, status, reported):
        uint(value, U32)
    check(before in (0, 258, U32) and after in (0, 258, U32) and cycle <= 1 and
          count <= 16 and count <= reported and len(raw) == 10+6*count and (status or 0 < reported == count),
          "invalid wait-chain result")
    check(not (before == 0 and after == 258), "worker handle became nonsignaled")
    head, tail = start["event"], stop["event"]
    check(decimal(head["raw_timestamp"]) <= lo <= hi <= decimal(tail["raw_timestamp"]) <= MAX_QPC, "wait-chain call outside its markers")
    nodes = []
    for pos in range(10, len(raw), 6):
        kind, state, process, tid, wait_time, switches = (uint(v, U32) for v in raw[pos:pos+6])
        node = dict(type=kind, status=state)
        if kind == THREAD:
            node.update(pid=process, tid=tid, wait_time=wait_time, context_switches=switches)
        else:
            check(not any((process, tid, wait_time, switches)), "thread fields on a wait object")
        nodes.append(node)
    direct = (len(nodes) >= 3 and nodes[0]["type"] == THREAD and nodes[0]["status"] == BLOCKED and
              (nodes[0]["pid"], nodes[0]["tid"]) == (pid, caller) and (nodes[1]["type"], nodes[1]["status"]) == (THREAD_WAIT, OWNED) and
              nodes[2]["type"] == THREAD and nodes[2]["status"] in (2, BLOCKED) and (nodes[2]["pid"], nodes[2]["tid"]) == (pid, worker))
    if status or cycle or nodes[0].get("pid") != pid or nodes[0].get("tid") != caller:
        relation = "query_unqualified"
    elif before != 258 or after != 258:
        relation = "worker_lifetime_unqualified"
    elif lo <= join[0] or hi >= join[1]:
        relation = "outside_join_call"
    else:
        relation = "blocked_on_joined_worker" if direct else "other_wait_state"
    return dict(view=slot, start_record=head["record_ordinal"], stop_record=tail["record_ordinal"],
                begin_qpc=str(lo), end_qpc=str(hi), worker_before=before, worker_after=after, query_win32=status,
                cycle=bool(cycle), reported_nodes=reported, nodes=nodes, relation=relation)


def observer(extra, main, join, signal, pid, caller, worker):
    check(2 <= len(extra) <= 2+2*MAX_VIEWS and len(extra) % 2 == 0, "missing observer markers")
    first, last = extra[0], extra[-1]
    head, tail = first["event"], last["event"]
    raw = words(last)
    check(len(raw) == 7, "invalid observer summary")
    setup, opened, error, why, tid, count = (uint(v, U32) for v in raw[1:])
    check(count <= MAX_VIEWS and len(extra) == 2+2*count and why <= 3 and
          (head["event_id"], tail["event_id"]) == (20, 21) and first["handoff_payload"] is None and
          head["header_thread_id"] == tail["header_thread_id"] == caller and
          head["record_ordinal"] < main[1]["event"]["record_ordinal"] < main[2]["event"]["record_ordinal"] < tail["record_ordinal"],
          "observer session does not enclose the activity")
    session_start, session_stop = decimal(head["raw_timestamp"]), decimal(tail["raw_timestamp"])
    check(session_start <= decimal(main[1]["event"]["raw_timestamp"]) <= decimal(main[2]["event"]["raw_timestamp"]) <= session_stop,
          "observer control clock outside activity")
    if not setup:
        check(tid not in (0, U32, caller, worker) and opened != U32 and why != 0, "observer thread identity unavailable")
    if why in (1, 2):
        check(not opened and not error and (count == MAX_VIEWS) == (why == 2), "inconsistent observer termination")
    elif why == 3:
        check(error != 0, "observer error missing")
    else:
        check(setup and opened == U32 and not count and not tid, "unstarted observer has observations")
    views = []
    signaled = False
    previous_stop = None
    for i in range(count):
        start, stop = extra[1+2*i:3+2*i]
        check(tid not in (0, U32, caller, worker) and start["event"]["header_thread_id"] == stop["event"]["header_thread_id"] == tid and
              (start["event"]["event_id"], stop["event"]["event_id"]) == (18, 19) and start["handoff_payload"] is None,
              "wait-chain markers have different owners")
        observation = view(start, stop, i+1, join, pid, caller, worker)
        query_begin, query_end = int(observation["begin_qpc"]), int(observation["end_qpc"])
        event_start, event_stop = decimal(start["event"]["raw_timestamp"]), decimal(stop["event"]["raw_timestamp"])
        check(session_start <= event_start+1 and event_stop <= session_stop+1, "query clock outside observer session")
        check(previous_stop is None or previous_stop <= event_start, "overlapping markers from the same observer")
        previous_stop = event_stop
        for status, earliest, latest in ((observation["worker_before"], event_start, query_begin),
                                         (observation["worker_after"], query_end, event_stop)):
            if status == 0:
                check(signal[0] <= latest+1, "signaled handle before worker completion")
                signaled = True
            elif status == 258:
                check(not signaled and earliest <= signal[1]+1, "live handle after worker completion")
        views.append(observation)
    complete = not (setup or opened or error) and all(v["relation"] != "query_unqualified" and U32 not in (v["worker_before"], v["worker_after"]) for v in views)
    return dict(status="observed" if complete else "partial", start_record=head["record_ordinal"], stop_record=tail["record_ordinal"],
                setup_win32=setup, open_win32=opened, observer_win32=error, stop_reason=why, observer_tid=tid, views=views)


def minimum_off_cpu(intervals, switches):
    # Each ordered group of sightings sharing a deschedule covers at least the
    # distance from the end of its first query to the start of its last query.
    n = len(intervals)
    cost = [0] + [None]*n
    for _ in range(min(n, switches)):
        previous = cost
        cost = [0]
        for end in range(1, n+1):
            cost.append(min(previous[start] + max(0, intervals[end-1][0]-intervals[start][1])
                            for start in range(end) if previous[start] is not None))
    return cost[n]


def residency(counter, call, views):
    witnesses = [v for v in views if v["relation"] == "blocked_on_joined_worker"]
    result = dict(status="unavailable", wait_call_ticks=str(call[1]-call[0]), witness_stop_records=[v["stop_record"] for v in witnesses],
                  off_cpu_lower_ticks=None, off_cpu_upper_ticks=None, on_cpu_lower_ticks=None, on_cpu_upper_ticks=None)
    if counter["status"] != "measured":
        return result
    switches = counter["switch_delta"]
    if not switches and witnesses:
        result["status"] = "counter_witness_conflict"
        return result
    # Place each observation on the caller's QPC axis allowing one tick either way.
    intervals = [(int(v["begin_qpc"])-1, int(v["end_qpc"])+1) for v in witnesses]
    lower = minimum_off_cpu(intervals, switches)
    # WCT's count has a separate origin. Compare differences only. Repeated
    # positive counts on the blocked root also constrain the same off-CPU run.
    counts = [v["nodes"][0]["context_switches"] for v in witnesses]
    # Both observed endpoints were already blocked. A difference of D between
    # their counts therefore needs at least D+1 off-CPU intervals in the bracket.
    if any(b < a for a, b in zip(counts, counts[1:])) or (counts and counts[-1]-counts[0] >= switches):
        result["status"] = "counter_witness_conflict"
        return result
    same_count_ticks = 0
    first = 0
    for end in range(1, len(counts)+1):
        if end == len(counts) or counts[end] != counts[first]:
            if counts[first]:
                same_count_ticks += max(0, intervals[end-1][0]-intervals[first][1])
            first = end
    lower = max(lower, same_count_ticks)
    duration = call[1]-call[0]
    upper = duration if switches else 0
    check(0 <= lower <= upper, "dispatch bounds exceed the wait call")
    result.update(status="bounded", off_cpu_lower_ticks=str(lower), off_cpu_upper_ticks=str(upper),
                  on_cpu_lower_ticks=str(duration-upper), on_cpu_upper_ticks=str(duration-lower))
    return result


def assessed(fn, *args):
    try:
        return fn(*args)
    except (ValueError, TypeError, KeyError, IndexError, struct.error):
        return dict(status="invalid_evidence")


def scheduling(main, extra, spans, join, timer, signal, pid, caller, worker):
    join_profile = assessed(profile, main[10], join, spans[13][1], spans[9][0])
    timer_profile = assessed(profile, main[8], timer, spans[6][1], spans[7][0])
    queries = assessed(observer, extra, main, join, signal, pid, caller, worker)
    caller_residency = residency(join_profile, join, queries.get("views", []))
    worker_residency = residency(timer_profile, timer, [])
    complete = queries["status"] == "observed" and all(r["status"] == "bounded" for r in (caller_residency, worker_residency))
    return dict(status="measured" if complete else "partial", caller_join=join_profile, worker_timer=timer_profile, observer=queries,
                caller_residency=caller_residency, worker_residency=worker_residency,
                counter_assumption="no_unobserved_full_32bit_turn_during_bracket", scheduler_timeline=None)
