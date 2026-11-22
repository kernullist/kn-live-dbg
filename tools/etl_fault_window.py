"""Validate original hard-fault intervals inside a qualified ETW activity window."""
from etl_activity_waits import MAX_RECORDS, tick as boundary_tick
from owned_module_benchmark import check, decimal, uint

MAX_TICK = (1 << 63) - 1


def positive_tick(value):
    tick = decimal(value)
    check(0 < tick <= MAX_TICK, "expected a positive signed QPC value")
    return tick


def fault_union(page, window, start_tick, stop_tick):
    edges, faults = window["overlaps"], page["hard_faults"]
    check(uint(window["fault_limit"]) == 128 and type(edges) is list and type(faults) is list and
          len(edges) == len(faults) == uint(window["candidate_faults"], 128), "incomplete overlap witnesses")
    recorded = uint(page["decoded_hard_faults"], page["records_seen"])
    logger_faults = uint(window["decoded_faults_on_start_logger"], recorded)
    check(logger_faults > 0 and len(edges) <= logger_faults and
          all(uint(window[k]) == 0 for k in ("untimed_thread_faults", "unassigned_possible_faults",
                                             "other_logger_thread_faults", "faults_outside_thread_bracket")),
          "unqualified fault coverage")
    spans = []
    bracket = window["thread_evidence"]
    first, last = bracket["before"], bracket["after"]
    thread_start, thread_stop = boundary_tick(first["raw_timestamp"]), boundary_tick(last["raw_timestamp"])
    previous_record, previous_fault = first["record_ordinal"], 0
    for edge, fault in zip(edges, faults, strict=True):
        ordinal = uint(edge["record_ordinal"], MAX_RECORDS)
        fault_ordinal = uint(edge["fault_ordinal"], recorded)
        check(previous_record < ordinal == uint(fault["record_ordinal"]) < last["record_ordinal"] and
              previous_fault < fault_ordinal == uint(fault["fault_ordinal"]) and
              uint(fault["faulting_thread_id"]) == window["start"]["header_thread_id"] and
              uint(fault["logger_id"]) == window["start"]["logger_id"], "fault witness identity mismatch")
        previous_record, previous_fault = ordinal, fault_ordinal
        begin, end = positive_tick(fault["initial_time_raw"]), positive_tick(fault["raw_timestamp"])
        check(thread_start < begin < end < thread_stop, "fault outside thread bracket")
        lo, hi = max(start_tick, begin), min(stop_tick, end)
        check(lo < hi and (lo, hi, hi - lo) == tuple(decimal(edge[k]) for k in
              ("overlap_start_raw", "overlap_end_raw", "overlap_ticks")), "fault intersection mismatch")
        spans.append((lo, hi))
    cursor, total = start_tick, 0
    for lo, hi in sorted(spans):
        total += max(0, hi - max(cursor, lo))
        cursor = max(cursor, hi)
    check(total == decimal(window["fault_union_ticks"]), "fault union differs from original witnesses")
    return total
