"""Bound the pending one-shot timer on the owned caller-to-worker join path."""

from owned_module_benchmark import check, uint


MAX_PROBES = 40


def phase_bounds(arrival, arm, signal, worker):
    # Use the causal order set <= timer signal <= worker exit to tighten feasible endpoints.
    set_lo, set_hi = arm
    exit_lo, exit_hi = worker
    signal_lo, signal_hi = max(signal[0], set_lo), min(signal[1], exit_hi)
    check(set_lo <= set_hi and signal_lo <= signal_hi and exit_lo <= exit_hi, "inconsistent_timer_bounds")
    set_hi, exit_lo = min(set_hi, signal_hi), max(exit_lo, signal_lo)

    def interval(lo, hi):
        return dict(lower=str(max(0, lo)), upper=str(max(0, hi)))

    return dict(timer_set_earliest_qpc=str(set_lo), timer_set_latest_qpc=str(set_hi),
                timer_signal_earliest_qpc=str(signal_lo), timer_signal_latest_qpc=str(signal_hi),
                before_timer_set_ticks=interval(set_lo-arrival, set_hi-arrival),
                timer_pending_ticks=interval(signal_lo-max(arrival, set_hi), signal_hi-max(arrival, set_lo)),
                after_timer_signal_ticks=interval(exit_lo-max(arrival, signal_hi), exit_hi-max(arrival, signal_lo)))


def timer_path(events, truth, main, timer_marker_end, timer_call, path):
    try:
        observer = uint(truth["timer_observer_tid"], 0xfffffffe)
        count = uint(truth["timer_probe_count"], MAX_PROBES)
        check(observer and observer not in (truth["caller_tid"], truth["joined_tid"]) and 2 <= count, "invalid_timer_observer")
        arms, samples = [], []
        for event in events:
            eid = event["event_id"]
            is_arm = eid in (22, 23)
            check(tuple(uint(event[k]) for k in ("version", "task", "opcode", "header_thread_id")) ==
                  (1, 10 if is_arm else 11, 1 if eid in (22, 24) else 2, truth["joined_tid"] if is_arm else observer),
                  "timer_descriptor_mismatch")
            (arms if is_arm else samples).append(event)
        check([e["event_id"] for e in arms] == [22, 23] and len(samples) == 2*count, "incomplete_timer_markers")
        arm_begin, arm_end = [int(e["raw_timestamp"]) for e in arms]
        check(main[7]["event"]["record_ordinal"] < arms[0]["record_ordinal"] < arms[1]["record_ordinal"] < main[8]["event"]["record_ordinal"] and
              timer_marker_end <= arm_begin <= arm_end <= timer_call[0], "timer_set_outside_worker_phase")
        probes = []
        previous = 0
        for i in range(count):
            start, stop = samples[2*i:2*i+2]
            last = i+1 == count
            check((start["event_id"], stop["event_id"]) == (24, 26 if last else 25), "invalid_timer_probe_sequence")
            begin, end = int(start["raw_timestamp"]), int(stop["raw_timestamp"])
            check(previous <= begin <= end, "timer_probe_order_mismatch")
            previous = end
            probes.append(dict(start_record=start["record_ordinal"], result_record=stop["record_ordinal"],
                               wait_result=0 if last else 258, marker_start_qpc=str(begin), marker_stop_qpc=str(end)))
        # Startup gates the worker on the first completed timeout. The observer can return late after a successful probe.
        activity = int(main[1]["event"]["raw_timestamp"])
        check(int(probes[0]["marker_stop_qpc"]) <= activity+1, "initial_timer_probe_outside_setup")
        # A timeout can be followed by a signal before its Stop marker. A successful wait only bounds the signal from above.
        arrival = int(path["caller_arrival_qpc"])
        signal = (int(probes[-2]["marker_start_qpc"])-1, min(int(probes[-1]["marker_stop_qpc"]), timer_call[1])+1)
        worker = (int(path["worker_signal_earliest_qpc"]), int(path["worker_signal_latest_qpc"]))
        phases = phase_bounds(arrival, (max(activity, arm_begin-1), arm_end+1), signal, worker)
        return dict(status="bounded", timer_observer_tid=observer, timer_set_start_record=arms[0]["record_ordinal"],
                    timer_set_stop_record=arms[1]["record_ordinal"], probes=probes, **phases)
    except (KeyError, TypeError, ValueError) as exc:
        return dict(status="unqualified", reason=str(exc))
