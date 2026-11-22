"""Evidence and paired timing for the owned caller/worker ETW workload."""
from collections import Counter
from fractions import Fraction
import hashlib
from pathlib import Path
import runpy
from statistics import median
from uuid import UUID, uuid5

from etl_handoff_scheduling import MAX_VIEWS, scheduling
from etl_handoff_timer import MAX_PROBES, timer_path
from owned_module_benchmark import check, decimal, encoded, fields, uint
from saved_etl_comparison import digest


DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]
PROVIDER = "4dc673b7-fb3f-4099-952a-37dac27cf194"
METRICS = ("activity", "caller_work", "worker_span", "join_call", "timer_call", "join_timer_overlap", "work_window_overlap")
MATCHED_IMAGE = dict(status="matched", win32_status=0)
UINT32 = (1 << 32) - 1
MAX_QPC = (1 << 63) - 1
MAX_PAIRS = 16
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258


def guid(value):
    check(type(value) is str and len(value) == 36 and str(UUID(value)) == value and UUID(value).int != 0, "invalid GUID")
    return value


def plan(study, pairs, steps, baseline_ms, candidate_ms, timeout_ms, recorder_pin, reader_pin, caller_delay_ms=None, observe_scheduling=False, observe_timer=False):
    namespace = UUID(guid(study))
    check(2 <= uint(pairs, MAX_PAIRS) and 1 <= uint(steps, 1_000_000) and 1 <= uint(timeout_ms, 120_000), "invalid study bounds")
    delays = {"baseline": uint(baseline_ms, 1000), "candidate": uint(candidate_ms, 1000)}
    slots = []
    for pair in range(1, pairs + 1):
        seed = int.from_bytes(hashlib.sha256(namespace.bytes + bytes([pair])).digest()[:4], "little")
        order = ("baseline", "candidate") if (namespace.int + pair) % 2 else ("candidate", "baseline")
        for role in order:
            slots.append(dict(slot=len(slots) + 1, pair=pair, role=role, seed=seed, delay_ms=delays[role],
                              ticket=str(uuid5(namespace, f"{pair}/{role}"))))
    result = dict(schema="kn.etl_handoff_plan.v1", study_id=study, pairs=pairs, steps=steps, baseline_ms=baseline_ms,
                  candidate_ms=candidate_ms, timeout_ms=timeout_ms, recorder_sha256=digest(recorder_pin),
                  reader_sha256=digest(reader_pin), slots=slots)
    check(type(observe_scheduling) is bool, "invalid scheduling selection")
    check(type(observe_timer) is bool, "invalid timer observation selection")
    if caller_delay_ms is not None or observe_scheduling or observe_timer:
        result.update(schema="kn.etl_handoff_plan.v2", caller_delay_ms=0 if caller_delay_ms is None else uint(caller_delay_ms, 1000))
    if observe_scheduling:
        result.update(schema="kn.etl_handoff_plan.v3", observe_scheduling=True)
    if observe_timer:
        result.update(schema="kn.etl_handoff_plan.v4", observe_scheduling=observe_scheduling, observe_timer=True)
    return result


def registered(value):
    keys = "study_id pairs steps baseline_ms candidate_ms timeout_ms recorder_sha256 reader_sha256".split()
    if type(value) is dict and value.get("schema") in ("kn.etl_handoff_plan.v2", "kn.etl_handoff_plan.v3", "kn.etl_handoff_plan.v4"):
        keys.append("caller_delay_ms")
        if value["schema"] in ("kn.etl_handoff_plan.v3", "kn.etl_handoff_plan.v4"):
            keys.append("observe_scheduling")
        if value["schema"] == "kn.etl_handoff_plan.v4":
            keys.append("observe_timer")
    fields(value, "schema slots " + " ".join(keys), "handoff plan")
    expected = plan(*(value[k] for k in keys))
    check(encoded(value) == encoded(expected), "plan differs from its registered workloads and arm order")
    return expected


def activity_id(acquisition, plan_pin, slot):
    return str(uuid5(UUID(acquisition), plan_pin + "/" + slot["ticket"]))


def checksum(seed, steps):
    # Compose the 32-bit affine transform by squaring, independently of the fixture's iteration loop.
    mul, add = 1664525, 1013904223
    while steps:
        if steps & 1:
            seed = (mul * seed + add) & UINT32
        mul, add = mul * mul & UINT32, (mul + 1) * add & UINT32
        steps >>= 1
    return seed


class Unqualified(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Unqualified(reason)


def qpc(value):
    number = decimal(value)
    require(0 < number <= MAX_QPC, "clock_unqualified")
    return number


def bracket(values):
    require(type(values) is list and len(values) == 2, "invalid_call_bracket")
    lo, hi = map(qpc, values)
    require(lo <= hi, "inverted_call_bracket")
    return lo, hi


def overlap(a, b):
    return max(0, min(a[1], b[1]) - max(a[0], b[0]))


def bound_join(ticks, ordinals, worker_write_end, join, timer, probes):
    arrival = ticks[9]
    join_start, join_return = join
    # Windows documents one ambiguous QPC tick when comparing different threads.
    earliest, latest = max(ticks[1], worker_write_end - 1), join_return
    seen_signaled = False
    for probe in probes:
        if probe["wait_result"] == WAIT_OBJECT_0:
            seen_signaled = True
            latest = min(latest, int(probe["call_end_qpc"]))
        else:
            require(not seen_signaled, "thread_signal_reversed")
            earliest = max(earliest, int(probe["call_start_qpc"]))
    require(earliest <= latest, "inconsistent_thread_signal_bounds")
    if latest < arrival or (probes and probes[0]["wait_result"] == WAIT_OBJECT_0):
        last = "caller"
    elif earliest > arrival or (probes and probes[1]["wait_result"] == WAIT_TIMEOUT):
        last = "worker"
    else:
        last = "unresolved"

    def partition(signal):
        ready = max(arrival, signal)
        return dict(start_to_caller_ticks=str(arrival - ticks[1]), exposed_worker_ticks=str(ready - arrival),
                    join_return_delay_ticks=str(join_return - ready), return_to_stop_ticks=str(ticks[2] - join_return))

    duration = timer[1] - timer[0]
    timer_low = min(duration, max(0, timer[1] - 1 - arrival))
    timer_high = min(duration, max(0, timer[1] + 1 - arrival), max(0, latest - arrival))
    require(timer_low <= timer_high and timer_low <= max(0, earliest - arrival), "timer_outside_worker_path")
    return dict(activity_start_record=ordinals[1], activity_stop_record=ordinals[2], caller_arrival_record=ordinals[9],
                worker_stop_record=ordinals[6], join_stop_record=ordinals[10], caller_arrival_qpc=str(arrival),
                worker_signal_earliest_qpc=str(earliest), worker_signal_latest_qpc=str(latest),
                join_call_start_qpc=str(join_start), join_return_qpc=str(join_return),
                probes=probes, last_prerequisite=last, at_earliest_signal=partition(earliest),
                at_latest_signal=partition(latest), worker_timer_after_arrival_ticks=dict(lower=str(timer_low), upper=str(timer_high)),
                worker_after_join_call_start_ticks=dict(lower=str(max(0, earliest-join_start)), upper=str(max(0, latest-join_start))))


def measure(cfg, slot, activity, truth, process, page, source_hash, size, join_path=False):
    probed = "caller_delay_ms" in cfg
    scheduled = cfg.get("observe_scheduling", False)
    observed_timer = cfg.get("observe_timer", False)
    count = 14 if probed else 10
    expected_schema = "kn.owned_etl_handoff.v3" if scheduled else "kn.owned_etl_handoff.v2" if probed else "kn.owned_etl_handoff.v1"
    require(truth["schema"] == ("kn.owned_etl_handoff.v4" if observed_timer else expected_schema) and truth["provider_id"] == PROVIDER and
            guid(truth["session_id"]) != activity and truth["activity_id"] == activity, "workload_identity_mismatch")
    if probed:
        require(uint(truth["caller_delay_ms"], 1000) == cfg["caller_delay_ms"], "workload_mismatch")
    require((uint(truth["seed"], UINT32), uint(truth["steps"]), uint(truth["delay_ms"])) ==
            (slot["seed"], cfg["steps"], slot["delay_ms"]) and
            uint(truth["caller_result"], UINT32) == checksum(slot["seed"], cfg["steps"]) and
            uint(truth["worker_result"], UINT32) == checksum(slot["seed"] ^ 0x9e3779b9, cfg["steps"]), "workload_mismatch")
    pid, caller, worker = (uint(truth[k], UINT32-1) for k in ("pid", "caller_tid", "joined_tid"))
    require(pid and caller and worker and caller != worker and type(process) is dict and uint(process["pid"]) == pid and
            process["process_created"] == truth["process_created"] and
            0 < decimal(truth["process_created"]) <= decimal(truth["worker_created"]) <= decimal(truth["worker_exited"]),
            "process_or_worker_generation_unqualified")
    marker_schema = "kn.etl_handoff_markers.v1" if scheduled else "kn.etl_activity_markers.v1"
    require(page["schema"] == marker_schema and (not scheduled or uint(page["handoff_payload_limit"]) == 1024) and page["source_sha256"] == source_hash and
            uint(page["source_bytes"]) == size and page["header_scope"] == "keyed_nonclassic_start_stop" and
            page["thread_filter"] is None and uint(page["after"]) == 0 and page["next_after"] is None, "marker_query_mismatch")
    header = page["log_header"]
    require(page["status"] == "read" and page["buffer_comparison"] == "matched" and
            0 < uint(header["buffers_written"]) == uint(page["buffers_processed"]) == uint(truth["buffers_written"]) and
            all(uint(v) == 0 for v in (header["events_lost"], header["buffers_lost"], page["loss_marker_records"],
                                       truth["events_lost"], truth["log_buffers_lost"], truth["system_trace_enable_flags"])) and
            uint(header["log_mode"]) & 0x20801 == 0x20801, "private_capture_coverage_unqualified")
    hz = qpc(truth["frequency"])
    require(uint(page["clock"]["raw_type"]) == 1 and page["clock"]["kind"] == "qpc" and
            qpc(page["clock"]["header_perf_frequency"]) == hz, "clock_unqualified")
    rows, writes = page["markers"], truth["write_brackets"]
    require(type(rows) is list and type(writes) is list and
            len(writes) == count and count <= len(rows) <= count + (2 + 2*MAX_VIEWS if scheduled else 0) + (2 + 2*MAX_PROBES if observed_timer else 0) and
            len(rows) == uint(page["matched_markers"]) == uint(page["decoded_activity_markers"]) and
            uint(page["excluded_start_stop_records"]) == 0, "incomplete_marker_set")
    spans = list(map(bracket, writes))
    ticks, ordinals, descriptors, loggers = {}, {}, {}, set()
    main_rows, observer_rows, timer_rows = {}, [], []
    previous = 0
    for i, row in enumerate(rows, 1):
        event = row["event"]
        descriptor = uint(event["event_id"], 26 if observed_timer else 21 if scheduled else 17 if probed else 10)
        index = uint(event["record_ordinal"], uint(page["records_seen"], 2_000_000))
        require(uint(row["marker_ordinal"]) == i and previous < index and
                event["provider_guid"] == PROVIDER and event["activity_id"] == activity and
                uint(event["header_flags"], 65535) & 2 and not uint(event["header_flags"], 65535) & (4 | 8 | 128 | 256) and
                not uint(event["event_property"], 65535) & 7 and
                uint(event["header_process_id"]) == pid and uint(event["channel"]) == 0, "marker_identity_mismatch")
        previous = index
        tick = qpc(event["raw_timestamp"])
        loggers.add(uint(event["logger_id"], 65535))
        if observed_timer and descriptor >= 22:
            timer_rows.append(event)
            continue
        if scheduled and 18 <= descriptor <= 21:
            require((uint(event["version"]), uint(event["task"]), uint(event["opcode"])) ==
                    (2, 8+(descriptor-18)//2, 1+(descriptor-18)%2), "observer_descriptor_mismatch")
            observer_rows.append(row)
            continue
        eid = {16: 12, 17: 14}.get(descriptor, descriptor)
        require(0 < eid <= count and eid not in ticks and uint(event["header_thread_id"]) == (worker if 5 <= eid <= 8 else caller) and
                (uint(event["version"]), uint(event["task"]), uint(event["opcode"])) ==
                (2 if scheduled and eid in (8, 10) else 1, 1 + (eid-1)//2, 1 + (eid-1)%2), "marker_identity_mismatch")
        lo, hi = spans[eid-1]
        require(lo <= tick <= hi, "marker_outside_producer_write")
        ticks[eid], ordinals[eid], descriptors[eid] = tick, index, descriptor
        main_rows[eid] = row
    require(len(ticks) == count, "incomplete_marker_set")
    require(len(loggers) == 1, "logger_mismatch")
    caller_order = (1, 3, 4, 11, 12, 9, 13, 14, 10, 2) if probed else (1, 3, 4, 9, 10, 2)
    for order in (caller_order, (1, 5, 7, 8, 6, 10, 2)):
        for left, right in zip(order, order[1:]):
            require(ordinals[left] < ordinals[right] and spans[left-1][1] <= spans[right-1][0], "dependency_order_mismatch")
    join, timer = bracket(truth["join_call"]), bracket(truth["timer_call"])
    require(spans[8][1] <= join[0] <= join[1] <= spans[9][0] and
            spans[6][1] <= timer[0] <= timer[1] <= spans[7][0] and spans[5][1] <= join[1],
            "wait_outside_recorded_dependency")
    values = dict(activity=ticks[2]-ticks[1], caller_work=ticks[4]-ticks[3], worker_span=ticks[6]-ticks[5],
                  join_call=join[1]-join[0], timer_call=timer[1]-timer[0], join_timer_overlap=overlap(join, timer),
                  work_window_overlap=overlap((ticks[3], ticks[4]), (ticks[5], ticks[7])))
    measurement = dict(frequency=str(hz), ticks={k: str(v) for k, v in values.items()})
    if probed or join_path:
        probes = []
        if probed:
            pause_ticks = 0
            if cfg["caller_delay_ms"]:
                pause = bracket(truth["caller_delay_call"])
                require(spans[3][1] <= pause[0] <= pause[1] <= spans[10][0], "caller_delay_outside_markers")
                pause_ticks = pause[1] - pause[0]
            else:
                require(truth["caller_delay_call"] is None, "unexpected_caller_delay")
            measurement["ticks"]["caller_delay_call"] = str(pause_ticks)
            require(type(truth["join_probes"]) is list and len(truth["join_probes"]) == 2 and
                    spans[13][1] <= join[0], "join_probe_order_mismatch")
            for slot_index, probe in enumerate(truth["join_probes"]):
                fields(probe, "wait_result call", "thread handle probe")
                start = 11 + 2 * slot_index
                call = bracket(probe["call"])
                result = uint(probe["wait_result"], UINT32)
                require(spans[start-1][1] <= call[0] <= call[1] <= spans[start][0], "probe_outside_markers")
                signaled = descriptors[start+1] == 16 + slot_index
                require(result == (WAIT_OBJECT_0 if signaled else WAIT_TIMEOUT), "probe_result_disagrees_with_etl")
                probes.append(dict(start_record=ordinals[start], result_record=ordinals[start+1],
                                   wait_result=result, call_start_qpc=str(call[0]), call_end_qpc=str(call[1])))
        measurement["join_path"] = bound_join(ticks, ordinals, spans[5][1], join, timer, probes)
    if scheduled:
        path = measurement["join_path"]
        signal = (int(path["worker_signal_earliest_qpc"]), int(path["worker_signal_latest_qpc"]))
        measurement["scheduling"] = scheduling(main_rows, observer_rows, spans, join, timer, signal, pid, caller, worker)
    if observed_timer:
        measurement["timer_path"] = timer_path(timer_rows, truth, main_rows, spans[6][1], timer, measurement["join_path"])
    return measurement


def rational(value):
    return dict(numerator=str(value.numerator), denominator=str(value.denominator))


def nanoseconds(row, key):
    measure = row["measurement"]
    return Fraction(int(measure["ticks"][key]) * 1_000_000_000, int(measure["frequency"]))


def distribution(values):
    ordered = sorted(values)
    n = len(ordered)
    counts = Counter("longer" if d > 0 else "shorter" if d < 0 else "equal" for d in values)
    return dict(pairs=n, longer=counts["longer"], shorter=counts["shorter"], equal=counts["equal"],
                minimum_ns=rational(ordered[0]) if n else None, maximum_ns=rational(ordered[-1]) if n else None,
                median_ns=rational((ordered[(n-1)//2]+ordered[n//2])/2) if n else None)


def path_ranges(row):
    measurement = row["measurement"]
    path = measurement["join_path"]
    scale = Fraction(1_000_000_000, int(measurement["frequency"]))
    early, late = path["at_earliest_signal"], path["at_latest_signal"]
    ranges = {key.removesuffix("_ticks"): sorted((scale * int(early[key]), scale * int(late[key]))) for key in early}
    for phase in ("worker_timer_after_arrival", "worker_after_join_call_start"):
        interval = path[phase + "_ticks"]
        ranges[phase] = (scale * int(interval["lower"]), scale * int(interval["upper"]))
    return ranges


def bounds(values):
    longer, shorter, equal = sum(lo > 0 for lo, hi in values), sum(hi < 0 for lo, hi in values), values.count((0, 0))
    return dict(pairs=len(values), longer=longer, shorter=shorter, equal=equal, unresolved=len(values)-longer-shorter-equal,
                median_lower_ns=rational(median(lo for lo, hi in values)) if values else None,
                median_upper_ns=rational(median(hi for lo, hi in values)) if values else None)


def summarize_paths(report):
    phases = ("start_to_caller", "exposed_worker", "join_return_delay", "return_to_stop", "worker_timer_after_arrival", "worker_after_join_call_start")
    groups = {group: {phase: [] for phase in phases} for group in ("all", "baseline", "candidate")}
    counts = {role: dict(caller=0, worker=0, unresolved=0, unavailable=0) for role in ("baseline", "candidate")}
    for pair in report["pairs"]:
        index = (pair["pair"] - 1) * 2
        arms = {r["selection"]["role"]: r for r in report["observations"][index:index+2]}
        for role, row in arms.items():
            measure = row["measurement"]
            counts[role][measure["join_path"]["last_prerequisite"] if measure else "unavailable"] += 1
        pair["join_path_change_ns"] = None
        if not pair["measured"]:
            continue
        base, candidate = path_ranges(arms["baseline"]), path_ranges(arms["candidate"])
        changes = {}
        for phase in phases:
            lo, hi = candidate[phase][0] - base[phase][1], candidate[phase][1] - base[phase][0]
            changes[phase] = dict(lower=rational(lo), upper=rational(hi))
            groups["all"][phase].append((lo, hi))
            groups[pair["order"][0]][phase].append((lo, hi))
        pair["join_path_change_ns"] = changes

    summaries = {group: {phase: bounds(values) for phase, values in data.items()} for group, data in groups.items()}
    report.update(schema="kn.etl_handoff_study.v2", join_path_summary=dict(last_prerequisites=counts, changes=summaries["all"],
                  by_first_arm={role: summaries[role] for role in counts}))
    report["qualification"]["join_path"] = "caller_arrival_and_worker_thread_termination"


def paired_phase_bounds(report, phases, pair_field, read_intervals):
    groups = {group: {phase: [] for phase in phases} for group in ("all", "baseline", "candidate")}
    for i, pair in enumerate(report["pairs"]):
        pair[pair_field] = None
        arms = {row["selection"]["role"]: read_intervals(row["measurement"]) if row["measurement"] else None
                for row in report["observations"][2*i:2*i+2]}
        if any(intervals is None for intervals in arms.values()):
            continue
        changes = {}
        for phase in phases:
            base, candidate = arms["baseline"][phase], arms["candidate"][phase]
            lo, hi = candidate[0]-base[1], candidate[1]-base[0]
            changes[phase] = dict(lower=rational(lo), upper=rational(hi))
            for group in ("all", pair["order"][0]):
                groups[group][phase].append((lo, hi))
        pair[pair_field] = changes
    measured = len(groups["all"][phases[0]])
    summaries = {group: {phase: bounds(values) for phase, values in data.items()} for group, data in groups.items()}
    return dict(measured_pairs=measured, unavailable_pairs=report["planned_pairs"]-measured,
                changes=summaries["all"], by_first_arm={k: summaries[k] for k in ("baseline", "candidate")})


def summarize_scheduling(report):
    phases = ("caller_residency", "worker_residency")

    def intervals(measurement):
        evidence = measurement["scheduling"]
        if evidence["status"] != "measured":
            return None
        scale = Fraction(1_000_000_000, int(measurement["frequency"]))
        return {phase: [scale*int(evidence[phase][k]) for k in ("off_cpu_lower_ticks", "off_cpu_upper_ticks")] for phase in phases}

    summary = paired_phase_bounds(report, phases, "off_cpu_change_ns", intervals)
    report.update(schema="kn.etl_handoff_study.v3", timing_status=report["status"],
                  status="partial" if summary["unavailable_pairs"] else "complete", scheduling_summary=summary)
    report["qualification"]["scheduler_residency"] = "wait_call_bounds_from_thread_dispatch_counts_and_wct"


def summarize_timer(report):
    phases = ("before_timer_set", "timer_pending", "after_timer_signal")

    def intervals(measurement):
        evidence = measurement["timer_path"]
        if evidence["status"] != "bounded":
            return None
        scale = Fraction(1_000_000_000, int(measurement["frequency"]))
        return {phase: [scale*int(evidence[phase+"_ticks"][k]) for k in ("lower", "upper")] for phase in phases}

    summary = paired_phase_bounds(report, phases, "timer_path_change_ns", intervals)
    report.setdefault("timing_status", report["status"])
    report["timer_path_summary"] = summary
    report["qualification"]["timer_signal"] = "owned_manual_reset_one_shot_with_independent_handle_probes"
    report["schema"] = "kn.etl_handoff_study.v5"
    if summary["unavailable_pairs"]:
        report["status"] = "partial"


def summarize(cfg, plan_pin, package_pin, acquisition, environment, observations, join_path=False):
    # A reused capture or producer process invalidates all measurements sharing it.
    for identity in ("session_id", "process", "etl_sha256"):
        by_identity = {}
        for row in observations:
            value = row.get(identity)
            if value is not None:
                key = (value["pid"], value["process_created"]) if identity == "process" else value
                by_identity.setdefault(key, []).append(row)
        for shared in by_identity.values():
            if len(shared) > 1:
                for row in shared:
                    row.update(status="unqualified", reason="reused_" + identity, measurement=None)
    metrics = (*METRICS, "caller_delay_call") if "caller_delay_ms" in cfg else METRICS
    deltas = {name: [] for name in metrics}
    orders = {role: {name: [] for name in metrics} for role in ("baseline", "candidate")}
    planned_order = Counter()
    pairs = []
    for index in range(cfg["pairs"]):
        first, second = observations[2*index:2*index+2]
        arms = {r["selection"]["role"]: r for r in (first, second)}
        first_role = first["selection"]["role"]
        planned_order[first_role] += 1
        item = dict(pair=index+1, order=[first["selection"]["role"], second["selection"]["role"]],
                    measured=all(r["measurement"] is not None for r in arms.values()), candidate_minus_baseline_ns=None)
        if item["measured"]:
            change = {}
            for key in metrics:
                delta = nanoseconds(arms["candidate"], key) - nanoseconds(arms["baseline"], key)
                deltas[key].append(delta)
                orders[first_role][key].append(delta)
                change[key] = rational(delta)
            item["candidate_minus_baseline_ns"] = change
        pairs.append(item)
    measured = len(deltas["activity"])
    report = dict(schema="kn.etl_handoff_study.v1", status="complete" if measured == len(pairs) else "partial",
                plan_sha256=plan_pin, package_sha256=package_pin, acquisition_id=acquisition, acquisition_environment=environment,
                plan=cfg, planned_pairs=len(pairs), measured_pairs=measured,
                unavailable_pairs=len(pairs)-measured, observations=observations, pairs=pairs,
                changes={name: distribution(values) for name, values in deltas.items()},
                by_first_arm={role: dict(planned_pairs=planned_order[role], measured_pairs=len(group["activity"]),
                                         changes={name: distribution(values) for name, values in group.items()})
                              for role, group in orders.items()},
                qualification=dict(workload="owned_fixed_work_with_worker_timer", wait_dependency="joined_worker_handle",
                                   scheduler_residency=None, product_regression=None, producer_authenticity="unverified"))
    if "caller_delay_ms" in cfg or join_path:
        summarize_paths(report)
    if cfg.get("observe_scheduling"):
        summarize_scheduling(report)
    if cfg.get("observe_timer"):
        summarize_timer(report)
    return report
