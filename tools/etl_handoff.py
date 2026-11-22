"""Evidence and paired timing for the owned caller/worker ETW workload."""
from collections import Counter
from fractions import Fraction
import hashlib
from pathlib import Path
import runpy
from uuid import UUID, uuid5

from owned_module_benchmark import check, decimal, encoded, fields, uint
from saved_etl_comparison import digest


DECODE = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))["decode_document"]
PROVIDER = "4dc673b7-fb3f-4099-952a-37dac27cf194"
METRICS = ("activity", "caller_work", "worker_span", "join_call", "timer_call", "join_timer_overlap", "work_window_overlap")
MATCHED_IMAGE = dict(status="matched", win32_status=0)
UINT32 = (1 << 32) - 1
MAX_QPC = (1 << 63) - 1
MAX_PAIRS = 16


def guid(value):
    check(type(value) is str and len(value) == 36 and str(UUID(value)) == value and UUID(value).int != 0, "invalid GUID")
    return value


def plan(study, pairs, steps, baseline_ms, candidate_ms, timeout_ms, recorder_pin, reader_pin):
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
    return dict(schema="kn.etl_handoff_plan.v1", study_id=study, pairs=pairs, steps=steps, baseline_ms=baseline_ms,
                candidate_ms=candidate_ms, timeout_ms=timeout_ms, recorder_sha256=digest(recorder_pin),
                reader_sha256=digest(reader_pin), slots=slots)


def registered(value):
    keys = "study_id pairs steps baseline_ms candidate_ms timeout_ms recorder_sha256 reader_sha256".split()
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


def measure(cfg, slot, activity, truth, process, page, source_hash, size):
    require(truth["schema"] == "kn.owned_etl_handoff.v1" and truth["provider_id"] == PROVIDER and
            guid(truth["session_id"]) != activity and truth["activity_id"] == activity, "workload_identity_mismatch")
    require((uint(truth["seed"], UINT32), uint(truth["steps"]), uint(truth["delay_ms"])) ==
            (slot["seed"], cfg["steps"], slot["delay_ms"]) and
            uint(truth["caller_result"], UINT32) == checksum(slot["seed"], cfg["steps"]) and
            uint(truth["worker_result"], UINT32) == checksum(slot["seed"] ^ 0x9e3779b9, cfg["steps"]), "workload_mismatch")
    pid, caller, worker = (uint(truth[k], UINT32-1) for k in ("pid", "caller_tid", "joined_tid"))
    require(pid and caller and worker and caller != worker and type(process) is dict and uint(process["pid"]) == pid and
            process["process_created"] == truth["process_created"] and
            0 < decimal(truth["process_created"]) <= decimal(truth["worker_created"]) <= decimal(truth["worker_exited"]),
            "process_or_worker_generation_unqualified")
    require(page["schema"] == "kn.etl_activity_markers.v1" and page["source_sha256"] == source_hash and
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
            len(writes) == len(rows) == uint(page["matched_markers"]) == uint(page["decoded_activity_markers"]) == 10 and
            uint(page["excluded_start_stop_records"]) == 0, "incomplete_marker_set")
    spans = list(map(bracket, writes))
    ticks, ordinals, loggers = {}, {}, set()
    previous = 0
    for i, row in enumerate(rows, 1):
        event = row["event"]
        eid, index = uint(event["event_id"], 10), uint(event["record_ordinal"], uint(page["records_seen"], 2_000_000))
        require(0 < eid and eid not in ticks and uint(row["marker_ordinal"]) == i and previous < index and
                event["provider_guid"] == PROVIDER and event["activity_id"] == activity and
                uint(event["header_flags"], 65535) & 2 and not uint(event["header_flags"], 65535) & (4 | 8 | 128 | 256) and
                not uint(event["event_property"], 65535) & 7 and
                uint(event["header_process_id"]) == pid and uint(event["header_thread_id"]) == (worker if 5 <= eid <= 8 else caller) and
                (uint(event["version"]), uint(event["channel"]), uint(event["task"]), uint(event["opcode"])) ==
                (1, 0, 1 + (eid-1)//2, 1 + (eid-1)%2), "marker_identity_mismatch")
        previous = index
        tick = qpc(event["raw_timestamp"])
        lo, hi = spans[eid-1]
        require(lo <= tick <= hi, "marker_outside_producer_write")
        loggers.add(uint(event["logger_id"], 65535))
        ticks[eid], ordinals[eid] = tick, index
    require(len(loggers) == 1, "logger_mismatch")
    for order in ((1, 3, 4, 9, 10, 2), (1, 5, 7, 8, 6, 10, 2)):
        for left, right in zip(order, order[1:]):
            require(ordinals[left] < ordinals[right] and spans[left-1][1] <= spans[right-1][0], "dependency_order_mismatch")
    join, timer = bracket(truth["join_call"]), bracket(truth["timer_call"])
    require(spans[8][1] <= join[0] <= join[1] <= spans[9][0] and
            spans[6][1] <= timer[0] <= timer[1] <= spans[7][0] and spans[5][1] <= join[1],
            "wait_outside_recorded_dependency")
    values = dict(activity=ticks[2]-ticks[1], caller_work=ticks[4]-ticks[3], worker_span=ticks[6]-ticks[5],
                  join_call=join[1]-join[0], timer_call=timer[1]-timer[0], join_timer_overlap=overlap(join, timer),
                  work_window_overlap=overlap((ticks[3], ticks[4]), (ticks[5], ticks[7])))
    return dict(frequency=str(hz), ticks={k: str(v) for k, v in values.items()})


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


def summarize(cfg, plan_pin, package_pin, acquisition, environment, observations):
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
    deltas = {name: [] for name in METRICS}
    orders = {role: {name: [] for name in METRICS} for role in ("baseline", "candidate")}
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
            for key in METRICS:
                delta = nanoseconds(arms["candidate"], key) - nanoseconds(arms["baseline"], key)
                deltas[key].append(delta)
                orders[first_role][key].append(delta)
                change[key] = rational(delta)
            item["candidate_minus_baseline_ns"] = change
        pairs.append(item)
    measured = len(deltas["activity"])
    return dict(schema="kn.etl_handoff_study.v1", status="complete" if measured == len(pairs) else "partial",
                plan_sha256=plan_pin, package_sha256=package_pin, acquisition_id=acquisition, acquisition_environment=environment,
                plan=cfg, planned_pairs=len(pairs), measured_pairs=measured,
                unavailable_pairs=len(pairs)-measured, observations=observations, pairs=pairs,
                changes={name: distribution(values) for name, values in deltas.items()},
                by_first_arm={role: dict(planned_pairs=planned_order[role], measured_pairs=len(group["activity"]),
                                         changes={name: distribution(values) for name, values in group.items()})
                              for role, group in orders.items()},
                qualification=dict(workload="owned_fixed_work_with_worker_timer", wait_dependency="joined_worker_handle",
                                   scheduler_residency=None, product_regression=None, producer_authenticity="unverified"))
