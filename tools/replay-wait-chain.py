"""Replay a pinned Windows WCT capture or paired traversal series after the target exits."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


DWORD = (1 << 32) - 1
U64 = (1 << 64) - 1
LIMIT = 16  # WCT_MAX_NODE_COUNT
THREAD, BLOCKED, OWNED = 8, 3, 6
LOCKS = {1: "critical_section", 3: "mutex"}
PARTIAL = {234, 565}  # ERROR_MORE_DATA, ERROR_TOO_MANY_THREADS
WAIT_TIMEOUT, WAIT_FAILED = 258, DWORD


def check(ok, reason):
    if not ok:
        raise ValueError(reason)


def fields(row, names):
    check(type(row) is dict and row.keys() == set(names.split()), "unexpected capture fields")


def uint(n, limit=DWORD):
    check(type(n) is int and 0 <= n <= limit, "invalid unsigned integer")
    return n


def creation(value):
    check(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), "invalid FILETIME")
    return uint(int(value), U64)


def check_result(ok, error):
    check(type(ok) is bool, "invalid native success flag")
    if ok:
        check(error is None, "successful call has an error")
    else:
        uint(error)


def pin(p):
    fields(p, "requested id pid created failure error initial before after")
    for k in ("requested", "id", "pid"):
        uint(p[k])
    check(p["requested"] != 0, "missing requested handle identity")
    created = creation(p["created"])
    failure = p["failure"]
    check(failure in (None, "open", "id", "owner", "times"), "unknown binding stage")
    check_result(failure is None, p["error"])
    signals = [p[k] for k in ("initial", "before", "after")]
    if failure is not None:
        check(not created and not any(s is not None for s in signals) and
              bool(p["id"]) == (failure in ("owner", "times")) and bool(p["pid"]) == (failure == "times"),
              "failed binding supplies an incompatible identity or signal")
        return
    check(p["id"] and p["pid"], "missing handle identity")
    last, exited = 0, False
    for s in signals:
        fields(s, "result error tick")
        tick = uint(s["tick"], U64)
        result = uint(s["result"])
        check(result in (0, WAIT_TIMEOUT, WAIT_FAILED) and last <= tick, "invalid process or thread wait")
        check_result(result != WAIT_FAILED, s["error"])
        check(not exited or result != WAIT_TIMEOUT, "terminated handle became live")
        exited |= result == 0
        last = tick


def bound(p, pid, expected, edge):
    s = p[edge]
    return (p["failure"] is None and p["pid"] == pid and p["id"] == p["requested"] and
            p["created"] == expected and expected != "0" and s["result"] == WAIT_TIMEOUT)


def query(q):
    fields(q, "start end ok error reported cycle nodes")
    check(uint(q["start"], U64) <= uint(q["end"], U64), "reversed traversal")
    check_result(q["ok"], q["error"])
    check(type(q["cycle"]) is bool if q["ok"] else q["cycle"] is None, "cycle flag without successful traversal")
    count = uint(q["reported"])
    check(not q["ok"] or count <= LIMIT, "successful traversal exceeds its buffer")
    expected = min(count, LIMIT) if q["ok"] or q["error"] in PARTIAL else 0
    check(type(q["nodes"]) is list and len(q["nodes"]) == expected, "native node count mismatch")
    for n in q["nodes"]:
        check(type(n) is dict, "invalid result node")
        fields(n, "type status pid tid wait_time context_switches" if n.get("type") == THREAD else "type status")
        for value in n.values():
            uint(value)


def validate(c):
    fields(c, "schema source clock flags node_limit requested process threads session discovery query")
    check(c["schema"] == "kn.wait_chain.v1" and c["source"] == "windows_wct" and c["clock"] == "GetTickCount64_ms" and
          uint(c["flags"]) == 0 and uint(c["node_limit"]) == LIMIT, "unknown WCT capture contract")
    r, process, threads = c["requested"], c["process"], c["threads"]
    fields(r, "pid process_created tid thread_created")
    pid, tid = uint(r["pid"]), uint(r["tid"])
    check(pid and tid and creation(r["process_created"]) and creation(r["thread_created"]), "unbound request")
    pin(process)
    check(process["requested"] == pid and type(threads) is list and len(threads) <= LIMIT + 1, "invalid pin roster")
    for t in threads:
        pin(t)
    admitted = bound(process, pid, r["process_created"], "initial")
    check(bool(threads) == admitted and (not threads or threads[0]["requested"] == tid), "root differs from admission")
    root = threads[0] if threads else None
    session, discovery, final = c["session"], c["discovery"], c["query"]
    check((session is not None) == bool(root and bound(root, pid, r["thread_created"], "initial")), "session admission mismatch")
    if session is not None:
        fields(session, "ok error")
        check_result(session["ok"], session["error"])
    check((discovery is not None) == bool(session and session["ok"]), "missing or unsolicited discovery")
    expected_ids = [tid] if root else []
    if discovery is not None:
        query(discovery)
        check(max(process["initial"]["tick"], root["initial"]["tick"]) <= discovery["start"], "discovery preceded admission")
        for n in discovery["nodes"]:
            if n["type"] == THREAD and n["pid"] == pid and n["tid"] and n["tid"] not in expected_ids:
                expected_ids.append(n["tid"])
        for p in threads[1:]:
            if p["initial"]:
                check(discovery["end"] <= p["initial"]["tick"], "owner pinned before discovery ended")
        check(discovery["end"] <= process["before"]["tick"], "query fence preceded discovery")
    check([t["requested"] for t in threads] == expected_ids, "pins differ from discovery roster")
    witnesses = [p for p in [process, *threads] if p["before"] is not None]
    signal_times = [p[phase]["tick"] for phase in ("before", "after") for p in witnesses]
    check(signal_times == sorted(signal_times), "out-of-order process and thread witnesses")
    prequalified = bool(discovery and bound(process, pid, r["process_created"], "before") and
                        bound(root, pid, r["thread_created"], "before"))
    check((final is not None) == prequalified, "traversal differs from its admission")
    if final is not None:
        query(final)
        for p in [process, *threads]:
            if p["before"]:
                check(p["before"]["tick"] <= final["start"] and final["end"] <= p["after"]["tick"],
                      "traversal outside pinned interval")
    return {p["requested"]: p for p in threads}


def assess(c, digest):
    pins = validate(c)
    r, final = c["requested"], c["query"]
    nodes = [] if final is None else final["nodes"]
    report = dict(schema="kn.wait_assessment.v1", receipt_sha256=digest, requested=r, source="windows_wct",
                  clock=c["clock"], observation_interval=None if final is None else [final["start"], final["end"]],
                  provider_cycle=None if final is None else final["cycle"], session=c["session"],
                  traversal_error=None if final is None else final["error"], node_count=len(nodes),
                  edges=[], potential_cycle=None, scope_boundary=None, conclusion="inconclusive", deadlock_established=False,
                  collector_authenticated=False,
                  atomic_snapshot=False, whole_host_assessed=False, object_lifetimes_verified=False,
                  wait_timeout="unknown", cancellation="unknown")
    if final is None:
        report["reason"] = "session_unavailable" if c["session"] and not c["session"]["ok"] else "target_binding_unavailable"
        return report
    if not final["ok"]:
        report["reason"] = "partial_traversal" if final["error"] in PARTIAL else "traversal_failed"
        return report
    if not (bound(c["process"], r["pid"], r["process_created"], "after") and
            bound(pins[r["tid"]], r["pid"], r["thread_created"], "after")):
        report["reason"] = "target_exited_or_unavailable"
        return report
    if not nodes or nodes[0]["type"] != THREAD or (nodes[0]["pid"], nodes[0]["tid"]) != (r["pid"], r["tid"]):
        report["reason"] = "unbound_traversal_root"
        return report

    def thread(n):
        if n["type"] != THREAD or n["pid"] != r["pid"] or n["status"] not in (2, BLOCKED):
            return None
        p = pins.get(n["tid"])
        if p and all(bound(p, r["pid"], p["created"], e) for e in ("initial", "before", "after")):
            return (n["tid"], p["created"])
        return None

    pin_positions = {p["requested"]: i for i, p in enumerate(c["threads"])}

    def edge(relation, i, j, lock, key):
        report["edges"].append(dict(relation=relation, node_indices=[i, j], thread_id=key[0], thread_created=key[1],
                                    lock_semantics=lock, observation="/query",
                                    evidence=[f"/query/nodes/{i}", f"/query/nodes/{j}", "/process",
                                              f"/threads/{pin_positions[key[0]]}"]))

    # WCT nodes alternate thread/object. Object positions belong to this traversal alone.
    # The same mutex may be acquired recursively by its owner. A self edge cannot prove a blocked cycle.
    for i, node in enumerate(nodes):
        if (node["type"] == THREAD) != (i % 2 == 0):
            reason = "unexpected_chain_shape"
        elif node["type"] == THREAD and node["pid"] != r["pid"]:
            reason = "process_scope_boundary"
        elif node["type"] == THREAD and thread(node) is None:
            reason = "thread_binding_or_status_unavailable"
        else:
            continue
        report["scope_boundary"] = dict(node_index=i, reason=reason)
        nodes = nodes[:i]
        break

    complete = set()
    for i in range(0, len(nodes) - 1, 2):
        waiter, lock = thread(nodes[i]), nodes[i + 1]
        semantics = LOCKS.get(lock["type"])
        if not waiter or nodes[i]["status"] != BLOCKED or not semantics or lock["status"] != OWNED:
            continue
        edge("waits_for", i, i + 1, semantics, waiter)
        if i + 2 < len(nodes):
            owner = thread(nodes[i + 2])
            if owner:
                edge("owned_by", i + 1, i + 2, semantics, owner)
                if waiter != owner:
                    complete.add(i)

    if report["scope_boundary"] is not None:
        report["reason"] = report["scope_boundary"]["reason"]
        return report
    if final["cycle"] and len(nodes) >= 5 and len(nodes) % 2 and nodes[-1]["status"] == BLOCKED:
        last = len(nodes) - 1
        end = thread(nodes[last])
        for first in range(0, last - 2, 2):
            segment = range(first, last, 2)
            members = [thread(nodes[i]) for i in segment]
            if end and members[0] == end and len(set(members)) == len(members) and all(i in complete for i in segment):
                report["potential_cycle"] = dict(node_indices=list(range(first, last + 1)),
                                                 evidence="/query", distinct_threads=len(members))
                report["conclusion"] = "potential_wait_cycle"
                report["reason"] = "wct_cycle_with_pinned_exclusive_lock_chain"
                report["next_observation"] = "repeat_for_the_same_generations_or_collect_a_frozen_wait_snapshot"
                return report
    if final["cycle"]:
        report["reason"] = "provider_cycle_without_qualified_closed_chain"
    elif len(nodes) == 1:
        report["reason"] = "single_thread_or_unsupported_wait"
    else:
        report["reason"] = "no_qualified_cycle_in_this_traversal"
    return report


def qpc(value):
    if value is None:
        return None
    check(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,18}", value), "invalid QPC integer")
    return uint(int(value), (1 << 63) - 1)


def held_inputs(receipt):
    # Discovery and initial identities came from a single open session per root.
    # Every embedded v1 view retains those exact inputs while bracketing a new call.
    def initial(p):
        return {k: v for k, v in p.items() if k not in ("before", "after")}
    return (receipt["requested"], initial(receipt["process"]), [initial(t) for t in receipt["threads"]],
            receipt["session"], receipt["discovery"])


def series_view(view, digest, base):
    fields(view, "timing receipt")
    c, timing = view["receipt"], view["timing"]
    a = assess(c, digest)
    check((timing is not None) == (c["query"] is not None), "timing without its traversal")
    if timing is not None:
        fields(timing, "reader_tid begin end")
        check(uint(timing["reader_tid"]) > 0, "missing reader identity")
        begin, end = qpc(timing["begin"]), qpc(timing["end"])
        check(begin is None or end is None or begin <= end, "reversed reader QPC interval")

    edges = a["edges"]
    for edge in edges:
        edge["observation"] = base + edge["observation"]
        edge["evidence"] = [base + pointer for pointer in edge["evidence"]]
    cycle = a["potential_cycle"]
    signature = None
    if cycle is not None:
        cycle["evidence"] = base + cycle["evidence"]
        c_nodes = c["query"]["nodes"]
        generations = {t["requested"]: t["created"] for t in c["threads"]}
        first, last = cycle["node_indices"][0], cycle["node_indices"][-1]
        arcs = []
        for i in range(first, last, 2):
            waiter, owner = c_nodes[i]["tid"], c_nodes[i + 2]["tid"]
            arcs.append((waiter, generations[waiter], LOCKS[c_nodes[i + 1]["type"]], owner, generations[owner]))
        # Rotation differs when the same directed ring is queried from another root.
        signature = tuple(sorted(arcs))
    result = {k: a[k] for k in ("requested", "provider_cycle", "observation_interval", "reason", "conclusion",
                                "scope_boundary", "node_count", "traversal_error", "edges", "potential_cycle")}
    result["receipt"] = base
    return result, signature


def overlap(round_, coordinator, hz):
    views = round_["views"]
    timings = [v["timing"] for v in views if v["timing"] is not None]
    mode = round_["dispatch"]
    failure = round_["failure"]
    if len(timings) == 2:
        check(mode in ("parallel", "serial_fallback"), "two readers require an explicit dispatch")
    else:
        check(mode == ("single" if timings else "unavailable"), "dispatch count mismatch")
    if mode == "serial_fallback":
        fields(failure, "stage win32_error")
        check(failure["stage"] in ("create_work", "initialize_barrier"), "unknown dispatch failure")
        uint(failure["win32_error"])
    else:
        check(failure is None, "unexpected dispatch failure")

    outer_start, outer_end = qpc(round_["begin_qpc"]), qpc(round_["end_qpc"])
    check(outer_start is None or outer_end is None or outer_start <= outer_end, "reversed coordinator QPC")
    windows = []
    for i, v in enumerate(views):
        t = v["timing"]
        if t is None:
            continue
        worker = mode == "parallel" and i == 1
        check((t["reader_tid"] != coordinator) == worker, "reader differs from dispatch")
        slack = int(worker)  # Ordering across Windows reader threads has one tick of ambiguity.
        a, b = qpc(t["begin"]), qpc(t["end"])
        for stamp in (a, b):
            if stamp is not None:
                check((outer_start is None or outer_start <= stamp + slack) and
                      (outer_end is None or stamp <= outer_end + slack), "reader outside coordinator QPC")
        windows.append((a, b))
    if len(windows) != 2:
        return "insufficient_queries", None, None
    if mode == "serial_fallback":
        check(windows[0][1] is None or windows[1][0] is None or windows[0][1] <= windows[1][0],
              "sequential calls overlap on one reader")
        check(views[0]["receipt"]["query"]["end"] <= views[1]["receipt"]["query"]["start"],
              "sequential calls overlap in native millisecond brackets")
        return "serial_fallback", None, None
    if hz is None or None in (outer_start, outer_end, *windows[0], *windows[1]):
        return "clock_unavailable", None, None
    a, b = windows
    whole = (min(a[0], b[0]), max(a[1], b[1]))
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    if hi < lo - 1:
        return "disjoint", None, whole
    if hi - lo <= 2:
        return "ambiguous", None, whole
    observations = [v["receipt"]["query"] for v in views]
    check(max(q["start"] for q in observations) <= min(q["end"] for q in observations),
          "overlap contradicts native millisecond brackets")
    return "overlapping", [str(lo + 1), str(hi - 1)], whole


class SeriesLifetimes:
    def __init__(self):
        self.terminated = set()
        self.parent_seen_after_discovery = set()

    def observe(self, view, slot, pin_, result, process=None):
        def generation(index, handle):
            if handle["created"] == "0":
                return (view, index)
            return ("thread" if index else "process", handle["pid"], handle["id"], handle["created"])

        key = generation(slot, pin_)
        if result == WAIT_TIMEOUT:
            check(key not in self.terminated, "retired process or thread generation became live")
            if process is not None:
                if slot == 0:
                    self.parent_seen_after_discovery.add(view)
                elif view in self.parent_seen_after_discovery and pin_["pid"] == process["id"]:
                    check(generation(0, process) not in self.terminated, "thread live after its process terminated")
        elif result == 0:
            self.terminated.add(key)


def series(c, digest):
    fields(c, "schema planned_rounds pause_ms collector qpc_hz rounds")
    total, delay = uint(c["planned_rounds"], 8), uint(c["pause_ms"], 5000)
    check(total >= 2 and delay and type(c["rounds"]) is list and 1 <= len(c["rounds"]) <= total, "invalid series plan")
    collector = c["collector"]
    fields(collector, "pid created coordinator_tid")
    check(uint(collector["pid"]) and uint(collector["coordinator_tid"]), "unbound collector")
    check(collector["created"] is None or creation(collector["created"]), "invalid collector creation")
    hz = qpc(c["qpc_hz"])
    check(hz is None or hz > 0, "invalid QPC frequency")

    baseline = None
    last_ms, last_qpc = 0, 0
    lifetimes = SeriesLifetimes()
    previous_process = None
    previous_ring = previous_window = None
    streak_start = 0
    rows, streaks = [], []
    issued = successful = potentials = overlapping = corroborated = 0
    for ri, r in enumerate(c["rounds"]):
        fields(r, "pause begin_qpc end_qpc dispatch failure views")
        check(type(r["views"]) is list and len(r["views"]) == 2, "two root receipts required")
        views, rings = [], []
        receipts = []
        for vi, v in enumerate(r["views"]):
            view, ring = series_view(v, digest, f"/rounds/{ri}/views/{vi}/receipt")
            views.append(view)
            rings.append(ring)
            receipts.append(v["receipt"])
        inputs = [held_inputs(receipt) for receipt in receipts]
        if baseline is None:
            left, right = (receipt["requested"] for receipt in receipts)
            check((left["pid"], left["process_created"]) == (right["pid"], right["process_created"]) and
                  left["tid"] != right["tid"], "roots require distinct threads in the same process generation")
            baseline = inputs
            for vi, receipt in enumerate(receipts):
                for pi, witness in enumerate([receipt["process"], *receipt["threads"]]):
                    initial = witness["initial"]
                    if initial is not None:
                        check(last_ms <= initial["tick"], "out-of-order initial witnesses")
                        lifetimes.observe(vi, pi, witness, initial["result"])
                        last_ms = initial["tick"]
                if receipt["discovery"] is not None:
                    last_ms = max(last_ms, receipt["discovery"]["end"])
        else:
            check(inputs == baseline, "held identities, session or discovery changed between rounds")

        pause = r["pause"]
        if ri == 0:
            check(pause is None, "unexpected initial pause")
        else:
            check(previous_process is not None, "series continued after both roots were unavailable")
            fields(pause, "start signal")
            s = pause["signal"]
            fields(s, "tick result error")
            check(last_ms <= uint(pause["start"], U64) <= uint(s["tick"], U64), "pause preceded previous witnesses")
            check(uint(s["result"]) in (0, WAIT_TIMEOUT, WAIT_FAILED), "invalid pause result")
            check_result(s["result"] != WAIT_FAILED, s["error"])
            process = receipts[previous_process]["process"]
            lifetimes.observe(previous_process, 0, process, s["result"], process)
            last_ms = s["tick"]

        queries = [receipt["query"] for receipt in receipts if receipt["query"] is not None]
        for phase in ("before", "after"):
            for vi, receipt in enumerate(receipts):
                for pi, witness in enumerate([receipt["process"], *receipt["threads"]]):
                    s = witness[phase]
                    if s is not None:
                        check(last_ms <= s["tick"], "out-of-order series witnesses")
                        lifetimes.observe(vi, pi, witness, s["result"], receipt["process"])
                        last_ms = s["tick"]
            if phase == "before" and queries:
                check(last_ms <= min(q["start"] for q in queries), "traversal preceded shared witnesses")
                last_ms = max(q["end"] for q in queries)
        previous_process = next((i for i, receipt in enumerate(receipts) if receipt["query"] is not None), None)
        clock_status, interior, window = overlap(r, collector["coordinator_tid"], hz)
        for value in (r["begin_qpc"], r["end_qpc"]):
            stamp = qpc(value)
            if stamp is not None:
                check(stamp >= last_qpc, "coordinator clock regressed between rounds")
                last_qpc = stamp
        issued += len(queries)
        successful += sum(q["ok"] for q in queries)
        potentials += sum(ring is not None for ring in rings)
        overlapping += interior is not None
        ring = rings[0]
        if None in rings:
            status = "cycle_unconfirmed_by_both_roots"
        elif rings[0] != rings[1]:
            status = "different_directed_cycles"
        elif not {v["requested"]["tid"] for v in views} <= {arc[0] for arc in ring}:
            status = "roots_outside_closed_cycle"
        elif not interior or collector["created"] is None:
            status = "matching_cycles_without_qualified_overlap"
        else:
            status = "corroborated"
        gap = None
        if previous_window is not None and window is not None:
            gap = max(0, window[0] - previous_window[1] - 1)
        row = dict(round=ri + 1, status=status, timing=clock_status, overlap_qpc=interior,
                   previous_gap_lower_bound_ticks=None if gap is None else str(gap),
                   evidence=f"/rounds/{ri}", views=views)
        rows.append(row)
        if status == "corroborated":
            corroborated += 1
            consecutive = (previous_ring == ring and gap is not None and gap * 1000 >= delay * hz and
                           pause["signal"]["result"] == WAIT_TIMEOUT)
            if consecutive:
                if streak_start == ri - 1:
                    arcs = [dict(waiter_tid=w, waiter_created=wc, lock_semantics=lock, owner_tid=o, owner_created=oc)
                            for w, wc, lock, o, oc in ring]
                    streaks.append(dict(first_round=streak_start + 1, last_round=ri + 1, relations=arcs))
                else:
                    streaks[-1]["last_round"] = ri + 1
            else:
                streak_start = ri
            previous_ring = ring
        else:
            previous_ring = None
        previous_window = window
    check(len(rows) == total or previous_process is None, "series truncated before a terminal unavailable round")
    conclusion = "repeated_potential_wait_cycle" if streaks else "potential_wait_cycle" if potentials else "inconclusive"
    return dict(schema="kn.wait_series_assessment.v1", receipt_sha256=digest, collector=collector,
                clock="windows_query_performance_counter", frequency_hz=c["qpc_hz"], requested_pause_ms=delay,
                coverage=dict(planned_rounds=total, recorded_rounds=len(rows), unrecorded_rounds=total-len(rows),
                              planned_queries=2*total, issued_queries=issued, unissued_queries=2*total-issued,
                              successful_queries=successful, potential_cycle_views=potentials,
                              overlapping_rounds=overlapping, corroborated_rounds=corroborated),
                conclusion=conclusion, repeated_groups=streaks, rounds=rows, atomic_snapshot=False,
                provider_execution_overlap_known=False, wait_interval_intersection_known=False,
                same_lock_lifetime_verified=False, continuous_wait_proven=False,
                deadlock_established=False, whole_host_assessed=False, collector_authenticated=False)


def unique_object(pairs):
    result = dict(pairs)
    check(len(result) == len(pairs), "duplicate JSON key")
    return result


def replay(path, digest):
    check(re.fullmatch(r"[0-9a-f]{64}", digest), "invalid SHA-256")
    with path.open("rb") as stream:
        raw = stream.read(512 * 1024 + 1)
    check(len(raw) <= 512 * 1024 and hashlib.sha256(raw).hexdigest() == digest, "capture size or SHA-256 mismatch")
    capture = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    if type(capture) is dict and capture.get("schema") == "kn.wait_series.v1":
        return series(capture, digest)
    check(len(raw) <= 65536, "single capture size limit exceeded")
    return assess(capture, digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(replay(args.capture, args.sha256), separators=(",", ":"), allow_nan=False))
    except (OSError, ValueError, RecursionError) as exc:
        print(f"wait-chain replay failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
