"""Replay a pinned Windows WCT capture or paired traversal series after the target exits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


DWORD = (1 << 32) - 1
U64 = (1 << 64) - 1
LIMIT = 16  # WCT_MAX_NODE_COUNT
THREAD, THREAD_WAIT, BLOCKED, OWNED = 8, 6, 3, 6
LOCKS = {1: "critical_section", 3: "mutex"}
DEPENDENCIES = {**LOCKS, THREAD_WAIT: "thread_termination"}
PARTIAL = {234, 565}  # ERROR_MORE_DATA, ERROR_TOO_MANY_THREADS
WAIT_TIMEOUT, WAIT_FAILED = 258, DWORD


def check(ok, reason):
    if not ok:
        raise ValueError(reason)


def fields(row, names, context="capture"):
    check(type(row) is dict and row.keys() == set(names.split()), f"unexpected {context} fields")


def uint(n, limit=DWORD):
    check(type(n) is int and 0 <= n <= limit, "invalid unsigned integer")
    return n


def creation(value):
    check(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), "invalid FILETIME")
    return uint(int(value), U64)


def requested_generation(row, context="capture"):
    fields(row, "pid process_created tid thread_created", context)
    pid, tid = uint(row["pid"]), uint(row["tid"])
    check(pid and tid and creation(row["process_created"]) and creation(row["thread_created"]), "unbound requested generation")
    return pid, tid


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
    pid, tid = requested_generation(r)
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
        waiter, object_node = thread(nodes[i]), nodes[i + 1]
        if not waiter or nodes[i]["status"] != BLOCKED or object_node["status"] != OWNED:
            continue
        target = thread(nodes[i + 2]) if i + 2 < len(nodes) else None
        if object_node["type"] == THREAD_WAIT:
            if target and target != waiter:
                report["edges"].append(dict(relation="waits_for_thread_termination", node_indices=[i, i + 1, i + 2],
                                            thread_id=waiter[0], thread_created=waiter[1],
                                            target_tid=target[0], target_created=target[1], wait_selection="unknown",
                                            observation="/query",
                                            evidence=[f"/query/nodes/{n}" for n in range(i, i + 3)] +
                                                     ["/process", f"/threads/{pin_positions[waiter[0]]}",
                                                      f"/threads/{pin_positions[target[0]]}"]))
                complete.add(i)
        elif object_node["type"] in LOCKS:
            semantics = LOCKS[object_node["type"]]
            edge("waits_for", i, i + 1, semantics, waiter)
            if target:
                edge("owned_by", i + 1, i + 2, semantics, target)
                if waiter != target:
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
                report["reason"] = ("wct_cycle_with_pinned_thread_termination_wait" if
                                    any(nodes[i + 1]["type"] == THREAD_WAIT for i in segment) else
                                    "wct_cycle_with_pinned_exclusive_lock_chain")
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


def cycle_signature(c, cycle):
    if cycle is None:
        return None
    nodes = c["query"]["nodes"]
    generations = {t["requested"]: t["created"] for t in c["threads"]}
    arcs = []
    for i in range(cycle["node_indices"][0], cycle["node_indices"][-1], 2):
        waiter, target = nodes[i]["tid"], nodes[i + 2]["tid"]
        arcs.append((waiter, generations[waiter], DEPENDENCIES[nodes[i + 1]["type"]], target, generations[target]))
    # Traversals of the same directed cycle can start at different members.
    return tuple(sorted(arcs))


def cycle_relations(ring):
    relations = []
    for waiter, created, semantics, target, target_created in ring:
        row = dict(waiter_tid=waiter, waiter_created=created)
        if semantics == "thread_termination":
            row.update(wait_semantics=semantics, target_tid=target, target_created=target_created)
        else:
            row.update(lock_semantics=semantics, owner_tid=target, owner_created=target_created)
        relations.append(row)
    return relations


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
    signature = cycle_signature(c, cycle)
    if cycle is not None:
        cycle["evidence"] = base + cycle["evidence"]
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
                    streaks.append(dict(first_round=streak_start + 1, last_round=ri + 1, relations=cycle_relations(ring)))
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


def first_cycle_exit(capture, rounds, first_round, primary, members):
    def same_process(pin_):
        return (pin_["failure"] is None and pin_["id"] == pin_["pid"] == primary["pid"] and
                pin_["created"] == primary["process_created"])

    for index in range(first_round, len(rounds)):
        views = rounds[index]
        if index > first_round:
            pause = capture["rounds"][index]["pause"]
            if pause["signal"]["result"] == 0:
                # The collector waited on the first process handle queried in the preceding round.
                prior, _, base = next(v for v in rounds[index - 1] if v[0]["query"] is not None)
                if same_process(prior["process"]):
                    return index, "process_termination_observed", [base + "/process", f"/rounds/{index}/pause/signal"]
        phases = ("after",) if index == first_round else ("before", "after")
        for phase in phases:
            for receipt, _, base in views:
                if not same_process(receipt["process"]):
                    continue
                pins = [("/process", receipt["process"])]
                pins.extend((f"/threads/{i}", p) for i, p in enumerate(receipt["threads"])
                            if p["failure"] is None and p["id"] == p["requested"] and p["pid"] == primary["pid"]
                            and (p["id"], p["created"]) in members)
                for path, p in pins:
                    signal = p[phase]
                    if signal is not None and signal["result"] == 0:
                        kind = "process_termination_observed" if path == "/process" else "cycle_member_termination_observed"
                        return index, kind, [base + "/process", base + path, base + path + "/" + phase]
    return None


def primary_owned_wait(edges, primary):
    for wait, owner in zip(edges, edges[1:]):
        if (wait["relation"] == "waits_for" and owner["relation"] == "owned_by" and
                wait["node_indices"][1] == owner["node_indices"][0] and
                (wait["thread_id"], wait["thread_created"]) == primary and
                (owner["thread_id"], owner["thread_created"]) != primary):
            return wait, owner
    return None


def diagnose(capture, assessment):
    paired = capture["schema"] == "kn.wait_series.v1"
    if paired:
        rounds = [[(raw["receipt"], view, view["receipt"])
                   for raw, view in zip(r["views"], row["views"])]
                  for r, row in zip(capture["rounds"], assessment["rounds"])]
        planned_rounds = capture["planned_rounds"]
        planned_queries = assessment["coverage"]["planned_queries"]
    else:
        rounds = [[(capture, assessment, "")]]
        planned_rounds = planned_queries = 1
    primary = rounds[0][0][0]["requested"]
    primary_key = (primary["tid"], primary["thread_created"])
    facts, open_waits, closed_views, gaps = [], [], [], []
    termination_waits = []
    reference_support, different_cycles = [], []
    reference = None
    first_round = None
    issued = 0

    def fact(kind, index, evidence, **details):
        facts.append(dict(kind=kind, round=index + 1, evidence=list(dict.fromkeys(evidence)), **details))
        return len(facts) - 1

    for index, views in enumerate(rounds):
        for c, a, base in views:
            q = c["query"]
            issued += q is not None
            primary_targets = [e for e in a["edges"] if e["relation"] == "waits_for_thread_termination"
                               and (e["thread_id"], e["thread_created"]) == primary_key]
            for dependency in primary_targets:
                termination_waits.append(fact("thread_termination_wait_observed", index,
                                              [base + "/query", *dependency["evidence"]],
                                              target_tid=dependency["target_tid"],
                                              target_created=dependency["target_created"]))
            cycle = a["potential_cycle"]
            ring = cycle_signature(c, cycle)
            if ring and any((arc[0], arc[1]) == primary_key for arc in ring):
                if reference is None:
                    reference, first_round = ring, index
                raw = [cycle["evidence"]]
                for edge in a["edges"]:
                    if edge["node_indices"][0] >= cycle["node_indices"][0]:
                        raw.extend(edge["evidence"])
                kind = "cycle_observed_in_traversal" if ring == reference else "different_cycle_observed_in_traversal"
                pos = fact(kind, index, raw, root_tid=c["requested"]["tid"])
                closed_views.append(pos)
                if ring == reference:
                    reference_support.append(pos)
                else:
                    different_cycles.append(pos)
                continue
            reason = "cycle_excludes_primary_generation" if ring else a["reason"]
            if q and q["cycle"] is False and a["scope_boundary"] is None:
                tids = [n["tid"] for n in q["nodes"] if n["type"] == THREAD]
                pair = primary_owned_wait(a["edges"], primary_key)
                if len(set(tids)) != len(tids):
                    reason = "repeated_thread_without_provider_cycle"
                elif pair:
                    wait, owner = pair
                    open_waits.append(fact("owned_wait_without_reported_cycle", index,
                                           [base + "/query", base + "/query/cycle", base + "/threads",
                                            *wait["evidence"], *owner["evidence"]],
                                           root_tid=c["requested"]["tid"]))
                    continue
                elif primary_targets:
                    continue
            gaps.append(dict(round=index + 1, receipt=base, reason=reason))

    ended = []
    repeated = False
    relations = cycle_relations(reference) if reference else []
    if reference:
        for group in assessment.get("repeated_groups", []):
            if group["relations"] == relations:
                first, last = group["first_round"], group["last_round"]
                refs = ["/collector", "/qpc_hz", "/pause_ms", *[f"/rounds/{i}" for i in range(first - 1, last)]]
                reference_support.append(fact("cycle_observed_in_consecutive_paired_rounds", first - 1, refs, last_round=last))
                repeated = True
        exit_fact = first_cycle_exit(capture, rounds, first_round, primary, {(arc[0], arc[1]) for arc in reference})
        if exit_fact:
            index, kind, evidence = exit_fact
            ended.append(fact(kind, index, evidence))

    cycle_status = "insufficient_evidence"
    next_cycle = "obtain_a_qualified_wait_observation_for_the_requested_generation"
    if reference:
        cycle_status = "repeated_potential_wait_cycle" if repeated else "potential_wait_cycle"
        next_cycle = "collect_wait_lifetime_and_release_evidence_for_the_same_generations"
    if different_cycles:
        cycle_status = "multiple_cycle_configurations_observed"
    if ended:
        cycle_status = "reference_member_or_process_terminated"
        next_cycle = "review_recorded_wait_completions_releases_and_timeouts_before_exit"
    contention_status = "cycle_reported_in_recording" if closed_views else "owned_wait_observed" if open_waits else "insufficient_evidence"
    report = dict(schema="kn.wait_diagnosis.v1", receipt_sha256=assessment["receipt_sha256"],
                source_schema=capture["schema"], primary=primary, facts=facts,
                coverage=dict(planned_queries=planned_queries, issued_queries=issued, unissued_queries=planned_queries-issued,
                              planned_rounds=planned_rounds, recorded_rounds=len(rounds),
                              unrecorded_rounds=planned_rounds-len(rounds)), unclassified_views=gaps,
                candidates=[
                    dict(candidate="reference_cycle_persisted_to_end_of_capture", status=cycle_status, relations=relations,
                         supporting_facts=reference_support, counterevidence=different_cycles + ended,
                         unobserved=["lock_lifetimes", "wait_interval_intersection", "continuous_wait", "timeout_or_cancellation"],
                         next_observation=next_cycle),
                    dict(candidate="primary_contention_without_a_reported_cycle_throughout_capture", status=contention_status,
                         supporting_facts=open_waits, counterevidence=closed_views,
                         unobserved=["unsupported_wait_dependencies", "lock_release", "cause_of_delay"],
                         next_observation="record_owner_progress_and_wait_completion_or_timeout")],
                deadlock_established=False, cause_of_hang_established=False, intent_assessed=False,
                whole_host_assessed=False, collector_authenticated=False)
    if reference and any(arc[2] == "thread_termination" for arc in reference):
        unknown = report["candidates"][0]["unobserved"]
        if all(arc[2] == "thread_termination" for arc in reference):
            unknown.remove("lock_lifetimes")
        unknown.append("thread_wait_completion")
    if termination_waits:
        report["candidates"].append(dict(candidate="primary_waited_for_thread_termination",
                                         status="dependency_observed", supporting_facts=termination_waits,
                                         counterevidence=[], unobserved=["wait_completion", "alternative_wait_objects", "timeout_or_cancellation",
                                                                        "target_exit_as_cause_of_wakeup"],
                                         next_observation="record_the_wait_result_and_target_thread_exit"))
    return report


# Each group names alternative facts for one necessary part of a witness.
# The persistence claim needs evidence of both the first cycle and a later exit.
CYCLE = "cycle_observed_in_traversal"
OTHER_CYCLE = "different_cycle_observed_in_traversal"
REPEATED = "cycle_observed_in_consecutive_paired_rounds"
OPEN_WAIT = "owned_wait_without_reported_cycle"
THREAD_WAIT_FACT = "thread_termination_wait_observed"
EXITS = ("process_termination_observed", "cycle_member_termination_observed")
OBSERVED_CYCLES = (CYCLE, OTHER_CYCLE)
INVESTIGATION_POLICY = "kn.wait_claim_policy.v1"
SINGLE_CAPTURE_LIMIT = 64 * 1024
CAPTURE_LIMIT = 512 * 1024
PROPOSAL_LIMIT = 32 * 1024
MAX_VIEWS = 16
MAX_CITATIONS = 32

# name, supporting facts, counterevidence, sufficient support groups, sufficient refutation groups
WAIT_CLAIMS = (
    ("primary_cycle_observed", OBSERVED_CYCLES, (), (OBSERVED_CYCLES,), ()),
    ("primary_owned_wait_without_reported_cycle_observed", (OPEN_WAIT,), (), ((OPEN_WAIT,),), ()),
    ("primary_waited_for_thread_termination", (THREAD_WAIT_FACT,), (), ((THREAD_WAIT_FACT,),), ()),
    ("cycle_corroborated_in_consecutive_paired_rounds", (REPEATED,), (), ((REPEATED,),), ()),
    ("reference_cycle_persisted_to_end_of_capture", (CYCLE, REPEATED), (OTHER_CYCLE, *EXITS), (), ((CYCLE,), EXITS)),
    ("primary_contention_without_a_reported_cycle_throughout_capture", (OPEN_WAIT,), OBSERVED_CYCLES, (), (OBSERVED_CYCLES,)),
)
CLAIM_NAMES = tuple(row[0] for row in WAIT_CLAIMS)


def original_value(capture, pointer):
    value = capture
    for token in pointer.split("/")[1:]:
        # These pointers are generated by the WCT interpreter and have fixed field names or array indices.
        if type(value) is list:
            check(re.fullmatch(r"0|[1-9][0-9]*", token) and int(token) < len(value), "unresolved wait evidence index")
            value = value[int(token)]
        else:
            check(type(value) is dict and token in value, "unresolved wait evidence field")
            value = value[token]
    return value


def bound_facts(capture, diagnosis):
    facts = []
    for fact in diagnosis["facts"]:
        for pointer in fact["evidence"]:
            check(pointer == "" or pointer.startswith("/"), "invalid wait evidence pointer")
            original_value(capture, pointer)
        check(fact["evidence"], "wait evidence is missing")
        preimage = ["kn.wait_fact.v1", diagnosis["receipt_sha256"], fact]
        encoded = json.dumps(preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        facts.append(dict(id=hashlib.sha256(encoded).hexdigest(), **fact))
    check(len({f["id"] for f in facts}) == len(facts), "duplicate wait evidence identity")
    return facts


def wait_hypotheses(facts):
    def matches(kinds):
        return [f["id"] for f in facts if f["kind"] in kinds]

    hypotheses = []
    for name, supporting, counter, positive, negative in WAIT_CLAIMS:
        verdict, required = "inconclusive", []
        for outcome, groups in (("supported", positive), ("refuted", negative)):
            witnesses = [matches(group) for group in groups]
            if witnesses and all(witnesses):
                check(verdict == "inconclusive", "conflicting decisive wait evidence")
                verdict, required = outcome, witnesses
        hypotheses.append(dict(claim=name, verdict=verdict, supporting_facts=matches(supporting),
                               counterevidence=matches(counter), required_evidence_groups=required))
    return hypotheses


def proposal_rows(proposal, digest):
    fields(proposal, "schema policy receipt_sha256 target claims", "proposal")
    check(proposal["schema"] == "kn.wait_claim_proposal.v1" and proposal["policy"] == INVESTIGATION_POLICY,
          "unsupported wait proposal schema or policy")
    check(proposal["receipt_sha256"] == digest, "proposal is outside the pinned capture")
    requested_generation(proposal["target"], "proposal target")
    rows = proposal["claims"]
    check(type(rows) is list and 1 <= len(rows) <= len(WAIT_CLAIMS), "invalid proposed claim count")
    seen = set()
    for row in rows:
        fields(row, "claim verdict evidence_ids", "claim")
        name, ids = row["claim"], row["evidence_ids"]
        check(name in CLAIM_NAMES and name not in seen and row["verdict"] in ("supported", "refuted"), "invalid proposed claim")
        seen.add(name)
        check(type(ids) is list and 1 <= len(ids) <= MAX_CITATIONS and
              all(type(i) is str and re.fullmatch(r"[0-9a-f]{64}", i) for i in ids) and len(set(ids)) == len(ids),
              "invalid proposed evidence IDs")
    return rows


def check_proposed(rows, hypotheses):
    by_name = {h["claim"]: h for h in hypotheses}
    checked = []
    for row in rows:
        finding = by_name[row["claim"]]
        groups = finding["required_evidence_groups"]
        ids = set(row["evidence_ids"])
        if finding["verdict"] != row["verdict"]:
            reason = "verdict_not_established"
        elif not ids.issubset(i for group in groups for i in group):
            reason = "citation_outside_decisive_evidence"
        elif not all(ids.intersection(group) for group in groups):
            reason = "missing_required_witness"
        else:
            reason = "verified"
        checked.append(dict(claim=row["claim"], proposed_verdict=row["verdict"], evidence_ids=row["evidence_ids"], result=reason))
    return checked


def recorded_view_count(capture):
    check(type(capture) is dict, "invalid capture")
    if capture.get("schema") == "kn.wait_chain.v1":
        return 1
    check(capture.get("schema") == "kn.wait_series.v1", "unsupported investigation source")
    rounds = capture.get("rounds")
    check(type(rounds) is list and 1 <= len(rounds) <= 8 and
          all(type(r) is dict and type(r.get("views")) is list and len(r["views"]) == 2 for r in rounds),
          "invalid recorded view count")
    return 2 * len(rounds)


def investigate(capture, digest, size, view_budget, proposal, proposal_sha256):
    required = recorded_view_count(capture)
    rows = proposal_rows(proposal, digest) if proposal is not None else []
    target_pointer = "/rounds/0/views/0/receipt/requested" if capture["schema"] == "kn.wait_series.v1" else "/requested"
    target = original_value(capture, target_pointer)
    requested_generation(target)
    if proposal is not None:
        check(proposal["target"] == target, "proposal targets another process or thread generation")
    limit = SINGLE_CAPTURE_LIMIT if capture["schema"] == "kn.wait_chain.v1" else CAPTURE_LIMIT
    plan = dict(goal="check_competing_wait_explanations_for_the_primary_thread", allowed_source=capture["schema"],
                operation="replay_retained_wct", hypotheses=list(CLAIM_NAMES),
                stop_conditions=["view_budget_exceeded", "pinned_source_exhausted", "proposal_not_verified"], max_capture_bytes=limit,
                max_views=view_budget, max_claims=len(WAIT_CLAIMS), max_evidence_ids_per_claim=MAX_CITATIONS,
                max_proposal_bytes=PROPOSAL_LIMIT, capture_bytes=size, required_views=required, evaluated_views=0)
    report = dict(schema="kn.wait_investigation.v1", policy=INVESTIGATION_POLICY, receipt_sha256=digest,
                  plan=plan, target=None, target_evidence=None, proposal_sha256=proposal_sha256, facts=[], hypotheses=[], coverage=None, unclassified_views=[],
                  missing_observations=[], proposal_checks=[], status="deferred", stop_reason="view_budget_exceeded",
                  collector_authenticated=False, deadlock_established=False, cause_of_hang_established=False)
    if required > view_budget:
        return report
    diagnosis = diagnose(capture, assessment_for(capture, digest))
    check(target == diagnosis["primary"], "unresolved primary identity")
    facts = bound_facts(capture, diagnosis)
    hypotheses = wait_hypotheses(facts)
    checks = check_proposed(rows, hypotheses)
    rejected = any(row["result"] != "verified" for row in checks)
    report.update(target=target, target_evidence=target_pointer, facts=facts, hypotheses=hypotheses, coverage=diagnosis["coverage"],
                  unclassified_views=diagnosis["unclassified_views"], proposal_checks=checks,
                  status="rejected" if rejected else "evaluated", stop_reason="proposal_not_verified" if rejected else "pinned_source_exhausted",
                  missing_observations=[dict(candidate=c["candidate"], unobserved=c["unobserved"], next_observation=c["next_observation"])
                                        for c in diagnosis["candidates"]])
    plan["evaluated_views"] = required
    return report


def unique_object(pairs):
    result = dict(pairs)
    check(len(result) == len(pairs), "duplicate JSON key")
    return result


def read_capture(stream, digest):
    check(re.fullmatch(r"[0-9a-f]{64}", digest), "invalid SHA-256")
    raw = stream.read(CAPTURE_LIMIT + 1)
    check(len(raw) <= CAPTURE_LIMIT and hashlib.sha256(raw).hexdigest() == digest, "capture size or SHA-256 mismatch")
    capture = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    check((type(capture) is dict and capture.get("schema") == "kn.wait_series.v1") or len(raw) <= SINGLE_CAPTURE_LIMIT,
          "single capture size limit exceeded")
    return capture, len(raw)


def assessment_for(capture, digest):
    return series(capture, digest) if type(capture) is dict and capture.get("schema") == "kn.wait_series.v1" else assess(capture, digest)


def replay_stream(stream, digest, explain):
    capture, _ = read_capture(stream, digest)
    result = assessment_for(capture, digest)
    return diagnose(capture, result) if explain else result


def replay(path, digest, *, explain=False):
    with path.open("rb") as stream:
        return replay_stream(stream, digest, explain)


def regular_identity(stream):
    if stream is None:
        return None
    info = os.fstat(stream.fileno())
    return info if stat.S_ISREG(info.st_mode) else None


def aliases_sink(identity):
    return identity is not None and any(sink is not None and os.path.samestat(identity, sink)
                                        for sink in (regular_identity(sys.stdout), regular_identity(sys.stderr)))


def diagnostic_allowed(stream, operands):
    sink = regular_identity(stream)
    if sink is None:
        return True
    stdin = regular_identity(sys.stdin)
    if stdin is not None and os.path.samestat(sink, stdin):
        return False
    for operand in operands:
        if os.fspath(operand).startswith(("\\\\", "//")):
            return False
        try:
            if os.path.samestat(sink, os.stat(operand)):
                return False
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, ValueError):
            return False
    return True


class ReplayArguments(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        # On help or invalid grammar argparse can print before it identifies the capture.
        if diagnostic_allowed(file or sys.stderr, sys.argv[1:]):
            super()._print_message(message, file)


def run_investigation(args):
    if args.check_claims and aliases_sink(regular_identity(sys.stdin)):
        return 2
    # Hold the original input until the result has been written. A disk-backed
    # diagnostic may already have an open hard link to this same file.
    if os.name == "nt":
        name = os.fspath(args.capture).replace("/", "\\").upper()
        if name.startswith(("\\\\.\\", "\\\\?\\")):
            check(re.match(r"^[A-Z]:\\", name[4:]) or name[4:].startswith("UNC\\"), "a saved capture file is required")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(args.capture, flags), "rb") as stream:
        identity = regular_identity(stream)
        if aliases_sink(identity):
            return 2
        check(identity is not None, "a saved capture file is required")
        budget = MAX_VIEWS if args.max_views is None else uint(args.max_views, MAX_VIEWS)
        capture, size = read_capture(stream, args.sha256)
        proposal = proposal_sha = None
        if args.check_claims:
            data = sys.stdin.buffer.read(PROPOSAL_LIMIT + 1)
            check(0 < len(data) <= PROPOSAL_LIMIT, "invalid proposal size")
            proposal = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object)
            check(type(proposal) is dict, "expected a typed claim proposal")
            proposal_sha = hashlib.sha256(data).hexdigest()
        report = investigate(capture, args.sha256, size, budget, proposal, proposal_sha)
        payload = memoryview((json.dumps(report, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii"))
        try:
            while payload:
                sent = os.write(sys.stdout.fileno(), payload[:32768])
                if not sent:
                    return 3
                payload = payload[sent:]
        except OSError:
            return 3
        return 0 if report["status"] == "evaluated" else 1


def main():
    parser = ReplayArguments(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--sha256", required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--diagnose", action="store_true", help="compare wait hypotheses using the original capture")
    modes.add_argument("--investigate", action="store_true", help="evaluate bounded wait claims and emit their original evidence IDs")
    modes.add_argument("--check-claims", action="store_true", help="verify a typed claim proposal from standard input")
    parser.add_argument("--max-views", type=int, help="maximum recorded root views to evaluate, from 0 to 16")
    args = parser.parse_args()
    try:
        if args.investigate or args.check_claims:
            return run_investigation(args)
        check(args.max_views is None, "view budget requires an investigation")
        with args.capture.open("rb") as stream:
            if aliases_sink(regular_identity(stream)):
                return 2
            result = replay_stream(stream, args.sha256, args.diagnose)
            print(json.dumps(result, separators=(",", ":"), allow_nan=False), flush=True)
    except (OSError, ValueError, RecursionError) as exc:
        if diagnostic_allowed(sys.stderr, (args.capture,)):
            print(f"wait-chain replay failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
