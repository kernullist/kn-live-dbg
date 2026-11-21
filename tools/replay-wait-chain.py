"""Reconstruct a wait graph from one pinned Windows WCT capture after the target exits."""
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


def unique_object(pairs):
    result = dict(pairs)
    check(len(result) == len(pairs), "duplicate JSON key")
    return result


def replay(path, digest):
    check(re.fullmatch(r"[0-9a-f]{64}", digest), "invalid SHA-256")
    with path.open("rb") as stream:
        raw = stream.read(65537)
    check(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == digest, "capture size or SHA-256 mismatch")
    capture = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
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
