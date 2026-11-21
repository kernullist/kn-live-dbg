"""Exercise the controller's WCT capture with owned mutexes and verify offline graph boundaries."""
import argparse
import copy
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest


HERE = Path(__file__).resolve()
REPLAY = HERE.with_name("replay-wait-chain.py")
WAIT_TIMEOUT = 258
kernel = c.WinDLL("kernel32", use_last_error=True)


def api(name, result, *args):
    f = getattr(kernel, name)
    f.restype, f.argtypes = result, args
    return f


mutex = api("CreateMutexW", w.HANDLE, c.c_void_p, w.BOOL, w.LPCWSTR)
release = api("ReleaseMutex", w.BOOL, w.HANDLE)
wait = api("WaitForSingleObject", w.DWORD, w.HANDLE, w.DWORD)
close = api("CloseHandle", w.BOOL, w.HANDLE)
current_thread = api("GetCurrentThread", w.HANDLE)
current_process = api("GetCurrentProcess", w.HANDLE)
process_id = api("GetCurrentProcessId", w.DWORD)
times = [api(name, w.BOOL, w.HANDLE, *([c.POINTER(w.FILETIME)] * 4)) for name in ("GetProcessTimes", "GetThreadTimes")]


def creation(thread):
    stamps = [w.FILETIME() for _ in range(4)]
    handle = current_thread() if thread else current_process()
    if not times[thread](handle, *(c.byref(s) for s in stamps)):
        raise c.WinError(c.get_last_error())
    return str(stamps[0].dwLowDateTime | (stamps[0].dwHighDateTime << 32))


def child(participants):
    locks = [mutex(None, False, None) for _ in range(participants)]
    if not all(locks):
        raise c.WinError(c.get_last_error())
    ids, outcomes = [None] * participants, [None] * participants
    ready = threading.Barrier(participants + 1, timeout=10)
    phase = threading.Event()
    command = []

    def control():
        command.append(sys.stdin.readline().strip())
        phase.set()

    def work(i):
        ids[i] = [threading.get_native_id(), creation(True)]
        if wait(locks[i], 1000) != 0:
            return
        try:
            ready.wait()
            last = i == participants - 1
            if last and (not phase.wait(35) or command != ["cycle"]):
                return
            following = locks[(i + 1) % participants]
            outcomes[i] = wait(following, 6000 if last else 50000)
            if outcomes[i] == 0 and not release(following):
                raise c.WinError(c.get_last_error())
        finally:
            if not release(locks[i]):
                raise c.WinError(c.get_last_error())

    workers = [threading.Thread(target=work, args=(i,)) for i in range(participants)]
    for t in workers:
        t.start()
    try:
        ready.wait()
        print(json.dumps(dict(pid=process_id(), process_created=creation(False), threads=ids)), flush=True)
        threading.Thread(target=control, daemon=True).start()
        for t in workers:
            t.join()
        print(json.dumps(outcomes), flush=True)
    finally:
        for h in locks:
            close(h)
    return 0 if outcomes == [0] * (participants - 1) + [WAIT_TIMEOUT] else 1


def run(argv, code=0):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=15)
    if result.returncode != code:
        raise AssertionError(f"exit {result.returncode}, expected {code}: {result.stderr[-500:]!r}")
    if code:
        assert not result.stdout
    return result.stdout


def capture(exe, target, *, pc=None, tc=None):
    tid, thread_created = target["threads"][0]
    return run([exe, "--wait-chain", target["pid"], pc or target["process_created"], tid, tc or thread_created])


def observe_until(exe, target, want_cycle):
    limit = time.monotonic() + (4.5 if want_cycle else 12)
    tids = [p[0] for p in target["threads"]]
    while time.monotonic() < limit:
        raw = capture(exe, target)
        q = json.loads(raw)["query"]
        if q and q["ok"] and q["cycle"] == want_cycle:
            nodes = q["nodes"]
            threads = [n["tid"] for n in nodes if n["type"] == 8]
            if threads == (tids + tids[:1] if want_cycle else tids) and nodes[1]["type"] == 3:
                return raw
        time.sleep(0.02)
    raise AssertionError(f"Windows did not return the expected owned wait chain (cycle={want_cycle})")


def series_args(exe, target, count, delay, *, peer_generation=None):
    left, right = target["threads"][:2]
    return [str(v) for v in (exe, "--wait-chain", target["pid"], target["process_created"], *left,
                             "--corroborate", right[0], peer_generation or right[1], count, delay)]


def observed_transition(exe, target, fixture):
    # Change the target only after the collector flushes its first complete round.
    with subprocess.Popen(series_args(exe, target, 4, 150), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as collector:
        try:
            lines = queue.Queue()
            def read_prefix():
                lines.put((collector.stdout.readline(), collector.stdout.readline()))
            threading.Thread(target=read_prefix, daemon=True).start()
            header, first = lines.get(timeout=10)
            initial = json.loads(header + first + b"]}")
            assert not any(v["receipt"]["query"]["cycle"] for v in initial["rounds"][0]["views"])
            fixture.stdin.write(b"cycle\n")
            fixture.stdin.flush()
            tail, err = collector.communicate(timeout=12)
            if collector.returncode:
                raise AssertionError(f"transition capture failed: {err[-300:]!r}")
            return header + first + tail
        finally:
            if collector.poll() is None:
                collector.kill()
                collector.wait(timeout=10)


def acquire(exe, participants):
    raw = {}
    with subprocess.Popen([sys.executable, "-E", "-s", "-B", str(HERE), "--child", "--participants", str(participants)],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
        try:
            line = queue.Queue()
            threading.Thread(target=lambda: line.put(p.stdout.readline()), daemon=True).start()
            target = json.loads(line.get(timeout=12))
            raw["one_way"] = observe_until(exe, target, False)
            raw["open_series"] = run(series_args(exe, target, 3, 35))
            if participants == 2:
                raw["wrong_process"] = capture(exe, target, pc=str(int(target["process_created"]) + 1))
                raw["wrong_thread"] = capture(exe, target, tc=str(int(target["threads"][0][1]) + 1))
            raw["transition"] = observed_transition(exe, target, p)
            raw["cycle"] = observe_until(exe, target, True)
            raw["closed_series"] = run(series_args(exe, target, 8, 50))
            if participants == 2:
                wrong_peer = str(int(target["threads"][1][1]) + 1)
                raw["single_series"] = run(series_args(exe, target, 2, 25, peer_generation=wrong_peer))
                raw["exit_series"] = run(series_args(exe, target, 8, 1100))
            out, err = p.communicate(timeout=12)
            if p.returncode or json.loads(out) != [0] * (participants - 1) + [WAIT_TIMEOUT]:
                raise AssertionError(f"fixture outcomes differ: {p.returncode}, {out[:100]!r}, {err[-300:]!r}")
        finally:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=10)
    raw["retired"] = capture(exe, target)
    raw["retired_series"] = run(series_args(exe, target, 4, 25))
    return target, raw


class WaitTests(unittest.TestCase):
    def replay(self, raw, expected=0, pin=None, *, diagnose=False):
        path = self.folder / "review.json"
        path.write_bytes(raw)
        result = run([sys.executable, "-E", "-s", "-B", str(REPLAY), path, "--sha256",
                      pin or hashlib.sha256(raw).hexdigest(), *(["--diagnose"] if diagnose else [])], expected)
        return json.loads(result) if result else None

    def altered(self, change, expected=0):
        c = json.loads(self.original["cycle"])
        change(c)
        return self.replay(json.dumps(c, separators=(",", ":")).encode(), expected)

    def check_series(self, payload, expected=0):
        return self.replay(json.dumps(payload, separators=(",", ":")).encode(), expected)

    def timed_rounds(self, count, name="closed_series"):
        # Replace timings explicitly so scheduler jitter cannot select the verdict.
        data = json.loads(self.original[name])
        data.update(planned_rounds=count, qpc_hz="1000000", pause_ms=50)
        data["rounds"] = data["rounds"][:count]
        for i, row in enumerate(data["rounds"]):
            base = 1_000_000 + i * 100_000
            row.update(begin_qpc=str(base), end_qpc=str(base + 1000))
            tick = row["views"][0]["receipt"]["query"]["start"]
            for view, (begin, end) in zip(row["views"], ((100, 700), (250, 850))):
                view["timing"].update(begin=str(base + begin), end=str(base + end))
                view["receipt"]["query"].update(start=tick, end=tick)
        return data

    def test_series_native_rotation_and_evidence(self):
        def resolve(document, pointer):
            for field in pointer.lstrip("/").split("/"):
                document = document[int(field) if isinstance(document, list) else field]
            return document

        for prefix, target in (("", self.target), ("triangle_", self.triangle)):
            ids = [thread[0] for thread in target["threads"]]
            for name, closed in (("open_series", False), ("closed_series", True)):
                raw = self.original[prefix + name]
                c, a = json.loads(raw), self.replay(raw)
                self.assertEqual(a, self.replay(raw))
                hz = int(c["qpc_hz"])
                count = c["planned_rounds"]
                self.assertEqual(a["coverage"]["issued_queries"], 2 * count)
                self.assertEqual(a["coverage"]["successful_queries"], 2 * count)
                self.assertEqual(a["coverage"]["potential_cycle_views"], 2 * count if closed else 0)
                groups = []
                previous_match = False
                previous_end = None
                matches = overlaps = 0
                for i, (r, actual) in enumerate(zip(c["rounds"], a["rounds"]), 1):
                    self.assertEqual(resolve(c, actual["evidence"]), r)
                    starts, ends = [], []
                    for root, (v, view) in enumerate(zip(r["views"], actual["views"])):
                        self.assertEqual(resolve(c, view["receipt"]), v["receipt"])
                        q = v["receipt"]["query"]
                        tids = [n["tid"] for n in q["nodes"] if n["type"] == 8]
                        self.assertEqual(tids, ids[root:] + ids[:root+1] if closed else ids[root:])
                        self.assertEqual(q["cycle"], closed)
                        for edge in view["edges"]:
                            self.assertEqual(resolve(c, edge["observation"]), q)
                            node1, node2, proc, pin = (resolve(c, p) for p in edge["evidence"])
                            self.assertEqual([node1, node2], [q["nodes"][j] for j in edge["node_indices"]])
                            self.assertEqual((proc["created"], pin["created"]), (target["process_created"], edge["thread_created"]))
                        if closed:
                            self.assertEqual(resolve(c, view["potential_cycle"]["evidence"]), q)
                        starts.append(int(v["timing"]["begin"]))
                        ends.append(int(v["timing"]["end"]))
                    overlap = r["dispatch"] == "parallel" and min(ends) - max(starts) > 2
                    match = closed and overlap
                    self.assertEqual(actual["overlap_qpc"], [str(max(starts) + 1), str(min(ends) - 1)] if overlap else None)
                    self.assertEqual(actual["status"] == "corroborated", match)
                    if (previous_match and match and r["pause"]["signal"]["result"] == WAIT_TIMEOUT and
                            (min(starts) - previous_end - 1) * 1000 >= c["pause_ms"] * hz):
                        if groups and groups[-1][1] == i-1:
                            groups[-1][1] = i
                        else:
                            groups.append([i-1, i])
                    matches += match
                    overlaps += overlap
                    previous_match, previous_end = match, max(ends)
                self.assertEqual((a["coverage"]["overlapping_rounds"], a["coverage"]["corroborated_rounds"]), (overlaps, matches))
                self.assertEqual([[g["first_round"], g["last_round"]] for g in a["repeated_groups"]], groups)
                for group in a["repeated_groups"]:
                    self.assertEqual({(e["waiter_tid"], e["owner_tid"]) for e in group["relations"]},
                                     {(tid, ids[(idx+1) % len(ids)]) for idx, tid in enumerate(ids)})
                self.assertEqual(a["conclusion"], "repeated_potential_wait_cycle" if groups else
                                 "potential_wait_cycle" if closed else "inconclusive")
                for key in ("atomic_snapshot", "provider_execution_overlap_known", "wait_interval_intersection_known", "same_lock_lifetime_verified",
                            "continuous_wait_proven", "deadlock_established", "whole_host_assessed", "collector_authenticated"):
                    self.assertIs(a[key], False)

    def test_series_changing_target_and_coverage(self):
        for prefix in ("", "triangle_"):
            raw = self.original[prefix + "transition"]
            doc, a = json.loads(raw), self.replay(raw)
            self.assertGreater(a["coverage"]["potential_cycle_views"], 0)
            self.assertEqual(a["coverage"]["corroborated_rounds"], 0)
            self.assertNotIn(True, [v["provider_cycle"] for v in a["rounds"][0]["views"]])
            self.assertTrue(any(v["receipt"]["query"]["cycle"] for r in doc["rounds"][1:] for v in r["views"][1:]))
            self.assertTrue(any(r["views"][1]["scope_boundary"] for r in a["rounds"][1:]))
            retired = self.replay(self.original[prefix + "retired_series"])
            self.assertEqual((retired["coverage"]["recorded_rounds"], retired["coverage"]["unissued_queries"]), (1, 8))
        partial = self.replay(self.original["single_series"])
        self.assertEqual((partial["coverage"]["issued_queries"], partial["coverage"]["unissued_queries"]), (2, 2))
        self.assertEqual(partial["coverage"]["corroborated_rounds"], 0)
        raw = self.original["exit_series"]
        doc, a = json.loads(raw), self.replay(raw)
        self.assertEqual(doc["rounds"][-1]["dispatch"], "unavailable")
        cov = a["coverage"]
        self.assertGreater(cov["issued_queries"], 0)
        self.assertLess(cov["recorded_rounds"], cov["planned_rounds"])
        self.assertEqual(cov["planned_queries"], cov["issued_queries"] + cov["unissued_queries"])

    def test_series_timing_boundaries(self):
        c = self.timed_rounds(3)
        a = self.check_series(c)
        self.assertEqual((a["conclusion"], a["repeated_groups"][0]["last_round"]), ("repeated_potential_wait_cycle", 3))
        for separation, status in ((-3, "disjoint"), (-1, "ambiguous"), (0, "ambiguous"), (1, "ambiguous"),
                                   (2, "ambiguous"), (3, "overlapping")):
            sample = copy.deepcopy(c)
            row = sample["rounds"][1]
            row["views"][1]["timing"]["begin"] = str(int(row["views"][0]["timing"]["end"]) - separation)
            a = self.check_series(sample)
            self.assertEqual(a["rounds"][1]["timing"], status)
            self.assertEqual(bool(a["repeated_groups"]), separation > 2)
        for field in ("qpc_hz", "created", "end"):
            sample = copy.deepcopy(c)
            if field == "qpc_hz":
                sample[field] = None
            elif field == "created":
                sample["collector"][field] = None
            else:
                sample["rounds"][1]["views"][1]["timing"][field] = None
            self.assertEqual(self.check_series(sample)["repeated_groups"], [])
        for pause, repeat in ((99, True), (100, False)):
            sample = copy.deepcopy(c)
            sample["pause_ms"] = pause
            self.assertEqual(bool(self.check_series(sample)["repeated_groups"]), repeat)
        # A failure to wait is an original Win32 outcome, even if elapsed QPC would qualify.
        c["rounds"][1]["pause"]["signal"].update(result=4294967295, error=6)
        self.assertEqual(self.check_series(c)["repeated_groups"][0]["first_round"], 2)
        row = c["rounds"][1]
        row.update(dispatch="serial_fallback", failure={"stage": "create_work", "win32_error": 8})
        row["views"][1]["timing"].update(reader_tid=c["collector"]["coordinator_tid"], begin=row["views"][0]["timing"]["end"])
        self.assertEqual(self.check_series(c)["rounds"][1]["timing"], "serial_fallback")
        self.assertEqual(self.check_series(c)["repeated_groups"], [])

    def test_series_independent_rings(self):
        c = self.timed_rounds(3, "triangle_closed_series")
        v = c["rounds"][1]["views"][1]["receipt"]
        v["query"]["nodes"][1]["type"] = 1
        self.assertEqual(self.check_series(c)["rounds"][1]["status"], "different_directed_cycles")
        v["query"]["nodes"][1]["type"] = 3
        first, second = v["query"]["nodes"][2], v["query"]["nodes"][4]
        v["query"]["nodes"][2], v["query"]["nodes"][4] = second, first
        self.assertEqual(self.check_series(c)["rounds"][1]["status"], "different_directed_cycles")
        # A chain may start at a third thread and end in a two-member cycle.
        c = self.timed_rounds(2, "triangle_closed_series")
        for r in c["rounds"]:
            for vi, v in enumerate(r["views"]):
                q = v["receipt"]["query"]
                if vi == 0:
                    q["nodes"][-1] = copy.deepcopy(q["nodes"][2])
                else:
                    q["nodes"] = q["nodes"][:4] + q["nodes"][:1]
                    q["reported"] = len(q["nodes"])
        a = self.check_series(c)
        self.assertTrue(all(r["status"] == "roots_outside_closed_cycle" for r in a["rounds"]))
        c = self.timed_rounds(2, "triangle_closed_series")
        for r in c["rounds"]:
            owner = r["views"][0]["receipt"]["threads"][2]
            owner["created"] = str(int(owner["created"]) + 1)
        self.assertTrue(all(r["status"] == "different_directed_cycles" for r in self.check_series(c)["rounds"]))
        c = self.timed_rounds(3, "triangle_closed_series")
        for r in c["rounds"]:
            for v in r["views"]:
                q = v["receipt"]["query"]
                q.update(nodes=q["nodes"][:3], reported=3, cycle=False)
        a = self.check_series(c)
        self.assertEqual((a["coverage"]["overlapping_rounds"], a["coverage"]["potential_cycle_views"]), (3, 0))
        self.assertEqual(a["conclusion"], "inconclusive")
        c = self.timed_rounds(3)
        c["rounds"][1]["views"][1]["receipt"]["query"].update(ok=False, error=5, cycle=None, nodes=[])
        a = self.check_series(c)
        self.assertEqual((a["coverage"]["issued_queries"], a["coverage"]["successful_queries"]), (6, 5))
        self.assertEqual(a["repeated_groups"], [])

    def test_series_contradictions_and_retirement(self):
        c = self.timed_rounds(2)
        for change in (
            lambda d: d["rounds"].pop(),
            lambda d: d["rounds"][0]["views"].reverse(),
            lambda d: d["rounds"][0]["views"][1]["timing"].update(reader_tid=d["collector"]["coordinator_tid"]),
            lambda d: d["rounds"][1]["views"][0]["timing"].update(begin="1"),
            lambda d: d["rounds"][1]["views"][1]["receipt"]["discovery"]["nodes"][0].update(context_switches=4294967295),
            lambda d: d["rounds"][0]["views"][0]["receipt"]["process"]["after"].update(result=0),
            lambda d: d["rounds"][-1]["views"][0]["receipt"]["threads"][0]["after"].update(result=0),
        ):
            d = copy.deepcopy(c)
            change(d)
            self.check_series(d, 2)
        conflicting = copy.deepcopy(c)
        row = conflicting["rounds"][-1]
        tick = max(v["receipt"]["query"]["end"] for v in row["views"])
        for i, v in enumerate(row["views"]):
            v["receipt"]["query"].update(start=tick + 4*i, end=tick + 4*i + 1)
            for pin in [v["receipt"]["process"], *v["receipt"]["threads"]]:
                pin["after"]["tick"] = tick + 10
        self.check_series(conflicting, 2)
        row = c["rounds"][1]
        for v in row["views"]:
            v["receipt"]["process"]["after"]["result"] = 0
        self.check_series(c, 2)
        for v in row["views"]:
            for pin in v["receipt"]["threads"]:
                pin["after"]["result"] = 0
        self.check_series(c)
        # Both process handles are now signaled. Preserve an otherwise valid terminal round.
        row = copy.deepcopy(row)
        row.update(dispatch="unavailable", begin_qpc="1500000", end_qpc="1501000")
        tick = max(p["after"]["tick"] for v in row["views"] for p in [v["receipt"]["process"], *v["receipt"]["threads"]])
        row["pause"].update(start=tick, signal={"tick": tick, "result": 0, "error": None})
        for v in row["views"]:
            v["timing"], v["receipt"]["query"] = None, None
            for p in [v["receipt"]["process"], *v["receipt"]["threads"]]:
                for phase in ("before", "after"):
                    p[phase].update(tick=tick, result=0)
        c["rounds"].append(row)
        c["planned_rounds"] = 4
        self.assertEqual(self.check_series(c)["coverage"]["unrecorded_rounds"], 1)
        row["pause"]["signal"]["result"] = WAIT_TIMEOUT
        self.check_series(c, 2)

    def test_diagnosis_native_facts_and_coverage(self):
        def resolve(raw, pointer):
            self.assertTrue(pointer == "" or pointer.startswith("/"))
            for field in pointer.split("/")[1:]:
                raw = raw[int(field) if isinstance(raw, list) else field]
            return raw

        for name in ("one_way", "cycle", "open_series", "closed_series", "triangle_closed_series",
                     "transition", "exit_series", "wrong_thread", "retired_series"):
            raw = self.original[name]
            c, d = json.loads(raw), self.replay(raw, diagnose=True)
            self.assertEqual(d, self.replay(raw, diagnose=True))
            self.assertEqual((d["schema"], d["source_schema"], d["receipt_sha256"]),
                             ("kn.wait_diagnosis.v1", c["schema"], hashlib.sha256(raw).hexdigest()))
            self.assertFalse(any(d[k] for k in ("deadlock_established", "cause_of_hang_established", "intent_assessed",
                                                "whole_host_assessed", "collector_authenticated")))
            cov = d["coverage"]
            self.assertEqual(cov["planned_rounds"], cov["recorded_rounds"] + cov["unrecorded_rounds"])
            self.assertEqual(cov["planned_queries"], cov["issued_queries"] + cov["unissued_queries"])
            cycle, contention = d["candidates"]
            for candidate in d["candidates"]:
                self.assertTrue(candidate["unobserved"] and candidate["next_observation"])
                for index in candidate["supporting_facts"] + candidate["counterevidence"]:
                    self.assertTrue(0 <= index < len(d["facts"]))
            for fact in d["facts"]:
                self.assertTrue(fact["evidence"])
                self.assertTrue(all(resolve(c, p) is not None for p in fact["evidence"]))
            for gap in d["unclassified_views"]:
                self.assertEqual(resolve(c, gap["receipt"])["schema"], "kn.wait_chain.v1")
            if name in ("one_way", "open_series"):
                self.assertEqual(cycle["status"], "insufficient_evidence")
                self.assertEqual(contention["status"], "owned_wait_observed")
            if name in ("cycle", "closed_series", "triangle_closed_series"):
                self.assertEqual(cycle["status"], self.replay(raw)["conclusion"])
                self.assertTrue(cycle["supporting_facts"])
                self.assertFalse(cycle["counterevidence"] or contention["supporting_facts"])
            if name == "transition":
                self.assertTrue(contention["supporting_facts"] and contention["counterevidence"])
            if name == "exit_series":
                self.assertEqual(cycle["status"], "reference_member_or_process_terminated")
                end = d["facts"][cycle["counterevidence"][0]]
                self.assertEqual(resolve(c, end["evidence"][-1])["result"], 0)
                self.assertGreater(end["round"], 1)
                self.assertGreater(d["coverage"]["unissued_queries"], 0)
            if name in ("wrong_thread", "retired_series"):
                self.assertFalse(d["facts"])
                self.assertTrue(d["unclassified_views"])
                self.assertEqual(d["coverage"]["issued_queries"], 0)

    def test_diagnosis_exit_requires_reference_membership(self):
        c = self.timed_rounds(3, "triangle_closed_series")
        primary, peer, third = [t[0] for t in self.triangle["threads"]]
        for r in c["rounds"]:
            for v in r["views"]:
                q = v["receipt"]["query"]
                by_tid = {n["tid"]: n for n in q["nodes"] if n["type"] == 8}
                root = v["receipt"]["requested"]["tid"]
                other = peer if root == primary else primary
                q.update(nodes=[by_tid[root], q["nodes"][1], by_tid[other], q["nodes"][3], by_tid[root]], reported=5)
        def explain():
            return self.replay(json.dumps(c).encode(), diagnose=True)["candidates"][0]

        for v in c["rounds"][-1]["views"]:
            next(p for p in v["receipt"]["threads"] if p["id"] == third)["after"]["result"] = 0
        self.assertEqual(explain()["counterevidence"], [])
        # Retain a thread with the same numeric ID and a different creation on the peer side.
        for r in c["rounds"]:
            other = next(p for p in r["views"][1]["receipt"]["threads"] if p["id"] == primary)
            other["created"] = str(int(other["created"]) + 1)
        other["after"]["result"] = 0
        self.assertEqual(explain()["counterevidence"], [])
        # An unsupported observation and a failed wait still leave persistence undetermined.
        for v in c["rounds"][-1]["views"]:
            q = v["receipt"]["query"]
            q.update(nodes=q["nodes"][:1], reported=1, cycle=False)
        last = c["rounds"][-1]["views"][0]["receipt"]["threads"][0]["after"]
        last.update(result=4294967295, error=6)
        self.assertEqual(explain()["counterevidence"], [])
        last.update(result=0, error=None)
        self.assertEqual(explain()["status"], "reference_member_or_process_terminated")

    def test_diagnosis_incomplete_and_contradictory_chains(self):
        def explain(c):
            return self.replay(json.dumps(c).encode(), diagnose=True)

        c = json.loads(self.original["cycle"])
        c["query"]["cycle"] = False
        d = explain(c)
        self.assertEqual(d["unclassified_views"][0]["reason"], "repeated_thread_without_provider_cycle")
        self.assertFalse(d["facts"])
        c = json.loads(self.original["triangle_one_way"])
        c["query"]["nodes"][-1]["pid"] = 4
        d = explain(c)
        self.assertFalse(d["facts"])
        self.assertEqual(d["unclassified_views"][0]["reason"], "process_scope_boundary")
        series = self.timed_rounds(3, "triangle_closed_series")
        for v in series["rounds"][-1]["views"]:
            nodes = v["receipt"]["query"]["nodes"]
            nodes[2], nodes[4] = nodes[4], nodes[2]
        mixed = explain(series)
        cause = mixed["candidates"][0]
        self.assertEqual(cause["status"], "multiple_cycle_configurations_observed")
        self.assertEqual([mixed["facts"][i]["kind"] for i in cause["counterevidence"]], ["different_cycle_observed_in_traversal"] * 2)
        c = json.loads(self.original["triangle_cycle"])
        c["query"]["nodes"][-1] = c["query"]["nodes"][2]
        d = explain(c)
        self.assertFalse(d["facts"])
        self.assertEqual(d["unclassified_views"][0]["reason"], "cycle_excludes_primary_generation")
        self.replay(json.dumps(d).encode(), expected=2, diagnose=True)
        self.replay(self.original["cycle"], expected=2, pin="0" * 64, diagnose=True)

    def test_series_invalid_requests(self):
        argv = series_args(self.exe, self.target, 2, 1)
        for i, values in ((6, ("--unknown",)), (7, (argv[4], "0")), (8, ("0",)), (9, ("1", "9")), (10, ("0", "5001"))):
            for value in values:
                bad = argv.copy()
                bad[i] = value
                run(bad, 2)
        run(argv[:-1], 2)
        self.replay(b" " * (512 * 1024 + 1), 2)

    def test_owned_native_and_offline(self):
        waits = self.target["threads"]
        for name, closed in (("one_way", False), ("cycle", True)):
            raw = self.original[name]
            c = json.loads(raw)
            q = c["query"]
            expected_threads = waits + waits[:1] if closed else waits
            states = q["nodes"]
            self.assertEqual([n["tid"] for n in states[::2]], [p[0] for p in expected_threads])
            self.assertTrue(all(n["pid"] == self.target["pid"] for n in states[::2]))
            self.assertTrue(all((n["type"], n["status"]) == (3, 6) for n in states[1::2]))
            self.assertEqual([(p["id"], p["created"]) for p in c["threads"]], [tuple(p) for p in waits])
            for p in (c["process"], *c["threads"]):
                self.assertTrue(all(p[k]["result"] == WAIT_TIMEOUT for k in ("initial", "before", "after")))
                self.assertLessEqual(p["before"]["tick"], q["start"])
                self.assertGreaterEqual(p["after"]["tick"], q["end"])
            a = self.replay(raw)
            self.assertEqual(a, self.replay(raw))
            self.assertEqual(a["conclusion"], "potential_wait_cycle" if closed else "inconclusive")
            self.assertEqual(a["provider_cycle"], closed)
            self.assertFalse(a["deadlock_established"] or a["atomic_snapshot"] or a["whole_host_assessed"])
            self.assertEqual((a["wait_timeout"], a["cancellation"]), ("unknown", "unknown"))
            self.assertEqual(a["observation_interval"], [q["start"], q["end"]])
            edges = a["edges"]
            self.assertEqual([e["relation"] for e in edges], ["waits_for", "owned_by"] * (2 if closed else 1))
            for i, e in enumerate(edges):
                self.assertEqual(e["node_indices"], [i, i+1])
                self.assertEqual(e["evidence"][:2], [f"/query/nodes/{i}", f"/query/nodes/{i+1}"])
                binding = e["evidence"][3]
                self.assertEqual((c["threads"][int(binding.split("/")[-1])]["created"], e["evidence"][2]),
                                 (e["thread_created"], "/process"))
                k = i if i % 2 == 0 else i+1
                self.assertEqual([e["thread_id"], e["thread_created"]], expected_threads[k//2])
            if closed:
                self.assertEqual(a["potential_cycle"]["node_indices"], list(range(5)))
            else:
                self.assertIsNone(a["potential_cycle"])

    def test_admission_and_identity_loss(self):
        invalid = run([self.exe, "--wait-chain", "4294967295", "1", "1", "1"])
        receipt = json.loads(invalid)
        self.assertEqual(receipt["process"]["failure"], "open")
        self.assertIsInstance(receipt["process"]["error"], int)
        self.assertIsNone(receipt["session"])
        self.assertEqual(self.replay(invalid)["edges"], [])
        for k in ("wrong_process", "wrong_thread", "retired"):
            c = json.loads(self.original[k])
            self.assertIsNone(c["session"])
            self.assertIsNone(c["query"])
            self.assertEqual(self.replay(self.original[k])["edges"], [])
        for which in ("process", "root", "owner"):
            def expire(c):
                p = c["process"] if which == "process" else c["threads"][int(which == "owner")]
                p["after"]["result"] = 0
            report = self.altered(expire)
            self.assertEqual(report["conclusion"], "inconclusive")
            if which != "owner":
                self.assertEqual(report["edges"], [])

    def test_scope_and_evidence_boundaries(self):
        def foreign_prefix(c):
            q = c["query"]
            prefix = copy.deepcopy(q["nodes"][:4])
            prefix[2]["pid"] = 4
            q["nodes"] = prefix + q["nodes"]
            q["reported"] = len(q["nodes"])
        foreign = self.altered(foreign_prefix)
        self.assertEqual((foreign["conclusion"], foreign["scope_boundary"]),
                         ("inconclusive", {"node_index": 2, "reason": "process_scope_boundary"}))
        self.assertTrue(all(max(e["node_indices"]) < 2 for e in foreign["edges"]))

        def shorten_final(c):
            q = c["query"]
            q.update(reported=3, nodes=q["nodes"][:3], cycle=False)
        separate = self.altered(shorten_final)
        self.assertEqual((separate["conclusion"], len(separate["edges"])), ("inconclusive", 2))

        def self_wait(c):
            q = c["query"]
            q.update(reported=3, nodes=[q["nodes"][0], q["nodes"][1], q["nodes"][0]])
        self.assertIsNone(self.altered(self_wait)["potential_cycle"])
        for change in (
            lambda c: c["query"].update(cycle=False),
            lambda c: c["query"]["nodes"][1].update(type=7),
            lambda c: c["query"]["nodes"][1].update(status=7),
            lambda c: c["query"]["nodes"][2].update(status=1),
            lambda c: c["query"]["nodes"][-1].update(tid=c["threads"][1]["id"]),
        ):
            self.assertEqual(self.altered(change)["conclusion"], "inconclusive")

    def test_lock_semantics_and_unbound_owner(self):
        def critical_sections(c):
            for node in c["query"]["nodes"][1::2]:
                node["type"] = 1
        replayed = self.altered(critical_sections)
        self.assertEqual(replayed["conclusion"], "potential_wait_cycle")
        self.assertTrue(all(e["lock_semantics"] == "critical_section" for e in replayed["edges"]))

        def missing_pin(c):
            c["query"]["nodes"][2]["tid"] = next(i for i in range(1, 5) if i not in {p["requested"] for p in c["threads"]})
        clipped = self.altered(missing_pin)
        self.assertEqual(clipped["scope_boundary"], dict(node_index=2, reason="thread_binding_or_status_unavailable"))
        self.assertIsNone(clipped["potential_cycle"])

    def test_partial_and_unsupported(self):
        def truncate(c):
            c["query"].update(ok=False, error=565, cycle=None)
        partial = self.altered(truncate)
        self.assertEqual((partial["reason"], partial["traversal_error"], partial["edges"]), ("partial_traversal", 565, []))
        def single(c):
            q = c["query"]
            q.update(cycle=False, reported=1, nodes=q["nodes"][:1])
        self.assertEqual(self.altered(single)["reason"], "single_thread_or_unsupported_wait")
        def failed(c):
            c["query"].update(ok=False, error=5, cycle=None, nodes=[])
        a = self.altered(failed)
        self.assertEqual((a["traversal_error"], a["edges"]), (5, []))

    def test_contradictions_and_cli(self):
        for change in (
            lambda c: c["requested"].update(pid=True),
            lambda c: c["threads"].reverse(),
            lambda c: c["threads"][0]["before"].update(tick=c["query"]["end"] + 1),
            lambda c: c["query"].update(reported=32),
            lambda c: c["query"].update(cycle=None),
            lambda c: c["process"].update(error=5),
            lambda c: c.update(query=None),
            lambda c: c.update(flags=1),
        ):
            self.altered(change, 2)
        raw = self.original["cycle"]
        self.replay(raw, 2, "0" * 64)
        self.replay(raw.replace(b'"flags":0', b'"flags":0,"flags":0'), 2)
        self.replay(b" " * 65537, 2)
        run([self.exe, "--wait-chain", "4294967296", "1", "1", "1"], 2)
        run([self.exe, "--wait-chain", "1", "1", "-1", "1"], 2)
        run([self.exe, "--wait-chain"], 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--keep", type=Path, help="save the original owned receipts in a new directory")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--participants", type=int, choices=(2, 3), default=2, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        return child(args.participants)
    if not args.exe:
        parser.error("--exe is required")
    with tempfile.TemporaryDirectory(prefix="kn-wct-") as work:
        WaitTests.folder = Path(work)
        WaitTests.exe = args.exe.resolve(strict=True)
        WaitTests.target, WaitTests.original = acquire(WaitTests.exe, 2)
        WaitTests.triangle, triangle = acquire(WaitTests.exe, 3)
        WaitTests.original.update({"triangle_" + name: data for name, data in triangle.items()})
        if args.keep:
            args.keep.mkdir()
            for name, data in WaitTests.original.items():
                (args.keep / (name + ".json")).write_bytes(data)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(WaitTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
