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


def child():
    locks = [mutex(None, False, None) for _ in range(2)]
    if not all(locks):
        raise c.WinError(c.get_last_error())
    ids, outcomes = [None, None], [None, None]
    ready = threading.Barrier(3, timeout=10)
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
            if i == 1 and (not phase.wait(35) or command != ["cycle"]):
                return
            outcomes[i] = wait(locks[1-i], 6000 if i else 50000)
            if outcomes[i] == 0 and not release(locks[1-i]):
                raise c.WinError(c.get_last_error())
        finally:
            if not release(locks[i]):
                raise c.WinError(c.get_last_error())

    workers = [threading.Thread(target=work, args=(i,)) for i in (0, 1)]
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
    return 0 if outcomes == [0, WAIT_TIMEOUT] else 1


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


def acquire(exe):
    with subprocess.Popen([sys.executable, "-E", "-s", "-B", str(HERE), "--child"],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
        try:
            line = queue.Queue()
            threading.Thread(target=lambda: line.put(p.stdout.readline()), daemon=True).start()
            target = json.loads(line.get(timeout=12))
            one_way = observe_until(exe, target, False)
            wrong = capture(exe, target, pc=str(int(target["process_created"]) + 1))
            other_thread = capture(exe, target, tc=str(int(target["threads"][0][1]) + 1))
            p.stdin.write(b"cycle\n")
            p.stdin.flush()
            cycle = observe_until(exe, target, True)
            out, err = p.communicate(timeout=12)
            if p.returncode or json.loads(out) != [0, WAIT_TIMEOUT]:
                raise AssertionError(f"fixture outcomes differ: {p.returncode}, {out[:100]!r}, {err[-300:]!r}")
        finally:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=10)
    retired = capture(exe, target)
    return target, dict(one_way=one_way, cycle=cycle, wrong_process=wrong, wrong_thread=other_thread, retired=retired)


class WaitTests(unittest.TestCase):
    def replay(self, raw, expected=0, pin=None):
        path = self.folder / "review.json"
        path.write_bytes(raw)
        result = run([sys.executable, "-E", "-s", "-B", str(REPLAY), path, "--sha256",
                      pin or hashlib.sha256(raw).hexdigest()], expected)
        return json.loads(result) if result else None

    def altered(self, change, expected=0):
        c = json.loads(self.original["cycle"])
        change(c)
        return self.replay(json.dumps(c, separators=(",", ":")).encode(), expected)

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
    args = parser.parse_args()
    if args.child:
        return child()
    if not args.exe:
        parser.error("--exe is required")
    with tempfile.TemporaryDirectory(prefix="kn-wct-") as work:
        WaitTests.folder = Path(work)
        WaitTests.exe = args.exe.resolve(strict=True)
        WaitTests.target, WaitTests.original = acquire(WaitTests.exe)
        if args.keep:
            args.keep.mkdir()
            for name, data in WaitTests.original.items():
                (args.keep / (name + ".json")).write_bytes(data)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(WaitTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
