"""Exercise the Windows notification provider with owned directories and replay the original journal."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import unittest


HERE = Path(__file__).resolve().parent
ABORTED, INCOMPLETE, TIMEOUT, FAILED = 995, 996, 258, 0xffffffff


def command(args, code=0):
    p = subprocess.run(list(map(str, args)), capture_output=True, timeout=20)
    if p.returncode != code or (code and p.stdout):
        raise AssertionError(f"exit {p.returncode}, expected {code}: {p.stderr[-300:]!r}")
    return p.stdout


def verify_declined_handle_closed(path):
    # A rejected regular file must be available for an exclusive open while admitted reads are pending.
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_file = kernel.CreateFileW
    open_file.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                          wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    open_file.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes, close.restype = (wintypes.HANDLE,), wintypes.BOOL
    handle = open_file(str(path), 0x40000000, 0, None, 3, 0, None)  # GENERIC_WRITE, OPEN_EXISTING, no sharing
    if handle == ctypes.c_void_p(-1).value or not close(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def completion_during_cancel(exe, directory):
    import ctypes
    from ctypes import wintypes
    import msvcrt
    import os

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreatePipe
    create.argtypes = (ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD)
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    read_end, write_end = wintypes.HANDLE(), wintypes.HANDLE()
    if not create(ctypes.byref(read_end), ctypes.byref(write_end), None, 1):
        raise ctypes.WinError(ctypes.get_last_error())

    def adopt(handle, flags, mode):
        fd = msvcrt.open_osfhandle(handle.value, flags | os.O_BINARY)
        handle.value = None
        return os.fdopen(fd, mode, buffering=0)

    try:
        with adopt(read_end, os.O_RDONLY, "rb") as reader, adopt(write_end, os.O_WRONLY, "wb") as writer:
            with subprocess.Popen([str(exe), "--io-lifecycle", "45", str(directory)], stdout=writer, stderr=subprocess.PIPE) as child:
                writer.close()
                timer = threading.Timer(12, child.kill)
                timer.start()
                data, line = bytearray(), bytearray()
                changed = False
                try:
                    while byte := reader.read(1):
                        data.extend(byte)
                        line.extend(byte)
                        # The one-byte pipe holds the producer inside its timeout record. More than
                        # one byte of that record still has to be consumed before CancelIoEx can run.
                        if not changed and b'"kind":"wait"' in line and line.endswith(b'"result":258,'):
                            (directory / "won-the-race.txt").touch()
                            changed = True
                        if byte == b"\n":
                            line.clear()
                    child.wait(timeout=3)
                    if not changed or child.returncode:
                        raise AssertionError("collector did not reach the observed timeout boundary")
                    return bytes(data)
                finally:
                    timer.cancel()
                    if child.poll() is None:
                        child.kill()
                        child.wait()
    finally:
        for handle in (read_end, write_end):
            if handle.value:
                close(handle)


def shared_change(exe, directory):
    directory.mkdir()
    raw = bytearray()
    with subprocess.Popen([str(exe), "--io-lifecycle", "3500", str(directory), str(directory)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        timer = threading.Timer(12, child.kill)
        timer.start()
        try:
            for line in child.stdout:
                raw.extend(line)
                if json.loads(line)["kind"] == "monitor":
                    (directory / "both-watchers.txt").touch(exist_ok=False)
            if child.wait(timeout=3) != 0:
                raise AssertionError("shared directory notification capture failed")
        finally:
            timer.cancel()
            if child.poll() is None:
                child.kill()
                child.wait()
    return bytes(raw)


def capture(exe, folder):
    import ctypes
    clock = ctypes.WinDLL("kernel32").GetTickCount64
    clock.restype = ctypes.c_uint64
    stimulus = {1: {}, 2: {}}
    dirs = [folder / n for n in ("first", "second", "quiet")]
    for d in dirs:
        d.mkdir()
    file = folder / "plain-file"
    file.touch()
    names = ["later.txt", "first-notification-\uac00.txt"]
    original = []
    with subprocess.Popen([str(exe), "--io-lifecycle", "3500", *map(str, dirs), str(folder / "missing"), str(file)],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        lines = queue.Queue()
        def read_lines():
            for line in child.stdout:
                lines.put(line)
            lines.put(b"")
        pump = threading.Thread(target=read_lines, daemon=True)
        pump.start()
        try:
            while line := lines.get(timeout=12):
                original.append(line)
                r = json.loads(line)
                if r["kind"] == "wait" and r["result"] < len(r["generations"]):
                    generation = r["generations"][r["result"]]
                    stimulus[generation]["signal_report_received"] = clock()
                if r["kind"] == "monitor":
                    verify_declined_handle_closed(file)
                    stimulus[2]["before_change"] = clock()
                    (dirs[1] / names[1]).touch()
                if r["kind"] == "release" and r["generation"] == 2:
                    stimulus[1]["before_change"] = clock()
                    (dirs[0] / names[0]).touch()
            child.wait(timeout=5)
            if child.returncode:
                raise AssertionError(f"native acquisition failed: {child.stderr.read()[-300:]!r}")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            pump.join(timeout=5)
    same = command([exe, "--io-lifecycle", 40, dirs[0], dirs[0]])
    raced = completion_during_cancel(exe, dirs[2])
    both = shared_change(exe, folder / "shared")
    return dict(ordered=b"".join(original), same_directory=same, cancel_race=raced, shared_change=both), dirs, names, stimulus


def encode(rows):
    return b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in rows)


def timed_control(raw, base=100, same_tick=False):
    rows = list(map(json.loads, raw.splitlines()))
    rows[0]["wait_ms"] = 1
    for n, r in enumerate(rows):
        start = base if same_tick else base + n * 4
        r["tick"] = start if same_tick else start + 2
        if "start" in r:
            r["start"] = start
        if r["kind"] == "monitor":
            epoch = r["tick"]
        if r["kind"] == "wait":
            r["timeout_ms"] = max(0, rows[0]["wait_ms"] - (start - epoch))
    return rows


def possible_signal_ticks(rows, generation):
    # Enumerate hidden issue and signal ticks. A non-resetting private event
    # must be able to satisfy each check at some instant in its call window.
    submit = next(r for r in rows if r["kind"] == "submit" and r["generation"] == generation)
    checks = []
    for r in rows:
        if r["kind"] == "wait" and generation in r["generations"]:
            if r["result"] == TIMEOUT:
                checks.append((False, range(r["start"], r["tick"] + 1)))
            elif r["result"] < len(r["generations"]) and generation == r["generations"][r["result"]]:
                checks.append((True, range(r["start"], r["tick"] + 1)))
        if r["generation"] == generation and r["kind"] in ("probe", "result") and r["event_result"] in (0, TIMEOUT):
            checks.append((r["event_result"] == 0, range(r["start"], r["tick"] + 1)))
        if r["generation"] == generation and r["kind"] == "release" and r["quiesce_result"] == 0:
            checks.append((True, [r["tick"]]))
    states = []
    for issue in range(submit["start"], submit["tick"] + 1):
        for signal in range(issue, rows[-1]["tick"] + 1):
            if all(any(t >= signal for t in window) if positive else any(t <= signal for t in window)
                   for positive, window in checks):
                states.append((issue, signal))
    return states


class IoTests(unittest.TestCase):
    def replay(self, raw, code=0, pin=None, *, timing=False):
        p = self.folder / "review.jsonl"
        p.write_bytes(raw)
        run = command([sys.executable, "-I", "-B", HERE / "replay-io-lifecycle.py", p,
                       "--sha256", pin or hashlib.sha256(raw).hexdigest(), *(["--timing"] if timing else [])], code)
        return json.loads(run) if run else None

    def test_native_order_identity_and_outcomes(self):
        data = self.raw["ordered"]
        raw = list(map(json.loads, data.splitlines()))
        a = self.replay(data)
        self.assertEqual(a, self.replay(data))
        self.assertTrue(a["journal_complete"])
        self.assertEqual(a["provider"]["pid"], raw[0]["pid"])
        self.assertEqual(a["receipt_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual([r["seq"] for r in raw], list(range(len(raw))))
        self.assertEqual({r["run"] for r in raw}, {a["provider"]["run"]})
        admitted = [r for r in raw if r["kind"] == "admit"]
        for slot, directory in zip(admitted, self.dirs):
            self.assertEqual(int.from_bytes(bytes.fromhex(slot["file_id"]), "little"), directory.stat().st_ino)
        self.assertTrue(all(r["stage"] != "ready" for r in admitted[3:]))
        waits = [r for r in raw if r["kind"] == "wait"]
        self.assertEqual([r["generations"][r["result"]] for r in waits if r["result"] != TIMEOUT], [2, 1])
        self.assertEqual((waits[-1]["result"], waits[-1]["generations"]), (TIMEOUT, [3]))
        self.assertEqual([op["outcome"] for op in a["requests"]],
                         ["completed", "completed", "operation_aborted", "UnknownOutcome", "UnknownOutcome"])
        for op, name in zip(a["requests"], self.names):
            size = op["observed_completion"]["bytes"]
            minimum = 12 + len(name.encode("utf-16-le"))  # FILE_NOTIFY_INFORMATION with one new entry.
            self.assertTrue(minimum <= size <= (minimum + 3) // 4 * 4, (size, minimum))
        self.assertEqual(a["requests"][2]["native_final_result"]["win32_error"], ABORTED)
        self.assertEqual(a["coverage"], dict(planned=5, admitted=3, submit_intents=3, returned_submissions=3, queued=3,
                                              pending_observed=3, cancellation_attempts=1, known_outcomes=3,
                                              retired_with_known_outcome=3, unknown_outcomes=2))
        for op in a["requests"]:
            for phase, line in op["observation_lines"].items():
                self.assertEqual((raw[line-1]["generation"], raw[line-1]["kind"]), (op["generation"], phase))
            for state in op["states"]:
                for line in state["evidence_lines"]:
                    self.assertIn(raw[line-1]["generation"], (0, op["generation"]))
        self.assertFalse(a["kernel_dispatch_observed"] or a["kernel_irp_generation_bound"] or a["cross_capture_joins"])
        self.assertNotIn(str(self.folder).encode(), data)
        self.assertNotIn(self.names[0].encode(), data)

    def test_live_completion_after_wait_timeout(self):
        data = self.raw["cancel_race"]
        rows = list(map(json.loads, data.splitlines()))
        report = self.replay(data)
        request = report["requests"][0]
        wait = next(r for r in rows if r["kind"] == "wait")
        cancel = rows[request["observation_lines"]["cancel"]-1]
        result = rows[request["observation_lines"]["result"]-1]
        self.assertEqual(wait["result"], TIMEOUT)
        self.assertLess(wait["seq"], cancel["seq"])
        self.assertLess(cancel["seq"], result["seq"])
        self.assertIn((cancel["ok"], cancel["error"]), ((True, None), (False, 1168)))
        self.assertTrue(result["ok"])
        size = 12 + len("won-the-race.txt".encode("utf-16-le"))
        self.assertTrue(size <= result["bytes"] <= (size + 3) // 4 * 4)
        self.assertEqual((request["outcome"], report["coverage"]["retired_with_known_outcome"]), ("completed", 1))

    def test_same_directory_has_separate_requests(self):
        raw = list(map(json.loads, self.raw["same_directory"].splitlines()))
        a = self.replay(self.raw["same_directory"])
        b = self.replay(self.raw["ordered"])
        self.assertNotEqual(a["provider"]["run"], b["provider"]["run"])
        ids = [(r["volume"], r["file_id"]) for r in raw if r["kind"] == "admit"]
        self.assertEqual(ids[0], ids[1])
        self.assertEqual([r["generation"] for r in raw if r["kind"] == "cancel"], [1, 2])
        self.assertEqual([r["generation"] for r in raw if r["kind"] == "result"], [1, 2])
        self.assertEqual([o["observed_completion"]["win32_error"] for o in a["requests"]], [ABORTED, ABORTED])
        self.assertEqual(a["coverage"]["retired_with_known_outcome"], 2)
        maximum = self.replay(command([self.exe, "--io-lifecycle", 1, *([self.dirs[2]] * 8)]))
        self.assertEqual(maximum["coverage"]["retired_with_known_outcome"], 8)
        self.assertEqual([op["outcome"] for op in maximum["requests"]], ["operation_aborted"] * 8)

    def test_interrupted_and_missing_records(self):
        rows = list(map(json.loads, self.raw["ordered"].splitlines()))
        cancel = next(i for i, r in enumerate(rows) if r["kind"] == "cancel")
        prefix = encode(rows[:cancel+1])
        partial = self.replay(prefix + b'{"schema":"kn.io_lifetime.')
        self.assertEqual(partial["qualified_prefix_lines"], cancel + 1)
        self.assertGreater(partial["trailing_bytes"], 0)
        self.assertFalse(partial["journal_complete"])
        self.assertEqual((partial["coverage"]["known_outcomes"], partial["requests"][2]["outcome"]), (2, "UnknownOutcome"))
        self.assertIsNone(partial["requests"][2]["resources_released"])
        resolved = self.replay(encode(rows[:cancel+2]))
        self.assertEqual((resolved["coverage"]["known_outcomes"], resolved["coverage"]["retired_with_known_outcome"]), (3, 2))
        delayed = self.replay(encode(rows[:cancel] + rows[cancel+1:]))
        self.assertEqual(delayed["missing_sequences"], [dict(first_missing=cancel, last_missing=cancel, next_line=cancel+1)])
        self.assertEqual(delayed["requests"][2]["outcome"], "UnknownOutcome")
        self.assertEqual(delayed["unjoined_records"][0]["kind"], "result")
        at_plan = self.replay(encode(rows[:1]))
        self.assertEqual((at_plan["coverage"]["planned"], at_plan["coverage"]["unknown_outcomes"]), (5, 5))

    def test_cancel_race_and_unconfirmed_outcomes(self):
        original = list(map(json.loads, self.raw["same_directory"].splitlines()))
        for accepted in (True, False):
            rows = copy.deepcopy(original)
            cancel = next(r for r in rows if r["kind"] == "cancel")
            cancel.update(ok=accepted, error=None if accepted else 1168)  # ERROR_NOT_FOUND can race normal completion.
            result = next(r for r in rows if r["kind"] == "result")
            result.update(ok=True, error=None, bytes=24)
            a = self.replay(encode(rows))
            self.assertEqual([op["outcome"] for op in a["requests"]], ["completed", "operation_aborted"])
            result["bytes"] = 0
            self.assertEqual(self.replay(encode(rows))["requests"][0]["outcome"], "completed_without_change_details")
        rows = copy.deepcopy(original)
        result = next(r for r in rows if r["kind"] == "result")
        result.update(ok=False, error=5, bytes=None)
        a = self.replay(encode(rows))
        self.assertEqual((a["requests"][0]["outcome"], a["requests"][0]["native_final_result"]["win32_error"]), ("UnknownOutcome", 5))
        rows = copy.deepcopy(original)
        release = next(r for r in rows if r["kind"] == "release")
        release.update(quiesce_result=FAILED, quiesce_error=6, close_attempted=False)
        a = self.replay(encode(rows))
        self.assertEqual((a["coverage"]["known_outcomes"], a["coverage"]["retired_with_known_outcome"]), (2, 1))
        self.assertFalse(a["requests"][0]["resources_released"])

    def test_submission_failure_and_early_result(self):
        rows = list(map(json.loads, self.raw["same_directory"].splitlines()))
        by_kind = {r["kind"]: r for r in rows if r["generation"] == 1}
        plan = dict(rows[0], requests=1)
        failed = dict(by_kind["submit"], ok=False, error=1)
        release = dict(by_kind["release"], quiesce_result=None)
        monitor = dict(next(r for r in rows if r["kind"] == "monitor"), tick=release["tick"])
        ordered = [plan, by_kind["admit"], by_kind["issue"], failed, release, monitor, rows[-1]]
        a = self.replay(encode([dict(r, seq=i) for i, r in enumerate(ordered)]))
        self.assertEqual((a["coverage"]["returned_submissions"], a["coverage"]["queued"], a["coverage"]["known_outcomes"]), (1, 0, 0))
        self.assertEqual(a["requests"][0]["outcome"], "UnknownOutcome")
        timing = self.replay(encode([dict(r, seq=i) for i, r in enumerate(ordered)]), timing=True)
        self.assertEqual((timing["requests"][0]["status"], timing["signal_order"]["possible_latest_generations"]), ("submission_failed", []))
        rows = list(map(json.loads, self.raw["ordered"].splitlines()))
        # Complete the first selected event early, preserving the native wait-any ordering.
        selected = next(r for r in rows if r["kind"] == "wait")
        first = selected["generations"][selected["result"]]
        probe = next(r for r in rows if r["kind"] == "probe" and r["generation"] == first)
        final = next(r for r in rows if r["kind"] == "result" and r["generation"] == probe["generation"])
        for k in ("ok", "error", "bytes", "event_result"):
            probe[k] = final[k]
        a = self.replay(encode(rows))
        op = a["requests"][first-1]
        self.assertNotIn("PendingObserved", [s["state"] for s in op["states"]])
        self.assertEqual(op["outcome"], "completed")
        for r in (probe, final):
            r.update(ok=False, error=1022, bytes=None)
        self.assertEqual(self.replay(encode(rows))["requests"][first-1]["outcome"], "changes_require_enumeration")

    def test_conflicting_completion_witnesses(self):
        rows = list(map(json.loads, self.raw["ordered"].splitlines()))
        probe = next(r for r in rows if r["kind"] == "probe" and r["generation"] == 1)
        probe.update(ok=True, error=None, bytes=7, event_result=0)
        op = self.replay(encode(rows))["requests"][0]
        self.assertEqual(op["outcome"], "UnknownOutcome")
        conflicts = [[rows[i-1]["kind"] for i in s["evidence_lines"]] for s in op["states"] if s["state"] == "IdentityConflict"]
        self.assertIn(["probe", "result"], conflicts)
        self.assertIn(["probe", "wait"], conflicts)
        final = next(r for r in rows if r["kind"] == "result" and r["generation"] == 1)
        probe.update(ok=False, error=INCOMPLETE, bytes=None, event_result=TIMEOUT)
        final["event_result"] = TIMEOUT
        op = self.replay(encode(rows))["requests"][0]
        self.assertEqual(op["outcome"], "UnknownOutcome")
        conflict = next(s for s in op["states"] if s["state"] == "IdentityConflict")
        self.assertEqual([rows[i-1]["kind"] for i in conflict["evidence_lines"]], ["wait", "result"])

    def test_wrong_run_reuse_and_cli(self):
        original = list(map(json.loads, self.raw["ordered"].splitlines()))
        end = original[-1]
        late = dict(end, seq=end["seq"] + 1, kind="cancel", generation=1, start=end["tick"], ok=True, error=None)
        self.replay(encode(original[:-1] + [late, dict(end, seq=late["seq"]+1)]), 2)
        for kind, updates in (("probe", {"run": "f"*32}), ("wait", {"generations": [1, 1]}),
                              ("wait", {"timeout_ms": 30001}), ("result", {"generation": 3}),
                              ("result", {"bytes": 4097}), ("result", {"start": 0}), ("release", {"quiesce_result": None})):
            rows = copy.deepcopy(original)
            next(r for r in rows if r["kind"] == kind).update(updates)
            self.replay(encode(rows), 2)
        self.replay(self.raw["ordered"] + b"tail", 2)
        self.replay(self.raw["ordered"], 2, "f" * 64)
        self.replay(b" " * (128 * 1024 + 1), 2)
        for args in ([], ["0", self.folder], ["30001", self.folder], ["1", *([self.folder] * 9)]):
            command([self.exe, "--io-lifecycle", *args], 2)
        denied = self.replay(command([self.exe, "--io-lifecycle", 1, r"\\.\NUL"]))
        self.assertEqual(denied["requests"][0]["admission"]["stage"], "path_policy")
        self.assertEqual(denied["coverage"]["submit_intents"], 0)

    def test_reader_disconnect_releases_owned_requests(self):
        with subprocess.Popen([str(self.exe), "--io-lifecycle", "300", str(self.dirs[0])],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            timer = threading.Timer(12, child.kill)
            timer.start()
            try:
                while line := child.stdout.readline():
                    if json.loads(line)["kind"] == "monitor":
                        break
                else:
                    self.fail("collector exited before it announced outstanding work")
                child.stdout.close()
                self.assertEqual(child.wait(timeout=10), 1)
            finally:
                timer.cancel()
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_owned_signal_windows_and_shared_wait_cost(self):
        raw = self.raw["ordered"]
        rows = list(map(json.loads, raw.splitlines()))
        q = self.replay(raw, timing=True)
        self.assertEqual(q["schema"], "kn.io_lifetime_timing.v1")
        self.assertEqual(q["receipt_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(q["coverage"], dict(planned=5, accepted=3, known_outcomes=3, bounded_signals=3, right_censored=0, conflicts=0))
        self.assertEqual(self.replay(raw, timing=True), q)
        self.assertLessEqual(self.stimulus[2]["signal_report_received"], self.stimulus[1]["before_change"])
        for g, witness in self.stimulus.items():
            w = q["requests"][g-1]["signal_window"]
            self.assertLessEqual(int(w["not_before"]["tick_ms"]), witness["signal_report_received"])
            self.assertGreaterEqual(int(w["not_after"]["tick_ms"]), witness["before_change"])
            for endpoint in w.values():
                row = rows[endpoint["evidence_line"]-1]
                self.assertEqual(row[endpoint["tick_field"]], int(endpoint["tick_ms"]))
        self.assertEqual([r["status"] for r in q["requests"][3:]], ["admission_unavailable"] * 2)
        self.assertEqual(q["signal_order"]["possible_latest_generations"], [3])
        edges = [(e["earlier_generation"], e["later_generation"]) for e in q["signal_order"]["proven_precedences"]]
        self.assertEqual(edges, [(1, 3), (2, 3)])
        monitor = q["monitor"]
        waits = [row for row in rows if row["kind"] == "wait"]
        self.assertEqual([w["selected_generation"] for w in monitor["waits"]], [2, 1, None])
        self.assertEqual(int(monitor["wait_call_ms"]), sum(r["tick"] - r["start"] for r in waits))
        self.assertEqual(int(monitor["wait_call_ms"]) + int(monitor["outside_wait_calls_ms"]), int(monitor["elapsed_ms"]))
        self.assertFalse(q["kernel_service_time_observed"] or q["cross_capture_joins"])
        same = self.replay(self.raw["same_directory"], timing=True)
        self.assertEqual(same["signal_order"]["possible_latest_generations"], [1, 2])
        self.assertEqual(same["signal_order"]["proven_precedences"], [])
        self.assertEqual(same["monitor"]["wait_call_ms"], same["monitor"]["waits"][0]["elapsed_ms"])
        race = self.replay(self.raw["cancel_race"], timing=True)["requests"][0]
        self.assertIsNotNone(race["cancellation"])
        self.assertEqual(race["outcome"], "completed")

    def test_exhaustive_latency_bounds_and_clock_ties(self):
        for base in (100, (1 << 64) - 1000):
            rows = timed_control(self.raw["same_directory"], base)
            q = self.replay(encode(rows), timing=True)
            for g in (1, 2):
                states = possible_signal_ticks(rows, g)
                durations = [signal - issue for issue, signal in states]
                request = q["requests"][g-1]
                self.assertEqual(request["submission_to_signal_ms"], dict(minimum=str(min(durations)), maximum=str(max(durations))))
                self.assertEqual([int(request["signal_window"][side]["tick_ms"]) for side in ("not_before", "not_after")],
                                 [min(s for _, s in states), max(s for _, s in states)])
            self.assertEqual(q["monitor"]["wait_call_ms"], "2")
        tied = timed_control(self.raw["ordered"], base=42, same_tick=True)
        q = self.replay(encode(tied), timing=True)
        self.assertEqual(q["signal_order"]["possible_latest_generations"], [3])
        self.assertTrue(all(r["submission_to_signal_ms"] == dict(minimum="0", maximum="0") for r in q["requests"][:3]))
        self.assertEqual({(e["earlier_generation"], e["later_generation"]) for e in q["signal_order"]["proven_precedences"]}, {(1, 3), (2, 3)})

    def test_one_change_signals_two_requests(self):
        data = self.raw["shared_change"]
        q = self.replay(data, timing=True)
        self.assertCountEqual([w["selected_generation"] for w in q["monitor"]["waits"]], [1, 2])
        self.assertTrue(all(r["outcome"] == "completed" and r["resources_released"] for r in q["requests"]))
        expected = 12 + len("both-watchers.txt".encode("utf-16-le"))
        for r in q["requests"]:
            self.assertTrue(expected <= r["native_final_result"]["bytes"] <= (expected + 3) // 4 * 4)
        self.assertNotIn(b"both-watchers.txt", data)
        self.assertEqual(q["signal_order"], dict(status="order_unresolved", possible_latest_generations=[1, 2], proven_precedences=[]))

    def test_gaps_censoring_and_unobserved_monitor(self):
        rows = timed_control(self.raw["ordered"])
        q = self.replay(encode(rows[:1]), timing=True)
        self.assertIsNone(q["monitor"]["wait_call_ms"])
        self.assertTrue(all(r["status"] == "admission_unobserved" for r in q["requests"]))
        select = next(i for i, r in enumerate(rows) if r["kind"] == "wait")
        q = self.replay(encode(rows[:select+1]), timing=True)
        self.assertEqual(q["requests"][1]["outcome"], "UnknownOutcome")
        self.assertEqual(q["requests"][1]["signal_window"]["not_after"]["evidence_line"], select+1)
        self.assertEqual(q["coverage"]["right_censored"], 2)
        self.assertIsNone(q["requests"][0]["submission_to_signal_ms"]["maximum"])
        self.assertIsNone(q["signal_order"]["possible_latest_generations"])
        broken = self.replay(encode(rows[:select] + rows[select+1:]), timing=True)
        self.assertEqual((broken["coverage"]["bounded_signals"], broken["coverage"]["right_censored"]), (0, 3))
        self.assertTrue(broken["unjoined_records"])
        partial = self.replay(encode(rows[:select]) + b'{"incomplete"', timing=True)
        self.assertGreater(partial["trailing_bytes"], 0)
        self.assertEqual(partial["monitor"]["waits"], [])
        excluded = [rows[0], next(r for r in rows if r["kind"] == "admit" and r["stage"] != "ready"),
                    next(r for r in rows if r["kind"] == "monitor"), rows[-1]]
        excluded = [dict(r, seq=i, generation=int(i == 1)) for i, r in enumerate(excluded)]
        excluded[0]["requests"] = 1
        none = self.replay(encode(excluded), timing=True)
        self.assertEqual(none["signal_order"], dict(status="no_accepted_requests", possible_latest_generations=[], proven_precedences=[]))

    def test_conflicting_and_failed_shared_waits(self):
        for name in ("same_directory", "ordered"):
            rows = timed_control(self.raw[name])
            first = next(r for r in rows if r["kind"] == "probe" and r["generation"] == 1)
            first.update(event_result=0, event_error=None)
            wait = next(r for r in rows if r["kind"] == "wait")
            q = self.replay(encode(rows), timing=True)
            self.assertEqual(q["requests"][0]["status"], "identity_conflict")
            self.assertIsNone(q["requests"][0]["signal_window"])
            self.assertIsNone(q["signal_order"]["possible_latest_generations"])
            self.assertEqual(q["monitor"]["waits"][0]["disputed_by_probe_lines"], [first["seq"]+1])
            # A disputed shared observation cannot tighten a different member's interval.
            other = q["requests"][1]["signal_window"]
            self.assertNotIn(wait["seq"]+1, [e["evidence_line"] for e in other.values() if e])
            op = self.replay(encode(rows))["requests"][0]
            self.assertEqual(op["outcome"], "UnknownOutcome")
            self.assertTrue(op["resources_released"])
            if name == "ordered":
                selected = self.replay(encode(rows[:wait["seq"] + 1]))["requests"][1]
                self.assertNotIn("CompletionEventSignaled", [s["state"] for s in selected["states"]])
                # The disputed selection cannot contradict this member's own later clear check.
                final = next(r for r in rows if r["kind"] == "result" and r["generation"] == 2)
                final.update(ok=False, error=6, bytes=None, event_result=TIMEOUT)
                member = self.replay(encode(rows), timing=True)["requests"][1]
                self.assertEqual(member["conflict_evidence_lines"], [])
                self.assertEqual(member["signal_window"]["not_after"]["observation"], "quiescence_observed")
        rows = timed_control(self.raw["same_directory"])
        wait = next(r for r in rows if r["kind"] == "wait")
        wait.update(result=FAILED, error=6)
        final = next(r for r in rows if r["kind"] == "result")
        final.update(event_result=FAILED, event_error=6)
        q = self.replay(encode(rows), timing=True)
        op = q["requests"][0]
        self.assertEqual((op["outcome"], op["signal_window"]["not_after"]["observation"]), ("UnknownOutcome", "quiescence_observed"))
        self.assertEqual(op["signal_window"]["not_before"]["observation"], "private_event_clear")
        self.assertEqual((q["monitor"]["waits"][0]["win32_error"], q["coverage"]["conflicts"]), (6, 0))
        rows = timed_control(self.raw["ordered"])
        previously_ready = next(r for r in rows if r["kind"] == "probe" and r["generation"] == 3)
        previously_ready["event_result"] = 0
        first_wait = next(i for i, r in enumerate(rows) if r["kind"] == "wait")
        q = self.replay(encode(rows[:first_wait+1]), timing=True)
        self.assertEqual(q["monitor"]["waits"][0]["disputed_by_probe_lines"], [])
        self.assertEqual(q["requests"][2]["status"], "signal_bounded")

    def test_timing_pin_and_output_aliases(self):
        raw = self.raw["ordered"]
        path = self.folder / "timing-original.jsonl"
        path.write_bytes(raw)
        alias = self.folder / "timing-hardlink.bin"
        os.link(path, alias)
        pin = hashlib.sha256(raw).hexdigest()
        self.replay(raw, 2, "f" * 64, timing=True)
        tool = [sys.executable, "-I", "-B", str(HERE / "replay-io-lifecycle.py")]
        for args, channel in (([path, "--timing", "--sha256", pin], "stdout"), ([path, "--timing", "--sha256"], "stderr"),
                              (["--help", path], "stdout"), (["--timing", path, "--bad"], "stderr")):
            with alias.open("ab", buffering=0) as sink:
                channels = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                channels[channel] = sink
                result = subprocess.run([*tool, *args], **channels, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(path.read_bytes(), raw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--keep", type=Path, help="save the original private journals in a new directory")
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-io-life-") as tmp:
        IoTests.folder = Path(tmp)
        IoTests.exe = args.exe.resolve(strict=True)
        IoTests.raw, IoTests.dirs, IoTests.names, IoTests.stimulus = capture(IoTests.exe, IoTests.folder)
        if args.keep:
            args.keep.mkdir()
            for name, data in IoTests.raw.items():
                (args.keep / (name + ".jsonl")).write_bytes(data)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(IoTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
