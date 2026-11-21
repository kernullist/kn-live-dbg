"""Exercise the Windows notification provider with owned directories and replay the original journal."""
import argparse
import copy
import hashlib
import json
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


def capture(exe, folder):
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
                if r["kind"] == "monitor":
                    verify_declined_handle_closed(file)
                    (dirs[1] / names[1]).touch()
                if r["kind"] == "release" and r["generation"] == 2:
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
    return dict(ordered=b"".join(original), same_directory=same, cancel_race=raced), dirs, names


def encode(rows):
    return b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in rows)


class IoTests(unittest.TestCase):
    def replay(self, raw, code=0, pin=None):
        p = self.folder / "review.jsonl"
        p.write_bytes(raw)
        run = command([sys.executable, "-I", "-B", HERE / "replay-io-lifecycle.py", p,
                       "--sha256", pin or hashlib.sha256(raw).hexdigest()], code)
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
        rows = list(map(json.loads, self.raw["ordered"].splitlines()))
        probe = next(r for r in rows if r["kind"] == "probe")
        final = next(r for r in rows if r["kind"] == "result" and r["generation"] == probe["generation"])
        for k in ("ok", "error", "bytes", "event_result"):
            probe[k] = final[k]
        a = self.replay(encode(rows))
        op = a["requests"][0]
        self.assertNotIn("PendingObserved", [s["state"] for s in op["states"]])
        self.assertEqual(op["outcome"], "completed")
        for r in (probe, final):
            r.update(ok=False, error=1022, bytes=None)
        self.assertEqual(self.replay(encode(rows))["requests"][0]["outcome"], "changes_require_enumeration")

    def test_conflicting_completion_witnesses(self):
        rows = list(map(json.loads, self.raw["ordered"].splitlines()))
        probe = next(r for r in rows if r["kind"] == "probe" and r["generation"] == 1)
        probe.update(ok=True, error=None, bytes=7, event_result=0)
        op = self.replay(encode(rows))["requests"][0]
        self.assertEqual(op["outcome"], "UnknownOutcome")
        conflict = next(s for s in op["states"] if s["state"] == "IdentityConflict")
        self.assertEqual([rows[i-1]["kind"] for i in conflict["evidence_lines"]], ["probe", "result"])
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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--keep", type=Path, help="save the original private journals in a new directory")
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="kn-io-life-") as tmp:
        IoTests.folder = Path(tmp)
        IoTests.exe = args.exe.resolve(strict=True)
        IoTests.raw, IoTests.dirs, IoTests.names = capture(IoTests.exe, IoTests.folder)
        if args.keep:
            args.keep.mkdir()
            for name, data in IoTests.raw.items():
                (args.keep / (name + ".jsonl")).write_bytes(data)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(IoTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
