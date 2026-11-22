"""Exercise the completion-port collector and recover its request edges from the pinned journal."""
import argparse
from contextlib import ExitStack
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import threading
import unittest


HERE = Path(__file__).resolve().parent
LEGACY = runpy.run_path(str(HERE / "test-io-lifecycle.py"))


def changes(exe, directories, *, same=False):
    """Independently watch each directory before triggering a change after the original monitor record."""
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    first, wait, close = api.FindFirstChangeNotificationW, api.WaitForSingleObject, api.FindCloseChangeNotification
    first.argtypes, first.restype = (w.LPCWSTR, w.BOOL, w.DWORD), w.HANDLE
    wait.argtypes, wait.restype = (w.HANDLE, w.DWORD), w.DWORD
    close.argtypes, close.restype = (w.HANDLE,), w.BOOL
    with ExitStack() as stack:
        witnesses = []
        for folder in directories:
            handle = first(str(folder), False, 1)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            stack.callback(close, handle)
            assert wait(handle, 0) == 258
            witnesses.append(handle)
        args = [str(exe), "--io-lifecycle", "--completion-port", "2000", *map(str, directories)]
        if same:
            args.append(str(directories[0]))
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            deadline = threading.Timer(15, child.kill)
            deadline.start()
            raw = bytearray()
            changed = []
            try:
                for line in child.stdout:
                    raw.extend(line)
                    row = json.loads(line)
                    index = None
                    if row["kind"] == "monitor":
                        index = 0 if same else 1
                    elif not same and row["kind"] == "release" and row["generation"] == 2:
                        index = 0
                    if index is not None:
                        assert wait(witnesses[index], 0) == 258
                        (directories[index] / "notify.txt").touch(exist_ok=False)
                        assert wait(witnesses[index], 1500) == 0
                        changed.append(index)
                assert child.wait(timeout=5) == 0, child.stderr.read()[-200:]
            finally:
                deadline.cancel()
                if child.poll() is None:
                    child.kill()
                    child.wait()
            assert changed == ([0] if same else [1, 0])
            if not same:
                assert wait(witnesses[2], 0) == 258
            return bytes(raw)


def decoded(raw):
    return [json.loads(line) for line in raw.splitlines()]


class PortTests(unittest.TestCase):
    def replay(self, data, *, raw=False, pin=None, code=0, options=("--completion-port",)):
        binary = data if isinstance(data, bytes) else LEGACY["encode"](data)
        path = self.folder / "review.jsonl"
        path.write_bytes(binary)
        digest = pin or hashlib.sha256(binary).hexdigest()
        out = LEGACY["command"]([sys.executable, "-I", "-B", HERE / "replay-io-lifecycle.py", path, "--sha256", digest, *options], code)
        self.assertEqual(path.read_bytes(), binary)
        return out if raw or code else json.loads(out)

    def test_ordered_success_failed_packet_and_empty_queue(self):
        rows = decoded(self.originals["ordered"])
        report = self.replay(self.originals["ordered"])
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["coverage"], dict(planned=3, admitted=3, associated=3, submitted=3, pending_observed=3,
                                                dequeue_calls=4, joined_packets=3, corroborated_results=3,
                                                cancellation_attempts=1, released=3))
        waits = report["waits"]
        self.assertEqual([w["joined_generation"] for w in waits], [2, 1, None, 3])
        self.assertEqual([w["phase"] for w in waits], ["monitor", "monitor", "monitor", "drain"])
        self.assertEqual([w["outstanding_generations"] for w in waits], [[1, 2, 3], [1, 3], [3], [3]])
        self.assertEqual(waits[2]["native_return"], dict(ok=False, error=258, bytes=None, completion_key=None, overlapped=None))
        for req, folder in zip(report["requests"], self.dirs):
            gen = req["generation"]
            op = req["handle_observations"]
            admission = op["admission"]
            self.assertEqual(int.from_bytes(bytes.fromhex(admission["file_id"]), "little"), folder.stat().st_ino)
            binding = rows[op["observation_lines"]["associate"] - 1]
            submission = rows[op["observation_lines"]["submit"] - 1]
            packet = rows[req["dequeue_line"] - 1]
            self.assertEqual(binding["port_handle"], report["port_open"]["port_handle"])
            self.assertEqual(binding["returned_port"], packet["port_handle"])
            self.assertEqual(binding["directory_handle"], submission["directory_handle"])
            self.assertEqual((binding["completion_key"], submission["overlapped"]), (packet["completion_key"], packet["overlapped"]))
            self.assertEqual(op["native_final_result"]["overlapped"], submission["overlapped"])
            self.assertEqual(packet["completion_key"], str(gen))
            self.assertEqual(op["native_final_result"]["win32_error"], packet["error"])
            if gen in (1, 2):
                self.assertEqual(packet["bytes"], op["native_final_result"]["bytes"])
                self.assertGreaterEqual(packet["bytes"], 12 + len("notify.txt".encode("utf-16-le")))
            else:
                self.assertEqual((packet["error"], packet["bytes"], req["packet_outcome"]), (995, 0, "operation_aborted"))
        self.assertTrue(all(r["correspondence"] == "packet_and_result_agree" for r in report["requests"]))
        self.assertEqual(self.replay(self.originals["ordered"], raw=True), self.replay(self.originals["ordered"], raw=True))

    def test_two_handles_one_change_and_cancel_race(self):
        r = self.replay(self.originals["shared"])
        self.assertEqual((r["status"], r["coverage"]["dequeue_calls"]), ("complete", 2))
        a, b = r["requests"]
        for field in ("file_id", "volume"):
            self.assertEqual(a["handle_observations"]["admission"][field], b["handle_observations"]["admission"][field])
        for field in ("completion_key", "directory_handle"):
            self.assertNotEqual(a["association"][field], b["association"][field])
        self.assertNotEqual(a["submission"]["overlapped"], b["submission"]["overlapped"])
        self.assertEqual({w["joined_generation"] for w in r["waits"]}, {1, 2})
        race = self.replay(self.originals["race"])
        self.assertEqual([w["relation"] for w in race["waits"]], ["timeout_without_packet", "successful_io_packet"])
        self.assertEqual((race["requests"][0]["packet_outcome"], race["coverage"]["cancellation_attempts"]), ("completed", 1))
        self.assertEqual(race["status"], "complete")

    def test_foreign_key_pointer_null_and_reused_packet(self):
        rows = decoded(self.originals["ordered"])
        index = next(i for i, row in enumerate(rows) if row["kind"] == "dequeue")
        first = rows[index]
        for delta, relation in ((dict(completion_key="1"), "selection_conflict"),
                                (dict(overlapped="1"), "selection_conflict"),
                                (dict(selected_generation=None, overlapped=None), "unmatched_packet"),
                                (dict(selected_generation=None, completion_key="90", overlapped="1"), "unmatched_packet")):
            trial = rows[:index] + [dict(first, **delta)]
            q = self.replay(trial)
            self.assertEqual((q["waits"][0]["relation"], q["coverage"]["joined_packets"], q["status"]), (relation, 0, "partial"))
        second = next(i for i in range(index + 1, len(rows)) if rows[i]["kind"] == "dequeue")
        stale = dict(rows[second], completion_key=first["completion_key"], overlapped=first["overlapped"], selected_generation=None)
        q = self.replay(rows[:second] + [stale])
        self.assertEqual([w["relation"] for w in q["waits"]], ["successful_io_packet", "unmatched_packet"])
        self.assertEqual(q["coverage"]["joined_packets"], 1)
        binding = next(i for i, r in enumerate(rows) if r["kind"] == "submit" and r["generation"] == 1)
        other = next(r for r in rows if r["kind"] == "submit" and r["generation"] == 2)
        self.replay(rows[:binding] + [dict(rows[binding], overlapped=other["overlapped"])] + rows[binding+1:], code=2)

    def test_contrary_results_and_native_unknowns(self):
        rows = decoded(self.originals["ordered"])
        i = next(i for i, r in enumerate(rows) if r["kind"] == "result")
        for delta, status, outcome in ((dict(bytes=1), "conflicting_observations", None),
                                       (dict(ok=False, bytes=None, error=996), "conflicting_observations", None),
                                       (dict(ok=False, bytes=None, error=6), "packet_with_unconfirmed_result", "completed")):
            q = self.replay(rows[:i] + [dict(rows[i], **delta)] + rows[i+1:])
            req = q["requests"][1]
            self.assertEqual((req["correspondence"], req["packet_outcome"], q["status"]), (status, outcome, "partial"))
            self.assertEqual(q["waits"][0]["native_return"]["bytes"], rows[i]["bytes"])
        t = next(i for i, r in enumerate(rows) if r["kind"] == "dequeue" and not r["overlapped"])
        err = self.replay(rows[:t] + [dict(rows[t], error=735)] + rows[t+1:])
        self.assertEqual((err["status"], err["waits"][2]["relation"]), ("partial", "dequeue_failed_without_packet"))
        self.replay(rows[:t] + [dict(rows[t], bytes=0)], code=2)
        self.replay(rows[:t] + [dict(rows[t], completion_key="0")], code=2)
        packet = next(n for n, r in enumerate(rows) if r["kind"] == "dequeue")
        for error, expected in ((996, "conflicting_observations"), (6, "packet_with_unconfirmed_result")):
            changed = list(rows)
            changed[packet] = dict(rows[packet], ok=False, error=error, bytes=0)
            changed[i] = dict(rows[i], ok=False, error=error, bytes=None)
            q = self.replay(changed)
            self.assertEqual((q["requests"][1]["correspondence"], q["status"]), (expected, "partial"))

    def test_gap_admission_failure_partial_and_pins(self):
        raw = self.originals["ordered"]
        rows = decoded(raw)
        i = next(i for i, r in enumerate(rows) if r["kind"] == "dequeue")
        q = self.replay(rows[:i] + rows[i+1:])
        self.assertEqual((q["qualified_prefix_lines"], q["unjoined_records"][0]["kind"], q["coverage"]["joined_packets"]),
                         (i, "result", 0))
        d = self.replay(LEGACY["encode"](rows[:i+1]) + b'{"cut"')
        self.assertEqual((d["trailing_bytes"], d["requests"][1]["correspondence"], d["journal_complete"]),
                         (6, "packet_observed", False))
        rejected = self.replay(self.originals["rejected"])
        self.assertTrue(rejected["journal_complete"])
        self.assertEqual((rejected["status"], rejected["coverage"]["admitted"], rejected["waits"]), ("partial", 0, []))
        failed = [rows[0], dict(rows[1], ok=False, error=8, port_handle=None), dict(rows[-1], seq=2)]
        denied = self.replay(failed)
        self.assertEqual((denied["port_open"]["error"], denied["port_close"], denied["coverage"]["planned"]), (8, None, 3))
        self.replay(raw, pin="0" * 64, code=2)
        self.replay(rows[:i] + [dict(rows[i], run=decoded(self.originals["shared"])[0]["run"])], code=2)
        self.replay(raw, options=(), code=2)
        self.replay(raw, options=("--timing", "--completion-port"), code=2)
        self.replay(self.originals["legacy"], code=2)

    def test_port_and_call_arguments_must_agree(self):
        rows = decoded(self.originals["ordered"])
        def change(kind, **override):
            i = next(i for i, r in enumerate(rows) if r["kind"] == kind)
            return self.replay(rows[:i] + [dict(rows[i], **override)] + rows[i+1:])
        q = change("dequeue", port_handle="123")
        self.assertEqual((q["status"], q["waits"][0]["relation"], q["coverage"]["joined_packets"]),
                         ("partial", "port_identity_conflict", 2))
        for q in (change("associate", directory_handle="123"), change("associate", port_handle="123", returned_port="123")):
            self.assertEqual((q["waits"][1]["relation"], q["requests"][0]["packet_outcome"]), ("association_conflict", None))
        for q in (change("probe", overlapped="1"), change("result", directory_handle="123")):
            self.assertEqual((q["coverage"]["corroborated_results"], q["status"]), (2, "partial"))
        q = change("cancel", overlapped="1")
        self.assertFalse(q["requests"][2]["cancellation_bound"])
        self.assertEqual((q["requests"][2]["packet_outcome"], q["status"]), ("operation_aborted", "partial"))
        q = change("port_close", port_handle="123")
        self.assertFalse(q["port_close_matches_open"])
        self.assertEqual((q["coverage"]["corroborated_results"], q["status"]), (3, "partial"))

    def test_unobserved_drain_and_association_failure(self):
        rows = decoded(self.originals["race"])
        drain = next(i for i, r in enumerate(rows) if r["kind"] == "drain")
        packet = rows[drain + 1]
        packet.update(ok=False, error=258, bytes=None, completion_key=None, overlapped=None, selected_generation=None)
        packet["tick"] += 1000
        for r in rows[drain + 2:]:
            r["tick"] += 1000
            if "start" in r:
                r["start"] += 1000
            if r["kind"] == "result":
                r.update(ok=False, error=996, bytes=None, event_result=258)
            if r["kind"] == "release":
                r.update(quiesce_result=258, close_attempted=False)
        q = self.replay(rows)
        self.assertTrue(q["journal_complete"])
        self.assertEqual((q["status"], q["coverage"]["joined_packets"], q["coverage"]["released"]), ("partial", 0, 0))
        req = q["requests"][0]
        self.assertIsNone(req["packet_outcome"])
        self.assertEqual(req["handle_observations"]["outcome"], "UnknownOutcome")
        kinds = ("plan", "port_open", "admit", "associate", "release", "monitor", "drain", "port_close", "end")
        failed = [dict(next(r for r in rows if r["kind"] == k)) for k in kinds]
        for i, r in enumerate(failed):
            r.update(seq=i, tick=100 + 4*i)
            if "start" in r:
                r["start"] = r["tick"] - 1
        failed[3].update(ok=False, error=87, returned_port=None)
        failed[4].update(quiesce_result=None, close_attempted=True)
        q = self.replay(failed)
        self.assertEqual((q["status"], q["coverage"]["associated"], q["coverage"]["submitted"]), ("partial", 0, 0))
        self.assertEqual(q["requests"][0]["association"]["error"], 87)

    def test_disconnect_with_pending_io_releases_directory(self):
        command = [str(self.exe), "--io-lifecycle", "--completion-port", "150", str(self.dirs[0])]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            deadline = threading.Timer(10, child.kill)
            deadline.start()
            try:
                for line in child.stdout:
                    if json.loads(line)["kind"] == "monitor":
                        break
                else:
                    self.fail("producer exited before announcing outstanding work")
                child.stdout.close()
                self.assertEqual(child.wait(timeout=5), 1)
            finally:
                deadline.cancel()
                if child.poll() is None:
                    child.kill()
                    child.wait()
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        open_file, close = api.CreateFileW, api.CloseHandle
        open_file.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
        open_file.restype = w.HANDLE
        close.argtypes, close.restype = (w.HANDLE,), w.BOOL
        handle = open_file(str(self.dirs[0]), 1, 0, None, 3, 0x02000000, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        self.assertTrue(close(handle))

    def test_full_port_and_output_alias(self):
        cli = [self.exe, "--io-lifecycle", "--completion-port", "30"]
        dirs = [self.dirs[2]] * 8
        raw = LEGACY["command"]([*cli, *dirs])
        report = self.replay(raw)
        self.assertEqual((report["status"], report["coverage"]["pending_observed"], report["coverage"]["dequeue_calls"]),
                         ("complete", 8, 9))
        self.assertEqual({w["joined_generation"] for w in report["waits"][1:]}, set(range(1, 9)))
        self.assertTrue(all(r["packet_outcome"] == "operation_aborted" for r in report["requests"]))
        LEGACY["command"]([*cli, *dirs, self.dirs[2]], 2)
        original = self.folder / "review.jsonl"
        alias = self.folder / "alias.bin"
        os.link(original, alias)
        command = [sys.executable, "-I", "-B", str(HERE / "replay-io-lifecycle.py"), str(original),
                   "--sha256", hashlib.sha256(raw).hexdigest(), "--completion-port"]
        with alias.open("ab") as sink:
            self.assertEqual(subprocess.run(command, stdout=sink, stderr=subprocess.PIPE, timeout=5).returncode, 2)
        self.assertEqual(original.read_bytes(), raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--keep", type=Path, help="save original private journals in a new directory")
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="kn-io-port-") as tmp:
        folder = Path(tmp)
        dirs = [folder / name for name in ("first", "second", "quiet", "shared")]
        for d in dirs:
            d.mkdir()
        raw = dict(ordered=changes(exe, dirs[:3]), shared=changes(exe, [dirs[3]], same=True),
                   race=LEGACY["completion_during_cancel"](exe, dirs[2], port=True),
                   rejected=LEGACY["command"]([exe, "--io-lifecycle", "--completion-port", "10", folder / "missing"]),
                   legacy=LEGACY["command"]([exe, "--io-lifecycle", "10", dirs[2]]))
        PortTests.folder, PortTests.dirs, PortTests.originals, PortTests.exe = folder, dirs[:3], raw, exe
        if args.keep:
            args.keep.mkdir()
            for name, data in raw.items():
                (args.keep / (name + ".jsonl")).write_bytes(data)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PortTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
