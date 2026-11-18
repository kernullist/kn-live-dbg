"""Exercise registered Windows runs, observed supervisor loss and offline denominators."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import copy
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import queue
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import owned_module_campaign as campaign
import owned_module_benchmark as package


TOOLS = Path(__file__).resolve().parent
RUNNER = TOOLS / "test-user-module-workload.py"
EVALUATE = TOOLS / "evaluate-corpus.py"
WIN = runpy.run_path(str(RUNNER))


def command(*args):
    return [sys.executable, "-B", *map(str, args)]


def cli(args, expected=0):
    result = subprocess.run(command(*args), capture_output=True, timeout=240)
    if result.returncode != expected:
        raise AssertionError((args[0], result.returncode, result.stderr[-1000:]))
    if expected == 2:
        assert result.stdout == b"" and b"Traceback" not in result.stderr
    return result.stdout


@contextmanager
def managed(argv):
    p = subprocess.Popen(command(*argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        yield p
    finally:
        if p.poll() is None:
            p.kill()
        p.wait(timeout=15)
        p.stdout.close()
        p.stderr.close()
        p._handle.Close()


def plan(directory, exe, slots, timeout):
    raw = cli([TOOLS / "owned_module_campaign.py", "create", "--directory", directory, "--core-exe", exe,
               "--attempts", slots, "--timeout-ms", timeout])
    pin = json.loads(raw)["plan_sha256"]
    (directory / "plan.pin").write_text(pin, encoding="ascii")
    return pin


def freeze(directory, pin, name):
    out = directory / (name + ".knruns")
    raw = cli([TOOLS / "owned_module_campaign.py", "snapshot", "--directory", directory, "--plan-sha256", pin, "--out", out])
    snapshot_pin = json.loads(raw)["snapshot_sha256"]
    assert hashlib.sha256(out.read_bytes()).hexdigest() == snapshot_pin
    (directory / (name + ".pin")).write_text(snapshot_pin, encoding="ascii")
    return out, snapshot_pin


def replay(path, pin, plan_hash, expected=0):
    return cli([EVALUATE, "--owned-module-campaign", path, "--sha256", pin, "--plan-sha256", plan_hash], expected)


class ProcessEntry(c.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD), ("heap", c.c_size_t),
                ("module", w.DWORD), ("threads", w.DWORD), ("parent", w.DWORD), ("priority", w.LONG),
                ("flags", w.DWORD), ("exe", w.WCHAR * 260)]


def direct_children(parent):
    take = WIN["api"]("CreateToolhelp32Snapshot", w.HANDLE, w.DWORD, w.DWORD)
    first = WIN["api"]("Process32FirstW", w.BOOL, w.HANDLE, c.POINTER(ProcessEntry))
    advance = WIN["api"]("Process32NextW", w.BOOL, w.HANDLE, c.POINTER(ProcessEntry))
    handle = take(2, 0)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        entry = ProcessEntry()
        entry.size = c.sizeof(entry)
        ok = first(handle, c.byref(entry))
        children = []
        while ok:
            if entry.parent == parent:
                children.append((entry.pid, entry.exe))
            ok = advance(handle, c.byref(entry))
        return children
    finally:
        WIN["close_handle"](handle)


def when(predicate, process):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline and process.poll() is None:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("owned process ended or timed out before the expected evidence appeared")


def arm(watcher):
    lines = queue.Queue()
    threading.Thread(target=lambda: lines.put(watcher.stdout.readline()), daemon=True).start()
    signal = lines.get(timeout=25)
    if not signal or json.loads(signal)["status"] != "armed":
        raise AssertionError("independent observer did not pin both original live processes")


def pin_descendants(stack, worker, generation, exe):
    children = direct_children(worker)
    with ExitStack() as attempt:
        handles = []
        for path in (exe, Path(sys.executable)):
            for pid, leaf in children:
                if leaf.lower() != path.name.lower():
                    continue
                handle = WIN["open_process"](0x00101000, False, pid)
                if not handle:
                    continue
                attempt.callback(WIN["close_handle"], handle)
                image = c.create_unicode_buffer(32768)
                size = w.DWORD(len(image))
                if (WIN["process_image"](handle, 0, image, c.byref(size)) and Path(image.value).samefile(path) and
                        WIN["peer_pid"](handle) == pid and WIN["creation"](handle) >= int(generation) and WIN["wait"](handle, 0) == 258):
                    handles.append((pid, handle))
                    break
            else:
                return None
        current = {pid for pid, _ in direct_children(worker)}
        if any(pid not in current or WIN["wait"](h, 0) != 258 for pid, h in handles):
            return None
        stack.enter_context(attempt.pop_all())
        return [h for _, h in handles]


def interrupt_slot(directory, pin, exe, slot, witnessed):
    args = [RUNNER, "--campaign", directory, "--plan-sha256", pin, "--slot", slot]
    with ExitStack() as stack:
        owner = stack.enter_context(managed([*args, "--core-exe", exe]))
        bound = when(lambda: campaign.current_snapshot(directory, pin)["attempts"][slot - 1]["bound"], owner)
        worker_pid, generation = bound["worker"]
        handle = WIN["native"](WIN["open_process"](0x00101000, False, worker_pid))
        stack.callback(WIN["close_handle"], handle)
        assert str(WIN["creation"](handle)) == generation and WIN["wait"](handle, 0) == 258
        if witnessed:
            watcher = stack.enter_context(managed([*args, "--watch-owner", "--watch-seconds", 30]))
            arm(watcher)
        # Wait for a real native observer and an actual Python subject in this worker's tree.
        children = when(lambda: pin_descendants(stack, worker_pid, generation, exe), owner)
        before = campaign.current_snapshot(directory, pin)["attempts"][slot - 1]
        assert before["admitted"]["supervisor"] == [owner.pid, str(WIN["creation"](int(owner._handle)))]
        assert before["ended"] is before["loss"] is None
        out = directory / f"live-{slot}.knruns"
        active_pin = campaign.freeze(directory, pin, out)
        owner.kill()
        assert owner.wait(timeout=10) != 0
        for peer in [handle, *children]:
            assert WIN["wait"](peer, 10000) == 0
        if witnessed:
            stdout, stderr = watcher.communicate(timeout=20)
            assert watcher.returncode == 0 and json.loads(stdout)["status"] == "owner_lost", stderr[-500:]
    live = json.loads(replay(out, active_pin, pin))
    assert live["attempts"][slot - 1]["status"] == "unresolved"
    return active_pin


def acquire(root, exe):
    directory = root / "series"
    pin = plan(directory, exe, 6, 180000)
    args = [RUNNER, "--campaign", directory, "--plan-sha256", pin]
    empty, empty_pin = freeze(directory, pin, "empty")
    empty_report = replay(empty, empty_pin, pin)
    assert json.loads(empty_report)["success_per_admission"]["value"] is None
    with ThreadPoolExecutor(max_workers=2) as pool:
        argv = command(*args, "--slot", 2, "--core-exe", root / "missing.exe")
        writers = [pool.submit(subprocess.run, argv, capture_output=True, timeout=60) for _ in range(2)]
        results = sorted((w.result() for w in writers), key=lambda r: r.returncode)
    assert [r.returncode for r in results] == [1, 2] and not results[1].stdout
    assert json.loads(results[0].stdout)["ended"]["outcome"] == "input_unavailable"
    altered = root / "inert-input.txt"
    altered.write_bytes(b"owned non-executable control\n")
    different = json.loads(cli([*args, "--slot", 5, "--core-exe", altered], 1))
    assert different["ended"]["outcome"] == "input_mismatch" and different["bound"] is None
    interrupt_slot(directory, pin, exe, 3, True)
    interrupt_slot(directory, pin, exe, 6, False)
    with managed([*args, "--slot", 1, "--core-exe", exe]) as owner:
        when(lambda: campaign.current_snapshot(directory, pin)["attempts"][0]["bound"], owner)
        with managed([*args, "--slot", 1, "--watch-owner", "--watch-seconds", 180]) as watcher:
            arm(watcher)
            stdout, stderr = owner.communicate(timeout=240)
            assert owner.returncode == 0 and json.loads(stdout)["ended"]["outcome"] == "published", stderr[-1000:]
            stdout, stderr = watcher.communicate(timeout=20)
            assert watcher.returncode == 0 and json.loads(stdout)["status"] == "already_recorded", stderr[-500:]
    out, snapshot_pin = freeze(directory, pin, "final")
    data = replay(out, snapshot_pin, pin)
    assert data == replay(out, snapshot_pin, pin) and empty_report == replay(empty, empty_pin, pin)
    (directory / "evaluation.json").write_bytes(data)
    cli([*args, "--slot", 1, "--core-exe", exe], 2)
    assert campaign.freeze(directory, pin, directory / "unchanged.knruns") == snapshot_pin
    for label, core, deadline, expected in (("deadline", exe, 50, "timed_out"), ("worker-failure", altered, 180000, "worker_error")):
        fixture = root / label
        p = plan(fixture, core, 1, deadline)
        cli([RUNNER, "--campaign", fixture, "--plan-sha256", p, "--slot", 1, "--core-exe", core], 1)
        frozen, frozen_pin = freeze(fixture, p, "final")
        result = json.loads(replay(frozen, frozen_pin, p))
        row = result["attempts"][0]
        assert row["status"] == expected and row["ended"]["job"]["active"] == 0 and row["workloads"] is None
        if expected == "worker_error":
            failure = row["ended"]["worker_failure"]
            assert (failure["phase"], failure["domain"], failure["code"]) == ("fixed", "win32", 193)
        assert result["success_per_admission"] == {"numerator": 0, "denominator": 1, "value": 0}
    return out, snapshot_pin, pin


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = json.loads(self.path.read_bytes())

    def test_real_denominators_and_cost_scope(self):
        result = json.loads(replay(self.path, self.pin, self.plan))
        self.assertEqual(result["counts"], {"planned": 6, "admitted": 5, "worker_bound": 3, "terminal": 4, "unresolved": 1,
                                           "unadmitted": 1, "published_packages": 1, "verified_packages": 1, "passed": 1, "job_accounted": 1,
                                           "admitted_without_process_truth": 4})
        self.assertEqual([r["status"] for r in result["attempts"]],
                         ["published", "input_unavailable", "owner_lost", "unadmitted", "input_mismatch", "unresolved"])
        self.assertEqual((result["success_per_admission"]["denominator"], result["success_per_planned_run"]["denominator"]), (5, 6))
        native = result["attempts"][0]
        self.assertEqual([(s["metrics"]["true_positives"], s["metrics"]["cases"]) for s in native["workloads"]], [(12, 12), (20, 22)])
        total = native["ended"]["job"]
        self.assertGreaterEqual(total["total"], 42)
        self.assertEqual(total["active"], 0)
        for metric in ("user_100ns", "kernel_100ns", "read_bytes", "written_bytes"):
            self.assertGreater(int(total[metric]), 0)
        if total["peak_job_bytes"] is None:
            self.assertGreater(total["peak_error"], 0)
        else:
            self.assertGreater(int(total["peak_job_bytes"]), 0)
        self.assertTrue(all(r["workloads"] is None for r in result["attempts"][1:]))
        self.assertEqual(result["declared_independence_groups"], 1)

    def test_repinned_contradictions(self):
        from importlib.util import module_from_spec, spec_from_file_location
        spec = spec_from_file_location("evaluator", EVALUATE)
        evaluator = module_from_spec(spec)
        spec.loader.exec_module(evaluator)
        def swap_claims(rows):
            rows[1]["admitted"], rows[4]["admitted"] = rows[4]["admitted"], rows[1]["admitted"]
        for change, reason in (
            (lambda rows: rows.pop(), "lost planned"),
            (lambda rows: rows.reverse(), "slot or ticket"),
            (swap_claims, "different campaign or slot"),
            (lambda rows: rows[0]["bound"].update(previous_sha256="0" * 64), "another admission"),
            (lambda rows: rows[0]["ended"].update(previous_sha256="0" * 64), "another attempt"),
            (lambda rows: rows[2]["loss"]["worker"].update(after=258), "pinned transition"),
            (lambda rows: rows[2].update(ended=rows[0]["ended"]), "conflicting owner-loss"),
            (lambda rows: rows[0]["ended"].update(worker_exit=1), "workload gate"),
            (lambda rows: rows[0]["ended"]["job"].update(total=1), "omits a witnessed process"),
            (lambda rows: rows[1]["ended"].update(package_sha256="0" * 64), "unacknowledged package"),
        ):
            data = copy.deepcopy(self.snapshot)
            change(data["attempts"])
            raw = json.dumps(data).encode()
            with tempfile.NamedTemporaryFile(dir=self.path.parent, suffix=".knruns", delete=False) as file:
                path = Path(file.name)
                file.write(raw)
            try:
                with self.assertRaisesRegex(ValueError, reason):
                    evaluator.evaluate_campaign(path, hashlib.sha256(raw).hexdigest(), self.plan)
            finally:
                path.unlink()

    def test_external_pins_and_missing_package(self):
        replay(self.path, "0" * 64, self.plan, 2)
        replay(self.path, self.pin, "0" * 64, 2)
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / "copy.knruns"
            copied.write_bytes(self.path.read_bytes())
            absent = json.loads(replay(copied, self.pin, self.plan))
            self.assertEqual((absent["counts"]["planned"], absent["counts"]["published_packages"], absent["counts"]["verified_packages"]), (6, 1, 0))
            self.assertEqual((absent["evidence"]["missing"], absent["evidence_survival_per_publication"]["value"]), (1, 0))
            wrong = campaign.package_path(copied.parent, self.snapshot["attempts"][0]["ticket"])
            wrong.mkdir()
            unreadable = json.loads(replay(copied, self.pin, self.plan))
            self.assertEqual(unreadable["evidence"]["unreadable"], 1)
            wrong.rmdir()
            wrong.write_bytes(b"altered evidence")
            altered = json.loads(replay(copied, self.pin, self.plan))
            self.assertEqual((altered["evidence"]["pin_mismatch"], altered["counts"]["admitted_without_process_truth"]), (1, 5))
            self.assertTrue(all(row["workloads"] is None for row in altered["attempts"]))
            self.snapshot["attempts"][0]["ended"]["package_sha256"] = hashlib.sha256(wrong.read_bytes()).hexdigest()
            raw = json.dumps(self.snapshot).encode()
            copied.write_bytes(raw)
            malformed = json.loads(replay(copied, hashlib.sha256(raw).hexdigest(), self.plan))
            self.assertEqual((malformed["evidence"]["invalid_records"], malformed["success_per_admission"]["numerator"]), (1, 0))
        cli([EVALUATE, "--owned-module-campaign", self.path, "--sha256", self.pin], 2)
        cli([EVALUATE, "--owned-module-run", self.path, "--sha256", self.pin, "--plan-sha256", self.plan], 2)

    def test_foreign_valid_acquisition_cannot_fill_a_ticket(self):
        row = self.snapshot["attempts"][0]
        original = campaign.package_path(self.path.parent, row["ticket"])
        manifest, parts = package.read_bundle(original, row["ended"]["package_sha256"], json.loads)
        foreign = "0" * 32 if row["ticket"] != "0" * 32 else "1" * 32
        truth = json.loads(parts["truth.json"])
        truth["run_id"] = manifest["run_id"] = foreign
        parts["truth.json"] = package.encoded(truth)
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / "copy.knruns"
            wrong = campaign.package_path(copied.parent, row["ticket"])
            row["ended"]["package_sha256"] = package.write_bundle(wrong, manifest, parts)
            self.assertEqual(json.loads(cli([EVALUATE, "--owned-module-run", wrong, "--sha256", row["ended"]["package_sha256"]]))["run_id"], foreign)
            raw = json.dumps(self.snapshot).encode()
            copied.write_bytes(raw)
            replay(copied, hashlib.sha256(raw).hexdigest(), self.plan, 2)

    def test_snapshot_during_write_and_after_writer_loss(self):
        with tempfile.TemporaryDirectory(prefix="kn-owned-campaign-recovery-") as temp:
            folder = Path(temp)
            with campaign.database(self.path.parent, "ro") as original:
                clone = sqlite3.connect(folder / campaign.DATABASE)
                try:
                    original.backup(clone)
                finally:
                    clone.close()
            writer = (
                "import sqlite3,sys,time\n"
                "db=sqlite3.connect(sys.argv[1])\n"
                "db.execute('PRAGMA cache_size=1')\n"
                "db.execute('BEGIN IMMEDIATE')\n"
                "db.execute('UPDATE slots SET ended=zeroblob(32768)')\n"
                "print('uncommitted',flush=True)\n"
                "time.sleep(40)\n"
            )
            with managed(["-c", writer, folder / campaign.DATABASE]) as process:
                self.assertEqual(process.stdout.readline().strip(), b"uncommitted")
                journal = folder / (campaign.DATABASE + "-journal")
                self.assertGreater(journal.stat().st_size, 512)
                process.kill()
                process.wait(timeout=10)
            self.assertEqual(campaign.freeze(folder, self.plan, folder / "recovered.knruns"), self.pin)
            # An uncommitted transaction without spilled pages permits a concurrent snapshot.
            with campaign.database(folder, "rw") as pending:
                pending.execute("BEGIN IMMEDIATE")
                pending.execute("UPDATE slots SET ended=NULL WHERE slot=1")
                self.assertEqual(campaign.freeze(folder, self.plan, folder / "concurrent.knruns"), self.pin)
                pending.rollback()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-exe", type=Path, required=True)
    parser.add_argument("--evidence-directory", type=Path, help="retain private evidence in a new directory")
    args = parser.parse_args()
    with ExitStack() as stack:
        if args.evidence_directory:
            root = args.evidence_directory.resolve()
            root.mkdir()
        else:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="kn-owned-campaign-")))
        CampaignTests.path, CampaignTests.pin, CampaignTests.plan = acquire(root, args.core_exe.resolve(strict=True))
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CampaignTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
