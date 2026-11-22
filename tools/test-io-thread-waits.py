"""Check live wait-any observations, independent managed thread views and offline evidence rejection."""
import argparse
import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import io_wait_study as study
from io_wait_sampler import ThreadSampler, thread_row
from saved_etl_comparison import record_bytes


HERE = Path(__file__).resolve().parent
CLI = HERE/"measure-io-waits.py"
PRIVATE = runpy.run_path(str(HERE/"test-etl-activity-window.py"))["private"]


def pin(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(args, code):
    r = subprocess.run([sys.executable, "-B", CLI, *map(str, args)], capture_output=True, timeout=35)
    assert r.returncode == code, (r.returncode, r.stdout[-400:], r.stderr[-400:])
    return json.loads(r.stdout) if code != 2 else None


def journal_lines(path):
    return [json.loads(line) for line in path.read_bytes().split(b"\n")[:-1]]


def await_record(folder, child, predicate):
    until = time.monotonic() + 6
    while child.poll() is None and time.monotonic() < until:
        for path in folder.glob(".kn-io-wait-*/journal.bin"):
            rows = journal_lines(path)
            if predicate(rows):
                return rows
        time.sleep(0.004)
    raise AssertionError("expected a committed producer record while the child was live")


def managed_samples(oracle, plan):
    raw = subprocess.check_output([oracle, str(plan["pid"]), str(plan["tid"])], timeout=5)
    values = [json.loads(line) for line in raw.splitlines()]
    assert len(values) == 5
    for view in values:
        assert view["schema"] == "kn.io_thread_wait_witness.v1"
        assert all(view[k] == plan[k] for k in ("pid", "tid", "process_created", "thread_created"))
        assert int(view["start_tick_ms"]) <= int(view["end_tick_ms"]) and (view["managed_thread_state"] == 5) == (view["managed_wait_reason"] != "None")
    return values


def capture_fixture():
    # Notify the stimulus controller after a genuine live Waiting query has completed.
    # The capture and replay still consume the original Win32 calls and unchanged records.
    path = Path(sys.argv[2])
    sys.argv = [str(CLI), *sys.argv[3:]]
    original = ThreadSampler.snapshot
    with path.open("xb", buffering=0) as observations:
        def sampled(api, *args):
            sample = original(api, *args)
            if (sample["thread_row"] and sample["thread_row"]["thread_state"] == 5 and
                    sample["before"]["result"] == sample["after"]["result"] == 258):
                observations.write((sample["start_tick_ms"]+"\n").encode("ascii"))
            return sample
        with patch.object(ThreadSampler, "snapshot", sampled):
            runpy.run_path(str(CLI), run_name="__main__")


def await_waiting(path, child, after_tick):
    until = time.monotonic()+4
    while child.poll() is None and time.monotonic() < until:
        if path.exists() and any(int(n) > after_tick for n in path.read_bytes().split(b"\n")[:-1]):
            return
        time.sleep(0.003)
    raise AssertionError("no live Waiting query after the recorded provider boundary")


def capture(name, work, args, dirs, mode):
    folder = work/name
    folder.mkdir()
    dest = folder/"original.json"
    wait = 3500 if mode == "ordered" else 2400 if mode == "shared" else 600
    limit = 1 if mode == "limited" else 256
    command = ["capture", "--exe", args.exe, "--exe-sha256", pin(args.exe), "--wait-ms", str(wait), "--interval-ms", "12",
               "--samples", str(limit), "--output", dest, *dirs]
    probe_log = folder/"observed-ticks.txt"
    entry = [__file__, "--capture-fixture", probe_log] if mode in ("ordered", "shared") else [CLI]
    child = subprocess.Popen([sys.executable, "-B", *entry, *map(str, command)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    witnesses = []
    try:
        if mode in ("ordered", "shared"):
            rows = await_record(folder, child, lambda rs: any(r["kind"] == "monitor" for r in rs))
            await_waiting(probe_log, child, next(r["tick"] for r in rows if r["kind"] == "monitor"))
            witnesses.append(managed_samples(args.oracle, rows[0]))
            (dirs[1]/("first-"+name)).write_bytes(b"first")
            if mode == "ordered":
                next_rows = await_record(folder, child, lambda rs: any(r["kind"] == "release" and r["generation"] == 2 for r in rs))
                await_waiting(probe_log, child, next(r["tick"] for r in next_rows if r["kind"] == "release" and r["generation"] == 2))
                witnesses.append(managed_samples(args.oracle, rows[0]))
                (dirs[0]/("second-"+name)).write_bytes(b"second")
        out, err = child.communicate(timeout=16)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        probe_log.unlink(missing_ok=True)
    assert child.returncode in (0, 1), (child.returncode, out[-300:], err[-300:])
    saved = json.loads(out)
    rc = int(mode == "limited" or saved["coverage"]["waits_with_inside_sample"] < saved["coverage"]["recorded_wait_calls"])
    assert child.returncode == rc, saved
    assert saved["capture_sha256"] == pin(dest)
    path = folder/"report.json"
    replay = ["replay", "--capture", dest, "--sha256", pin(dest)]
    receipt = invoke([*replay, "--output", path], rc)
    assert receipt["report_sha256"] == pin(path) and receipt["coverage"] == saved["coverage"]
    assert invoke([*replay, "--check-report", pin(path)], rc) == dict(receipt, status="matched")
    (folder/"managed-views.json").write_text(json.dumps(witnesses), encoding="ascii")
    return dest, json.loads(path.read_bytes()), witnesses


def independent(dest, report, witnesses):
    data = json.loads(dest.read_bytes())
    original = base64.b64decode(data["producer"]["stdout"]["base64"], validate=True)
    journal = dest.with_name("journal.jsonl")
    journal.write_bytes(original)
    assert pin(journal) == report["journal_sha256"]
    timing = subprocess.check_output([sys.executable, "-I", "-B", HERE/"replay-io-lifecycle.py", journal, "--sha256", pin(journal), "--timing"])
    assert json.loads(timing) == report["journal_timing"]
    rows = journal_lines(journal)
    plan = rows[0]
    samples = data["sampler"]["samples"]
    counts = [0, 0]
    for group in report["wait_sets"]:
        line = rows[group["wait_line"]-1]
        assert line["kind"] == "wait" and group["semantics"] == "wait_any"
        assert group["wait_result"] == line["result"] and group["win32_error"] == line["error"]
        roster = [m["generation"] for m in group["members"]]
        assert roster == line["generations"] and group["native_selected_generation"] == (roster[line["result"]] if line["result"] < len(roster) else None)
        for member in group["members"]:
            g = member["generation"]
            assert (rows[member["admit_line"]-1]["generation"], rows[member["admit_line"]-1]["stage"]) == (g, "ready")
            assert rows[member["submit_line"]-1]["ok"] and rows[member["submit_line"]-1]["generation"] == g
            if member["pending_probe_line"]:
                probe = rows[member["pending_probe_line"]-1]
                assert (probe["generation"], probe["kind"], probe["error"]) == (g, "probe", 996)
            final = rows[member["result_line"]-1]
            assert (final["generation"], final["kind"]) == (g, "result")
        inside, waiting = [], []
        for s in samples:
            row = s["thread_row"]
            if not row or s["before"]["result"] != 258 or s["after"]["result"] != 258:
                continue
            raw = row["native_fields"]
            assert int.from_bytes(bytes.fromhex(raw["owner_le"]), "little") == plan["pid"]
            client = bytes.fromhex(raw["client_id_le"])
            assert [int.from_bytes(client[k:k+8], "little") for k in (0, 8)] == [plan["pid"], plan["tid"]]
            native = bytes.fromhex(raw["state_reason_le"])
            state = int.from_bytes(native[:4], "little")
            assert state == row["thread_state"] and int.from_bytes(native[4:], "little") == row["raw_wait_reason"]
            # Both ends must lie strictly inside the original call on the shared millisecond clock.
            if line["start"] < int(s["start_tick_ms"]) and int(s["end_tick_ms"]) < line["tick"]:
                inside.append(s["slot"])
                if state == 5:
                    waiting.append(s["slot"])
        assert (inside, waiting) == (group["inside_samples"], group["waiting_samples"])
        counts[0] += len(inside)
        counts[1] += len(waiting)
    for i, readings in enumerate(witnesses):
        wait = report["wait_sets"][i]
        assert wait["waiting_samples"] and any(int(wait["start_tick_ms"]) < int(view["start_tick_ms"]) <= int(view["end_tick_ms"]) < int(wait["end_tick_ms"])
                                               and view["managed_thread_state"] == 5 for view in readings)
        PRIVATE(readings[0])
    assert counts == [report["coverage"][k] for k in ("inside_call_samples", "waiting_inside_call_samples")]
    assert sum(report["coverage"]["sample_relations"].values()) == len(samples)
    assert report["thread_binding"] == "same_live_thread" and report["scheduler_duration_ms"] is report["kernel_request_identity"] is None
    return data


def controls(data, report, foreign, folder):
    assess = lambda package: study.assess(package, report["capture_sha256"])
    for key, value, why in (("sampler", foreign["sampler"], "plan_line_unbound"),
                            ("producer", dict(data["producer"], process_identity=foreign["producer"]["process_identity"]), "process_generation_mismatch")):
        mixed = assess(dict(data, **{key: value}))
        assert mixed["thread_binding"] == why and not mixed["coverage"]["inside_call_samples"]
        assert mixed["journal_timing"] == report["journal_timing"]
    different = deepcopy(data)
    different["sampler"]["binding"]["thread_created"] = "1"
    assert assess(different)["thread_binding"] == "thread_generation_mismatch"
    altered = deepcopy(data)
    slot = report["wait_sets"][0]["waiting_samples"][0]
    index = slot-1
    def edited():
        d = deepcopy(data)
        return d, d["sampler"]["samples"][index]
    unavailable, sample = edited()
    sample.update(lookup="query_failed", thread_row=None, native_calls=[dict(buffer_bytes=1 << 20, returned_bytes=0, ntstatus=0xc0000022)])
    incomplete = assess(unavailable)
    assert incomplete["status"] == "partial" and incomplete["sample_links"][index]["relation"] == "query_failed"
    assert incomplete["coverage"]["waiting_inside_call_samples"] == report["coverage"]["waiting_inside_call_samples"]-1
    ready, sample = edited()
    row = sample["thread_row"]
    row["thread_state"] = 1
    row["native_fields"]["state_reason_le"] = struct.pack("<II", 1, row["raw_wait_reason"]).hex()
    view = assess(ready)["sample_links"][index]
    assert view["relation"] == "inside_wait_call" and view["reported_thread_state"] == 1 and view["wait_reason_when_waiting"] is None
    early, sample = edited()
    sample["after"] = dict(result=0, win32_error=0)
    s = early["sampler"]
    s.update(samples=s["samples"][:slot], stopped="thread_ended",
             terminal_wait=dict(sample_slot=slot, phase="after_sample", tick_ms=sample["end_tick_ms"], wait=sample["after"]))
    rejected = assess(early)
    assert rejected["thread_binding"] == "thread_exit_before_provider_record" and rejected["coverage"]["inside_call_samples"] == 0
    corrupt, sample = edited()
    sample["thread_row"]["thread_state"] ^= 1
    oversized, sample = edited()
    sample["thread_row"]["native_fields"]["client_id_le"] += "00"
    bad_retry, sample = edited()
    call = sample["native_calls"][-1]
    sample["native_calls"].append(dict(call, buffer_bytes=2*call["buffer_bytes"]))
    for bad in (corrupt, oversized, bad_retry, dict(data, host=dict(data["host"], pointer_bytes=4))):
        try:
            assess(bad)
            raise AssertionError("accepted inconsistent native fields or layout")
        except ValueError:
            pass
    # Quantized clock ties admit both orderings. A second point inside the same call has its own evidence.
    for s in altered["sampler"]["samples"]:
        s["start_tick_ms"] = s["end_tick_ms"] = report["wait_sets"][0]["start_tick_ms"]
    tied = assess(altered)
    assert tied["status"] == "partial" and tied["sources_status"] == "complete" and not tied["coverage"]["inside_call_samples"]
    assert any(r["relation"] == "boundary_ambiguous" for r in tied["sample_links"])
    raw = bytes.fromhex("01000000") + bytes(252)
    assert thread_row(raw, len(raw), 1, 1) == ("invalid_layout", None)
    buffer = bytearray(336)
    struct.pack_into("<I", buffer, 4, 2)
    assert thread_row(buffer, len(buffer), 1, 1) == ("invalid_layout", None)
    alias = folder/"alias.json"
    source = folder/"ordered/original.json"
    alias.hardlink_to(source)
    digest = pin(source)
    with alias.open("ab") as stream:
        r = subprocess.run([sys.executable, "-B", CLI, "replay", "--capture", source, "--help"], stdout=stream, stderr=stream)
    assert r.returncode == 2 and pin(alias) == digest
    invoke(["replay", "--capture", source, "--sha256", "0"*64, "--output", folder/"no.json"], 2)
    assert not (folder/"no.json").exists()
    sample = data["sampler"]["samples"][index]
    for fragment in (data, report, report["host"], report["coverage"], sample, sample["native_calls"][0], sample["thread_row"], sample["thread_row"]["native_fields"],
                     data["sampler"], data["sampler"]["binding"], data["sampler"]["terminal_wait"], report["sample_links"][index],
                     report["wait_sets"][0], report["wait_sets"][0]["members"][0]):
        PRIVATE(fragment)

    lines = base64.b64decode(data["producer"]["stdout"]["base64"]).splitlines(keepends=True)
    def with_journal(raw):
        return assess(dict(data, producer=dict(data["producer"], stdout=record_bytes(io.BytesIO(raw), study.JOURNAL_LIMIT))))
    first = report["wait_sets"][0]
    prefix = with_journal(b"".join(lines[:first["wait_line"]]))
    assert prefix["status"] == "partial" and len(prefix["wait_sets"]) == 1
    assert prefix["wait_sets"][0]["waiting_samples"] == first["waiting_samples"]
    assert any(r["relation"] == "journal_gap" and r["wait_line"] is None for r in prefix["sample_links"])
    probe_line = first["members"][0]["pending_probe_line"]
    original = lines[probe_line-1]
    assert original.count(b'"event_result":258') == 1
    lines[probe_line-1] = original.replace(b'"event_result":258', b'"event_result":0')
    disputed = with_journal(b"".join(lines))
    w = disputed["wait_sets"][0]
    assert disputed["status"] == "partial" and w["disputed_by_probe_lines"] == [probe_line]
    assert w["native_selected_generation"] == 2 and w["qualified_selected_generation"] is None and w["waiting_samples"] == first["waiting_samples"]


def launch_controls(args, folder):
    exe = folder/"invalid.exe"
    exe.write_bytes(b"invalid image")
    dest = folder/"launch.json"
    command = ["capture", "--exe", exe, "--exe-sha256", pin(exe), "--wait-ms", 100, "--output", dest, folder/"a"]
    receipt = invoke(command, 1)
    assert receipt["capture_sha256"] == pin(dest)
    r = json.loads(dest.read_bytes())
    assert r["producer"]["state"] == "launch_error" and r["producer"]["os_error"] and not r["sampler"]["samples"]
    checked = folder/"failed-report.json"
    invoke(["replay", "--capture", dest, "--sha256", pin(dest), "--output", checked], 1)
    report = json.loads(checked.read_bytes())
    assert report["wait_sets"] == [] and report["producer_status"]["os_error"] == r["producer"]["os_error"]
    invoke(command, 2)
    rejected = folder/"wrong-pin.json"
    invoke(["capture", "--exe", args.exe, "--exe-sha256", "f"*64, "--output", rejected, "--wait-ms", 100, folder], 2)
    assert not rejected.exists()


def run(args, folder):
    dirs = [folder/name for name in ("a", "b", "c")]
    for d in dirs:
        d.mkdir()
    results = {}
    for name, watched in (("ordered", dirs), ("shared", [dirs[0], dirs[0]]), ("quiet", dirs), ("limited", dirs)):
        dest, report, witnesses = capture(name, folder, args, watched, name)
        data = independent(dest, report, witnesses)
        actual = [w["qualified_selected_generation"] for w in report["wait_sets"]]
        if name == "ordered":
            assert actual == [2, 1, None] and report["coverage"]["waits_with_waiting_sample"] == 3
        elif name == "shared":
            assert sorted(actual) == [1, 2]
        else:
            assert actual == [None] and report["wait_sets"][0]["wait_result"] == 258
        results[name] = data, report
        print(name, report["status"], report["coverage"])
    controls(*results["ordered"], results["quiet"][0], folder)
    launch_controls(args, folder)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--keep", type=Path, help="retain the original captures and independent views in a new directory")
    args = parser.parse_args()
    args.exe, args.oracle = args.exe.resolve(strict=True), args.oracle.resolve(strict=True)
    if args.keep:
        args.keep.mkdir()
        run(args, args.keep.resolve())
    else:
        with tempfile.TemporaryDirectory() as temp:
            run(args, Path(temp))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--capture-fixture"]:
        capture_fixture()
    else:
        main()
