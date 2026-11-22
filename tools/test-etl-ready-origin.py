"""Compare selected ReadyThread origins in the public TaskbarLatency ETL with TDH and TraceProcessor."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SCHEDULE = runpy.run_path(str(HERE / "test-etl-activity-schedule.py"))
TDH = SCHEDULE["SCHED"]
CAP = SCHEDULE["CAP"]
read = SCHEDULE["read"]
PIN = "8a59fa63479e49d68fc9bf878f1960313ce2ee179f30ee14655973a5bd7ec3d5"
# Ordinary waits, DPC on idle/non-idle CPUs, direct attempts, lifetimes ending
# before the ready event, and a missing prefix/tail in the original capture.
RECORDS = (369897, 373207, 373233, 373271, 373294, 738362, 738466,
           88389, 104979, 105005, 9013, 1065544, 1093290)
READY = ("record_ordinal", "raw_timestamp", "cpu", "logger_id", "payload_tid", "adjust_reason",
         "adjust_increment", "reserved_field", "ready_flags")
HEADER = ("header_thread_id", "header_process_id", "header_flags")


def select(path, pin, n):
    return ["--etl-switches", path, "--sha256", pin, "--ready-origin", str(n)]


def ordinal(row):
    return row["record_ordinal"]


def switch(actual, expected, role):
    if expected is None:
        assert actual is None
        return
    TDH["source_fields"](actual, expected, ("record_ordinal", "raw_timestamp", "cpu", "logger_id", "switch_ordinal", "version", "opcode"))
    assert actual["kind"] == "switch_" + role
    assert actual["payload_tid"] == expected["old_thread_id" if role == "out" else "new_thread_id"]
    if role == "out":
        TDH["source_fields"](actual, expected, ("old_state", "old_wait_reason"))


def boundary(actual, expected):
    if expected is None:
        assert actual is None
    else:
        TDH["source_fields"](actual, expected, ("record_ordinal", "raw_timestamp", "logger_id", "payload_tid", "payload_pid", "opcode"))


def bracket(actual, boundaries, ready):
    before = next((p for p in reversed(boundaries) if ordinal(p) < ordinal(ready)), None)
    after = next((p for p in boundaries if ordinal(p) > ordinal(ready)), None)
    boundary(actual["before"], before)
    boundary(actual["after"], after)
    if before and after and before["opcode"] in (1, 3) and after["opcode"] in (2, 4):
        assert before["payload_pid"] == after["payload_pid"] and before["logger_id"] == ready["logger_id"] == after["logger_id"]
        assert int(before["raw_timestamp"]) < int(ready["raw_timestamp"]) < int(after["raw_timestamp"])
        assert actual["paired_record_pid"] == before["payload_pid"]
        return before["payload_pid"]
    assert actual["paired_record_pid"] is None
    return None


def verify(doc, r, switches, bounds, ready, transitions):
    n, tid, cpu = ordinal(r), r["payload_tid"], r["cpu"]
    assert doc["schema"] == "kn.etl_switches.v5" and doc["status"] == "read" and doc["requested_ready_record"] == n
    TDH["source_fields"](doc["selected_ready"], r, READY)
    TDH["source_fields"](doc, r, HEADER)
    assert doc["selected_ready"]["cpu_field"] == ("processor_index" if r["header_flags"] & 0x200 else "processor_number")
    assert doc["executing_dpc"] == bool(r["ready_flags"] & 1) and doc["direct_switch_attempt"] == bool(r["ready_flags"] & 8)
    prior = next((p for p in reversed(switches) if p["cpu"] == cpu and ordinal(p) < n), None)
    following = next((p for p in switches if p["cpu"] == cpu and ordinal(p) > n), None)
    source, target, edge = doc["source_cpu_context"], doc["target_dispatch"], doc["relationship"]
    switch(source["switch_in"], prior, "in")
    switch(source["switch_out"], following, "out")
    if prior and following:
        assert prior["new_thread_id"] == following["old_thread_id"]
    context_tid = following["old_thread_id"] if following else prior["new_thread_id"] if prior else 0
    if context_tid:
        context_pid = bracket(source["thread_evidence"], bounds[context_tid], r)
    else:
        idle = source["thread_evidence"]
        assert idle["relation"] == "unusable_tid" and idle["before"] is idle["after"] is idle["paired_record_pid"] is None
        context_pid = None
    assert source["header_binding"] == "unreported" and r["header_thread_id"] == r["header_process_id"] == 0xffffffff

    earlier = [(role, p) for role, p in transitions[tid] if ordinal(p) < n]
    earlier.extend(("boundary", p) for p in bounds[tid] if ordinal(p) < n)
    role, before = max(earlier, key=lambda item: ordinal(item[1]), default=(None, None))
    after = next((p for k, p in transitions[tid] if k == "in" and ordinal(p) > n), None)
    if role == "boundary":
        boundary(target["preceding_thread_event"], before)
    else:
        switch(target["preceding_thread_event"], before, role)
    switch(target["switch_out"], before if role == "out" else None, "out")
    switch(target["switch_in"], after, "in")
    target_pid = bracket(target["thread_evidence"], bounds[tid], r)
    if target["relation"] == "waiting_ready_switch_in":
        assert role == "out" and before["old_state"] == 5 and target_pid is not None
        seq = [p for p in ready[tid] if ordinal(before) < ordinal(p) < ordinal(after)]
        assert seq[-1] == r and sum(not (p["ready_flags"] & ~9) for p in seq) == target["dispatchable_records"] == 1
        assert target["ready_records"] == len(seq)
        TDH["source_fields"](target["first_ready"], seq[0], READY)
        if len(seq) == 1:
            assert target["last_ready"] is None
        else:
            TDH["source_fields"](target["last_ready"], seq[-1], READY)
        tick = int(r["raw_timestamp"])
        assert int(target["switch_out_to_ready_ticks"]) == tick - int(before["raw_timestamp"]) > 0
        assert int(target["ready_to_switch_in_ticks"]) == int(after["raw_timestamp"]) - tick > 0
    else:
        assert target["switch_out_to_ready_ticks"] is target["ready_to_switch_in_ticks"] is None
    if doc["executing_dpc"]:
        assert edge["relation"] == "dpc_context"
    elif n in (104979, 105005):
        assert context_pid is None and source["thread_evidence"]["before"]["opcode"] == 2
        assert source["thread_evidence"]["after"] is None and target["relation"] == "waiting_ready_switch_in"
        assert edge["relation"] == "thread_bracket_unqualified"
    else:
        assert prior and following and context_tid != tid and context_pid and target_pid
        assert target["relation"] == "waiting_ready_switch_in" and source["relation"] == "running_on_cpu"
        assert edge == {"relation": "readying_thread_context", "readying_pid": context_pid, "readying_tid": context_tid}
    if edge["relation"] != "readying_thread_context":
        assert edge["readying_pid"] is edge["readying_tid"] is None
    for private in (source, target, edge, doc["selected_ready"]):
        TDH["require_private"](private)


def sdk_rows(sdk, path, docs):
    keys = {}
    for doc in docs:
        r = doc["selected_ready"]
        keys[f'{r["payload_tid"]},{r["cpu"]},{r["raw_timestamp"]}'] = doc
    p = subprocess.run([sdk, path, *keys], capture_output=True, check=True, timeout=240)
    result = json.loads(p.stdout)
    raw, activity = defaultdict(list), defaultdict(list)
    for row in result["ready_rows"]:
        raw[row["key"]].append(row)
        TDH["require_private"](row)
    for row in result["activity_rows"]:
        activity[row["key"]].append(row)
        TDH["require_private"](row)
    assert all(0 < row["row"] <= result["ready_total"] for group in raw.values() for row in group)
    assert all(0 < row["row"] <= result["activity_total"] for group in activity.values() for row in group)
    compared = 0
    for key, doc in keys.items():
        n = doc["requested_ready_record"]
        if not raw[key]:
            assert n in (9013, 1065544, 1093290) and doc["relationship"]["readying_tid"] is None
            continue
        ready, = raw[key]
        assert (ready["dpc"], ready["direct"]) == (doc["executing_dpc"], doc["direct_switch_attempt"])
        target = doc["target_dispatch"]
        if target["relation"] != "waiting_ready_switch_in":
            continue
        row, = activity[key]
        compared += 1
        assert row["previous_out"] == target["switch_out"]["raw_timestamp"] and row["switch_in"] == target["switch_in"]["raw_timestamp"]
        assert (row["target_tid"], row["target_pid"], row["switch_in_cpu"]) == (
            target["switch_in"]["payload_tid"], target["thread_evidence"]["paired_record_pid"], target["switch_in"]["cpu"])
        edge = doc["relationship"]
        if edge["readying_tid"] is not None:
            assert (ready["source_tid"], ready["source_pid"]) == (row["source_tid"], row["source_pid"]) == (edge["readying_tid"], edge["readying_pid"])
        if n in (104979, 105005):
            assert row["source_exited"] and int(row["source_exited"]) < int(doc["selected_ready"]["raw_timestamp"])
        print(f'ETW {n}, SDK ReadyThread {ready["row"]}, ThreadActivity {row["row"]}, {edge["relation"]}')
    print(f'SDK ReadyThread {result["ready_total"]}, ThreadActivity {result["activity_total"]}, matched target waits {compared}')


def controls(exe, trace, doc, openssl, folder):
    n = doc["requested_ready_record"]
    flags = select(trace, PIN, n)
    _, digest = read(exe, flags)
    for selector in (["--thread-id", "1"], ["--after", "0"], ["--limit", "1"], ["--capture-settings"],
                     ["--intervals"], ["--schedule-activity", "1", "2"], ["--ready-origin", "1"]):
        for args in ([*flags, *selector], [*flags[:4], *selector, *flags[4:]]):
            assert not CAP["invoke"](exe, args, 2)
    for bad in ([], ["0"], ["01"], ["-1"], ["2000001"]):
        assert not CAP["invoke"](exe, [*flags[:-1], *bad], 2)
    assert not CAP["invoke"](exe, ["--etl-hard-faults", *flags[1:]], 2)
    for args, status in ((select(trace, PIN, 1), "not_ready_thread"),
                         (select(trace, PIN, doc["records_seen"] + 1), "ready_record_not_observed"),
                         (select(trace, "0"*64, n), "digest_mismatch")):
        for extra in ([], ["--check-page", digest]):
            bad, _ = read(exe, [*args, *extra], 1)
            assert bad["status"] == status and bad["requested_ready_record"] == int(args[-1])
    wrong, _ = read(exe, [*select(trace, PIN, 373233), "--check-page", digest], 1)
    assert wrong["status"] == "page_mismatch" and not wrong["page_bytes_match"]
    sign = SCHEDULE["ACTIVITY"]["SIGNED"]
    signer = sign["Signer"](openssl, folder / "keys") if openssl else None

    def replay(path, args, value, code):
        plain, _ = read(exe, [*args, "--check-page", value], code)
        assert plain["page_bytes_match"] and plain["requested_ready_record"] == n
        TDH["require_private"](plain)
        if signer:
            statement = folder / "capture.jws"
            statement.write_bytes(signer.token(sign["statement"](path)))
            signed, _ = read(exe, [*args, "--check-page", value, "--capture-statement", statement, "archive_witness", signer.point], code)
            assert signed["capture_statement"]["bound_to_replayed_page"] and signed["source_status"] == plain["source_status"]

    replay(trace, flags, digest, 0)
    original = trace.read_bytes()
    header = struct.pack("<qqII", int(doc["clock"]["header_perf_frequency"]), int(doc["log_header"]["start_filetime"]), 1, 0)
    assert original[:512].count(header) == 1
    for delta, fmt, value in ((0, "<q", 0), (16, "<I", 2), (20, "<I", 1)):
        changed = bytearray(original)
        struct.pack_into(fmt, changed, original[:512].index(header) + delta, value)
        path = folder / "header.etl"
        path.write_bytes(changed)
        args = select(path, hashlib.sha256(changed).hexdigest(), n)
        code = int(delta == 20)
        limited, page = read(exe, args, code)
        assert limited["status"] == ("partial" if code else "read")
        assert limited["relationship"]["readying_tid"] is None and limited["target_dispatch"]["ready_to_switch_in_ticks"] is None
        assert limited["source_cpu_context"]["relation"] == ("coverage_unqualified" if code else "clock_unqualified")
        if code:
            replay(path, args, page, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "oracle", "etl", "sdk"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--openssl", type=Path)
    args = parser.parse_args()
    path = args.etl.resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == PIN
    footer, _, switches, bounds, ready, transitions = TDH["tdh"](args.oracle, path)
    wanted = {ordinal(r): r for rows in ready.values() for r in rows if ordinal(r) in RECORDS}
    docs = []
    for n in RECORDS:
        doc, _ = read(args.exe, select(path, PIN, n))
        assert doc["records_seen"] == footer["records_seen"] and doc["decoded_switches"] == len(switches)
        assert doc["ready_records"] == sum(map(len, ready.values())) and doc["thread_boundary_records"] == sum(map(len, bounds.values()))
        verify(doc, wanted[n], switches, bounds, ready, transitions)
        docs.append(doc)
    sdk_rows(args.sdk, path, docs)
    with tempfile.TemporaryDirectory() as folder:
        controls(args.exe, path, docs[0], args.openssl, Path(folder))
    print("TDH, replay and scope controls passed", dict(Counter(doc["relationship"]["relation"] for doc in docs)))


if __name__ == "__main__":
    main()
