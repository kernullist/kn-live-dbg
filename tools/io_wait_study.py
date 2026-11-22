"""Check a retained I/O journal and qualify thread-state samples against the original wait calls."""
import io
import json
from collections import Counter
from pathlib import Path
import runpy
import struct

from owned_module_benchmark import check, decimal, fields, sha, uint
from saved_etl_comparison import DIAGNOSTIC, digest, original


IO = runpy.run_path(str(Path(__file__).with_name("replay-io-lifecycle.py")))
JOURNAL_LIMIT = 128 * 1024
PACKAGE_LIMIT = 2 << 20
MAX_SAMPLES = 512
DWORD = 0xffffffff
TIMEOUT = 258
MATCHED = dict(status="matched", win32_status=0)


def decode(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=IO["unique"])


def liveness(result):
    fields(result, "result win32_error", "retained thread liveness")
    value = uint(result["result"], DWORD)
    check(value in (0, TIMEOUT, DWORD) and bool(uint(result["win32_error"], DWORD)) == (value == DWORD), "invalid liveness result")
    return value


def native_row(row, used, binding):
    fields(row, "process_id client_process_id client_thread_id thread_state raw_wait_reason native_fields", "native thread row")
    source = row["native_fields"]
    fields(source, "process_offset thread_index process_header_le owner_le client_id_le state_reason_le", "native field locations")

    def unpack(key, fmt):
        text = source[key]
        check(type(text) is str and len(text) == 2*struct.calcsize(fmt), "invalid native field extent")
        raw = bytes.fromhex(text)
        check(raw.hex() == text, "invalid native field bytes")
        return struct.unpack(fmt, raw)

    offset, index = uint(source["process_offset"], used), uint(source["thread_index"], DWORD)
    stride, count = unpack("process_header_le", "<II")
    check(offset % 8 == 0 and index < count and
          (not stride or (stride % 8 == 0 and offset+stride <= used)) and
          256 + 80*count <= (stride if stride else used-offset), "thread field outside native record")
    values = (*unpack("owner_le", "<Q"), *unpack("client_id_le", "<QQ"), *unpack("state_reason_le", "<II"))
    check(values == tuple(uint(row[k], DWORD) for k in ("process_id", "client_process_id", "client_thread_id", "thread_state", "raw_wait_reason")),
          "thread fields differ from native bytes")
    check(values[:3] == (binding["owner_pid"], binding["owner_pid"], binding["thread_id"]), "foreign thread projection")


def sample_status(sample, slot, binding, previous):
    fields(sample, "slot start_tick_ms end_tick_ms before after native_calls lookup thread_row", "thread-state sample")
    lo, hi = decimal(sample["start_tick_ms"]), decimal(sample["end_tick_ms"])
    check(uint(sample["slot"]) == slot and previous <= lo <= hi, "sample outside capture order")
    before, after = (liveness(sample[k]) for k in ("before", "after"))
    check(before != 0 or after != TIMEOUT, "retained thread became live again")
    calls, lookup, row = sample["native_calls"], sample["lookup"], sample["thread_row"]
    check(type(calls) is list and len(calls) <= 5 and bool(calls) == (before == TIMEOUT), "inconsistent native query count")
    size, used, status = 0, 0, None
    for call in calls:
        fields(call, "buffer_bytes returned_bytes ntstatus", "native query")
        capacity = uint(call["buffer_bytes"], 32 << 20)
        check(capacity >= 1 << 20 and (not size or (capacity == max(size*2, used) and status == 0xc0000004)), "unexpected native query retry")
        size, status = capacity, uint(call["ntstatus"], DWORD)
        used = uint(call["returned_bytes"], DWORD)
    if status is None:
        check(lookup == "not_queried", "unexpected lookup without a call")
    elif status:
        if status == 0xc0000004 and max(size*2, used) > 32 << 20:
            check(lookup == "buffer_limit", "unreported buffer limit")
        else:
            check(lookup == "query_failed" and (status != 0xc0000004 or len(calls) == 5), "unexpected failed lookup")
    else:
        check(lookup in ("found", "thread_absent", "process_absent", "duplicate_process", "conflicting_thread", "invalid_layout") and
              (lookup == "invalid_layout" or 256 <= used <= size), "invalid native result extent")
    check((row is not None) == (lookup == "found"), "inconsistent native thread row")
    if row is not None:
        native_row(row, used, binding)
    if DWORD in (before, after):
        return hi, "liveness_unavailable"
    if before != TIMEOUT or after != TIMEOUT:
        return hi, "lifetime_unqualified"
    return hi, "observed" if row is not None else lookup


def sampler_evidence(package):
    sampler = package["sampler"]
    fields(sampler, "plan_line_sha256 binding samples stopped terminal_wait", "scheduler source")
    if sampler["plan_line_sha256"] is not None:
        digest(sampler["plan_line_sha256"])
    binding, samples, stopped = sampler["binding"], sampler["samples"], sampler["stopped"]
    check(type(samples) is list and len(samples) <= package["sample_limit"], "too many scheduler samples")
    terminal = sampler["terminal_wait"]
    check((terminal is not None) == (stopped in ("thread_ended", "liveness_unavailable")), "missing or unexpected final thread wait")
    if binding is None:
        check(not samples and stopped in ("no_plan", "producer_unbound", "unsupported_layout") and
              (sampler["plan_line_sha256"] is None) == (stopped == "no_plan"), "unexpected unbound capture")
        return []
    status = binding["status"]
    detailed = status in ("bound", "generation_mismatch")
    fields(binding, "status win32_error" + (" owner_pid thread_id thread_created" if detailed else ""), "thread handle identity")
    error = uint(binding["win32_error"], DWORD)
    if detailed:
        check(not error and uint(binding["owner_pid"], DWORD) and uint(binding["thread_id"], DWORD) and
              decimal(binding["thread_created"]), "invalid thread handle identity")
    else:
        check(status in ("open_failed", "identity_unavailable", "api_unavailable") and error, "invalid thread open result")
    check(sampler["plan_line_sha256"] is not None, "unbound journal plan")
    if status != "bound":
        check(not samples and stopped == "thread_unbound", "samples from an unbound thread")
        return []
    check(stopped in ("thread_ended", "deadline", "liveness_unavailable", "sample_limit") and
          (stopped != "sample_limit" or len(samples) == package["sample_limit"]), "invalid sampling stop")
    previous, result = 0, []
    for index, sample in enumerate(samples, 1):
        previous, relation = sample_status(sample, index, binding, previous)
        result.append(relation)
        check(index == len(samples) or liveness(sample["after"]) == TIMEOUT, "samples after a lifetime boundary")
    if terminal is not None:
        fields(terminal, "sample_slot phase tick_ms wait", "final retained thread wait")
        check(samples and uint(terminal["sample_slot"]) == len(samples) and decimal(terminal["tick_ms"]) >= previous and
              liveness(terminal["wait"]) == (0 if stopped == "thread_ended" else DWORD), "invalid final thread wait")
        last = samples[-1]["after"]
        check((terminal["phase"] == "after_sample" and terminal["wait"] == last) or
              (terminal["phase"] == "between_samples" and liveness(last) == TIMEOUT and len(samples) < package["sample_limit"]),
              "final thread wait out of sequence")
    elif samples:
        check(liveness(samples[-1]["after"]) == TIMEOUT, "unreported final thread wait")
    return result


def producer_records(package):
    attempt = package["producer"]
    fields(attempt, "state exit_code os_error image_binding process_identity stdout stderr", "I/O producer")
    state = attempt["state"]
    check(state in ("exited", "timed_out", "launch_error"), "invalid producer state")
    if state == "launch_error":
        check(uint(attempt["os_error"], DWORD) and attempt["exit_code"] is attempt["image_binding"] is attempt["process_identity"] is None,
              "invalid failed launch")
    else:
        check(attempt["os_error"] is None and ((state == "exited" and type(attempt["exit_code"]) is int) or
              (state == "timed_out" and attempt["exit_code"] is None)), "invalid producer exit")
        binding = attempt["image_binding"]
        fields(binding, "status win32_status", "process image binding")
        check(binding["status"] in ("unavailable", "different_path", "matched") and
              bool(uint(binding["win32_status"], DWORD)) == (binding["status"] == "unavailable"), "invalid process image binding")
        identity = attempt["process_identity"]
        if identity is not None:
            fields(identity, "pid process_created", "retained process identity")
            check(uint(identity["pid"], DWORD) and decimal(identity["process_created"]), "invalid process generation")
    raw, complete = original(attempt["stdout"], JOURNAL_LIMIT)
    original(attempt["stderr"], DIAGNOSTIC)
    if state == "launch_error":
        check(not attempt["stdout"]["byte_count"] and not attempt["stderr"]["byte_count"] and package["sampler"]["stopped"] == "no_plan",
              "observations without a launched producer")
    if not complete:
        return None, None, None, {}, None, "journal_truncated"
    try:
        source = IO["read_journal_stream"](io.BytesIO(raw), sha(raw))
        timing = IO["assess"](*source, sha(raw), True)
    except (ValueError, KeyError, TypeError, RecursionError):
        return None, None, None, {}, None, "journal_unavailable"
    prefix = source[0][:timing["qualified_prefix_lines"]]
    pending = {r["generation"]: n for n, r in enumerate(prefix, 1) if r["kind"] == "probe" and r["error"] == IO["INCOMPLETE"]}
    return source[0][0], sha(raw.split(b"\n", 1)[0]+b"\n"), timing, pending, prefix[-1]["tick"], None


def correspondence(package, plan, plan_hash, prefix_end):
    producer, sampler = package["producer"], package["sampler"]
    if producer["image_binding"] != MATCHED:
        return "image_unbound"
    if plan is None:
        return "journal_unavailable"
    if plan["requests"] != package["request_count"] or plan["wait_ms"] != package["wait_ms"]:
        return "plan_mismatch"
    if producer["process_identity"] != dict(pid=plan["pid"], process_created=plan["process_created"]):
        return "process_generation_mismatch"
    if sampler["plan_line_sha256"] != plan_hash:
        return "plan_line_unbound"
    bound = sampler["binding"]
    if not bound or bound["status"] != "bound":
        return "thread_unbound"
    if (bound["owner_pid"], bound["thread_id"], bound["thread_created"]) != (plan["pid"], plan["tid"], plan["thread_created"]):
        return "thread_generation_mismatch"
    samples, terminal = sampler["samples"], sampler["terminal_wait"]
    if samples and int(samples[0]["start_tick_ms"]) < plan["tick"]:
        return "sample_before_provider_plan"
    if sampler["stopped"] == "thread_ended" and int(terminal["tick_ms"]) < prefix_end:
        return "thread_exit_before_provider_record"
    return "same_live_thread"


def assess(package, pin):
    fields(package, "schema host collector_sha256 wait_ms request_count interval_ms sample_limit producer sampler", "I/O wait capture")
    check(package["schema"] == "kn.io_thread_wait_capture.v1" and uint(package["wait_ms"], 30000) and uint(package["request_count"], 8) and
          uint(package["interval_ms"], 1000) and uint(package["sample_limit"], MAX_SAMPLES), "invalid capture plan")
    digest(package["collector_sha256"])
    host = package["host"]
    fields(host, "windows_version pointer_bytes machine information_class clock", "scheduler environment")
    version = host["windows_version"]
    check(type(version) is list and len(version) == 3 and all(uint(v, DWORD) == v for v in version) and version[0] and version[2] and
          uint(host["pointer_bytes"]) in (4, 8) and type(host["machine"]) is str and len(host["machine"]) <= 32 and
          host["information_class"] == "SystemProcessInformation" and host["clock"] == "GetTickCount64_ms", "invalid scheduler environment")
    supported = host["pointer_bytes"] == 8 and host["machine"] in ("amd64", "x86_64")
    check(supported or package["sampler"]["stopped"] in ("unsupported_layout", "no_plan", "producer_unbound"), "samples on an unsupported layout")
    check(not supported or package["sampler"]["stopped"] != "unsupported_layout", "inconsistent layout selection")
    plan, header_hash, timing, pending, prefix_end, journal_issue = producer_records(package)
    statuses = sampler_evidence(package)
    binding = correspondence(package, plan, header_hash, prefix_end)
    queries = package["sampler"]["samples"]
    waits = []
    if timing:
        requests = {r["generation"]: r for r in timing["requests"]}
        for wait in timing["monitor"]["waits"]:
            members = [dict(generation=g, admit_line=requests[g]["admission"]["evidence_line"], submit_line=requests[g]["submission"]["evidence_line"],
                            pending_probe_line=pending.get(g),
                            outcome=requests[g]["outcome"], result_line=(requests[g]["native_final_result"] or {}).get("evidence_line"))
                       for g in wait["generations"]]
            selected = wait["selected_generation"]
            qualified = selected is not None and not wait["disputed_by_probe_lines"] and not requests[selected]["conflict_evidence_lines"]
            waits.append(dict(wait_line=wait["evidence_line"], start_tick_ms=wait["start_tick_ms"], end_tick_ms=wait["end_tick_ms"],
                              semantics="wait_any", members=members, wait_result=wait["wait_result"], win32_error=wait["win32_error"],
                              native_selected_generation=selected, qualified_selected_generation=selected if qualified else None,
                              disputed_by_probe_lines=wait["disputed_by_probe_lines"],
                              inside_samples=[], waiting_samples=[]))
    links = []
    for row, status in zip(queries, statuses, strict=True):
        lo, hi = (int(row[k]) for k in ("start_tick_ms", "end_tick_ms"))
        overlaps = [w for w in waits if lo <= int(w["end_tick_ms"]) and int(w["start_tick_ms"]) <= hi]
        inside = next((w for w in overlaps if int(w["start_tick_ms"]) < lo and hi < int(w["end_tick_ms"])), None)
        relation = status if binding == "same_live_thread" else binding
        line = state = wait_reason = None
        if relation == "observed":
            state = row["thread_row"]["thread_state"]
            wait_reason = row["thread_row"]["raw_wait_reason"] if state == 5 else None
            if inside:
                line = inside["wait_line"]
                inside["inside_samples"].append(row["slot"])
                relation = "inside_wait_call"
                if state == 5:
                    inside["waiting_samples"].append(row["slot"])
                    relation = "waiting_inside_call"
            elif overlaps:
                relation = "boundary_ambiguous"
            elif not timing["journal_complete"] and hi >= prefix_end:
                relation = "journal_gap"
            else:
                relation = "outside_recorded_wait_calls"
        links.append(dict(sample_slot=row["slot"], relation=relation, wait_line=line,
                          reported_thread_state=state, wait_reason_when_waiting=wait_reason,
                          touching_wait_lines=[w["wait_line"] for w in overlaps] if binding == "same_live_thread" else []))
    for wait in waits:
        wait["scheduler_evidence"] = ("waiting_observed" if wait["waiting_samples"] else "other_state_only" if wait["inside_samples"]
                                      else "no_interior_sample" if binding == "same_live_thread" else "thread_unbound")
    producer = package["producer"]
    source_complete = (timing and timing["journal_complete"] and not timing["coverage"]["conflicts"] and binding == "same_live_thread" and
                       producer["state"] == "exited" and producer["exit_code"] == 0 and package["sampler"]["stopped"] == "thread_ended" and
                       "observed" in statuses and all(s in ("observed", "lifetime_unqualified") for s in statuses))
    observed_calls = sum(bool(w["inside_samples"]) for w in waits)
    complete = source_complete and waits and observed_calls == len(waits)
    return dict(schema="kn.io_thread_waits.v1", status="complete" if complete else "partial", sources_status="complete" if source_complete else "partial",
                capture_sha256=pin, host=host,
                collector_sha256=package["collector_sha256"], journal_sha256=producer["stdout"]["original_sha256"], journal_issue=journal_issue,
                producer_status={k: producer[k] for k in ("state", "exit_code", "os_error", "image_binding", "process_identity")},
                journal_timing=timing, qualified_prefix_end_ms=str(prefix_end) if prefix_end is not None else None,
                thread_binding=binding, scheduler_source=package["sampler"], wait_sets=waits, sample_links=links,
                coverage=dict(recorded_wait_calls=len(waits), waits_with_inside_sample=observed_calls, attempted_samples=len(queries),
                              sample_relations=dict(sorted(Counter(link["relation"] for link in links).items())),
                              inside_call_samples=sum(len(w["inside_samples"]) for w in waits),
                              waiting_inside_call_samples=sum(len(w["waiting_samples"]) for w in waits),
                              waits_with_waiting_sample=sum(bool(w["waiting_samples"]) for w in waits)),
                scheduler_duration_ms=None, kernel_request_identity=None)
