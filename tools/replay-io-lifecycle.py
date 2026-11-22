"""Replay a pinned Windows directory I/O journal into per-request lifecycle evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


DWORD = (1 << 32) - 1
U64 = (1 << 64) - 1
ABORTED, INCOMPLETE, ENUM_DIR, TIMEOUT, FAILED = 995, 996, 1022, 258, DWORD
SCHEMA = "kn.io_lifetime.v1"
COMMON = set("schema run seq tick kind generation".split())
EXTRA = {
    "plan": "source clock pid process_created tid thread_created requests wait_ms buffer_bytes notify_filter subtree",
    "admit": "stage error rejected_close_error volume file_id", "issue": "", "submit": "start ok error",
    "probe": "start ok error bytes event_result event_error", "monitor": "",
    "wait": "start timeout_ms generations result error", "cancel": "start ok error",
    "result": "start ok error bytes event_result event_error", "release": "quiesce_result quiesce_error close_attempted directory_error event_error", "end": "",
}


def check(test, reason):
    if not test:
        raise ValueError(reason)


def uint(v, maximum=DWORD):
    check(type(v) is int and 0 <= v <= maximum, "invalid unsigned integer")
    return v


def decimal(v):
    check(type(v) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", v), "invalid decimal identity")
    return uint(int(v), U64)


def hexadecimal(v):
    return type(v) is str and re.fullmatch(r"[a-f0-9]{32}", v)


def unique(pairs):
    row = dict(pairs)
    check(len(row) == len(pairs), "duplicate JSON key")
    return row


def native_error(ok, error):
    check(type(ok) is bool, "invalid success flag")
    if ok:
        check(error is None, "error on a successful call")
    else:
        uint(error)


def validate_record(r, previous_tick):
    check(type(r) is dict and r.get("schema") == SCHEMA and type(r.get("kind")) is str and r["kind"] in EXTRA,
          "unsupported journal record")
    k = r["kind"]
    check(r.keys() == COMMON | set(EXTRA[k].split()), "unexpected record fields")
    check(hexadecimal(r["run"]) and int(r["run"], 16) != 0, "invalid provider run")
    uint(r["seq"], 127)
    t = uint(r["tick"], U64)
    check(t >= previous_tick, "observer clock regressed")
    g = uint(r["generation"], 8)
    check((g == 0) == (k in ("plan", "monitor", "wait", "end")), "incorrect generation scope")
    if "start" in r:
        check(previous_tick <= uint(r["start"], U64) <= t, "call outside observer order")
    if k == "plan":
        check(r["source"] == "win32_directory_changes" and r["clock"] == "GetTickCount64_ms" and
              uint(r["pid"]) and decimal(r["process_created"]) and uint(r["tid"]) and decimal(r["thread_created"]),
              "unbound provider")
        check(uint(r["requests"], 8) and uint(r["wait_ms"], 30000) and uint(r["buffer_bytes"]) == 4096 and
              uint(r["notify_filter"]) == 3 and r["subtree"] is False, "invalid collection plan")
    elif k == "admit":
        stage = r["stage"]
        check(stage in ("ready", "path_policy", "parent_unavailable", "open", "attributes", "directory_policy",
                        "volume", "volume_policy", "file_id", "create_event"), "unknown admission stage")
        native_error(stage in ("ready", "path_policy", "parent_unavailable", "directory_policy", "volume_policy"), r["error"])
        if r["rejected_close_error"] is not None:
            check(stage in ("attributes", "directory_policy", "volume", "volume_policy", "file_id", "create_event"),
                  "unexpected declined handle close result")
            uint(r["rejected_close_error"])
        if stage == "ready":
            decimal(r["volume"])
            check(hexadecimal(r["file_id"]), "missing directory identity")
        else:
            check(r["volume"] is None and r["file_id"] is None, "identity on failed admission")
    elif k in ("submit", "cancel", "probe", "result"):
        native_error(r["ok"], r["error"])
        if k in ("probe", "result"):
            if r["ok"]:
                uint(r["bytes"], 4096)
            else:
                check(r["bytes"] is None, "byte count on unsuccessful result")
            sig = uint(r["event_result"])
            check(sig in (0, TIMEOUT, FAILED), "invalid manual-reset event result")
            native_error(sig != FAILED, r["event_error"])
    elif k == "wait":
        status = uint(r["result"])
        native_error(status != FAILED, r["error"])
        uint(r["timeout_ms"], 30000)
        gens = r["generations"]
        check(type(gens) is list and 1 <= len(gens) <= 8 and all(uint(i, 8) for i in gens) and
              gens == sorted(set(gens)), "invalid active operation list")
        check(status < len(gens) or status in (TIMEOUT, FAILED), "invalid event selection")
    elif k == "release":
        quiesce = r["quiesce_result"]
        if quiesce is not None:
            check(uint(quiesce) in (0, FAILED), "invalid final event wait")
        native_error(quiesce != FAILED, r["quiesce_error"])
        check(r["close_attempted"] is (quiesce != FAILED), "release differs from event ownership")
        check(r["close_attempted"] or (r["directory_error"] is None and r["event_error"] is None), "close result without release")
        for error in (r["directory_error"], r["event_error"]):
            if error is not None:
                uint(error)


def read_journal_stream(stream, pin):
    check(type(pin) is str and re.fullmatch(r"[a-f0-9]{64}", pin), "invalid SHA-256")
    raw = stream.read(128 * 1024 + 1)
    check(len(raw) <= 128 * 1024 and hashlib.sha256(raw).hexdigest() == pin, "capture size or SHA-256 mismatch")
    *lines, tail = raw.split(b"\n")
    check(1 <= len(lines) <= 128 and len(tail) <= 4096, "missing plan or oversized journal")
    rows, gaps, seen = [], [], set()
    order = {name: i for i, name in enumerate(("admit", "issue", "submit", "probe", "cancel", "result", "release"))}
    phases, unavailable, rejected, selected = {}, set(), set(), set()
    draining = False
    previous_seq, previous_tick = -1, 0
    for index, line in enumerate(lines):
        check(0 < len(line) <= 4096, "empty or oversized record")
        r = json.loads(line.decode("utf-8-sig" if index == 0 else "utf-8"), object_pairs_hook=unique)
        validate_record(r, previous_tick)
        if not rows:
            check(r["kind"] == "plan" and r["seq"] == 0, "first complete record must be the plan")
        else:
            plan = rows[0]
            check(r["run"] == plan["run"] and r["generation"] <= plan["requests"] and r["kind"] != "plan",
                  "provider run or generation conflict")
            check(rows[-1]["kind"] != "end" and r["seq"] > previous_seq, "duplicate, late or reordered record")
            if r["seq"] > previous_seq + 1:
                gaps.append(dict(first_missing=previous_seq + 1, last_missing=r["seq"] - 1, next_line=index + 1))
        k, g = r["kind"], r["generation"]
        if g:
            check(order[k] > phases.get(g, -1) and g not in unavailable and (g not in rejected or k == "release"),
                  "retained generation reused or observed after failure")
            phases[g] = order[k]
            if k == "admit" and r["stage"] != "ready":
                unavailable.add(g)
            if k == "submit" and not r["ok"]:
                rejected.add(g)
            if k == "cancel":
                check(g not in selected, "cancel after a selected completion")
                draining = True
        elif k == "wait":
            gens = r["generations"]
            check(not draining and all(i <= rows[0]["requests"] and phases.get(i, -1) < order["result"] and
                                      i not in unavailable | rejected | selected for i in gens), "invalid or retired wait member")
            if r["result"] < len(gens):
                selected.add(gens[r["result"]])
            else:
                draining = True
        if k != "wait":
            key = (r["generation"], r["kind"])
            check(key not in seen, "duplicate phase for a retained generation")
            seen.add(key)
        previous_seq, previous_tick = r["seq"], r["tick"]
        rows.append(r)
    check(not tail or rows[-1]["kind"] != "end", "data after committed end")
    return rows, gaps, len(tail)


def read_journal(path, pin):
    with path.open("rb") as stream:
        return read_journal_stream(stream, pin)


class PrefixEnded(Exception):
    pass


class Transcript:
    def __init__(self, rows, limit):
        self.rows = rows
        self.limit = limit
        self.pos = 1

    def take(self, kind, generation=0):
        if self.pos == self.limit:
            raise PrefixEnded
        row = self.rows[self.pos]
        check((row["kind"], row["generation"]) == (kind, generation), "operation differs from retained ownership or sequence")
        self.pos += 1
        return row, self.pos  # Physical line number, including the plan.


class Operation:
    def __init__(self, generation):
        self.gen = generation
        self.lines = {}
        self.states = []
        self.known = None
        self.probe = None
        self.selected = None
        self.conflict = False
        self.admitted = False
        self.queued = False
        self.retired = False
        self.native_result = None
        self.admission = None

    def take(self, source, kind):
        row, line = source.take(kind, self.gen)
        self.lines[kind] = line
        return row

    def state(self, name, *lines):
        self.states.append(dict(state=name, evidence_lines=list(lines)))

    def invalidate(self, *lines):
        self.conflict = True
        self.known = None
        self.state("IdentityConflict", *lines)

    def release(self, source):
        r = self.take(source, "release")
        check((r["quiesce_result"] is not None) == self.queued, "final event wait differs from admitted I/O")
        self.retired = r["close_attempted"] and r["directory_error"] is None and r["event_error"] is None
        if self.retired and self.known and not self.conflict and "result" in self.lines:
            self.state("RetiredWithKnownOutcome", self.lines["result"], self.lines["release"])
        elif not self.retired:
            self.state("ReleaseUnconfirmed", self.lines["release"])

    def observe_result(self, row, kind):
        line = self.lines[kind]
        value = (row["ok"], row["error"], row["bytes"])
        if kind == "probe":
            self.probe = row
            if row["error"] == INCOMPLETE:
                self.state("PendingObserved", line)
        else:
            self.native_result = dict(ok=row["ok"], win32_error=row["error"], bytes=row["bytes"], evidence_line=line)
            p = self.probe
            prior_result = p["ok"] or p["error"] in (ABORTED, ENUM_DIR)
            changed = prior_result and value != (p["ok"], p["error"], p["bytes"])
            signaled_then_timeout = (self.selected or p["event_result"] == 0) and row["event_result"] == TIMEOUT
            if changed or signaled_then_timeout:
                sources = [self.lines["probe"]] if changed or p["event_result"] == 0 else []
                if signaled_then_timeout and self.selected:
                    sources.append(self.selected)
                self.invalidate(*sources, line)
                return
        if self.conflict:
            return
        if row["event_result"] == 0 and (row["ok"] or row["error"] in (ABORTED, ENUM_DIR)):
            if row["ok"]:
                outcome = "completed_without_change_details" if row["bytes"] == 0 else "completed"
            else:
                outcome = "operation_aborted" if row["error"] == ABORTED else "changes_require_enumeration"
            self.known = dict(outcome=outcome, bytes=row["bytes"], win32_error=row["error"], evidence_line=line)
            self.state("CompletionObserved", self.lines["issue"], self.lines["submit"], line)
        elif kind == "result":
            self.known = None
            self.state("ObservationGap", line)

    def admit(self, source):
        r = self.take(source, "admit")
        self.admission = dict(stage=r["stage"], win32_error=r["error"], rejected_close_error=r["rejected_close_error"],
                              evidence_line=self.lines["admit"])
        self.admitted = r["stage"] == "ready"
        if not self.admitted:
            self.state("AdmissionUnavailable", self.lines["admit"])
            return
        self.take(source, "issue")
        self.state("RequestObserved", self.lines["admit"], self.lines["issue"])
        r = self.take(source, "submit")
        if not r["ok"]:
            self.state("SubmissionFailed", self.lines["submit"])
            self.release(source)
            return
        self.queued = True
        self.state("SubmissionObserved", self.lines["submit"])
        self.observe_result(self.take(source, "probe"), "probe")

    def finish(self, source):
        self.observe_result(self.take(source, "result"), "result")
        self.release(source)

    def report(self):
        return dict(generation=self.gen, admission=self.admission, observation_lines=self.lines, states=self.states,
                    observed_completion=self.known, native_final_result=self.native_result, resources_released=self.retired if "release" in self.lines else None,
                    outcome=self.known["outcome"] if self.known else "UnknownOutcome")


def call_window(row, line):
    return dict(evidence_line=line, start_tick_ms=str(row["start"]), end_tick_ms=str(row["tick"]),
                elapsed_ms=str(row["tick"] - row["start"]))


def monitor_timing(rows, disputed):
    monitor_line = next((n for n, r in enumerate(rows, 1) if r["kind"] == "monitor"), None)
    waits = []
    wait_ticks = 0
    for n, row in enumerate(rows, 1):
        if row["kind"] != "wait":
            continue
        generations = row["generations"]
        result = row["result"]
        waits.append(dict(**call_window(row, n), generations=generations, requested_ms=row["timeout_ms"],
                          wait_result=result, win32_error=row["error"], disputed_by_probe_lines=disputed.get(n, []),
                          selected_generation=generations[result] if result < len(generations) else None))
        wait_ticks += row["tick"] - row["start"]
    total = rows[-1]["tick"] - rows[monitor_line - 1]["tick"] if monitor_line else None
    return dict(monitor_line=monitor_line, through_line=len(rows) if monitor_line else None,
                elapsed_ms=str(total) if monitor_line else None, wait_call_ms=str(wait_ticks) if monitor_line else None,
                outside_wait_calls_ms=str(total - wait_ticks) if monitor_line else None, waits=waits)


def endpoint(row, line, field, observation):
    return dict(evidence_line=line, tick_field=field, tick_ms=str(row[field]), observation=observation)


def request_timing(rows, request, disputed):
    lines, generation = request["observation_lines"], request["generation"]
    submit_line = lines.get("submit")
    submit = rows[submit_line - 1] if submit_line else None
    submission = dict(**call_window(submit, submit_line), ok=submit["ok"], win32_error=submit["error"]) if submit else None
    cancel_line = lines.get("cancel")
    cancel = rows[cancel_line - 1] if cancel_line else None
    cancellation = dict(**call_window(cancel, cancel_line), ok=cancel["ok"], win32_error=cancel["error"]) if cancel else None
    conflicts = [s["evidence_lines"] for s in request["states"] if s["state"] == "IdentityConflict"]
    report = dict(generation=generation, admission=request["admission"], submission=submission, cancellation=cancellation,
                  outcome=request["outcome"], native_final_result=request["native_final_result"],
                  resources_released=request["resources_released"], conflict_evidence_lines=conflicts,
                  signal_window=None, submission_to_signal_ms=None)
    if not submit:
        admission = request["admission"]
        status = ("admission_unobserved" if admission is None else
                  "submission_unobserved" if admission["stage"] == "ready" else "admission_unavailable")
        return dict(report, status=status)
    if not submit["ok"] or conflicts:
        return dict(report, status="submission_failed" if not submit["ok"] else "identity_conflict")

    # The event starts clear. Each check occurs somewhere inside the recorded
    # call window. A timeout supplies its start as a lower bound, never its end.
    lower = endpoint(submit, submit_line, "start", "submission_started")
    upper = None
    for n in range(submit_line + 1, len(rows) + 1):
        row = rows[n - 1]
        kind = row["kind"]
        if kind == "wait" and generation in row["generations"] and n not in disputed:
            if row["result"] == TIMEOUT:
                lower = endpoint(row, n, "start", "wait_any_timeout")
            elif row["result"] < len(row["generations"]) and row["generations"][row["result"]] == generation and upper is None:
                upper = endpoint(row, n, "tick", "wait_any_selected")
        elif row["generation"] == generation:
            if kind in ("probe", "result"):
                if row["event_result"] == TIMEOUT:
                    lower = endpoint(row, n, "start", "private_event_clear")
                elif row["event_result"] == 0 and upper is None:
                    upper = endpoint(row, n, "tick", "private_event_signaled")
            elif kind == "release" and row["quiesce_result"] == 0 and upper is None:
                upper = endpoint(row, n, "tick", "quiescence_observed")
    minimum = max(0, int(lower["tick_ms"]) - submit["tick"])
    maximum = int(upper["tick_ms"]) - submit["start"] if upper else None
    report["signal_window"] = dict(not_before=lower, not_after=upper)
    report["submission_to_signal_ms"] = dict(minimum=str(minimum), maximum=str(maximum) if upper else None)
    return dict(report, status="signal_bounded" if upper else "right_censored")


def signal_order(requests, complete):
    bounded = [r for r in requests if r["status"] == "signal_bounded"]
    candidates = {r["generation"] for r in bounded}
    precedences = []
    for earlier in bounded:
        upper = earlier["signal_window"]["not_after"]["evidence_line"]
        for later in bounded:
            lower = later["signal_window"]["not_before"]["evidence_line"]
            # One issuing thread writes these records in order. Distinct
            # observations can establish order even within a single clock tick.
            if earlier is not later and upper < lower:
                candidates.discard(earlier["generation"])
                precedences.append(dict(earlier_generation=earlier["generation"], later_generation=later["generation"],
                                        signal_by_line=upper, clear_or_submission_from_line=lower))
    full = complete and all(r["status"] in ("signal_bounded", "admission_unavailable", "submission_failed") for r in requests)
    if not full:
        status = "incomplete"
    elif len(candidates) == 1:
        status = "unique_latest_signal"
    else:
        status = "order_unresolved" if candidates else "no_accepted_requests"
    return dict(status=status, possible_latest_generations=sorted(candidates) if full else None, proven_precedences=precedences)


def timing_report(rows, assessment, disputed):
    requests = [request_timing(rows, r, disputed) for r in assessment["requests"]]
    coverage = assessment["coverage"]
    return dict(schema="kn.io_lifetime_timing.v1", receipt_sha256=assessment["receipt_sha256"], source=assessment["source"],
                provider=assessment["provider"], clock=assessment["clock"], measured_event="private_manual_reset_completion_event",
                journal_complete=assessment["journal_complete"], committed_lines=assessment["committed_lines"],
                qualified_prefix_lines=len(rows), trailing_bytes=assessment["trailing_bytes"], missing_sequences=assessment["missing_sequences"],
                unjoined_records=assessment["unjoined_records"], coverage=dict(planned=coverage["planned"], accepted=coverage["queued"],
                    known_outcomes=coverage["known_outcomes"], bounded_signals=sum(r["status"] == "signal_bounded" for r in requests),
                    right_censored=sum(r["status"] == "right_censored" for r in requests), conflicts=sum(bool(r["conflict_evidence_lines"]) for r in requests)),
                monitor=monitor_timing(rows, disputed), requests=requests, signal_order=signal_order(requests, assessment["journal_complete"]),
                kernel_service_time_observed=False, cross_capture_joins=False, provider_authenticated=False)


def assess(rows, gaps, tail, pin, timing):
    p = rows[0]
    limit = gaps[0]["next_line"] - 1 if gaps else len(rows)
    source = Transcript(rows, limit)
    slots = [Operation(i) for i in range(1, p["requests"] + 1)]
    disputed = {}
    complete = False
    try:
        for op in slots:
            op.admit(source)
        monitor, _ = source.take("monitor")
        active = [op for op in slots if op.queued]
        while active:
            wait, wait_line = source.take("wait")
            check(wait["generations"] == [op.gen for op in active], "wait roster differs from outstanding generations")
            check(wait["timeout_ms"] == max(0, p["wait_ms"] - (wait["start"] - monitor["tick"])), "wait budget differs from plan")
            # A private manual-reset event already seen signaled cannot time out or
            # lose selection to a higher-index handle. WAIT_FAILED observes no state.
            if wait["result"] != FAILED:
                for earlier in active[:wait["result"]]:
                    if earlier.probe["event_result"] == 0:
                        earlier.invalidate(earlier.lines["probe"], wait_line)
                        disputed.setdefault(wait_line, []).append(earlier.lines["probe"])
            if wait["result"] in (TIMEOUT, FAILED):
                for op in active:
                    op.take(source, "cancel")
                    op.state("CancellationAttempted", wait_line, op.lines["cancel"])
                for op in active:
                    op.finish(source)
                break
            op = active.pop(wait["result"])
            if wait_line in disputed:
                op.state("ObservationGap", wait_line)
            else:
                op.selected = wait_line
                op.state("CompletionEventSignaled", wait_line)
            op.finish(source)
        source.take("end")
        check(source.pos == limit, "unexpected record after end")
        complete = True
    except PrefixEnded:
        pass

    if not complete:
        for op in slots:
            if not op.retired and not (op.lines.get("admit") and not op.admitted):
                op.state("ObservationGap", 1, *([max(op.lines.values())] if op.lines else []))
    assessment = dict(schema="kn.io_lifetime_assessment.v1", receipt_sha256=pin, source=p["source"],
                provider=dict(run=p["run"], pid=p["pid"], process_created=p["process_created"], tid=p["tid"],
                              thread_created=p["thread_created"]), clock=p["clock"],
                journal_complete=complete, committed_lines=len(rows), qualified_prefix_lines=limit, trailing_bytes=tail,
                missing_sequences=gaps, unjoined_records=[dict(line=i+1, seq=r["seq"], generation=r["generation"], kind=r["kind"])
                                                          for i, r in enumerate(rows) if i >= limit],
                coverage=dict(planned=len(slots), admitted=sum(op.admitted for op in slots),
                              submit_intents=sum("issue" in op.lines for op in slots),
                              returned_submissions=sum("submit" in op.lines for op in slots), queued=sum(op.queued for op in slots),
                              pending_observed=sum(bool(op.probe and op.probe["error"] == INCOMPLETE) for op in slots),
                              cancellation_attempts=sum("cancel" in op.lines for op in slots),
                              known_outcomes=sum(op.known is not None for op in slots),
                              retired_with_known_outcome=sum(bool(op.retired and op.known) for op in slots),
                              unknown_outcomes=sum(op.known is None for op in slots)),
                requests=[op.report() for op in slots], kernel_dispatch_observed=False, kernel_irp_generation_bound=False,
                cross_capture_joins=False, provider_authenticated=False)
    return timing_report(rows[:limit], assessment, disputed) if timing else assessment


def replay(path, pin, *, timing=False):
    return assess(*read_journal(path, pin), pin, timing)


def outputs_distinct(arguments, opened=None):
    if sys.stdout is None:
        return False
    try:
        sinks = [os.fstat(s.fileno()) for s in (sys.stdout, sys.stderr) if s is not None]
    except (OSError, ValueError):
        return False
    sinks = [s for s in sinks if stat.S_ISREG(s.st_mode)]
    if not sinks:
        return True
    if opened is not None and any(os.path.samestat(os.fstat(opened.fileno()), s) for s in sinks):
        return False
    # Invalid grammar can reach argparse's help/error output before there is a
    # parsed journal. Cover literal positional names and --option=value syntax.
    operands = [*arguments, *(arg.split("=", 1)[1] for arg in arguments if arg.startswith("--") and "=" in arg)]
    for operand in operands:
        try:
            info = os.stat(operand)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except (OSError, ValueError):
            return False
        if any(os.path.samestat(info, s) for s in sinks):
            return False
    return True


def main():
    if not outputs_distinct(sys.argv[1:]):
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--timing", action="store_true", help="bound private event signals and account for shared wait calls")
    args = parser.parse_args()
    try:
        check(stat.S_ISREG(args.journal.stat().st_mode), "a regular I/O journal is required")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(args.journal, flags), "rb") as stream:
            check(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "a regular I/O journal is required")
            if not outputs_distinct(sys.argv[1:], stream):
                return 2
            report = assess(*read_journal_stream(stream, args.sha256), args.sha256, args.timing)
            if not outputs_distinct(sys.argv[1:], stream):
                return 2
            print(json.dumps(report, separators=(",", ":"), allow_nan=False), flush=True)
    except (OSError, ValueError, RecursionError) as exc:
        if outputs_distinct(sys.argv[1:]):
            print(f"I/O lifecycle replay failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
