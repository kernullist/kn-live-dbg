"""Replay a pinned Windows directory I/O journal into per-request lifecycle evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
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


def read_journal(path, pin):
    check(type(pin) is str and re.fullmatch(r"[a-f0-9]{64}", pin), "invalid SHA-256")
    with path.open("rb") as stream:
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
                self.conflict = True
                self.known = None
                sources = [self.lines["probe"]] if changed or p["event_result"] == 0 else []
                if signaled_then_timeout and self.selected:
                    sources.append(self.selected)
                self.state("IdentityConflict", *sources, line)
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


def replay(path, pin):
    rows, gaps, tail = read_journal(path, pin)
    p = rows[0]
    limit = gaps[0]["next_line"] - 1 if gaps else len(rows)
    source = Transcript(rows, limit)
    slots = [Operation(i) for i in range(1, p["requests"] + 1)]
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
            if wait["result"] in (TIMEOUT, FAILED):
                for op in active:
                    op.take(source, "cancel")
                    op.state("CancellationAttempted", wait_line, op.lines["cancel"])
                for op in active:
                    op.finish(source)
                break
            op = active.pop(wait["result"])
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
    return dict(schema="kn.io_lifetime_assessment.v1", receipt_sha256=pin, source=p["source"],
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(replay(args.journal, args.sha256), separators=(",", ":"), allow_nan=False))
    except (OSError, ValueError, RecursionError) as exc:
        print(f"I/O lifecycle replay failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
