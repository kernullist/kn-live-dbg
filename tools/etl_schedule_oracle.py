"""Reconstruct saved scheduling intervals from Windows tracerpt's ordered XML rows."""
from bisect import bisect_left
from collections import defaultdict
from typing import NamedTuple


class Edge(NamedTuple):
    record: int
    tick: int
    cpu: int
    tid: int
    kind: str
    version: int
    opcode: int
    ordinal: int = 0
    state: int = 0
    reason: int = 0
    pid: int = 0


class Ready(NamedTuple):
    record: int
    tick: int
    cpu: int
    tid: int
    reason: int
    increment: int
    flags: int
    reserved: int


class ScheduleOracle:
    def __init__(self):
        self.cpus = defaultdict(list)
        self.threads = defaultdict(list)
        self.ready = defaultdict(list)
        self.before_cpu = {}
        self.before_thread = {}
        self.bad_cpus, self.bad_cpu_times = set(), set()
        self.bad_tids, self.bad_tid_times = set(), set()
        self.ready_count = self.boundaries = 0
        self.last_tick = None
        self.reversed_clock = self.unknown_tid = False

    def clock(self, tick):
        if self.last_tick is not None and tick < self.last_tick:
            self.reversed_clock = True
        self.last_tick = tick

    def switch(self, record, tick, cpu, version, ordinal, incoming, outgoing, state, reason):
        self.clock(tick)
        self.unknown_tid |= 0xffffffff in (outgoing, incoming)
        old = Edge(record, tick, cpu, outgoing, "switch_out", version, 36, ordinal, state, reason)
        new = Edge(record, tick, cpu, incoming, "switch_in", version, 36, ordinal)
        self.cpus[cpu].append((old, new))
        for edge in (old, new):
            if edge.tid not in (0, 0xffffffff):
                self.threads[edge.tid].append(edge)

    def boundary(self, record, tick, cpu, opcode, pid, tid):
        self.clock(tick)
        self.boundaries += 1
        kind = {1: "start", 2: "end", 3: "rundown_start", 4: "rundown_end"}[opcode]
        if tid not in (0, 0xffffffff):
            self.threads[tid].append(Edge(record, tick, cpu, tid, kind, 3, opcode, pid=pid))

    def readiness(self, record, tick, cpu, tid, reason, increment, flags, reserved):
        self.clock(tick)
        self.ready_count += 1
        self.ready[tid].append(Ready(record, tick, cpu, tid, reason, increment, flags, reserved))

    def prepare(self):
        for cpu, events in self.cpus.items():
            for (_, old_in), (new_out, _) in zip(events, events[1:]):
                self.before_cpu[new_out.record] = old_in
                if old_in.tid != new_out.tid:
                    self.bad_cpus.add(cpu)
                if old_in.tick >= new_out.tick:
                    self.bad_cpu_times.add(cpu)
        for tid, edges in self.threads.items():
            for a, b in zip(edges, edges[1:]):
                self.before_thread[b.record, b.kind] = a
                if a.opcode == b.opcode == 36:
                    if a.kind == b.kind or (a.kind == "switch_in" and a.cpu != b.cpu):
                        self.bad_tids.add(tid)
                    if a.record != b.record and a.tick >= b.tick:
                        self.bad_tid_times.add(tid)

    @staticmethod
    def edge_json(edge, row):
        if not edge:
            return None
        # XML supplies ProcessorID, not the native logger ID or header flag.
        obj = dict(record_ordinal=edge.record, raw_timestamp=str(edge.tick), cpu=edge.cpu,
                   logger_id=row["logger_id"], cpu_field=row["cpu_field"], kind=edge.kind,
                   payload_tid=edge.tid, version=edge.version, opcode=edge.opcode)
        if edge.opcode == 36:
            obj["switch_ordinal"] = edge.ordinal
        else:
            obj["payload_pid"] = edge.pid
        if edge.kind == "switch_out":
            obj.update(old_state=edge.state, old_wait_reason=edge.reason)
        return obj

    @staticmethod
    def ready_json(event, row):
        if not event:
            return None
        return dict(record_ordinal=event.record, raw_timestamp=str(event.tick), cpu=event.cpu,
                    logger_id=row["logger_id"], cpu_field=row["cpu_field"], payload_tid=event.tid,
                    ready_flags=event.flags, adjust_reason=event.reason, adjust_increment=event.increment,
                    reserved_field=event.reserved)

    def compare(self, row, clock_ok, coverage):
        n = row["record_ordinal"]
        tick = int(row["raw_timestamp"])
        old, new = row["old_thread_id"], row["new_thread_id"]
        cpu = row["cpu"]
        before = self.before_cpu.get(n)
        old_prior = self.before_thread.get((n, "switch_out"))
        new_prior = self.before_thread.get((n, "switch_in"))

        def assess(running):
            tid, start, prior = (old, before, old_prior) if running else (new, new_prior, new_prior)
            if tid == 0xffffffff or (not running and tid == 0):
                return "unusable_tid" if tid else "idle_tid", None
            if start is None:
                return "no_previous_on_cpu" if running else "no_previous_thread_event", None
            if prior and prior.opcode != 36:
                return "thread_boundary", None
            if start.record == n:
                return "same_switch", None
            if running and start.tid != tid:
                return "cpu_tid_conflict", None
            if tid and (running and prior != before or not running and prior.kind != "switch_out"):
                return "thread_transition_conflict", None
            if not coverage or (not running and self.unknown_tid):
                return "coverage_unqualified", None
            if (cpu in self.bad_cpus if running else self.bad_cpus):
                return "cpu_history_conflict", None
            if tid in self.bad_tids:
                return "thread_transition_conflict", None
            if (not clock_ok or self.reversed_clock or start.tick >= tick or tid in self.bad_tid_times or
                    (cpu in self.bad_cpu_times if running else self.bad_cpu_times)):
                return "clock_unqualified", None
            label = ("running_on_cpu" if tid else "idle_on_cpu") if running else "off_cpu"
            return label, str(tick - start.tick)

        run_kind, run_ticks = assess(True)
        off_kind, off_ticks = assess(False)
        assert row["on_cpu"] == dict(relation=run_kind, elapsed_ticks=run_ticks, previous_switch=self.edge_json(before, row),
                                     other_thread_event=self.edge_json(old_prior if old_prior != before else None, row)), ("on_cpu", n)
        candidates = []
        if new_prior and new_prior.kind == "switch_out":
            history = self.ready.get(new, [])
            candidates = history[bisect_left(history, (new_prior.record + 1,)):bisect_left(history, (n,))]
        dispatchable = [p for p in candidates if p.flags in (0, 1)]
        waiting = ready_ticks = None
        if off_ticks is None:
            kind = "off_cpu_unqualified"
        elif not candidates:
            kind = "ready_unobserved"
        elif (candidates[0].tick <= new_prior.tick or candidates[-1].tick >= tick or
              any(a.tick >= b.tick for a, b in zip(candidates, candidates[1:]))):
            kind = "ready_clock_unqualified"
        elif any(p.flags & ~7 for p in candidates):
            kind = "ready_flags_unqualified"
        elif not dispatchable:
            kind = "ready_deferred"
        elif dispatchable != [candidates[-1]]:
            kind = "ready_sequence_conflict"
        else:
            kind = "waiting_ready_switch_in" if new_prior.state == 5 else "ready_switch_in"
            waiting, ready_ticks = str(candidates[-1].tick - new_prior.tick), str(tick - candidates[-1].tick)
        split = dict(relation=kind, ready_records=len(candidates), dispatchable_records=len(dispatchable),
                     first_ready=self.ready_json(candidates[0] if candidates else None, row),
                     last_ready=self.ready_json(candidates[-1] if len(candidates) > 1 else None, row),
                     switch_out_to_ready_ticks=waiting, ready_to_switch_in_ticks=ready_ticks)
        assert row["off_cpu"] == dict(relation=off_kind, elapsed_ticks=off_ticks,
                                      previous_thread_event=self.edge_json(new_prior, row), readiness=split), ("off_cpu", n)
        return run_kind, off_kind, kind
