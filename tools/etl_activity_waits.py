"""Partition a marked thread's scheduler time using its original switch and ReadyThread witnesses."""
from collections import Counter
import re

from owned_module_benchmark import check, decimal, uint

MAX_RECORDS = 2_000_000
BUCKETS = ("thread_wait_ticks", "dpc_wait_ticks", "unattributed_wait_ticks",
           "other_before_ready_ticks", "ready_to_dispatch_ticks", "unclassified_off_cpu_ticks")


def tick(raw):
    check(type(raw) is str and re.fullmatch(r"0|-?[1-9][0-9]{0,18}", raw), "invalid QPC timestamp")
    n = int(raw)
    check(-(1 << 63) <= n < 1 << 63, "QPC value outside signed 64-bit range")
    return n


def candidate(interval):
    if "readiness" not in interval:
        return None
    seq = interval["readiness"]
    count = uint(seq["ready_records"], MAX_RECORDS)
    first, last = seq["first_ready"], seq["last_ready"]
    check((first is None) == (count == 0) and (last is None) == (count <= 1), "incomplete ready sequence")
    return last if last is not None else first


def lifetime(pair, tid, pid, logger, start, end):
    check(pair["relation"] in ("rundown_bracket", "start_end") and uint(pair["paired_record_pid"]) == pid and
          0 < tid < 0xffffffff and 0 < pid < 0xffffffff, "unqualified thread identity")
    before, after = pair["before"], pair["after"]
    for b in (before, after):
        check((uint(b["payload_tid"]), uint(b["payload_pid"]), uint(b["logger_id"])) == (tid, pid, logger),
              "thread boundary identity mismatch")
    check(before["opcode"] in (1, 3) and after["opcode"] in (2, 4) and
          0 < uint(before["record_ordinal"]) < uint(start["record_ordinal"]) < uint(end["record_ordinal"]) < uint(after["record_ordinal"]) and
          tick(before["raw_timestamp"]) < tick(start["raw_timestamp"]) < tick(end["raw_timestamp"]) < tick(after["raw_timestamp"]),
          "endpoints outside recorded thread lifetime")
    return (logger, tid, pid, before["record_ordinal"], after["record_ordinal"])


def source_overlap(origin, ready, before_start, before_end):
    src = origin["source_cpu_context"]
    edge = origin["relationship"]
    a, b = src["switch_in"], src["switch_out"]
    tid, pid = uint(edge["readying_tid"]), uint(edge["readying_pid"])
    check(src["relation"] == "running_on_cpu" and src["header_binding"] in ("matched", "unreported") and
          not origin["executing_dpc"] and not (ready["ready_flags"] & 1) and
          a["kind"] == "switch_in" and b["kind"] == "switch_out" and
          a["payload_tid"] == b["payload_tid"] == tid != ready["payload_tid"] and
          all(a[k] == ready[k] == b[k] for k in ("cpu", "cpu_field", "logger_id")) and
          a["record_ordinal"] < ready["record_ordinal"] < b["record_ordinal"] and
          tick(a["raw_timestamp"]) < tick(ready["raw_timestamp"]) < tick(b["raw_timestamp"]), "unqualified source CPU interval")
    check((origin["header_thread_id"], origin["header_process_id"]) ==
          ((tid, pid) if src["header_binding"] == "matched" else (0xffffffff, 0xffffffff)), "ready header binding mismatch")
    key = lifetime(src["thread_evidence"], tid, pid, ready["logger_id"], a, b)
    lo = max(before_start, tick(a["raw_timestamp"]))
    hi = min(before_end, tick(ready["raw_timestamp"]))
    return key, (lo, hi) if lo < hi else None


def text_totals(values):
    return {k: str(values[k]) for k in BUCKETS}


class ActivityWaits:
    def __init__(self, window):
        self.header = {k: v for k, v in window.items() if k != "intervals"}
        start, stop = window["start"], window["stop"]
        self.tid, self.pid, self.logger = (uint(start[name]) for name in ("header_thread_id", "header_process_id", "logger_id"))
        check(start["opcode"] == 1 and stop["opcode"] == 2 and
              all(start[k] == stop[k] for k in ("provider_guid", "activity_id", "header_thread_id", "header_process_id", "logger_id", "channel", "task")) and
              uint(window["intervening_boundaries"]) == uint(window["unassigned_activity_boundaries"]) == 0, "inconsistent activity markers")
        lifetime(window["thread_evidence"], self.tid, self.pid, self.logger, start, stop)
        self.start, self.stop = tick(start["raw_timestamp"]), tick(stop["raw_timestamp"])
        check(self.stop - self.start == decimal(window["window_ticks"]) > 0, "inconsistent activity duration")
        self.cursor = self.start
        self.previous_end = None
        self.count = self.off_count = self.running = self.off = self.overlap = 0
        self.buckets = Counter()
        self.sources = {}

    def account(self, window, origins):
        check(self.header == {k: v for k, v in window.items() if k != "intervals"}, "activity changed between pages")
        waits = []
        for interval in window["intervals"]:
            a, b = interval["start"], interval["end"]
            lo, hi = tick(interval["overlap_start_raw"]), tick(interval["overlap_end_raw"])
            check(lo == self.cursor == max(self.start, tick(a["raw_timestamp"])) and hi == min(self.stop, tick(b["raw_timestamp"])) and
                  self.start <= lo < hi <= self.stop and decimal(interval["overlap_ticks"]) == hi - lo and
                  a["payload_tid"] == b["payload_tid"] == self.tid and a["logger_id"] == b["logger_id"] == self.logger and
                  0 < uint(a["record_ordinal"]) < uint(b["record_ordinal"]) <= MAX_RECORDS, "noncontiguous or misbound scheduler interval")
            lifetime(self.header["thread_evidence"], self.tid, self.pid, self.logger, a, b)
            if self.previous_end is not None:
                check(all(self.previous_end[k] == a[k] for k in ("record_ordinal", "raw_timestamp", "cpu", "cpu_field",
                          "logger_id", "switch_ordinal", "opcode", "version")), "adjacent intervals disagree on the original switch")
            self.previous_end = b
            self.cursor = hi
            self.count += 1
            if interval["relation"] == "running_on_cpu":
                check((a["kind"], b["kind"]) == ("switch_in", "switch_out") and a["cpu"] == b["cpu"] and
                      "readiness" not in interval, "invalid running interval")
                self.running += hi - lo
                continue
            check(interval["relation"] == "off_cpu" and (a["kind"], b["kind"]) == ("switch_out", "switch_in"), "invalid off-CPU interval")
            self.off_count += 1
            self.off += hi - lo
            r = candidate(interval)
            origin = origins[r["record_ordinal"]] if r else None
            waits.append(self.wait(interval, r, origin, lo, hi))
        return waits

    def wait(self, interval, r, origin, lo, hi):
        seq = interval["readiness"]
        row = dict(interval_ordinal=self.count, ready_record=None, ready_position=None, relationship=None,
                   dispatch_relation=seq["relation"], source_overlap_start_raw=None, source_overlap_end_raw=None,
                   source_running_overlap_ticks=None)
        classified = Counter()
        if origin is not None:
            target = origin["target_dispatch"]
            edge = origin["relationship"]
            check(origin["selected_ready"] == r and r["payload_tid"] == self.tid and
                  target["switch_in"] == interval["end"] and target["switch_out"] == interval["start"] and
                  all(target[k] == seq[k] for k in ("ready_records", "first_ready", "last_ready")),
                  "ready event belongs to a different off-CPU interval")
            check(origin["executing_dpc"] is bool(r["ready_flags"] & 1) and origin["direct_switch_attempt"] is bool(r["ready_flags"] & 8),
                  "ready flag mismatch")
            at = tick(r["raw_timestamp"])
            position = "before_overlap" if at < lo else "after_overlap" if at >= hi else "in_overlap"
            row.update(ready_record=r["record_ordinal"], ready_position=position, relationship=edge["relation"], dispatch_relation=target["relation"])
            if edge["relation"] != "readying_thread_context":
                check(edge["readying_tid"] is None and edge["readying_pid"] is None, "thread identity on an unqualified edge")
            elif target["relation"] != "waiting_ready_switch_in" or origin["executing_dpc"]:
                raise ValueError("attributed source without a waiting dispatch")
            if target["relation"] in ("waiting_ready_switch_in", "ready_switch_in"):
                a, b = interval["start"], interval["end"]
                check(target["off_cpu_relation"] == "off_cpu" and uint(target["dispatchable_records"]) == 1 and
                      not r["ready_flags"] & ~9 and r["reserved_field"] == 0 and a["record_ordinal"] < r["record_ordinal"] < b["record_ordinal"] and
                      r["logger_id"] == self.logger and r["cpu_field"] == a["cpu_field"] == b["cpu_field"] and
                      target["thread_evidence"] == self.header["thread_evidence"] and
                      at - tick(a["raw_timestamp"]) == decimal(target["switch_out_to_ready_ticks"]) > 0 and
                      tick(b["raw_timestamp"]) - at == decimal(target["ready_to_switch_in_ticks"]) > 0, "unqualified dispatch timing")
                pivot = min(hi, max(lo, at))
                before, after = pivot - lo, hi - pivot
                classified["ready_to_dispatch_ticks"] = after
                waiting = target["relation"] == "waiting_ready_switch_in"
                check(waiting == (a["old_state"] == 5), "waiting state mismatch")
                if not waiting:
                    classified["other_before_ready_ticks"] = before
                elif edge["relation"] == "readying_thread_context":
                    key, span = source_overlap(origin, r, lo, pivot)
                    self.add_source(key, span, before, after, r, row)
                    classified["thread_wait_ticks"] = before
                elif origin["executing_dpc"]:
                    check(edge["relation"] == "dpc_context", "missing DPC qualification")
                    classified["dpc_wait_ticks"] = before
                else:
                    classified["unattributed_wait_ticks"] = before
            else:
                check(target["switch_out_to_ready_ticks"] is None and target["ready_to_switch_in_ticks"] is None,
                      "duration on an unqualified dispatch")
        if not classified:
            classified["unclassified_off_cpu_ticks"] = hi - lo
        check(sum(classified.values()) == hi - lo, "inconsistent wait partition")
        self.buckets.update(classified)
        row.update(text_totals(classified))
        return row

    def add_source(self, key, span, before, after, r, row):
        amount = span[1] - span[0] if span else 0
        if span:
            row.update(source_overlap_start_raw=str(span[0]), source_overlap_end_raw=str(span[1]))
        row["source_running_overlap_ticks"] = str(amount)
        self.overlap += amount
        group = self.sources.setdefault(key, dict(transitions=0, before=0, after=0, overlap=0, first_ready_record=r["record_ordinal"]))
        group["transitions"] += 1
        group["before"] += before
        group["after"] += after
        group["overlap"] += amount

    def finish(self):
        w = self.header
        check(self.cursor == self.stop and self.count == uint(w["intersecting_intervals"], MAX_RECORDS) and
              self.off_count == uint(w["off_cpu_intervals"]) and self.running == decimal(w["on_cpu_ticks"]) and
              self.off == decimal(w["off_cpu_ticks"]) == sum(self.buckets.values()) and
              self.running + self.off == self.stop - self.start and self.overlap <= self.buckets["thread_wait_ticks"],
              "incomplete whole-activity accounting")
        sources = []
        for (logger, tid, pid, first, last), g in sorted(self.sources.items()):
            sources.append(dict(logger_id=logger, source_tid=tid, source_pid=pid, lifetime_start_record=first, lifetime_end_record=last,
                                first_ready_record=g["first_ready_record"], ready_transitions=g["transitions"],
                                thread_wait_ticks=str(g["before"]), ready_to_dispatch_ticks=str(g["after"]),
                                source_running_overlap_ticks=str(g["overlap"])))
        return dict(window_ticks=str(self.stop - self.start), on_cpu_ticks=str(self.running), off_cpu_ticks=str(self.off),
                    off_cpu_intervals=self.off_count, **text_totals(self.buckets), source_running_overlap_ticks=str(self.overlap),
                    source_lifetimes=sources)
