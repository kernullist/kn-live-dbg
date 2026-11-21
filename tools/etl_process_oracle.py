"""Compare file-local process instance claims with ordered Windows tracerpt events."""
from bisect import bisect_left
from collections import defaultdict
import struct


PROCESS_GUID = "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"
NAMES = {1: "start", 2: "end", 3: "rundown_start", 4: "rundown_end", 39: "defunct"}


class ProcessOracle:
    def __init__(self):
        self.by_pid = defaultdict(list)
        self.points, self.keys = {}, {}
        self.last_tick = None
        self.clock_reversed = False
        self.last_image_tick = None
        self.image_clock_reversed = False
        self.unsupported = self.defunct = self.raw = 0

    def image_tick(self, value):
        self.image_clock_reversed |= self.last_image_tick is not None and value < self.last_image_tick
        self.last_image_tick = value

    def tick(self, value):
        self.image_tick(value)
        self.clock_reversed |= self.last_tick is not None and value < self.last_tick
        self.last_tick = value

    def add(self, record, tick, op, version, width, fields, raw):
        if version not in (2, 3, 4) and (version, op) != (5, 39):
            self.unsupported += 1
            return
        assert width in (4, 8)
        if fields:
            key, pid, parent, session, status = (int(fields[k], 0) for k in
                ("UniqueProcessKey", "ProcessId", "ParentId", "SessionId", "ExitStatus"))
            status = (status + 2**31) % 2**32 - 2**31
            exit_time = str(int(fields["ExitTime"], 0)) if version == 5 else None
        else:
            data = bytes.fromhex(raw)
            key = int.from_bytes(data[:width], "little")
            pid, parent, session, status = struct.unpack_from("<IIIi", data, width)
            exit_time = str(struct.unpack_from("<Q", data, len(data) - 8)[0]) if version == 5 else None
            self.raw += 1
        self.defunct += op == 39
        self.by_pid[pid].append(record)
        self.keys[record] = key
        self.points[record] = dict(record_ordinal=record, raw_timestamp=str(tick), event=NAMES[op], opcode=op,
            version=version, pointer_bytes=width, payload_pid=pid, parent_pid=parent, session_id=session,
            exit_status=status, defunct_exit_time_raw=exit_time)

    def prepare(self):
        self.bad_transitions, self.bad_times = set(), set()
        for pid, records in self.by_pid.items():
            points = [self.points[r] for r in records]
            directions = [p["opcode"] in (1, 3) for p in points if p["opcode"] != 39]
            if any(a == b for a, b in zip(directions, directions[1:])):
                self.bad_transitions.add(pid)
            ticks = [int(p["raw_timestamp"]) for p in points]
            if any(a >= b for a, b in zip(ticks, ticks[1:])):
                self.bad_times.add(pid)

    def metadata(self, with_images):
        return dict(provider_guid=PROCESS_GUID, event_id=0, lifecycle_opcodes=[1, 2, 3, 4], lifecycle_versions=[2, 3, 4],
                    defunct_opcode=39, defunct_versions=[2, 3, 4, 5],
                    decoded_events=len(self.points), retained_events=len(self.points), unsupported_events=self.unsupported,
                    defunct_events=self.defunct, source_clock_reversed=self.clock_reversed,
                    image_binding_clock_reversed=self.image_clock_reversed if with_images else None,
                    generation_scope="source_sha256_and_start_record", creation_filetime=None)

    def expected(self, sample, clock_ok, coverage):
        thread = sample["thread_evidence"]
        t1, t2 = thread["before"], thread["after"]
        pid = None
        if (t1 and t2 and t1["opcode"] in (1, 3) and t2["opcode"] in (2, 4) and
                t1["payload_pid"] == t2["payload_pid"] and t1["payload_pid"] not in (0, 0xffffffff)):
            pid = t1["payload_pid"]
        records = self.by_pid.get(pid, ())
        n = bisect_left(records, sample["record_ordinal"])
        a = self.points[records[n-1]] if n else None
        b = self.points[records[n]] if n < len(records) else None
        before = a["record_ordinal"] if a else None
        after = b["record_ordinal"] if b else None
        keys = "not_compared"
        generation = None
        if pid is None:
            relation = "thread_pid_unavailable"
        elif thread["paired_record_pid"] is None:
            relation = "thread_pid_unqualified"
        elif a is None and b is None:
            relation = "no_record"
        elif any(p and p["opcode"] == 39 for p in (a, b)):
            relation = "defunct_marker"
        elif a is None or b is None:
            relation = "one_boundary"
        elif a["opcode"] in (2, 4) or b["opcode"] in (1, 3):
            relation = "outside_bracket"
        elif (a["version"], a["pointer_bytes"]) != (b["version"], b["pointer_bytes"]):
            relation = "layout_conflict"
        else:
            lkey, rkey = self.keys[before], self.keys[after]
            keys = ("unreported" if not (lkey or rkey) else "one_unreported" if not (lkey and rkey)
                    else "equal" if lkey == rkey else "different")
            lo, at, hi = map(int, (a["raw_timestamp"], sample["raw_timestamp"], b["raw_timestamp"]))
            if pid in self.bad_transitions:
                relation = "conflicting_transitions"
            elif keys == "different" or any(a[k] != b[k] for k in ("parent_pid", "session_id")):
                relation = "process_identity_conflict"
            elif ((a["opcode"] == 1 and before >= t1["record_ordinal"]) or
                  (b["opcode"] == 2 and after <= t2["record_ordinal"])):
                relation = "thread_outside_process"
            elif (not clock_ok or self.clock_reversed or pid in self.bad_times or not lo < at < hi or
                  (a["opcode"] == 1 and lo >= int(t1["raw_timestamp"])) or
                  (b["opcode"] == 2 and hi <= int(t2["raw_timestamp"]))):
                relation = "clock_unqualified"
            elif not coverage or self.unsupported:
                relation = "coverage_unqualified"
            elif (a["opcode"], b["opcode"]) == (1, 2):
                relation = "start_end"
                generation = dict(payload_pid=pid, start_record=before)
            else:
                relation = "rundown_bracket"
        return dict(relation=relation, candidate_pid=pid, before_record=before, after_record=after,
                    opaque_key_comparison=keys, recorded_generation=generation)

    def image_in_process(self, process, image, images):
        generation = process["recorded_generation"]
        if generation is None:
            relation = "process_generation_unavailable"
        elif image["reported_rva"] is None:
            relation = "image_pair_unavailable"
        else:
            lo, hi = process["before_record"], process["after_record"]
            w, = image["witnesses"]
            left, right = w["before_record"], w["after_record"]
            if not lo < left < right < hi or any(images.by_ordinal[n]["payload_pid"] != generation["payload_pid"] for n in (left,right)):
                relation = "image_outside_process"
            elif self.image_clock_reversed or not (int(self.points[lo]["raw_timestamp"]) < int(images.by_ordinal[left]["raw_timestamp"]) and
                      int(images.by_ordinal[right]["raw_timestamp"]) < int(self.points[hi]["raw_timestamp"])):
                relation = "clock_unqualified"
            else:
                relation = "inside_process_generation"
        return dict(relation=relation, process_start_record=generation["start_record"] if relation == "inside_process_generation" else None,
                    reported_rva=image["reported_rva"] if relation == "inside_process_generation" else None)
