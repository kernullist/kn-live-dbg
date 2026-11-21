"""Private, offline evidence for the two owned Windows module-observation workloads."""
from collections import Counter, deque
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import zipfile


MIB = 1024 * 1024
MANIFEST = "owned-module-manifest.json"
WORLDS = ("fixed", "changing")
PAIRED_SCHEMA = "kn.owned_module_benchmark.v2"
IO_FIELDS = ("read_operations", "write_operations", "other_operations", "read_bytes", "written_bytes", "other_bytes")
COST_COUNTERS = ("user_100ns", "kernel_100ns", *IO_FIELDS)
COST_METRICS = ("roundtrip_ns", "native_service_ns", *COST_COUNTERS, "working_set_change_bytes")
LIMITS = {MANIFEST: 64 * 1024, "truth.json": 2 * MIB, "fixed.jsonl": 4 * MIB, "changing.jsonl": 4 * MIB,
          "collector.bin": 32 * MIB, "target.bin": 32 * MIB, "controller.py": MIB}
MAX_PACKAGE = sum(LIMITS.values()) + 64 * 1024
UNAVAILABLE = {"identity_unavailable", "generation_changed", "access_denied", "unsupported", "cancelled"}
ERRORS = {"fault", "incomplete", "invalid_clock"}
SOURCE_RESULTS = UNAVAILABLE | ERRORS | {"observed"}


class PackagePinMismatch(ValueError):
    pass


def check(ok, message):
    if not ok:
        raise ValueError(message)


def fields(value, names, where):
    check(type(value) is dict and value.keys() == set(names.split()), "invalid fields in " + where)


def uint(value, hi=(1 << 64) - 1):
    check(type(value) is int and 0 <= value <= hi, "invalid unsigned integer")
    return value


def decimal(value):
    check(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value), "invalid decimal integer")
    return uint(int(value))


def identity(value, *, nullable=False):
    check(type(value) is list and len(value) == 2, "invalid process identity")
    pid, generation = uint(value[0], 0xffffffff), decimal(value[1])
    check((pid > 4 and generation > 0) or (nullable and pid == generation == 0), "unbound process identity")
    return pid, value[1]


def identities(values, limit):
    check(type(values) is list and len(values) <= limit, "invalid identity list")
    keys = [identity(v) for v in values]
    check(len(keys) == len(set(keys)), "duplicate identity in one census or selection")
    return keys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def publish_new(destination, write):
    """Seal in the destination directory and publish without replacing an existing file."""
    temp = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".knbench-", suffix=".tmp", delete=False) as out:
            temp = Path(out.name)
            write(out)
            out.flush()
            os.fsync(out.fileno())
            out.seek(0)
            pin = hashlib.file_digest(out, "sha256").hexdigest()
        if os.name == "nt":
            os.rename(temp, destination)  # Windows fails if the destination exists.
            temp = None
        else:
            os.link(temp, destination)
        return pin
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def write_bundle(destination, manifest, contents):
    check(set(contents) == LIMITS.keys() - {MANIFEST}, "incomplete acquisition inputs")
    manifest = dict(manifest, artifacts={name: sha(data) for name, data in contents.items()})
    contents = {MANIFEST: encoded(manifest), **contents}
    check(all(0 < len(data) <= LIMITS[name] for name, data in contents.items()), "artifact exceeds format bounds")
    def write(out):
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in LIMITS:
                archive.writestr(name, contents[name])
    return publish_new(destination, write)


def read_bundle(path, expected, decode):
    check(isinstance(expected, str) and re.fullmatch("[0-9a-f]{64}", expected), "expected a lowercase SHA-256 pin")
    with path.open("rb") as stream:
        raw = stream.read(MAX_PACKAGE + 1)
    if len(raw) > MAX_PACKAGE or sha(raw) != expected:
        raise PackagePinMismatch("package size or SHA-256 mismatch")
    check(len(raw) >= 22 and raw.startswith(b"PK\x03\x04") and raw[30:30 + len(MANIFEST)] == MANIFEST.encode(),
          "invalid package header")
    # ZipFile eagerly materializes the central directory. Bound its byte count before opening it.
    sig, disk, directory_disk, entries, total, size, offset, comment = struct.unpack_from("<4s4H2IH", raw, len(raw) - 22)
    check(sig == b"PK\x05\x06" and disk == directory_disk == comment == 0 and entries == total == len(LIMITS) and
          0 < size <= 4096 and offset + size == len(raw) - 22, "invalid package directory")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            check([i.filename for i in infos] == list(LIMITS), "unexpected package membership or order")
            parts = {}
            cursor = 0
            for i in infos:
                check(i.compress_type == zipfile.ZIP_STORED and i.flag_bits == 0 and
                      0 < i.file_size == i.compress_size <= LIMITS[i.filename], "unsupported or oversized package member")
                name = i.filename.encode("ascii")
                check(i.orig_filename == i.filename and i.header_offset == cursor and not i.extra and not i.comment and
                      cursor + 30 + len(name) + i.file_size <= offset, "invalid local member extent")
                sig, _, flags, method, _, _, crc, packed, length, namesize, extra = struct.unpack_from("<4s5H3I2H", raw, cursor)
                check(sig == b"PK\x03\x04" and flags == method == extra == 0 and
                      packed == length == i.file_size and crc == i.CRC and namesize == len(name) and
                      raw.startswith(name, cursor + 30), "inconsistent local member header")
                cursor += 30 + len(name) + i.file_size
                parts[i.filename] = archive.read(i)
            check(cursor == offset, "unaccounted package contents")
    except (zipfile.BadZipFile, NotImplementedError) as exc:
        raise ValueError("invalid package member encoding or checksum") from exc
    manifest = decode(parts.pop(MANIFEST))
    paired = type(manifest) is dict and manifest.get("schema") == PAIRED_SCHEMA
    fields(manifest, "schema run_id clock rounds cadence_ms environment collector_file_id target_file_id artifacts" +
           (" qpc_hz" if paired else ""), "manifest")
    if paired:
        check(decimal(manifest["qpc_hz"]) > 0, "invalid supervisor performance frequency")
    check(manifest["schema"] in ("kn.owned_module_benchmark.v1", PAIRED_SCHEMA) and manifest["clock"] == "GetTickCount64_ms" and
          uint(manifest["rounds"]) == 16 and uint(manifest["cadence_ms"]) == 25, "unknown acquisition contract")
    check(isinstance(manifest["run_id"], str) and re.fullmatch("[0-9a-f]{32}", manifest["run_id"]), "invalid run identity")
    for name in ("collector_file_id", "target_file_id"):
        check(isinstance(manifest[name], str) and re.fullmatch("[0-9a-f]{48}", manifest[name]) and
              int(manifest[name][16:], 16) != 0, "invalid file identity")
    check(manifest["collector_file_id"] != manifest["target_file_id"], "collector and target file identities alias")
    env = manifest["environment"]
    fields(env, "os_build architecture", "measured environment")
    check(type(env["os_build"]) is str and re.fullmatch(r"[0-9]{1,6}(\.[0-9]{1,6}){0,3}", env["os_build"]) and
          env["architecture"] in ("amd64", "arm64", "x86", "unknown"), "invalid measured environment")
    check(manifest["artifacts"] == {name: sha(data) for name, data in parts.items()}, "retained artifact hash mismatch")
    return manifest, parts


class Replies:
    def __init__(self, raw, decode, paired=False):
        limit = 2 + 16 * 9 * (2 if paired else 1)
        check(raw.endswith(b"\n") and raw.count(b"\n") <= limit, "incomplete or oversized observer transcript")
        self.lines = raw[:-1].split(b"\n")
        self.index = 0
        self.decode = decode

    def take(self, kind, measured=False):
        check(self.index < len(self.lines), "missing observer reply")
        wire = self.decode(self.lines[self.index])
        self.index += 1
        fields(wire, "schema payload qpc" if measured else "schema payload", "observer envelope")
        data = wire["payload"]
        check(wire["schema"] == "kn.owned_module_workload.v1" and type(data) is dict and data.get("kind") == kind,
              "observer reply does not match the controller request")
        return (data, wire["qpc"]) if measured else data


def bracket(event, previous, *names):
    times = [uint(event[k]) for k in names]
    check(previous <= times[0] and all(a <= b for a, b in zip(times, times[1:])), "nonmonotonic controller chronology")
    return times[-1]


def arm_order(run_id, kind, ordinal):
    # Counterbalance each operation independently. A registered run fixes its ticket before admission.
    idle_first = (int(run_id[-1], 16) + ordinal + (kind == "dispatch")) % 2 == 0
    return ("idle", "observe") if idle_first else ("observe", "idle")


class PairedCosts:
    def __init__(self, run_id, collector, frequency):
        self.run_id, self.collector, self.frequency = run_id, collector, frequency
        self.last_qpc = 0
        self.last_counters = {}
        self.groups = {kind: dict(pairs=0, observe_first=0,
                                  totals={metric: Counter() for metric in COST_METRICS})
                       for kind in ("inventory", "dispatch")}
        self.links = []

    def sample(self, row, previous_ms):
        fields(row, "process begin_ms end_ms begin_qpc end_qpc kernel_100ns user_100ns io_error io memory_error working_set_bytes",
               "collector cost sample")
        check(identity(row["process"]) == self.collector, "collector cost sample belongs to a different generation")
        end_ms = bracket(row, previous_ms, "begin_ms", "end_ms")
        first, last = decimal(row["begin_qpc"]), decimal(row["end_qpc"])
        check(self.last_qpc <= first <= last, "nonmonotonic performance counter")
        self.last_qpc = last
        values = {k: decimal(row[k]) for k in ("user_100ns", "kernel_100ns")}
        if row["io_error"] is not None:
            uint(row["io_error"], 0xffffffff)
            check(row["io"] is None, "failed I/O query supplied counters")
        else:
            fields(row["io"], " ".join(IO_FIELDS), "process I/O counters")
            values.update({k: decimal(row["io"][k]) for k in IO_FIELDS})
        for k, value in values.items():
            check(value >= self.last_counters.get(k, 0), "process cumulative counter regressed")
            self.last_counters[k] = value
        if row["memory_error"] is not None:
            uint(row["memory_error"], 0xffffffff)
            check(row["working_set_bytes"] is None, "failed memory query supplied a working set")
        else:
            values["working_set_change_bytes"] = decimal(row["working_set_bytes"])
        return end_ms, first, last, values

    def request(self, event, replies, previous, truth_index):
        kind = event["kind"]
        fields(event, "kind start end arms", "paired controller request")
        arms = event["arms"]
        check(type(arms) is list and len(arms) == 2, "incomplete pair")
        group = self.groups[kind]
        order = arm_order(self.run_id, kind, group["pairs"])
        values, lines = {}, {}
        for mode, arm in zip(order, arms):
            fields(arm, "mode before start end after", "measured arm")
            check(arm["mode"] == mode, "arm differs from registered order")
            previous, _, sample_end, before = self.sample(arm["before"], previous)
            end = bracket(arm, previous, "start", "end")
            reply, native = replies.take(kind if mode == "observe" else "idle", measured=True)
            lines[mode] = replies.index
            if mode == "idle":
                fields(reply, "kind tick", "idle receipt")
                check(arm["start"] <= uint(reply["tick"]) <= end, "idle receipt outside its request")
            else:
                check(uint(event["start"]) == arm["start"] and uint(event["end"]) == end,
                      "observation request differs from measured interval")
                source = reply
            previous, sample_begin, _, after = self.sample(arm["after"], end)
            values[mode] = {k: after[k] - before[k] for k in before.keys() & after.keys()}
            fields(native, "process hz begin end", "native performance counter")
            check(identity(native["process"]) == self.collector, "native measurement belongs to a different collector")
            start_qpc, end_qpc = decimal(native["begin"]), decimal(native["end"])
            check(decimal(native["hz"]) == self.frequency, "native and supervisor performance frequencies differ")
            # Across threads Windows treats ordering within one performance-counter tick as ambiguous.
            check(start_qpc <= end_qpc and sample_end <= start_qpc + 1 and end_qpc <= sample_begin + 1,
                  "native service outside supervisor performance interval")
            values[mode]["roundtrip_ns"] = (sample_begin - sample_end) * 1_000_000_000 // self.frequency
            values[mode]["native_service_ns"] = (end_qpc - start_qpc) * 1_000_000_000 // self.frequency
        for k, total in group["totals"].items():
            if k in values["observe"] and k in values["idle"]:
                total["paired"] += 1
                total["observed"] += values["observe"][k]
                total["idle"] += values["idle"][k]
        group["pairs"] += 1
        group["observe_first"] += order[0] == "observe"
        self.links.append(dict(kind=kind, truth_event=truth_index, source_reply=lines["observe"], idle_reply=lines["idle"]))
        return source, lines["observe"], previous

    def report(self):
        result = {}
        for kind, group in self.groups.items():
            metrics = {}
            for metric, total in group["totals"].items():
                pairs, observed, idle = total["paired"], total["observed"], total["idle"]
                metrics[metric] = dict(paired=pairs, unavailable_pairs=group["pairs"] - pairs,
                                       observed_total=str(observed) if pairs else None,
                                       idle_total=str(idle) if pairs else None,
                                       observed_minus_idle=str(observed - idle) if pairs else None)
            result[kind] = dict(pairs=group["pairs"], observe_first=group["observe_first"],
                                idle_first=group["pairs"] - group["observe_first"], metrics=metrics)
        return dict(basis="same_collector_fixed_owned_job", collector=list(self.collector),
                    interval_clock="windows_query_performance_counter", frequency_hz=str(self.frequency),
                    operations=result, receipts=self.links)


def read_visit(data, row, key, live, start, end):
    fields(data, "kind key start end before after rows base terminal complete win32_error result last_success", "dispatch")
    check(identity(data["key"]) == key and start <= uint(data["start"]) <= uint(data["end"]) <= end,
          "dispatch identity or timing mismatch")
    before, after = decimal(data["before"]), decimal(data["after"])
    count, base, terminal = uint(data["rows"], 1024), uint(data["base"]), uint(data["terminal"], 0xffffffff)
    error = uint(data["win32_error"], 0xffffffff)
    result = data["result"]
    check(type(result) is str and result in SOURCE_RESULTS and type(data["complete"]) is bool, "unknown source result")
    check((count > 0 or base == 0) and (not base or 0x10000 <= base <= 0x00007ffffffeffff) and
          (not data["complete"] or (count > 0 and terminal == 18)), "inconsistent module enumeration")
    stable = before == after == int(key[1])
    qualified = (live and stable and 0 < count and data["complete"] and terminal == 18 and base == row["base"]
                 and result not in {"invalid_clock", "cancelled"})
    check((result == "observed") == qualified, "source result contradicts the child image or enumeration fences")
    if not live:
        check(not count and not base and not data["complete"] and after == 0 and
              result in {"identity_unavailable", "generation_changed", "access_denied"}, "source read after confirmed exit")
    if result == "access_denied":
        check(error == 5 and (not before or terminal == 5), "access denial without its Win32 result")
    elif result == "identity_unavailable":
        check(not before or not after, "identity unavailable despite both generation fences")
    elif result == "generation_changed":
        check((before and before != int(key[1])) or (after and after != int(key[1])), "generation change without a conflicting fence")
    elif result in {"incomplete", "unsupported"}:
        check(stable and not data["complete"] and error == terminal and
              (result == "unsupported") == (error in {50, 120}) and error != 5, "source failure contradicts enumeration status")
    if qualified:
        success = uint(data["last_success"])
        check(error == 0 and data["start"] <= success <= data["end"], "invalid successful observation time or status")
        row["last_success"] = success
        if row["first_success"] is None:
            row["first_success"] = success
    else:
        last = data["last_success"]
        check((last is None or type(last) is int) and last == row["last_success"], "failed visit changed the last success")
    row["attempts"] += 1
    row["last_end"] = data["end"]
    row.update(last_start=data["start"], last_result=result, last_error=error)
    return result


def verify_owner_loss(value, manifest):
    fields(value, "controller_exit peers", "interruption")
    check(uint(value["controller_exit"], 0xffffffff) != 0, "controller did not exit abruptly")
    fields(value["peers"], "target collector", "interruption peers")
    keys = set()
    for label, peer in value["peers"].items():
        fields(peer, "announced pinned before after image_file_id", "interruption witness")
        key = identity(peer["pinned"])
        check(identity(peer["announced"]) == key and peer["image_file_id"] == manifest[label + "_file_id"] and
              uint(peer["before"]) == 258 and uint(peer["after"]) == 0,
              "pinned interruption witness did not transition from live to terminated")
        keys.add(key)
    check(len({key[0] for key in keys}) == 2, "interruption witnesses alias")
    return keys


def verify_retained_scopes(ledger, members, population, admission):
    scopes = ledger.get("scopes")
    check(type(scopes) is list and len(scopes) == len(members) == decimal(ledger.get("retained")) == decimal(ledger.get("current"))
          and decimal(ledger.get("scopes_omitted")) == decimal(ledger.get("untracked_outcomes")) == 0,
          "incomplete retained generation ledger")
    remaining = set(members)
    for scope in scopes:
        check(type(scope) is dict, "invalid retained generation")
        address = scope.get("key")
        fields(address, "pid generation", "retained process identity")
        key = identity([decimal(address["pid"]), address["generation"]])
        check(key in remaining, "duplicate or foreign retained generation")
        remaining.remove(key)
        row = population[key]
        expected = dict(in_latest_inventory=True, first_seen_ms=str(row["source_first_seen"]), last_seen_ms=str(admission),
                        last_attempt_ms=None if row["last_start"] is None else str(row["last_start"]),
                        last_success_ms=None if row["last_success"] is None else str(row["last_success"]),
                        win32_error=str(row["last_error"]) if row["last_error"] else None,
                        failure_class="none" if row["last_result"] == "observed" else row["last_result"])
        check(scope.get("in_latest_inventory") is True and all(k in scope and scope[k] == v for k, v in expected.items()),
              "retained generation contradicts its census or last dispatch")


def replay_world(name, truth, replies, manifest, seen, previous):
    fields(truth, "name collector collector_file_id events job_total job_active_after_cleanup", "truth world")
    collector = identity(truth["collector"])
    check(truth["name"] == name and truth["collector_file_id"] == manifest["collector_file_id"] and
          collector not in seen, "observer binding mismatch")
    seen.add(collector)
    costs = None
    if name == "fixed" and manifest["schema"] == PAIRED_SCHEMA:
        costs = PairedCosts(manifest["run_id"], collector, decimal(manifest["qpc_hz"]))
    fields(replies.take("ready"), "kind", "ready acknowledgement")
    events = truth["events"]
    check(type(events) is list and 1 <= len(events) <= 256, "invalid controller journal size")
    population, live, selected = {}, set(), deque()
    counts, births, departures = Counter(), Counter(), Counter()
    rounds = 0
    last_admission = None
    loans = first_observations = 0
    latest_members = set()
    cutoff = None
    selected_exit = None
    for index, event in enumerate(events, 1):
        check(type(event) is dict, "invalid controller event")
        kind = event.get("kind")
        check(cutoff is None or kind == "exit", "acquisition after cutoff")
        if kind in ("inventory", "dispatch"):
            if costs:
                data, source_reply, previous = costs.request(event, replies, previous, index)
            else:
                fields(event, "kind start end", "source request")
                previous = bracket(event, previous, "start", "end")
                data = replies.take(kind)
                source_reply = replies.index
        if kind == "ready":
            fields(event, "kind child parent image_file_id role member base launch ready confirmed", "child readiness")
            key = identity(event["child"])
            check(identity(event["parent"]) == key and key not in seen and key[0] != collector[0] and
                  key[0] not in {v[0] for v in live} and event["image_file_id"] == manifest["target_file_id"],
                  "child image, handle or generation mismatch")
            role = event["role"]
            check(type(role) is str and role in {"initial", "growth", "replacement", "exit_before_census", "out_of_scope"} and
                  type(event["member"]) is bool and event["member"] == (role != "out_of_scope") and
                  not selected, "invalid workload admission")
            births[rounds, role] += 1
            if role == "replacement":
                check(departures[rounds, "observed_then_replaced"] == 1, "replacement preceded the controlled exit")
            previous = bracket(event, previous, "launch", "ready", "confirmed")
            base = uint(event["base"], 0x00007ffffffeffff)
            check(base >= 0x10000, "invalid child executable base")
            seen.add(key)
            live.add(key)
            population[key] = dict(id=f"{name}.{index}", truth_event=index, member=event["member"], role=role,
                                   base=base, ready=event["ready"], first_success=None,
                                   last_end=None, attempts=0, admitted=False, first_qualified_reply=None,
                                   first_error_reply=None, last_reply=None, exit_boundary=None)
        elif kind == "exit":
            fields(event, "kind key request ack confirmed code", "child exit")
            key = identity(event["key"])
            check(key in live and uint(event["code"]) == 0, "missing or repeated child exit")
            previous = bracket(event, previous, "request", "ack", "confirmed")
            row = population[key]
            if cutoff is not None:
                row["exit_boundary"] = "workload_cutoff"
            elif rounds == 0 and row["role"] == "exit_before_census":
                row["exit_boundary"] = "before_first_census"
            elif selected_exit is not None and selected and selected[0] == selected_exit == key:
                selected_exit = None
                row["exit_boundary"] = "after_selection_before_dispatch"
            else:
                eligible = [k for k in live if population[k]["member"] and population[k]["first_success"] is not None]
                check(name == "changing" and rounds in (5, 8, 11) and not selected and eligible and
                      min(eligible, key=lambda k: (population[k]["ready"], k)) == key, "unexpected controlled replacement")
                row["exit_boundary"] = "observed_then_replaced"
            if cutoff is None:
                departures[rounds, row["exit_boundary"]] += 1
            live.remove(key)
        elif kind == "inventory":
            check(not selected, "new inventory with pending dispatches")
            fields(data, "kind start admission members selected loan", "inventory reply")
            admission = uint(data["admission"])
            check(event["start"] <= uint(data["start"]) <= admission <= event["end"] and
                  (last_admission is None or data["start"] >= last_admission + manifest["cadence_ms"]), "invalid census timing")
            last_admission = admission
            members = set(identities(data["members"], 64))
            check(members <= {k for k in live if population[k]["member"]}, "census crossed a generation or job boundary")
            for key in members - latest_members:
                population[key].update(source_first_seen=admission, last_start=None, last_success=None,
                                       last_error=0, last_result="unattempted")
            latest_members = members
            for key in members:
                population[key]["admitted"] = True
            picked = identities(data["selected"], 8)
            loan = identity(data["loan"], nullable=True)
            check(set(picked) <= members and (not loan[0] or loan in picked), "selection outside its census")
            loans += bool(loan[0])
            selected.extend(picked)
            rounds += 1
            if name == "changing" and rounds == 1:
                check(picked, "missing controlled selection")
                selected_exit = picked[0]
        elif kind == "dispatch":
            check(selected and selected_exit is None, "dispatch contradicts selection or controlled exit")
            key = selected.popleft()
            row = population[key]
            already_observed = row["last_success"] is not None
            result = read_visit(data, row, key, key in live, event["start"], event["end"])
            first_observations += result == "observed" and not already_observed
            row["last_reply"] = source_reply
            if result == "observed" and row["first_qualified_reply"] is None:
                row["first_qualified_reply"] = source_reply
            if result in ERRORS and row["first_error_reply"] is None:
                row["first_error_reply"] = source_reply
            counts[result] += 1
        elif kind == "finish":
            fields(event, "kind start end cutoff code", "finish request")
            previous = bracket(event, previous, "start", "end", "cutoff")
            check(not selected and rounds == manifest["rounds"] and uint(event["code"]) == 0, "unfinished observer run")
            response = replies.take(kind)
            fields(response, "kind ledger", "finish reply")
            ledger = response["ledger"]
            check(type(ledger) is dict and ledger.get("schema") == "kn.user_module_observation_debt.v1", "missing terminal ledger")
            check(ledger.get("source") == "toolhelp_process_modules" and ledger.get("clock_domain") == manifest["clock"] and
                  ledger.get("whole_target_success_reported") is False, "unexpected terminal measurement scope")
            outcomes = ledger.get("outcomes")
            check(type(outcomes) is dict and outcomes.keys() == SOURCE_RESULTS and
                  all(decimal(n) == counts[k] for k, n in outcomes.items()) and
                  decimal(ledger.get("attempts")) == sum(counts.values()) and
                  decimal(ledger.get("complete_censuses")) == rounds, "terminal source counts disagree with receipts")
            sample_counts = {"observed_service": counts["observed"], "cancelled_service": counts["cancelled"],
                             "failed_service": sum(counts.values()) - counts["observed"] - counts["cancelled"] - counts["invalid_clock"],
                             "first_observation_wait": first_observations, "successful_revisit": counts["observed"] - first_observations}
            check(all(type(ledger.get(k)) is dict and decimal(ledger[k].get("samples")) == n for k, n in sample_counts.items()) and
                  decimal(ledger.get("loan_offers")) == decimal(ledger.get("loan_entries")) == loans,
                  "terminal service or reservation counts disagree with receipts")
            verify_retained_scopes(ledger, latest_members, population, last_admission)
            cutoff = previous
        else:
            raise ValueError("unknown controller event")
    expected_births = Counter({(0, "initial"): 12, (0, "out_of_scope"): 1})
    expected_departures = Counter()
    if name == "changing":
        expected_births[0, "exit_before_census"] = 1
        expected_births.update({(n, "growth"): 2 for n in (1, 2, 3)})
        expected_births.update({(n, "replacement"): 1 for n in (5, 8, 11)})
        expected_departures.update({(0, "before_first_census"): 1, (1, "after_selection_before_dispatch"): 1})
        expected_departures.update({(n, "observed_then_replaced"): 1 for n in (5, 8, 11)})
    members = [row for row in population.values() if row["member"]]
    check(cutoff is not None and replies.index == len(replies.lines) and not live and
          births == expected_births and departures == expected_departures and
          uint(truth["job_total"]) == len(members) and uint(truth["job_active_after_cleanup"]) == 0,
          "incomplete workload, source transcript or final job accounting")
    cases = []
    for row in members:
        end = row["first_success"]
        if end is not None:
            outcome = "positive"
        elif row["first_error_reply"] is not None:
            outcome = "error"
        else:
            outcome = "unavailable" if row["attempts"] else "missing"
        if end is None:
            end = row["last_end"]
        cases.append(dict(id=row["id"], truth_event=row["truth_event"], outcome=outcome, admitted=row["admitted"],
                          exit_boundary=row["exit_boundary"],
                          attempts=row["attempts"], first_qualified_reply=row["first_qualified_reply"],
                          outcome_reply=row["first_qualified_reply"] or row["first_error_reply"] or row["last_reply"],
                          elapsed_reply=row["first_qualified_reply"] or row["last_reply"],
                          elapsed_us=None if end is None else str(uint((end - row["ready"]) * 1000))))
    scope = dict(workload=name, censuses=rounds, attempts=sum(counts.values()), source_results=dict(sorted(counts.items())),
                 out_of_scope_controls=births[0, "out_of_scope"], job_active_after_cleanup=truth["job_active_after_cleanup"], cases=cases)
    if costs:
        scope["paired_costs"] = costs.report()
    return scope, previous


def verified_run(path, pin, decode):
    manifest, parts = read_bundle(path, pin, decode)
    truth = decode(parts["truth.json"])
    fields(truth, "schema run_id worlds owner_loss", "controller truth")
    paired = manifest["schema"] == PAIRED_SCHEMA
    check(truth["schema"] == ("kn.owned_module_truth.v2" if paired else "kn.owned_module_truth.v1") and truth["run_id"] == manifest["run_id"] and
          type(truth["worlds"]) is list and len(truth["worlds"]) == 2, "truth belongs to a different or incomplete run")
    seen = verify_owner_loss(truth["owner_loss"], manifest)
    worlds = []
    previous = 0
    for name, world in zip(WORLDS, truth["worlds"]):
        replies = Replies(parts[name + ".jsonl"], decode, paired=paired and name == "fixed")
        scope, previous = replay_world(name, world, replies, manifest, seen, previous)
        worlds.append(scope)
    return manifest, worlds
