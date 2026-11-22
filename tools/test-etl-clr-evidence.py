"""Check saved sample-to-CLR declarations against Windows tracerpt named fields."""
import argparse
import copy
from collections import Counter, defaultdict
import hashlib
import json
import shutil
from pathlib import Path
from runpy import run_path
import tempfile


BASE = run_path(str(Path(__file__).with_name("test-etl-profile.py")))
IMPORT = run_path(str(Path(__file__).with_name("test-etl-trace-import.py")))
ProcessOracle = run_path(str(Path(__file__).with_name("etl_process_oracle.py")))["ProcessOracle"]
RUNTIME = "e13c0d23-ccbc-4e12-931b-d9cc2eee27e4"
RUNDOWN = "a669021c-c450-4609-a035-5af59af4df18"


class ClrOracle:
    def __init__(self):
        self.points = {}
        self.by_pid = defaultdict(list)
        self.actions = Counter()

    def observe_xml(self, event, ns, record):
        system = event.find(ns + "System")
        provider = system.find(ns + "Provider").get("Guid", "").strip("{}").lower()
        if provider not in (RUNTIME, RUNDOWN):
            return
        data = event.find(ns + "UserData")
        if data is None:
            return
        fields = {field.tag.rsplit("}", 1)[-1]: field.text for template in data for field in template}
        if "MethodStartAddress" not in fields:
            return
        opcode = int(system.findtext(ns + "Opcode"))
        action = {33: "load", 34: "unload", 35: "rundown", 36: "rundown",
                  37: "load", 38: "unload", 39: "rundown", 40: "rundown"}[opcode]
        pid = int(system.find(ns + "Execution").get("ProcessID"), 0)
        point = dict(record_ordinal=record, raw_timestamp=system.find(ns + "TimeCreated").get("RawTime"),
                     header_process_id=pid, provider_guid=provider, event_id=int(system.findtext(ns + "EventID")),
                     version=int(system.findtext(ns + "Version")), opcode=opcode, action=action,
                     method_start=hex(int(fields["MethodStartAddress"], 0)), method_size=int(fields["MethodSize"], 0),
                     method_id=hex(int(fields["MethodID"], 0)), module_id=hex(int(fields["ModuleID"], 0)),
                     method_token=hex(int(fields["MethodToken"], 0)), method_flags=hex(int(fields["MethodFlags"], 0)),
                     clr_instance_id=int(fields["ClrInstanceID"], 0) if "ClrInstanceID" in fields else None,
                     rejit_id=hex(int(fields["ReJITID"], 0)) if "ReJITID" in fields else None)
        self.points[record] = point
        self.by_pid[pid].append(point)
        self.actions[action] += 1

    def lifetimes(self, process, boundaries, cache):
        # These public workloads use one load and at most one unload per
        # published start within an actual process generation. Pair the named
        # fields before looking at any sample, independently of the native index.
        generation = process["recorded_generation"]
        start = generation["start_record"]
        if start in cache:
            return cache[start]
        close = process["after_record"]
        groups = defaultdict(list)
        for point in self.by_pid[generation["payload_pid"]]:
            if start < point["record_ordinal"] < close:
                groups[point["method_start"]].append(point)
        spans = []
        for events in groups.values():
            assert [p["action"] for p in events] in (["load"], ["load", "unload"])
            opened = events[0]
            ended = events[1] if len(events) > 1 else None
            if ended:
                for key in ("method_id", "module_id", "method_start", "method_size", "method_flags", "method_token", "clr_instance_id", "rejit_id"):
                    assert opened[key] == ended[key]
                assert int(opened["raw_timestamp"]) < int(ended["raw_timestamp"]) < int(boundaries[close]["raw_timestamp"])
            assert int(boundaries[start]["raw_timestamp"]) < int(opened["raw_timestamp"])
            base = int(opened["method_start"], 0)
            spans.append((base, base + opened["method_size"], opened, ended))
        cache[start] = spans
        return spans

    def compare(self, report, processes, cache, counts):
        meta = report["clr_source"]
        assert meta == dict(load_events=self.actions["load"], unload_events=self.actions["unload"], rundown_events=self.actions["rundown"],
                            unsupported_events=0, unknown_pid_events=0, retained_events=len(self.points), clock_reversed=False,
                            runtime_bytes_observed=False)
        references = set()
        for row in report["samples"]:
            process = row["process_evidence"]
            generation = process["recorded_generation"]
            raw = row["record_ordinal"]
            ip = int(row["instruction_pointer"], 0)
            relation = "process_generation_unavailable" if generation is None else "no_covering_declaration"
            witnesses, offset, start = [], None, None
            if generation is not None:
                for lo, hi, opened, ended in self.lifetimes(process, processes.points, cache):
                    if not lo <= ip < hi or opened["record_ordinal"] >= raw or (ended and ended["record_ordinal"] <= raw):
                        continue
                    assert int(opened["raw_timestamp"]) < int(row["raw_timestamp"])
                    if ended:
                        assert int(row["raw_timestamp"]) < int(ended["raw_timestamp"])
                    witnesses.append(dict(before_record=opened["record_ordinal"], after_record=ended["record_ordinal"] if ended else None))
                    references.add(opened["record_ordinal"])
                    if ended:
                        references.add(ended["record_ordinal"])
                        offset, start, relation = hex(ip - lo), generation["start_record"], "load_unload"
                    else:
                        relation = "preceding_declaration"
            assert len(witnesses) <= 1, "fixture has overlapping method declarations"
            expected = dict(relation=relation, candidate_ranges=len(witnesses), process_start_record=start,
                            method_offset=offset, witnesses=witnesses)
            assert row["clr_evidence"] == expected, (row["sample_ordinal"], row["clr_evidence"], expected)
            counts[relation] += 1
        assert [p["record_ordinal"] for p in report["clr_records"]] == sorted(references)
        for point in report["clr_records"]:
            expected = dict(self.points[point["record_ordinal"]], logger_id=report["samples"][0]["logger_id"])
            assert point == expected, ("CLR XML record", point["record_ordinal"])


def check_reported_methods(imported, source):
    records = {p["record_ordinal"]: p for p in source["clr_records"]}
    for sample, row in zip(imported["samples"], source["samples"], strict=True):
        evidence = row["clr_evidence"]
        assert sample["reported_clr_relation"] == evidence["relation"] and sample["code_version"] is None
        if evidence["relation"] == "load_unload":
            w = evidence["witnesses"][0]
            a, b = records[w["before_record"]], records[w["after_record"]]
            assert sample["reported_clr_method"] == dict(process_start_record=evidence["process_start_record"],
                pid=a["header_process_id"], load_record=a["record_ordinal"], unload_record=b["record_ordinal"],
                method_id=str(int(a["method_id"], 0)), module_id=str(int(a["module_id"], 0)), method_start=str(int(a["method_start"], 0)),
                method_size=a["method_size"], method_offset=str(int(evidence["method_offset"], 0)), method_token=int(a["method_token"], 0),
                method_flags=int(a["method_flags"], 0), clr_instance_id=a["clr_instance_id"],
                rejit_id=str(int(a["rejit_id"], 0)) if a["rejit_id"] is not None else None, runtime_bytes_observed=False)
        else:
            assert sample["reported_clr_method"] is None


def check_two_rows(api, exe, source, path):
    page = copy.deepcopy(source)
    first = page["samples"][0]
    second = copy.deepcopy(first)
    second["record_ordinal"] += 1
    second["sample_ordinal"] += 1
    tick = int(first["raw_timestamp"])
    second["raw_timestamp"] = str(tick + 1)
    page["samples"].append(second)
    page["next_after"] = second["sample_ordinal"]

    def query_status(rc):
        path.write_text(json.dumps(page), encoding="utf8")
        return api["query"](exe, path, rc=rc)["status"]

    assert query_status(0) == "ok"
    second["raw_timestamp"] = str(tick - 1)
    assert query_status(1) == "unavailable"
    second["raw_timestamp"] = str(tick + 1)
    load, unload = copy.deepcopy(page["clr_records"])
    load.update(record_ordinal=first["record_ordinal"] - 1, raw_timestamp=str(tick - 1))
    unload.update(record_ordinal=second["record_ordinal"] + 1, raw_timestamp=str(tick + 2))
    page["clr_records"][1:1] = [load, unload]
    evidence = second["clr_evidence"]
    evidence["witnesses"] = [dict(before_record=load["record_ordinal"], after_record=unload["record_ordinal"])]
    original_start = int(load["method_start"], 0)
    original_size = load["method_size"]
    for overlap in (False, True):
        start = original_start - 1 if overlap else original_start + original_size
        for point in (load, unload):
            point.update(method_start=hex(start), method_size=original_size + int(overlap))
        second["instruction_pointer"] = first["instruction_pointer"] if overlap else hex(start)
        evidence["method_offset"] = hex(int(second["instruction_pointer"], 0) - start)
        assert query_status(1 if overlap else 0) == ("unavailable" if overlap else "ok")


def check_import(exe, etl, pin, after, folder, short_tail=False):
    # A single original row makes each mutation independent of other witnesses.
    api = IMPORT
    args = ["--etl-profile", etl, "--sha256", pin, "--clr-evidence", "--after", after, "--limit", 1]
    original = api["command"](exe, args)
    source = json.loads(original)
    row = source["samples"][0]
    evidence = row["clr_evidence"]
    path = folder / "clr-page.json"
    path.write_bytes(original)
    for mode in ("offline", "observe", "named"):
        imported = api["query"](exe, path, mode=mode)
        assert imported["status"] == "ok" and imported["file_sha256"] == hashlib.sha256(original).hexdigest()
        assert imported["source"]["native_schema"] == "kn.etl_profile.v8" and not any(imported[k] for k in api["TRUST"])
        assert imported["address_spaces"] == imported["code_versions"] == []
        check_reported_methods(imported, source)
    expected = hashlib.sha256(original).hexdigest()
    api["replay"](exe, args, expected, expected, "read", True)
    if evidence["relation"] != "load_unload":
        return
    api["private_parts"]([source["clr_source"], evidence, *evidence["witnesses"], *source["clr_records"],
                          imported["samples"][0]["reported_clr_method"]])
    if short_tail:
        trimmed = folder / "one-short.etl"
        shutil.copyfile(etl, trimmed)
        with trimmed.open("r+b") as stream:
            stream.truncate(trimmed.stat().st_size - 1)
        with trimmed.open("rb") as stream:
            short_pin = hashlib.file_digest(stream, "sha256").hexdigest()
        short_args = list(args)
        short_args[1], short_args[3] = trimmed, short_pin
        shortened = api["command"](exe, short_args, 1)
        partial = json.loads(shortened)
        assert partial["status"] == "partial" and partial["buffer_comparison"] == "fewer_than_declared"
        saved = partial["samples"][0]
        assert (saved["record_ordinal"], saved["raw_timestamp"]) == (row["record_ordinal"], row["raw_timestamp"])
        assert saved["clr_evidence"]["method_offset"] is None and saved["clr_evidence"]["relation"] != "load_unload"
        path.write_bytes(shortened)
        assert api["query"](exe, path, rc=1)["samples"][0]["reported_clr_method"] is None
        short_digest = hashlib.sha256(shortened).hexdigest()
        api["replay"](exe, short_args, short_digest, short_digest, "partial", True)

    check_two_rows(api, exe, source, path)

    def reject(keys, value):
        changed = copy.deepcopy(source)
        part = changed
        for key in keys[:-1]:
            part = part[key]
        part[keys[-1]] = value
        path.write_text(json.dumps(changed), encoding="utf8")
        assert api["query"](exe, path, rc=1)["status"] == "unavailable", keys

    a, b = source["clr_records"]
    for keys, value in [
        (("samples", 0, "clr_evidence", "method_offset"), "0x100000"),
        (("samples", 0, "clr_evidence", "process_start_record"), a["record_ordinal"]),
        (("samples", 0, "clr_evidence", "candidate_ranges"), 2),
        (("samples", 0, "clr_evidence", "witnesses", 0, "after_record"), a["record_ordinal"]),
        (("samples", 0, "process_evidence", "recorded_generation", "payload_pid"), a["header_process_id"] + 1),
        (("samples", 0, "thread_evidence", "before", "payload_tid"), row["sampled_thread_id"] + 1),
        (("process_records", 1, "parent_pid"), source["process_records"][0]["parent_pid"] + 1),
        (("clr_records", 1, "method_id"), "0x1" if a["method_id"] != "0x1" else "0x2"),
        (("clr_records", 1, "method_size"), a["method_size"] + 1),
        (("clr_records", 1, "rejit_id"), "0x1"),
        (("clr_records", 1, "raw_timestamp"), row["raw_timestamp"]),
        (("clr_records", 1, "logger_id"), b["logger_id"] + 1),
        (("clr_source", "clock_reversed"), True),
        (("log_header", "events_lost"), 1),
        (("thread_source", "unsupported_events"), 1),
        (("clr_source", "runtime_bytes_observed"), True),
        (("clr_records", 0, "action"), "unload")]:
        reject(keys, value)
    for version, instance, rejit in [(0, None, None), (2, 0, "0x0"), (2, 65535, "0xfedcba9876543210")]:
        changed = copy.deepcopy(source)
        for method in changed["clr_records"]:
            method.update(version=version, clr_instance_id=instance, rejit_id=rejit)
        path.write_text(json.dumps(changed), encoding="utf8")
        sample = api["query"](exe, path)["samples"][0]
        assert sample["verified_level"] == "unqualified" and sample["code_version"] is None
        assert sample["reported_clr_method"]["clr_instance_id"] == instance
        assert sample["reported_clr_method"]["rejit_id"] == (None if rejit is None else str(int(rejit, 0)))
        if version == 2:
            changed["clr_records"][1]["rejit_id"] = hex(int(rejit, 0) ^ 1)
            path.write_text(json.dumps(changed), encoding="utf8")
            assert api["query"](exe, path, rc=1)["status"] == "unavailable"

    truncated = copy.deepcopy(source)
    truncated["clr_source"].update(load_events=65537, retained_events=65536)
    truncated["clr_records"] = []
    truncated["samples"][0]["clr_evidence"] = dict(relation="index_limit", candidate_ranges=0, witnesses=[],
                                                    process_start_record=None, method_offset=None)
    path.write_text(json.dumps(truncated), encoding="utf8")
    assert api["query"](exe, path, rc=1)["status"] == "unavailable"
    truncated["status"] = "partial"
    path.write_text(json.dumps(truncated), encoding="utf8")
    partial = api["query"](exe, path, rc=1)
    assert partial["status"] == "partial" and partial["samples"][0]["reported_clr_method"] is None
    truncated["clr_source"] = source["clr_source"]
    path.write_text(json.dumps(truncated), encoding="utf8")
    assert api["query"](exe, path, rc=1)["status"] == "unavailable"
    # A self-consistent claim can still be fabricated. Only the ETL replay
    # distinguishes it here. Neither import returns an independently verified sample.
    changed = copy.deepcopy(source)
    for p in changed["clr_records"]:
        p["module_id"] = "0x7" if a["module_id"] != "0x7" else "0x8"
    path.write_text(json.dumps(changed), encoding="utf8")
    projected = api["query"](exe, path)["samples"][0]
    assert projected["verified_level"] == "unqualified" and projected["code_version"] is None
    api["replay"](exe, args, hashlib.sha256(path.read_bytes()).hexdigest(), expected, "read", False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--etl", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--expect-methods", type=int, required=True)
    parser.add_argument("--expect-paired", type=int)
    parser.add_argument("--expect-load-only", type=int)
    parser.add_argument("--after", type=int, action="append", default=[])
    parser.add_argument("--all-pages", action="store_true")
    parser.add_argument("--check-import", action="store_true")
    parser.add_argument("--check-short-tail", action="store_true", help="require a one-byte-short copy to withhold a paired method")
    args = parser.parse_args()
    if args.check_short_tail and not args.check_import:
        parser.error("--check-short-tail requires --check-import")
    exe, etl = args.exe.resolve(), args.etl.resolve()
    with etl.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == args.sha256
    with tempfile.TemporaryDirectory() as folder:
        clr, processes = ClrOracle(), ProcessOracle()
        total, samples, threads, _, _ = BASE["oracle"](etl, Path(folder), False, processes=processes, clr=clr)
        assert len(clr.points) == args.expect_methods
        offsets = range(0, max(1, len(samples)), 128) if args.all_pages else sorted({0, max(0, len(samples) - 1), *args.after})
        counts, cache, imported = Counter(), {}, set()
        for after in offsets:
            flags = ["--clr-evidence", "--after", after, "--limit", 128]
            if args.check_import:
                raw = IMPORT["command"](exe, ["--etl-profile", etl, "--sha256", args.sha256, *flags])
                report = json.loads(raw)
                path = Path(folder) / "native-page.json"
                path.write_bytes(raw)
                imported_page = IMPORT["query"](exe, path, "/limit", 128)
                IMPORT["assert_page"](imported_page, raw, report, samples, 0, 128)
                check_reported_methods(imported_page, report)
            else:
                report = BASE["run"](exe, etl, args.sha256, *flags)
            BASE["compare"](report, args.sha256, etl.stat().st_size, total, samples, after, 128, threads, None, processes)
            clr.compare(report, processes, cache, counts)
            if args.check_import:
                for row in report["samples"]:
                    relation = row["clr_evidence"]["relation"]
                    if relation not in imported:
                        check_import(exe, etl, args.sha256, row["sample_ordinal"] - 1, Path(folder), args.check_short_tail)
                        imported.add(relation)
        if args.check_short_tail:
            assert "load_unload" in imported, "no paired sample exercised the short ETL"
        for name, value in (("load_unload", args.expect_paired), ("preceding_declaration", args.expect_load_only)):
            if value is not None:
                assert args.all_pages and counts[name] == value, (name, counts[name], value)
        assert not args.all_pages or sum(counts.values()) == len(samples)
        print("CLR records", len(clr.points), "checked samples", sum(counts.values()), "relations", dict(counts))


if __name__ == "__main__":
    main()
