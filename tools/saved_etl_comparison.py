"""Capture framing and offline adjudication for paired saved Windows ETL readers."""
import base64
import binascii
from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys
from typing import NamedTuple

from owned_module_benchmark import PackagePinMismatch, check, decimal, encoded, fields, publish_new, sha, uint


MAGIC = b"KNETLBC1"
HEADER = struct.Struct("<8sIQ")
MAX_ETL = 512 << 20
MAX_METADATA = 4 << 20
MAX_REGISTERED_SLOTS = 32
MIB = 1 << 20
DIAGNOSTIC = 64 << 10
ROLES = ("native", "tracerpt")
PROVIDER = re.compile(r"\{([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\}")
ROW_COUNT = re.compile(r"\| *([0-9]{1,19}) {3}")
TASK_OR_ID = re.compile(r"(?<!\S)[0-9]{1,5}(?!\S)")


class Family(NamedTuple):
    domain: str
    provider: str
    opcodes: dict[int, str]
    versions: set[int]
    other_names: set[str]


FAMILIES = {
    "cpu_profile": Family("execution", "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc", {46: "SampleProf"}, {2},
                          {"CollectionStart", "CollectionEnd", "SetInterval"}),
    "context_switch": Family("execution", "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c", {36: "CSwitch"}, {2, 3, 4},
                             {"Start", "End", "DCStart", "DCEnd", "ReadyThread", "SetName", "AutoBoost Clear Floor",
                              "AutoBoost Entry Exhaustion", "AutoBoost Set Floor"}),
}
WITH_DISK_IO = {
    **FAMILIES,
    "disk_io": Family("io", "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c",
                      {10: "Read", 11: "Write", 12: "ReadInit", 13: "WriteInit", 14: "FlushBuffers", 15: "FlushInit"},
                      {2, 3}, set()),
}
NATIVE_ARGS = ("--capabilities", "--probe-etl", "source.etl", "--sha256")
TRACERPT_ARGS = ("source.etl", "-of", "CSV", "-o", "NUL", "-summary", "summary.txt", "-y")


def local_path(value):
    value = os.fspath(value)
    check(value and "\0" not in value, "expected a local file path")
    path = Path(value)
    if os.name == "nt":
        check(not value.startswith(("\\", "/")) and (not path.drive or path.is_absolute()) and
              not any(c in '<>"|?*' or ord(c) < 32 for c in value), "expected a local Windows path")
        for part in path.parts[int(bool(path.anchor)):]:
            check(part in (".", "..") or (":" not in part and not part.endswith((" ", ".")) and not Path(part).is_reserved()),
                  "ambiguous or reserved Windows path")
    return Path(os.path.abspath(path))


def outputs_safe(arguments, opened=None):
    """A diagnostic, help text or result can itself point at an acquisition input."""
    sinks = [os.fstat(stream.fileno()) for stream in (sys.stdout, sys.stderr) if stream is not None]
    sinks = [s for s in sinks if stat.S_ISREG(s.st_mode)]
    if not sinks:
        return True
    if opened is not None and any(os.path.samestat(s, os.fstat(opened.fileno())) for s in sinks):
        return False
    for arg in arguments:
        name = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        try:
            identity = os.stat(local_path(name))
            if any(os.path.samestat(s, identity) for s in sinks):
                return False
        except (FileNotFoundError, NotADirectoryError):
            pass
        except (OSError, ValueError):
            return False
    return True


def write_result(data):
    if sys.stdout is None:
        return 2
    try:
        remaining = memoryview(data)
        while remaining:
            count = os.write(sys.stdout.fileno(), remaining[:32768])
            if not count:
                return 2
            remaining = remaining[count:]
    except OSError:
        return 2
    return 0


def digest(value):
    check(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA-256")
    return value


class InputPinMismatch(ValueError):
    def __init__(self, role, expected, observed):
        super().__init__("ETL admission pin mismatch" if role == "etl" else "reader binary admission pin mismatch")
        self.role = role
        self.expected = expected
        self.observed = observed


def registration(value):
    fields(value, "plan_sha256 slot ticket admission_id", "registered reader slot")
    digest(value["plan_sha256"])
    check(1 <= uint(value["slot"], MAX_REGISTERED_SLOTS), "invalid registered slot")
    for key in ("ticket", "admission_id"):
        check(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{32}", value[key]), "invalid registered identity")
    check(value["ticket"] != value["admission_id"], "repeated registered identity")
    return value


def config(pin, timeout_ms, include_disk_io=False):
    check(1 <= uint(timeout_ms, 600000), "timeout must be 1..600000 ms")
    return dict(native=[*NATIVE_ARGS, pin], tracerpt=list(TRACERPT_ARGS), timeout_ms=timeout_ms,
                adjudication=("classic_profile_switch_and_disk_io_descriptor_counts_v2" if include_disk_io else
                              "classic_profile_and_switch_descriptor_counts_v1"))


def stream_bytes(stream, size, consume):
    remaining = size
    while remaining:
        block = stream.read(min(remaining, MIB))
        check(block, "truncated comparison source")
        consume(block)
        remaining -= len(block)
    check(not stream.read(1), "unexpected bytes after comparison source")


def write_package(path, manifest, source):
    metadata = encoded(manifest)
    size = manifest["source_bytes"]
    check(0 < len(metadata) <= MAX_METADATA and 0 < size <= MAX_ETL, "comparison package bounds exceeded")

    def write(output):
        output.write(HEADER.pack(MAGIC, len(metadata), size))
        output.write(metadata)
        actual = hashlib.sha256()
        source.seek(0)

        def copy(block):
            actual.update(block)
            output.write(block)
        stream_bytes(source, size, copy)
        check(actual.hexdigest() == manifest["source_sha256"], "source changed during acquisition")

    return publish_new(path, write)


def record_bytes(stream, limit):
    size = stream.seek(0, 2)
    stream.seek(0)
    prefix = stream.read(min(limit, size))
    check(len(prefix) == min(limit, size), "cannot retain comparison output")
    entire = hashlib.sha256(prefix)
    stream_bytes(stream, size - len(prefix), entire.update)
    return dict(byte_count=size, original_sha256=entire.hexdigest(), retained_sha256=sha(prefix),
                base64=base64.b64encode(prefix).decode("ascii"))


def original(record, limit):
    fields(record, "byte_count original_sha256 retained_sha256 base64", "original tool output")
    size = uint(record["byte_count"])
    length = min(size, limit)
    text = record["base64"]
    check(type(text) is str and len(text) == 4 * ((length + 2) // 3), "invalid retained output extent")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid comparison output encoding") from exc
    check(len(raw) == length and base64.b64encode(raw).decode("ascii") == text and sha(raw) == record["retained_sha256"],
          "comparison output digest or extent mismatch")
    full_pin = digest(record["original_sha256"])
    check(size != length or full_pin == record["retained_sha256"], "complete output differs from original digest")
    return raw, size == length


def descriptor_row(line, with_opcode):
    # tracerpt pads short columns and lets long names expand. Identify the
    # numeric task/ID column by its actual offset; opcode labels may contain spaces.
    check(len(line) <= 2048 and line.endswith("|"), "unrecognized tracerpt row bounds")
    count = ROW_COUNT.match(line)
    check(count, "missing tracerpt row count")
    pieces = line[count.end():-1].rsplit(None, 2)
    check(len(pieces) == 3, "incomplete tracerpt descriptor")
    desc, version, provider = pieces
    guid = PROVIDER.fullmatch(provider)
    check(guid and re.fullmatch(r"[0-9]{1,3}", version), "invalid tracerpt provider/version")
    candidates = []
    for field in TASK_OR_ID.finditer(desc):
        name = desc[:field.start()].rstrip(" ")
        prefix = desc[:field.start()]
        if ((len(name) < 20 and prefix != name.ljust(20) + " ") or
                (len(name) >= 20 and len(prefix) - len(name) not in (1, 2))):
            continue
        task = field[0]
        opcode = desc[field.end():].strip(" ")
        column = task.ljust(15) + " " + opcode if opcode else task
        if desc[field.start():] == column and (with_opcode or not opcode):
            uint(int(task), 65535)
            candidates.append((count[1], name, task, opcode, version, guid[1]))
    check(len(candidates) == 1, "ambiguous or unsupported tracerpt descriptor columns")
    return candidates[0]


def table(lines, heading, with_opcode):
    # The second summary table groups by event ID. Never add it to opcode counts.
    starts = [i for i, line in enumerate(lines) if line.startswith("|") and line[1:-1].split() == heading]
    check(len(starts) == 1, "unsupported tracerpt table headings")
    start = starts[0]
    border = re.compile(r"\+-+\+")
    check(start > 0 and start + 1 < len(lines) and border.fullmatch(lines[start - 1]) and border.fullmatch(lines[start + 1]),
          "incomplete tracerpt table")
    rows = []
    for i in range(start + 2, len(lines)):
        line = lines[i]
        if border.fullmatch(line):
            return rows, start - 1, i
        rows.append(descriptor_row(line, with_opcode))
    raise ValueError("unterminated tracerpt table")


def tracerpt_counts(raw, families=FAMILIES):
    # English table headings and ASCII descriptors are the supported summary
    # contract. Opaque provider names outside the registered families need no decoding.
    text = raw.decode("utf-16") if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else raw.decode("latin1")
    lines = text.splitlines()
    check(len(lines) > 5 and lines[0].strip() == "Files Processed:" and lines[1].strip() == "source.etl",
          "tracerpt source name or summary format differs")
    counters = {}
    for i, key in enumerate(("Total Buffers Processed", "Total Events Processed", "Total Events Lost"), 2):
        words = lines[i].split()
        check(words[:-1] == key.split() and re.fullmatch(r"[0-9]{1,19}", words[-1]), "invalid tracerpt summary counters")
        counters[key] = uint(int(words[-1]))
    opcodes, first, end = table(lines, "Event Count Event Name Task Opcode Version Guid".split(), True)
    check(first == 8 and all(lines[i].split()[:2] == label.split() for i, label in
          enumerate(("Start Time", "End Time", "Elapsed Time"), 5)), "unexpected tracerpt summary preamble")
    total = counters["Total Events Processed"]
    def partitions(rows):
        breakdown = Counter()
        for row in rows:
            count = uint(int(row[0]))
            check(count > 0, "empty tracerpt descriptor row")
            breakdown[(row[-1].lower(), uint(int(row[-2]), 255))] += count
        return breakdown
    groups = partitions(opcodes)
    check(sum(groups.values()) == total, "tracerpt opcode table count mismatch")
    tables = "opcode_only"
    if any(line.strip() for line in lines[end + 1:]):
        ids, second, last = table(lines, "Event Count Event Name Event ID Version Guid".split(), False)
        check(second == end + 1 and not any(line.strip() for line in lines[last + 1:]), "unexpected tracerpt summary tail")
        check(groups == partitions(ids), "tracerpt event ID table provider/version mismatch")
        tables = "opcode_and_event_id"
    counts = {name: dict(supported_descriptors=0, other_versions=0, unresolved_opcode_names=0) for name in families}
    for number, _, _, opcode, version, provider in opcodes:
        for name, family in families.items():
            if provider.lower() != family.provider:
                continue
            numeric = opcode.isascii() and opcode.isdecimal()
            if numeric:
                uint(int(opcode), 255)
            if opcode in family.opcodes.values() or (numeric and int(opcode) in family.opcodes):
                counts[name]["supported_descriptors" if int(version) in family.versions else "other_versions"] += int(number)
            elif not numeric and opcode not in family.other_names:
                counts[name]["unresolved_opcode_names"] += int(number)
    return dict(records=total, buffers=counters["Total Buffers Processed"], events_lost=counters["Total Events Lost"],
                summary_tables=tables, families=counts)


def native_counts(raw, decode, pin, size, exit_code, families=FAMILIES):
    doc = decode(raw)
    check(type(doc) is dict and doc.get("schema") == "kn.capabilities.v1" and doc.get("scope") == "saved_etl_probe" and
          doc.get("target_probed") is False, "wrong native report")
    probe = doc.get("probe")
    check(type(probe) is dict and probe.get("schema") == "kn.etl_capability_probe.v1" and probe.get("expected_sha256") == pin,
          "native invocation is not bound to the supplied trace")
    status, win32 = probe.get("status"), probe.get("win32_status")
    check(type(status) is str and re.fullmatch(r"[a-z_]{1,48}", status) and
          type(probe.get("trace_opened")) is bool and (probe.get("source_revalidated") is None or
          type(probe["source_revalidated"]) is bool), "invalid native status evidence")
    if win32 is not None:
        uint(win32, 0xffffffff)
    stages = dict(status=status, win32_status=win32, trace_opened=probe["trace_opened"], source_revalidated=probe["source_revalidated"])
    if probe.get("coverage") is None:
        check(exit_code == 1 and probe.get("status") not in ("read", "partial"), "native coverage missing from successful report")
        return None, stages
    check(probe.get("source_sha256") == pin and uint(probe.get("source_bytes")) == size and
          probe.get("source_revalidated") is True and probe.get("trace_opened") is True and uint(probe.get("win32_status")) == 0,
          "native source identity unavailable")
    c = probe["coverage"]
    fields(c, "records_seen buffers_written buffers_processed buffer_comparison events_lost buffers_lost loss_marker_records", "native coverage")
    for key in c.keys() - {"buffer_comparison"}:
        uint(c[key])
    comparison = c["buffer_comparison"]
    check(comparison in {"matched", "fewer_than_declared", "more_than_declared", "not_comparable"}, "unknown native buffer accounting")
    check(c["records_seen"] <= 2_000_000 and c["loss_marker_records"] <= c["records_seen"], "native record bounds exceeded")
    if comparison != "not_comparable":
        check(c["buffers_written"] > 0, "native comparable traversal has no declared buffers")
        expected = ("matched" if c["buffers_processed"] == c["buffers_written"] else
                    "fewer_than_declared" if c["buffers_processed"] < c["buffers_written"] else "more_than_declared")
        check(comparison == expected, "inconsistent native buffer counts")
    gap = comparison != "matched" or bool(c["events_lost"] or c["buffers_lost"] or c["loss_marker_records"])
    check(probe.get("status") == ("partial" if gap else "read") and exit_code == int(gap), "native status disagrees with coverage")
    counts = {}
    check(type(doc.get("capabilities")) is list, "native family list missing")
    domains = tuple(family.domain for family in families.values())
    for row in doc["capabilities"]:
        check(type(row) is dict, "invalid native family row")
        if row.get("domain") not in domains or row.get("backend") != "etl":
            continue
        name = row.get("operation")
        if name not in families or row["domain"] != families[name].domain:
            continue
        check(name not in counts and row.get("availability_scope") == "supplied_etl_record_family", "ambiguous native family")
        evidence = row.get("record_evidence")
        fields(evidence, "observation decoded unsupported first_decoded_record first_payload_bytes first_payload_sha256", "native family evidence")
        observed, unsupported = uint(evidence["decoded"]), uint(evidence["unsupported"])
        check(observed + unsupported <= c["records_seen"], "native family exceeds traversal")
        if observed:
            check(1 <= uint(evidence["first_decoded_record"]) <= c["records_seen"] and uint(evidence["first_payload_bytes"]) > 0,
                  "native first record outside traversal")
            digest(evidence["first_payload_sha256"])
        else:
            check(all(evidence[key] is None for key in ("first_decoded_record", "first_payload_bytes", "first_payload_sha256")),
                  "empty native family has sample evidence")
        label = "decoded_records" if observed else "unsupported_layout_only" if unsupported else "no_matching_records_observed"
        check(evidence["observation"] == label and row.get("availability") == ("available" if observed and not unsupported and not gap else "partial"),
              "native family status disagrees with counts")
        counts[name] = dict(decoded=observed, unsupported=unsupported)
    # The original two rows are required by both contracts. Older readers can
    # successfully report those rows without implementing the optional disk probe.
    check(FAMILIES.keys() <= counts.keys() and sum(r["decoded"] + r["unsupported"] for r in counts.values()) <= c["records_seen"],
          "native family inventory incomplete")
    return dict(records=c["records_seen"], buffers=c["buffers_processed"], coverage=c, gap=gap, families=counts), stages


def extent(record, limit):
    if record is None:
        return None
    return dict(byte_count=record["byte_count"], retained_bytes=min(record["byte_count"], limit),
                original_sha256=record["original_sha256"], retained_sha256=record["retained_sha256"])


def attempt(manifest, role, decode, families=FAMILIES):
    tool, row = manifest["tools"][role], manifest["attempts"][role]
    fields(tool, "before_sha256 after_sha256 expected_sha256", "comparison binary")
    before, after = digest(tool["before_sha256"]), digest(tool["after_sha256"])
    if role == "native" or tool["expected_sha256"] is not None:
        check(digest(tool["expected_sha256"]) == before, "binary differs from admission pin")
    fields(row, "state exit_code os_error image_binding started_ns ended_ns stdout stderr", "comparison attempt")
    start, end = decimal(row["started_ns"]), decimal(row["ended_ns"])
    check(start <= end, "reversed comparison clock")
    state = row["state"]
    check(state in ("exited", "timed_out", "launch_error"), "invalid comparison process state")
    binding = row["image_binding"]
    if state == "launch_error":
        check(binding is None, "unexpected process image for failed launch")
    else:
        fields(binding, "status win32_status", "started reader image")
        check(binding["status"] in ("matched", "different_path", "unavailable") and
              (uint(binding["win32_status"], 0xffffffff) != 0) == (binding["status"] == "unavailable"), "invalid process image binding")
    if state == "exited":
        uint(row["exit_code"], 0xffffffff)
        check(row["os_error"] is None, "unexpected process error")
    else:
        check(row["exit_code"] is None, "no original program exit on launch failure or timeout")
        if state == "launch_error":
            check(uint(row["os_error"], 0xffffffff) > 0, "missing original launch error")
        else:
            check(row["os_error"] is None, "unexpected timeout error")
    limit = MIB if role == "native" else DIAGNOSTIC
    stdout, full = original(row["stdout"], limit)
    _, stderr_full = original(row["stderr"], DIAGNOSTIC)
    summary, summary_full = (original(manifest["summary"], MIB) if role == "tracerpt" and manifest["summary"] is not None else (None, True))
    status, counts, stages = state, None, None
    if before != after:
        status = "binary_changed"
    elif state == "exited":
        if binding["status"] != "matched":
            status = "reader_image_unverified"
        elif not full or not stderr_full or not summary_full:
            status = "retained_output_truncated"
        elif row["exit_code"] not in ((0, 1) if role == "native" else (0,)):
            status = "reader_error"
        elif role == "tracerpt" and summary is None:
            status = "summary_unavailable"
        else:
            try:
                if role == "native":
                    counts, stages = native_counts(stdout, decode, manifest["source_sha256"], manifest["source_bytes"], row["exit_code"], families)
                else:
                    counts = tracerpt_counts(summary, families)
                status = "observed" if counts is not None else "source_unavailable"
            except (ValueError, KeyError, TypeError, IndexError, OverflowError, RecursionError):
                status = "unqualified_output"
    return dict(status=status, process_state=state, exit_code=row["exit_code"], os_error=row["os_error"],
                elapsed_ns=str(end - start), binary=tool, image_binding=binding, stdout=extent(row["stdout"], limit), stderr=extent(row["stderr"], DIAGNOSTIC),
                summary=extent(manifest["summary"], MIB) if role == "tracerpt" else None, native_probe=stages, counts=counts)


def adjudicate(manifest, decode, package_pin, ratio):
    check(type(manifest) is dict, "invalid paired acquisition")
    schema = manifest.get("schema")
    campaign = schema == "kn.etl_reader_comparison.v3"
    fields(manifest, "schema source_sha256 source_bytes config config_sha256 os_build tools attempts summary" +
           (" registration" if campaign else ""), "paired acquisition")
    check(campaign or schema in ("kn.etl_reader_comparison.v1", "kn.etl_reader_comparison.v2"), "unknown ETL acquisition")
    pin = digest(manifest["source_sha256"])
    cfg = manifest["config"]
    if campaign:
        registration(manifest["registration"])
        check(type(cfg) is dict, "missing registered reader configuration")
        include_disk_io = cfg == config(pin, cfg.get("timeout_ms"), True)
    else:
        include_disk_io = schema == "kn.etl_reader_comparison.v2"
    registered = WITH_DISK_IO if include_disk_io else FAMILIES
    check(type(cfg) is dict and cfg == config(pin, cfg.get("timeout_ms"), include_disk_io) and sha(encoded(cfg)) == manifest["config_sha256"],
          "comparison configuration mismatch")
    check(type(manifest["os_build"]) is str and re.fullmatch(r"[0-9]{1,6}(\.[0-9]{1,6}){2}", manifest["os_build"]), "invalid reader OS build")
    for key in ("tools", "attempts"):
        fields(manifest[key], "native tracerpt", "paired readers")
    reads = {role: attempt(manifest, role, decode, registered) for role in ROLES}
    check(decimal(manifest["attempts"]["native"]["ended_ns"]) <= decimal(manifest["attempts"]["tracerpt"]["started_ns"]),
          "reader attempts conflict with registered order")
    native, external = (reads[role]["counts"] for role in ROLES)
    families = {}
    comparable = agreed = 0
    for name in registered:
        nr = native["families"].get(name) if native else None
        er = external["families"][name] if external else None
        if native is None or external is None:
            status = "reader_unavailable"
        elif nr is None:
            status = "native_family_unavailable"
        elif native["gap"] or external["events_lost"] or nr["unsupported"] or er["other_versions"] or er["unresolved_opcode_names"]:
            status = "coverage_limited"
        elif native["records"] != external["records"] or native["buffers"] != external["buffers"]:
            status = "traversal_disagreement"
        else:
            comparable += 1
            matches = nr["decoded"] == er["supported_descriptors"]
            agreed += matches
            status = ("agreed_observed" if nr["decoded"] else "agreed_empty") if matches else "count_disagreement"
        families[name] = dict(verdict=status, native=nr, tracerpt=er)
    evaluation_schema = "kn.etl_reader_evaluation.v2" if include_disk_io else "kn.etl_reader_evaluation.v1"
    report = dict(schema=evaluation_schema, package_sha256=package_pin, source_sha256=pin,
                source_bytes=manifest["source_bytes"], config=cfg, config_sha256=manifest["config_sha256"], reader_os_build=manifest["os_build"],
                layer="independent_comparison", task="saved_etl_descriptor_counts", unit="event_family_in_one_file",
                artifacts_opened=True, target_probed=False, producer_authenticated=False, ground_truth_authenticated=False,
                independent_detection_validation=False, overall_ranking=None, readers=reads, families=families,
                planned_readers=2, observed_readers=sum(r["counts"] is not None for r in reads.values()),
                agreement_per_planned_family=ratio(agreed, len(registered)), agreement_per_comparable_family=ratio(agreed, comparable))
    if campaign:
        report.update(schema="kn.etl_reader_evaluation.v3", registration=manifest["registration"], campaign_plan_checked=False)
        for role in ROLES:
            report["readers"][role].update(started_ns=manifest["attempts"][role]["started_ns"],
                                          ended_ns=manifest["attempts"][role]["ended_ns"])
    return report


def replay(stream, expected, decode, ratio):
    digest(expected)
    header = stream.read(HEADER.size)
    check(len(header) == HEADER.size, "incomplete ETL comparison header")
    magic, meta_size, size = HEADER.unpack(header)
    check(magic == MAGIC and 0 < meta_size <= MAX_METADATA and 0 < size <= MAX_ETL, "invalid ETL comparison framing")
    metadata = stream.read(meta_size)
    check(len(metadata) == meta_size, "incomplete ETL comparison metadata")
    package, source = hashlib.sha256(header + metadata), hashlib.sha256()
    def consume(block):
        package.update(block)
        source.update(block)
    stream_bytes(stream, size, consume)
    if package.hexdigest() != expected:
        raise PackagePinMismatch("ETL comparison package pin mismatch")
    manifest = decode(metadata)
    check(type(manifest) is dict and uint(manifest.get("source_bytes")) == size and manifest.get("source_sha256") == source.hexdigest(),
          "retained ETL differs from original source")
    return adjudicate(manifest, decode, expected, ratio)
