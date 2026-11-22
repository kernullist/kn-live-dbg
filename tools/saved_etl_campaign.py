"""Register, run and freeze comparisons of saved ETLs before evaluating the cohort."""
import argparse
import base64
import binascii
from collections import Counter
from contextlib import ExitStack, contextmanager, suppress
from functools import cache
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time
import uuid

from owned_module_benchmark import PackagePinMismatch, check, decimal, encoded, fields, publish_new, sha, uint
from owned_module_campaign import MAX_SNAPSHOT, package_path
import saved_etl_comparison as pair


PLAN_FILE = "plan.kncampaign"
PLAN = "kn.etl_reader_plan.v1"
ADMISSION = "kn.etl_reader_admission.v1"
OUTCOME = "kn.etl_reader_outcome.v1"
SNAPSHOT = "kn.etl_reader_campaign.v1"
EVALUATION = "kn.etl_reader_campaign_evaluation.v1"
STUDY_PLAN = "kn.etl_reader_plan.v2"
STUDY_SNAPSHOT = "kn.etl_reader_campaign.v2"
STUDY_EVALUATION = "kn.etl_reader_campaign_evaluation.v2"
# Reuse the standalone imported-result evaluator's exact JSON and partition rules.
CORPUS = runpy.run_path(str(Path(__file__).with_name("evaluate-corpus.py")))
MAX_CORPUS_B64 = 4 * ((CORPUS["MAX_BYTES"] + 2) // 3)
MAX_STUDY_SNAPSHOT = MAX_SNAPSHOT + MAX_CORPUS_B64
EMPTY_HOLES = sha(b"[]")
MAX_RECEIPT = 2048
ERROR_PREFIX = 256
ACQUISITIONS = ("unadmitted", "unresolved", "unusable_receipts", "published", "pin_mismatch", "os_error", "acquisition_rejected")
EVIDENCE = ("no_publication_receipt", "unusable_receipts", "verified", "missing", "unreadable", "pin_mismatch", "invalid_package", "binding_mismatch")
MAX_ARCHIVE = pair.HEADER.size + pair.MAX_METADATA + pair.MAX_ETL
VERDICTS = ("agreed_observed", "agreed_empty", "count_disagreement", "coverage_limited",
            "traversal_disagreement", "native_family_unavailable", "reader_unavailable", "no_verified_pair")


@cache
def capture_tool():
    return runpy.run_path(str(Path(__file__).with_name("capture-etl-comparison.py")))


@contextmanager
def regular_file(path):
    before = path.lstat()
    check(stat.S_ISREG(before.st_mode), "expected a regular campaign artifact")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        check(os.path.samestat(before, os.fstat(stream.fileno())), "campaign artifact changed at open")
        yield stream


@contextmanager
def directory_files(directory):
    # Keep the Windows directory chain in place and refuse reparse or recall-on-access artifacts.
    if os.name == "nt":
        files = capture_tool()["WindowsFiles"]()
        with ExitStack() as stack:
            files.parents(stack, directory, set())
            yield files.hold
    else:
        check(all(stat.S_ISDIR(p.lstat().st_mode) for p in (directory, *directory.parents)),
              "expected local campaign directories without symbolic links")
        yield regular_file


def read_bounded(stream, limit):
    size = os.fstat(stream.fileno()).st_size
    check(0 < size <= limit, "campaign artifact outside byte bounds")
    data = stream.read(size + 1)
    check(len(data) == size, "campaign artifact size changed during read")
    return data


def strict_object(raw):
    obj = json.loads(raw)
    check(type(obj) is dict and encoded(obj) == raw, "noncanonical campaign record")
    return obj


def whole_file_case(case):
    return (case["layer"], case["task"], case["unit"], case["holes_sha256"]) == (
        "independent_comparison", "saved_etl_descriptor_counts", "case", EMPTY_HOLES)


def select_cases(raw, pin, case_ids):
    check(0 < len(raw) <= CORPUS["MAX_BYTES"] and sha(raw) == pair.digest(pin), "study corpus size or hash mismatch")
    corpus = CORPUS["decode_document"](raw)
    declared = CORPUS["validate_corpus"](corpus)  # Includes cases outside the requested slots.
    chosen = list(declared) if case_ids is None else case_ids
    check(type(chosen) is list and 1 <= len(chosen) <= pair.MAX_REGISTERED_SLOTS, "select 1..32 study case IDs")
    by_source = {}
    eligible = {}
    for key, case in declared.items():
        if not whole_file_case(case):
            continue
        group = (case["family"], case["independence_group"])
        check(by_source.setdefault(case["artifact_sha256"], group) == group,
              "one whole-file ETL has conflicting sample family or independence group")
        eligible[key] = case
    check(all(type(key) is str and key in eligible for key in chosen), "unknown case or incompatible ETL comparison scope")
    return corpus, [eligible[key] for key in chosen]


def load_study(path, pin, ids):
    with directory_files(path.parent) as opened, opened(path) as stream:
        raw = read_bounded(stream, CORPUS["MAX_BYTES"])
    _, selected = select_cases(raw, pin, ids)
    binding = dict(corpus_sha256=pin, case_ids=[c["id"] for c in selected],
                   corpus_base64=base64.b64encode(raw).decode("ascii"))
    return binding, [c["artifact_sha256"] for c in selected]


def unpack_study(binding):
    fields(binding, "corpus_sha256 case_ids corpus_base64", "registered ETL corpus")
    original = binding["corpus_base64"]
    check(type(original) is str and 0 < len(original) <= MAX_CORPUS_B64 and type(binding["case_ids"]) is list,
          "invalid corpus bytes or case selection")
    raw = base64.b64decode(original, validate=True)
    check(base64.b64encode(raw).decode("ascii") == original, "noncanonical corpus encoding")
    return select_cases(raw, binding["corpus_sha256"], binding["case_ids"])


def validate_plan(plan, pin):
    check(type(plan) is dict and plan.get("schema") in (PLAN, STUDY_PLAN), "invalid reader campaign plan")
    bound = plan["schema"] == STUDY_PLAN
    fields(plan, "schema campaign_id sources tickets tools include_disk_io timeout_ms" + (" study" if bound else ""), "reader campaign plan")
    check(sha(encoded(plan)) == pair.digest(pin), "reader campaign plan pin mismatch")
    sources, tickets = plan["sources"], plan["tickets"]
    check(type(sources) is list and 1 <= len(sources) <= pair.MAX_REGISTERED_SLOTS and
          type(tickets) is list and len(tickets) == len(sources), "invalid registered denominator")
    for source in sources:
        pair.digest(source)
    if bound:
        _, selected = unpack_study(plan["study"])
        check(sources == [c["artifact_sha256"] for c in selected], "slot sources differ from the registered study cases")
    ids = [plan["campaign_id"], *tickets]
    check(all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in ids) and len(set(ids)) == len(ids),
          "invalid or repeated plan identities")
    fields(plan["tools"], "native tracerpt", "registered readers")
    for reader_pin in plan["tools"].values():
        pair.digest(reader_pin)
    check(type(plan["include_disk_io"]) is bool and 1 <= uint(plan["timeout_ms"], 600000), "invalid reader scope or deadline")
    return plan


@contextmanager
def held_plan(directory, pin, open_file):
    with open_file(directory / PLAN_FILE) as stream:
        raw = read_bounded(stream, MAX_STUDY_SNAPSHOT)
        check(sha(raw) == pair.digest(pin), "registered plan hash mismatch")
        plan = strict_object(raw)
        check(plan.get("schema") == STUDY_PLAN or len(raw) <= MAX_SNAPSHOT, "unbound plan exceeds size bound")
        yield validate_plan(plan, pin)


def create(directory, sources, native_pin, tracerpt_pin, timeout, include_disk_io, *, study=None):
    check(1 <= len(sources) <= pair.MAX_REGISTERED_SLOTS, "invalid registered denominator")
    plan = dict(schema=PLAN, campaign_id=uuid.uuid4().hex, sources=list(sources),
                tickets=[uuid.uuid4().hex for _ in sources], tools=dict(native=native_pin, tracerpt=tracerpt_pin),
                include_disk_io=include_disk_io, timeout_ms=timeout)
    if study is not None:
        plan.update(schema=STUDY_PLAN, study=study)
    data = encoded(plan)
    pin = sha(data)
    validate_plan(plan, pin)
    with directory_files(directory.parent):
        directory.mkdir()
        created = directory.lstat()
        try:
            with directory_files(directory):
                publish_new(directory / PLAN_FILE, lambda file: file.write(data))
        except (OSError, ValueError):
            with suppress(OSError):
                if os.path.samestat(created, directory.lstat()):
                    directory.rmdir()  # Only the empty directory created for this plan.
            raise
    return dict(schema="kn.etl_reader_plan_receipt.v1", plan_sha256=pin, planned_slots=len(sources))


def receipt_path(directory, ticket, phase):
    return directory / (ticket + "." + phase + ".knruns")


def validate_row(plan, pin, slot, row):
    fields(row, "slot admitted ended", "reader campaign slot")
    check(uint(row["slot"]) == slot, "missing or reordered registered slot")
    admission, end = row["admitted"], row["ended"]
    if admission is None:
        check(end is None, "terminal receipt without admission")
        return "unadmitted"
    fields(admission, "schema registration tick_ns", "reader admission")
    reg = pair.registration(admission["registration"])
    check(admission["schema"] == ADMISSION and reg["plan_sha256"] == pin and reg["slot"] == slot and
          reg["ticket"] == plan["tickets"][slot-1], "foreign reader admission")
    start = decimal(admission["tick_ns"])
    if end is None:
        return "unresolved"
    fields(end, "schema admission_sha256 tick_ns outcome package_sha256 error", "terminal reader receipt")
    check(end["schema"] == OUTCOME and end["admission_sha256"] == sha(encoded(admission)) and
          decimal(end["tick_ns"]) >= start, "terminal receipt conflicts with admission")
    outcome, error = end["outcome"], end["error"]
    if outcome == "published":
        pair.digest(end["package_sha256"])
        check(error is None, "error on published reader pair")
    else:
        check(end["package_sha256"] is None, "unpublished slot claims a package")
        if outcome == "pin_mismatch":
            fields(error, "domain code role expected_sha256 observed_sha256", "admission mismatch")
            check(error["domain"] == "admission" and error["code"] is None and error["role"] in ("etl", *pair.ROLES),
                  "invalid admission mismatch")
            expected = plan["sources"][slot-1] if error["role"] == "etl" else plan["tools"][error["role"]]
            check(error["expected_sha256"] == expected and pair.digest(error["observed_sha256"]) != expected,
                  "mismatched bytes must differ from the registered input")
        elif outcome == "os_error":
            fields(error, "domain code role", "acquisition OS error")
            check(error["domain"] in ("win32", "errno") and error["role"] is None, "invalid OS error")
            if error["code"] is not None:
                check(type(error["code"]) is int and -(1 << 31) <= error["code"] <= 0xffffffff, "invalid original OS code")
        else:
            fields(error, "domain code role diagnostic", "acquisition rejection")
            check(outcome == "acquisition_rejected" and error["domain"] == "validation" and
                  error["code"] is None and error["role"] is None, "invalid acquisition disposition")
            pair.original(error["diagnostic"], ERROR_PREFIX)
    return outcome


def reserve(directory, plan, pin, slot):
    check(1 <= uint(slot, len(plan["tickets"])), "slot outside registered plan")
    reg = dict(plan_sha256=pin, slot=slot, ticket=plan["tickets"][slot-1], admission_id=uuid.uuid4().hex)
    admission = dict(schema=ADMISSION, registration=reg, tick_ns=str(time.perf_counter_ns()))
    validate_row(plan, pin, slot, dict(slot=slot, admitted=admission, ended=None))
    if any(os.path.lexists(path) for path in (receipt_path(directory, reg["ticket"], "ended"), package_path(directory, reg["ticket"]))):
        raise FileExistsError("slot already has a terminal artifact")
    publish_new(receipt_path(directory, reg["ticket"], "admitted"), lambda f: f.write(encoded(admission)))
    return admission


def run_slot(directory, pin, slot, etl, exe):
    check(os.name == "nt", "reader acquisition requires Windows")
    with directory_files(directory) as open_file, held_plan(directory, pin, open_file) as plan, ExitStack() as held:
        admission = reserve(directory, plan, pin, slot)
        reg = admission["registration"]
        admission_stream = held.enter_context(open_file(receipt_path(directory, reg["ticket"], "admitted")))
        check(admission_stream.read(MAX_RECEIPT + 1) == encoded(admission), "slot admission changed before acquisition")
        config = argparse.Namespace(etl=etl, exe=exe, output=package_path(directory, reg["ticket"]),
                                    sha256=plan["sources"][slot-1], exe_sha256=plan["tools"]["native"],
                                    tracerpt_sha256=plan["tools"]["tracerpt"], timeout_ms=plan["timeout_ms"],
                                    include_disk_io=plan["include_disk_io"])
        package = error = None
        try:
            package = capture_tool()["acquire"](config, reg)["package_sha256"]
            state = "published"
        except pair.InputPinMismatch as exc:
            state = "pin_mismatch"
            error = dict(domain="admission", code=None, role=exc.role, expected_sha256=exc.expected, observed_sha256=exc.observed)
        except OSError as exc:
            code = getattr(exc, "winerror", None)
            state = "os_error"
            error = dict(domain="win32" if code is not None else "errno", code=exc.errno if code is None else code, role=None)
        except ValueError as exc:
            diagnostic = pair.record_bytes(io.BytesIO(str(exc).encode("utf-8", errors="backslashreplace")), ERROR_PREFIX)
            state, error = "acquisition_rejected", dict(domain="validation", code=None, role=None, diagnostic=diagnostic)
        end = dict(schema=OUTCOME, admission_sha256=sha(encoded(admission)), tick_ns=str(time.perf_counter_ns()),
                   outcome=state, package_sha256=package, error=error)
        validate_row(plan, pin, slot, dict(slot=slot, admitted=admission, ended=end))
        publish_new(receipt_path(directory, reg["ticket"], "ended"), lambda f: f.write(encoded(end)))
    return dict(schema="kn.etl_reader_slot_receipt.v1", registration=reg, result=end)


def observe_receipt(path, open_file):
    try:
        with open_file(path) as stream:
            size = uint(os.fstat(stream.fileno()).st_size)
            prefix = stream.read(min(size, MAX_RECEIPT))
            check(len(prefix) == min(size, MAX_RECEIPT) and os.fstat(stream.fileno()).st_size == size,
                  "receipt size changed during read")
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        code = getattr(exc, "winerror", None)
        if code is not None:
            return dict(observation="read_error", domain="win32", code=code)
        return dict(observation="read_error", domain="errno" if isinstance(exc, OSError) else "validation",
                    code=getattr(exc, "errno", None))
    # Preserve a bounded prefix, including for an oversized file with no trusted full hash.
    return dict(observation="read", file_bytes=size, prefix_sha256=sha(prefix), prefix=base64.b64encode(prefix).decode("ascii"))


def decode_observation(obs):
    if obs is None:
        return None, True
    check(type(obs) is dict, "invalid receipt observation")
    if obs.get("observation") == "read_error":
        fields(obs, "observation domain code", "receipt read error")
        check(obs["domain"] in ("win32", "errno", "validation") and
              (obs["code"] is None or type(obs["code"]) is int and -(1 << 31) <= obs["code"] <= 0xffffffff)
              and (obs["domain"] != "validation" or obs["code"] is None), "invalid original receipt read error")
        return None, False
    fields(obs, "observation file_bytes prefix_sha256 prefix", "receipt bytes")
    size = uint(obs["file_bytes"])
    length = min(size, MAX_RECEIPT)
    check(obs["observation"] == "read" and type(obs["prefix"]) is str and len(obs["prefix"]) == 4*((length+2)//3),
          "invalid receipt prefix extent")
    try:
        raw = base64.b64decode(obs["prefix"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid receipt prefix encoding") from exc
    check(len(raw) == length and base64.b64encode(raw).decode("ascii") == obs["prefix"] and
          sha(raw) == obs["prefix_sha256"], "receipt prefix identity mismatch")
    if size > length:
        return None, False
    try:
        return strict_object(raw), True
    except (ValueError, RecursionError):
        return None, False


def observed_slot(plan, pin, slot, observations):
    fields(observations, "admitted ended", "original receipt observations")
    admission, admission_ok = decode_observation(observations["admitted"])
    end, end_ok = decode_observation(observations["ended"])
    if admission_ok and end_ok:
        row = dict(slot=slot, admitted=admission, ended=end)
        try:
            validate_row(plan, pin, slot, row)
        except (ValueError, TypeError, RecursionError):
            pass
        else:
            return row
    # A broken terminal receipt does not erase an independently valid admission.
    try:
        validate_row(plan, pin, slot, dict(slot=slot, admitted=admission, ended=None))
    except (ValueError, TypeError, RecursionError):
        admission = None
    return dict(slot=slot, admitted=admission, ended=None, unusable_receipts=observations)


def validate_snapshot(snapshot, pin):
    fields(snapshot, "schema plan plan_sha256 attempts", "reader campaign snapshot")
    plan = validate_plan(snapshot["plan"], pin)
    schema = STUDY_SNAPSHOT if plan["schema"] == STUDY_PLAN else SNAPSHOT
    check(snapshot["schema"] == schema and snapshot["plan_sha256"] == pin, "wrong reader campaign snapshot")
    rows = snapshot["attempts"]
    check(type(rows) is list and len(rows) == len(plan["tickets"]), "snapshot lost a planned slot")
    states = []
    for i, row in enumerate(rows, 1):
        if type(row) is dict and "unusable_receipts" in row:
            fields(row, "slot admitted ended unusable_receipts", "reader slot with receipt gap")
            reproduced = observed_slot(plan, pin, i, row["unusable_receipts"])
            check(uint(row["slot"]) == i and row["ended"] is None and "unusable_receipts" in reproduced and
                  encoded(row["admitted"]) == encoded(reproduced["admitted"]), "unjustified or misplaced receipt gap")
            states.append("unusable_receipts")
        else:
            states.append(validate_row(plan, pin, i, row))
    return plan, states


def freeze(directory, pin, output):
    check(output.parent == directory and output.suffix.lower() == ".knruns", "place a new .knruns snapshot beside its packages")
    with directory_files(directory) as open_file, held_plan(directory, pin, open_file) as plan:
        reserved = {receipt_path(directory, ticket, phase) for ticket in plan["tickets"] for phase in ("admitted", "ended")}
        check(output not in reserved, "snapshot collides with a reserved receipt")
        def collect():
            rows = []
            for i, ticket in enumerate(plan["tickets"], 1):
                # End precedes admission so a newly published end cannot appear without its earlier admission.
                observations = {phase: observe_receipt(receipt_path(directory, ticket, phase), open_file)
                                for phase in ("ended", "admitted")}
                rows.append(observed_slot(plan, pin, i, observations))
            return rows
        # Immutable, create-once receipts can appear at most twice per slot. Identical
        # consecutive scans share a point between scans for all cooperating publishers.
        previous = collect()
        for _ in range(2 * len(previous) + 1):
            current = collect()
            if previous == current:
                break
            previous = current
        else:
            raise ValueError("reader campaign receipts did not stabilize")
        schema = STUDY_SNAPSHOT if plan["schema"] == STUDY_PLAN else SNAPSHOT
        snapshot = dict(schema=schema, plan=plan, plan_sha256=pin, attempts=current)
        validate_snapshot(snapshot, pin)
        raw = encoded(snapshot)
        check(len(raw) <= (MAX_STUDY_SNAPSHOT if schema == STUDY_SNAPSHOT else MAX_SNAPSHOT), "reader snapshot exceeds size bound")
        snapshot_pin = publish_new(output, lambda f: f.write(raw))
    return dict(schema="kn.etl_reader_snapshot_receipt.v1", plan_sha256=pin, snapshot_sha256=snapshot_pin)


def verify_pair(directory, plan, row, decode, ratio, open_file):
    reg = row["admitted"]["registration"]
    expected = row["ended"]["package_sha256"]
    try:
        with open_file(package_path(directory, reg["ticket"])) as stream:
            check(0 < os.fstat(stream.fileno()).st_size <= MAX_ARCHIVE, "package outside byte bound")
            result = pair.replay(stream, expected, decode, ratio)
    except FileNotFoundError:
        return "missing", None
    except PackagePinMismatch:
        return "pin_mismatch", None
    except OSError:
        return "unreadable", None
    except (ValueError, KeyError, IndexError, TypeError, OverflowError, RecursionError):
        return "invalid_package", None
    source = plan["sources"][reg["slot"]-1]
    if (result["schema"] != "kn.etl_reader_evaluation.v3" or result.get("registration") != reg or
            result["source_sha256"] != source or result["config"] != pair.config(source, plan["timeout_ms"], plan["include_disk_io"])):
        return "binding_mismatch", None
    for role, pin in plan["tools"].items():
        read = result["readers"][role]
        if (read["binary"]["before_sha256"] != pin or read["binary"]["expected_sha256"] != pin or
                int(read["started_ns"]) < int(row["admitted"]["tick_ns"]) or int(read["ended_ns"]) > int(row["ended"]["tick_ns"])):
            return "binding_mismatch", None
    return "verified", result


def reader_metrics(rows, registered, ratio):
    acquisitions = Counter(row["acquisition"] for row in rows)
    evidence = Counter(row["evidence"] for row in rows)
    reader_statuses = {role: Counter() for role in pair.ROLES}
    verdicts = {name: Counter() for name in registered}
    observed = 0
    for row in rows:
        result = row["pair"]
        for name, counts in verdicts.items():
            counts[result["families"][name]["verdict"] if result else "no_verified_pair"] += 1
        for role, counts in reader_statuses.items():
            counts[result["readers"][role]["status"] if result else "no_verified_pair"] += 1
        if result:
            observed += result["observed_readers"]
    planned = len(rows)
    families = {}
    for name, counts in verdicts.items():
        agreed = counts["agreed_observed"] + counts["agreed_empty"]
        families[name] = dict(verdicts={k: counts[k] for k in VERDICTS},
                              agreement_per_planned=ratio(agreed, planned),
                              agreement_per_comparable=ratio(agreed, agreed + counts["count_disagreement"]))
    agreed = sum(v["agreement_per_planned"]["numerator"] for v in families.values())
    comparable = sum(v["agreement_per_comparable"]["denominator"] for v in families.values())
    return dict(acquisition_counts={k: acquisitions[k] for k in ACQUISITIONS}, evidence_counts={k: evidence[k] for k in EVIDENCE},
                reader_statuses=reader_statuses, verified_packages_per_published=ratio(evidence["verified"], acquisitions["published"]),
                observed_readers_per_planned=ratio(observed, 2 * planned), families=families,
                agreement_per_planned_family=ratio(agreed, planned * len(families)),
                agreement_per_comparable_family=ratio(agreed, comparable))


def study_panel(rows, registered, ratio):
    return dict(planned_slots=len(rows), slots=[row["slot"] for row in rows],
                distinct_cases=len({row["case_id"] for row in rows}), distinct_source_hashes=len({row["source_sha256"] for row in rows}),
                cross_partition_input_mismatches=sum(row.get("supplied_source_partition") in ("development", "heldout")
                                                     and row["supplied_source_partition"] != row["partition"] for row in rows),
                **reader_metrics(rows, registered, ratio))


def study_partitions(corpus, selected, rows, registered, ratio):
    source_partition = {c["artifact_sha256"]: c["partition"] for c in corpus["cases"]}
    for row, case in zip(rows, selected, strict=True):
        row.update(case_id=case["id"], partition=case["partition"], sample_family=case["family"],
                   independence_group=case["independence_group"])
        if row["acquisition"] == "pin_mismatch" and row["ended"]["error"]["role"] == "etl":
            row["supplied_source_partition"] = source_partition.get(row["ended"]["error"]["observed_sha256"])
    partitions = {}
    for partition in ("development", "heldout"):
        members = [row for row in rows if row["partition"] == partition]
        panel = study_panel(members, registered, ratio)
        roster = [c for c in corpus["cases"] if c["partition"] == partition]
        eligible = [c["id"] for c in roster if whole_file_case(c)]
        chosen = {row["case_id"] for row in members}
        panel["declared_corpus_cases"] = len(roster)
        panel["unselected_corpus_cases"] = len(roster) - len(chosen)
        panel["selected_cases_per_eligible"] = ratio(len(chosen), len(eligible))
        panel["unselected_eligible_case_ids"] = [key for key in eligible if key not in chosen]
        for category in ("sample_family", "independence_group"):
            groups = {}
            for row in members:
                groups.setdefault(row[category], []).append(row)
            panel["by_" + category] = {label: study_panel(group, registered, ratio) for label, group in sorted(groups.items())}
        groups = panel["by_independence_group"].values()
        complete = agreed = 0
        for group in groups:
            tally = group["agreement_per_planned_family"]
            agreed += tally["numerator"] == tally["denominator"]
            complete += group["agreement_per_comparable_family"]["denominator"] == tally["denominator"]
        panel["declared_independence_groups"] = len(groups)
        panel["agreement_per_planned_group"] = ratio(agreed, len(groups))
        panel["agreement_per_comparable_group"] = ratio(agreed, complete)
        partitions[partition] = panel
    return partitions


def evaluate(path, snapshot_pin, plan_pin, decode, ratio, study_pin=None):
    with directory_files(path.parent) as open_file:
        with open_file(path) as stream:
            raw = read_bounded(stream, MAX_STUDY_SNAPSHOT)
        check(sha(raw) == pair.digest(snapshot_pin), "reader campaign snapshot pin mismatch")
        snapshot = decode(raw)
        check(type(snapshot) is dict and (snapshot.get("schema") == STUDY_SNAPSHOT or len(raw) <= MAX_SNAPSHOT),
              "unbound reader snapshot exceeds size bound")
        plan, states = validate_snapshot(snapshot, plan_pin)
        study = plan.get("study")
        if study_pin is not None:
            check(study is not None and study["corpus_sha256"] == pair.digest(study_pin), "unexpected or missing study corpus")
        registered = pair.WITH_DISK_IO if plan["include_disk_io"] else pair.FAMILIES
        rows = []
        for row, state, source in zip(snapshot["attempts"], states, plan["sources"], strict=True):
            result = None
            if state == "published":
                disposition, result = verify_pair(path.parent, plan, row, decode, ratio, open_file)
            else:
                disposition = "unusable_receipts" if state == "unusable_receipts" else "no_publication_receipt"
            summary = dict(slot=row["slot"], admitted=row["admitted"], ended=row["ended"],
                           source_sha256=source, acquisition=state, evidence=disposition, pair=result)
            if state == "unusable_receipts":
                summary["receipt_observations"] = {phase: {k: v for k, v in obs.items() if k != "prefix"} if obs else None
                                                   for phase, obs in row["unusable_receipts"].items()}
            rows.append(summary)
    report = dict(schema=STUDY_EVALUATION if study is not None else EVALUATION, plan_sha256=plan_pin,
                  snapshot_sha256=snapshot_pin, campaign_id=plan["campaign_id"], layer="independent_comparison",
                  unit="registered_file_family", distinct_source_hashes=len(set(plan["sources"])), target_probed=False,
                  independent_detection_validation=False, overall_ranking=None, planned_slots=len(rows), campaign_plan_checked=True)
    if study is None:
        report.update(reader_metrics(rows, registered, ratio))
    else:
        corpus, selected = unpack_study(study)
        report.update(corpus_sha256=study["corpus_sha256"], corpus_id=corpus["corpus_id"], cohort_id=corpus["cohort_id"],
                      declared_environment=corpus["environment"], declared_corpus_cases=len(corpus["cases"]),
                      partition_assignments_authenticated=False, ground_truth_authenticated=False,
                      partitions=study_partitions(corpus, selected, rows, registered, ratio))
    report["attempts"] = rows
    return report


def outputs_safe(args, *, evaluator=False):
    # The ticket files are implicit inputs. A disk-backed diagnostic can alias one even on bad syntax.
    if not pair.outputs_safe(args):
        return False
    if not any(stream is not None and stat.S_ISREG(os.fstat(stream.fileno()).st_mode) for stream in (sys.stdout, sys.stderr)):
        return True
    roots = set()
    for i, arg in enumerate(args):
        option, sep, value = arg.partition("=")
        if evaluator:
            if not option.startswith("--e") or not "--etl-reader-campaign".startswith(option):
                continue
        elif option != "--directory":
            continue
        value = value if sep else args[i+1] if i+1 < len(args) else ""
        if value:
            try:
                path = pair.local_path(value)
            except (OSError, ValueError):
                return False
            roots.add(path.parent if evaluator else path)
    for root in roots:
        try:
            with directory_files(root):
                with os.scandir(root) as children:
                    for entry in children:
                        if entry.name.lower().endswith((".kncampaign", ".knbench", ".knruns")) and not pair.outputs_safe([entry.path]):
                            return False
        except FileNotFoundError:
            continue
        except (ValueError, OSError):
            return False
    return True


def main():
    args = sys.argv[1:]
    if not outputs_safe(args):
        return 2
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="op", required=True)
    init, run, snap = [sub.add_parser(op, allow_abbrev=False) for op in ("create", "run", "snapshot")]
    for cmd in (init, run, snap):
        cmd.add_argument("--directory", required=True)
    roster = init.add_mutually_exclusive_group(required=True)
    roster.add_argument("--source-sha256", action="append")
    roster.add_argument("--study-corpus", help="pinned benchmark corpus for a partitioned ETL evaluation")
    init.add_argument("--study-sha256", help="expected SHA-256 of the exact corpus file")
    init.add_argument("--case-id", action="append", help="case for this slot, repeat in acquisition order (default: all cases)")
    init.add_argument("--exe-sha256", required=True)
    init.add_argument("--tracerpt-sha256", required=True)
    init.add_argument("--include-disk-io", action="store_true")
    init.add_argument("--timeout-ms", type=int, default=240000)
    for cmd in (run, snap):
        cmd.add_argument("--plan-sha256", required=True)
    run.add_argument("--slot", type=int, required=True)
    run.add_argument("--etl", required=True)
    run.add_argument("--exe", required=True)
    snap.add_argument("--out", required=True)
    opt = parser.parse_args(args)
    try:
        directory = pair.local_path(opt.directory)
        if opt.op == "create":
            sources, study = opt.source_sha256, None
            if opt.study_corpus is not None:
                check(opt.study_sha256 is not None, "--study-corpus requires --study-sha256")
                study, sources = load_study(pair.local_path(opt.study_corpus), opt.study_sha256, opt.case_id)
            else:
                check(opt.case_id is None and opt.study_sha256 is None, "case selection and study hash require --study-corpus")
            receipt = create(directory, sources, opt.exe_sha256, opt.tracerpt_sha256, opt.timeout_ms, opt.include_disk_io, study=study)
        elif opt.op == "run":
            receipt = run_slot(directory, opt.plan_sha256, opt.slot, opt.etl, opt.exe)
        else:
            receipt = freeze(directory, opt.plan_sha256, pair.local_path(opt.out))
    except (OSError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        if outputs_safe(args):
            print(f"ETL campaign {opt.op} failed: {exc}", file=sys.stderr)
        return 2
    if not outputs_safe(args) or pair.write_result(encoded(receipt)) != 0:
        return 2
    return int(opt.op == "run" and receipt["result"]["outcome"] != "published")


if __name__ == "__main__":
    raise SystemExit(main())
