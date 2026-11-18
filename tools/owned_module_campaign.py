"""Pre-register owned workload attempts and freeze their acquisition receipts."""
import argparse
from contextlib import closing, contextmanager
import json
from pathlib import Path
import re
import sqlite3
import sys
import uuid

from owned_module_benchmark import LIMITS, check, decimal, encoded, fields, identity, publish_new, sha, uint


DATABASE = "attempts.kncampaign"
APPLICATION_ID = 0x4B4E4D43
MAX_SLOTS = 32
MAX_SNAPSHOT = 256 * 1024
IMAGES = ("collector.bin", "target.bin", "controller.py")
INPUT_LIMITS = {**{k: LIMITS[k] for k in IMAGES}, "campaign.py": LIMITS["controller.py"], "format.py": LIMITS["controller.py"]}
RECEIPT = "kn.owned_module_attempt_receipt.v1"
COUNTERS = ("user_100ns", "kernel_100ns", "read_bytes", "written_bytes", "other_bytes",
            "read_operations", "write_operations", "other_operations")
OUTCOMES = ("published", "input_unavailable", "input_mismatch", "startup_error", "worker_error", "protocol_error",
            "timed_out", "invalid_package", "interrupted", "supervisor_error")


def digest(value):
    check(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA-256")
    return value


def content_pin(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return sha((raw + "\n").encode("ascii"))


def validate_plan(plan, pin):
    fields(plan, "schema campaign_id tickets timeout_ms inputs", "campaign plan")
    check(plan["schema"] == "kn.owned_module_plan.v1" and content_pin(plan) == digest(pin), "campaign plan pin mismatch")
    tickets = plan["tickets"]
    check(type(tickets) is list and 1 <= len(tickets) <= MAX_SLOTS, "invalid planned denominator")
    ids = [plan["campaign_id"], *tickets]
    check(all(type(x) is str and re.fullmatch(r"[0-9a-f]{32}", x) for x in ids) and len(ids) == len(set(ids)),
          "invalid or repeated campaign identity")
    check(1 <= uint(plan["timeout_ms"], 3600000), "invalid acquisition deadline")
    fields(plan["inputs"], " ".join(INPUT_LIMITS), "pinned acquisition inputs")
    for value in plan["inputs"].values():
        digest(value)
    return plan


def input_hash(stream, name):
    data = stream.read(INPUT_LIMITS[name] + 1)
    check(0 < len(data) <= INPUT_LIMITS[name], "input outside acquisition size bounds")
    return sha(data)


def input_paths(exe):
    here = Path(__file__).resolve().parent
    return {"collector.bin": exe, "target.bin": Path(sys.executable), "controller.py": here / "test-user-module-workload.py",
            "campaign.py": here / "owned_module_campaign.py", "format.py": here / "owned_module_benchmark.py"}


def package_path(directory, ticket):
    check(type(ticket) is str and re.fullmatch("[0-9a-f]{32}", ticket), "invalid package ticket")
    return directory / (ticket + ".knbench")


@contextmanager
def database(directory, mode):
    uri = (directory / DATABASE).resolve().as_uri() + "?mode=" + mode
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as db:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_SNAPSHOT)
        db.execute("PRAGMA trusted_schema=OFF")
        if mode != "ro":
            db.execute("PRAGMA synchronous=FULL")
        with db:
            yield db


def create(directory, exe, count, timeout):
    check(1 <= uint(count, MAX_SLOTS) and 1 <= uint(timeout, 3600000), "invalid campaign size or deadline")
    inputs = {}
    for name, path in input_paths(exe).items():
        with path.open("rb") as stream:
            inputs[name] = input_hash(stream, name)
    plan = dict(schema="kn.owned_module_plan.v1", campaign_id=uuid.uuid4().hex, timeout_ms=timeout,
                inputs=inputs, tickets=[uuid.uuid4().hex for _ in range(count)])
    pin = content_pin(plan)
    validate_plan(plan, pin)
    directory.mkdir()
    (directory / DATABASE).touch(exist_ok=False)
    with database(directory, "rw") as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(f"PRAGMA application_id={APPLICATION_ID}")
        db.execute("CREATE TABLE plan (id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL)")
        db.execute("CREATE TABLE slots (slot INTEGER PRIMARY KEY, admitted BLOB, bound BLOB, ended BLOB, loss BLOB)")
        db.execute("INSERT INTO plan VALUES (1, ?)", (encoded(plan),))
        db.executemany("INSERT INTO slots(slot) VALUES (?)", [(i,) for i in range(1, count + 1)])
    return pin


def read_plan(db, pin):
    check(db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID, "unknown campaign database")
    row = db.execute("SELECT value FROM plan WHERE id=1").fetchone()
    check(row is not None and type(row[0]) is bytes, "missing registered plan")
    plan = json.loads(row[0])
    check(encoded(plan) == row[0], "noncanonical registered plan")
    return validate_plan(plan, pin)


def admit(directory, pin, slot, admission):
    with database(directory, "rw") as db:
        db.execute("BEGIN IMMEDIATE")
        plan = read_plan(db, pin)
        check(1 <= uint(slot, len(plan["tickets"])), "slot outside registered plan")
        claim = dict(schema=RECEIPT, **admission, slot=slot, ticket=plan["tickets"][slot - 1], plan_sha256=pin)
        inspect_attempt(dict(slot=slot, ticket=claim["ticket"], admitted=claim, bound=None, ended=None, loss=None),
                        plan["timeout_ms"], pin)
        changed = db.execute("UPDATE slots SET admitted=? WHERE slot=? AND admitted IS NULL AND bound IS NULL AND ended IS NULL AND loss IS NULL",
                             (encoded(claim), slot))
        check(changed.rowcount == 1, "slot already admitted or missing")
    return plan, claim


def record(directory, pin, slot, admission, phase, event, bound=None):
    with database(directory, "rw") as db:
        db.execute("BEGIN IMMEDIATE")
        plan = read_plan(db, pin)
        if phase == "bound":
            column = "bound"
        else:
            check(phase in ("ended", "loss"), "unknown campaign transition")
            column = phase
        check(phase != "bound" or bound is None, "duplicate job assignment")
        receipt = dict(schema=RECEIPT, **event, previous_sha256=content_pin(bound if bound is not None else admission))
        check(1 <= uint(slot, len(plan["tickets"])), "slot outside registered plan")
        row = dict(slot=slot, ticket=plan["tickets"][slot - 1], admitted=admission, bound=bound, ended=None, loss=None)
        row[column] = receipt
        inspect_attempt(row, plan["timeout_ms"], pin)
        query = f"UPDATE slots SET {column}=? WHERE slot=? AND admitted=? AND bound IS ? AND ended IS NULL AND loss IS NULL"
        changed = db.execute(query, (encoded(receipt), slot, encoded(admission), None if bound is None else encoded(bound)))
        if phase == "loss" and changed.rowcount == 0:
            return None  # The supervisor or another observer already recorded a terminal result.
        check(changed.rowcount == 1, "campaign transition conflict")
        return receipt


def check_worker_failure(failure, ticket):
    fields(failure, "schema ticket phase domain code", "worker failure")
    check(failure["schema"] == "kn.owned_module_worker_failure.v1" and failure["ticket"] == ticket and
          failure["phase"] in ("inputs", "fixed", "changing", "interruption", "publication"), "wrong worker failure boundary")
    domain = failure["domain"]
    check(domain in ("win32", "errno", "os", "assertion", "timeout", "invalid_data", "runtime"), "unknown worker error domain")
    if domain in ("win32", "errno"):
        uint(failure["code"], 0xffffffff)
    else:
        check(failure["code"] is None, "invented worker error code")


def inspect_attempt(row, timeout, pin):
    fields(row, "slot ticket admitted bound ended loss", "attempt")
    admitted, bound, end = row["admitted"], row["bound"], row["ended"]
    if admitted is None:
        check(bound is None and end is None and row["loss"] is None, "evidence without admission")
        return "unadmitted"
    fields(admitted, "schema supervisor tick_ms slot ticket plan_sha256", "admission")
    check(admitted["schema"] == RECEIPT and uint(admitted["slot"]) == row["slot"] and
          admitted["ticket"] == row["ticket"] and admitted["plan_sha256"] == pin,
          "admission belongs to a different campaign or slot")
    supervisor = identity(admitted["supervisor"])
    last = uint(admitted["tick_ms"])
    if bound is not None:
        fields(bound, "schema worker tick_ms previous_sha256", "job assignment")
        check(bound["schema"] == RECEIPT and bound["previous_sha256"] == content_pin(admitted), "job assignment refers to another admission")
        check(identity(bound["worker"])[0] != supervisor[0] and uint(bound["tick_ms"]) >= last, "invalid job assignment")
        last = bound["tick_ms"]
    loss = row["loss"]
    if loss is not None:
        check(bound is not None and end is None, "conflicting owner-loss receipt")
        fields(loss, "schema observer before_ms after_ms supervisor worker previous_sha256", "owner-loss observation")
        check(loss["schema"] == RECEIPT and loss["previous_sha256"] == content_pin(bound) and last <= uint(loss["before_ms"]) <= uint(loss["after_ms"]),
              "owner-loss witness binding or clock mismatch")
        observer = identity(loss["observer"])
        for name, expected in (("supervisor", admitted["supervisor"]), ("worker", bound["worker"])):
            peer = loss[name]
            fields(peer, "key before after exit_code", "pinned peer")
            check(identity(peer["key"]) == identity(expected) and observer[0] != expected[0] and
                  uint(peer["before"]) == 258 and uint(peer["after"]) == 0, "owner-loss witness did not observe the pinned transition")
            uint(peer["exit_code"], 0xffffffff)
        return "owner_lost"
    if end is None:
        return "unresolved"
    fields(end, "schema outcome tick_ms worker_exit worker_failure package_sha256 error_code job accounting_error forced_cleanup previous_sha256", "terminal receipt")
    check(end["schema"] == RECEIPT and end["previous_sha256"] == content_pin(bound if bound is not None else admitted),
          "terminal receipt refers to another attempt")
    check(type(end["forced_cleanup"]) is bool and (bound is not None or not end["forced_cleanup"]), "invalid job cleanup disposition")
    check(uint(end["tick_ms"]) >= last and end["outcome"] in OUTCOMES, "invalid terminal boundary")
    for field in ("worker_exit", "error_code", "accounting_error"):
        if end[field] is not None:
            uint(end[field], 0xffffffff)
    outcome, job = end["outcome"], end["job"]
    if end["worker_failure"] is not None:
        check(bound is not None and outcome == "worker_error" and end["worker_exit"] == 3, "worker diagnostic conflicts with its exit")
        check_worker_failure(end["worker_failure"], row["ticket"])
    if bound is None:
        check(outcome in ("input_unavailable", "input_mismatch", "startup_error", "interrupted", "supervisor_error")
              and job is None and end["accounting_error"] is None and end["worker_exit"] is None, "invalid pre-dispatch outcome")
    else:
        check(outcome not in ("input_unavailable", "input_mismatch", "startup_error"), "startup result after job assignment")
        check((job is None) == (end["accounting_error"] is not None), "missing job accounting disposition")
    if job is not None:
        fields(job, "total active peak_job_bytes peak_error " + " ".join(COUNTERS), "job accounting")
        check(0 < uint(job["total"], 0xffffffff), "empty assigned job count")
        uint(job["active"], job["total"])
        for k in COUNTERS:
            decimal(job[k])
        check((job["peak_job_bytes"] is None) == (job["peak_error"] is not None), "missing peak memory disposition")
        if job["peak_error"] is None:
            decimal(job["peak_job_bytes"])
        else:
            uint(job["peak_error"], 0xffffffff)
    if outcome == "published":
        check(bound is not None and end["worker_exit"] in (0, 1), "invalid package publication")
        digest(end["package_sha256"])
    else:
        check(end["package_sha256"] is None, "unacknowledged package cannot be credited")
    if outcome == "timed_out":
        check(end["tick_ms"] - last >= timeout, "timeout precedes registered deadline")
    return outcome


def passed(end):
    return (end is not None and end["outcome"] == "published" and end["worker_exit"] == 0 and
            end["error_code"] is None and end["job"] is not None and end["job"]["active"] == 0 and not end["forced_cleanup"])


def validate_snapshot(snapshot, pin):
    fields(snapshot, "schema plan plan_sha256 attempts", "campaign snapshot")
    check(snapshot["schema"] == "kn.owned_module_campaign.v1" and snapshot["plan_sha256"] == pin, "wrong campaign snapshot")
    plan = validate_plan(snapshot["plan"], pin)
    rows = snapshot["attempts"]
    check(type(rows) is list and len(rows) == len(plan["tickets"]), "snapshot lost planned attempts")
    workers = set()
    validated = []
    for slot, (ticket, row) in enumerate(zip(plan["tickets"], rows), 1):
        check(type(row) is dict and uint(row.get("slot")) == slot and row.get("ticket") == ticket, "attempt slot or ticket mismatch")
        validated.append((row, inspect_attempt(row, plan["timeout_ms"], pin)))
        if row["bound"] is not None:
            key = identity(row["bound"]["worker"])
            check(key not in workers, "worker generation reused between attempts")
            workers.add(key)
    return plan, validated


def snapshot_transaction(directory, pin, mode):
    with database(directory, mode) as db:
        db.execute("BEGIN")
        plan = read_plan(db, pin)
        records = db.execute("SELECT slot,admitted,bound,ended,loss FROM slots ORDER BY slot LIMIT ?", (MAX_SLOTS + 1,)).fetchall()
        check(len(records) == len(plan["tickets"]), "registry lost planned attempts")
        rows = []
        for ticket, (slot, *events) in zip(plan["tickets"], records):
            row = dict(slot=slot, ticket=ticket)
            for name, raw in zip(("admitted", "bound", "ended", "loss"), events):
                row[name] = None if raw is None else json.loads(raw)
                check(raw is None or encoded(row[name]) == raw, "noncanonical attempt receipt")
            rows.append(row)
    snapshot = dict(schema="kn.owned_module_campaign.v1", plan=plan, plan_sha256=pin, attempts=rows)
    validate_snapshot(snapshot, pin)
    return snapshot


def current_snapshot(directory, pin):
    try:
        return snapshot_transaction(directory, pin, "ro")
    except sqlite3.OperationalError as exc:
        if getattr(exc, "sqlite_errorcode", 0) & 0xff != sqlite3.SQLITE_READONLY:
            raise
        # SQLite needs write access to roll back a hot journal left by a dead writer.
        return snapshot_transaction(directory, pin, "rw")


def freeze(directory, pin, output):
    check(output.parent.resolve() == directory.resolve() and output.suffix.lower() == ".knruns",
          "place a new .knruns snapshot beside its packages")
    data = encoded(current_snapshot(directory, pin))
    check(len(data) <= MAX_SNAPSHOT, "campaign snapshot exceeds size bound")
    return publish_new(output, lambda out: out.write(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="op", required=True)
    init = sub.add_parser("create")
    init.add_argument("--directory", required=True, type=Path)
    init.add_argument("--core-exe", required=True, type=Path)
    init.add_argument("--attempts", required=True, type=int)
    init.add_argument("--timeout-ms", type=int, default=180000)
    snapshot = sub.add_parser("snapshot")
    snapshot.add_argument("--directory", required=True, type=Path)
    snapshot.add_argument("--plan-sha256", required=True)
    snapshot.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.op == "create":
            result = {"plan_sha256": create(args.directory, args.core_exe, args.attempts, args.timeout_ms)}
        else:
            result = {"snapshot_sha256": freeze(args.directory, args.plan_sha256, args.out)}
    except (OSError, ValueError, TypeError, sqlite3.Error, RecursionError) as exc:
        print(f"campaign {args.op} failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
