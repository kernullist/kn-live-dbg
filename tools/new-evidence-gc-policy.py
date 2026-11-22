"""Prepare a private collection retirement or file GC policy from a stopped-store inventory."""
import argparse
import json
import os
from pathlib import Path
import re


def collection(snapshot, identifier):
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", identifier):
        raise ValueError("invalid collection ID")
    roots = [row for row in snapshot["collections"] if row["id"] == identifier]
    if len(roots) != 1 or roots[0]["closed"] is not True:
        raise ValueError("a single closed collection is required")
    return roots[0]


def file_policy(args, snapshot):
    if (snapshot["artifacts_included"] is not True or not 0 < args.byte_limit <= 128 * 1024 * 1024 or
            not 0 < len(args.paths) <= 128 or len(set(args.paths)) != len(args.paths)):
        raise ValueError("invalid file selection")
    if args.from_retired_collection is None:
        policy = {"schema": "kn.evidence_gc_policy.v1", "policy": "kn.gc_explicit_uncommitted.v1"}
        retention = "uncommitted_requires_policy"
    else:
        root = collection(snapshot, args.from_retired_collection)
        if root["status"] != "retired" or not re.fullmatch("[0-9a-f]{64}", root["retirement_sha256"]):
            raise ValueError("verified retirement receipt required")
        policy = {"schema": "kn.evidence_gc_policy.v2", "policy": "kn.gc_explicit_retired.v1",
                  "retired_collection_id": root["id"], "retirement_sha256": root["retirement_sha256"]}
        retention = "retired_requires_policy"
    selected = []
    for path in sorted(args.paths):
        found = [row for row in snapshot["artifacts"] if row["artifact"]["path"] == path]
        if (len(found) != 1 or found[0]["verified"] is not True or found[0]["retention"] != retention or
                found[0]["collections"] or found[0]["journal_references"] != "0" or
                (args.from_retired_collection is not None and (found[0]["retired_original_matched"] is not True or
                 args.from_retired_collection not in found[0]["retired_collections"]))):
            raise ValueError("selected path is absent, duplicated, omitted or protected")
        member = found[0]["artifact"]
        if (any(not isinstance(member[key], str) for key in ("path", "sha256", "bytes", "schema")) or
                not member["bytes"].isascii() or not member["bytes"].isdigit() or
                not 0 < int(member["bytes"]) <= 64 * 1024 * 1024 or str(int(member["bytes"])) != member["bytes"]):
            raise ValueError("malformed inventory member")
        selected.append({key: member[key] for key in ("path", "sha256", "bytes", "schema")})
    if sum(int(member["bytes"]) for member in selected) > args.byte_limit:
        raise ValueError("selected files exceed the byte limit")
    return dict(policy, reason=args.reason, minimum_age_seconds=str(args.minimum_age_seconds),
                byte_limit=str(args.byte_limit), members=selected)


def count(row, field):
    value = row[field]
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value) or int(value) > 2**64 - 1:
        raise ValueError("invalid inventory counter")
    return int(value)


def routine_candidate(snapshot, target, age, cap):
    report = snapshot["collection_retention"]
    if (report["schema"] != "kn.evidence_collection_retention.v1" or report["status"] != "verified" or
            not 0 <= target <= 8 * 1024**3 or not 0 <= cap <= 1024**3 or
            any(not re.fullmatch("[0-9a-f]{64}", snapshot[key]) for key in ("catalog_sha256", "artifacts_sha256"))):
        raise ValueError("a verified store retention report is required")
    lanes = [row for row in report["classes"] if row["class"] == "routine_only"]
    if len(lanes) != 1 or count(lanes[0], "named_bytes") <= target:
        raise ValueError("routine bytes are within target or unknown")
    observed = count(report, "observed_filetime")
    eligible = []
    seen = set()
    for row in report["roots"]:
        identifier = row["collection_id"]
        if not re.fullmatch(r"0|[1-9][0-9]{0,19}", identifier) or identifier in seen:
            raise ValueError("invalid or duplicated budget owner")
        seen.add(identifier)
        written = count(row, "closure_last_write_filetime")
        if (row["class"] == "routine_only" and 0 < count(row, "exclusive_routine_bytes") <= cap and
                0 < written <= observed and (observed - written) // 10_000_000 >= age):
            eligible.append((written, int(identifier), identifier))
    if not eligible:
        raise ValueError("no eligible routine collection")
    return min(eligible)[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--path", action="append", dest="paths")
    selection.add_argument("--retire-collection", metavar="ID")
    selection.add_argument("--retire-excess-routine", metavar="TARGET_BYTES", type=int,
                           help="select one closed routine collection when its store-wide byte budget is exceeded")
    parser.add_argument("--from-retired-collection", metavar="ID", help="bind selected file paths to this collection's retirement receipt")
    parser.add_argument("--reason", required=True)
    parser.add_argument("--minimum-age-seconds", type=int, default=86400)
    parser.add_argument("--byte-limit", type=int, default=128 * 1024 * 1024)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.inventory.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("inventory too large")
        snapshot = json.loads(args.inventory.read_text(encoding="utf-8-sig"))
        if (snapshot["schema"] != "kn.evidence_store_inventory.v1" or snapshot["status"] != "verified" or
                snapshot["scope"] not in ("image_collection_namespace", "image_and_irp_collection_namespace") or snapshot["catalog_complete"] is not True or
                snapshot.get("artifact_page_status", "complete") not in ("not_requested", "complete", "more") or
                snapshot["membership_complete"] is not True or snapshot["artifact_inventory_complete"] is not True):
            raise ValueError("a complete store inventory is required")
        if (not args.reason or "\0" in args.reason or len(args.reason.encode("utf-16-le")) > 1024 or
                not 0 <= args.minimum_age_seconds <= 10 * 366 * 86400):
            raise ValueError("invalid explicit policy bounds")
        budget = args.retire_excess_routine
        if args.retire_collection is None and budget is None:
            policy = file_policy(args, snapshot)
        else:
            identifier = args.retire_collection if budget is None else routine_candidate(snapshot, budget, args.minimum_age_seconds, args.byte_limit)
            root = collection(snapshot, identifier)
            if (args.from_retired_collection is not None or root["status"] != "verified_prefix" or not 0 <= args.byte_limit <= 1024**3 or
                    any(not re.fullmatch("[0-9a-f]{64}", root[key]) for key in ("session_sha256", "head_sha256"))):
                raise ValueError("invalid retirement selection")
            policy = dict(schema="kn.evidence_retirement_policy.v1", collection_id=root["id"], session_sha256=root["session_sha256"],
                          head_sha256=root["head_sha256"], reason=args.reason, minimum_age_seconds=str(args.minimum_age_seconds),
                          exclusive_byte_limit=str(args.byte_limit))
            if budget is not None:
                policy.update(schema="kn.evidence_retirement_policy.v2", policy="kn.retire_routine_excess.v1",
                              routine_named_byte_target=str(budget), catalog_sha256=snapshot["catalog_sha256"],
                              artifacts_sha256=snapshot["artifacts_sha256"])
        raw = json.dumps(policy, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > 128 * 1024:
            raise ValueError("policy too large")
        # Create-new only. An interrupted partial file is rejected by the collector;
        # it cannot authorize any deletion and is never silently overwritten here.
        with args.output.open("xb") as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        print("Policy creation failed (" + type(error).__name__ + "); no deletion was requested.")
        return 1
    command = "gc" if args.paths else "retire-collection"
    print(f"Private policy created. Preflight it with --offline !kmon {command}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
