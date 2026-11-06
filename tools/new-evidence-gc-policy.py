"""Create an explicit private GC policy from selected inventory rows; never delete files."""
import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--path", action="append", required=True, dest="paths")
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
                snapshot["scope"] != "image_collection_namespace" or snapshot["catalog_complete"] is not True or
                snapshot["membership_complete"] is not True or snapshot["artifact_inventory_complete"] is not True or
                snapshot["artifacts_included"] is not True):
            raise ValueError("a complete store inventory with artifact detail is required")
        if (not args.reason or "\0" in args.reason or len(args.reason.encode("utf-16-le")) > 1024 or
                not 0 <= args.minimum_age_seconds <= 10 * 366 * 86400 or not 0 < args.byte_limit <= 128 * 1024 * 1024 or
                not 0 < len(args.paths) <= 128 or len(set(args.paths)) != len(args.paths)):
            raise ValueError("invalid explicit policy bounds")
        selected = []
        for path in sorted(args.paths):
            found = [row for row in snapshot["artifacts"] if row["artifact"]["path"] == path]
            if (len(found) != 1 or found[0]["verified"] is not True or found[0]["retention"] != "uncommitted_requires_policy" or
                    found[0]["collections"] or found[0]["journal_references"] != "0"):
                raise ValueError("selected path is absent, duplicated, omitted or protected")
            member = found[0]["artifact"]
            if (any(not isinstance(member[key], str) for key in ("path", "sha256", "bytes", "schema")) or
                    not member["bytes"].isascii() or not member["bytes"].isdigit() or
                    not 0 < int(member["bytes"]) <= 64 * 1024 * 1024 or str(int(member["bytes"])) != member["bytes"]):
                raise ValueError("malformed inventory member")
            selected.append({key: member[key] for key in ("path", "sha256", "bytes", "schema")})
        if sum(int(member["bytes"]) for member in selected) > args.byte_limit:
            raise ValueError("selected files exceed the byte limit")
        policy = {"schema": "kn.evidence_gc_policy.v1", "policy": "kn.gc_explicit_uncommitted.v1", "reason": args.reason,
                  "minimum_age_seconds": str(args.minimum_age_seconds), "byte_limit": str(args.byte_limit), "members": selected}
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
    print("Private policy created. Review it, then preflight with --offline !kmon gc; the inventory grants no deletion authority.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
