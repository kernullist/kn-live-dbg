"""Exercise the public offline entry point using owned evidence-harness outputs."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--live-directory", type=Path)
    parser.add_argument("--require-symlink", action="store_true")
    args = parser.parse_args()
    checks = 0
    skipped = 0

    def check(ok, message):
        nonlocal checks
        if not ok:
            raise AssertionError(message)
        checks += 1

    def run(words, expected=None, structured=False):
        result = subprocess.run(
            [str(args.executable.resolve()), "--offline", *map(str, words)],
            capture_output=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        check(result.returncode == expected if expected is not None else result.returncode in (0, 1),
              "offline command exit status")
        check(b"preflight checks" not in result.stdout and b"must run elevated" not in result.stderr,
              "offline entry must precede live startup")
        if structured:
            check(not result.stderr, "structured command must not emit diagnostics on success")
            document = json.loads(result.stdout.decode("utf-8-sig"))
            if document.get("schema") == "kmon.evidence_replay.v1":
                check(result.returncode == (1 if document["gaps"] else 0), "replay exit status reflects reported gaps")
            return document
        return result

    def query(directory, *options, expected=None):
        return run(["!kmon", "evidence", directory, *options, "/json"], expected, True)

    restart = args.fixtures / "restart.kncase"
    replay = run(["!kmon", "replay", restart, "/json"], 0, True)
    why = run(["!kmon", "why", restart, "/json"], 0, True)
    check(replay == why and replay["status"] == "replayed_declared_scope" and
          replay["slot"] == "points_to_recorded_root", "replay and why reconstruct the saved owned reference")
    check(not replay["execution_observed"] and not replay["image_verification_replayed"] and
          not replay["collector_authenticated"] and replay["unfulfilled_requirements"],
          "offline interpretation must preserve claim boundaries")
    inventory = args.fixtures / "inventory"
    first = query(inventory, expected=1)
    check(first["status"] == "partial_inventory" and first["matched"] == 300 and first["returned"] == 256 and
          first["invalid_files"] == 1 and first["duplicate_files"] == 1 and
          not first["publication_closure_known"], "invalid and duplicate files remain visible")
    tail = query(inventory, "/cursor", first["next_cursor"], expected=1)
    check(tail["returned"] == 44 and tail["page_offset"] == 256 and tail["next_cursor"] is None,
          "new process can continue the retained historical inventory")
    selected = query(inventory, "/pid", "1299", "/role", "tls_callback", expected=1)
    check(selected["matched"] == selected["returned"] == 1 and
          selected["cases"][0]["receipt"]["reference"]["pid"] == 1299,
          "filter precedes the global result limit")
    wrong_scope = query(inventory, "/pid", "1299", "/cursor", first["next_cursor"], expected=1)
    check(wrong_scope["status"] == "invalid_cursor" and wrong_scope["matched"] is None,
          "scope mismatch is not an empty successful query")
    absent = query(args.fixtures / "absent", expected=1)
    check(absent["status"] == "unavailable" and absent["matched"] is None, "missing inventory remains unavailable")
    missing = query(args.fixtures / "closed", expected=1)
    check(missing["unavailable_written_bundles"] == 1 and not missing["publication_closure_known"],
          "closed ledger detects an unavailable publication")
    empty = query(args.fixtures / "empty", expected=0)
    check(empty["matched"] == 0 and not empty["publication_closure_known"], "empty inventory has unknown closure")
    run(["!kmon", "replay", args.fixtures / "truncated.kncase", "/json"], 1)
    for words in ([], ["!kmon", "start"], ["write", "on"], ["!kmon", "why"],
                  ["!kmon", "evidence", inventory, "/limit", "0"]):
        check(b"usage" in run(words, 2).stderr, "unsupported offline command is rejected before live startup")

    # The file itself must be opened without following a reparse point. A path
    # attribute check alone leaves a substitution window before CreateFile.
    with tempfile.TemporaryDirectory(prefix="kmon-evidence-link-") as folder:
        check(Path(folder).resolve().parent == Path(tempfile.gettempdir()).resolve(), "cleanup remains in the owned temporary directory")
        link = Path(folder) / "alias.kncase"
        try:
            os.symlink(restart.resolve(), link)
        except OSError as error:
            if args.require_symlink or getattr(error, "winerror", None) != 1314:
                raise
            skipped += 1
        else:
            run(["!kmon", "replay", link, "/json"], 1)
            linked = query(folder, expected=1)
            check(linked["invalid_files"] == 1 and linked["matched"] == 0, "reparse file is not imported")

    live_replayed = 0
    live_partial = 0
    if args.live_directory:
        retained = query(args.live_directory, expected=0)
        check(retained["inventory_complete"] and retained["publication_closure_known"] and
              retained["matched"] > 0 and retained["unavailable_written_bundles"] == 0,
              "live publications reconcile after monitor exit")
        check(sum(int(s["written"]) for s in retained["sessions"]) == retained["matched"],
              "live closure counts match distinct recovered bundles")
        check(retained["next_cursor"] is None, "live verification must visit the whole selected inventory")
        for row in retained["cases"]:
            check(Path(row["file"]).name == row["file"], "inventory emits filenames only")
            result = run(["!kmon", "replay", args.live_directory / row["file"], "/json"], structured=True)
            check(result["evidence_id"] == row["evidence_id"] and result["original_receipt"] == row["receipt"],
                  "fresh offline replay preserves the original live receipt")
            check(not result["execution_observed"] and not result["actor_attributed"] and
                  not result["image_verification_replayed"], "live replay does not promote a stored classification")
            if result["status"] == "partial":
                check(bool(result["gaps"]), "partial replay names its missing evidence")
                live_partial += 1
            else:
                check(result["status"] == "replayed_declared_scope" and not result["gaps"], "replayed scope has no hidden gaps")
                live_replayed += 1
    print(json.dumps({"checks_passed": checks, "symlink_checks_skipped": skipped,
                      "live_replayed": live_replayed, "live_partial": live_partial}))


if __name__ == "__main__":
    main()
