"""Replay process handle outcomes and link successful captures to an owned Windows image."""
import argparse
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import runpy
import shutil
import subprocess
import sys
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--root", type=Path, help="retain the trial in a new private store")
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    checks = 0

    def check(ok, reason):
        nonlocal checks
        assert ok, reason
        checks += 1

    def command(arguments, code=0):
        with subprocess.Popen([str(exe), *map(str, arguments)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            try:
                collector = birth(kernel, int(p._handle)) if arguments[0] == "--verify-process-image" else None
                out, err = p.communicate(timeout=60)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=10)
            check(p.returncode == code, (arguments[0], p.returncode, code, out[-300:], err[-160:]))
            if collector is not None:
                query = json.loads(out)["source_initialization"]["collector_identity_query"]
                if query is not None:
                    check((int(query["pid"]), int(query["creation_filetime"]), int(query["win32_status"])) ==
                          (p.pid, collector, 0), "parent verified the collector generation on its launch handle")
            return out

    offline = ["--offline", "!kmon"]
    loader = Path(__file__).with_name("test-image-loader-window.py")
    birth = runpy.run_path(str(loader))["process_birth"]
    access = runpy.run_path(str(Path(__file__).with_name("test-process-handle-observer.py")))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    def launch(script_args):
        return subprocess.Popen([sys.executable, "-B", *map(str, script_args)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=subprocess.CREATE_NO_WINDOW)

    def ready(p):
        lines = queue.Queue()
        threading.Thread(target=lambda: lines.put(p.stdout.readline()), daemon=True).start()
        who = json.loads(lines.get(timeout=25))
        check(who["pid"] == p.pid and p.poll() is None, "owned target reported ready")
        return who

    def release(p):
        out, err = p.communicate(b"release\n", timeout=20)
        check(p.returncode == 0 and not out and not err, "owned target exited")

    def cleanup(p):
        if p.poll() is None:
            p.kill()
            p.wait(timeout=10)
        for pipe in (p.stdin, p.stdout, p.stderr):
            pipe.close()

    with tempfile.TemporaryDirectory(prefix="image-source-") as temporary:
        root = args.root.resolve() if args.root else Path(temporary) / "private"
        check(not root.exists(), "trial requires a new store")
        check(json.loads(command([*offline, "init-store", root, "/acl-only", "/json"]))["root_acl_verified"], "private trial")
        reference = root / "owned-version.dll"
        shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32/version.dll", reference)
        pages = {}

        def retain(name, data):
            path = root / (name + ".json")
            with path.open("xb") as f:
                f.write(data)
            pages[name] = (path, hashlib.sha256(data).hexdigest())
            return json.loads(data)

        target = launch([loader, "--child", reference])
        try:
            actor = ready(target)
            created = birth(kernel, int(target._handle))
            check(created == actor["birth"], "parent and target independently matched the process creation time")

            def acquire(name, pid, generation, image, code, state):
                case = root / name
                out = retain(name, command(["--verify-process-image", pid, generation, image, hex(actor["base"]),
                                            hex(actor["rva"]), 64, case, "--allow-residency"], code))
                receipt = out["source_initialization"]
                rows = receipt["handle_actions"]
                check(receipt["schema"] == "kn.process_image_source.v1" and receipt["status"] == state, name)
                check((int(receipt["requested_pid"]), int(receipt["requested_creation_filetime"])) == (pid, generation),
                      "request identity preserved")
                check([int(r["sequence"]) for r in rows] == list(range(1, 1 + len(rows))) and
                      int(rows[0]["requested_access"]) == 0x410 and int(rows[0]["win32_status"]) == out["open_status"],
                      "actual Win32 read/query access, order and result")
                check(all(int(r["requested_filetime"]) and int(r["returned_filetime"]) for r in rows), "original call times")
                if state == "open_failed":
                    check(len(rows) == 1 and not rows[0]["succeeded"] and rows[0]["acquisition_id"] == "0" and
                          "bound_identity" not in rows[0] and receipt["acquired"] == receipt["closed"] == "0", "no phantom ownership")
                else:
                    check([r["call"] for r in rows] == ["open", "duplicate", "close", "close"] and
                          all(r["succeeded"] for r in rows), "both handles released after use")
                    check([r["acquisition_id"] for r in rows] == ["1", "2", "2", "1"] and
                          [r["parent_acquisition_id"] for r in rows] == ["0", "1", "1", "0"] and rows[1]["same_access"] and
                          receipt["acquired"] == receipt["closed"] == "2", "duplicate lineage and close totals")
                    check(all(int(r["bound_identity"]["pid"]) == target.pid and
                              int(r["bound_identity"]["creation_filetime"]) == created for r in rows[:2]),
                          "both handle observations match independent process generation")
                check(bool(receipt["collector_identity_query"]) == (state == "ready") and
                      bool(receipt["source_id"]) == (state == "ready"), "original collector query only after target admission")
                check(case.exists() == (code == 0) and out["original_claim_recorded"] == (code == 0), "publication outcome")
                return out

            clean = acquire("normal", target.pid, created, reference, 0, "ready")
            second = acquire("second", target.pid, created, reference, 0, "ready")
            check(second["operation_id"] != clean["operation_id"], "two collectors have distinct recorded operations")
            original = json.loads((root / "normal/recipe.knverify").read_bytes())["payload"]["recipe"]
            p = original["payload"]
            selected = [r for r in p["read_set"]["reads"] if int(r["address"]) == actor["base"] + actor["rva"] and
                        int(r["requested_bytes"]) == 64]
            check(selected and all("".join(s["bytes_hex"] for s in r["read"]["spans"]) == actor["range_hex"] for r in selected) and
                  clean["result"]["mapping"]["native_image_mapping_observed"], "actual native mapping and target's own 64 bytes")
            check(original["recipe_sha256"] == clean["recipe_sha256"] and
                  p["source_id"] == clean["source_initialization"]["source_id"], "published recipe binding")
            acquire("wrong-generation", target.pid, created + 1, reference, 1, "target_generation_mismatch")
            missing = acquire("missing-process", 0xffffffff, created, reference, 1, "open_failed")
            check(missing["open_status"] == access["process_open_status"](0xffffffff, 0x410) == 87, "Win32 invalid process ID")
            acquire("missing-reference", target.pid, created, root / "absent.dll", 1, "ready")
            access["deny_child_access"](target, 0x10)
            denied = acquire("denied", target.pid, created, reference, 1, "open_failed")
            check(denied["open_status"] == access["process_open_status"](target.pid, 0x410) == 5,
                  "owned process DACL denied VM_READ on the same generation")
            release(target)
        finally:
            cleanup(target)
            reference.unlink()

        def replay(name, case=None, code=0, pin=None):
            path, observed = pages[name]
            return json.loads(command([*offline, "replay-image-source", path, pin or observed,
                                       *([case] if case else []), "/json"], code))

        def verified(name, case=None):
            result = replay(name, case)
            saved = json.loads(pages[name][0].read_bytes())
            check(result["status"] == "replayed" and result["report_sha256"] == pages[name][1] and
                  result["source_initialization"] == saved["source_initialization"] and
                  result["original_claim_matched"] == saved["original_claim_recorded"] and
                  result["capture_status"] == saved["status"], "post-exit source receipt and optional original claim")
            check(not result["execution_observed"] and not result["collector_authenticated"], "bounded claim")
            return result

        for name in ("denied", "missing-process", "wrong-generation", "missing-reference"):
            verified(name)
        missing_time = json.loads(pages["missing-reference"][0].read_bytes())
        source = missing_time["source_initialization"]
        source["collector_identity_query"]["creation_filetime"] = "0"
        parts = source["source_id"].split(":")
        parts[2] = "0"
        source["source_id"] = ":".join(parts)
        retain("edit-zero-collector", json.dumps(missing_time, separators=(",", ":")).encode())
        check(replay("edit-zero-collector", code=1)["status"] == "source_receipt_invalid",
              "a missing generation cannot qualify the source even with a matching source id and fresh external pin")
        check(replay("normal", code=1)["status"] == "image_case_required", "published image requires original claim replay")
        check(replay("wrong-generation", root / "normal", 1)["status"] == "unexpected_image_case", "no case for rejected target")
        check(replay("normal", root / "second", 1)["status"] == "image_case_mismatch", "fresh capture of same bytes is a different operation")
        direct = verified("normal", root / "normal")
        archive = json.loads(command([*offline, "journal-image", root / "normal", root, "1", "/json"]))
        check(archive["closed"] and archive["indexed"], "managed original retained")
        managed = root / archive["capture_path"]
        for member in ("recipe.knverify", clean["reference_sha256"] + ".knblob"):
            (root / "normal" / member).unlink()
        (root / "normal").rmdir()
        check(verified("normal", managed) == direct, "same source receipt and claim after direct inputs were removed")
        check(replay("normal", managed, 1, "0" * 64)["status"] == "report_digest_mismatch", "exact report bytes pinned")
        for key, edit in (
            ("missing", lambda page: page.pop("source_initialization")),
            ("parent", lambda page: page["source_initialization"]["handle_actions"][1].update(parent_acquisition_id="0")),
            ("order", lambda page: page["source_initialization"]["handle_actions"].reverse()),
            ("totals", lambda page: page["source_initialization"].update(closed="0")),
            ("duplicate", lambda page: page["source_initialization"]["handle_actions"][1]["bound_identity"].update(creation_filetime="1")),
            ("controller", lambda page: page["source_initialization"]["collector_identity_query"].update(pid="1")),
            ("open-status", lambda page: page.update(open_status=5)),
            ("execution", lambda page: page.update(execution_observed=True)),
            ("operation", lambda page: page.update(operation_id=second["operation_id"])),
            ("receipt-pin", lambda page: page.update(recipe_sha256=second["recipe_sha256"])),
        ):
            page = copy.deepcopy(clean)
            edit(page)
            name = "edit-" + key
            retain(name, json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode())
            result = replay(name, managed, 1)
            check(result["status"] in ("source_receipt_missing", "source_receipt_invalid", "report_invalid", "image_case_mismatch") and
                  not result["original_claim_matched"], "independently repinned inconsistent report")
        command_line = [*offline, "replay-image-source", *pages["normal"], managed, "/json"]
        for sink in (pages["normal"][0], managed, root / "image-references" / (clean["reference_sha256"] + ".knblob")):
            alias = root / "external-link"
            os.link(sink, alias)
            try:
                before = (hashlib.sha256(sink.read_bytes()).digest(), sink.stat().st_mtime_ns)
                with alias.open("ab") as output:
                    proc = subprocess.run([str(exe), *map(str, command_line)], stdout=output, stderr=subprocess.PIPE, timeout=40)
                check(proc.returncode == 2 and before == (hashlib.sha256(sink.read_bytes()).digest(), sink.stat().st_mtime_ns),
                      "replay protects original report and archived dependencies on redirected output")
            finally:
                alias.unlink()
        disk = Path(temporary) / "source-replay.json"
        with disk.open("xb") as out:
            proc = subprocess.run([str(exe), *map(str, command_line)], stdout=out, stderr=subprocess.PIPE, timeout=40)
        check(proc.returncode == 0 and json.loads(disk.read_bytes()) == direct, "separate redirected report reproduces")
        with disk.open("rb") as out:
            proc = subprocess.run([str(exe), *map(str, command_line)], stdout=out, stderr=subprocess.PIPE, timeout=40)
        check(proc.returncode == 3 and json.loads(disk.read_bytes()) == direct, "read-only output preserves the original")
        original = pages["normal"][0].read_bytes()
        with pages["normal"][0].open("ab") as err:
            proc = subprocess.run([str(exe), *map(str, [*command_line, "/json"])], stdout=subprocess.PIPE, stderr=err, timeout=40)
        check(proc.returncode == 2 and pages["normal"][0].read_bytes() == original, "malformed usage preserves its input")
    print(f"[image.source] passed={checks} native_mem_image=true owned_targets=1 remaining=0")


if __name__ == "__main__":
    main()
