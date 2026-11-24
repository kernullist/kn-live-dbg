"""Exercise the real handle reader and post-exit replay with an owned, nonexecuting PE buffer."""
import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time

from image_claim_oracle import check_report, check_original_claim, unpack_recipe


def child(image, mode):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    kernel.VirtualFree.restype = wintypes.BOOL
    kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.VirtualProtect.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetCurrentProcessId.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    data = Path(image).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0"
    optional = pe + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x20b
    preferred = struct.unpack_from("<Q", data, optional + 24)[0]
    size, headers = struct.unpack_from("<II", data, optional + 56)
    assert size == 0x4000 and headers == 0x400, "only the owned synthetic fixture is accepted"
    base = kernel.VirtualAlloc(None, size, 0x3000, 0x04)  # RW, never executable.
    if not base:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        mapped = bytearray(size)
        mapped[:headers] = data[:headers]
        section_count = struct.unpack_from("<H", data, pe + 6)[0]
        section_start = optional + struct.unpack_from("<H", data, pe + 20)[0]
        for index in range(section_count):
            _, rva, raw_size, raw = struct.unpack_from("<IIII", data, section_start + index * 40 + 8)
            assert rva + raw_size <= size and raw + raw_size <= len(data)
            mapped[rva:rva + raw_size] = data[raw:raw + raw_size]
        reloc, reloc_size = struct.unpack_from("<II", data, optional + 112 + 5 * 8)
        cursor, end = reloc, reloc + reloc_size
        while cursor < end:
            page, block = struct.unpack_from("<II", mapped, cursor)
            assert block >= 8 and block % 2 == 0 and cursor + block <= end
            for pos in range(cursor + 8, cursor + block, 2):
                entry = struct.unpack_from("<H", mapped, pos)[0]
                kind, offset = entry >> 12, entry & 0xfff
                if kind == 0:
                    continue
                assert kind == 10 and page + offset + 8 <= size
                value = struct.unpack_from("<Q", mapped, page + offset)[0]
                struct.pack_into("<Q", mapped, page + offset, (value + base - preferred) & ((1 << 64) - 1))
            cursor += block
        if mode == "modified":
            mapped[0x2150] ^= 1
        ctypes.memmove(base, bytes(mapped), size)
        if mode == "hole":
            old = wintypes.DWORD()
            if not kernel.VirtualProtect(base + 0x2000, 4096, 0x01, ctypes.byref(old)):
                raise ctypes.WinError(ctypes.get_last_error())
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), *(ctypes.byref(t) for t in times)):
            raise ctypes.WinError(ctypes.get_last_error())
        creation = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        print(json.dumps({"pid": kernel.GetCurrentProcessId(), "creation": creation, "base": base}), flush=True)
        assert sys.stdin.readline().strip() == "release", "parent must explicitly release the owned fixture"
    finally:
        if not kernel.VirtualFree(base, 0, 0x8000):
            raise ctypes.WinError(ctypes.get_last_error())


def signal_capture(event, program, command):
    """Send the signal only inside a fresh console owned by this test."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    handler_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    handler = handler_type(lambda kind: kind in (0, 1))
    kernel.SetConsoleCtrlHandler.argtypes = [handler_type, wintypes.BOOL]
    kernel.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    kernel.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
    kernel.FindFirstChangeNotificationW.restype = wintypes.HANDLE
    kernel.FindNextChangeNotification.argtypes = [wintypes.HANDLE]
    kernel.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
    kernel.WaitForMultipleObjects.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL, wintypes.DWORD]
    kernel.WaitForMultipleObjects.restype = wintypes.DWORD

    def members():
        ids = (wintypes.DWORD * 8)()
        count = kernel.GetConsoleProcessList(ids, len(ids))
        if not 0 < count <= len(ids):
            raise RuntimeError("could not enumerate the isolated console")
        return set(ids[:count])

    if event not in (0, 1) or len(command) != 9 or command[0] != "--verify-process-image":
        raise ValueError("invalid capture control trial")
    case = Path(command[7])
    if case.exists() or members() != {os.getpid()}:
        raise RuntimeError("control trial requires a new case and its own console")
    # Ctrl+C ignore is an inheritable attribute, independent of the handler list.
    if not kernel.SetConsoleCtrlHandler(handler_type(), False) or not kernel.SetConsoleCtrlHandler(handler, True):
        raise ctypes.WinError(ctypes.get_last_error())
    change = kernel.FindFirstChangeNotificationW(str(case.parent), False, 2)  # FILE_NOTIFY_CHANGE_DIR_NAME
    try:
        if change == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        with subprocess.Popen([program, *command], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as capture:
            try:
                waitables = (wintypes.HANDLE * 2)(change, int(capture._handle))
                deadline = time.monotonic() + 30
                while not case.is_dir():
                    remaining = max(0, int(1000 * (deadline - time.monotonic())))
                    if not remaining or kernel.WaitForMultipleObjects(2, waitables, False, remaining) != 0:
                        raise RuntimeError("capture did not create its new case")
                    if not case.is_dir() and not kernel.FindNextChangeNotification(change):
                        raise ctypes.WinError(ctypes.get_last_error())
                # The capture creates the directory after opening the target and reference.
                if members() != {os.getpid(), capture.pid}:
                    raise RuntimeError("unexpected console membership at interruption")
                if not kernel.GenerateConsoleCtrlEvent(event, 0):
                    raise ctypes.WinError(ctypes.get_last_error())
                out, err = capture.communicate(timeout=45)
                print(json.dumps({"code": capture.returncode, "stdout": out.decode("utf-8"), "stderr": err.decode("utf-8")}))
            finally:
                if capture.poll() is None:
                    capture.kill()
                    capture.wait(timeout=10)
    finally:
        if change != ctypes.c_void_p(-1).value:
            kernel.FindCloseChangeNotification(change)
        kernel.SetConsoleCtrlHandler(handler, False)


def run_console_capture(exe, command, event):
    start = subprocess.STARTUPINFO()
    start.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    start.wShowWindow = subprocess.SW_HIDE
    output = subprocess.check_output([sys.executable, "-B", str(Path(__file__).resolve()), "--signal-capture",
                                      str(event), str(exe), *map(str, command)], timeout=100,
                                     creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=start)
    return json.loads(output)


def capture_interruptions(exe, command, root, check):
    # The overlay leaves the mapped PE unchanged and gives the controller time
    # to observe creation of the case during publication of the reference copy.
    reference = root / "signal-reference.exe"
    shutil.copyfile(command[3], reference)
    with reference.open("ab") as overlay:
        overlay.truncate(32 * 1024 * 1024)
    retained = []
    for event, name in ((0, "ctrl-c"), (1, "ctrl-break")):
        case = root / name
        args = command.copy()
        args[3], args[7] = reference, case
        diagnostic = run_console_capture(exe, args, event)
        result = json.loads(diagnostic["stdout"]) if diagnostic["stdout"].strip() else {}
        check(diagnostic["code"] == 1 and not diagnostic["stderr"],
              f"{name}: exit={diagnostic['code']} capture={result.get('status')} stderr_bytes={len(diagnostic['stderr'].encode())}")
        check(result["status"] == "interrupted" and result["original_claim_recorded"] and
              result["result"]["ownership"] == "owned_unverified", "observed stop publishes an incomplete comparison")
        payload = unpack_recipe(json.loads((case / "recipe.knverify").read_bytes()))["payload"]
        reads = payload["read_set"]
        invoked = [r for r in reads["reads"] if r["source_invoked"]]
        check(reads["operation_id"] == result["operation_id"] and reads["cancelled"] and reads["recording_complete"] and
              int(reads["charged_source_calls"]) == len(invoked) and
              int(reads["charged_requested_bytes"]) == sum(int(r["requested_bytes"]) for r in invoked),
              "interrupted recording retains exactly its actual source work")
        report_file = root / (name + "-capture.json")
        encoded = diagnostic["stdout"].encode("utf-8")
        report_file.write_bytes(encoded)
        retained.append((case, result["result"], payload["reference_sha256"], report_file, hashlib.sha256(encoded).hexdigest()))
    reference.unlink()
    return retained


def check_capture_streams(exe, command, root, check):
    from _winapi import CreateJunction

    with tempfile.TemporaryDirectory(dir=root, prefix="delivery-") as working:
        work = Path(working)
        reference = work / "--allow-residency"
        shutil.copyfile(command[3], reference)
        case = work / "case"
        shutil.copytree(command[7], case)
        nested = case / "nested"
        nested.mkdir()
        subfile = nested / "original.bin"
        subfile.write_bytes(b"owned prior evidence")
        original = case / "recipe.knverify"
        blob, = case.glob("*.knblob")
        occupied = [*command]
        occupied[3], occupied[7] = reference.name, case
        missing = occupied.copy()
        missing[1:3] = [4294967295, 1]

        def call(args, output, stream):
            handles = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with output.open("ab", buffering=0) as out:
                handles[stream] = out
                return subprocess.run([str(exe), *map(str, args)], cwd=work, timeout=30, **handles)

        def stamp(path):
            return hashlib.sha256(path.read_bytes()).digest(), path.stat().st_mtime_ns

        for source in (reference, original, blob, subfile):
            alias = work / "outside.log"
            os.link(source, alias)
            try:
                before = stamp(source)
                for args, stream, expected in ((missing, "stdout", 2), ([*occupied, "extra"], "stderr", 2),
                                               (["--mode", "offline", *occupied], "stdout", 5),
                                               ([*occupied, "--mode=observe"], "stdout", 2)):
                    outcome = call(args, alias, stream)
                    check(outcome.returncode == expected and not outcome.stdout and not outcome.stderr,
                          "unsafe redirected diagnostic returns its exit code without delivering bytes")
                    check(stamp(source) == before, "original content and write time survive output through another name")
            finally:
                alias.unlink()

        fresh = occupied.copy()
        fresh[7] = work / "new-case"
        before = stamp(reference)
        check(call(fresh, reference, "stdout").returncode == 2 and not fresh[7].exists() and stamp(reference) == before,
              "direct reference alias rejected before the live acquisition")
        before = stamp(subfile)
        check(call(occupied, subfile, "stdout").returncode == 2 and stamp(subfile) == before,
              "single-name output inside an occupied case is protected")
        junction = work / "outside-directory"
        CreateJunction(str(nested), str(junction))
        try:
            check(call(occupied, junction / subfile.name, "stdout").returncode == 2 and stamp(subfile) == before,
                  "a report opened through a junction into the occupied case cannot change the evidence")
        finally:
            junction.rmdir()
        file_dest = missing.copy()
        file_dest[7] = subfile
        check(call(file_dest, subfile, "stdout").returncode == 2 and stamp(subfile) == before,
              "a regular file at the requested case name is protected")
        shifted = [command[0], original, "invalid"]
        before = stamp(original)
        check(call(shifted, original, "stderr").returncode == 2 and stamp(original) == before,
              "misplaced filename in malformed input still protects the original")
        check(call([*occupied, "extra", "operand"], original, "stderr").returncode == 2 and stamp(original) == before,
              "excess operands cannot cause a disk usage message to overwrite a prior case")

        report = work / "case-report.jsonl"
        report.write_bytes(b"prior report\n")
        other_name = work / "second-report-name"
        os.link(report, other_name)
        os.link(report, work / "third-report-name")
        successful = call(fresh, other_name, "stdout")
        lines = report.read_bytes().splitlines()
        check(successful.returncode == 0 and lines[0] == b"prior report" and json.loads(lines[1])["original_claim_recorded"],
              "distinct multi-link report appends the real capture result")
        check((fresh[7] / "recipe.knverify").is_file(), "successful disk delivery published the original case")
        rejected = call(missing, report, "stdout")
        check(rejected.returncode == 1 and json.loads(report.read_bytes().splitlines()[-1])["status"] == "failed",
              "separate disk report retains the acquisition failure for an occupied case")
        usage = call([*occupied, "extra"], report, "stderr")
        check(usage.returncode == 2 and report.read_bytes().splitlines()[-1].startswith(b"usage:"),
              "malformed arguments can still deliver usage to a distinct disk file")
        before = stamp(original)
        unused = call(missing, original, "stderr")
        check(unused.returncode == 1 and json.loads(unused.stdout)["status"] == "failed" and stamp(original) == before,
              "a valid invocation protects the writing stream and preserves an unused stderr alias")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    exe, fixtures = args.exe.resolve(), args.fixtures.resolve()
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, message
        checks += 1

    def run(arguments, code=0, save_stdout=None):
        result = subprocess.run([str(exe), *map(str, arguments)], capture_output=True, timeout=30)
        check(result.returncode == code, f"exit {result.returncode}, expected {code}: {result.stderr}")
        if code == 2:
            check(not result.stdout and b"usage:" in result.stderr, "invalid grammar produces no evidence")
            return None
        if save_stdout is not None:
            with save_stdout.open("xb") as stream:
                stream.write(result.stdout)
        return json.loads(result.stdout)

    def replay(directory, current=False, code=0):
        result = run(["--offline", "!kmon", "replay-image", directory, *(["/current"] if current else []), "/json"], code)
        if result["status"] in ("replayed", "reanalyzed"):
            source = json.loads((directory / "recipe.knverify").read_bytes())
            recipe = unpack_recipe(source)
            check_original_claim(source, result)
            blob = (directory / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes()
            check_report(recipe, blob, result)
        else:
            check(result["claim_assessment"] is None, "failed replay withholds current claims")
        return result

    def encode(document):
        payload = json.dumps(document["payload"], ensure_ascii=False, separators=(",", ":"))
        document["recipe_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
        return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()

    with tempfile.TemporaryDirectory(prefix="live-image-", dir=fixtures) as temporary:
        root = Path(temporary)
        source_store = root / "outcomes"
        run(["--offline", "!kmon", "init-store", source_store, "/acl-only", "/json"])
        for collection_id, mode in enumerate(("clean", "modified", "hole"), 1):
            reference = root / f"원본-{mode}.exe"
            shutil.copyfile(fixtures / "owned-image.exe", reference)
            target = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "--child", str(reference), mode],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                ready = queue.Queue()
                reader = threading.Thread(target=lambda: ready.put(target.stdout.readline()), daemon=True)
                reader.start()
                identity = json.loads(ready.get(timeout=20))  # Observed readiness, never a sleep-based ordering claim.
                reader.join(timeout=1)
                check(identity["pid"] == target.pid and target.poll() is None, "handshake comes from the owned live child")
                directory = root / mode
                command = ["--verify-process-image", identity["pid"], identity["creation"], reference,
                           f'{identity["base"]:x}', "2000", "4096", directory, "--allow-residency"]
                wrong = command.copy()
                wrong[2] += 1
                wrong[7] = root / f"wrong-identity-{mode}"
                denied = run(wrong, 1)
                check(denied["status"] == "failed" and not wrong[7].exists(), "creation mismatch rejected before file publication")
                run(command[:-1], 2)
                run([*command, "--allow-residency"], 2)
                check(not directory.exists(), "bad consent grammar does not open an output directory")
                source_page = root / (mode + "-capture.json")
                result = run(command, save_stdout=source_page)
                manifest = directory / "recipe.knverify"
                original = manifest.read_bytes()
                publication = json.loads(original)
                recipe = unpack_recipe(publication)
                payload = recipe["payload"]
                read_set = payload["read_set"]
                reads = read_set["reads"]
                check(recipe["schema"] == "kn.image_recipe.v3" and result["schema"] == "kn.image_capture.v3" and
                      encode(copy.deepcopy(recipe)) == json.dumps(recipe, ensure_ascii=False, separators=(",", ":")).encode(),
                      "independent canonical digest matches v3")
                check(publication["schema"] == "kn.image_claim_publication.v1" and result["original_claim_recorded"],
                      "live capture atomically retains the original claim before successful return")
                check(read_set["operation_id"] == result["operation_id"] and read_set["target_id"] ==
                      f'process:{identity["pid"]}:{identity["creation"]}', "original operation binds the requested process generation")
                check(read_set["recording_complete"] and int(read_set["attempts"]) == len(reads) and
                      not int(read_set["unrecorded_attempts"]), "all parser and confirmation attempts were saved")
                check(int(read_set["charged_requested_bytes"]) == sum(int(r["requested_bytes"]) for r in reads) and
                      int(read_set["charged_source_calls"]) == len(reads), "independent charged-byte and call totals")
                for index, receipt in enumerate(reads, 1):
                    read = receipt["read"]
                    check(receipt["completed"] and receipt["source_invoked"] and receipt["residency_consent"] and
                          receipt["fallback"] is None and receipt["address_domain"] == "virtual" and
                          read["read_receipt_id"] == str(index) and read["operation_id"] == read_set["operation_id"],
                          "each original read retains its receipt, source, consent, and no implicit fallback")
                    check(read["backend_contract"] == "win32_read_process_memory" and read["backend_copy_attempted"] and
                          read["side_effects_possible"] and read["identity_revalidated"] and
                          read["native_status_domain"] == "win32" and read["transport_status"] is None,
                          "real Win32 read metadata does not invent native-driver transport")
                    check(receipt["source_contract"]["user_only"] and receipt["address_shape"]["legacy_assumed"],
                          "OS user ceiling remains separate from assumed virtual width")
                expected = {"clean": "owned_verified", "modified": "owned_modified", "hole": "owned_unverified"}[mode]
                check(result["result"]["ownership"] == expected, "capture uses actual target bytes and retained reference")
                if mode == "modified":
                    page_reads = [r for r in reads if int(r["address"]) == identity["base"] + 0x2000]
                    check(len(page_reads) == 2, "changed bytes require two distinct original reads")
                if mode == "hole":
                    check(any(r["read"]["native_status"] != 0 and r["read"]["transferred_bytes"] == 0 and
                              not r["read"]["spans"][0]["bytes_hex"] for r in reads), "unreadable page preserves raw failure without parser bytes")
                check(run(command, 1)["status"] == "failed" and manifest.read_bytes() == original,
                      "an existing case is never replaced")
                undelivered = None
                interrupted = []
                if mode == "clean":
                    check_capture_streams(exe, command, root, check)
                    interrupted = capture_interruptions(exe, command, root, check)
                    undelivered = root / "stdout-failed"
                    output_command = command.copy()
                    output_command[7] = undelivered
                    sink = root / "readonly-output.txt"
                    sink.write_bytes(b"owned sentinel")
                    with sink.open("rb") as output:
                        delivery = subprocess.run([str(exe), *map(str, output_command)], stdout=output,
                                                  stderr=subprocess.PIPE, timeout=30)
                    check(delivery.returncode == 3 and sink.read_bytes() == b"owned sentinel" and
                          (undelivered / "recipe.knverify").is_file(), "stdout failure reports failure while preserving the published case")
                target.stdin.write("release\n")
                target.stdin.flush()
                remaining, errors = target.communicate(timeout=10)
                check(target.returncode == 0 and not remaining and not errors, "owned child exits and frees its mapping before replay")
                reference.write_bytes(b"replaced after observed process exit")
                reference.unlink()
                exact = replay(directory)
                check(exact["status"] == "replayed" and exact["result"] == exact["recorded_result"] == result["result"],
                      "post-exit replay survives original reference replacement and removal")
                source_pin = hashlib.sha256(source_page.read_bytes()).hexdigest()
                saved = run(["--offline", "!kmon", "journal-image-source", source_page, source_pin,
                             source_store, collection_id, directory, "/json"])
                check(saved["closed"] and saved["capture_status"] == "recorded", "archive the actual comparison outcome")
                budget = run(["--offline", "!kmon", "store", source_store, "/retention", "/json"])["collection_retention"]
                row = next(r for r in budget["roots"] if r["collection_id"] == str(collection_id))
                check(row["class"] == ("observation_gap" if mode == "hole" else "first_observation") and
                      row["source_copies"]["report_sha256"] == source_pin, "coverage of the live read decides its retention class")
                if undelivered is not None:
                    check(replay(undelivered)["status"] == "replayed", "case survives failed stdout delivery and target exit")
                for case, recorded, digest, capture_file, capture_pin in interrupted:
                    original_stop = replay(case)
                    current_stop = replay(case, current=True)
                    check(original_stop["capture_interrupted"] and current_stop["capture_interrupted"] and
                          original_stop["result"] == original_stop["recorded_result"] == recorded,
                          "interruption and original scope replay after target exit and reference removal")
                    source = run(["--offline", "!kmon", "replay-image-source", capture_file, capture_pin, case, "/json"])
                    check(source["original_claim_matched"] and source["capture_status"] == "interrupted" and
                          source["source_initialization"]["status"] == "ready", "source opened before the interrupted observation")
                    if case.name == "ctrl-break":
                        store = root / "signal-archive"
                        run(["--offline", "!kmon", "init-store", store, "/acl-only", "/json"])
                        archived = run(["--offline", "!kmon", "journal-image", case, store, "1", "/json"])
                        check(archived["closed"] and archived["indexed"], "interrupted case has a closed journal")
                        (case / "recipe.knverify").unlink()
                        (case / (digest + ".knblob")).unlink()
                        case.rmdir()
                        archived_report = run(["--offline", "!kmon", "replay-image", store / archived["capture_path"], "/json"])
                        check(archived_report == original_stop, "managed replay reproduces the interrupted case after direct case removal")
                        managed_source = run(["--offline", "!kmon", "replay-image-source", capture_file, capture_pin,
                                              store / archived["capture_path"], "/json"])
                        check(managed_source == source, "original source actions and interrupted claim bind to the archived case")
                        acquisition = run(["--offline", "!kmon", "journal-image-source", capture_file, capture_pin, store,
                                           "2", store / archived["capture_path"], "/json"])
                        check(acquisition["closed"] and acquisition["capture_status"] == "interrupted", "interrupted attempt archived")
                        capture_file.unlink()
                        retained = run(["--offline", "!kmon", "replay-image-source", store / acquisition["report_path"], capture_pin, "/json"])
                        check(retained == source, "the archive reproduces the interrupt after the original stdout is removed")
                        budget = run(["--offline", "!kmon", "store", store, "/retention", "/json"])["collection_retention"]
                        rows = {r["collection_id"]: r for r in budget["roots"]}
                        check(rows["2"]["class"] == "observation_gap" and rows["2"]["source_copies"]["active_copies"] == "1" and
                              rows["1"]["class"] == "unclassified" and "source_copies" not in rows["1"],
                              "interrupted acquisition and legacy image-only collection retain their own priorities")
                current = replay(directory, current=True)
                check(current["status"] == "reanalyzed" and current["result"] == exact["result"], "current policy uses only retained inputs")
                check(not exact["execution_observed"] and not exact["collector_authenticated"], "read evidence does not prove execution or collector trust")
                if mode == "modified":
                    claims = {c["name"]: c for c in exact["proof"]["claims"]}
                    check(claims["recorded_range_differs_reference_policy"]["status"] == "supported", "post-exit claim uses original confirmation bytes")
                after_exit = command.copy()
                after_exit[7] = root / f"after-exit-{mode}"
                check(run(after_exit, 1)["status"] == "failed" and not after_exit[7].exists(), "exited target cannot be recaptured by PID alone")
                if mode == "clean":
                    mutations = [
                        lambda p: p["read_set"].__setitem__("charged_requested_bytes", "1"),
                        lambda p: p["read_set"]["reads"][0].__setitem__("residency_consent", False),
                        lambda p: p["read_set"]["reads"][0].__setitem__("source_invoked", False),
                        lambda p: p["read_set"]["reads"][0]["read"].__setitem__("operation_id", "unrelated"),
                        lambda p: p["read_set"]["reads"][0]["read"].__setitem__("read_receipt_id", "2"),
                        lambda p: p["read_set"]["reads"][0].__setitem__("completed", False),
                        lambda p: p["read_set"]["reads"][0].__setitem__("fallback", {"from_receipt": "1"}),
                        lambda p: p["read_set"]["reads"][-1]["source_contract"].__setitem__("maximum_read_bytes", "32"),
                        lambda p: p["read_set"]["reads"][0]["read"].__setitem__("transferred_bytes", 4097),
                        lambda p: p["read_set"].__setitem__("collector_authenticated", True),
                    ]
                    for mutate in mutations:
                        corrupted = copy.deepcopy(recipe)
                        mutate(corrupted["payload"])
                        manifest.write_bytes(encode(corrupted))
                        check(replay(directory, code=1)["status"] == "recipe_unavailable_or_corrupt",
                              "independently rehashed contradictory evidence is rejected")
                    manifest.write_bytes(original)
                    check(manifest.read_bytes() == original, "tamper controls restore exactly the owned original artifact")
            finally:
                if target.poll() is None:
                    target.kill()
                    target.wait(timeout=10)
                for stream in (target.stdin, target.stdout, target.stderr):
                    stream.close()
                check(target.poll() is not None, "no owned child process remains")
    print(f"[image.recipe.live] passed={checks} owned_children=3 remaining=0 execution_fixture=false")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        child(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 13 and sys.argv[1] == "--signal-capture":
        signal_capture(int(sys.argv[2]), sys.argv[3], sys.argv[4:])
    else:
        main()
