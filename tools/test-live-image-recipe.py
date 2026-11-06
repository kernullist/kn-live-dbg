"""Exercise the real handle reader and post-exit replay with an owned, nonexecuting PE buffer."""
import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import queue
import shutil
import struct
import subprocess
import sys
import tempfile
import threading


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

    def run(arguments, code=0):
        result = subprocess.run([str(exe), *map(str, arguments)], capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
        check(result.returncode == code, f"exit {result.returncode}, expected {code}: {result.stderr}")
        if code == 2:
            check(not result.stdout and "usage:" in result.stderr, "invalid grammar produces no evidence")
            return None
        return json.loads(result.stdout)

    def replay(directory, current=False, code=0):
        return run(["--offline", "!kmon", "replay-image", directory, *(["/current"] if current else []), "/json"], code)

    def encode(document):
        payload = json.dumps(document["payload"], ensure_ascii=False, separators=(",", ":"))
        document["recipe_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
        return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()

    with tempfile.TemporaryDirectory(prefix="live-image-", dir=fixtures) as temporary:
        root = Path(temporary)
        for mode in ("clean", "modified", "hole"):
            reference = root / f"원본-{mode}.exe"
            shutil.copyfile(fixtures / "owned-image.exe", reference)
            target = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child", str(reference), mode],
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
                result = run(command)
                manifest = directory / "recipe.knverify"
                original = manifest.read_bytes()
                recipe = json.loads(original)
                payload = recipe["payload"]
                read_set = payload["read_set"]
                reads = read_set["reads"]
                check(recipe["schema"] == "kn.image_recipe.v2" and encode(copy.deepcopy(recipe)) == original,
                      "independent canonical digest matches v2")
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
                if mode == "clean":
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
                if undelivered is not None:
                    check(replay(undelivered)["status"] == "replayed", "case survives failed stdout delivery and target exit")
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
    else:
        main()
