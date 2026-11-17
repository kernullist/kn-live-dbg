"""Owned LoadLibrary MEM_IMAGE -> live capture -> private journal -> post-exit replay."""
import argparse
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

from image_claim_oracle import check_original_claim, check_report, normalized_pe, unpack_recipe


def child(path, mode):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel.LoadLibraryExW.restype = wintypes.HMODULE
    kernel.FreeLibrary.argtypes = [wintypes.HMODULE]
    kernel.FreeLibrary.restype = wintypes.BOOL
    kernel.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
    kernel.GetProcAddress.restype = ctypes.c_void_p
    kernel.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    kernel.VirtualFree.restype = wintypes.BOOL
    kernel.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.VirtualProtect.restype = wintypes.BOOL

    class MemoryInfo(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("allocation", ctypes.c_void_p), ("allocation_protect", wintypes.DWORD),
                    ("partition", wintypes.WORD), ("size", ctypes.c_size_t), ("state", wintypes.DWORD),
                    ("protect", wintypes.DWORD), ("type", wintypes.DWORD)]

    kernel.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MemoryInfo), ctypes.c_size_t]
    kernel.VirtualQuery.restype = ctypes.c_size_t
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetCurrentProcessId.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    raw = Path(path).read_bytes()
    nt = struct.unpack_from("<I", raw, 0x3c)[0]
    optional = nt + 24
    preferred = struct.unpack_from("<Q", raw, optional + 24)[0]
    size = struct.unpack_from("<I", raw, optional + 56)[0]
    assert raw[nt:nt + 4] == b"PE\0\0" and struct.unpack_from("<H", raw, nt + 4)[0] == 0x8664
    assert struct.unpack_from("<I", raw, optional + 16)[0] == 0, "owned DLL has no entry point"
    reserved = kernel.VirtualAlloc(preferred, size, 0x2000, 0x01)
    module = None
    try:
        module = kernel.LoadLibraryExW(str(Path(path).resolve()), None, 0x1100)
        if not module:
            raise ctypes.WinError(ctypes.get_last_error())
        address = kernel.GetProcAddress(module, b"KnOwnedImageProbe")
        assert address and module != preferred, "real loader relocation is required"
        region = MemoryInfo()
        assert kernel.VirtualQuery(address, ctypes.byref(region), ctypes.sizeof(region)) == ctypes.sizeof(region)
        assert region.type == 0x1000000 and region.state == 0x1000 and region.protect == 0x20 and region.allocation == module
        rva = address - module
        expected = bytes(normalized_pe(raw, module, rva, 64))
        assert ctypes.string_at(address, 64) == expected and int.from_bytes(expected[:8], "little") == address
        if mode == "modified":
            old, restored = wintypes.DWORD(), wintypes.DWORD()
            assert kernel.VirtualProtect(address, 64, 0x04, ctypes.byref(old))
            try:
                ctypes.c_ubyte.from_address(address + 32).value ^= 1
            finally:
                assert kernel.VirtualProtect(address, 64, old.value, ctypes.byref(restored))
        assert kernel.VirtualQuery(address, ctypes.byref(region), ctypes.sizeof(region)) == ctypes.sizeof(region)
        # VirtualQuery retains MEM_IMAGE for a modified copy-on-write image page.
        # This test asserts mapped byte provenance, never page sharing or execution.
        assert region.type == 0x1000000 and region.protect == 0x20
        times = [wintypes.FILETIME() for _ in range(4)]
        assert kernel.GetProcessTimes(kernel.GetCurrentProcess(), *(ctypes.byref(value) for value in times))
        print(json.dumps({"pid": kernel.GetCurrentProcessId(), "creation": times[0].dwHighDateTime << 32 | times[0].dwLowDateTime,
                          "base": module, "preferred": preferred, "rva": rva, "type": region.type, "protection": region.protect}), flush=True)
        assert sys.stdin.readline().strip() == "release", "parent explicitly releases the owned image"
    finally:
        if module:
            assert kernel.FreeLibrary(module)
        if reserved:
            assert kernel.VirtualFree(reserved, 0, 0x8000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, message
        checks += 1

    def run(arguments):
        result = subprocess.run([str(args.exe.resolve()), *map(str, arguments)], capture_output=True, text=True, encoding="utf-8", timeout=60)
        check(result.returncode == 0, f"exit={result.returncode}: {result.stdout[-800:]} {result.stderr[-500:]}")
        return json.loads(result.stdout)

    with tempfile.TemporaryDirectory(prefix="mapped-image-", dir=args.fixtures) as temporary:
        root = Path(temporary)
        store = root / "private"
        check(run(["--offline", "!kmon", "init-store", store, "/acl-only"])["status"] == "ready", "explicit owned private store")
        for identifier, mode in enumerate(("clean", "modified"), 1):
            image = root / (mode + ".dll")
            shutil.copyfile(args.dll, image)
            raw = image.read_bytes()
            target = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child", str(image), mode],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            ready = queue.Queue()
            reader = threading.Thread(target=lambda: ready.put(target.stdout.readline()), daemon=True)
            reader.start()
            try:
                line = ready.get(timeout=30)
                if not line:
                    raise AssertionError(target.communicate(timeout=10)[1])
                identity = json.loads(line)
                reader.join(timeout=1)
                check(target.poll() is None and identity["pid"] == target.pid and identity["base"] != identity["preferred"] and
                      identity["type"] == 0x1000000 and identity["protection"] == 0x20, "observed owned executable MEM_IMAGE at relocated base")
                case = root / (mode + "-case")
                captured = run(["--verify-process-image", target.pid, identity["creation"], image, f'{identity["base"]:x}',
                                f'{identity["rva"]:x}', "64", case, "--allow-residency"])
                document = json.loads((case / "recipe.knverify").read_bytes())
                recipe = unpack_recipe(document)
                payload = recipe["payload"]
                expected = normalized_pe(raw, identity["base"], identity["rva"], 64)
                observed = bytes.fromhex(captured["result"]["observed_hex"])
                differences = [i for i in range(64) if expected[i] != observed[i]]
                check(differences == ([32] if mode == "modified" else []), "independent DIR64 normalization and exact owned mutation")
                check(captured["result"]["ownership"] == ("owned_modified" if mode == "modified" else "owned_verified"), "real image bytes select positive and negative claims")
                check(not captured["execution_observed"] and captured["original_claim_recorded"], "byte observation is not execution evidence")
                reads = payload["read_set"]["reads"]
                check(payload["read_set"]["recording_complete"] and int(payload["read_set"]["attempts"]) == len(reads), "complete original receipt denominator")
                matching = [r for r in reads if int(r["address"]) == identity["base"] + identity["rva"]]
                check(len(matching) >= (2 if mode == "modified" else 1), "modified range has two original observations")
                for receipt in reads:
                    check(receipt["read"]["backend_contract"] == "win32_read_process_memory" and receipt["residency_consent"] and
                          receipt["read"]["identity_revalidated"], "native handle identity and residency consent retained")
                archived = run(["--offline", "!kmon", "journal-image", case, store, identifier])
                check(archived["closed"] and archived["indexed"] and archived["reference_created"] == (identifier == 1), "live capture archived with shared exact reference")
                target.stdin.write("release\n")
                target.stdin.flush()
                rest, errors = target.communicate(timeout=10)
                check(target.returncode == 0 and not rest and not errors, "observed unload and child exit precede replay")
                image.unlink()
                shutil.rmtree(case)
                replayed = run(["--offline", "!kmon", "replay-image", store / archived["capture_path"]])
                check(replayed["status"] == "replayed" and replayed["recorded_result"] == captured["result"], "managed replay survives target exit and original artifacts removal")
                check_original_claim(document, replayed)
                check_report(recipe, raw, replayed)
                # A separately pinned approval authorizes only the exact owned
                # mutation, after unload and source removal. DIR64 at offset 0
                # remains part of the original comparison, not the exception.
                encode = lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                digest = lambda value: hashlib.sha256(value).hexdigest()
                change = {"schema": "kn.authorized_image_changes.v1", "image_sha256": digest(raw), "issuer": "owned-probe-build",
                          "policy_epoch": "1", "not_before_filetime": "1", "not_after_filetime": "18446744073709551615",
                          "comparison_policy": "kn.executable_page.direct.v1", "hash_basis": "non_fixup_compared_bytes.v1",
                          "changes": [{"rva": str(identity["rva"] + 32), "length": "1", "before_sha256": digest(expected[32:33]),
                                       "after_sha256": digest(bytes([expected[32] ^ 1]))}]}
                change_path, policy_path = root / "change.knchange", root / "policy.knapproval"
                change_path.write_bytes(encode(change))
                policy = {"schema": "kn.image_approval_policy.v1", "policy_id": "owned-probe-approval", "policy_epoch": "1",
                          "not_before_filetime": "1", "not_after_filetime": "18446744073709551615",
                          "approvals": [{"image_sha256": digest(raw), "manifest_sha256": digest(change_path.read_bytes()), "issuer": change["issuer"]}]}
                policy_path.write_bytes(encode(policy))
                assessed = run(["--offline", "!kmon", "assess-image", store / archived["capture_path"], change_path, policy_path, digest(policy_path.read_bytes())])
                check(assessed["reference_trust"] == "R-approved" and assessed["comparison_complete"], "approved reference is relative to a separate exact policy")
                check(assessed["decision"] == ("all_observed_changes_authorized" if mode == "modified" else "no_observed_change") and
                      assessed["rules"][0]["state"] == ("authorized" if mode == "modified" else "not_applied"), "exact ASLR-independent non-fixup rule")
                check(assessed["authorized_changed_bytes"] == ("1" if mode == "modified" else "0") and assessed["unexplained_changed_bytes"] == "0", "exact approved byte denominator")
                check(assessed["replay"] == replayed and not assessed["issuer_signature_verified"] and not assessed["current_image_state_known"], "approval preserves original claims and does not imply signature or current state")
                anchor = digest(policy_path.read_bytes())
                approval = run(["--offline", "!kmon", "journal-image-approval", store / archived["capture_path"],
                                change_path, policy_path, anchor, store, identifier + 100])
                check(approval["closed"] and approval["indexed"] and not approval["current_approval_established"], "managed capture retains historical approval after target exit")
                change_path.unlink()
                policy_path.unlink()
                historical = run(["--offline", "!kmon", "replay-image-approval", store / approval["approval_path"], anchor])
                check(historical["status"] == "reproduced" and historical["original_assessment_reproduced"] and
                      historical["assessment"] == historical["recorded_assessment"], "exact historical result survives original policy and manifest deletion")
                check(historical["assessment"]["decision"] == assessed["decision"] and
                      historical["assessment"]["authorized_changed_bytes"] == assessed["authorized_changed_bytes"], "retained approval preserves exact native byte result")
                check_original_claim(document, historical["assessment"]["replay"])
                check_report(recipe, raw, historical["assessment"]["replay"])
                approved_membership = run(["--offline", "!kmon", "journal", store / "collections" / str(identifier + 100), "/index"])
                check(approved_membership["closed"] and approved_membership["committed_approval_paths"] == [approval["approval_path"]] and
                      approved_membership["unique_paths"] == "6" and not approved_membership["replay_established"], "five original approval members plus closure ledger")
                disclosure_root = root / (mode + "-disclosure")
                redacted = run(["--offline", "!kmon", "redact-image", store / archived["capture_path"], disclosure_root, "/acl-only"])
                check(redacted["status"] == "ready", "managed capture supports original-policy count redaction")
                manifest = json.loads((disclosure_root / "redaction.knredact").read_bytes())
                check(manifest["source_file_sha256"] == hashlib.sha256((store / archived["capture_path"]).read_bytes()).hexdigest() and
                      manifest["source_semantic_sha256"] == document["publication_sha256"] and not manifest["transfer_authorized"],
                      "redaction links exact managed original and grants no transfer approval")
                recovered = run(["--offline", "!kmon", "journal", store / "collections" / str(identifier), "/index"])
                check(recovered["closed"] and recovered["committed_direct_capture_paths"] == [archived["capture_path"]] and
                      not recovered["replay_established"], "separate committed membership and semantic replay")
            finally:
                if target.poll() is None:
                    target.kill()
                    target.communicate(timeout=10)
                reader.join(timeout=2)
        check(run(["--offline", "!kmon", "privacy", store, "/audit"])["status"] == "ready", "all archived outputs remain private")
    print(f"[image.mapped.journal] checks={checks} cases=2 children_remaining=0 dll_sha256={hashlib.sha256(args.dll.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        child(sys.argv[2], sys.argv[3])
    else:
        main()
