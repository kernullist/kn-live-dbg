"""Replay named and ordinal IAT evidence from a stopped, owned native process (x64 MSVC tools)."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import queue
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import threading


EXPORTS = {"FixtureTick": ("KERNEL32.dll", "GetTickCount64", None),
           "FixtureProcess": ("KERNEL32.dll", "GetCurrentProcessId", None),
           "FixtureOrdinal": ("iat-provider.dll", None, "17")}


def actor(image):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    with os.add_dll_directory(str(image.parent)):
        module = ctypes.WinDLL(str(image), use_last_error=True)
        get = kernel.GetProcAddress
        get.argtypes, get.restype = [wintypes.HMODULE, ctypes.c_char_p], ctypes.c_void_p
        birth = runpy.run_path(str(Path(__file__).with_name("test-image-loader-window.py")))["process_birth"]
        entries = {}
        for name in EXPORTS:
            address = get(module._handle, name.encode("ascii"))
            assert address
            raw = ctypes.string_at(address, 6)
            assert raw[:2] == b"\xff\x25", "fixture must expose the linker's six-byte AMD64 import thunk"
            entries[name] = [address - module._handle, raw.hex()]
        print(json.dumps(dict(pid=os.getpid(), birth=birth(kernel, kernel.GetCurrentProcess()),
                              base=module._handle, entries=entries)), flush=True)
        if sys.stdin.readline().strip() != "release":
            raise ValueError("missing owned target release")


def build_fixture(link, directory):
    def dll(name, exports, inputs):
        definition = directory / (name + ".def")
        definition.write_text("LIBRARY " + name + "\nEXPORTS\n" + "\n".join(exports) + "\n", encoding="ascii")
        subprocess.run([link, "/nologo", "/dll", "/noentry", "/machine:x64", "/debug:full", "/incremental:no",
                        "/def:" + definition.name, "/out:" + name + ".dll", *inputs],
                       cwd=directory, capture_output=True, timeout=60, check=True)
    dll("iat-provider", ["OrdinalTick=GetTickCount64 @17 NONAME"], ["kernel32.lib"])
    # A normal initialized data pointer gives the loader a base relocation when
    # it places the test image away from its preferred base.
    source = directory / "anchor.cpp"
    source.write_text('extern "C" __declspec(dllexport) int FixtureAnchor() { return 7; }\n'
                      'extern "C" __declspec(dllexport) int (*FixtureAnchorAddress)() = FixtureAnchor;\n', encoding="ascii")
    subprocess.run([str(Path(link).with_name("cl.exe")), "/nologo", "/c", "/Zl", "/Z7", "/O2", source.name],
                   cwd=directory, capture_output=True, check=True, timeout=60)
    dll("iat-test", ["FixtureTick=GetTickCount64", "FixtureProcess=GetCurrentProcessId", "FixtureOrdinal=OrdinalTick",
                     "FixtureForward=KERNEL32.GetCurrentProcessId"], ["anchor.obj", "kernel32.lib", "iat-provider.lib"])
    return directory / "iat-test.dll"


def main(options):
    exe = options.exe.resolve(strict=True)
    link = shutil.which(options.link)
    if not link:
        raise RuntimeError("Run from the x64 Native Tools command prompt or pass --link with the SDK LIB path set")
    checks = 0

    def check(ok, message):
        nonlocal checks
        if not ok:
            raise AssertionError(message)
        checks += 1

    def invoke(*arguments, code=0):
        p = subprocess.run([str(exe), *map(str, arguments)], capture_output=True, timeout=60)
        check(p.returncode == code, (arguments[0], p.returncode, code, p.stderr[-400:], p.stdout[-250:]))
        return p.stdout

    def offline(action, *args, code=0):
        return json.loads(invoke("--offline", "!kmon", action, *args, "/json", code=code))

    def replay(path, pin, name, *case, code=0):
        return offline("replay-image-source", path, pin, *case, "/iat:" + name, code=code)

    with tempfile.TemporaryDirectory(prefix="iat-replay-") as temp:
        store = options.store.resolve() if options.store else Path(temp) / "store"
        check(not store.exists(), "the test requires a new private store")
        check(offline("init-store", store, "/acl-only")["root_acl_verified"], "private archive")
        with tempfile.TemporaryDirectory(prefix="owned-iat-", dir=temp) as direct:
            work = Path(direct)
            dll = build_fixture(link, work)
            with subprocess.Popen([sys.executable, "-B", __file__, "--actor", str(dll)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                ready = queue.Queue()
                threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
                try:
                    owner = json.loads(ready.get(timeout=30))
                    birth = runpy.run_path(str(Path(__file__).with_name("test-image-loader-window.py")))["process_birth"]
                    check((owner["pid"], owner["birth"]) == (child.pid, birth(ctypes.WinDLL("kernel32"), int(child._handle))),
                          "parent independently verified the child's generation")
                    begin = min(item[0] for item in owner["entries"].values())
                    end = max(item[0] + 6 for item in owner["entries"].values())
                    def acquire(label, length):
                        case = work / label
                        raw = invoke("--verify-process-image", child.pid, owner["birth"], dll, hex(owner["base"]),
                                     hex(begin), length, case, "--allow-residency")
                        report = work / (label + ".json")
                        report.write_bytes(raw)
                        return case, report, hashlib.sha256(raw).hexdigest()
                    case, report, pin = acquire("full", end - begin)
                    partial_case, partial_report, partial_pin = acquire("partial", 2)
                finally:
                    try:
                        _, err = child.communicate(b"release\n", timeout=15)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.communicate()
                        raise
                check(child.returncode == 0, ("target exit", err[-200:]))
            recipe = json.loads((case / "recipe.knverify").read_bytes())["payload"]["recipe"]
            baseline = offline("replay-image-source", report, pin, case)
            check(baseline["original_claim_matched"] and "iat_reference" not in baseline, "original replay contract")
            edges = {}
            for name, (module, function, ordinal) in EXPORTS.items():
                page = replay(report, pin, name, case)
                edge = page.pop("iat_reference")
                check(page == baseline and edge["status"] == "observed" and edge["relation"] == "references",
                      ("relation from the original claim", name, edge))
                rva, observed = owner["entries"][name]
                slot = rva + 6 + struct.unpack_from("<i", bytes.fromhex(observed), 2)[0]
                check(int(edge["image_base"]) == owner["base"] and int(edge["instruction_rva"]) == rva and
                      edge["instruction_hex"] == observed and int(edge["iat_slot_rva"]) == slot, "target's own instruction bytes")
                check((edge["import_module"].lower(), edge["import_name"], edge["import_ordinal"]) ==
                      (module.lower(), function, ordinal), "linker-declared import")
                payload = recipe["payload"]
                check(edge["recipe_sha256"] == recipe["recipe_sha256"] and edge["reference_sha256"] == hashlib.sha256(dll.read_bytes()).hexdigest() and
                      edge["claim_file_sha256"] == hashlib.sha256((case / "recipe.knverify").read_bytes()).hexdigest() and
                      edge["operation_id"] == payload["read_set"]["operation_id"] and
                      edge["address_space_id"] == payload["read_set"]["address_space_id"], "exact operation and reference")
                reads = {row["sequence"]: row for row in payload["read_set"]["reads"]}
                check(bool(edge["byte_receipts"]), "source read provenance")
                for receipt in edge["byte_receipts"]:
                    row = reads[receipt["sequence"]]
                    original = row["read"]
                    offset = owner["base"] + rva - int(row["address"])
                    data = bytes.fromhex("".join(span["bytes_hex"] for span in original["spans"]))
                    check(offset >= 0 and data[offset:offset + 6].hex() == observed and
                          receipt["started_tick"] == original["started_tick"] and receipt["ended_tick"] == original["ended_tick"],
                          "receipt resolves to independently observed original bytes and interval")
                check(not any(edge[key] for key in ("instruction_reread", "slot_value_evaluated", "execution_observed",
                                                    "mapping_lifetime_bound")), "single code read and declared slot")
                edges[name] = edge
            for name in ("FixtureForward", "fixturetick", "Absent"):
                edge = replay(report, pin, name, case)["iat_reference"]
                check(edge["relation"] is None and edge["reason"] == "export_instruction_unavailable", "no local export boundary")
            edge = replay(report, pin, "FixtureAnchor", case)["iat_reference"]
            check(edge["reason"] == "unsupported_export_instruction" and edge["relation"] is None, "ordinary exported function")
            for name in EXPORTS:
                edge = replay(partial_report, partial_pin, name, partial_case)["iat_reference"]
                check(edge["relation"] is None and edge["reason"] == "instruction_outside_capture", "truncated original range")
            wrong = replay(report, "0" * 64, "FixtureTick", case, code=1)
            check(wrong["status"] == "report_digest_mismatch" and wrong["iat_reference"] is None, "report substitution")
            wrong = replay(report, pin, "FixtureTick", partial_case, code=1)
            check(wrong["status"] == "image_case_mismatch" and wrong["iat_reference"] is None, "other acquisition of same process")
            for selector in ("/iat:", "/iat:" + "x" * 256, "/iat:invalid name"):
                invoke("--offline", "!kmon", "replay-image-source", report, pin, case, selector, "/json", code=2)
            saved = offline("journal-image-source", report, pin, store, 1, case)
            check(saved["closed"] and saved["indexed"], "committed archive")
        managed = store / saved["report_path"]
        for name, edge in edges.items():
            check(replay(managed, pin, name)["iat_reference"] == edge, "same relation after direct files and target disappeared")
        claim = store / saved["capture_path"]
        reference, = (store / "image-references").glob("*.knblob")
        for path in (managed, claim, reference):
            before = path.read_bytes()
            with path.open("r+b") as stream:
                result = subprocess.run([str(exe), "--offline", "!kmon", "replay-image-source", str(managed), pin,
                                         str(claim), "/iat:FixtureTick", "/json"], stdout=stream, stderr=subprocess.PIPE, timeout=60)
            check(result.returncode == 2 and path.read_bytes() == before, "redirected output protected original evidence")
    print(f"image IAT references: {checks} checks passed after owned target exit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--link", default="link.exe", help="Microsoft x64 linker")
    parser.add_argument("--store", type=Path, help="retain the verified cases in a new private store")
    parser.add_argument("--actor", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.actor:
        actor(args.actor)
    elif args.exe:
        main(args)
    else:
        parser.error("--exe is required")
