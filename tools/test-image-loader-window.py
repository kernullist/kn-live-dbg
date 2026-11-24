"""Exercise loader-instance correlation with an owned DLL, a private trace and the installed native CLI."""
import argparse
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
import threading
import uuid
import xml.etree.ElementTree as ET


KERNEL = "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
MARKER = "{02a921c3-281c-47c3-a734-9b233a737d8d}"


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def child(path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryW.argtypes, kernel.LoadLibraryW.restype = [wintypes.LPCWSTR], wintypes.HMODULE
    kernel.FreeLibrary.argtypes = [wintypes.HMODULE]
    times = [wintypes.FILETIME() for _ in range(4)]
    assert kernel.GetProcessTimes(wintypes.HANDLE(-1), *(ctypes.byref(value) for value in times))
    birth = times[0].dwHighDateTime << 32 | times[0].dwLowDateTime
    for _ in range(2):
        base = kernel.LoadLibraryW(str(path))
        assert base, ctypes.get_last_error()
        try:
            print(json.dumps({"pid": os.getpid(), "birth": birth, "base": base}), flush=True)
            command = sys.stdin.readline().strip()
        finally:
            assert kernel.FreeLibrary(base)
        if command == "release":
            return
        assert command == "reload"


def run(args, code=0, cwd=None):
    p = subprocess.run(list(map(str, args)), capture_output=True, timeout=120, creationflags=subprocess.CREATE_NO_WINDOW, cwd=cwd)
    assert p.returncode == code, (p.returncode, p.stdout[:850], p.stderr[:500])
    return p.stdout


def study(exe, root, capture_only, private_capturer):
    # The native init-store sets the ACL before the session records any image or process names.
    assert not root.exists()
    assert json.loads(run([exe, "--offline", "!kmon", "init-store", root, "/acl-only", "/json"]))["root_acl_verified"]
    dll = root / "kn-owned-version.dll"
    system = Path(os.environ["SystemRoot"]) / "System32"
    session = "KnLiveDbg-Image-" + uuid.uuid4().hex
    etl = root / "loader.etl"
    logman = system / "logman.exe"
    started = False
    copied = None
    cases = []
    try:
        with (system / "version.dll").open("rb") as source, dll.open("xb") as dest:
            copied = os.fstat(dest.fileno())
            shutil.copyfileobj(source, dest)
        content = dll.read_bytes()
        pe = struct.unpack_from("<I", content, 0x3c)[0]
        rva = struct.unpack_from("<I", content, pe + 24 + 20)[0]  # PE32+ BaseOfCode
        assert rva > 0
        if not private_capturer:
            providers = root / "providers.txt"
            with providers.open("x", encoding="ascii") as out:
                out.write(KERNEL + " 0x50 5\n" + MARKER + " 0x1 5\n")
            try:
                run([logman, "create", "trace", session, "-pf", providers, "-ct", "perf", "-f", "bin", "-o", etl, "-ets"])
                started = True
            finally:
                providers.unlink()
        with subprocess.Popen([sys.executable, "-B", __file__, "--child", str(dll)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW) as target:
            ready = queue.Queue()
            def read_lines():
                for line in target.stdout:
                    ready.put(line)
                ready.put(None)
            threading.Thread(target=read_lines, daemon=True).start()
            try:
                for index in range(2):
                    line = ready.get(timeout=30)
                    assert line is not None, "owned DLL did not load"
                    actor = json.loads(line)
                    assert actor["pid"] == target.pid
                    case = root / ("capture-" + str(index))
                    local_etl = root / ("marker-" + str(index) + ".etl") if private_capturer else etl
                    program = [private_capturer, "--private", local_etl] if private_capturer else [exe, "--verify-process-image"]
                    args = [*program, actor["pid"], actor["birth"], dll, hex(actor["base"]),
                            hex(rva), "64", case, "--allow-residency", "--trace-loader"]
                    capture = json.loads(run(args))
                    assert capture["original_claim_recorded"] and capture["loader_marker_submitted"]
                    cases.append((case, capture["recipe_sha256"], actor, local_etl))
                    target.stdin.write("reload\n" if index == 0 else "release\n")
                    target.stdin.flush()
                assert target.wait(timeout=20) == 0
            finally:
                if target.poll() is None:
                    target.kill()
                    target.wait(timeout=20)
    finally:
        try:
            if started:
                run([logman, "stop", session, "-ets"])
        finally:
            if copied is not None and dll.exists():
                if not os.path.samestat(copied, dll.stat(follow_symlinks=False)):
                    raise RuntimeError("The disposable DLL name changed owner")
                dll.unlink()
    plan = {"private": bool(private_capturer), "cases": [(str(p), pin, actor, str(log), sha(log)) for p, pin, actor, log in cases]}
    (root / "trial.json").write_text(json.dumps(plan), encoding="utf-8")
    if not capture_only:
        verify(exe, root, private_capturer)


def check_windows_decoder(trace, report, root):
    # tracerpt independently exposes the raw clock and the collector's opaque payload.
    workspace = root / ("decoder-" + uuid.uuid4().hex)
    workspace.mkdir()
    xml = workspace / "events.xml"
    n = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    marker = report["marker"]
    wanted = {int(marker["record"]): (MARKER, marker)}
    if report["recorded_loader_interval"]:
        for point in (report["previous_image"]["event"], report["next_image"]["event"],
                      *(report[g][end] for g in ("collector_generation", "target_generation") for end in ("start", "end"))):
            wanted[int(point["record"])] = (KERNEL, point)
    try:
        tool = Path(os.environ["SystemRoot"]) / "System32/tracerpt.exe"
        run([tool, trace, "-o", xml, "-of", "XML", "-rts", "-y"], cwd=workspace)
        ordinal = 0
        for _, event in ET.iterparse(xml, events=("end",)):
            if event.tag != n + "Event":
                continue
            ordinal += 1
            if ordinal in wanted:
                guid, point = wanted.pop(ordinal)
                system = event.find(n + "System")
                assert system.find(n + "Provider").get("Guid").lower() == guid
                assert int(system.findtext(n + "EventID")) == int(point["id"])
                assert int(system.findtext(n + "Version")) == int(point["version"])
                assert int(system.find(n + "TimeCreated").get("RawTime")) == int(point["qpc"])
                if guid == MARKER:
                    assert int(system.find(n + "Execution").get("ProcessID")) == int(report["collector_generation"]["pid"])
                    data = bytes.fromhex(event.findtext(n + "BinaryEventData"))
                    digest, frequency, start, end = struct.unpack_from("<64sqqq", data)
                    assert digest.decode("ascii") == report["recipe_sha256"]
                    assert (frequency, start, end) == tuple(int(report[k]) for k in ("qpc_frequency", "capture_start_qpc", "capture_end_qpc"))
                    assert list(struct.iter_unpack("<qq", data[88:])) == [(int(r["start_qpc"]), int(r["end_qpc"])) for r in report["read_windows"]]
            event.clear()
        assert not wanted and ordinal == int(report["records_seen"])
    finally:
        xml.unlink(missing_ok=True)
        workspace.rmdir()


def check_output_files(args, report, root, expected):
    # Use disposable copies so a regression cannot alter the retained trial.
    folder = root / ("redirect-" + uuid.uuid4().hex)
    folder.mkdir()
    case = folder / "case"
    case.mkdir()
    trace = folder / "input.etl"
    claim = case / "recipe.knverify"
    reference = case / (report["reference_sha256"] + ".knblob")
    output = folder / "output"
    test = args.copy()
    test[2], test[6] = trace, case
    try:
        for original, copy in ((Path(args[2]), trace), (Path(args[6]) / claim.name, claim), (Path(args[6]) / reference.name, reference)):
            shutil.copyfile(original, copy)
        for source in (trace, claim, reference):
            pin = sha(source)
            os.link(source, output)
            try:
                with output.open("ab", buffering=0) as stream:
                    p = subprocess.run(test, stdout=stream, stderr=subprocess.PIPE, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
                assert p.returncode == 2 and sha(source) == pin
            finally:
                output.unlink()
        with output.open("xb") as stream:
            p = subprocess.run(test, stdout=stream, stderr=subprocess.PIPE, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
        assert p.returncode == 1 and output.read_bytes() == expected
        assert run(test + ["--invalid"], 2) == b""
    finally:
        for owned in (output, trace, claim, reference):
            owned.unlink(missing_ok=True)
        case.rmdir()
        folder.rmdir()


def verify(exe, root, private_capturer):
    trial = json.loads((root / "trial.json").read_bytes())
    reports = []
    for case, pin, actor, name, trace_pin in trial["cases"]:
        trace = Path(name)
        assert sha(trace) == trace_pin
        args = [exe, "--etl-image-lifetime", trace, "--sha256", trace_pin, "--capture", case, "--recipe-sha256", pin]
        code = int(trial["private"])
        data = run(args, code)
        report = json.loads(data)
        assert report["etl_sha256"] == trace_pin and report["recipe_sha256"] == pin and report["original_claim_reproduced"]
        if trial["private"]:
            assert report["issue"] == "process_generation_unavailable" and not report["recorded_loader_interval"]
            if private_capturer:
                print(run([private_capturer, "--controls", trace, case, pin]).decode("ascii").strip())
        else:
            assert report["status"] == "bracketed" and report["recorded_loader_interval"]
            assert int(report["previous_image"]["base"]) == int(report["next_image"]["base"]) == actor["base"]
            assert int(report["previous_image"]["event"]["qpc"]) < int(report["capture_start_qpc"])
            assert int(report["next_image"]["event"]["qpc"]) > int(report["capture_end_qpc"])
        assert not any(report[k] for k in ("continuous_mapping_proven", "execution_observed", "collector_authenticated", "current_state_known"))
        assert int(report["target_generation"]["creation_filetime"]) == actor["birth"]
        assert not report["loader_transitions"] and int(report["matching_markers"]) == 1
        assert len(report["read_windows"]) > 1
        check_windows_decoder(trace, report, root)
        assert run(args, code) == data
        if not reports:
            archived = json.loads(run([exe, "--offline", "!kmon", "journal-image", case, root, "1", "/json"]))
            assert archived["status"] == "archived"
            managed = args.copy()
            managed[6] = root / archived["capture_path"]
            assert run(managed, code) == data
            if trial["private"]:
                check_output_files(args, report, root, data)
        (root / ("result-" + str(len(reports)) + ".json")).write_bytes(data)
        reports.append(report)
        for i in (4, 8):
            wrong = args.copy()
            wrong[i] = "0" * 64
            failure = json.loads(run(wrong, 1))
            assert not failure["recorded_loader_interval"]
    assert reports[0]["target_generation"] == reports[1]["target_generation"]
    if not trial["private"]:
        assert int(reports[0]["next_image"]["event"]["qpc"]) < int(reports[1]["previous_image"]["event"]["qpc"])
    assert reports[0]["collector_generation"] != reports[1]["collector_generation"]
    print("Checked two captures after target exit and source removal. Tracing mode:", "private" if trial["private"] else "system")


if __name__ == "__main__":
    options = argparse.ArgumentParser(description=__doc__)
    options.add_argument("--child", type=Path)
    options.add_argument("--exe", type=Path)
    options.add_argument("--root", type=Path)
    options.add_argument("--private-capturer", type=Path, help="test helper that records its real marker in an in-process session")
    options.add_argument("--capture-only", action="store_true")
    options.add_argument("--verify-existing", action="store_true")
    args = options.parse_args()
    if args.child:
        child(args.child)
    elif args.exe and args.root:
        if args.verify_existing:
            verify(args.exe.resolve(), args.root.resolve(), args.private_capturer)
        else:
            study(args.exe.resolve(), args.root.resolve(), args.capture_only, args.private_capturer)
    else:
        options.error("supply --exe and an owned trial root")
