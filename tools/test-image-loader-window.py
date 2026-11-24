"""Exercise loader-instance correlation with an owned DLL, a private trace and the installed native CLI."""
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
import threading
import time
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
    expected = (code,) if isinstance(code, int) else code
    assert p.returncode in expected, (p.returncode, p.stdout[:850], p.stderr[:500])
    return p.stdout


def loader_command(exe, row):
    case, pin, _, trace, trace_pin = row
    return [exe, "--etl-image-lifetime", trace, "--sha256", trace_pin, "--capture", case, "--recipe-sha256", pin]


def managed_capture_name(case):
    digest = sha(Path(case) / "recipe.knverify")
    return f"image-captures/capture-1-{digest}.kncapture"


def sign_recordings(root, sessions, openssl, private):
    signing = runpy.run_path(str(Path(__file__).with_name("test-etl-capture-statement.py")))
    for role in ("capture_controller", "archive_witness"):
        # This directory inherits the ACL of the initialized private store.
        work = root / ("signer-" + uuid.uuid4().hex)
        work.mkdir()
        keydir = work / "key"
        try:
            signer = signing["Signer"](openssl, keydir)
            with (root / (role + ".hex")).open("x", encoding="ascii") as point:
                point.write(signer.point)
            for trace, session in sessions.items():
                context = None
                if role == "capture_controller":
                    context = dict(session_id=session, se_system_profile_privilege_enabled=None,
                                   system_trace_enable_flags=0 if private else None)
                claims = signing["statement"](trace, context)
                with (root / f"{trace.stem}-{role}.knetlstatement").open("xb") as out:
                    out.write(signer.token(claims) + b"\r\n")
        finally:
            if keydir.exists():
                for name in ("ephemeral.pem", "public.pem", "input", "signature.der"):
                    (keydir / name).unlink(missing_ok=True)
                keydir.rmdir()
            work.rmdir()


def study(exe, root, capture_only, private_capturer, openssl):
    # The native init-store sets the ACL before the session records any image or process names.
    assert not root.exists()
    assert json.loads(run([exe, "--offline", "!kmon", "init-store", root, "/acl-only", "/json"]))["root_acl_verified"]
    dll = root / "kn-owned-version.dll"
    system = Path(os.environ["SystemRoot"]) / "System32"
    system_id = uuid.uuid4()
    session = "KnLiveDbg-Image-" + system_id.hex
    etl = root / "loader.etl"
    logman = system / "logman.exe"
    started = False
    copied = None
    cases = []
    sessions = {}
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
                    if openssl:
                        session_id = str(uuid.uuid4() if private_capturer else system_id)
                        sessions[local_etl] = session_id
                        if private_capturer:
                            program = [private_capturer, "--private-session", "{" + session_id + "}", local_etl]
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
    plan = {"private": bool(private_capturer), "cases": [(str(p), pin, actor, str(log), sha(log)) for p, pin, actor, log in cases],
            "managed_capture": managed_capture_name(cases[0][0])}
    if openssl:
        plan["sessions"] = {trace.name: session for trace, session in sessions.items()}
    with (root / "trial.json").open("x", encoding="utf-8") as out:
        json.dump(plan, out)
    if openssl:
        sign_recordings(root, sessions, openssl, bool(private_capturer))
    for index, row in enumerate(plan["cases"]):
        data = run(loader_command(exe, row), (0, 1))
        retain_original_report(root / f"result-{index}.json", data)
    archived = json.loads(run([exe, "--offline", "!kmon", "journal-image", cases[0][0], root, "1", "/json"]))
    assert archived["status"] == "archived" and Path(archived["capture_path"]) == Path(plan["managed_capture"])
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
    statement = folder / "controller.knetlstatement"
    output = folder / "output"
    test = args.copy()
    test[2], test[6] = trace, case
    try:
        for original, copy in ((Path(args[2]), trace), (Path(args[6]) / claim.name, claim), (Path(args[6]) / reference.name, reference)):
            shutil.copyfile(original, copy)
        protected = [trace, claim, reference]
        checked = [*test, "--check-page", hashlib.sha256(expected).hexdigest()]
        recorded_statement = root / (Path(args[2]).stem + "-capture_controller.knetlstatement")
        if recorded_statement.is_file():
            shutil.copyfile(recorded_statement, statement)
            protected.append(statement)
            checked += ["--capture-statement", statement, "capture_controller", (root / "capture_controller.hex").read_text(encoding="ascii")]
        for source in protected:
            pin = sha(source)
            os.link(source, output)
            try:
                for command in ([checked] if source == statement else [test, checked]):
                    with output.open("ab", buffering=0) as stream:
                        p = subprocess.run(command, stdout=stream, stderr=subprocess.PIPE, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
                    assert p.returncode == 2 and sha(source) == pin
            finally:
                output.unlink()
        with output.open("xb") as stream:
            p = subprocess.run(test, stdout=stream, stderr=subprocess.PIPE, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
        assert p.returncode == 1 and output.read_bytes() == expected
        original_time = output.stat().st_mtime_ns
        try:
            retain_original_report(output, expected + b"\n")
        except ValueError:
            pass
        else:
            raise AssertionError("A different report was accepted at the original path")
        assert output.read_bytes() == expected and output.stat().st_mtime_ns == original_time
        assert run(test + ["--invalid"], 2) == b""
        claim.write_bytes(b"{")
        error_page = run(test, 1)
        assert json.loads(error_page)["issue"] == "original_claim_unavailable"
        rejected = json.loads(run([*test, "--check-page", hashlib.sha256(error_page).hexdigest(), *checked[len(test) + 2:]], 1))
        assert rejected["status"] == "original_claim_unavailable" and rejected["page_bytes_match"] is None
        assert not rejected["original_claim_reproduced"] and not rejected["read_window_in_attested_etl"]
    finally:
        for owned in (output, trace, claim, reference, statement):
            owned.unlink(missing_ok=True)
        case.rmdir()
        folder.rmdir()


def statement_options(root, trace, role):
    return ["--capture-statement", root / f"{trace.stem}-{role}.knetlstatement", role,
            (root / (role + ".hex")).read_text(encoding="ascii")]


def retain_original_report(path, data):
    if not path.exists():
        pending = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
        try:
            with pending.open("xb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            try:
                # Windows rename publishes the complete file only if the final name is free.
                pending.rename(path)
            except FileExistsError:
                pass
        finally:
            pending.unlink(missing_ok=True)
    return original_report_pin(path, data)


def original_report_pin(path, data):
    # A concurrent Windows rename can briefly deny a CRT reader delete sharing.
    for attempt in range(5):
        try:
            original = path.read_bytes()
            break
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.01 * (attempt + 1))
    if original != data:
        raise ValueError("The new reader did not reproduce the retained report")
    return hashlib.sha256(original).hexdigest()


def check_replay(args, data, pin, root, trial, code):
    report = json.loads(data)
    base = [*args, "--check-page", pin.upper()]
    expected = json.loads(run(base, code))
    publication = json.loads((Path(args[6]) / "recipe.knverify").read_bytes())
    assert expected["schema"] == "kn.image_loader_window_replay.v1" and expected["status"] == "matched"
    assert expected["replayed_page_sha256"] == expected["expected_page_sha256"] == pin and expected["page_bytes_match"]
    assert expected["claim_publication_sha256"] == publication["publication_sha256"] and expected["original_claim_reproduced"]
    for key in ("etl_sha256", "recipe_sha256", "original_claim_sha256", "reference_sha256"):
        assert expected[key] == report[key]
    assert (expected["source_status"], expected["source_issue"]) == (report["status"], report["issue"])
    assert expected["capture_statement"] is None and not expected["read_window_in_attested_etl"]
    wrong = hashlib.sha256(data.rstrip(b"\n") + b"\r\n").hexdigest()
    assert json.loads(run([*args, "--check-page", wrong], 1))["status"] == "page_mismatch"
    for i in (4, 8):
        bad = base.copy()
        bad[i] = "0" * 64
        result = json.loads(run(bad, 1))
        assert result["page_bytes_match"] is None and result["source_status"] is None and not result["read_window_in_attested_etl"]
    trace = Path(args[2])
    session = trial.get("sessions", {}).get(trace.name)
    if session is None:
        return base
    for role, other in (("capture_controller", "archive_witness"), ("archive_witness", "capture_controller")):
        options = statement_options(root, trace, role)
        statement, point = options[1], options[3]
        receipt = json.loads(run([*base, *options], code))
        auth = receipt["capture_statement"]
        assert receipt["page_bytes_match"] and receipt["status"] == "matched" and receipt["read_window_in_attested_etl"]
        assert receipt["source_status"] == report["status"] and not any(receipt[k] for k in
            ("execution_observed", "continuous_mapping_proven", "collector_authenticated"))
        assert auth["bound_to_replayed_page"] and auth["signature_verified"] and auth["role_matches"] and auth["etl_identity_matches"]
        assert auth["trusted_key_sha256"] == hashlib.sha256(bytes.fromhex(point)).hexdigest() and auth["statement_file_sha256"] == sha(statement)
        assert auth["capture_controller_statement_authenticated"] == (role == "capture_controller")
        assert auth["claims"]["session_id"] == (session if role == "capture_controller" else None)
        for bad_options, reason in (([*options[:2], other, point], "signer_role_mismatch"),
                                    ([*options[:3], (root / (other + ".hex")).read_text(encoding="ascii")], "signature_rejected"),
                                    ([options[0], root / "absent.knetlstatement", role, point], "statement_unavailable")):
            bad = json.loads(run([*base, *bad_options], 1))
            assert bad["status"] == "capture_statement_rejected" and bad["page_bytes_match"] and not bad["read_window_in_attested_etl"]
            assert bad["capture_statement"]["status"] == reason and bad["capture_statement"]["claims"] is None
        stale = json.loads(run([*args, *options, "--check-page", wrong], 1))
        assert stale["status"] == "page_mismatch" and stale["capture_statement"]["signature_verified"]
        assert not stale["read_window_in_attested_etl"] and stale["capture_statement"]["claims"] is None
        assert run([*args, *options], 2) == b""
    return [*base, *statement_options(root, trace, "capture_controller")]


def verify(exe, root, private_capturer):
    trial = json.loads((root / "trial.json").read_bytes())
    managed_path = root / managed_capture_name(trial["cases"][0][0])
    if "managed_capture" in trial:
        assert root / trial["managed_capture"] == managed_path
    saved_reports = [root / f"result-{index}.json" for index in range(len(trial["cases"]))]
    has_baseline = "managed_capture" in trial or managed_path.is_file() or any(path.is_file() for path in saved_reports)
    if not has_baseline:
        print("This historical capture-only trial has no saved report. Checking freshly generated reports.")
    reports = []
    for row, saved in zip(trial["cases"], saved_reports):
        case, pin, actor, name, trace_pin = row
        trace = Path(name)
        assert sha(trace) == trace_pin
        args = loader_command(exe, row)
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
        report_pin = original_report_pin(saved, data) if has_baseline else hashlib.sha256(data).hexdigest()
        checked = check_replay(args, data, report_pin, root, trial, code)
        if not reports:
            if has_baseline:
                managed = args.copy()
                managed[6] = managed_path
                assert run(managed, code) == data
                assert run([*managed, *checked[len(args):]], code) == run(checked, code)
            if trial["private"]:
                check_output_files(args, report, root, data)
        reports.append(report)
        for i in (4, 8):
            wrong = args.copy()
            wrong[i] = "0" * 64
            failure = json.loads(run(wrong, 1))
            assert not failure["recorded_loader_interval"]
    assert reports[0]["target_generation"] == reports[1]["target_generation"]
    if not trial["private"]:
        assert int(reports[0]["next_image"]["event"]["qpc"]) < int(reports[1]["previous_image"]["event"]["qpc"])
    elif trial.get("sessions"):
        # Two independently recorded files contain the same target at the same base in this trial.
        first, second = trial["cases"]
        point = (root / "capture_controller.hex").read_text(encoding="ascii")
        first_statement = root / (Path(first[3]).stem + "-capture_controller.knetlstatement")
        options = ["--capture-statement", first_statement, "capture_controller", point]
        args = [exe, "--etl-image-lifetime", first[3], "--sha256", first[4], "--capture", second[0], "--recipe-sha256", second[1]]
        missing = run(args, 1)
        assert json.loads(missing)["issue"] == "capture_marker_missing"
        receipt = json.loads(run([*args, "--check-page", hashlib.sha256(missing).hexdigest(), *options], 1))
        assert receipt["status"] == "matched" and receipt["source_issue"] == "capture_marker_missing"
        assert receipt["capture_statement"]["capture_controller_statement_authenticated"] and not receipt["read_window_in_attested_etl"]
        args[2], args[4] = second[3], second[4]
        rejected = json.loads(run([*args, "--check-page", sha(root / "result-1.json"), *options], 1))
        assert rejected["status"] == "capture_statement_rejected" and rejected["page_bytes_match"]
        assert rejected["capture_statement"]["status"] == "etl_identity_mismatch" and not rejected["read_window_in_attested_etl"]
    assert reports[0]["collector_generation"] != reports[1]["collector_generation"]
    print("Checked two captures after target exit and source removal. Tracing mode:", "private" if trial["private"] else "system")


if __name__ == "__main__":
    options = argparse.ArgumentParser(description=__doc__)
    options.add_argument("--child", type=Path)
    options.add_argument("--exe", type=Path)
    options.add_argument("--root", type=Path)
    options.add_argument("--private-capturer", type=Path, help="test helper that records its real marker in an in-process session")
    options.add_argument("--capture-only", action="store_true")
    options.add_argument("--openssl", type=Path, help="issue controller and archive statements for newly recorded trials")
    options.add_argument("--verify-existing", action="store_true")
    args = options.parse_args()
    if args.child:
        child(args.child)
    elif args.exe and args.root:
        if args.verify_existing:
            verify(args.exe.resolve(), args.root.resolve(), args.private_capturer)
        else:
            study(args.exe.resolve(), args.root.resolve(), args.capture_only, args.private_capturer,
                  args.openssl.resolve(strict=True) if args.openssl else None)
    else:
        options.error("supply --exe and an owned trial root")
