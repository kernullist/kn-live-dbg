"""Exercise the one-shot operating modes through the shipped Windows executable."""

import argparse
import ctypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import runpy
import socket
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    exe = str(parser.parse_args().exe.resolve(strict=True))
    checks = 0

    with tempfile.TemporaryDirectory(prefix="kn-launch-") as folder:
        root = Path(folder)
        trace = root / "saved trace.kntrace"
        fixture = runpy.run_path(str(Path(__file__).with_name("test-execution-trace.py")))["fixture"]()
        trace.write_bytes(json.dumps(fixture, separators=(",", ":")).encode())
        digest = hashlib.sha256(trace.read_bytes()).hexdigest()

        def call(args, code=0, source=subprocess.DEVNULL):
            nonlocal checks
            with subprocess.Popen([exe, *args], cwd=root, stdin=source,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
                try:
                    out, err = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    raise
                assert proc.returncode == code, (args, proc.returncode, err[:300])
                row = json.loads(out)
                if "probe" in row:
                    assert row["probe"]["process_id"] == proc.pid
            checks += 1
            return row

        def denied(args, mode, code=5):
            row = call(args, code)
            assert row["schema"] == "kn.launch_authority.v1" and row["mode"] == mode
            assert row["status"] == ("blocked_by_policy" if code == 5 else "invalid_request")
            assert "PRIVATE-SENTINEL" not in json.dumps(row)

        legacy_caps = call(["--capabilities"])
        launch = next(c for c in legacy_caps["capabilities"]
                      if (c["domain"], c["operation"], c["backend"]) == ("session", "restricted_launch", "local_cli"))
        assert launch["availability"] == "not_probed" and launch["consistency"] == "one_shot"
        legacy_page = call(["--offline", "!kmon", "trace", str(trace), "/limit", "2"])
        env = os.environ.copy()
        env["PATH"] = str(Path(exe).parent) + os.pathsep + env["PATH"]
        example = subprocess.run('cmd.exe /d /c KnLiveDbg.exe --mode offline trace - /limit 2 < "saved trace.kntrace"',
                                 executable=env["COMSPEC"], cwd=root, env=env, capture_output=True, check=True, timeout=30)
        assert json.loads(example.stdout) == legacy_page
        checks += 1
        allowed = ["--help", "--capabilities", "trace -"]
        probe_args = ["--capabilities", "--probe", "--allow-residency"]
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.setblocking(False)
            address = f"127.0.0.1:{listener.getsockname()[1]}"
            for mode in ("offline", "observe"):
                prefix = ["--mode", mode]
                menu = call([*prefix, "--help"])
                expected = allowed + ([" ".join(probe_args)] if mode == "observe" else [])
                assert menu["status"] == "ready" and menu["mode"] == mode and menu["allowed_operations"] == expected
                assert call([*prefix, "--capabilities"]) == legacy_caps
                denied(prefix, mode, 2)
                for operation in (
                    ["--connect", address], ["remote", "on"], ["mcp", "on"], ["--cloak"],
                    ["--schema-worker"], ["--symbol-index-worker"], ["--self-test", "all"],
                    ["--offline", "!kmon", "init-store", str(root / "denied-store"), "/acl-only"],
                    ["--offline", "!kmon", "gc", str(root), "PRIVATE-SENTINEL", "/apply", "1"],
                    ["--crash-diagnose", str(trace), "--sha256", digest],
                    ["--io-lifecycle", "50", str(root)],
                    ["--wait-chain", "1", "1", "1", "1", "--corroborate", "2", "2", "2", "10"],
                    ["--wait-chain", "1", "1", "1", "1"], ["--verify-process-image"], ["write", "on"], ["!kmon", "on"], ["kdinit"],
                    ["--capabilities", "--probe"], ["trace", str(trace)], ["PRIVATE-SENTINEL"],
                ):
                    denied([*prefix, *operation], mode)
                assert not (root / "denied-store").exists()
                with trace.open("rb") as stream:
                    stream.seek(7)
                    first = call([*prefix, "trace", "-", "/limit", "2"], source=stream)
                    assert first == legacy_page and stream.tell() == 7
                    assert first["file_sha256"] == digest and first["samples_total"] == 5
                    assert len(first["samples"]) == 2 and not first["live_backend_opened"]
                    second = call([*prefix, "trace", "-", "/limit", "2", "/cursor", first["next_cursor"]], source=stream)
                    assert [x["sequence"] for x in second["samples"]] == ["3", "4"]
                    assert not second["execution_independently_verified"] and stream.tell() == 7
                    mismatch = call([*prefix, "trace", "-", "/limit", "1", "/cursor", first["next_cursor"]], 1, stream)
                    assert mismatch["status"] == "unavailable" and "cursor" in mismatch["error"]
                try:
                    connection, _ = listener.accept()
                except BlockingIOError:
                    pass
                else:
                    connection.close()
                    raise AssertionError("restricted command contacted the remote endpoint")

        denied(["--mode", "offline", *probe_args], "offline")
        denied(["--mode", "observe", *probe_args, "extra"], "observe")
        denied(["--mode", "offline", "--mode", "observe", *probe_args], None, 2)
        denied(["--help", "--mode", "offline"], None, 2)
        denied(["--capabilities", "--mode=observe"], None, 2)
        denied(["--self-test", "connect-argv", "--Mode", "offline"], None, 2)
        denied(["--mode"], None, 2)
        for value in ("collect", "lab", "", "PRIVATE-SENTINEL"):
            denied(["--mode", value, "--capabilities"], None)

        report = call(["--MODE", "Observe", *probe_args])
        probe = report["probe"]
        assert probe["scope"] == "owned_process_range_only" and probe["sample_bytes_matched"]
        assert probe["observer_actions"] == ["owned_process_handle_and_read"]
        assert probe["process_handle_attempted"] and probe["process_read_attempted"] and probe["process_read_may_change_residency"]
        assert not any(probe[k] for k in ("native_probe_attempted", "native_source_opened", "native_contract_passed",
                                          "driver_load_requested", "symbol_network_requested", "mutation_requested"))
        assert probe["probe_handles_closed"] and probe["process_id"] > 0
        read = probe["process_read"]
        assert read["requested_bytes"] == 32 and bytes.fromhex(read["spans"][0]["bytes_hex"]) == bytes(range(0x51, 0x71))
        assert probe["process_read_set"]["charged_source_calls"] == "1" and read["identity_revalidated"]
        assert read["side_effects_possible"]
        for entry in report["capabilities"]:
            if entry["backend"] == "native":
                expected = "unsupported" if entry["implementation"] == "unsupported" else "blocked_by_policy"
                assert entry["availability"] == expected and entry["availability_scope"] == "launch_policy"
                assert set(entry["probe_stages"].values()) == {"not_probed", "not_performed"}

        trace_args = ["--mode", "offline", "trace", "-"]
        assert call(trace_args, 1)["status"] == "unavailable"  # NUL device
        # Keep the writer open and silent. Inspecting a pipe as a regular file
        # would block before a parser could return a useful error.
        process = subprocess.Popen([exe, *trace_args], cwd=root, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert process.wait(timeout=10) == 1
            assert json.loads(process.stdout.read())["status"] == "unavailable"
            checks += 1
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
        create_file = ctypes.windll.kernel32.CreateFileW
        create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        create_file.restype = ctypes.c_void_p
        handle = create_file(str(trace), 0x80, 7, None, 3, 0, None)  # FILE_READ_ATTRIBUTES only
        assert handle != ctypes.c_void_p(-1).value
        with os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY), "rb") as metadata:
            assert call(trace_args, 1, metadata)["status"] == "unavailable"
        moved = root / "original.kntrace"
        handle = create_file(str(trace), 0x80000000, 7, None, 3, 0, None)  # GENERIC_READ, share delete
        assert handle != ctypes.c_void_p(-1).value
        with os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDONLY), "rb") as original:
            trace.rename(moved)
            trace.write_bytes(b"replacement")
            assert call(trace_args, source=original)["file_sha256"] == digest
        moved.replace(trace)
        with trace.open("r+b") as writable:
            assert call(trace_args, 1, writable)["status"] == "unavailable"
        set_attributes = ctypes.windll.kernel32.SetFileAttributesW
        set_attributes.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        set_attributes.restype = ctypes.c_int
        assert set_attributes(str(trace), 0x1000)  # FILE_ATTRIBUTE_OFFLINE
        try:
            assert trace.stat().st_file_attributes & 0x1000
            with trace.open("rb") as stream:
                assert call(trace_args, 1, stream)["status"] == "unavailable"
        finally:
            assert set_attributes(str(trace), 0x80)
        assert hashlib.sha256(trace.read_bytes()).hexdigest() == digest
        with Path(str(trace) + ":alternate").open("wb") as alternate:
            alternate.write(trace.read_bytes())
        with Path(str(trace) + ":alternate").open("rb") as alternate:
            assert call(trace_args, 1, alternate)["status"] == "unavailable"
        exact = trace.read_bytes().ljust(2 * 1024 * 1024, b" ")
        trace.write_bytes(exact)
        with trace.open("rb") as stream:
            assert call(trace_args, source=stream)["file_sha256"] == hashlib.sha256(exact).hexdigest()
        for content in (b"", b"\xff", exact + b" "):
            trace.write_bytes(content)
            with trace.open("rb") as stream:
                assert call(trace_args, 1, stream)["status"] == "unavailable"
        assert set(root.iterdir()) == {trace}
    print(f"restricted launch: {checks} CLI results checked; zero remote accepts; owned fixtures removed")


if __name__ == "__main__":
    main()
