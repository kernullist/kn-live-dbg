"""Exercise private operation recovery through the product's loopback HTTP listener."""
import argparse
import ctypes
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Listener:
    def __init__(self, exe, root, password):
        self.port = free_port()
        self.password = password
        self.session = None
        self.proc = subprocess.Popen([exe, "--self-test", "mcp-journal-fixture", root, str(self.port)],
                                     cwd=root.parent, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self.read_output, daemon=True)
        self.reader.start()
        self.send(password)

    def read_output(self):
        for line in self.proc.stdout:
            self.lines.put(line.rstrip())
        self.lines.put(None)

    def send(self, command):
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()

    def cmd(self, command):
        self.send(command)
        return self.lines.get(timeout=25)

    def rpc(self, method, params=None, wrong_auth=False):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, separators=(",", ":"))
        token = "invalid-local-fixture-credential" if wrong_auth else self.password
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=45)
        try:
            conn.request("POST", "/mcp/", body, headers)
            response = conn.getresponse()
            data = response.read()
            if wrong_auth:
                assert response.status == 401
                return
            assert response.status == 200, response.status
            if method == "initialize":
                self.session = response.getheader("Mcp-Session-Id")
                assert self.session
            return json.loads(data)["result"]
        finally:
            conn.close()

    def lookup(self, identity):
        return self.rpc("tools/call", {"name": "operations.get", "arguments": {"operation_id": identity}})["structuredContent"]

    def budget(self):
        result = self.rpc("resources/read", {"uri": "kn://capabilities"})
        caps = json.loads(result["contents"][0]["text"])
        assert caps["operation_journal"] == "bounded_private_journal"
        return caps["observe_budget"]

    def begin(self, pool, name, args):
        future = pool.submit(self.rpc, "tools/call", {"name": name, "arguments": args})
        phase = self.cmd("queued")
        assert phase and re.fullmatch(r"queued [0-9a-f]{32}", phase), "admission checkpoint"
        return phase.split()[1], future

    def finish(self, pool, name="timeline.status", args=None):
        identity, future = self.begin(pool, name, args or {})
        assert self.cmd("dispatch") == "dispatched " + identity
        assert self.cmd("return") == "returned"
        result = future.result(timeout=45)
        assert not result["isError"]
        receipt = result["_meta"]["knlivedbg/operation"]
        assert receipt["operation_id"] == identity and receipt["journal"]["recovered"] is False
        return receipt

    def kill(self):
        self.proc.kill()
        self.proc.wait(timeout=15)

    def close(self):
        try:
            if self.proc.poll() is None:
                self.send("stop")
                self.proc.wait(timeout=10)
        finally:
            if self.proc.poll() is None:
                self.kill()
            self.reader.join(timeout=5)
            self.proc.stdin.close()
            self.proc.stdout.close()
        # HTTP.sys can release the registration after process exit.
        deadline = time.monotonic() + 5
        while True:
            try:
                connection = socket.create_connection(("127.0.0.1", self.port), timeout=3)
            except ConnectionRefusedError:
                break
            except TimeoutError:
                if time.monotonic() >= deadline:
                    raise AssertionError("fixture port release unverified")
                continue
            connection.close()
            assert time.monotonic() < deadline, "fixture port still accepts connections"
            time.sleep(0.05)


@contextmanager
def listener(exe, root, password, expected=True):
    server = Listener(exe, root, password)
    try:
        marker = server.lines.get(timeout=30)
        assert marker == ("ready" if expected else "unavailable"), ("listener startup", marker)
        if expected:
            server.rpc("initialize")
        else:
            assert server.proc.wait(timeout=15) == 1
        yield server
    finally:
        server.close()


def recovered(server, identity, state, phase):
    row = server.lookup(identity)
    assert row["operation_id"] == identity and row["state"] == state
    assert row["journal"]["recovered"] is True and row["journal"]["last_recorded_phase"] == phase
    assert row["journal"]["effect_verified_utc"] is None and not row["automatic_retry"] and not row["effects_verified"]
    return row


def verify_owned_plaintext(root, password, original, queued, args):
    """Independently read just the temporary fixture created by boundaries()."""
    class Blob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]

    def blob(data):
        buffer = ctypes.create_string_buffer(data)
        return Blob(len(data), ctypes.addressof(buffer)), buffer

    raw = (root / "operations.knmcpjournal").read_bytes()
    assert raw[:8] == b"KNMCPJ1\0" and int.from_bytes(raw[8:12], "little") == len(raw) - 12
    policy = json.loads((root / "store.knprivacy").read_bytes())
    salt = hashlib.sha256(("KnLiveDbg.observe.journal.v1\n" + policy["root_identity"] + "\n" + password).encode()).digest()
    sealed, sealed_buffer = blob(raw[12:])
    entropy, entropy_buffer = blob(salt)
    clear = Blob()
    decrypt = ctypes.WinDLL("crypt32", use_last_error=True).CryptUnprotectData
    decrypt.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(Blob)]
    decrypt.restype = ctypes.c_int
    assert decrypt(ctypes.byref(sealed), None, ctypes.byref(entropy), None, None, 1, ctypes.byref(clear)), ctypes.get_last_error()
    try:
        assert 0 < clear.size <= 1024 * 1024
        plaintext = ctypes.string_at(clear.data, clear.size)
    finally:
        ctypes.memset(clear.data, 0, clear.size)
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
        free(clear.data)
    header, key, *records = plaintext.splitlines()
    assert header == b"KnLiveDbg.observe.operations.1" and re.fullmatch(b"[0-9a-f]{64}", key)
    assert password.encode() not in plaintext and args["source"].encode() not in plaintext
    rows = [json.loads(line) for line in records]
    assert [(r["operation_id"], r["journal"]["last_recorded_phase"]) for r in rows] == [
        (original["operation_id"], "engine_returned"), (queued, "admitted")]
    assert all("structuredContent" not in r and "arguments" not in r and not r["result_payload_retained"] for r in rows)
    frame = b"tool\ntimeline.query\n" + json.dumps(args, separators=(",", ":")).encode()
    assert hmac.new(key, frame, hashlib.sha256).hexdigest() == original["journal"]["request_hmac_sha256"]
    assert hashlib.sha256(key).hexdigest()[:32] == original["journal"]["principal_id"]


def boundaries(exe, folder, pool):
    root, other = folder / "first private store", folder / "second"
    saved = root / "operations.knmcpjournal"
    password = secrets.token_urlsafe(24)
    canary = "journal-owned-filter-private"
    name, args = "timeline.query", {"limit": "1", "source": canary}
    with listener(exe, root, password) as active:
        with listener(exe, root, password, expected=False):
            pass
        active.rpc("tools/list", wrong_auth=True)
        complete = active.finish(pool, name, args)
        journal = complete["journal"]
        assert re.fullmatch("[0-9a-f]{64}", journal["request_hmac_sha256"])
        assert all(re.fullmatch("[0-9a-f]{32}", journal[k]) for k in ("target_generation", "principal_id"))
        assert all(int(journal[k]) > 0 for k in ("admitted_utc", "dispatched_utc", "engine_returned_utc"))
        assert journal["approved_scope"] == "loopback_observe" and complete["state"] == "succeeded"
        queued, unanswered = active.begin(pool, name, args)
        active.kill()
        try:
            unanswered.result(timeout=10)
        except (ConnectionError, http.client.RemoteDisconnected):
            pass
        else:
            raise AssertionError("queued client unexpectedly received a result")
    image = saved.read_bytes()
    verify_owned_plaintext(root, password, complete, queued, args)
    audit = (root / "fixture-audit.jsonl").read_text(encoding="utf-8")
    logged = [item["operation"] for line in audit.splitlines() if "operation" in (item := json.loads(line))]
    assert {"operation_id": complete["operation_id"], "state": "succeeded"} in logged
    assert all(set(op) == {"operation_id", "state"} for op in logged)
    assert all(private not in audit for private in (password, canary, journal["principal_id"],
                                                    journal["target_generation"], journal["request_hmac_sha256"]))
    assert image.startswith(b"KNMCPJ1\0") and len(image) < 1024 * 1024
    for private in (password, canary, complete["operation_id"], journal["request_hmac_sha256"], "timeline.query"):
        assert private.encode() not in image and private.encode("utf-16-le") not in image
    with listener(exe, root, secrets.token_urlsafe(24), expected=False):
        pass
    assert saved.read_bytes() == image
    with listener(exe, other, password) as unrelated:
        assert unrelated.lookup(queued)["state"] == "not_retained"
    other_file = other / "operations.knmcpjournal"
    other_file.write_bytes(image)
    with listener(exe, other, password, expected=False):
        pass
    assert other_file.read_bytes() == image
    with listener(exe, root, password) as active:
        prior = recovered(active, complete["operation_id"], "succeeded", "engine_returned")
        prior["journal"]["recovered"] = False
        assert prior == complete
        cancelled = recovered(active, queued, "cancelled_before_execution", "admitted")
        assert not cancelled["engine_dispatched"] and cancelled["operation_finished"] and not cancelled["engine_finished"]
        assert cancelled["finished_tick_ms"] is None and cancelled["journal"]["dispatched_utc"] is None
        assert cancelled["observe_charge"]["examined_events"] == cancelled["observe_charge"]["payload_utf8_bytes"] == 0
        assert active.budget()["admitted_calls"]["used"] == 0
        same = active.finish(pool, name, args)["journal"]
        assert same["request_hmac_sha256"] == journal["request_hmac_sha256"] and same["principal_id"] == journal["principal_id"]
        assert same["target_generation"] != journal["target_generation"]
        failed, pending = active.begin(pool, "ti.subscribe", {"action": "status"})
        assert active.cmd("dispatch") == "dispatched " + failed and active.cmd("return") == "returned"
        rejection = pending.result(timeout=15)
        assert rejection["isError"] and rejection["_meta"]["knlivedbg/operation"]["state"] == "failed"
        dispatched, waiter = active.begin(pool, name, {"limit": "1", "source": "different"})
        assert active.cmd("dispatch") == "dispatched " + dispatched
        timeout = waiter.result(timeout=45)["_meta"]["knlivedbg/operation"]
        assert timeout["state"] == "unknown_outcome" and timeout["operation_id"] == dispatched
        assert timeout["journal"]["request_hmac_sha256"] != same["request_hmac_sha256"]
        active.kill()
    with listener(exe, root, password) as active:
        failed_receipt = recovered(active, failed, "failed", "engine_returned")
        assert failed_receipt["engine_finished"] and failed_receipt["journal"]["engine_returned_utc"] is not None
        unknown = recovered(active, dispatched, "unknown_outcome", "dispatch_authorized")
        assert unknown["engine_dispatched"] and not unknown["engine_finished"] and not unknown["operation_finished"]
        assert unknown["observe_charge"]["examined_events"] is None and unknown["journal"]["engine_returned_utc"] is None
        assert active.budget()["admitted_calls"]["used"] == 0
        held, waiter = active.begin(pool, name, args)
        assert active.cmd("dispatch") == "dispatched " + held
        known = waiter.result(timeout=45)["_meta"]["knlivedbg/operation"]
        assert known["operation_id"] == held and known["state"] == "unknown_outcome"
        assert active.cmd("restart-held") == "restarted"
        active.session = None
        active.rpc("initialize")
        assert active.budget()["admitted_calls"]["used"] == 0
        recovered(active, held, "unknown_outcome", "dispatch_authorized")
        assert active.finish(pool)["journal"]["target_generation"] == known["journal"]["target_generation"]

    # A share-deny-delete handle prevents committing the next atomic replacement.
    for failure in ("admission", "dispatch", "completion"):
        with listener(exe, root, password) as active:
            if failure != "admission":
                identity, pending = active.begin(pool, name, args)
            if failure == "completion":
                assert active.cmd("dispatch") == "dispatched " + identity
            previous = saved.read_bytes()
            with saved.open("rb"):
                if failure == "admission":
                    reply = active.rpc("tools/call", {"name": name, "arguments": args})
                else:
                    assert active.cmd("dispatch" if failure == "dispatch" else "return") == ("refused" if failure == "dispatch" else "returned")
                    reply = pending.result(timeout=15)
            assert reply["isError"] and reply["structuredContent"]["status"] == "journal_unavailable"
            if failure == "admission":
                assert "_meta" not in reply
            else:
                assert reply["_meta"]["knlivedbg/operation"]["operation_id"] == identity
            assert saved.read_bytes() == previous
            assert active.lookup(dispatched)["status"] == "journal_unavailable"
        with listener(exe, root, password) as active:
            if failure == "dispatch":
                recovered(active, identity, "cancelled_before_execution", "admitted")
            if failure == "completion":
                recovered(active, identity, "unknown_outcome", "dispatch_authorized")

    original = saved.read_bytes()
    for invalid in (original[:-8], original[:12], original + b"x", b""):
        saved.write_bytes(invalid)
        with listener(exe, root, password, expected=False):
            pass
        assert saved.read_bytes() == invalid
    saved.write_bytes(original)
    alias = folder / "external-link"
    os.link(saved, alias)
    with listener(exe, root, password, expected=False):
        pass
    alias.unlink()
    saved.unlink()
    with listener(exe, root, password, expected=False):
        pass
    assert not saved.exists()
    print("process restart, real HTTP timeout, principal binding, corruption and three failed publication boundaries passed", flush=True)


def retention(exe, folder, pool):
    root, password, ids = folder / "retention", secrets.token_urlsafe(24), []
    for count in (128, 128, 1):
        with listener(exe, root, password) as active:
            for _ in range(count):
                ids.append(active.finish(pool)["operation_id"])
    with listener(exe, root, password) as active:
        assert len(set(ids)) == 257 and active.lookup(ids[0])["state"] == "not_retained"
        for identity in ids[1:]:
            recovered(active, identity, "succeeded", "engine_returned")
        assert active.budget()["admitted_calls"]["used"] == 0
    print("257 admissions across three listener lifetimes, oldest receipt evicted and 256 recovered", flush=True)


def late_return(exe, folder, pool):
    root, password = folder / "late", secrets.token_urlsafe(24)
    with listener(exe, root, password) as active:
        identity, pending = active.begin(pool, "timeline.status", {})
        assert active.cmd("dispatch") == "dispatched " + identity
        receipt = pending.result(timeout=45)["_meta"]["knlivedbg/operation"]
        assert receipt["operation_id"] == identity and receipt["state"] == "unknown_outcome"
        assert receipt["observe_charge"]["payload_utf8_bytes"] is None
        assert active.cmd("return") == "returned"
        settled = active.lookup(identity)
        assert settled["state"] == "succeeded" and settled["observe_charge"]["payload_utf8_bytes"] > 0
    with listener(exe, root, password) as restarted:
        after = recovered(restarted, identity, "succeeded", "engine_returned")
        after["journal"]["recovered"] = False
        assert after == settled
    print("late engine return recovered by the operation ID from the timed-out HTTP response", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="kn-mcp-journal-") as directory, ThreadPoolExecutor(max_workers=1) as pool:
        folder = Path(directory)
        boundaries(exe, folder, pool)
        late_return(exe, folder, pool)
        retention(exe, folder, pool)
    assert not folder.exists() and hashlib.sha256(exe.read_bytes()).hexdigest() == digest
    print("journal fixtures removed, product SHA-256", digest)


if __name__ == "__main__":
    main()
