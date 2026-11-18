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


def wire(port, authorization, session, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, separators=(",", ":"))
    headers = {"Authorization": authorization, "Content-Type": "application/json"}
    if session:
        headers["Mcp-Session-Id"] = session
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=45)
    try:
        conn.request("POST", "/mcp/", body, headers)
        response = conn.getresponse()
        data = response.read()
        return response.status, response.getheader("Mcp-Session-Id"), json.loads(data) if data else {}
    finally:
        conn.close()


class Listener:
    def __init__(self, exe, root, password, grants=(), durable=True, target_ttl=None, access=(), tls=False, port=None):
        self.port = free_port() if port is None else port
        self.password = password
        self.session = None
        options = ["--tls"] if tls else []
        for grant in grants:
            options.extend(("--principal" if len(grant) == 2 else "--principal-target", *grant))
        for fingerprint, permission in access:
            options.extend(("--principal-access", fingerprint, permission))
        if target_ttl is not None:
            options.extend(("--target-ttl", str(target_ttl)))
        self.proc = subprocess.Popen([exe, "--self-test", "mcp-journal-fixture", root if durable else "-", str(self.port), *options],
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
        token = "invalid-local-fixture-credential" if wrong_auth else self.password
        status, session, reply = wire(self.port, "Bearer " + token, self.session, method, params)
        if wrong_auth:
            assert status == 401
            return
        assert status == 200, status
        if method == "initialize":
            self.session = session
            assert self.session
        return reply["result"]

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
def listener(exe, root, password, expected=True, grants=(), durable=True, target_ttl=None, access=()):
    server = Listener(exe, root, password, grants, durable, target_ttl, access)
    try:
        marker = server.lines.get(timeout=30)
        assert marker == ("ready" if expected else "unavailable"), ("listener startup", marker)
        if expected and not grants:
            server.rpc("initialize")
        elif not expected:
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


def read_owned_journal(root, password, scoped=False):
    """Independently decrypt the controller's own temporary fixture."""
    class Blob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]

    def blob(data):
        buffer = ctypes.create_string_buffer(data)
        return Blob(len(data), ctypes.addressof(buffer)), buffer

    raw = (root / "operations.knmcpjournal").read_bytes()
    assert raw[:8] == b"KNMCPJ1\0" and int.from_bytes(raw[8:12], "little") == len(raw) - 12
    policy = json.loads((root / "store.knprivacy").read_bytes())
    domain = "KnLiveDbg.observe.source.journal.v1" if scoped else "KnLiveDbg.observe.journal.v1"
    salt = hashlib.sha256((domain + "\n" + policy["root_identity"] + "\n" + password).encode()).digest()
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
    assert password.encode() not in plaintext
    return plaintext, key, [json.loads(line) for line in records]


def verify_owned_plaintext(root, password, original, queued, args):
    plaintext, key, rows = read_owned_journal(root, password)
    assert args["source"].encode() not in plaintext
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


class SourceClient:
    def __init__(self, server, bearer):
        self.server, self.bearer, self.session = server, bearer, None
        self.call("initialize")

    def call(self, method, params=None):
        status, session, reply = wire(self.server.port, "Bearer " + self.bearer, self.session, method, params)
        assert status == 200
        if method == "initialize":
            assert session and session != self.session
            self.session = session
        else:
            assert session is None
        return reply

    def tool(self, name, args):
        return self.call("tools/call", {"name": name, "arguments": args})["result"]

    def lookup(self, identity):
        return self.tool("operations.get", {"operation_id": identity})["structuredContent"]

    def caps(self):
        reply = self.call("resources/read", {"uri": "kn://capabilities"})
        return json.loads(reply["result"]["contents"][0]["text"])

    def query(self, pool, args):
        pending = pool.submit(self.tool, "timeline.query", args)
        queued = self.server.cmd("queued")
        assert queued and re.fullmatch(r"queued [0-9a-f]{32}", queued)
        identity = queued.split()[1]
        assert self.server.cmd("dispatch") == "dispatched " + identity
        assert self.server.cmd("return") == "returned"
        result = pending.result(timeout=45)
        assert not result["isError"]
        receipt = result["_meta"]["knlivedbg/operation"]
        assert receipt["operation_id"] == identity and self.lookup(identity) == receipt
        return result["structuredContent"], receipt


def source_principals(exe, folder, pool, durable):
    root, unlock = folder / ("scoped" if durable else "volatile"), secrets.token_urlsafe(24)
    a, b, replacement = (secrets.token_hex(32) for _ in range(3))
    def grant(bearer, source):
        return hashlib.sha256(bearer.encode("ascii")).hexdigest(), source

    grants = [grant(a, "alpha"), grant(b, "beta")]
    with listener(exe, root, unlock, grants=grants, durable=durable) as active:
        alice, bob = SourceClient(active, a), SourceClient(active, b)
        assert alice.session != bob.session
        for invalid in ("Bearer " + unlock, "Bearer " + grants[0][0], a, "Bearer " + replacement):
            assert wire(active.port, invalid, alice.session, "tools/list") == (401, None, {})
        assert "error" in wire(active.port, "Bearer " + a, bob.session, "tools/list")[2]
        assert alice.call("tools/list")["result"] == alice.caps()["tools"]
        assert {t["name"] for t in alice.caps()["tools"]["tools"]} == {"timeline.query", "operations.get"}
        assert [r["uri"] for r in alice.call("resources/list")["result"]["resources"]] == ["kn://capabilities"]
        assert alice.call("prompts/list")["result"] == {"prompts": []}
        assert alice.caps()["scope"] == "observe_source" and alice.caps()["evidence_source"] == "alpha"
        baseline = bob.caps()["observe_budget"]
        assert baseline["admitted_calls"] == {"limit": 64, "used": 0, "remaining": 64}
        for name, args in (("graph.query", {}), ("timeline.status", {}), ("ti.subscribe", {}),
                           ("timeline.query", {"source": "Alpha"}), ("timeline.query", {"source": "alpha.more"}),
                           ("timeline.query", {"source": "beta"}), ("timeline.query", {"principal": "alpha"})):
            denied = alice.tool(name, args)
            assert denied["isError"] and "_meta" not in denied
        assert "error" in alice.call("resources/read", {"uri": "kn://session/info"})
        assert alice.caps()["observe_budget"] == baseline
        page, receipt = alice.query(pool, {"limit": "4"})
        assert page["schema"] == "kn.mcp_source_timeline.v1" and page["source"] == "alpha"
        assert page["returned"] == page["total_stored"] == 2
        assert [e["action"] for e in page["events"]] == ["fixture-5", "fixture-1"]
        assert all(set(e) == {"timestamp_filetime", "domain", "action", "pid", "tid", "target_pid"} for e in page["events"])
        assert not any(value in json.dumps(page) for value in ("fixture-private", "fixture-2", "fixture-3", "fixture-4"))
        assert receipt["observe_charge"]["examined_events"] == 2
        assert bob.caps()["observe_budget"] == baseline
        original_session = alice.session
        used = alice.caps()["observe_budget"]
        alice.call("initialize")
        assert "error" in wire(active.port, "Bearer " + a, original_session, "tools/list")[2]
        assert alice.caps()["observe_budget"] == used and bob.caps()["observe_budget"] == baseline
        other, b_receipt = bob.query(pool, {"source": "beta", "domain": "PROCESS", "pid": "2"})
        assert other["total_stored"] == other["returned"] == 1 and other["events"][0]["action"] == "fixture-2"
        assert b_receipt["observe_charge"]["examined_events"] == 1
        aid, bid = receipt["operation_id"], b_receipt["operation_id"]
        missing = bob.lookup(secrets.token_hex(16))
        def invisible(client, identity):
            assert client.lookup(identity) == dict(missing, operation_id=identity)
        assert missing["state"] == "not_retained" and not missing["outcome_known"]
        invisible(bob, aid)
        invisible(alice, bid)
        if not durable:
            assert active.cmd("evict") == "evicted"
            empty, charge = alice.query(pool, {"limit": "1"})
            assert empty["total_stored"] == 0 and not empty["events"] and charge["observe_charge"]["examined_events"] == 0
            survivor, _ = bob.query(pool, {"limit": "2"})
            assert survivor["total_stored"] == 1 and survivor["events"][0]["action"] is None
            assert active.cmd("clear") == "cleared"
            empty, _ = bob.query(pool, {"limit": "1"})
            assert empty["total_stored"] == 0 and not empty["events"]
            # Spend only Alice's requested-event share, then check her receipt
            # and Bob's engine admission after Alice's next request is denied.
            remaining = alice.caps()["observe_budget"]["requested_events"]["remaining"]
            while remaining:
                count = min(64, remaining)
                alice.query(pool, {"limit": str(count)})
                remaining -= count
            denial = alice.tool("timeline.query", {"limit": "1"})
            assert denial["isError"] and denial["structuredContent"]["dimension"] == "requested_events" and "_meta" not in denial
            assert alice.lookup(aid) == receipt
            bob.query(pool, {"limit": "1"})
        if durable:
            assert receipt["journal"]["approved_scope"] == "loopback_observe_source"
            assert receipt["journal"]["principal_id"] != b_receipt["journal"]["principal_id"]
    audit = (root / "fixture-audit.jsonl" if durable else folder / "fixture-audit.jsonl").read_text(encoding="utf-8-sig")
    assert all(secret not in audit for secret in (unlock, a, b, grants[0][0], grants[1][0], "fixture-private", "alpha", "beta"))
    if durable:
        clear, key, rows = read_owned_journal(root, unlock, scoped=True)
        assert all(s.encode() not in clear for s in (a, b, grants[0][0], grants[1][0], "alpha", "beta", "fixture-private"))
        assert [r["operation_id"] for r in rows] == [aid, bid]
        for row, (fingerprint, source), args in zip(rows, grants, ({"limit": "4"}, {"source": "beta", "domain": "PROCESS", "pid": "2"})):
            owner = hmac.new(key, f"grant.v1\n{fingerprint}\n{source}".encode(), hashlib.sha256).hexdigest()[:32]
            assert row["journal"]["principal_id"] == owner
            frame = (owner + "\ntool\ntimeline.query\n" + json.dumps(args, separators=(",", ":"))).encode()
            assert row["journal"]["request_hmac_sha256"] == hmac.new(key, frame, hashlib.sha256).hexdigest()
        # Reopening in shared-password mode cannot recover or replace scoped records.
        image = root / "operations.knmcpjournal"
        before = image.read_bytes()
        with listener(exe, root, unlock, expected=False):
            pass
        # A fresh directory distinguishes credential-reuse rejection from a
        # pre-existing journal that cannot be decrypted with this password.
        reused_secret_root = folder / "reject-client-as-unlock"
        with listener(exe, reused_secret_root, a, expected=False, grants=grants):
            pass
        assert not reused_secret_root.exists()
        assert image.read_bytes() == before
    with listener(exe, root, unlock, grants=list(reversed(grants)), durable=durable) as restarted:
        alice, bob = SourceClient(restarted, a), SourceClient(restarted, b)
        for client, identity in ((alice, aid), (bob, bid)):
            if durable:
                recovered(client, identity, "succeeded", "engine_returned")
            else:
                invisible(client, identity)
        invisible(alice, bid)
        invisible(bob, aid)
    if durable:
        for dispatch in (False, True):
            with listener(exe, root, unlock, grants=grants) as active:
                alice = SourceClient(active, a)
                pending = pool.submit(alice.tool, "timeline.query", {"limit": "1"})
                checkpoint = active.cmd("queued")
                assert re.fullmatch(r"queued [0-9a-f]{32}", checkpoint)
                interrupted = checkpoint.split()[1]
                if dispatch:
                    assert active.cmd("dispatch") == "dispatched " + interrupted
                active.kill()
                assert isinstance(pending.exception(timeout=15), (ConnectionError, http.client.RemoteDisconnected))
            with listener(exe, root, unlock, grants=grants) as restarted:
                alice, bob = SourceClient(restarted, a), SourceClient(restarted, b)
                recovered(alice, interrupted, "unknown_outcome" if dispatch else "cancelled_before_execution",
                          "dispatch_authorized" if dispatch else "admitted")
                invisible(bob, interrupted)
        with listener(exe, root, unlock, grants=[grant(a, "beta"), grant(replacement, "beta")]) as changed:
            assert wire(changed.port, "Bearer " + b, None, "initialize") == (401, None, {})
            for bearer in (a, replacement):
                client = SourceClient(changed, bearer)
                invisible(client, aid)
                invisible(client, bid)
        shared = folder / "scope-mode-boundary"
        with listener(exe, shared, unlock):
            pass
        with listener(exe, shared, unlock, expected=False, grants=grants):
            pass
        with listener(exe, shared, unlock):
            pass
    else:
        bearers = [secrets.token_hex(32) for _ in range(17)]
        many = [grant(bearer, "alpha") for bearer in bearers]
        with listener(exe, root, unlock, grants=many[:16], durable=False) as active:
            first, last = SourceClient(active, bearers[0]), SourceClient(active, bearers[15])
            assert first.caps()["observe_budget"]["admitted_calls"]["limit"] == 8
            _, theirs = first.query(pool, {"source": "", "limit": "1"})
            assert last.caps()["evidence_source"] == "alpha"
            invisible(last, theirs["operation_id"])
        extra = [token for fingerprint, source in many for token in ("--principal", fingerprint, source)]
        invalid = subprocess.run([exe, "--self-test", "mcp-journal-fixture", "-", str(free_port()), *extra],
                                 cwd=folder, input="", text=True, capture_output=True, timeout=15)
        assert invalid.returncode == 2 and "ready" not in invalid.stdout
    print("source grants: separate credentials, sessions, budgets, projected rows and owned receipts; durable =", durable, flush=True)


class TargetClient(SourceClient):
    def __init__(self, server, bearer):
        super().__init__(server, bearer)
        self.handle = self.caps()["target_session"]
        assert re.fullmatch("[0-9a-f]{32}", self.handle) and self.handle != self.session

    def renew(self):
        old = self.handle
        self.call("initialize")
        self.handle = self.caps()["target_session"]
        assert re.fullmatch("[0-9a-f]{32}", self.handle) and self.handle not in (old, self.session)

    def lookup(self, identity):
        return self.tool("operations.get", {"operation_id": identity, "target_session": self.handle})["structuredContent"]


def target_sessions(exe, folder, pool):
    root = folder / "targets"
    unlock, a, b, reader = (secrets.token_hex(32) for _ in range(4))
    fp, other, source_fp = (hashlib.sha256(value.encode()).hexdigest() for value in (a, b, reader))
    boot = "b" * 32
    grant = (fp, "ti", boot, "73", "100")
    grants = [grant, (other, "ti", boot, "73", "200"), (source_fp, "ti")]
    def denied(reply):
        assert reply["isError"] and reply["structuredContent"] == {
            "schema": "kn.mcp_authority.v1", "scope": "observe_target", "status": "target_session_unavailable"}
        assert "_meta" not in reply and "Header" not in json.dumps(reply)

    with listener(exe, root, unlock, grants=grants) as active:
        alice, bob, source = TargetClient(active, a), TargetClient(active, b), SourceClient(active, reader)
        handle = alice.handle
        caps = alice.caps()
        assert caps["scope"] == "observe_target" and caps["target_session_ttl_seconds"] == 300
        assert caps["tools"] == alice.call("tools/list")["result"]
        assert {t["name"] for t in caps["tools"]["tools"]} == {"timeline.query", "operations.get"}
        assert all("target_session" in t["inputSchema"]["required"] for t in caps["tools"]["tools"])
        assert "target_session" not in source.caps() and bob.handle != handle
        before = caps["observe_budget"]
        for invalid in ({}, {"target_session": bob.handle}, {"target_session": alice.session}, {"target_session": "bad"}):
            denied(alice.tool("timeline.query", invalid))
            denied(alice.tool("operations.get", dict(invalid, operation_id="d" * 32)))
        for args in ({"pid": "94"}, {"source": "TI"}, {"source": "beta"}, {"boot_id": boot}):
            blocked = alice.tool("timeline.query", dict(args, target_session=handle))
            assert blocked["isError"] and blocked["structuredContent"]["scope"] == "observe_target" and "_meta" not in blocked
        assert alice.caps()["observe_budget"] == before
        args = {"target_session": handle, "pid": "73", "limit": "4", "order": "oldest"}
        data, receipt = alice.query(pool, args)
        aid = receipt["operation_id"]
        assert data["schema"] == "kn.mcp_target_timeline.v1" and data["subject"] == "event_header_process"
        assert data["returned"] == data["total_stored"] == receipt["observe_charge"]["examined_events"] == 2
        assert [row["action"] for row in data["events"]] == ["HeaderA", "HeaderB"]
        assert all(set(row) == {"domain", "action", "timestamp_filetime", "pid", "tid"} and row["pid"] == 73 for row in data["events"])
        other_rows, bob_receipt = bob.query(pool, {"limit": "3", "target_session": bob.handle})
        assert [r["action"] for r in other_rows["events"]] == ["ReusedPid"]
        assert bob.lookup(aid)["state"] == source.lookup(aid)["state"] == "not_retained"
        assert alice.lookup(bob_receipt["operation_id"])["state"] == "not_retained"
        scoped, source_receipt = source.query(pool, {"limit": "16"})
        assert "Imported" in [r["action"] for r in scoped["events"]] and all("target_pid" in r for r in scoped["events"])
        after = alice.caps()["observe_budget"]
        alice.renew()
        assert alice.caps()["observe_budget"] == after and bob.caps()["target_session"] == bob.handle
        denied(alice.tool("operations.get", {"operation_id": aid, "target_session": handle}))
        assert alice.lookup(aid) == receipt
        assert active.cmd("evict") == "evicted"
        empty, charge = alice.query(pool, {"limit": "1", "target_session": alice.handle})
        assert empty["total_stored"] == charge["observe_charge"]["examined_events"] == 0 and empty["events"] == []
        assert active.cmd("clear") == "cleared"
        assert not bob.query(pool, {"limit": "1", "target_session": bob.handle})[0]["events"]
        secrets_used = (unlock, a, b, reader, fp, other, source_fp, boot, handle, alice.handle, bob.handle)

    clear, key, rows = read_owned_journal(root, unlock, scoped=True)
    audit = (root / "fixture-audit.jsonl").read_text(encoding="utf-8-sig")
    assert all(value.encode() not in clear and value not in audit for value in secrets_used)
    attempts = [json.loads(line) for line in audit.splitlines()]
    assert any(row["scope"] == "observe_target" and row["decision"] == "target_session_unavailable" for row in attempts)
    assert any(row["scope"] == "observe_source" and row.get("tool") == "timeline.query" for row in attempts)
    journal = rows[0]["journal"]
    def mac(frame):
        return hmac.new(key, frame.encode(), hashlib.sha256).hexdigest()
    owner = mac(f"grant.target.v1\n{fp}\nti\n{boot}\n73\n100")[:32]
    assert journal["approved_scope"] == "loopback_observe_target" and journal["principal_id"] == owner
    assert journal["target_generation"] == mac(f"target.v1\n{boot}\n73\n100")[:32]
    assert journal["request_hmac_sha256"] == mac(owner + "\ntool\ntimeline.query\n" + json.dumps(args, separators=(",", ":")))
    assert journal["effect_verified_utc"] is None
    with listener(exe, root, unlock, grants=[grant], target_ttl=3) as active:
        alice = TargetClient(active, a)
        assert alice.caps()["target_session_ttl_seconds"] == 3
        old = recovered(alice, aid, "succeeded", "engine_returned")["journal"]
        _, current = alice.query(pool, {"limit": "1", "target_session": alice.handle})
        assert old["controller_generation"] != current["journal"]["controller_generation"]
        assert old["target_generation"] == current["journal"]["target_generation"]
        for stage in ("queued", "popped", "read"):
            alice.renew()
            pending = pool.submit(alice.tool, "timeline.query", {"limit": "1", "target_session": alice.handle})
            checkpoint = active.cmd("queued")
            assert checkpoint and re.fullmatch(r"queued [0-9a-f]{32}", checkpoint)
            identity = checkpoint.split()[1]
            if stage != "queued":
                assert active.cmd("dispatch") == "dispatched " + identity
            if stage == "read":
                assert active.cmd("return-across-expiry") == "read-across-expiry"
            else:
                assert active.cmd("await-expiry") == "expired"
                denied(pending.result(timeout=5))  # expiry also releases the synchronous HTTP listener
                assert active.cmd("dispatch" if stage == "queued" else "return") == ("refused" if stage == "queued" else "returned")
            denied(pending.result(timeout=45))
            assert alice.caps()["target_session"] is None
            denied(alice.tool("operations.get", {"operation_id": identity, "target_session": alice.handle}))
            alice.renew()
            charge = alice.lookup(identity)
            assert charge["operation_finished"] and not charge["effects_verified"]
            assert charge["observe_charge"]["payload_utf8_bytes"] == 0
            assert charge["observe_charge"]["examined_events"] == (1 if stage == "read" else 0)
            assert charge["engine_dispatched"] == (stage != "queued")
    for changed in [(fp, "ti"), (fp, "ti", boot, "73", "200"), (fp, "ti", "c" * 32, "73", "100"),
                    (fp, "ti", boot, "94", "100"), (other, *grant[1:])]:
        with listener(exe, root, unlock, grants=[changed]) as active:
            client = (SourceClient if len(changed) == 2 else TargetClient)(active, b if changed[0] == other else a)
            assert client.lookup(aid)["state"] == "not_retained"
    with listener(exe, root, unlock, grants=[(source_fp, *grant[1:])]) as changed:
        narrowed = TargetClient(changed, reader)
        assert narrowed.lookup(source_receipt["operation_id"])["state"] == "not_retained"

    with listener(exe, folder / "volatile-targets", unlock, grants=[grant], durable=False) as active:
        volatile = TargetClient(active, a)
        data, transient = volatile.query(pool, {"limit": "3", "target_session": volatile.handle})
        assert len(data["events"]) == 2 and "journal" not in transient and "operation_journal" not in volatile.caps()
    with listener(exe, folder / "volatile-targets", unlock, grants=[grant], durable=False) as restarted:
        assert TargetClient(restarted, a).lookup(transient["operation_id"])["state"] == "not_retained"
    print("target sessions: PID reuse, other boots, peer roles, import, expiry at three boundaries and exact durable ownership passed", flush=True)


def resource_access(exe, folder, pool, previous=None):
    root, unlock = folder / "resource-access", secrets.token_hex(32)
    a, b, c = (secrets.token_hex(32) for _ in range(3))
    fp, op_fp, both_fp = (hashlib.sha256(value.encode()).hexdigest() for value in (a, b, c))
    grants = [(fp, "ti", "b" * 32, "73", "100"), (op_fp, "alpha"), (both_fp, "alpha")]
    policy = [(op_fp, "operations"), (fp, "evidence")]

    def begin(client, arguments):
        pending = pool.submit(client.tool, "timeline.query", arguments)
        checkpoint = client.server.cmd("queued")
        assert checkpoint and re.fullmatch(r"queued [0-9a-f]{32}", checkpoint)
        return checkpoint.split()[1], pending

    def no_receipt(reply, identity):
        encoded = json.dumps(reply)
        assert "_meta" not in reply and identity not in encoded
        assert "kn.mcp_operation.v1" not in encoded and "operation_id" not in encoded

    def names(client):
        catalog = client.call("tools/list")["result"]
        assert catalog == client.caps()["tools"]
        return {t["name"] for t in catalog["tools"]}

    with listener(previous or exe, root, unlock, grants=grants) as old:
        original = SourceClient(old, b)
        _, prior = original.query(pool, {"limit": "2"})
        if previous:
            assert "approved_access" not in prior["journal"]
    _, _, previous_rows = read_owned_journal(root, unlock, scoped=True)
    assert len(previous_rows) == 1

    with listener(exe, root, unlock, grants=grants, access=policy) as active:
        evidence, receipts, both = TargetClient(active, a), SourceClient(active, b), SourceClient(active, c)
        assert names(evidence) == {"timeline.query"} and names(receipts) == {"operations.get"}
        assert names(both) == {"timeline.query", "operations.get"}
        assert [client.caps()["observe_access"] for client in (evidence, receipts, both)] == ["evidence", "operations", "both"]
        assert "operation_journal" not in evidence.caps() and "observe_budget" not in receipts.caps()
        assert evidence.caps()["evidence_source"] == "ti" and "evidence_source" not in receipts.caps()
        assert "alpha" not in json.dumps(receipts.caps())
        assert receipts.caps()["operation_journal"] == "bounded_private_journal"
        for client in (evidence, both):
            assert client.caps()["observe_budget"]["admitted_calls"] == {"limit": 64, "used": 0, "remaining": 64}
        assert receipts.lookup(prior["operation_id"]) == previous_rows[0]
        blocked = receipts.tool("timeline.query", {"limit": "1"})
        assert blocked["isError"] and blocked["structuredContent"]["status"] == "blocked_by_policy" and "_meta" not in blocked
        assert "error" in receipts.call("resources/read", {"uri": "kn://ti/stats"})
        assert "error" in evidence.call("resources/read", {"uri": "kn://audit/tail"})

        args = {"limit": "4", "target_session": evidence.handle}
        admitted, pending = begin(evidence, args)
        assert active.cmd("dispatch") == "dispatched " + admitted and active.cmd("return") == "returned"
        reply = pending.result(timeout=15)
        no_receipt(reply, admitted)
        rows = reply["structuredContent"]
        assert not reply["isError"] and rows["schema"] == "kn.mcp_target_timeline.v1" and rows["total_stored"] == 2
        assert json.loads(reply["content"][0]["text"]) == rows and len(reply["content"]) == 1
        for identity in (admitted, prior["operation_id"], "bad"):
            blocked = evidence.tool("operations.get", {"operation_id": identity, "target_session": evidence.handle})
            assert blocked["isError"] and blocked["structuredContent"]["status"] == "blocked_by_policy"
            no_receipt(blocked, identity)
        assert receipts.lookup(admitted)["state"] == both.lookup(admitted)["state"] == "not_retained"
        before = evidence.caps()["observe_budget"]
        evidence.renew()
        assert names(evidence) == {"timeline.query"} and evidence.caps()["observe_budget"] == before
        _, other = both.query(pool, {"limit": "1"})
        assert other["journal"]["approved_access"] == "both"

        # Keep a dispatched, authorized read past the real HTTP deadline.
        late, pending = begin(evidence, dict(args, target_session=evidence.handle))
        assert active.cmd("dispatch") == "dispatched " + late
        timed_out = pending.result(timeout=45)
        assert timed_out["isError"] and "outcome unknown" in timed_out["content"][0]["text"]
        no_receipt(timed_out, late)
        assert active.cmd("return") == "returned"

        # Refuse replacement of the private image at terminal settlement.
        failed, pending = begin(evidence, dict(args, target_session=evidence.handle))
        assert active.cmd("dispatch") == "dispatched " + failed
        with (root / "operations.knmcpjournal").open("rb"):
            assert active.cmd("return") == "returned"
            failed_reply = pending.result(timeout=15)
        assert failed_reply["isError"] and failed_reply["structuredContent"]["status"] == "journal_unavailable"
        no_receipt(failed_reply, failed)
        token = evidence.handle

    audit = [json.loads(line) for line in (root / "fixture-audit.jsonl").read_text(encoding="utf-8-sig").splitlines()]
    assert any(row.get("observe_access") == "evidence" and row.get("operation", {}).get("operation_id") == admitted for row in audit)
    clear, _, rows = read_owned_journal(root, unlock, scoped=True)
    admissions = {row["operation_id"]: row for row in rows}
    assert admissions[prior["operation_id"]] == previous_rows[0]
    for identity in (admitted, late, failed):
        assert admissions[identity]["journal"]["approved_access"] == "evidence"
    for secret in (a, b, c, fp, op_fp, both_fp, token):
        assert secret.encode() not in clear and secret not in json.dumps(audit)

    with listener(exe, root, unlock, grants=[grants[0]], access=[(fp, "operations")]) as reopened:
        owner = TargetClient(reopened, a)
        assert names(owner) == {"operations.get"} and "observe_budget" not in owner.caps()
        assert "evidence_source" not in owner.caps() and grants[0][2] not in json.dumps(owner.caps())
        for identity in (admitted, late):
            row = recovered(owner, identity, "succeeded", "engine_returned")
            assert row["journal"]["approved_access"] == "evidence" and "events" not in row
        recovered(owner, failed, "unknown_outcome", "dispatch_authorized")
        assert owner.lookup(other["operation_id"])["state"] == "not_retained"
        foreign_handle = owner.tool("operations.get", {"operation_id": admitted, "target_session": token})
        assert foreign_handle["structuredContent"]["status"] == "target_session_unavailable"
        no_receipt(foreign_handle, admitted)
    with listener(exe, root, unlock, grants=[(fp, "ti")], access=[(fp, "operations")]) as changed:
        assert SourceClient(changed, a).lookup(admitted)["state"] == "not_retained"
    with listener(exe, folder / "volatile-access", unlock, grants=[grants[1]], durable=False, access=[(op_fp, "operations")]) as volatile:
        client = SourceClient(volatile, b)
        assert client.lookup(prior["operation_id"])["state"] == "not_retained"
        assert "observe_budget" not in client.caps() and "operation_journal" not in client.caps()
    with listener(exe, folder / "volatile-access", unlock, grants=[grants[1]], durable=False, access=[(op_fp, "evidence")]) as volatile:
        client = SourceClient(volatile, b)
        assert names(client) == {"timeline.query"} and client.caps()["observe_budget"]["admitted_calls"]["limit"] == 128
        identity, pending = begin(client, {"limit": "4"})
        assert volatile.cmd("dispatch") == "dispatched " + identity and volatile.cmd("return") == "returned"
        result = pending.result(timeout=15)
        assert result["structuredContent"]["schema"] == "kn.mcp_source_timeline.v1" and result["structuredContent"]["returned"] == 2
        no_receipt(result, identity)
    print("resource access: independent evidence and operation reads, receipt suppression, private audit, recovery and quota isolation passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--principals-only", action="store_true")
    parser.add_argument("--targets-only", action="store_true")
    parser.add_argument("--access-only", action="store_true")
    parser.add_argument("--previous-exe", type=Path, help="pre-access release binary for historical journal compatibility")
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="kn-mcp-journal-") as directory, ThreadPoolExecutor(max_workers=1) as pool:
        folder = Path(directory)
        if args.access_only or not (args.principals_only or args.targets_only):
            resource_access(exe, folder, pool, args.previous_exe.resolve(strict=True) if args.previous_exe else None)
        if not args.access_only:
            target_sessions(exe, folder, pool)
        if not (args.access_only or args.targets_only):
            source_principals(exe, folder, pool, durable=False)
            source_principals(exe, folder, pool, durable=True)
        if not (args.access_only or args.principals_only or args.targets_only):
            boundaries(exe, folder, pool)
            late_return(exe, folder, pool)
            retention(exe, folder, pool)
    assert not folder.exists() and hashlib.sha256(exe.read_bytes()).hexdigest() == digest
    print("journal fixtures removed, product SHA-256", digest)


if __name__ == "__main__":
    main()
