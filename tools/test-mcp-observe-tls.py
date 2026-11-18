"""Exercise the scoped HTTPS bridge and the product's HTTP.sys binding boundary on loopback."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import runpy
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading


TOOLS = Path(__file__).resolve().parent
CLIENT = TOOLS / "mcp-observe-tls.py"
client_module = runpy.run_path(str(CLIENT))
fixture = runpy.run_path(str(TOOLS / "test-mcp-operation-recovery.py"))
ObserveClient = client_module["ObserveClient"]


def rpc(method, params=None):
    return {"jsonrpc": "2.0", "id": 7, "method": method, "params": params or {}}


def certificates(directory, openssl):
    def run(*args):
        subprocess.run([openssl, *args], cwd=directory, capture_output=True, check=True)

    common = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
    run("req", "-x509", *common, "-days", "1", "-subj", "/CN=fixture CA", "-keyout", "ca.key", "-out", "ca.pem",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, san in (("valid", "127.0.0.1"), ("other", "192.0.2.10")):
        run("req", "-new", *common, "-subj", "/CN=fixture.invalid", "-keyout", name + ".key", "-out", name + ".csr")
        ext = directory / (name + ".ext")
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                       f"extendedKeyUsage=serverAuth\nsubjectAltName=IP:{san}\n", encoding="ascii")
        run("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-days", "1", "-extfile", str(ext), "-out", name + ".pem")


@contextmanager
def endpoint_fixture(directory, token, cert=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method = message["method"]
            self.server.seen.append((self.path, method, self.headers.get("Authorization") == "Bearer " + token,
                                     self.headers.get("Mcp-Session-Id")))
            self.send_response(self.server.code if self.server.code != 200 else (202 if "id" not in message else 200))
            if self.server.location:
                self.send_header("Location", self.server.location)
            if method == "initialize":
                self.send_header("Mcp-Session-Id", self.server.session)
            payload = (json.dumps({"id": message["id"], "jsonrpc": "2.0", "result": {"method": method}}).encode()
                       if "id" in message else b"")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.seen, server.code, server.location, server.session = [], 200, "", secrets.token_hex(16)
        server.url = f"{'https' if cert else 'http'}://127.0.0.1:{server.server_port}/mcp"
        if cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(directory / (cert + ".pem"), directory / (cert + ".key"))
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def exercise_client(directory, openssl):
    certificates(directory, openssl)
    token, ca = secrets.token_hex(32), directory / "ca.pem"
    with (endpoint_fixture(directory, token, "valid") as trusted, endpoint_fixture(directory, token, "valid") as other_trusted,
          endpoint_fixture(directory, token, "other") as wrong_name, endpoint_fixture(directory, token) as plaintext):
        for url in (plaintext.url, trusted.url.replace("127.0.0.1", "127.1"), trusted.url + "?x=1",
                    trusted.url + "#x", trusted.url.replace("127.0.0.1", "user@127.0.0.1"),
                    trusted.url.replace("127.0.0.1", "0.0.0.0"), trusted.url.replace("127.0.0.1", "127.0.0.1%00")):
            try:
                ObserveClient(url, token, ca)
            except ValueError:
                continue
            raise AssertionError("invalid authority accepted")
        assert "error" in ObserveClient(trusted.url, token).request(rpc("initialize"))
        assert "error" in ObserveClient(wrong_name.url, token, ca).request(rpc("initialize"))
        assert not trusted.seen and not wrong_name.seen
        client = ObserveClient(trusted.url, token, ca)
        for status in (301, 302, 303, 307, 308):
            for destination in (plaintext.url, other_trusted.url):
                trusted.code, trusted.location = status, destination
                assert "error" in client.request(rpc("initialize")) and client.session is None
        assert len(trusted.seen) == 10 and not plaintext.seen and not other_trusted.seen
        trusted.code, trusted.location = 200, ""
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        messages = [rpc("initialize"), notification, rpc("resources/read", {"uri": "kn://capabilities"}),
                    rpc("tools/call", {"name": "timeline.query"}), rpc("tools/call", {"name": "operations.get"}),
                    rpc("tools/call", {"name": "fixture.unlisted"}), rpc("resources/read", {"uri": "kn://private"})]
        data = "".join(json.dumps(m) + "\n" for m in messages).encode()
        env = dict(os.environ, KNLIVEDBG_TOKEN=token, KNLIVEDBG_TLS_CA=str(ca), HTTPS_PROXY=plaintext.url, NO_PROXY="",
                   PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"], SSLKEYLOGFILE=str(directory / "keylog"))
        bridge = TOOLS / "mcp-bridge.ps1"
        ps = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", bridge]
        descriptor = directory / "endpoint.json"
        exact = trusted.url + "/"
        fields = {"transport": "https", "url": exact, "remote_url": "", "client_url": exact, "bind": "127.0.0.1",
                  "port": trusted.server_port, "write": False, "token_source": "principal"}
        descriptor.write_text(json.dumps(fields), encoding="utf-8")
        for command in ([sys.executable, "-I", "-B", CLIENT, "--endpoint", trusted.url],
                        [*ps, "-TlsEndpoint", trusted.url], [*ps, "-EndpointPath", descriptor, "-PreferRemote"]):
            trusted.seen.clear()
            run = subprocess.run(command, input=data, capture_output=True, env=env, timeout=30)
            assert run.returncode == 0, "stdio bridge failed to start"
            replies = [json.loads(line) for line in run.stdout.splitlines()]
            assert ["error" in reply for reply in replies] == [False] * 4 + [True, True]
            assert len(trusted.seen) == 5 and all(s[0] == "/mcp/" and s[2] for s in trusted.seen)
            assert [s[3] for s in trusted.seen] == [None] + [trusted.session] * 4
            assert token.encode() not in run.stdout + run.stderr
        for changed in ({"transport": "http"}, {"transport": ""}, {"url": plaintext.url}, {"client_url": plaintext.url},
                        {"remote_url": plaintext.url}, {"token_source": "password"}, {"write": True}):
            descriptor.write_text(json.dumps(dict(fields, **changed)), encoding="utf-8")
            run = subprocess.run([*ps, "-EndpointPath", descriptor, "-PrintEndpoint"], capture_output=True, env=env, timeout=15)
            assert run.returncode != 0 and token.encode() not in run.stdout + run.stderr
        assert not (directory / "keylog").exists() and not plaintext.seen and not wrong_name.seen and not other_trusted.seen
    print("verified TLS stdio session and retained reads; untrusted CA, wrong IP, ten redirects and off-scope requests denied")


def exercise_product(exe, directory, native_port, ca):
    recovery = subprocess.run([exe, "--self-test", "mcp-journal-transport-fixture", directory],
                              input=secrets.token_urlsafe(32) + "\n", text=True, capture_output=True, timeout=30)
    assert recovery.returncode == 0 and "transport journal isolation and recovery passed" in recovery.stdout
    print("native TLS and loopback journals recovered source and target receipts only in their original transport")
    token, other = secrets.token_hex(32), secrets.token_hex(32)
    fingerprints = [hashlib.sha256(key.encode()).hexdigest() for key in (token, other)]
    password = secrets.token_urlsafe(32)
    grants = list(zip(fingerprints, ["alpha", "beta"]))
    root = directory / "journal"
    server = fixture["Listener"](exe, root, password, grants=grants, tls=True, port=native_port)
    try:
        marker = server.lines.get(timeout=30)
        if native_port is None:
            assert marker.startswith("unavailable: exact HTTP.sys SSL certificate binding unavailable"), marker
            assert server.proc.wait(timeout=15) == 1 and not (directory / "journal").exists()
            print("product refused an unprovisioned HTTPS port before journal creation; no listener survived")
            return
        assert marker == "ready", marker
        url = f"https://127.0.0.1:{native_port}/mcp"
        alice, bob = (ObserveClient(url, key, ca) for key in (token, other))
        for client in (alice, bob):
            assert "result" in client.request(rpc("initialize"))
        assert alice.session != bob.session
        assert "error" in ObserveClient(url, secrets.token_hex(32), ca).request(rpc("initialize"))
        clear = http.client.HTTPConnection("127.0.0.1", native_port, timeout=5)
        try:
            clear.request("POST", "/mcp/", json.dumps(rpc("initialize")), {"Content-Type": "application/json"})
            assert clear.getresponse().status >= 400
        except (OSError, http.client.HTTPException):
            pass
        finally:
            clear.close()
        caps = alice.request(rpc("resources/read", {"uri": "kn://capabilities"}))
        policy = json.loads(caps["result"]["contents"][0]["text"])
        assert policy["transport"] == "https" and policy["evidence_source"] == "alpha"
        for extra in ({"Origin": "https://127.0.0.1"}, {"Host": "example.invalid"}):
            conn = http.client.HTTPSConnection("127.0.0.1", native_port, context=alice.context, timeout=5)
            try:
                conn.request("POST", "/mcp/", b"{}", dict(extra, Authorization="Bearer " + token))
                assert conn.getresponse().status in (400, 403, 404)
            finally:
                conn.close()
        with ThreadPoolExecutor(1) as pool:
            query = pool.submit(alice.request, rpc("tools/call", {"name": "timeline.query", "arguments": {}}))
            queued = server.cmd("queued")
            identity = queued.split()[1]
            assert server.cmd("dispatch") == "dispatched " + identity and server.cmd("return") == "returned"
            result = query.result(timeout=45)["result"]
            assert not result["isError"] and result["_meta"]["knlivedbg/operation"]["operation_id"] == identity
        lookup = rpc("tools/call", {"name": "operations.get", "arguments": {"operation_id": identity}})
        receipt = alice.request(lookup)["result"]["structuredContent"]
        assert receipt["state"] == "succeeded" and receipt["journal"]["approved_scope"] == "https_observe_source"
        assert bob.request(lookup)["result"]["structuredContent"]["state"] == "not_retained"
        print("verified native HTTP.sys TLS, scoped evidence, receipt isolation and Host/Origin rejection")
    finally:
        server.close()
    restarted = fixture["Listener"](exe, root, password, grants=grants, tls=True, port=native_port)
    try:
        assert restarted.lines.get(timeout=30) == "ready"
        for key, expected in ((token, "succeeded"), (other, "not_retained")):
            client = ObserveClient(url, key, ca)
            assert "result" in client.request(rpc("initialize"))
            receipt = client.request(lookup)["result"]["structuredContent"]
            assert receipt["state"] == expected
            if key == token:
                assert receipt["journal"]["recovered"] and receipt["journal"]["approved_scope"] == "https_observe_source"
        print("native TLS restart recovered the original principal's receipt")
    finally:
        restarted.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--openssl", default=shutil.which("openssl"))
    parser.add_argument("--native-port", type=int, help="pre-provisioned loopback HTTP.sys HTTPS port")
    parser.add_argument("--ca-file", help="CA for the pre-provisioned native listener")
    args = parser.parse_args()
    if not args.openssl:
        parser.error("supply --openssl to generate the temporary fixture certificates")
    with tempfile.TemporaryDirectory(prefix="kn-observe-tls-") as tmp:
        directory = Path(tmp)
        exercise_client(directory, args.openssl)
        exercise_product(args.exe.resolve(), directory, args.native_port, args.ca_file)


if __name__ == "__main__":
    main()
