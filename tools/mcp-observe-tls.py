"""MCP stdio client for a single HTTPS retained-evidence listener."""

import argparse
import http.client
import ipaddress
import json
import math
import os
import re
import ssl
import sys


LIMIT = 1024 * 1024


def endpoint(value):
    match = re.fullmatch(r"https://([0-9.]+):([1-9][0-9]{0,4})/mcp/?", value)
    if match:
        host, port = match.groups()
        address = ipaddress.IPv4Address(host)
        first = address.packed[0]
        if str(address) == host and 0 < first < 224 and (first != 127 or host == "127.0.0.1") and int(port) <= 65535:
            return host, int(port)
    raise ValueError("expected one HTTPS unicast IPv4 address, port and /mcp path")


def permitted(method, params):
    if method == "tools/call":
        return params.get("name") in ("timeline.query", "operations.get")
    if method == "resources/read":
        return params.get("uri") == "kn://capabilities"
    return method in ("initialize", "notifications/initialized", "ping", "tools/list", "resources/list",
                      "resources/templates/list", "prompts/list")


def rpc_error(identity, code, message):
    return {"jsonrpc": "2.0", "id": identity, "error": {"code": code, "message": message}}


def decode_json(data):
    def finite_number(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return value

    def invalid_constant(_):
        raise ValueError("invalid JSON number")

    return json.loads(data.decode("utf-8"), parse_constant=invalid_constant, parse_float=finite_number)


class ObserveClient:
    def __init__(self, url, token, ca_file=None):
        self.host, self.port = endpoint(url)
        if not re.fullmatch(r"[0-9a-f]{64}", token):
            raise ValueError("set KNLIVEDBG_TOKEN to the assigned client bearer")
        self.authorization = "Bearer " + token
        self.session = None
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        if ca_file:
            self.context.load_verify_locations(cafile=ca_file)
        else:
            self.context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        self.context.set_alpn_protocols(["http/1.1"])

    def request(self, message):
        if not isinstance(message, dict):
            return rpc_error(None, -32600, "expected a JSON-RPC request")
        method, params, identity = message.get("method"), message.get("params", {}), message.get("id")
        notification = "id" not in message
        if (message.get("jsonrpc") != "2.0" or not isinstance(method, str) or not isinstance(params, dict)
                or (not notification and type(identity) not in (int, str))):
            return rpc_error(None, -32600, "invalid JSON-RPC request")
        if not permitted(method, params) or (notification != (method == "notifications/initialized")):
            return None if notification else rpc_error(identity, -32601, "method outside retained-evidence access")
        if method == "initialize":
            self.session = None
        elif not self.session:
            return None if notification else rpc_error(identity, -32000, "initialize the HTTPS session first")

        headers = {"Authorization": self.authorization, "Content-Type": "application/json", "Accept": "application/json"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=45)
        try:
            # One POST to the selected authority. Never follow a Location or replay a failed request.
            body = json.dumps(message, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(body) > LIMIT:
                raise ValueError("request exceeds limit")
            conn.request("POST", "/mcp/", body, headers)
            response = conn.getresponse()
            if notification and response.status == 202:
                return None
            if response.status != 200:
                return None if notification else rpc_error(identity, -32000, f"HTTPS endpoint returned HTTP {response.status}")
            payload = response.read(LIMIT + 1)
            if len(payload) > LIMIT:
                raise ValueError("response exceeds limit")
            reply = decode_json(payload)
            if (not isinstance(reply, dict) or reply.get("jsonrpc") != "2.0" or type(reply.get("id")) is not type(identity)
                    or reply["id"] != identity or (("result" in reply) == ("error" in reply))):
                raise ValueError("invalid JSON-RPC response")
            if method == "initialize" and "result" in reply:
                session = response.getheader("Mcp-Session-Id", "")
                if not re.fullmatch(r"[0-9a-f]{32}", session):
                    raise ValueError("invalid session header")
                self.session = session
            return None if notification else reply
        except (ValueError, OSError, http.client.HTTPException, RecursionError):
            return None if notification else rpc_error(identity, -32000, "HTTPS request failed; check trust, endpoint and session")
        finally:
            conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--ca-file", default=os.environ.get("KNLIVEDBG_TLS_CA"))
    args = parser.parse_args()
    try:
        client = ObserveClient(args.endpoint, os.environ.get("KNLIVEDBG_TOKEN", ""), args.ca_file)
    except (ValueError, OSError):
        parser.exit(2, "Invalid scoped HTTPS endpoint, bearer or CA configuration.\n")
    while line := sys.stdin.buffer.readline(LIMIT + 1):
        if len(line) > LIMIT:
            parser.exit(2, "MCP stdio frame exceeds 1 MiB.\n")
        try:
            reply = client.request(decode_json(line))
        except (ValueError, RecursionError):
            reply = rpc_error(None, -32700, "invalid JSON")
        if reply is not None:
            sys.stdout.buffer.write(json.dumps(reply, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n")
            sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
