"""Check saved snapshot boot comparisons against Windows CNG and the current OS boot GUID."""
import argparse
import ctypes as ct
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def os_boot_guid():
    query = ct.WinDLL("ntdll").NtQuerySystemInformation
    query.argtypes = [w.ULONG, w.LPVOID, w.ULONG, ct.POINTER(w.ULONG)]
    query.restype = w.LONG
    buf, used = ct.create_string_buffer(64), w.ULONG()
    assert query(90, buf, len(buf), ct.byref(used)) == 0 and used.value >= 16
    return buf.raw[:16].hex()


class Protection:
    def __init__(self):
        ncrypt = ct.WinDLL("ncrypt")
        ptr = ct.POINTER
        handle = w.HANDLE

        def api(name, types):
            function = getattr(ncrypt, name)
            function.argtypes = types
            function.restype = w.LONG
            return function

        self.create = api("NCryptCreateProtectionDescriptor", [w.LPCWSTR, w.DWORD, ptr(handle)])
        self.protect = api("NCryptProtectSecret", [handle, w.DWORD, handle, w.ULONG, handle, handle, ptr(handle), ptr(w.ULONG)])
        self.unprotect = api("NCryptUnprotectSecret", [ptr(handle), w.DWORD, handle, w.ULONG, handle, handle, ptr(handle), ptr(w.ULONG)])
        self.info = api("NCryptGetProtectionDescriptorInfo", [handle, handle, w.DWORD, ptr(handle)])
        self.close = api("NCryptCloseProtectionDescriptor", [handle])
        self.free = ct.WinDLL("kernel32").LocalFree
        self.free.argtypes = [handle]
        self.free.restype = handle

    def decode(self, blob):
        descriptor, result, rule, length = w.HANDLE(), w.HANDLE(), w.HANDLE(), w.ULONG()
        try:
            assert self.unprotect(ct.byref(descriptor), 64, blob, len(blob), None, None, ct.byref(result), ct.byref(length)) == 0
            assert self.info(descriptor, None, 1, ct.byref(rule)) == 0
            return ct.wstring_at(rule).replace(" ", ""), ct.string_at(result, length.value)
        finally:
            self.free(rule)
            self.free(result)
            if descriptor:
                self.close(descriptor)

    def alternate_policy(self, message, policy):
        descriptor, result, length = w.HANDLE(), w.HANDLE(), w.ULONG()
        try:
            assert self.create(policy, 0, ct.byref(descriptor)) == 0
            assert self.protect(descriptor, 64, message, len(message), None, None, ct.byref(result), ct.byref(length)) == 0
            return ct.string_at(result, length.value)
        finally:
            self.free(result)
            if descriptor:
                self.close(descriptor)


def exercise(helper, folder, exe=None):
    def run(*args, code=0):
        p = subprocess.run([helper, *args], capture_output=True, timeout=30)
        assert p.returncode == code, (args[0], p.returncode, p.stderr)
        return p.stdout.decode("ascii").split()

    before, after = folder / "before.json", folder / "after.json"
    run("policy-check")
    existing = folder / "existing.json"
    existing.write_bytes(b"snapshot-size-fixture")
    run("oversize", existing)
    assert existing.read_bytes() == b"snapshot-size-fixture"
    run("capture", before, "before")
    run("capture", after, "after")
    protection = Protection()
    original = after.read_bytes()
    parsed = json.loads(original)
    token = parsed["local_boot_receipt"].encode("ascii")
    member = b'  "local_boot_receipt":"' + token + b'",\n'
    assert original.startswith(b"{\n" + member)
    plain = original.replace(member, b"", 1)
    digest = hashlib.sha256(plain.decode("utf-8").encode("utf-16-le")).hexdigest()
    descriptor, message = protection.decode(bytes.fromhex(token.decode()))
    assert descriptor == "LOCAL=userANDLOCAL=machine" and message == ("kn.snapshot.local-boot.v1:" + digest).encode()
    old = json.loads(before.read_bytes())
    assert old["boot_id"] == parsed["boot_id"] == os_boot_guid()
    assert old["process_inventory"][0]["create_time"] != parsed["process_inventory"][0]["create_time"]
    assert old["local_boot_receipt"] != parsed["local_boot_receipt"]
    probe = folder / "renamed.json"
    cases = 0
    offline_cases = 0

    def offline(left, right, *options, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
        return subprocess.run([exe, "--offline", "!diff", left, right, *options], stdout=stdout, stderr=stderr, timeout=60)

    def check(data, source, basis="origin_unverified"):
        nonlocal cases, offline_cases
        probe.write_bytes(data)
        qualified = basis == "local_boot_receipts"
        for action in ("diff", "session-option"):
            assert run(action, before, probe) == [basis, str(int(qualified)), "3" if qualified else "0", "local_receipt", source]
            cases += 1
        if exe:
            output = offline(before, probe, "/summary", "/json")
            assert output.returncode == 0, (output.returncode, output.stdout, output.stderr)
            report = json.loads(output.stdout)
            assert report == dict(schema="kn.saved_snapshot_diff.v1", status="compared",
                                  baseline_sha256=hashlib.sha256(before.read_bytes()).hexdigest(),
                                  current_sha256=hashlib.sha256(data).hexdigest(), baseline_boot_source="local_receipt",
                                  current_boot_source=source, same_boot=qualified, boot_basis=basis, added=0,
                                  escalated=3 if qualified else 0, removed=0, high=0), report
            offline_cases += 1

    check(original, "local_receipt", "local_boot_receipts")
    check(plain, "receipt_missing")
    check(plain.replace(b'"boot_id":"' + parsed["boot_id"].encode(), b'"boot_id":"boot-filetime:0x1234'), "receipt_missing")
    for data in (original.replace(b'"label":"after"', b'"label":"other"'), original.replace(b'"display":"fixture"', b'"display":"other"', 1),
                 original + b" ", original.replace(b"\n", b"\r\n"), original.replace(token, old["local_boot_receipt"].encode(), 1),
                 original.replace(token, b"0" * 8194, 1), original.replace(token, b"", 1),
                 original.replace(token[-2:] + b'",\n', (b"00" if token[-2:] != b"00" else b"01") + b'",\n', 1),
                 original.replace(b'"' + token + b'"', b"null", 1)):
        assert data != original
        check(data, "receipt_unverified")

    for policy in ("LOCAL=user", "LOCAL=machine", "LOCAL=user OR LOCAL=machine"):
        alternate = protection.alternate_policy(message, policy)
        assert protection.decode(alternate)[1] == message
        check(original.replace(token, alternate.hex().encode(), 1), "receipt_unverified")

    probe.write_bytes(original.replace(member, member + member, 1))
    run("diff", before, probe, code=1)
    if exe:
        rejected = offline(before, probe, "/summary", "/json")
        assert rejected.returncode == 1 and json.loads(rejected.stdout)["reason"] == "invalid_current_snapshot"
        missing = offline(folder / "absent", after, "/summary", "/json")
        assert missing.returncode == 1 and json.loads(missing.stdout)["reason"] == "baseline_file_unavailable"
        assert offline(before, after, "/apply").returncode == 2
        alias = folder / "alias.json"
        os.link(before, alias)
        saved = before.read_bytes()
        for flags, stream in ((("/summary", "/json"), "stdout"), (("/apply",), "stderr")):
            with alias.open("ab") as sink:
                assert offline(before, after, *flags, **{stream: sink}).returncode == 2
            assert before.read_bytes() == saved
        offline_cases += 5
    rerecorded = folder / "rewritten.json"
    run("resave", after, rerecorded)
    check(rerecorded.read_bytes(), "receipt_missing")
    assert run("diff", after, after) == ["local_boot_receipts", "1", "0", "local_receipt", "local_receipt"]
    return cases, offline_cases


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True, help="compiled snapshot-boot-selftest.exe")
    parser.add_argument("--exe", type=Path, help="also exercise the product's offline summary")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        count, product = exercise(options.helper.resolve(), Path(temporary), options.exe.resolve() if options.exe else None)
    print(f"{count} saved-file comparisons and {product} product checks passed, including independent CNG decryption")
