"""Owned Windows fixtures: independent ACL/EFS/identity checks and observed interruptions."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import importlib.util
import json
from pathlib import Path
import queue
import subprocess
import threading
import uuid

CHECKS = 0


def check(value, label):
    global CHECKS
    CHECKS += 1
    if not value:
        raise AssertionError(label)


k = c.WinDLL("kernel32", use_last_error=True)
a = c.WinDLL("advapi32", use_last_error=True)
P = c.c_void_p


def api(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn


open_file = api(k, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD, P, w.DWORD, w.DWORD, w.HANDLE)
close = api(k, "CloseHandle", w.BOOL, w.HANDLE)
free = api(k, "LocalFree", P, P)
attributes = api(k, "GetFileAttributesW", w.DWORD, w.LPCWSTR)
get_sd = api(a, "GetNamedSecurityInfoW", w.DWORD, w.LPWSTR, c.c_int, w.DWORD, P, P, P, P, P)
control = api(a, "GetSecurityDescriptorControl", w.BOOL, P, P, P)
get_ace = api(a, "GetAce", w.BOOL, P, w.DWORD, P)
sid_string = api(a, "ConvertSidToStringSidW", w.BOOL, P, P)
parse_sd = api(a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL, w.LPCWSTR, w.DWORD, P, P)
set_sd = api(a, "SetFileSecurityW", w.BOOL, w.LPCWSTR, w.DWORD, P)
decrypt = api(a, "DecryptFileW", w.BOOL, w.LPCWSTR, w.DWORD)
INVALID = c.c_void_p(-1).value


def sid(pointer):
    value = c.c_wchar_p()
    check(sid_string(pointer, c.byref(value)), "independent SID conversion")
    try:
        return value.value
    finally:
        free(c.cast(value, P))


def acl(path, principal, root=False):
    owner, dacl, descriptor = P(), P(), P()
    check(get_sd(str(path), 1, 5, c.byref(owner), None, c.byref(dacl), None, c.byref(descriptor)) == 0,
          "independent OS descriptor")
    try:
        ctl, revision = w.WORD(), w.DWORD()
        check(control(descriptor, c.byref(ctl), c.byref(revision)), "descriptor control")
        check(sid(owner) in ({principal} if root else {principal, "S-1-5-18", "S-1-5-32-544"}), "owner scope")
        if root:
            check(ctl.value & 0x1000, "root blocks parent ACL inheritance")
        count = c.c_ushort.from_address(dacl.value + 4).value
        found = set()
        check(count in (1, 2), "exact private ACE count")
        for i in range(count):
            entry = P()
            check(get_ace(dacl, i, c.byref(entry)), "read actual ACE")
            header = c.string_at(entry, 8)
            check(header[0] == 0 and int.from_bytes(header[4:8], "little") == 0x1F01FF, "allow full file access only")
            if path.is_dir():
                check(header[1] & 3 == 3, "directory propagates both container and object protection")
            found.add(sid(entry.value + 8))
        check(found == {principal, "S-1-5-18"}, "no additional principal grant")
    finally:
        free(descriptor)


def replace_acl(path, sddl):
    descriptor = P()
    check(parse_sd(sddl, 1, c.byref(descriptor), None), "owned test ACL parse")
    try:
        check(set_sd(str(path), 4 | 0x80000000, descriptor), "owned test ACL replacement")
    finally:
        free(descriptor)


def restricted_read(path):
    process = api(k, "GetCurrentProcess", w.HANDLE)
    token_open = api(a, "OpenProcessToken", w.BOOL, w.HANDLE, w.DWORD, P)
    restricted = api(a, "CreateRestrictedToken", w.BOOL, w.HANDLE, w.DWORD, w.DWORD, P, w.DWORD, P, w.DWORD, P, P)
    parse_sid = api(a, "ConvertStringSidToSidW", w.BOOL, w.LPCWSTR, P)
    impersonate = api(a, "ImpersonateLoggedOnUser", w.BOOL, w.HANDLE)
    revert = api(a, "RevertToSelf", w.BOOL)

    class SidAndAttributes(c.Structure):
        _fields_ = [("sid", P), ("attributes", w.DWORD)]

    token, limited, world = w.HANDLE(), w.HANDLE(), P()
    active = False
    try:
        check(token_open(process(), 0xE, c.byref(token)), "open own token")
        check(parse_sid("S-1-1-0", c.byref(world)), "restricting World SID")
        row = SidAndAttributes(world, 0)
        check(restricted(token, 1, 0, None, 0, None, 1, c.byref(row), c.byref(limited)), "disable privileges and restrict token")
        check(impersonate(limited), "impersonate owned restricted token")
        active = True
        handle = open_file(str(path), 0x80000000, 7, None, 3, 0, None)
        error = c.get_last_error()
        if handle != INVALID:
            close(handle)
        check(handle == INVALID and error == 5, "restricted principal actually denied original bytes")
    finally:
        if active:
            check(revert(), "restore original thread token")
        if limited:
            close(limited)
        if token:
            close(token)
        if world:
            free(world)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--producer", type=Path)
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    exe, producer = args.exe.resolve(), (args.producer or args.exe).resolve()
    sandbox = args.fixtures.resolve() / ("privacy-" + uuid.uuid4().hex)
    sandbox.mkdir(parents=True)
    spec = importlib.util.spec_from_file_location("gc_identity", Path(__file__).with_name("test-evidence-gc.py"))
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)

    def command(action, root, option=False):
        check(root.absolute().is_relative_to(sandbox), "all product calls stay in owned fixture namespace")
        if args.cli:
            return [str(exe), "--offline", "!kmon", "init-store" if action == "init" else "privacy", str(root),
                    *(["/acl-only" if action == "init" else "/audit"] if option else []), "/json"]
        return [str(exe), action, str(root), *(["acl" if action == "init" else "audit"] if option else [])]

    def run(action, root, option=False):
        result = subprocess.run(command(action, root, option), capture_output=True, text=True, encoding="utf-8", timeout=60)
        lines = [s for s in result.stdout.splitlines() if s.startswith('{"schema":"kn.evidence_privacy.v1"')]
        check(len(lines) == 1, f"one privacy report: rc={result.returncode}")
        report = json.loads(lines[0])
        check(result.returncode == (0 if report["status"] == "ready" else 1), "status exit contract")
        for key in ("atomic_security_snapshot", "administrator_or_recovery_agent_excluded", "collector_authenticated",
                    "external_transfer_authorized", "power_loss_durability_established"):
            check(report[key] is False, "bounded privacy claim: " + key)
        return report

    def create(name, efs=False):
        root = sandbox / name
        report = run("init", root, not efs)
        check(report["status"] == "ready" and report["initialized"] and report["efs_required"] == efs,
              "new private root initialized: " + name + ": " + report["status"] + ": " + report["issue"])
        check(report["root_identity"] == identity.physical_identity(root), "full physical root identity")
        raw = (root / "store.knprivacy").read_bytes()
        check(hashlib.sha256(raw).hexdigest() == report["policy_sha256"], "policy hash binds exact plaintext bytes")
        policy = json.loads(raw)
        check(policy == {"schema": "kn.evidence_private_store.v1", "policy": report["policy"], "owner_sid": report["owner_sid"],
                         "root_identity": report["root_identity"]}, "policy binds principal, root and selected protection")
        for path in (root, root / "store.knprivacy"):
            acl(path, report["owner_sid"], path == root)
            if efs:
                check(attributes(str(path)) & 0x4000, "actual EFS encrypted attribute")
        return root, report

    root, report = create("acl")
    original_policy = (root / "store.knprivacy").read_bytes()
    check(run("inspect", root, True)["checked_entries"] == "1", "audit counts policy once")
    write = subprocess.run([str(producer), "write", str(root)], capture_output=True, text=True, timeout=30)
    check(write.returncode == 0 and write.stdout.strip() == hashlib.sha256((root / "owned.kncase").read_bytes()).hexdigest(),
          "original writer and reader preserve exact plaintext hash")
    restricted_read(root / "owned.kncase")
    check(run("init", root, True)["status"] != "ready" and (root / "store.knprivacy").read_bytes() == original_policy,
          "existing root never adopted or overwritten")

    copy, _ = create("copied-policy")
    (copy / "store.knprivacy").write_bytes(original_policy)
    check(run("inspect", copy)["issue"] == "private_store_policy_principal_or_identity_mismatch", "copied policy cannot bind another physical root")
    for name, data in (("malformed", b"{}"), ("duplicate", original_policy[:-1] + b',"policy":"kn.current_principal_acl.v1"}'),
                       ("too-large", b" " * 4097), ("invalid-utf8", b"\xff"), ("wrong-principal", original_policy.replace(report["owner_sid"].encode(), b"S-1-1-0"))):
        bad, _ = create(name)
        if name == "wrong-principal":
            data = (bad / "store.knprivacy").read_bytes().replace(report["owner_sid"].encode(), b"S-1-1-0")
        (bad / "store.knprivacy").write_bytes(data)
        check(run("inspect", bad)["status"] == "denied", "reject noncanonical policy: " + name)

    weak, weak_report = create("weak-root")
    sid_value = weak_report["owner_sid"]
    replace_acl(weak, f"D:P(A;OICI;FA;;;{sid_value})(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)")
    check(run("inspect", weak)["status"] == "denied", "reject widened root ACL")
    child = root / "weak-child"
    child.mkdir()
    replace_acl(child, f"D:P(A;;FA;;;{report['owner_sid']})(A;;FA;;;SY)")
    check(run("inspect", root)["status"] == "ready" and run("inspect", root, True)["status"] == "denied", "root-only inspection distinct from inheritance audit")
    child.rmdir()
    weak_file = root / "weak-file"
    weak_file.write_bytes(b"owned fixture")
    replace_acl(weak_file, f"D:P(A;;FA;;;{report['owner_sid']})(A;;FA;;;SY)(A;;FR;;;WD)")
    check(run("inspect", root, True)["status"] == "denied", "extra file reader rejected")
    weak_file.unlink()
    for suffix in ("bad.", "bad ", "bad:stream", "NUL.txt", "com1", "LPT\u00b2.txt", "bad?"):
        invalid = sandbox / suffix
        before_names = set(sandbox.iterdir())
        check(run("init", invalid, True)["status"] != "ready" and set(sandbox.iterdir()) == before_names, "ambiguous, device or stream root rejected before output")
    unicode_root, _ = create("unicode-공간 테스트")
    check(run("inspect", unicode_root, True)["status"] == "ready", "Unicode and spaced local path")
    hardlink = sandbox / "policy-alias"
    hardlink.hardlink_to(root / "store.knprivacy")
    check(run("inspect", root)["status"] == "denied", "policy hardlink rejected")
    hardlink.unlink()
    target, _ = create("junction-target")
    link = root / "junction"
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, timeout=15)
    check(made.returncode == 0, "owned junction fixture")
    try:
        check(run("inspect", root, True)["status"] == "denied" and run("inspect", link)["status"] == "denied", "reject descendant and root reparse points")
    finally:
        check(link.parent.resolve().is_relative_to(sandbox), "owned junction cleanup parent")
        link.rmdir()  # Removes the link only, never its target.
    check(run("inspect", target, True)["status"] == "ready", "junction target untouched")

    def held(command_line, stage, callback, kill=True):
        child_process = subprocess.Popen(command_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: lines.put(child_process.stdout.readline()), daemon=True)
        reader.start()
        try:
            check(lines.get(timeout=30).strip() == "[privacy.stage] " + stage and child_process.poll() is None, "observed exact stage: " + stage)
            callback()
        finally:
            if child_process.poll() is None and kill:
                child_process.kill()
            try:
                output, _ = child_process.communicate(input="continue\n" if not kill else None, timeout=15)
            except subprocess.TimeoutExpired:
                child_process.kill()
                child_process.communicate(timeout=15)
                raise
            finally:
                reader.join(timeout=5)
        check(child_process.poll() is not None and not reader.is_alive(), "owned child and pipe reader reaped")
        return child_process.returncode, output

    def pinned():
        for path, access, flags in ((root, 0x10000, 0x02000000), (root / "store.knprivacy", 0x40000000, 0)):
            handle = open_file(str(path), access, 7, None, 3, flags, None)
            error = c.get_last_error()
            if handle != INVALID:
                close(handle)
            check(handle == INVALID and error == 32, f"guard excludes directory deletion and policy overwrite: access={access}, error={error}")

    held([str(producer), "guard", str(root)], "guarded", pinned, False)
    collision = sandbox / "late-collision"
    before = set(sandbox.glob(".kn-private-*"))
    collision_code, collision_output = held([str(producer), "init", str(collision), "acl", "private_policy_committed"], "private_policy_committed",
         lambda: (collision.mkdir(), (collision / "sentinel").write_bytes(b"owned collision")), False)
    collision_result = json.loads(collision_output)
    check(collision_code == 1 and collision_result["issue"].startswith("private_store_publication_failed_"), "actual rename rejects destination collision")
    check((collision / "sentinel").read_bytes() == b"owned collision" and not (collision / "store.knprivacy").exists(),
          "late destination is never replaced")
    check(len(set(sandbox.glob(".kn-private-*")) - before) == 1, "late collision preserves private staging")
    for stage in ("private_root_created", "private_root_protected", "private_policy_committed", "private_root_published"):
        interrupted = sandbox / stage
        before = set(sandbox.glob(".kn-private-*"))
        held([str(producer), "init", str(interrupted), "acl", stage], stage,
             lambda: check(interrupted.exists() == (stage == "private_root_published"), "target absent until publication"))
        if stage == "private_root_published":
            check(run("inspect", interrupted, True)["status"] == "ready", "published root survives process interruption")
        else:
            residual = set(sandbox.glob(".kn-private-*")) - before
            check(len(residual) == 1 and not interrupted.exists(), "one private staging directory, no half-published root")
            acl(next(iter(residual)), report["owner_sid"], True)
            if stage == "private_policy_committed":
                check(run("inspect", next(iter(residual)), True)["status"] == "ready", "staging policy remains bound to same physical directory")

    encrypted = sandbox / "efs"
    efs = run("init", encrypted)
    if efs["status"] == "ready":
        check(efs["efs_required"], "EFS required by default")
        for path in (encrypted, encrypted / "store.knprivacy"):
            acl(path, efs["owner_sid"], path == encrypted)
            check(attributes(str(path)) & 0x4000, "EFS confirmed by independent OS metadata")
        made = subprocess.run([str(producer), "write", str(encrypted)], capture_output=True, text=True, timeout=30)
        data = (encrypted / "owned.kncase").read_bytes()
        check(made.returncode == 0 and made.stdout.strip() == hashlib.sha256(data).hexdigest(), "EFS transparent original hash and replay reader")
        check(attributes(str(encrypted / "owned.kncase")) & 0x4000 and run("inspect", encrypted, True)["status"] == "ready", "new file inherits EFS")
        restricted_read(encrypted / "owned.kncase")
        check(decrypt(str(encrypted / "owned.kncase"), 0), "owned EFS downgrade fixture")
        check(run("inspect", encrypted, True)["status"] == "denied", "unencrypted child fails required EFS audit")
        efs_result = "verified"
    else:
        check(efs["efs_required"] and efs["issue"].startswith("efs_initialization_failed_") and not encrypted.exists(),
              "unavailable EFS never falls back or publishes target")
        temporary = Path(efs["temporary_directory"])
        check(temporary.parent == sandbox and temporary.is_dir() and not list(temporary.iterdir()), "failed EFS leaves empty owned private staging only")
        acl(temporary, efs["owner_sid"], True)
        efs_result = efs["issue"]
    if args.cli:
        for tail in ([], ["init-store"], ["init-store", "/acl-only"], ["privacy", "/json"], ["privacy"], ["privacy", str(root), "/acl-only"],
                     ["init-store", str(root), "/audit"], ["init-store", str(root), "/json", "/json"]):
            invalid = subprocess.run([str(exe), "--offline", "!kmon", *tail], capture_output=True, timeout=15)
            check(invalid.returncode == 2, "invalid offline privacy grammar")
        broken = subprocess.Popen(command("inspect", root), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        broken.stdout.close()
        broken.stdout = None
        try:
            broken.communicate(timeout=15)
            check(broken.returncode == 3, "broken JSON output is a reported failure")
        finally:
            if broken.poll() is None:
                broken.kill()
                broken.communicate(timeout=15)
    print(f"[privacy.oracle] checks={CHECKS} efs={efs_result} interruptions=4 children_remaining=0 mode={'cli' if args.cli else 'harness'} fixtures={sandbox}")


if __name__ == "__main__":
    main()
