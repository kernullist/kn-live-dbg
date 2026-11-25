"""Check the portable approval through the public CLIs and independently read its original bytes."""
import ctypes
from datetime import datetime, timedelta
import hashlib
import io
import json
from pathlib import Path
import runpy
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


CLI = Path(__file__).with_name("archive-image-approval.py")
FRAME = struct.Struct("<8sI7I")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def call(command, expected=0):
    result = subprocess.run(list(map(str, command)), capture_output=True, timeout=180)
    assert result.returncode == expected, (result.returncode, result.stdout[:1000], result.stderr[:500])
    return json.loads(result.stdout)


def unpack(data, require_efs):
    magic, flags, *sizes = FRAME.unpack_from(data)
    assert magic == b"KNAPARC1" and flags == int(require_efs)
    parts, pos = [], FRAME.size
    for size in sizes:
        parts.append(data[pos:pos+size])
        pos += size
    return parts, data[pos:]


def frame(parts, members, flags=0):
    return FRAME.pack(b"KNAPARC1", flags, *map(len, parts)) + b"".join(parts) + members


def check_publication(exe, workspace):
    from etl_reader_process import WindowsFiles
    from windows_private_archive import publish_archive
    files = WindowsFiles()
    native = [exe, "--offline", "!kmon", "privacy", workspace]
    protection = call([*native, "/json"])
    pending_pattern = ".knapprovalarchive.pending-*"
    destination = workspace / "race.knapprovalarchive"
    payload = b"publication test"

    def compete(stream):
        stream.write(payload)
        pending, = workspace.glob(pending_pattern)
        competing = files.create(str(pending), 0x40000000, 7, None, 3, 0x80, None)
        if competing != ctypes.c_void_p(-1).value:
            files.close(competing)
            raise AssertionError("pending archive allowed a second writer")
        assert ctypes.get_last_error() == 32  # ERROR_SHARING_VIOLATION
        with destination.open("xb") as winner:
            winner.write(b"already published")
        return {"archive_sha256": sha(payload)}

    try:
        publish_archive(destination, files, protection, compete)
        raise AssertionError("archive replaced a competing publication")
    except OSError as exc:
        assert exc.winerror in (80, 183)
    assert destination.read_bytes() == b"already published" and not list(workspace.glob(pending_pattern))
    destination.unlink()

    def bad_digest(stream):
        stream.write(payload)
        return {"archive_sha256": sha(b"different")}

    try:
        publish_archive(destination, files, protection, bad_digest)
        raise AssertionError("archive published unverified bytes")
    except ValueError as exc:
        assert "sealed bytes differ" in str(exc)
    assert not destination.exists() and not list(workspace.glob(pending_pattern))

    child = """import os, sys
from pathlib import Path
from etl_reader_process import WindowsFiles
from windows_private_archive import publish_archive
def interrupt(stream):
    stream.write(b'interrupted publication')
    stream.flush()
    os._exit(17)
publish_archive(Path(sys.argv[1]), WindowsFiles(), dict(owner_sid=sys.argv[2], efs_required=False), interrupt)
"""
    stopped = subprocess.run([sys.executable, "-B", "-c", child, str(destination), protection["owner_sid"]],
                             cwd=CLI.parent, capture_output=True, timeout=30)
    assert stopped.returncode == 17 and not destination.exists()
    pending, = workspace.glob(pending_pattern)
    assert pending.read_bytes() == b"interrupted publication"
    audit = call([*native, "/audit", "/json"])
    assert audit["status"] == "ready" and audit["audit_complete"] is True
    pending.unlink()


def verify_archived_approval(exe, capture, manifest, policy, envelope, source, receipt, root_pin, target, at,
                             *, catalog=None, exercise_failures=False, require_efs=False):
    native = [exe, "--offline", "!kmon"]
    cli = [sys.executable, "-B", CLI]
    original = json.loads(receipt)
    native_pin = original["native_policy_sha256"]
    common = ["--debugger", exe, "--debugger-sha256", sha(exe.read_bytes()), "--receipt-sha256", sha(receipt),
              "--trusted-root-sha256", root_pin, "--policy-target", target, "--verification-time", at]
    if "windows_publisher" in original:
        common += ["--require-windows-publisher"]

    with tempfile.TemporaryDirectory() as temporary:
        workspace = Path(temporary) / "private"
        store_options = [] if require_efs else ["/acl-only"]
        call([*native, "init-store", workspace, *store_options, "/json"])
        archive = workspace / "portable.knapprovalarchive"
        with tempfile.TemporaryDirectory(dir=temporary) as private:
            origin = Path(private) / "original"
            call([*native, "init-store", origin, *store_options, "/json"])
            report = call([*native, "journal-image-approval", capture, manifest, policy, native_pin, origin, "7", "/json"])
            assert report["status"] == "archived"
            col = origin / "collections/7"
            journal = call([*native, "journal", col, "/json"])
            root, = journal["committed_approval_paths"]
            expected = call([*native, "replay-image-approval", origin / root, native_pin, "/json"])["assessment"]
            head = ["--journal-head-sha256", journal["head_sha256"]]
            proof = [envelope.read_bytes(), source.read_bytes(), receipt, catalog.read_bytes() if catalog else b""]
            for name, raw in zip(("tuf.json", "source.json", "receipt.json", "distribution.cat"), proof):
                if raw:
                    (origin / name).write_bytes(raw)
            pack = [*cli, "pack", *common, *head, "--collection", col, "--publisher-reference", origin / "tuf.json",
                    "--policy", origin / "source.json", "--receipt", origin / "receipt.json"]
            if catalog:
                pack += ["--catalog", origin / "distribution.cat"]
            if require_efs:
                weak = Path(temporary) / "acl-only"
                call([*native, "init-store", weak, "/acl-only", "/json"])
                lost = weak / archive.name
                assert call([*pack, "--out", lost], 1)["reason"] == "destination would drop source encryption"
                assert not lost.exists()
            archived = call([*pack, "--out", archive])
            data = archive.read_bytes()
            parts, members = unpack(data, require_efs)
            assert archived["archive_requires_efs"] is require_efs
            if require_efs:
                assert archive.stat().st_file_attributes & 0x4000
                assert call([*native, "privacy", workspace, "/audit", "/json"])["audit_complete"]
            segments = sorted((col / "journal-segments").glob("*.knjseg"))
            assert parts == [(col / "session.knsession").read_bytes(), *(p.read_bytes() for p in segments), *proof]
            entries = [row for part in parts[1:3] for row in json.loads(part)["payload"]["transaction"]["members"]]
            cursor = 0
            for row in sorted(entries, key=lambda r: r["path"]):
                raw = (origin / row["path"]).read_bytes()
                assert sha(raw) == row["sha256"] and len(raw) == int(row["bytes"])
                assert members[cursor:cursor+len(raw)] == raw
                cursor += len(raw)
            assert cursor == len(members) and archived["archive_sha256"] == sha(data)
            if exercise_failures:
                assert call([*pack, "--out", archive], 1)["status"] == "rejected"
                assert archive.read_bytes() == data
                denied = workspace / "denied.knapprovalarchive"
                assert call([*pack, "--trusted-root-sha256", "0"*64, "--out", denied], 1)["status"] == "rejected"
                assert not denied.exists() and not list(workspace.glob("*.pending-*"))
                # Even help and a parse failure must not append to an indirect member through a hard link.
                sink = workspace / "other-name.txt"
                index = col / "indexes" / "heads" / (journal["head_sha256"] + ".knjindex")
                for path, option in ((origin / root, "--help"), (index, "--invalid-option")):
                    sink.hardlink_to(path)
                    before = sink.read_bytes()
                    with sink.open("ab") as out:
                        result = subprocess.run([*map(str, pack), option], stdout=out, stderr=out, timeout=30)
                    assert result.returncode == 2 and sink.read_bytes() == before
                    sink.unlink()
                check_publication(exe, workspace)

        assert not origin.exists()
        recovery = Path(temporary) / "recovery"
        call([*native, "init-store", recovery, *store_options, "/json"])
        replay = [*cli, "replay", *common, "--private-workspace", recovery]
        def read(path, pin, *more, code=0):
            return call([*replay, "--archive", path, "--archive-sha256", pin, *more], code)
        observed = read(archive, sha(data), *head, "--minimum-root-version", "1")
        checkpoint = original["publisher_proof"].get("publisher_history", {}).get("previous_checkpoint_sha256")
        if checkpoint:
            assert observed["publisher_history"] == archived["publisher_history"] == original["publisher_proof"]["publisher_history"]
            assert read(archive, sha(data), "--previous-checkpoint-sha256", checkpoint)["assessment"] == expected
            rejected = read(archive, sha(data), "--previous-checkpoint-sha256", "0"*64, code=1)
            assert rejected["status"] == "rejected" and "assessment" not in rejected
        assert observed["status"] == "reproduced" and observed["journal_membership_checked"]
        assert observed["original_assessment_reproduced"] and expected == archived["assessment"] == observed["assessment"]
        assert observed["original_windows_verification"] == original.get("windows_publisher")
        if "windows_publisher" in original:
            assert observed["current_windows_verification"]["status"] == "verified"
        else:
            assert observed["current_windows_verification"] is None
        assert not list(recovery.glob(".knapproval-replay-*"))
        if require_efs:
            denied = read(archive, sha(data), "--private-workspace", weak, code=1)
            assert denied["reason"] == "private replay workspace would drop archive encryption"
            assert not list(weak.glob(".knapproval-replay-*"))

        if exercise_failures or catalog or checkpoint:
            changed = workspace / "changed.knapprovalarchive"
            def reject(raw, *more):
                changed.write_bytes(raw)
                r = read(changed, sha(raw), *more, code=1)
                assert r["status"] == "rejected" and "assessment" not in r
                assert not list(recovery.glob(".knapproval-replay-*"))
                return r
            if checkpoint:
                magic, prior_at, prior_size, _, size = struct.unpack_from("<8s16sI16sI", parts[3])
                assert magic == b"KNPUBHS1" and prior_size > 0 and size > 0
                different_at = datetime.strptime(prior_at.decode("ascii"), "%Y%m%dT%H%M%SZ") - timedelta(seconds=1)
                changed_parts = parts.copy()
                changed_parts[3] = parts[3][:8] + different_at.strftime("%Y%m%dT%H%M%SZ").encode() + parts[3][24:]
                assert reject(frame(changed_parts, members))["reason"] == "previous_checkpoint_mismatch"
                changed_parts[3] = parts[3][-size:]
                assert reject(frame(changed_parts, members))["reason"] == "publisher_history_required"
            if catalog:
                wrong = parts.copy()
                wrong[6] = bytes([parts[6][0] ^ 1]) + parts[6][1:]
                reject(frame(wrong, members))
                forged = json.loads(receipt)
                forged["windows_publisher"]["catalog_member_sha256"] = "0" * 64
                wrong = parts.copy()
                wrong[5] = json.dumps(forged).encode()
                reject(frame(wrong, members), "--receipt-sha256", sha(wrong[5]))
                later = json.loads(receipt)
                windows = later["windows_publisher"]
                windows["finished_utc"] = (datetime.fromisoformat(windows["finished_utc"]) + timedelta(hours=1)).isoformat()
                wrong[5] = json.dumps(later).encode()
                denied = reject(frame(wrong, members), "--receipt-sha256", sha(wrong[5]))
                assert denied["reason"] == "recorded Windows verification finished after the original assessment"

                verify = runpy.run_path(str(CLI))["verify_stream"]
                args = SimpleNamespace(trusted_root_sha256=root_pin, minimum_root_version=None, policy_target=target,
                                       verification_time=at, require_windows_publisher=True, receipt_sha256=sha(receipt),
                                       journal_head_sha256=head[1])
                unavailable = {"status": "windows_trust_unavailable"}
                def unavailable_on_this_host(*_):
                    audit = call([*native, "privacy", recovery, "/audit", "/json"])
                    assert audit["status"] == "ready" and audit["audit_complete"] is True
                    return unavailable
                with patch("windows_pe_trust.verify_reference", side_effect=unavailable_on_this_host):
                    retained = verify(io.BytesIO(data), args, exe, recovery, {"efs_required": False})
                assert retained["original_windows_verification"] == original["windows_publisher"]
                assert retained["current_windows_verification"] == unavailable and retained["assessment"] == expected
                with patch("windows_pe_trust.verify_reference", return_value=dict(unavailable, catalog_member_sha256="0"*64)):
                    try:
                        verify(io.BytesIO(data), args, exe, recovery, {"efs_required": False})
                        raise AssertionError("an observed catalog member mismatch passed")
                    except ValueError as exc:
                        assert str(exc) == "Windows catalog member differs"
            if exercise_failures:
                assert read(archive, "0"*64, code=1)["status"] == "rejected"
                for flag, val in (("--journal-head-sha256", "0"*64), ("--receipt-sha256", "0"*64),
                                  ("--policy-target", "unapproved.json"), ("--minimum-root-version", "999")):
                    assert read(archive, sha(data), flag, val, code=1)["status"] == "rejected"
                reject(data[:-1])
                reject(data+b"x")
                reject(frame(parts, members, flags=1))
                reject(frame(parts, members[:-1]+bytes([members[-1]^1])))
                wrong = parts.copy()
                wrong[4] += b" "
                reject(frame(wrong, members))
                wrong = parts.copy()
                wrong[5] = json.dumps(dict(original, reference_bytes=True)).encode()
                reject(frame(wrong, members), "--receipt-sha256", sha(wrong[5]))
                wrong = parts.copy()
                closure = json.loads(parts[2])
                closure["payload"]["transaction"]["requires"].pop()
                def canonical(value):
                    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
                assert canonical(json.loads(parts[2])) == parts[2]
                closure["payload_sha256"] = sha(canonical(closure["payload"]))
                wrong[2] = canonical(closure)
                reject(frame(wrong, members))
                # The native session remains well framed. The member path itself must be rejected before extraction.
                ledger = closure["payload"]["transaction"]["members"][0]["path"].encode()
                wrong[2] = parts[2].replace(ledger, b"../escape/ledger")
                assert wrong[2] != parts[2]
                reject(frame(wrong, members))
                assert data == archive.read_bytes()
