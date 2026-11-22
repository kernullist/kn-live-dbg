"""Verify signed ETL capture statements with an owned recorder and an independent OpenSSL signer."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

AUDIT = runpy.run_path(str(Path(__file__).with_name("validate-public-content.py")))
TYPE = "kn.etl_capture_statement.v1+jws"
HEADER = {"alg": "ES256", "typ": TYPE}
CONTEXT = ("session_id", "target_id", "boot_id", "se_system_profile_privilege_enabled",
           "system_trace_enable_flags", "sampled_profile_stack_requested", "context_switch_stack_requested")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def run(args, expected=0, **kwargs):
    p = subprocess.run(list(map(str, args)), capture_output=True, timeout=120, **kwargs)
    assert p.returncode == expected, (Path(args[0]).name, p.returncode, expected, p.stderr[:240])
    return p.stdout


class Signer:
    def __init__(self, openssl, folder):
        self.openssl, self.folder = openssl, folder
        folder.mkdir()
        self.key = folder / "ephemeral.pem"
        run([openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", self.key])
        self.public = folder / "public.pem"
        run([openssl, "pkey", "-in", self.key, "-pubout", "-out", self.public])
        spki = run([openssl, "pkey", "-pubin", "-in", self.public, "-pubout", "-outform", "DER"])
        # id-ecPublicKey, prime256v1, BIT STRING with an uncompressed point.
        prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
        assert spki.startswith(prefix) and len(spki) == len(prefix) + 65 and spki[len(prefix)] == 4
        self.point = spki[len(prefix):].hex()

    def token(self, claims, header=None):
        h = HEADER if header is None else header
        body = b64(h if isinstance(h, bytes) else compact(h)) + b"." + b64(claims if isinstance(claims, bytes) else compact(claims))
        message, sig = self.folder / "input", self.folder / "signature.der"
        message.write_bytes(body)
        run([self.openssl, "dgst", "-sha256", "-sign", self.key, "-out", sig, message])
        run([self.openssl, "dgst", "-sha256", "-verify", self.public, "-signature", sig, message])
        der = sig.read_bytes()
        assert der[0] == 0x30 and der[1] == len(der) - 2
        pos, raw = 2, bytearray()
        for _ in range(2):
            assert der[pos] == 2
            size = der[pos + 1]
            component = der[pos + 2:pos + 2 + size]
            assert 1 <= size <= 33 and len(component) == size and component[0] < 128
            raw.extend(int.from_bytes(component, "big").to_bytes(32, "big"))
            pos += 2 + size
        assert pos == len(der)
        return body + b"." + b64(raw)


def statement(etl, capture=None):
    with etl.open("rb") as f:
        pin = hashlib.file_digest(f, "sha256").hexdigest()
    obj = dict(schema="kn.etl_capture_statement.v1", role="archive_witness", etl_sha256=pin,
               etl_bytes=str(etl.stat().st_size), **dict.fromkeys(CONTEXT))
    if capture:
        obj.update(role="capture_controller", session_id=capture["session_id"],
                   se_system_profile_privilege_enabled=capture["se_system_profile_privilege_enabled"],
                   system_trace_enable_flags=capture["system_trace_enable_flags"],
                   sampled_profile_stack_requested=False, context_switch_stack_requested=False)
    return obj


def provider_guids(event):
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    tns = "{http://schemas.microsoft.com/win/2004/08/events/trace}"
    provider = event.find(ns + "System/" + ns + "Provider")
    return [v.strip("{}").lower() for v in ((provider.get("Guid", "") if provider is not None else ""),
            event.findtext(tns + "ExtendedTracingInfo/" + tns + "EventGuid") or "")]


def owned_capture(exe, folder):
    record = json.loads(run([exe, folder]))
    etl = folder / record["session_id"] / "capture.etl"
    xml = folder / "owned.xml"
    run([Path(os.environ["SystemRoot"]) / "System32/tracerpt.exe", etl, "-o", xml, "-of", "XML", "-rts", "-y"], cwd=folder)
    events = ET.parse(xml).findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}Event")
    assert sum(record["provider_id"] in provider_guids(e) for e in events) == 1, len(events)
    assert record["system_trace_enable_flags"] == 0
    return etl, record, len(events)


def check(exe, signer, etl, claims, folder, expected_records=None, reference=None, short=False):
    source_pin = claims["etl_sha256"]
    jws = folder / "record.knetlstatement"
    token = signer.token(claims)
    jws.write_bytes(token + b"\r\n")
    key = signer.point.upper()
    signature_args = ["--capture-statement", jws, claims["role"], key]
    rc = 1 if short else 0
    variants = [("--etl-hard-faults", []), ("--etl-hard-faults", ["--handoff-markers"]),
                ("--etl-disk-io", []), ("--etl-profile", ["--capture-settings"]), ("--etl-profile", ["--clr-evidence"]),
                ("--etl-switches", ["--capture-settings", "--intervals"])]
    if reference:
        flags = ["--after", "0", "--thread-evidence", "--image-evidence", "--process-evidence",
                 "--build-evidence", "--capture-settings", "--reference-image", *reference]
        variants.extend([("--etl-profile", flags), ("--etl-profile", [*flags, "--clr-evidence"])])
    for verb, flags in variants:
        native = [exe, verb, etl, "--sha256", source_pin, *flags, "--limit", "4"]
        raw = run(native, rc)
        report = json.loads(raw)
        if expected_records is not None:
            assert report["records_seen"] == expected_records
        page_pin = sha(raw)
        plain = json.loads(run([*native, "--check-page", page_pin], rc))
        args = [*native, "--check-page", page_pin]
        proof = json.loads(run([*args, *signature_args], rc))
        bound = proof.pop("capture_statement")
        assert proof["schema"] == "kn.etl_page_replay.v2"
        proof["schema"] = "kn.etl_page_replay.v1"
        assert proof == plain and proof["status"] == "matched" and proof["page_bytes_match"] and not proof["collector_authenticated"]
        assert proof["source_status"] == ("partial" if short else "read")
        assert bound["signature_verified"] and bound["role_matches"] and bound["etl_identity_matches"] and bound["bound_to_replayed_page"]
        assert bound["expected_role"] == bound["signed_role"] == claims["role"]
        assert bound["status"] == "bound" and bound["capture_controller_statement_authenticated"] == (claims["role"] == "capture_controller")
        assert bound["claimed_etl_sha256"] == source_pin and bound["claimed_etl_bytes"] == claims["etl_bytes"]
        assert bound["statement_file_sha256"] == sha(jws.read_bytes()) and bound["trusted_key_sha256"] == sha(bytes.fromhex(key))
        assert bound["claims"] == {k: claims[k] for k in ("role", *CONTEXT)}
        if "--handoff-markers" in flags:
            assert proof["source_kind"] == "handoff_marker" and report["schema"] == "kn.etl_handoff_markers.v1"
        if verb == "--etl-hard-faults" and not flags and report["hard_faults"]:
            selected = [exe, verb, etl, "--sha256", source_pin, "--schedule-of", "1"]
            schedule_pin = sha(run(selected, rc))
            receipt = json.loads(run([*selected, "--check-page", schedule_pin, *signature_args], rc))
            assert receipt["status"] == "matched" and receipt["requested_fault_ordinal"] == 1
            assert receipt["source_status"] == proof["source_status"] and receipt["page_bytes_match"]
            assert receipt["capture_statement"] == bound
        for part in (bound, bound["claims"], claims):
            for enc in ("utf-8", "utf-16-le", "utf-16-be"):
                fragment = ("log\n" + json.dumps(dict(reversed(list(part.items()))))[:-1]).encode(enc)
                assert any(v["rule"] == "private-evidence-bundle" for v in AUDIT["inspect"]("part.txt", fragment))
    return args, jws, token


def adversarial(args, jws, token, signer, other, claims):
    key = signer.point
    role = claims["role"]
    def assess(data, status, valid, identity, alt_key=key, cmd=None, expected_role=role):
        jws.write_bytes(data)
        result = json.loads(run([*(args if cmd is None else cmd), "--capture-statement", jws, expected_role, alt_key], 1))
        auth = result["capture_statement"]
        assert auth["status"] == status and auth["signature_verified"] is valid and auth["etl_identity_matches"] is identity, (status, auth["status"])
        assert auth["claims"] is None and not auth["capture_controller_statement_authenticated"] and not auth["bound_to_replayed_page"]
        return result
    wrong = assess(token, "signer_role_mismatch", True, True, expected_role="archive_witness")["capture_statement"]
    assert wrong["role_matches"] is False and wrong["signed_role"] == role and wrong["expected_role"] == "archive_witness"
    archive = dict(claims, **dict.fromkeys(CONTEXT))
    archive["role"] = "archive_witness"
    assert assess(signer.token(archive), "signer_role_mismatch", True, True)["capture_statement"]["signed_role"] == "archive_witness"
    assert assess(token, "signature_rejected", False, None, other.point)["page_bytes_match"]
    assess(token, "signature_rejected", False, None, "04"+"00"*64)
    # These are signed schema controls, separate from the recorder's measured settings.
    alternate = dict(claims, target_id="12345678-1111-2222-3333-123456789abc",
                     boot_id="12345678-1111-2222-3333-123456789abd", system_trace_enable_flags=0xffffffff,
                     se_system_profile_privilege_enabled=None, sampled_profile_stack_requested=True,
                     context_switch_stack_requested=None)
    jws.write_bytes(signer.token(alternate, json.dumps(dict(reversed(list(HEADER.items()))), indent=2).encode()))
    alternate_proof = json.loads(run([*args, "--capture-statement", jws, role, key]))["capture_statement"]
    assert alternate_proof["claims"] == {k: alternate[k] for k in ("role", *CONTEXT)}
    assert assess(signer.token(dict(claims, etl_bytes="1")), "etl_identity_mismatch", True, False)["status"] == "capture_statement_rejected"
    assess(signer.token(dict(claims, etl_sha256="0"*64)), "etl_identity_mismatch", True, False)
    bad_page = args.copy()
    bad_page[-1] = "0"*64
    assert assess(token, "bound", True, True, cmd=bad_page)["status"] == "page_mismatch"
    bad_source = args.copy()
    bad_source[4] = "0"*64
    result = assess(token, "not_checked", None, None, cmd=bad_source)
    assert result["page_bytes_match"] is None and result["status"] == "digest_mismatch"
    h, p, sig = token.split(b".")
    reformatted = b64(json.dumps(HEADER, indent=1).encode())
    assess(b".".join((reformatted, p, sig)), "signature_rejected", False, None)
    forged = b64(compact(dict(claims, role="archive_witness")))
    assess(b".".join((h, forged, sig)), "signature_rejected", False, None)
    for obj in (dict(claims, role="archive_witness"), dict(claims, boot_id="anonymous"), dict(claims, etl_bytes="01"),
                dict(claims, target_id="00000000-0000-0000-0000-000000000000"), dict(claims, authenticated=True),
                dict(claims, system_trace_enable_flags=1 << 32), dict(claims, sampled_profile_stack_requested=1),
                compact(claims).replace(b'"role":', b'"role":"capture_controller","role":'), b"\xef\xbb\xbf"+compact(claims),
                compact(claims).replace(b"capture_controller", b"\xff")):
        assess(signer.token(obj), "invalid_claims", True, None)
    for hdr in (dict(HEADER, alg="none"), dict(HEADER, alg="HS256"), dict(HEADER, kid=key), dict(HEADER, jwk={}),
                dict(HEADER, typ="other"), b'{"alg":"ES256","alg":"ES256","typ":"kn.etl_capture_statement.v1+jws"}'):
        assess(signer.token(claims, hdr), "invalid_jws", None, None)
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    padded_bits = bytes([alphabet[alphabet.index(sig[-1:])+1]])
    for data in (token+b"=", token+b".", b"."+p+b"."+sig, token+b"\n\n", token[:-1]+padded_bits, b"\0"+token):
        assess(data, "invalid_jws", None, None)
    assess(b"x"*8193, "statement_unavailable", None, None)
    jws.unlink()
    absent = json.loads(run([*args, "--capture-statement", jws, role, key], 1))
    assert absent["capture_statement"]["status"] == "statement_unavailable" and absent["page_bytes_match"]
    jws.write_bytes(token)
    with jws.open("r+b") as writer:
        denied = json.loads(run([*args, "--capture-statement", jws, role, key], 1))
        assert denied["capture_statement"]["status"] == "statement_unavailable" and writer.tell() == 0
    ads = Path(str(jws) + ":test")
    ads.write_bytes(token)
    denied = json.loads(run([*args, "--capture-statement", ads, role, key], 1))
    assert denied["capture_statement"]["status"] == "statement_unavailable"
    for tail in (["--capture-statement", jws, role, key[2:]], ["--capture-statement", jws, role, key[:-1]+"G"],
                 ["--capture-statement", jws, "unrestricted", key], ["--capture-statement", jws, role, key]*2):
        assert not run([*args, *tail], 2)
    assert not run([*args[:-2], "--capture-statement", jws, role, key], 2)
    for path in (Path(args[2]), jws):
        original = path.read_bytes()
        link = jws.parent/"alias"
        os.link(path, link)
        for stream, cmd in (("stdout", [*args, "--capture-statement", jws, role, key]),
                            ("stderr", [*args, "--capture-statement", jws, role, key, "--bad"])):
            with link.open("ab") as sink:
                r = subprocess.run(cmd, stdout=sink if stream=="stdout" else subprocess.DEVNULL,
                                   stderr=sink if stream=="stderr" else subprocess.DEVNULL, timeout=30)
            assert r.returncode == 2 and path.read_bytes() == original
        link.unlink()
    # Signer-supplied key references and valid signed bytes never authorize a restricted launch.
    r = json.loads(run([args[0], "--mode", "offline", *args[1:], "--capture-statement", jws, role, key], 5))
    assert r["status"] == "blocked_by_policy"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("exe", "capture-exe", "openssl"):
        p.add_argument("--"+arg, type=Path, required=True)
    p.add_argument("--etl", type=Path)
    p.add_argument("--sha256")
    p.add_argument("--check-short-tail", action="store_true", help="require the shortened fixture to produce a partial ETL page")
    p.add_argument("--reference-image", nargs=2, metavar=("PE", "SHA256"))
    cfg = p.parse_args()
    if bool(cfg.etl) != bool(cfg.sha256) or ((cfg.reference_image or cfg.check_short_tail) and not cfg.etl):
        p.error("use --etl and --sha256 together for the archive, reference and short-tail checks")
    exe, recorder, openssl = (v.resolve(strict=True) for v in (cfg.exe, cfg.capture_exe, cfg.openssl))
    with tempfile.TemporaryDirectory(prefix="kn-signed-etl-") as tmp:
        folder = Path(tmp)
        signer, other = Signer(openssl, folder/"first"), Signer(openssl, folder/"second")
        etl, record, count = owned_capture(recorder, folder)
        claims = statement(etl, record)
        args, jws, token = check(exe, signer, etl, claims, folder, count)
        adversarial(args, jws, token, signer, other, claims)
        print("Owned private ETW recorder: one provider event in", count, "records; signed controller and failure controls passed.")
        if cfg.etl:
            local = folder/"archive.etl"
            shutil.copyfile(cfg.etl, local)
            archive = statement(local)
            assert archive["etl_sha256"] == cfg.sha256.lower()
            ref = [Path(cfg.reference_image[0]).resolve(strict=True), cfg.reference_image[1]] if cfg.reference_image else None
            check(exe, signer, local, archive, folder, reference=ref)
            print("Pinned public ETL: independent archive signature and page replay passed.")
            if cfg.check_short_tail:
                with local.open("r+b") as stream:
                    stream.truncate(local.stat().st_size-1)
                check(exe, signer, local, statement(local), folder, short=True)
                print("One-byte-short ETL: matched signed page retained partial source status.")


if __name__ == "__main__":
    main()
