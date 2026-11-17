"""Adversarial approval controls against original PE bytes and capture reads."""
import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading

from image_claim_oracle import check_original_claim, check_report, normalized_pe, unpack_recipe


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def material(recipe, blob, rva=None, length=1):
    p = recipe["payload"]
    start, size, base = int(p["rva"]), int(p["length"]), int(p["image_base"])
    expected = bytes(normalized_pe(blob, base, start, size))
    reads = p.get("reads", p.get("read_set", {}).get("reads", []))
    observed = None
    for receipt in reads:
        if int(receipt["address"]) == base + start and int(receipt.get("length", receipt.get("requested_bytes"))) == size:
            spans = receipt.get("read", receipt)["spans"]
            if all(span["state"] == "complete" for span in spans):
                observed = bytes.fromhex("".join(span.get("bytes", span.get("bytes_hex")) for span in spans))
                break
    if observed is None:
        observed = expected  # An unobserved rule can never become authorized.
    if rva is None:
        rva = next((start + i for i in range(size) if observed[i] != expected[i]), start + 0x150)
    offset = rva - start
    before = expected[offset:offset + length]
    after = observed[offset:offset + length]
    if before == after:
        after = bytes([before[0] ^ 1]) + before[1:]
    manifest = {"schema": "kn.authorized_image_changes.v1", "image_sha256": sha(blob), "issuer": "owned-fixture-issuer",
                "policy_epoch": "7", "not_before_filetime": "1", "not_after_filetime": "18446744073709551615",
                "comparison_policy": "kn.executable_page.direct.v1", "hash_basis": "non_fixup_compared_bytes.v1",
                "changes": [{"rva": str(rva), "length": str(length), "before_sha256": sha(before), "after_sha256": sha(after)}]}
    return manifest, expected, observed


def policy_for(manifest, raw=None):
    return {"schema": "kn.image_approval_policy.v1", "policy_id": "owned-fixture-policy", "policy_epoch": "7",
            "not_before_filetime": "1", "not_after_filetime": "18446744073709551615",
            "approvals": [{"image_sha256": manifest["image_sha256"], "manifest_sha256": sha(raw if raw is not None else encoded(manifest)),
                           "issuer": manifest["issuer"]}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    fixture_root = args.fixtures.resolve()
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, ({key: item for key, item in message.items() if key != "replay"} if isinstance(message, dict) else str(message)[:1500])
        checks += 1

    def source(name):
        case = fixture_root / name
        document = json.loads((case / "recipe.knverify").read_bytes())
        recipe = unpack_recipe(document)
        blob = (case / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes()
        return case, document, recipe, blob

    case, document, recipe, blob = source("modified")
    baseline, _, _ = material(recipe, blob)
    captured = int(recipe["payload"]["captured_filetime"])
    with tempfile.TemporaryDirectory(prefix="approval-controls-", dir=fixture_root) as temporary:
        root = Path(temporary).resolve()
        assert root.is_relative_to(fixture_root)
        change_path, policy_path = root / "변경.knchange", root / "정책.knapproval"

        def command(anchor, selected=case, when=captured + 100):
            return [str(args.exe.resolve())] + (["--offline", "!kmon", "assess-image"] if args.product else ["--assess"]) + \
                [str(selected), str(change_path), str(policy_path), anchor] + (["/json"] if args.product else [str(when)])

        def prepare(manifest=baseline, policy=None, raw=None):
            data = encoded(manifest) if raw is None else raw
            change_path.write_bytes(data)
            policy = policy_for(manifest, data) if policy is None else policy
            policy_path.write_bytes(encoded(policy))
            return sha(policy_path.read_bytes())

        def run(manifest=baseline, policy=None, raw=None, anchor=None, selected=case, when=captured + 100,
                issue="", state=None, authorized=None):
            actual_anchor = prepare(manifest, policy, raw)
            before = {p: p.read_bytes() for p in (change_path, policy_path, selected / "recipe.knverify")}
            process = subprocess.run(command(anchor or actual_anchor, selected, when), capture_output=True, text=True, encoding="utf-8", timeout=60)
            report = json.loads(process.stdout)
            check(process.returncode == (1 if issue else 0), (process.returncode, report, process.stderr))
            check(report["issue"] == issue and report["status"] == ("unavailable" if issue else "assessed"), report)
            check(all(path.read_bytes() == raw_bytes for path, raw_bytes in before.items()), "assessment must preserve exact inputs")
            check(not any(report[field] for field in ("issuer_signature_verified", "collector_authenticated", "execution_observed", "current_image_state_known")), "approval does not authenticate provenance or execution")
            if state:
                check(report["rules"][0]["state"] == state, report)
            if authorized is not None:
                check(int(report["authorized_changed_bytes"]) == authorized, report)
            if issue:
                check(not report["reference_approved"] and report["authorized_ranges"] == [] and report["rules"] == [], report)
            else:
                original = json.loads((selected / "recipe.knverify").read_bytes())
                selected_recipe = unpack_recipe(original)
                selected_blob = (selected / (selected_recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes()
                check_original_claim(original, report["replay"])
                check_report(selected_recipe, selected_blob, report["replay"])
                check(report["replay"]["recorded_result"] == selected_recipe["payload"]["recorded_result"], "original difference is never rewritten")
                check(report["reference_trust"] == "R-approved" and report["approval_basis"] == "caller_pinned_exact_policy", report)
            return report

        approved = run(state="authorized", authorized=1)
        check(int(approved["unexplained_changed_bytes"]) == 0, approved)
        for name in ("clean", "observed", "observed-modified", "unstable", "sparse", "wrong-pdb", "alias", "header-changed", "observed-no-consent", "observed-budget"):
            item, _, rec, raw = source(name)
            change, _, _ = material(rec, raw, int(rec["payload"]["rva"]) + 0x150)
            output = run(change, selected=item, when=int(rec["payload"]["captured_filetime"]) + 100)
            if name == "observed-modified":
                check(output["rules"][0]["state"] == "authorized" and output["authorized_changed_bytes"] == "1", output)
            elif name in ("clean", "observed"):
                check(output["rules"][0]["state"] == "not_applied" and output["authorized_changed_bytes"] == "0", output)
            else:
                check(output["decision"] == "incomplete_comparison" and output["authorized_changed_bytes"] == "0", output)
        for key, value, state in (("before_sha256", "0" * 64, "before_hash_mismatch"),
                                  ("after_sha256", "0" * 64, "after_hash_mismatch"),
                                  ("rva", "8192", "outside_capture")):
            bad = copy.deepcopy(baseline)
            bad["changes"][0][key] = value
            rejected = run(bad, state=state, authorized=0)
            check(rejected["decision"] == "unexplained_changes" and rejected["unexplained_changed_bytes"] == "1", rejected)
        for rva, length in recipe["payload"]["normalization"]["relocations"] + recipe["payload"]["normalization"]["loader_exclusions"]:
            bad = copy.deepcopy(baseline)
            start = max(int(rva), int(recipe["payload"]["rva"]))
            end = min(int(rva) + int(length), int(recipe["payload"]["rva"]) + int(recipe["payload"]["length"]))
            bad["changes"][0].update(rva=str(start), length=str(end - start))
            run(bad, state="normalization_overlap", authorized=0)
        many_case, _, many_recipe, many_blob = source("max-differences")
        many, _, _ = material(many_recipe, many_blob)
        report = run(many, selected=many_case, when=int(many_recipe["payload"]["captured_filetime"]) + 100)
        check(report["decision"] == "unexplained_changes" and int(report["unexplained_changed_bytes"]) > 1, "one exception cannot suppress other differences")

        run(anchor="0" * 64, issue="policy_anchor_mismatch")
        for key in ("image_sha256", "manifest_sha256", "issuer"):
            policy = policy_for(baseline)
            policy["approvals"][0][key] = "unknown" if key == "issuer" else "0" * 64
            run(policy=policy, issue="manifest_not_approved")
        for key, value, issue in (("policy_epoch", "8", "policy_epoch_mismatch"),
                                  ("comparison_policy", "future", "change_policy_unavailable"),
                                  ("hash_basis", "future", "change_policy_unavailable"),
                                  ("image_sha256", "0" * 64, "reference_not_approved")):
            bad = {**baseline, key: value}
            run(bad, issue=issue)
        for target in ("manifest", "policy"):
            for field, value, issue in (("not_after_filetime", str(captured), "approval_not_valid_at_evaluation"),
                                        ("not_before_filetime", str(captured + 1), "approval_not_valid_at_capture"),
                                        ("not_before_filetime", "18446744073709551614", "approval_not_valid_at_evaluation")):
                bad = copy.deepcopy(baseline)
                policy = policy_for(bad)
                if target == "manifest":
                    bad[field] = value
                    policy = policy_for(bad)
                else:
                    policy[field] = value
                run(bad, policy=policy, issue=issue)
        if not args.product:
            run(when=captured - 1, issue="approval_not_valid_at_capture")
            run({**baseline, "not_before_filetime": str(captured)}, when=captured, state="authorized")
            run({**baseline, "not_after_filetime": str(captured + 1)}, when=captured, state="authorized")
            run({**baseline, "not_after_filetime": str(captured + 1)}, when=captured + 1, issue="approval_not_valid_at_evaluation")

        malformed = []
        for field, value in (("schema", "kn.authorized_image_changes.v2"), ("issuer", ""), ("issuer", "x\x00y"),
                             ("policy_epoch", "07"), ("policy_epoch", "0"), ("policy_epoch", "18446744073709551616"),
                             ("policy_epoch", 7), ("not_after_filetime", "1"), ("extra", True), ("changes", [])):
            malformed.append({**baseline, field: value})
        for field, value in (("rva", "-1"), ("rva", "4294967296"), ("rva", "4294967295"), ("length", "0"),
                             ("length", "4097"), ("rva", "01"), ("length", 1), ("before_sha256", "A" * 64),
                             ("before_sha256", baseline["changes"][0]["after_sha256"]), ("extra", 1)):
            bad = copy.deepcopy(baseline)
            bad["changes"][0][field] = value
            malformed.append(bad)
        for count in (2, 129):
            malformed.append({**baseline, "changes": baseline["changes"] * count})
        for bad in malformed:
            policy = policy_for(bad)
            policy["approvals"][0]["issuer"] = baseline["issuer"]
            run(bad, policy=policy, issue="manifest_invalid")
        for bad in ({**policy_for(baseline), "extra": True}, {**policy_for(baseline), "approvals": []},
                    {**policy_for(baseline), "approvals": policy_for(baseline)["approvals"] * 2}):
            run(policy=bad, issue="policy_invalid")
        for raw in (encoded(baseline)[:-1], encoded(baseline).replace(b'"issuer":', b'"issuer":"forged","issuer":'),
                    b'\xef\xbb\xbf' + encoded(baseline), b'\xff' + encoded(baseline), b' ' * 65537):
            run(raw=raw, issue="manifest_unavailable_or_invalid_json")
        run(raw=json.dumps(baseline, ensure_ascii=False, indent=2).encode("utf-8"), state="authorized", authorized=1)
        unicode_manifest = {**baseline, "issuer": "검증용 발급자"}
        run(unicode_manifest, state="authorized", authorized=1)
        bounded = copy.deepcopy(baseline)
        bounded["changes"] = [{**baseline["changes"][0], "rva": str(int(baseline["changes"][0]["rva"]) + i)} for i in range(128)]
        run(bounded, state="authorized", authorized=1)
        bounded["changes"].append({**bounded["changes"][-1], "rva": str(int(bounded["changes"][-1]["rva"]) + 1)})
        run(bounded, issue="manifest_invalid")
        policy = policy_for(baseline)
        policy["approvals"] += [{**policy["approvals"][0], "manifest_sha256": f"{i:064x}"} for i in range(127)]
        run(policy=policy, state="authorized", authorized=1)
        policy["approvals"].append({**policy["approvals"][0], "manifest_sha256": f"{127:064x}"})
        run(policy=policy, issue="policy_invalid")

        # Bare v1/v2 retain the old claim-not-recorded contract.
        for name in ("modified", "observed-modified"):
            original_case, _, bare_recipe, _ = source(name)
            bare = root / (name + "-bare")
            shutil.copytree(original_case, bare)
            (bare / "recipe.knverify").write_bytes(encoded(bare_recipe))
            run(selected=bare, when=int(bare_recipe["payload"]["captured_filetime"]) + 100, state="authorized", authorized=1)

        # A structurally rehashed original claim is never approval evidence.
        forged = root / "forged"
        shutil.copytree(case, forged)
        changed = copy.deepcopy(document)
        changed["payload"]["recorded_claim"]["policy"] = "unavailable-policy"
        changed["publication_sha256"] = sha(encoded(changed["payload"]))
        (forged / "recipe.knverify").write_bytes(encoded(changed))
        run(selected=forged, issue="original_direct_replay_unavailable")

        # Replacing the retained PE and the matching observed bytes can replay as
        # a local match. The original pinned distribution hash still rejects it.
        replacement = root / "replacement"
        shutil.copytree(case, replacement)
        replaced = copy.deepcopy(recipe)
        payload = replaced["payload"]
        rva = int(baseline["changes"][0]["rva"])
        new_blob = bytearray(blob)
        # Owned fixture .text starts at RVA 0x1000 and file offset 0x400.
        new_blob[0x400 + rva - 0x1000] ^= 1
        payload["reference_sha256"] = sha(new_blob)
        (replacement / (sha(new_blob) + ".knblob")).write_bytes(new_blob)
        replaced["recipe_sha256"] = sha(encoded(payload))
        path = replacement / "recipe.knverify"
        path.write_bytes(encoded(replaced))
        replay_command = [str(args.exe.resolve())] + (["--offline", "!kmon", "replay-image"] if args.product else ["--report"])
        local = subprocess.run(replay_command + [str(replacement), "/current"], capture_output=True, text=True, encoding="utf-8", timeout=60)
        local_report = json.loads(local.stdout)
        check(local.returncode == 0 and local_report["result"]["changes"] == [] and int(local_report["result"]["compared_bytes"]) > 0, local_report)
        payload["recorded_result"] = local_report["result"]
        # A clean original comparison does not perform the conditional second
        # difference-confirmation read. Retain its exact executed schedule.
        page_address = int(payload["image_base"]) + int(payload["rva"])
        pages = [i for i, read in enumerate(payload["reads"]) if int(read["address"]) == page_address and int(read["length"]) == int(payload["length"])]
        check(len(pages) == 2, "owned modified recipe has two page reads")
        del payload["reads"][pages[1]]
        replaced["recipe_sha256"] = sha(encoded(payload))
        path.write_bytes(encoded(replaced))
        result = run(selected=replacement, issue="reference_not_approved")
        check(result["replay"]["status"] == "replayed" and result["reference_trust"] == "R-retained", "local retained match cannot promote to approved")

        if not args.product:
            anchor = prepare()
            process = subprocess.Popen(command(anchor) + ["approval_inputs_leased"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            ready = queue.Queue()
            reader = threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True)
            reader.start()
            try:
                check(json.loads(ready.get(timeout=30))["stage"] == "approval_inputs_leased", "observed input lease barrier")
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
                kernel.CreateFileW.restype = wintypes.HANDLE
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                for selected in (change_path, policy_path):
                    handle = kernel.CreateFileW(str(selected), 0x40000000, 7, None, 3, 0, None)
                    try:
                        check(handle == ctypes.c_void_p(-1).value and ctypes.get_last_error() == 32, "held input denies concurrent writes")
                    finally:
                        if handle != ctypes.c_void_p(-1).value:
                            kernel.CloseHandle(handle)
                process.stdin.write("continue\n")
                process.stdin.flush()
                output, errors = process.communicate(timeout=60)
                check(process.returncode == 0 and json.loads(output)["rules"][0]["state"] == "authorized", errors)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
                reader.join(timeout=2)
        else:
            anchor = prepare()
            for suffix in (["/json"], ["/bad"], ["/current"]):
                process = subprocess.run(command(anchor) + suffix, capture_output=True, text=True, encoding="utf-8", timeout=30)
                check(process.returncode == 2 and "usage" in process.stderr, "CLI rejects duplicate/unknown options")
            # Closing the output consumer cannot be reported as successful delivery.
            process = subprocess.Popen(command(anchor), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.stdout.close()
            process.wait(timeout=60)
            check(process.returncode == 3, "JSON delivery failure is explicit")
            process.stderr.close()
    print(f"[image.authorized.changes] checks={checks} mode={'product' if args.product else 'harness'} independent_original_bytes=true")


if __name__ == "__main__":
    main()
