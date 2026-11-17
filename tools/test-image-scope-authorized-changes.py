"""Scoped approval controls using retained PE bytes and original returned receipts."""
import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import queue
import shutil
import stat
import subprocess
import tempfile
import threading

from image_claim_oracle import normalized_pe
from image_scope_claim_oracle import check_scope_report, derive_slice


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def inner(document):
    return document["payload"]["artifact"] if document["schema"] == "kn.image_scope_claim_publication.v1" else document


def policy_for(manifest, raw=None):
    return dict(schema="kn.image_approval_policy.v1", policy_id="owned-scope-policy", policy_epoch="7",
                not_before_filetime="1", not_after_filetime="18446744073709551615",
                approvals=[dict(image_sha256=manifest["image_sha256"], issuer=manifest["issuer"],
                                manifest_sha256=sha(encoded(manifest) if raw is None else raw))])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    exe, fixtures = args.exe.resolve(), args.fixtures.resolve()
    checks = 0

    def check(value, message):
        nonlocal checks
        assert value, str(message)[:2000]
        checks += 1

    def target(name):
        return fixtures / name / ("image-sweeps/sweep-7-1.knsweep" if name.startswith("sweep_") else "image-reads/slice.knslice")

    def source(path):
        document = inner(json.loads(path.read_bytes()))
        p, root = document["payload"], path.parent.parent
        if document["schema"] == "kn.image_sweep.v1":
            recipes = [inner(json.loads((root / "image-reads" / f"reads-{p['sweep']['collection_id']}-{row['read_set_id']}.knslice").read_bytes()))
                       for row in p["slices"]]
        else:
            recipes = [document]
        blobs = [(root / "image-references" / (recipe["payload"]["reference_sha256"] + ".knblob")).read_bytes() for recipe in recipes]
        return document, recipes, blobs

    def material(path, rva=0x1050, length=1):
        document, recipes, blobs = source(path)
        before, after = bytearray(length), bytearray(length)
        for recipe, blob in zip(recipes, blobs):
            p = recipe["payload"]
            derive_slice(recipe, blob)  # Independent counters, PE normalization, and original receipt binding.
            reads = p["target_reads"]
            for page in p["recorded_result"]:
                c = page["comparison"]
                start, size = int(c["rva"]), int(c["requested_bytes"])
                expected = normalized_pe(blob, int(p["slice"]["relocation_base"]), start, size)
                observed = expected
                for call in reads["parser_reads"]:
                    if call["accepted"] and int(call["address"]) == int(p["image_base"]) + start and int(call["length"]) == size:
                        receipt = reads["attempts"]["reads"][int(call["returned_receipt"]) - 1]["read"]
                        if receipt["status"] == "complete":
                            observed = b"".join(bytes.fromhex(span["bytes_hex"]) for span in receipt["spans"])
                            break
                for address in range(max(start, rva), min(start + size, rva + length)):
                    before[address - rva], after[address - rva] = expected[address - start], observed[address - start]
        if before == after:
            after[0] ^= 1  # Proposed, unapplied change; never an authorization oracle.
        policy = document["payload"].get("policy", "kn.executable_sweep.temporal.v1")
        return dict(schema="kn.authorized_image_changes.v1", image_sha256=sha(blobs[0]), issuer="owned-scope-issuer",
                    policy_epoch="7", not_before_filetime="1", not_after_filetime="18446744073709551615",
                    comparison_policy=policy, hash_basis="non_fixup_compared_bytes.v1",
                    changes=[dict(rva=str(rva), length=str(length), before_sha256=sha(before), after_sha256=sha(after))])

    baseline_path = target("modified")
    baseline = material(baseline_path)
    all_times = [int(recipe["payload"]["captured_filetime"]) for name in ("modified", "sweep_boundary_modified") for recipe in source(target(name))[1]]
    when = max(all_times) + 10000
    with tempfile.TemporaryDirectory(prefix="scope-approval-", dir=fixtures) as temporary:
        root = Path(temporary).resolve()
        check(root.is_relative_to(fixtures), "owned scratch root")
        change_path, policy_path = root / "변경.knchange", root / "정책.knapproval"

        def prepare(manifest=baseline, policy=None, raw=None):
            data = encoded(manifest) if raw is None else raw
            change_path.write_bytes(data)
            policy_path.write_bytes(encoded(policy_for(manifest, data) if policy is None else policy))
            return sha(policy_path.read_bytes())

        def command(anchor, selected=baseline_path, at=when):
            return [str(exe)] + (["--offline", "!kmon", "assess-image"] if args.product else ["--assess-scope"]) + \
                list(map(str, [selected, change_path, policy_path, anchor])) + (["/json"] if args.product else [str(at)])

        def run(manifest=baseline, selected=baseline_path, policy=None, raw=None, anchor=None, at=when, issue="", state=None, authorized=None):
            actual_anchor = prepare(manifest, policy, raw)
            before = {path: path.read_bytes() for path in (change_path, policy_path, selected) if path.exists()}
            process = subprocess.run(command(anchor or actual_anchor, selected, at), capture_output=True, encoding="utf-8", timeout=60)
            check(process.returncode == (1 if issue else 0), (process.returncode, process.stdout[-2000:], process.stderr))
            report = json.loads(process.stdout)
            check(report["schema"] == "kn.image_scope_change_assessment.v1" and report["issue"] == issue, report)
            check(all(path.read_bytes() == data for path, data in before.items()), "read-only input preservation")
            check(not any(report[key] for key in ("atomic_snapshot", "issuer_signature_verified", "collector_authenticated",
                                                  "execution_observed", "current_image_state_known", "journal_membership_checked")), report)
            if issue:
                check(report["status"] == "unavailable" and not report["reference_approved"] and not report["comparison_complete"] and
                      report["authorized_changed_bytes"] == "0" and report["rules"] == [] and report["authorized_ranges"] == [], report)
            else:
                document, recipes, blobs = source(selected)
                check_scope_report(document, recipes, blobs, report["replay"])
                check(report["status"] == "assessed" and report["reference_trust"] == "R-approved", report)
                check(report["root_file_sha256"] == sha(selected.read_bytes()) and report["policy_sha256"] == actual_anchor, report)
                check(report["root_semantic_sha256"] == document.get("recipe_sha256", document.get("manifest_sha256")), report)
                changed = sum(derive_slice(recipe, blob)["difference_bytes"] for recipe, blob in zip(recipes, blobs))
                check(int(report["observed_changed_bytes"]) == changed == int(report["authorized_changed_bytes"]) + int(report["unexplained_changed_bytes"]), report)
                for field, count in (("authorized_ranges", "authorized_changed_bytes"), ("unexplained_ranges", "unexplained_changed_bytes")):
                    spans = report[field]
                    check(sum(int(span["length"]) for span in spans) == int(report[count]) and
                          all(int(a["rva"]) + int(a["length"]) <= int(b["rva"]) for a, b in zip(spans, spans[1:])), report)
                check(report["assembly_basis"] == "retained_observation_parts" and len(report["observations"]) == len(recipes), report)
                for row, recipe in zip(report["observations"], recipes):
                    check(row["recipe_sha256"] == recipe["recipe_sha256"] and row["captured_filetime"] == recipe["payload"]["captured_filetime"] and
                          row["comparison_policy"] == recipe["payload"]["policy"], row)
                for row, recipe, blob in zip(report["observations"], recipes, blobs):
                    check(row["identity_qualified"] == derive_slice(recipe, blob)["identity"], row)
            if state:
                check(report["rules"][0]["state"] == state, report)
            if authorized is not None:
                check(int(report["authorized_changed_bytes"]) == authorized, report)
            return report

        output = run(state="authorized", authorized=1)
        check(output["decision"] == "incomplete_comparison" and output["membership_complete"], "IAT exclusion remains partial")
        cases = {
            "clean": (0x1050, "not_applied", 0), "secondary_verified": (0x1050, "not_applied", 0),
            "secondary_modified": (0x1050, "authorized", 1), "continuation": (0x2050, "not_applied", 0),
            "unstable": (0x1050, "not_fully_compared", 0), "secondary_unstable": (0x1050, "not_fully_compared", 0),
            "unreadable": (0x1050, "outside_observed_ranges", 0), "identity": (0x1050, "not_fully_compared", 0),
            "guard": (0x1050, "outside_observed_ranges", 0), "secondary": (0x1050, "outside_observed_ranges", 0),
            "sweep_clean": (0x1050, "not_applied", 0), "sweep_modified": (0x1050, "authorized", 1),
            "sweep_secondary": (0x1050, "not_applied", 0), "sweep_excluded": (0x1100, "normalization_overlap", 0),
            "sweep_gap": (0x2050, "not_applied", 0), "sweep_interrupted": (0x1050, "not_applied", 0),
            "sweep_modified_gap": (0x2050, "authorized", 1), "sweep_modified_interrupted": (0x1050, "authorized", 1),
            "sweep_partial_modified": (0x2050, "authorized", 1), "sweep_unstable": (0x1050, "not_fully_compared", 0),
            "sweep_raw_lost": (0x1050, "not_applied", 0)}
        for name, (rva, state, count) in cases.items():
            selected = target(name)
            report = run(material(selected, rva), selected, state=state, authorized=count)
            if name in ("sweep_gap", "sweep_interrupted", "sweep_modified_gap", "sweep_modified_interrupted", "sweep_partial_modified"):
                check(not report["comparison_complete"] and report["decision"] == "incomplete_comparison", name)
            if name == "sweep_raw_lost":
                check(report["replay"]["result"]["raw_publication_failures"] == "2", "raw publication loss remains in original replay")
        for name in ("boundary_modified", "sweep_boundary_modified"):
            selected = target(name)
            report = run(material(selected, 0x1fff, 2), selected, state="authorized", authorized=2)
            rule = report["rules"][0]
            check(len(rule["parts"]) == 2 and rule["spans_recipe_observations"] == name.startswith("sweep_"), rule)
            check([int(part["rva"]) for part in rule["parts"]] == [0x1fff, 0x2000] and all(part["length"] == "1" for part in rule["parts"]), rule)
            check(report["comparison_complete"] == name.startswith("sweep_"), report)
            partial = material(selected, 0x1fff)
            report = run(partial, selected, state="authorized", authorized=1)
            check(report["decision"] == "unexplained_changes" and report["unexplained_changed_bytes"] == "1", report)
        run(material(target("sweep_modified_gap"), 0x1fff, 2), target("sweep_modified_gap"), state="not_fully_compared", authorized=0)
        for rva, length in ((0x1020, 8), (0x1100, 8), (0x101f, 2)):
            run(material(baseline_path, rva, length), state="normalization_overlap", authorized=0)
        for field, value, state in (("before_sha256", "0" * 64, "before_hash_mismatch"), ("after_sha256", "0" * 64, "after_hash_mismatch"),
                                    ("rva", "16384", "outside_observed_ranges")):
            bad = copy.deepcopy(baseline)
            bad["changes"][0][field] = value
            run(bad, state=state, authorized=0)
        run(anchor="0" * 64, issue="policy_anchor_mismatch")
        if not args.product:
            run(anchor="bad", issue="invalid_policy_anchor")
        for field, value, issue in (("policy_epoch", "8", "policy_epoch_mismatch"), ("comparison_policy", "future", "change_policy_unavailable"),
                                    ("comparison_policy", "kn.executable_slice.secondary.v1", "change_policy_scope_mismatch"),
                                    ("hash_basis", "future", "change_policy_unavailable"), ("image_sha256", "0" * 64, "reference_not_approved")):
            run({**baseline, field: value}, issue=issue)
        for field in ("image_sha256", "issuer", "manifest_sha256"):
            policy = policy_for(baseline)
            policy["approvals"][0][field] = "unapproved" if field == "issuer" else "0" * 64
            run(policy=policy, issue="manifest_not_approved")
        for bad in ({**baseline, "extra": True}, {**baseline, "changes": []}, {**baseline, "changes": baseline["changes"] * 2},
                    {**baseline, "policy_epoch": "07"}, {**baseline, "issuer": ""}):
            policy = policy_for(bad)
            policy["approvals"][0]["issuer"] = baseline["issuer"]
            run(bad, policy=policy, issue="manifest_invalid")
        for field, value in (("length", "4097"), ("length", "0"), ("rva", "4294967295"), ("before_sha256", "A" * 64)):
            bad = copy.deepcopy(baseline)
            bad["changes"][0][field] = value
            run(bad, issue="manifest_invalid")
        for raw in (encoded(baseline)[:-1], b'\xef\xbb\xbf' + encoded(baseline), b'\xff' + encoded(baseline), b' ' * 65537,
                    encoded(baseline).replace(b'"issuer":', b'"issuer":"forged","issuer":')):
            run(raw=raw, issue="manifest_unavailable_or_invalid_json")
        run({**baseline, "issuer": "검증용 발급자"}, state="authorized", authorized=1)
        run(raw=json.dumps(baseline, indent=2).encode(), state="authorized", authorized=1)
        bounded = copy.deepcopy(baseline)
        bounded["changes"] = [{**baseline["changes"][0], "rva": str(0x1050 + i)} for i in range(128)]
        run(bounded, state="authorized", authorized=1)
        bounded["changes"].append({**bounded["changes"][-1], "rva": str(0x1050 + 128)})
        run(bounded, issue="manifest_invalid")
        run(material(target("sweep_boundary_modified"), 0x1800, 4096), target("sweep_boundary_modified"), state="authorized", authorized=2)
        for name in ("modified", "sweep_boundary_modified"):
            selected = target(name)
            manifest = material(selected)
            document, recipes, _ = source(selected)
            times = [int(recipe["payload"]["captured_filetime"]) for recipe in recipes]
            if name.startswith("sweep_"):
                times += [int(document["payload"]["sweep"]["started_filetime"])] + [int(row["observed_filetime"]) for row in document["payload"]["slices"]]
            for item in ("manifest", "policy"):
                for field, value, issue in (("not_after_filetime", str(max(times)), "approval_not_valid_at_evaluation"),
                                            ("not_before_filetime", str(min(times) + 1), "approval_not_valid_at_observation")):
                    bad = copy.deepcopy(manifest)
                    policy = policy_for(bad)
                    if item == "manifest":
                        bad[field] = value
                        policy = policy_for(bad)
                    else:
                        policy[field] = value
                    run(bad, selected, policy, issue=issue)
            if not args.product:
                run(manifest, selected, at=min(times) - 1, issue="approval_not_valid_at_observation")
                run({**manifest, "not_before_filetime": str(min(times)), "not_after_filetime": str(max(times) + 1)}, selected, at=max(times))
        # Original claim publications and bare historical inputs share the byte oracle.
        for name in ("modified", "secondary_modified", "sweep_modified"):
            selected = fixtures / "scope-claim-publications" / name / target(name).relative_to(fixtures / name)
            report = run(material(selected), selected, state="authorized", authorized=1)
            check(report["replay"]["original_claim_replay"]["status"] == "reproduced", report)
        copied = root / "forged"
        shutil.copytree(fixtures / "scope-claim-publications" / "modified", copied)
        forged = copied / "image-reads/slice.knslice"
        document = json.loads(forged.read_bytes())
        document["payload"]["recorded_claim"]["policy"] = "future"
        document["publication_sha256"] = sha(encoded(document["payload"]))
        forged.write_bytes(encoded(document))
        run(selected=forged, issue="original_scope_replay_unavailable")
        late = root / "late-child"
        shutil.copytree(fixtures / "sweep_boundary_modified", late)
        selected = late / "image-sweeps/sweep-7-1.knsweep"
        document = json.loads(selected.read_bytes())
        child = late / "image-reads/reads-7-2.knslice"
        recipe = json.loads(child.read_bytes())
        recipe["payload"]["captured_filetime"] = "18446744073709551614"
        recipe["recipe_sha256"] = sha(encoded(recipe["payload"]))
        child.write_bytes(encoded(recipe))
        document["payload"]["slices"][1]["recipe_sha256"] = recipe["recipe_sha256"]
        document["manifest_sha256"] = sha(encoded(document["payload"]))
        selected.write_bytes(encoded(document))
        run(material(target("sweep_boundary_modified")), selected, issue="approval_not_valid_at_observation")

        if not args.product:
            # Observed lease barrier, then open-for-write denial and path alias switch.
            alias = root / "alias"
            created = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(fixtures / "modified")], capture_output=True)
            check(created.returncode == 0 and alias.lstat().st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT, "owned junction created")
            anchor = prepare()
            process = subprocess.Popen(command(anchor, alias / "image-reads/slice.knslice") + ["scope_root_leased"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            ready = queue.Queue()
            reader = threading.Thread(target=lambda: ready.put(process.stderr.readline()), daemon=True)
            reader.start()
            try:
                check(ready.get(timeout=30).strip() == "leased:scope_root_leased", "observed root lease")
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
                kernel.CreateFileW.restype = wintypes.HANDLE
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                for path in (change_path, policy_path, baseline_path):
                    handle = kernel.CreateFileW(str(path), 0x40000000, 7, None, 3, 0, None)
                    try:
                        check(handle == ctypes.c_void_p(-1).value and ctypes.get_last_error() == 32, "held approval/root denies write")
                    finally:
                        if handle != ctypes.c_void_p(-1).value:
                            kernel.CloseHandle(handle)
                alias.rmdir()  # Remove only this verified junction, never its target.
                changed = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(fixtures / "clean")], capture_output=True)
                check(changed.returncode == 0 and alias.lstat().st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT, "alias switched after root acquisition")
                process.stdin.write("continue\n")
                process.stdin.flush()
                out, error = process.communicate(timeout=60)
                report = json.loads(out)
                check(process.returncode == 0 and report["root_file_sha256"] == sha(baseline_path.read_bytes()) and report["authorized_changed_bytes"] == "1", (report, error))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                reader.join(timeout=2)
                for pipe in (process.stdin, process.stdout, process.stderr):
                    pipe.close()
                if alias.exists():
                    check(alias.lstat().st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT, "cleanup only junction")
                    alias.rmdir()
            # If this filesystem permits renaming an ancestor of a leased file,
            # restore it before final validation: pathname rechecks alone miss the switch.
            leased, substitute, moved = (root / name for name in ("leased-case", "substitute-case", "moved-case"))
            shutil.copytree(fixtures / "modified", leased)
            shutil.copytree(fixtures / "clean", substitute)
            selected = leased / "image-reads/slice.knslice"
            anchor = prepare()
            process = subprocess.Popen(command(anchor, selected) + ["scope_path_cycle"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
            ready = queue.Queue()
            def stages():
                for _ in range(2):
                    ready.put(process.stderr.readline().strip())
            reader = threading.Thread(target=stages, daemon=True)
            reader.start()
            switched = False
            try:
                check(ready.get(timeout=30) == "leased:scope_root_leased", "original handle acquired before parent switch")
                try:
                    leased.rename(moved)
                except OSError as error:
                    check(error.winerror in (5, 32), "filesystem blocks moving the leased parent")
                else:
                    substitute.rename(leased)
                    switched = True
                process.stdin.write("continue\n")
                process.stdin.flush()
                check(ready.get(timeout=30) == "leased:scope_original_replayed", "replay completed before pathname restoration")
                reader.join(timeout=2)
                if switched:
                    leased.rename(substitute)
                    moved.rename(leased)
                process.stdin.write("continue\n")
                process.stdin.flush()
                out, error = process.communicate(timeout=60)
                report = json.loads(out)
                check(process.returncode == (1 if switched else 0), (report, error))
                check(report["issue"] == ("scope_root_binding_mismatch" if switched else ""), report)
                check(report["root_file_sha256"] == sha(baseline_path.read_bytes()) and selected.read_bytes() == baseline_path.read_bytes(), report)
                if switched:
                    check(not report["reference_approved"] and report["authorized_changed_bytes"] == "0", report)
                print(f"[image.scope.root.binding] ancestor_switch_exercised={str(switched).lower()}")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                reader.join(timeout=2)
                for pipe in (process.stdin, process.stdout, process.stderr):
                    pipe.close()
        else:
            anchor = prepare()
            for suffix in (["/json"], ["/bad"], ["/current"]):
                process = subprocess.run(command(anchor) + suffix, capture_output=True, encoding="utf-8", timeout=30)
                check(process.returncode == 2 and "usage" in process.stderr, "CLI unknown/duplicate option")
            process = subprocess.Popen(command(anchor), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdout.close()
                process.wait(timeout=60)
                check(process.returncode == 3, "failed JSON delivery is explicit")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                process.stdout.close()
                process.stderr.close()
    print(f"[image.scope.authorized.changes] checks={checks} mode={'product' if args.product else 'harness'} independent_original_bytes=true")


if __name__ == "__main__":
    main()
