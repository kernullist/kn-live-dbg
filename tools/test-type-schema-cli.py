"""Exercise offline schema publication and hostile package input without a driver."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    exe = args.exe.resolve()
    fixtures = args.fixtures.resolve()
    checks = 0

    def check(ok, description):
        nonlocal checks
        assert ok, description
        checks += 1

    def run(*arguments, success=True):
        result = subprocess.run([str(exe), "--schema", *map(str, arguments)],
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        check((result.returncode == 0) == success, f"command exit: {arguments[0] if arguments else '<missing>'}")
        if not success:
            check(not result.stdout.strip() and bool(result.stderr.strip()), "failure must not publish a success DTO")
        return result

    def encode(package):
        payload = json.dumps(package["payload"], ensure_ascii=False, separators=(",", ":"))
        package["package_sha256"] = hashlib.sha256(payload.encode()).hexdigest()
        return json.dumps(package, ensure_ascii=False, separators=(",", ":"))

    with tempfile.TemporaryDirectory(prefix="schema-cli-", dir=fixtures) as temporary:
        root = Path(temporary)
        output = root / "owned.knschema"
        image, pdb = fixtures / "fixture-a.exe", fixtures / "fixture-a.pdb"
        result = run("create", image, pdb, "PdbIdentityFixture", output)
        package = json.loads(result.stdout)
        data = output.read_bytes()
        check(package["schema"] == "kn.type_schema.v1" and encode(copy.deepcopy(package)).encode() == data,
              "independent Python hash and canonical encoding agree")
        payload = package["payload"]
        for field, path in (("image_sha256", image), ("pdb_sha256", pdb),
                            ("provider_sha256", exe.parent / "msdia140.dll")):
            check(payload[field] == hashlib.sha256(path.read_bytes()).hexdigest(), "artifact hash matches actual bytes")
        check(not payload["trusted_distribution"] and not payload["runtime_invariants_checked"] and
              not payload["parser_isolated"], "package does not upgrade its evidence or isolation")
        check(json.loads(run("inspect", output).stdout) == package, "fresh process reconstructs the same package")
        run("create", image, pdb, "PdbIdentityFixture", output, success=False)
        check(output.read_bytes() == data, "collision preserves existing publication")
        for arguments in ((), ("inspect",), ("inspect", output, "extra"), ("unknown", output),
                          ("create", image, pdb, "PdbIdentityFixture", output, "extra")):
            run(*arguments, success=False)
        for target, suffix in (("MissingType", "missing"), ("pdbidentityfixture", "case")):
            failed = root / (suffix + ".knschema")
            run("create", image, pdb, target, failed, success=False)
            check(not failed.exists(), "failed type selection leaves no publication")
        run("create", image, fixtures / "fixture-b.pdb", "PdbIdentityFixture", root / "wrong.knschema", success=False)
        invalid = root / "invalid.knschema"

        def reject_document(document, rehash=True):
            invalid.write_text(encode(document) if rehash else document, encoding="utf-8", newline="")
            run("inspect", invalid, success=False)

        for mutation in ("overflow", "duplicate", "child_extent", "pointer_expansion", "tag_conflict",
                         "bit_overrun", "claimed_trust", "root_mode", "unknown_field", "machine", "missing_depth_gap"):
            changed = copy.deepcopy(package)
            fields = changed["payload"]["fields"]
            by_path = {tuple(f["path"]): f for f in fields}
            if mutation == "overflow":
                fields[0]["storage_bytes"] = str(2**64 - 1)
            elif mutation == "duplicate":
                fields.append(copy.deepcopy(fields[0]))
            elif mutation == "child_extent":
                by_path[("Nested", "Counter")]["offset"] = "0"
            elif mutation == "pointer_expansion":
                by_path[("Next",)]["expansion"] = "embedded"
            elif mutation == "tag_conflict":
                by_path[("Value",)]["symbol_tag"] = "14"
            elif mutation == "bit_overrun":
                by_path[("Flags",)]["bit_width"] = "33"
            elif mutation == "claimed_trust":
                changed["payload"]["trusted_distribution"] = True
            elif mutation == "root_mode":
                changed["payload"]["root_interpretation"] = "follow_pointer"
            elif mutation == "unknown_field":
                fields[0]["unexpected"] = "value"
            elif mutation == "machine":
                changed["payload"]["machine"] = "332"
            else:
                fields[0]["symbol_tag"] = "17"
                fields[0]["expansion"] = "unavailable"
                fields[0]["bit_width"] = "0"
            reject_document(changed)
        for malformed in (data.decode() + " ", data.decode()[:-1], "[]", "{}", "null", "not JSON",
                          data.decode().replace('"schema":', '"schema":"duplicate","schema":', 1)):
            reject_document(malformed, False)
        changed = copy.deepcopy(package)
        changed["payload"]["type_name"] = "ChangedType"
        reject_document(json.dumps(changed, separators=(",", ":")), False)
        invalid.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        run("inspect", invalid, success=False)
        corrupt_pdb = root / "corrupt.pdb"
        corrupt_pdb.write_bytes(b"owned malformed PDB control")
        run("create", image, corrupt_pdb, "PdbIdentityFixture", root / "corrupt.knschema", success=False)
        symlink_skipped = 0
        link = root / "link.knschema"
        try:
            link.symlink_to(output)
        except OSError:
            symlink_skipped = 1
        else:
            run("inspect", link, success=False)
        check(not list(root.glob("*.pending-*")), "normal failure paths leave no temporary publications")
    print(f"type schema CLI passed: {checks} checks, symlink_skipped={symlink_skipped}; no live target")


if __name__ == "__main__":
    main()
