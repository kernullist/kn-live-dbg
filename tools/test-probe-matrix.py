"""Compare generated probe contracts with actual CLI modes and saved artifacts."""
import argparse
from contextlib import redirect_stdout
from collections import Counter
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
from runpy import run_path
import subprocess
import sys
import tempfile
from unittest.mock import patch


def report(exe, *args):
    result = subprocess.run([exe, *args], capture_output=True, timeout=90, check=True)
    assert not result.stderr
    return json.loads(result.stdout)


def rejects(render, case):
    try:
        render(case)
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError("invalid inventory reached public matrix generation")


def malformed_inventories(data):
    def vary(edit):
        case = deepcopy(data)
        edit(case)
        return case

    first = lambda case: case["probe_contracts"][0]
    row = lambda case: case["capabilities"][0]
    yield vary(lambda c: c["probe_contracts"].append(first(c)))
    yield vary(lambda c: c["probe_contracts"].append(dict(first(c), id="unused")))
    yield vary(lambda c: c["probe_contracts"].append(dict(first(c), id="new", invocation="--capabilities --probe --other")))
    yield vary(lambda c: first(c).update(invocation="--capabilities --probe\nother"))
    yield vary(lambda c: first(c).update(invocation="--capabilities --probe & echo text"))
    yield vary(lambda c: first(c).update(id="foreign|column"))
    yield vary(lambda c: first(c).update(observation="first\u2028second"))
    yield vary(lambda c: first(c).update(extra="unscoped"))
    yield vary(lambda c: row(c).update(probe_contract="unknown"))
    yield vary(lambda c: row(c).pop("probe_contract"))
    yield vary(lambda c: row(c).update(probe_contract="owned_read", implementation="unsupported"))
    yield vary(lambda c: row(c).update(availability_scope="owned_control_range_only"))
    yield vary(lambda c: row(c).update(validation="validated"))
    yield vary(lambda c: row(c)["probe_stages"].update(source_opened="passed"))
    yield vary(lambda c: row(c).pop("probe_stages"))
    yield vary(lambda c: row(c).update(range_evidence=None))
    yield vary(lambda c: row(c).update(record_evidence={}))
    yield vary(lambda c: c["target"].update(os_build=1))
    yield vary(lambda c: c.pop("target"))
    yield vary(lambda c: c.pop("probe_contracts"))
    yield vary(lambda c: c.update(probe={}))
    yield vary(lambda c: c.update(scope="saved_dump_probe"))
    yield vary(lambda c: c["capabilities"].append(row(c)))


def test_publication(generator, data):
    valid = json.dumps(data)
    duplicate = valid.replace('"compiled_contract"', '"saved_dump_probe", "scope": "compiled_contract"', 1)
    assert valid != duplicate
    invalid = (duplicate, valid[:-2], json.dumps(dict(data, probe={})))
    with tempfile.TemporaryDirectory(prefix="kn-probe-matrix-") as folder:
        root = Path(folder)
        exe, output = root / "inventory.exe", root / "matrix.md"
        output.write_bytes(b"prior matrix\n")
        for payload in invalid:
            with (patch.object(sys, "argv", ["matrix", "--exe", str(exe), "--output", str(output)]),
                  patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=payload)) as launch,
                  redirect_stdout(io.StringIO())):
                assert generator["main"]() == 1
            assert launch.call_args.args[0] == [str(exe.resolve()), "--capabilities"]
            assert output.read_bytes() == b"prior matrix\n" and list(root.iterdir()) == [output]
    return len(invalid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--dump", type=Path, required=True, help="owned probed-4.dmp from the dump-source harness")
    parser.add_argument("--etl", type=Path, required=True, help="saved ETL with a stable, loss-free scan")
    args = parser.parse_args()
    exe, dump, etl = (p.resolve(strict=True) for p in (args.exe, args.dump, args.etl))
    with dump.open("rb") as stream:
        header_pin = hashlib.sha256(stream.read(8192)).hexdigest()
    with etl.open("rb") as stream:
        etl_pin = hashlib.file_digest(stream, "sha256").hexdigest()
    data = report(exe, "--capabilities")
    generator = run_path(str(Path(__file__).with_name("generate-support-matrix.py")))
    render = generator["render"]
    audit = run_path(str(Path(__file__).with_name("validate-public-content.py")))["inspect"]
    catalog = {contract["id"]: contract for contract in data["probe_contracts"]}
    public = render(data)
    assert not audit("inventory.json", json.dumps(data).encode()) and not audit("matrix.md", public.encode())
    for mode in ("offline", "observe"):
        assert report(exe, "--mode", mode, "--capabilities") == data
    for contract in catalog.values():
        assert contract["invocation"] in public and contract["availability_scope"] in public

    calls = ((["--capabilities", "--probe"], {"owned_read", "native_connection"}, False),
             (["--mode", "observe", "--capabilities", "--probe", "--allow-residency"], {"owned_read", "native_connection"}, True),
             (["--capabilities", "--probe-dump", dump, "--header-sha256", header_pin], {"saved_dump_range"}, False),
             (["--capabilities", "--probe-etl", etl, "--sha256", etl_pin], {"saved_etl_family"}, False))
    counts = Counter(row["probe_contract"] for row in data["capabilities"])
    for argv, selected, restricted in calls:
        evidence = report(exe, *argv)
        assert "probe_contracts" not in evidence and len(evidence["capabilities"]) == len(data["capabilities"])
        assert audit("observed.json", json.dumps(evidence).encode())
        rejects(render, evidence)
        scoped = Counter()
        for static, observed in zip(data["capabilities"], evidence["capabilities"], strict=True):
            assert all(static[key] == observed[key] for key in ("domain", "backend", "operation", "implementation"))
            assert "probe_contract" not in observed
            route = static["probe_contract"]
            if route in selected:
                scope = catalog[route]["availability_scope"]
                if restricted and route == "native_connection":
                    assert observed["availability"] == "blocked_by_policy"
                    scope = "launch_policy"
                assert observed["availability_scope"] == scope and observed["availability"] != "not_probed"
                scoped[route] += 1
            else:
                scope = "launch_policy" if restricted and static["backend"] == "native" else "not_probed"
                assert observed["availability_scope"] == scope
                if scope == "launch_policy":
                    assert static["implementation"] == observed["availability"] == "unsupported"
                assert observed["probe_stages"] == static["probe_stages"]
        assert scoped == {route: counts[route] for route in selected}

    legacy = deepcopy(data)
    del legacy["probe_contracts"]
    for row in legacy["capabilities"]:
        del row["probe_contract"]
    old = render(legacy)
    assert "does not declare its probe catalog" in old and "| Probe contract |" not in old
    assert not any(c["invocation"] in old for c in catalog.values())
    cases = list(malformed_inventories(data))
    for case in cases:
        rejects(render, case)
    quoted = deepcopy(data)
    quoted["probe_contracts"][0]["observation"] = "<element> | [link](example)"
    escaped = render(quoted)
    assert r"&lt;element&gt; \| \[link\](example)" in escaped
    refused_writes = test_publication(generator, data)
    print(f"Probe catalog passed: {len(catalog)} contracts, {sum(counts[r] for r in catalog)} scoped rows, "
          f"{len(calls)} observed modes, {len(cases)} rejected inventories, {refused_writes} preserved outputs and legacy rendering")


if __name__ == "__main__":
    main()
