"""Check compiled capability claims without starting a live controller."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    exe = str(args.exe.resolve())
    result = subprocess.run([exe, "--capabilities"], capture_output=True, text=True,
                            check=True, timeout=30)
    data = json.loads(result.stdout)
    assert data["schema"] == "kn.capabilities.v1"
    assert data["scope"] == "compiled_contract" and data["target_probed"] is False
    assert data["inventory_complete"] is False
    assert data["target"] == {"os_build": None, "security_state": "unknown",
                              "virtual_address_bits": None, "validation": "not_performed"}
    root = Path(__file__).resolve().parents[1]
    abi = re.search(r"#define KNDBG_ABI_VERSION (\d+)u",
                    (root / "shared/KnLiveDbgIoctl.h").read_text()).group(1)
    assert data["driver_abi"] == int(abi)
    keys = [(c["domain"], c["operation"], c["backend"]) for c in data["capabilities"]]
    assert len(set(keys)) == len(keys)
    for capability in data["capabilities"]:
        assert capability["availability"] == "not_probed"
        assert capability["requirements"] and capability["limits"]
    by_key = dict(zip(keys, data["capabilities"]))
    policy = by_key[("session", "mutation_gate", "native")]
    assert "default_write_denied_driver_flag" in policy["requirements"]
    assert "confirmed_session_status" in policy["requirements"]
    assert "not_an_observe_collect_partition" in policy["limits"]
    assert by_key[("security", "inspect_vtl1_memory", "native")]["implementation"] == "unsupported"
    assert by_key[("io", "interpose_dispatch", "native")]["implementation"] == "experimental"
    assert "image_verification_not_replayed" in by_key[("evidence", "replay", "bundle")]["limits"]
    assert "single_bundle_fact_graph" in by_key[("evidence", "graph", "bundle")]["limits"]
    assert "graph_and_query_bound_cursor" in by_key[("evidence", "graph", "bundle")]["requirements"]
    assert "qualified_paging_depth" in by_key[("memory", "read_virtual", "dump")]["requirements"]
    assert "not_captured_vs_not_present" in by_key[("memory", "read_virtual", "dump")]["limits"]
    schema = by_key[("schema", "export_type", "local_pdb")]
    assert "exact_amd64_image_pdb_identity" in schema["requirements"]
    assert "cli_parser_process_containment" in schema["limits"] and "no_runtime_qualification" in schema["limits"]
    assert "other_symbol_paths_not_isolated" in schema["limits"] and "no_filesystem_or_network_sandbox" in schema["limits"]
    assert "exact_reference_blob" in by_key[("image", "replay_verification", "recipe")]["requirements"]
    assert "direct_mapping_basis" in by_key[("image", "capture_verification", "dump")]["limits"]
    assert "claim_specific_requirements" in by_key[("proof", "image_range", "recipe")]["requirements"]
    assert "no_hard_deadline_or_measured_slo" in by_key[("scheduler", "capture_timing", "native")]["limits"]
    cross_view = by_key[("process", "cross_view", "native")]
    assert "matching_pid_eprocess_create_time" in cross_view["requirements"]
    assert "unverified_candidates_retained" in cross_view["limits"]
    assert "shared_api_dependency" in cross_view["limits"]
    registry = (root / "user/CommandRegistry.cpp").read_text(encoding="utf-8-sig")
    expected = re.findall(r'Make\(L"([^"\n]+)",\s*L"([^"\n]*)",[^\n]*?CommandSupport::(\w+)\)', registry)
    assert expected, "command registry was not parsed"
    actual = [(c["name"], c["canonical"], c["route"]) for c in data["commands"]]
    assert actual == [(name, canonical, route.lower()) for name, canonical, route in expected]
    invalid = subprocess.run([exe, "--capabilities", "unexpected"], capture_output=True,
                             text=True, timeout=30)
    assert invalid.returncode != 0 and not invalid.stdout.strip()
    help_result = subprocess.run([exe, "--help"], capture_output=True, text=True,
                                 check=True, timeout=30)
    assert "--capabilities" in help_result.stdout
    assert "--schema create" in help_result.stdout and "--schema inspect" in help_result.stdout
    print(f"source capabilities passed: {len(keys)} contracts, {len(actual)} command routes")


if __name__ == "__main__":
    main()
