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
        assert capability["availability_scope"] == "none"
        assert capability["address_contract"]
        assert capability["validation"] == "not_performed_for_target_environment"
        assert capability["probe_stages"] == {
            "source_opened": "not_probed", "sample_read": "not_probed", "layout_qualified": "not_probed",
            "semantic_validation": "not_probed", "environment_regression": "not_performed"}
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
    sweep_graph = by_key[("evidence", "graph", "recipe")]
    assert "successful_original_slice_replay" in sweep_graph["requirements"]
    assert "no_execution_or_cross_bundle_lifetime_join" in sweep_graph["limits"]
    assert "query_budget_excludes_replay" in sweep_graph["limits"]
    assert "qualified_paging_depth" in by_key[("memory", "read_virtual", "dump")]["requirements"]
    assert "not_captured_vs_not_present" in by_key[("memory", "read_virtual", "dump")]["limits"]
    schema = by_key[("schema", "export_type", "local_pdb")]
    assert "exact_amd64_image_pdb_identity" in schema["requirements"]
    assert "cli_parser_process_containment" in schema["limits"] and "no_runtime_qualification" in schema["limits"]
    assert "other_symbol_paths_not_isolated" in schema["limits"] and "no_filesystem_or_network_sandbox" in schema["limits"]
    assert "exact_reference_blob" in by_key[("image", "replay_verification", "recipe")]["requirements"]
    journal = by_key[("evidence", "journal", "local_files")]
    assert journal["availability"] == "not_probed" and journal["consistency"] == "verified_committed_prefix"
    assert "exact_file_hashes" in journal["requirements"] and "no_gc_or_global_retention" in journal["limits"]
    store = by_key[("evidence", "store", "local_files")]
    assert store["availability"] == "not_probed" and store["consistency"] == "coordinated_stopped_store"
    assert "participating_publishers" in store["requirements"] and "no_deletion_authority_or_disk_allocation" in store["limits"]
    gc = by_key[("evidence", "gc", "local_files")]
    assert gc["availability"] == "not_probed" and "durable_intent_before_delete" in gc["requirements"]
    assert "committed_roots_and_failure_ledgers_protected" in gc["limits"]
    retention = by_key[("evidence", "retention", "native")]
    privacy = by_key[("evidence", "privacy", "local_files")]
    disclosure = by_key[("evidence", "disclosure", "local_files")]
    assert disclosure["availability"] == "not_probed" and disclosure["consistency"] == "reviewed_historical_image_counts"
    assert "durable_intent_before_http" in disclosure["requirements"] and "no_raw_capture_transfer" in disclosure["limits"]
    assert privacy["availability"] == "not_probed" and privacy["consistency"] == "observed_os_access_controls"
    assert "efs_default" in privacy["requirements"] and "no_transfer_authority" in privacy["limits"]
    assert retention["availability"] == "not_probed" and retention["consistency"] == "recording_session_partitions"
    assert "complete_journal_batch_before_repeat_demotion" in retention["requirements"] and "image_pipeline_only" in retention["limits"]
    assert "direct_mapping_basis" in by_key[("image", "capture_verification", "dump")]["limits"]
    live_image = by_key[("image", "capture_verification", "process_handle")]
    assert "explicit_residency_consent" in live_image["requirements"] and "no_native_fallback" in live_image["limits"]
    assert "claim_specific_requirements" in by_key[("proof", "image_range", "recipe")]["requirements"]
    assert "no_hard_deadline_or_measured_slo" in by_key[("scheduler", "capture_timing", "native")]["limits"]
    cross_view = by_key[("process", "cross_view", "native")]
    assert "matching_pid_eprocess_create_time" in cross_view["requirements"]
    assert "unverified_candidates_retained" in cross_view["limits"]
    assert "shared_api_dependency" in cross_view["limits"]
    assert "fair_session_queue" in cross_view["limits"]
    assert "x0_or_x1_only" in by_key[("execution", "classify_reference", "native")]["limits"]
    assert "saved_context_not_cpu_sample" in by_key[("execution", "classify_reference", "native")]["limits"]
    assert "single_observation_ids" in by_key[("io", "request_graph", "native")]["limits"]
    assert "no_request_lifetime_or_completion_inference" in by_key[("io", "request_graph", "native")]["limits"]
    trace = by_key[("execution", "trace_import", "trace")]
    assert trace["implementation"] == "implemented" and "unauthenticated_producer" in trace["limits"]
    assert "no_raw_decoder_or_live_backend" in trace["limits"]
    operation = by_key[("session", "operation_status", "mcp")]
    assert operation["implementation"] == "implemented"
    assert "returned_operation_id" in operation["requirements"]
    assert "no_effect_verification_or_rollback" in operation["limits"]
    assert "no_idempotent_resubmission" in operation["limits"]
    process_source = by_key[("memory", "read_virtual", "process_handle")]
    assert "expected_pid_create_time" in process_source["requirements"]
    assert "no_liveness_or_atomic_snapshot_claim" in process_source["limits"]
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
    assert "--capabilities --probe" in help_result.stdout
    assert "--schema create" in help_result.stdout and "--schema inspect" in help_result.stdout
    print(f"source capabilities passed: {len(keys)} contracts, {len(actual)} command routes")


if __name__ == "__main__":
    main()
