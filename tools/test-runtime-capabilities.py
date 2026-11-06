"""Check a bounded owned-process probe without loading a driver or accepting global support claims."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--policy-exe", type=Path, required=True)
    args = parser.parse_args()
    exe = str(args.exe.resolve())
    run = subprocess.run([exe, "--capabilities", "--probe"], check=True,
                         capture_output=True, text=True, encoding="utf-8", timeout=30)
    data = json.loads(run.stdout)
    assert data["scope"] == "runtime_probe" and data["target_probed"] is True
    assert data["inventory_complete"] is False
    probe = data["probe"]
    assert probe["scope"] == "owned_process_range_and_native_connection_only"
    assert probe["process_id"] > 0 and int(probe["process_create_time"]) > 0
    assert probe["started_ms"] <= probe["finished_ms"]
    assert probe["driver_load_requested"] is False and probe["mutation_requested"] is False
    assert probe["symbol_network_requested"] is False and probe["probe_handles_closed"] is True
    assert probe["process_source_opened"] is True and probe["sample_bytes_matched"] is True
    sample = probe["process_read"]
    assert sample["status"] == "complete" and sample["identity_revalidated"] is True
    assert sample["native_status_domain"] == "win32" and sample["native_status"] == 0
    assert sample["requested_bytes"] == 32 and len(sample["spans"]) == 1
    assert bytes.fromhex(sample["spans"][0]["bytes_hex"]) == bytes(range(0x51, 0x71))
    read_set = probe["process_read_set"]
    assert read_set["schema"] == "kn.read_set.v1" and read_set["recording_complete"] is True
    assert read_set["attempts"] == read_set["receipts_saved"] == read_set["charged_source_calls"] == "1"
    assert read_set["charged_requested_bytes"] == read_set["stored_valid_bytes_with_repeats"] == "32"
    assert read_set["reads"][0]["read"] == sample and sample["read_receipt_id"] == "1"
    assert read_set["operation_id"] == sample["operation_id"] and read_set["execution_observed"] is False
    native_ready = probe["native_source_opened"] and probe["native_contract_passed"] and probe["native_session_passed"]
    for capability in data["capabilities"]:
        assert capability["validation"] == "not_performed_for_target_environment"
        stages = capability["probe_stages"]
        assert stages["layout_qualified"] == stages["semantic_validation"] == "not_probed"
        assert stages["environment_regression"] == "not_performed"
        if capability["implementation"] == "unsupported":
            assert capability["availability"] == "unsupported"
        elif capability["backend"] == "process_handle":
            assert capability["availability"] == "available"
            assert capability["availability_scope"] == "owned_control_range_only"
            assert stages["source_opened"] == stages["sample_read"] == "passed"
        elif capability["backend"] == "native":
            assert capability["availability"] == ("partial" if native_ready else "unavailable")
            assert stages["sample_read"] == "not_probed"
        else:
            assert capability["availability"] == "not_probed"
    for extra in (("--probe", "unexpected"), ("--probe-other",), ("--probe", "--probe")):
        invalid = subprocess.run([exe, "--capabilities", *extra], capture_output=True, text=True, timeout=30)
        assert invalid.returncode != 0 and not invalid.stdout.strip()
    spec = importlib.util.spec_from_file_location("matrix", Path(__file__).with_name("generate-support-matrix.py"))
    matrix = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(matrix)
    try:
        matrix.render(data)
    except ValueError:
        pass
    else:
        raise AssertionError("runtime observations must never generate public support documentation")
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp) / "matrix.md"
        command = [sys.executable, str(Path(matrix.__file__)), "--exe", exe, "--output", str(output)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        subprocess.run([*command, "--check"], check=True, capture_output=True, timeout=30)
        output.write_text("stale", encoding="utf-8")
        stale = subprocess.run([*command, "--check"], capture_output=True, timeout=30)
        assert stale.returncode != 0 and output.read_text(encoding="utf-8") == "stale"
        policy_exe = str(args.policy_exe.resolve())
        unicode_result = subprocess.run([policy_exe, "--unicode-json"], capture_output=True,
                                        text=True, encoding="utf-8", check=True, timeout=30)
        assert json.loads(unicode_result.stdout)["native_reason"] == '\ud55c\uae00 \U0001f512 "quoted"\n'
        with output.open("rb") as read_only_output:
            failed_write = subprocess.run([policy_exe, "--unicode-json"], stdout=read_only_output,
                                          stderr=subprocess.PIPE, timeout=30)
        assert failed_write.returncode == 2 and output.read_text(encoding="utf-8") == "stale"
    print("Runtime capability probe passed: owned read, conservative native state, no validation promotion, matrix drift")


if __name__ == "__main__":
    main()
