"""Independently check native reference grades without a driver or live target."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    run = subprocess.run([str(args.exe.resolve()), "--execution-evidence-json"],
                         capture_output=True, text=True, check=True, timeout=30)
    records = json.loads(run.stdout)
    assert len(records) == 10
    assert [r["level"] for r in records] == ["X0", "X1", "X1", "X1", "X0", "X1", "X1", "X0", "unqualified", "unqualified"]
    assert [r["observation"] for r in records[:8]] == [
        "registered_pointer", "thread_start_metadata", "raw_stack_value", "queued_apc_routine",
        "apc_argument_candidate", "captured_thread_context", "saved_trap_context", "configured_debug_register"]
    for r in records:
        assert r["schema"] == "kn.execution_evidence.v1"
        assert r["source"] == 'synthetic "native" source'
        assert not r["execution_observed"] and not r["actor_attributed"]
        assert not r["control_flow_observed"] and not r["write_observed"]
        assert not r["collector_authenticated"]
        assert r["cpu"] is None and r["code_version"] is None
        assert r["execution_requirement"] == "separate_cpu_qualified_execution_source"
    assert records[5]["context_capture_time"] == "1200" and records[5]["thread_create_time"] == "1100"
    assert records[9]["context_capture_time"] is None and records[9]["thread_create_time"] is None
    print("execution evidence JSON oracle passed: 10 source and missing-context controls")


if __name__ == "__main__":
    main()
