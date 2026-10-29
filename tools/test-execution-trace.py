"""Validate normalized trace imports with independent synthetic source records."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def fixture():
    code = bytes.fromhex("909090c3")
    return {
        "schema": "kn.execution_trace.v1",
        "source": {"id": "synthetic-source", "producer": 'synthetic "sampler"', "kind": "cpu_sample",
                   "target_id": "fixture-target", "boot_id": "fixture-boot", "vm_id": "fixture-vm",
                   "vtl": "0", "architecture": "amd64", "clock_domain": "fixture-clock", "ticks_per_second": "1000",
                   "first_tick": "10", "last_tick": "10000", "records_lost": "0"},
        "address_spaces": [{"id": "as0", "domain": "user", "pid": "100", "process_create_time": "1000",
                            "root_identity": "4096", "epoch": "1", "paging_levels": "4"}],
        "code_versions": [{"id": "c0", "space": "as0", "base": "1048576", "bytes_hex": code.hex(),
                           "sha256": hashlib.sha256(code).hexdigest(), "first_tick": "10", "last_tick": "10000"}],
        "samples": [{"sequence": str(i + 1), "tick": str(20 + i), "cpu": str(i % 2), "space": "as0",
                     "tid": "104", "thread_create_time": "1100", "ip": str(1048576 + i % 4), "code_version": "c0"}
                    for i in range(5)],
        "loss_intervals": [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    args = parser.parse_args()
    exe = str(args.exe.resolve())
    checks = 0
    with tempfile.TemporaryDirectory(prefix="kn-trace-") as directory:
        path = Path(directory) / "synthetic trace.kntrace"

        def run(data=None, options=(), success=True, raw=None):
            nonlocal checks
            if data is not None:
                path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            if raw is not None:
                path.write_bytes(raw)
            process = subprocess.run([exe, "--offline", "!kmon", "trace", str(path), *options],
                                     capture_output=True, encoding="utf-8", timeout=90)
            checks += 1
            assert (process.returncode == 0) == success, (checks, process.returncode, process.stderr, process.stdout[:500])
            if success:
                row = json.loads(process.stdout)
                assert row["schema"] == "kn.execution_trace_query.v1" and row["status"] == "ok"
                assert row["file_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
                assert row["source"]["architecture"] == "amd64" and row["source"]["clock_alignment"] == "not_established"
                for key in ("collector_authenticated", "execution_independently_verified", "execution_observed",
                            "control_flow_observed", "write_observed", "actor_attributed", "continuous_execution",
                            "live_backend_opened", "raw_decoder_used"):
                    assert row[key] is False, key
                assert all(s["qualified_reported_level"] not in ("X3", "X4") for s in row["samples"])
                return row
            return None

        base = fixture()
        value = run(base, ("/limit", "2", "/json"))
        assert len(value["samples"]) == 2 and not value["query_complete"]
        assert all(s["qualified_reported_level"] == "X2" for s in value["samples"])
        assert value["code_versions"][0]["retained_bytes_hash_verified"]
        assert not value["code_versions"][0]["runtime_mapping_verified"]
        cursor = value["next_cursor"]
        collected = value["samples"]
        while cursor:
            value = run(options=("/limit", "2", "/cursor", cursor))
            collected.extend(value["samples"])
            cursor = value["next_cursor"]
        assert [s["sequence"] for s in collected] == ["1", "2", "3", "4", "5"] and value["query_complete"]
        cursor = run(base, ("/limit", "2"))["next_cursor"]
        run(options=("/limit", "3", "/cursor", cursor), success=False)
        changed = copy.deepcopy(base)
        changed["source"]["boot_id"] = "other-boot"
        run(changed, ("/limit", "2", "/cursor", cursor), success=False)
        for options in (("/limit", "0"), ("/limit", "129"), ("/limit", "-1"), ("/limit", "01"),
                        ("/limit", "1", "/limit", "2"), ("/cursor",), ("/json", "/json"), ("/unknown",),
                        ("/cursor", "bad"), ("/cursor", "x" * 129)):
            run(base, options, success=False)

        for kind, level in (("saved_context", "X1"), ("pointer_reference", "X0")):
            changed = copy.deepcopy(base)
            changed["source"]["kind"] = kind
            changed["samples"][0]["cpu"] = None
            assert run(changed)["samples"][0]["qualified_reported_level"] == level
        for section, field, value in (("source", "vtl", None), ("samples", "cpu", None),
                                      ("samples", "tid", "0"), ("samples", "thread_create_time", "999"),
                                      ("address_spaces", "root_identity", "0"), ("address_spaces", "epoch", "0"),
                                      ("address_spaces", "process_create_time", "0")):
            changed = copy.deepcopy(base)
            target = changed[section] if section == "source" else changed[section][0]
            target[field] = value
            assert run(changed)["samples"][0]["qualified_reported_level"] == "unqualified"
        changed = copy.deepcopy(base)
        changed["code_versions"][0]["first_tick"] = "21"
        assert run(changed)["samples"][0]["qualification"] == "code_context_mismatch"
        changed["samples"][0]["code_version"] = None
        assert run(changed)["samples"][0]["qualified_reported_level"] == "X2"
        changed = copy.deepcopy(base)
        other = dict(changed["code_versions"][0], id="other", bytes_hex="cc9090c3",
                     sha256=hashlib.sha256(bytes.fromhex("cc9090c3")).hexdigest())
        changed["code_versions"].append(other)
        assert run(changed)["samples"][0]["qualification"] == "conflicting_code_versions"
        changed["code_versions"][1] = dict(base["code_versions"][0], id="other")
        assert run(changed)["samples"][0]["qualified_reported_level"] == "X2"

        changed = copy.deepcopy(base)
        changed["samples"][1]["sequence"] = "3"
        changed["samples"] = changed["samples"][:2]
        run(changed, success=False)
        changed["source"]["records_lost"] = "1"
        changed["loss_intervals"] = [{"first_tick": "19", "last_tick": "21", "reason": "synthetic overflow"}]
        value = run(changed)
        assert value["sequence_gaps"] == "1" and value["samples"][0]["loss_interval_overlap"]
        changed["source"]["records_lost"] = None
        assert run(changed)["records_lost"] is None

        mutations = [
            ("source", "kind", "decoded_pt"), ("source", "architecture", "arm64"), ("source", "vtl", "2"),
            ("source", "ticks_per_second", "0"), ("source", "last_tick", "9"), ("source", "id", ""),
            ("source", "records_lost", "18446744073709551616"), ("source", "first_tick", "1e1"),
            ("source", "clock_domain", "bad\u0000clock"), ("samples", "sequence", "0"),
            ("samples", "sequence", "-1"), ("samples", "cpu", "4294967296"), ("samples", "cpu", 1),
            ("samples", "space", "missing"), ("samples", "code_version", "missing"), ("samples", "tick", "9"),
            ("samples", "ip", str(0x800000000000)), ("code_versions", "sha256", "0" * 64),
            ("code_versions", "bytes_hex", "gg"), ("code_versions", "bytes_hex", "90" * 4097),
            ("code_versions", "bytes_hex", ""), ("code_versions", "space", "missing"),
            ("code_versions", "last_tick", "10001"), ("address_spaces", "paging_levels", "3"),
            ("address_spaces", "domain", "physical"), ("address_spaces", "pid", "4294967296"),
        ]
        for section, field, value in mutations:
            changed = copy.deepcopy(base)
            target = changed[section] if section == "source" else changed[section][0]
            target[field] = value
            run(changed, success=False)
        for section in ("source", "address_spaces", "samples", "code_versions"):
            changed = copy.deepcopy(base)
            target = changed[section] if section == "source" else changed[section][0]
            target["authenticated"] = True
            run(changed, success=False)
        for section in ("address_spaces", "code_versions"):
            changed = copy.deepcopy(base)
            changed[section].append(copy.deepcopy(changed[section][0]))
            run(changed, success=False)
        changed = copy.deepcopy(base)
        changed["samples"][1]["sequence"] = "1"
        run(changed, success=False)
        changed = copy.deepcopy(base)
        changed["samples"][1]["tick"] = "19"
        run(changed, success=False)

        for section, maximum in (("address_spaces", 64), ("code_versions", 128)):
            changed = copy.deepcopy(base)
            initial = changed[section][0]
            prefix = "as" if section == "address_spaces" else "c"
            changed[section] = [dict(initial, id=f"{prefix}{i}") for i in range(maximum)]
            run(changed)
            changed[section].append(dict(initial, id="over_limit"))
            run(changed, success=False)
        changed = copy.deepcopy(base)
        changed["samples"] = [dict(base["samples"][0], sequence=str(i + 1), tick=str(i + 20)) for i in range(4096)]
        assert run(changed, ("/limit", "128"))["samples_total"] == 4096
        changed["samples"].append(dict(base["samples"][0], sequence="4097", tick="5000"))
        run(changed, success=False)
        changed = copy.deepcopy(base)
        changed["loss_intervals"] = [{"first_tick": "10", "last_tick": "10", "reason": "unknown"}] * 128
        run(changed)
        changed["loss_intervals"].append(changed["loss_intervals"][0])
        run(changed, success=False)
        changed = copy.deepcopy(base)
        changed["samples"] = []
        assert run(changed)["samples_total"] == 0
        changed = copy.deepcopy(base)
        large_tick = 9007199254740993
        changed["source"]["first_tick"] = changed["code_versions"][0]["first_tick"] = str(large_tick)
        changed["source"]["last_tick"] = changed["code_versions"][0]["last_tick"] = str(large_tick + 100)
        changed["samples"] = [dict(changed["samples"][0], sequence=str(2**64 - 1), tick=str(large_tick + 1))]
        value = run(changed)
        assert value["samples"][0]["sequence"] == str(2**64 - 1) and value["samples"][0]["tick"] == str(large_tick + 1)
        changed = copy.deepcopy(base)
        changed["source"]["producer"] = "synthetic \uC2E4\uD5D8 \U0001F600"
        assert run(changed)["source"]["producer"] == changed["source"]["producer"]
        run(raw=json.dumps(changed, ensure_ascii=True).encode())

        text = json.dumps(base, separators=(",", ":")).encode()
        run(raw=text + b" " * (2 * 1024 * 1024 - len(text)))
        run(raw=text + b" " * (2 * 1024 * 1024 + 1 - len(text)), success=False)
        for raw in (b"", b"\xff", b"\xef\xbb\xbf" + text, text + b"junk", text[:-1],
                    text.replace(b'"synthetic-source"', b'"\\ud800"'),
                    text.replace(b'"synthetic-source"', b'"\\udc00"'),
                    text.replace(b'"schema":', b'"schema":"fake","schema":', 1),
                    b"[" * 100 + b"0" + b"]" * 100):
            run(raw=raw, success=False)
        changed = copy.deepcopy(base)
        changed["address_spaces"][0]["paging_levels"] = "5"
        changed["code_versions"][0]["base"] = str(0x1000000000000)
        for sample in changed["samples"]:
            sample["ip"] = str(0x1000000000000)
        assert run(changed)["address_spaces"][0]["virtual_address_bits"] == "57"
        changed["address_spaces"][0]["paging_levels"] = "4"
        run(changed, success=False)
        path.unlink()
        run(success=False)
        path.mkdir()
        run(success=False)
    print(f"execution trace controls passed: {checks}; synthetic normalized samples, no live backend")


if __name__ == "__main__":
    main()
