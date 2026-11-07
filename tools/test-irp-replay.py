"""Adversarial IRP replay checks using owned captures, without a live target."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("--product", action="store_true")
    args = parser.parse_args()
    original = (args.fixtures / "positive.knirp").read_bytes()
    capture = json.loads(original)
    prefix = [str(args.executable.resolve())] + (["--offline", "!kmon", "replay-irp"] if args.product else ["--replay-irp"])
    checks = 0

    def run(path, code=0):
        nonlocal checks
        done = subprocess.run(prefix + [str(path)], capture_output=True, timeout=60, encoding="utf-8")
        assert done.returncode == code, (done.returncode, code, done.stderr[-1000:], done.stdout[-1000:])
        result = json.loads(done.stdout)
        assert result["schema"] == "kn.irp_replay.v1"
        assert not result["collector_authenticated"] and not result["referenced_lifetime"]
        assert not result["execution_observed"] and result["build_approval"] == "not_established"
        if code:
            assert not result["qualified_observation_reproduced"] and not result["summary_matched"]
            assert result["result"] is None
        checks += 1
        return result

    with tempfile.TemporaryDirectory(prefix="replay-controls-", dir=args.fixtures.resolve()) as folder:
        root = Path(folder)
        assert root.resolve().parent == args.fixtures.resolve()
        path = root / "capture.knirp"
        path.write_bytes(original)
        missing = run(path)
        assert missing["summary_matched"] and not missing["qualified_observation_reproduced"]
        assert missing["result"]["requests"][0]["validation_stage"] == "decoded_candidate"
        reference = next(args.fixtures.glob("irp-reference-*.knblob"))
        saved = root / reference.name
        shutil.copyfile(reference, saved)
        valid = run(path)
        assert valid["qualified_observation_reproduced"] and valid["result"]["requests"] == capture["requests"]

        def mutate(change):
            document = copy.deepcopy(capture)
            change(document)
            path.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            return run(path, 1)

        mutate(lambda c: c.update(threads_visited="0"))
        mutate(lambda c: c.update(runtime_qualified=False))
        mutate(lambda c: c.update(qualification_reason="approved"))
        mutate(lambda c: c.update(collector_authenticated=True))
        mutate(lambda c: c.update(referenced_lifetime=True))
        mutate(lambda c: c.update(policy="future-policy"))
        mutate(lambda c: c.update(schema="kn.irp_capture.v1"))
        mutate(lambda c: c.update(final_cancelled=True))
        mutate(lambda c: c.update(final_source_contract_same=False))
        mutate(lambda c: c.update(reference_content_stable=False))
        mutate(lambda c: c.update(scan_finished_tick_ms="0"))
        mutate(lambda c: c.update(reference_captured_bytes="67108865"))
        mutate(lambda c: c["requests"][0]["stacks"][0].update(completion="4660"))
        mutate(lambda c: c["next_cursor"].update(irp="18446744073709551616"))
        mutate(lambda c: c["source_contract"].update(maximum_read_bytes="1"))
        mutate(lambda c: c["source_contract"].update(kernel_only=False))
        mutate(lambda c: c["reads"]["parser_reads"].reverse())
        mutate(lambda c: c["reads"]["parser_reads"].pop())
        mutate(lambda c: c["reads"]["parser_reads"][0].update(accepted=False))
        mutate(lambda c: c["reads"].update(unrecorded_parser_calls="1"))
        mutate(lambda c: c["reads"]["attempts"]["budget"].update(maximum_source_calls="4096"))
        mutate(lambda c: c["schemas"][0]["payload"]["fields"][0].update(offset="99999"))
        mutate(lambda c: c.update(unrecognized_path="file-must-not-be-opened"))
        # Duplicate keys and trailing data cannot be silently normalized away.
        path.write_bytes(original[:-1] + b',"runtime_qualified":true}')
        run(path, 1)
        path.write_bytes(original + b"\n")
        run(path, 1)
        path.write_bytes(b"{}" + b" " * (16 * 1024 * 1024))
        run(path, 1)
        path.write_bytes(original)
        content = saved.read_bytes()
        saved.write_bytes(b"invalid reference")
        assert run(path, 1)["reference_status"] == "mismatch"
        saved.write_bytes(content)
        assert run(path)["qualified_observation_reproduced"]
        run(root / "missing.knirp", 1)
        # Replay each original outcome, including owner/source churn, failed
        # reads, cancellation, missing optional fields, and the >2 MiB trace.
        for fixture in sorted(args.fixtures.glob("case-*.knirp")):
            result = run(fixture)
            assert result["summary_matched"]
        if args.product:
            for options in ([], ["/json"], [str(path), "/current"], [str(path), "/json", "/json"]):
                done = subprocess.run(prefix + options, capture_output=True, timeout=60)
                assert done.returncode == 2 and b"usage" in done.stderr
                checks += 1
    print(f"IRP replay controls passed: {checks}; original outcomes and mutations; no live source")


if __name__ == "__main__":
    main()
