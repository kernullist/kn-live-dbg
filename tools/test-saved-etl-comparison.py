"""Regression controls for paired saved ETL acquisition and offline adjudication."""
import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
from threading import Barrier
import unittest

import saved_etl_comparison as pair


HERE = Path(__file__).resolve().parent
EVALUATOR = runpy.run_path(str(HERE / "evaluate-corpus.py"))
SOURCE = b"synthetic framing control"
PIN = pair.sha(SOURCE)
PROFILE = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"
THREAD = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"
OTHER = "00000000-0000-0000-0000-000000000001"


def retained(data, limit=pair.MIB):
    return pair.record_bytes(io.BytesIO(data), limit)


def external(rows, *, loss=0, buffers=1):
    total = sum(r[0] for r in rows)
    lines = ["Files Processed:", "\tsource.etl", f"Total Buffers Processed {buffers}", f"Total Events Processed {total}",
             f"Total Events Lost {loss}", "Start Time x", "End Time y", "Elapsed Time z"]
    border = "+" + "-" * 82 + "+"
    lines += [border, "|Event Count Event Name Task Opcode Version Guid|", border]
    groups = {}
    for count, name, op, version, provider in rows:
        lines.append(f"|{count:11}   {name:20} {0:<15} {op:15} {version:<15} {{{provider}}}|")
        key = name, version, provider
        groups[key] = groups.get(key, 0) + count
    lines += [border, border, "|Event Count Event Name Event ID Version Guid|", border]
    for (name, version, provider), count in groups.items():
        lines.append(f"|{count:11}   {name:20} {0:<15} {version:<15} {{{provider}}}|")
    return ("\r\n".join([*lines, border, ""])).encode("ascii")


ROWS = [(2, "PerfInfo", "SampleProf", 2, PROFILE), (1, "Other", "CSwitch", 2, OTHER)]


def native():
    coverage = dict(records_seen=3, buffers_written=1, buffers_processed=1, buffer_comparison="matched",
                    events_lost=0, buffers_lost=0, loss_marker_records=0)
    probe = dict(schema="kn.etl_capability_probe.v1", expected_sha256=PIN, source_sha256=PIN, source_bytes=len(SOURCE),
                 status="read", source_revalidated=True, trace_opened=True, win32_status=0, coverage=coverage)
    rows = []
    for op, n in (("cpu_profile", 2), ("context_switch", 0)):
        evidence = dict(observation="decoded_records" if n else "no_matching_records_observed", decoded=n, unsupported=0,
                        first_decoded_record=1 if n else None, first_payload_bytes=12 if n else None,
                        first_payload_sha256=pair.sha(b"sample") if n else None)
        rows.append(dict(domain="execution", operation=op, backend="etl", availability_scope="supplied_etl_record_family",
                         availability="available" if n else "partial", record_evidence=evidence))
    return dict(schema="kn.capabilities.v1", scope="saved_etl_probe", target_probed=False, probe=probe, capabilities=rows)


def manifest():
    cfg = pair.config(PIN, 3000)
    binaries = {r: dict(before_sha256=PIN, after_sha256=PIN, expected_sha256=PIN) for r in pair.ROLES}
    attempts = {r: dict(state="exited", os_error=None, exit_code=0, image_binding=dict(status="matched", win32_status=0),
                        started_ns=str(i * 3), ended_ns=str(i * 3 + 2),
                        stdout=retained(pair.encoded(native()) if i == 0 else b""), stderr=retained(b""))
                for i, r in enumerate(pair.ROLES)}
    return dict(schema="kn.etl_reader_comparison.v1", source_sha256=PIN, source_bytes=len(SOURCE), config=cfg,
                config_sha256=pair.sha(pair.encoded(cfg)), os_build="10.0.1", tools=binaries, attempts=attempts,
                summary=retained(external(ROWS)))


def frame(m, *, metadata=None, source=SOURCE):
    raw = pair.encoded(m) if metadata is None else metadata
    return pair.HEADER.pack(pair.MAGIC, len(raw), len(source)) + raw + source


def replay(raw, pin=None):
    return pair.replay(io.BytesIO(raw), pin or pair.sha(raw), EVALUATOR["decode_document"], EVALUATOR["ratio"])


def evaluate(m):
    return replay(frame(m))


def invoke(script, *args, **sinks):
    return subprocess.run([sys.executable, "-B", str(HERE / script), *map(str, args)],
                          stdout=sinks.get("stdout", subprocess.PIPE), stderr=sinks.get("stderr", subprocess.PIPE), timeout=300)


class ReplayTests(unittest.TestCase):
    def test_independent_counts_and_denominators(self):
        m = manifest()
        for rows, cpu, switches, agreed, comparable in (
            (ROWS, "agreed_observed", "agreed_empty", 2, 2),
            ([(1, "PerfInfo", "46", 2, PROFILE), (2, "Thread", "36", 4, THREAD)], "count_disagreement", "count_disagreement", 0, 2),
            ([(2, "PerfInfo", "SampleProf", 1, PROFILE), ROWS[1]], "coverage_limited", "agreed_empty", 1, 1),
            ([(2, "PerfInfo", "", 2, PROFILE), ROWS[1]], "coverage_limited", "agreed_empty", 1, 1),
            ([(2, "PerfInfo", "UnknownName", 2, PROFILE), ROWS[1]], "coverage_limited", "agreed_empty", 1, 1),
            ([(1, "Thread", "ReadyThread", 2, THREAD)], "traversal_disagreement", "traversal_disagreement", 0, 0),
        ):
            with self.subTest(cpu=cpu, rows=rows):
                m["summary"] = retained(external(rows))
                q = evaluate(m)
                self.assertEqual([q["families"][k]["verdict"] for k in pair.FAMILIES], [cpu, switches])
                self.assertEqual(q["agreement_per_planned_family"], EVALUATOR["ratio"](agreed, 2))
                self.assertEqual(q["agreement_per_comparable_family"], EVALUATOR["ratio"](agreed, comparable))
                self.assertFalse(q["ground_truth_authenticated"] or q["independent_detection_validation"] or q["target_probed"])

    def test_loss_and_incomplete_native_layout(self):
        m = manifest()
        for summary, verdict in ((external(ROWS, loss=1), "coverage_limited"), (external(ROWS, buffers=2), "traversal_disagreement")):
            m["summary"] = retained(summary)
            self.assertTrue(all(v["verdict"] == verdict for v in evaluate(m)["families"].values()))
        m["summary"] = retained(external(ROWS))
        n = native()
        n["probe"]["status"] = "partial"
        n["probe"]["coverage"].update(buffer_comparison="not_comparable", buffers_written=0)
        n["capabilities"][0]["availability"] = "partial"
        m["attempts"]["native"].update(exit_code=1, stdout=retained(pair.encoded(n)))
        q = evaluate(m)
        self.assertTrue(all(v["verdict"] == "coverage_limited" for v in q["families"].values()))
        self.assertEqual(q["readers"]["native"]["native_probe"]["status"], "partial")
        n = native()
        n["capabilities"][0]["availability"] = "partial"
        n["capabilities"][0]["record_evidence"]["unsupported"] = 1
        m["attempts"]["native"].update(exit_code=0, stdout=retained(pair.encoded(n)))
        q = evaluate(m)
        self.assertEqual(q["families"]["cpu_profile"]["verdict"], "coverage_limited")
        self.assertEqual(q["families"]["context_switch"]["verdict"], "agreed_empty")

    def test_unqualified_summaries_preserve_two_planned_families(self):
        raw = external(ROWS)
        before, after = raw.split(b"Event ID")
        bad = [raw.replace(b"source.etl", b"other.etl"), raw.replace(b"Files Processed:", b"Dateien:"),
               raw.replace(b"Processed 3", b"Processed 4"), raw.replace(b"SampleProf", b"x" * 2300),
               raw[:-50], raw + b"unexpected row", before + b"Event ID" + after.replace(PROFILE.encode(), THREAD.encode()),
               raw.replace(b"|          2   PerfInfo", b"|          0   PerfInfo", 1)]
        for item in bad:
            m = manifest()
            m["summary"] = retained(item)
            q = evaluate(m)
            self.assertEqual(q["readers"]["tracerpt"]["status"], "unqualified_output")
            self.assertEqual(q["agreement_per_comparable_family"]["value"], None)
            self.assertEqual(q["agreement_per_planned_family"]["denominator"], 2)
        self.assertEqual(pair.tracerpt_counts(raw.decode("ascii").encode("utf-16")), pair.tracerpt_counts(raw))
        end = raw.index(b"\r\n+", raw.index(b"Other")) + 2
        single = raw[:raw.index(b"\r\n", end) + 2]
        self.assertEqual(pair.tracerpt_counts(single)["summary_tables"], "opcode_only")

    def test_process_failures_and_output_retention(self):
        for state, code, error, status in (("timed_out", None, None, "timed_out"), ("launch_error", None, 193, "launch_error"),
                                           ("exited", 13, None, "reader_error")):
            m = manifest()
            m["attempts"]["native"].update(state=state, exit_code=code, os_error=error)
            if state == "launch_error":
                m["attempts"]["native"]["image_binding"] = None
            r = evaluate(m)
            self.assertEqual(r["readers"]["native"]["status"], status)
            self.assertEqual(r["observed_readers"], 1)
            self.assertTrue(all(v["verdict"] == "reader_unavailable" for v in r["families"].values()))
        m = manifest()
        m["summary"] = None
        self.assertEqual(evaluate(m)["readers"]["tracerpt"]["status"], "summary_unavailable")
        m["summary"] = retained(bytes(pair.MIB + 1))
        q = evaluate(m)["readers"]["tracerpt"]
        self.assertEqual((q["summary"]["byte_count"], q["status"]), (pair.MIB + 1, "retained_output_truncated"))
        self.assertEqual(q["summary"]["original_sha256"], pair.sha(bytes(pair.MIB + 1)))
        self.assertEqual(q["summary"]["retained_sha256"], pair.sha(bytes(pair.MIB)))
        m = manifest()
        m["tools"]["native"]["after_sha256"] = pair.sha(b"other")
        self.assertEqual(evaluate(m)["readers"]["native"]["status"], "binary_changed")
        for status, error in (("different_path", 0), ("unavailable", 5)):
            m = manifest()
            m["attempts"]["native"]["image_binding"].update(status=status, win32_status=error)
            self.assertEqual(evaluate(m)["readers"]["native"]["status"], "reader_image_unverified")
        n = native()
        n["probe"].update(status="open_trace_failed", win32_status=13, coverage=None, trace_opened=False, source_revalidated=None)
        m = manifest()
        m["attempts"]["native"].update(exit_code=1, stdout=retained(pair.encoded(n)))
        q = evaluate(m)["readers"]["native"]
        self.assertEqual((q["status"], q["native_probe"]["win32_status"]), ("source_unavailable", 13))

    def test_integrity_and_immutable_publication(self):
        m = manifest()
        raw = frame(m)
        for data in (raw[:-1], raw + b"x", frame(m, source=b"x" * len(SOURCE)), frame(m, metadata=b'{"k":1,"k":2}')):
            with self.assertRaises(ValueError):
                replay(data)
        with self.assertRaises(ValueError):
            replay(raw, pair.sha(b"wrong"))
        for section, key, value in (("config", "timeout_ms", True), ("config", "native", ["other"]),
                                    ("summary", "retained_sha256", PIN), ("summary", "original_sha256", PIN), ("summary", "base64", "AAAA")):
            changed = copy.deepcopy(m)
            changed[section][key] = value
            with self.assertRaises(ValueError):
                evaluate(changed)
        m["attempts"]["tracerpt"]["started_ns"] = "1"
        with self.assertRaises(ValueError):
            evaluate(m)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "renamed.data"
            self.assertEqual(pair.write_package(path, manifest(), io.BytesIO(SOURCE)), pair.sha(raw))
            with self.assertRaises(FileExistsError):
                pair.write_package(path, manifest(), io.BytesIO(SOURCE))
            with self.assertRaises(ValueError):
                pair.write_package(path.with_suffix(".other"), manifest(), io.BytesIO(bytes(len(SOURCE))))
            self.assertEqual(list(path.parent.iterdir()), [path])
            self.assertEqual(path.read_bytes(), raw)

    def test_cli_hardlinks_preserve_input_on_success_and_bad_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.bin"
            raw = frame(manifest())
            path.write_bytes(raw)
            alias = path.with_suffix(".link")
            os.link(path, alias)
            sel = "--saved-etl-comparison=" + str(path)
            for cmd, args, channel in (
                    ("evaluate-corpus.py", [sel, "--sha256", pair.sha(raw)], "stdout"),
                    ("evaluate-corpus.py", [sel, "--sha256"], "stderr"),
                    ("evaluate-corpus.py", ["--help", sel], "stdout"),
                    ("capture-etl-comparison.py", ["--etl", path, "--etl=unused", "--bad"], "stderr"),
                    ("capture-etl-comparison.py", ["--help", "--output=" + str(path)], "stdout")):
                with alias.open("ab", buffering=0) as sink:
                    r = invoke(cmd, *args, **{channel: sink})
                self.assertEqual(r.returncode, 2)
                self.assertEqual(path.read_bytes(), raw)
            result = invoke("evaluate-corpus.py", sel, "--sha256", pair.sha(raw))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), replay(raw))
            wrong = invoke("evaluate-corpus.py", sel, "--sha256", PIN)
            self.assertEqual((wrong.returncode, wrong.stdout), (2, b""))

    def test_competing_archives_have_one_immutable_winner(self):
        barrier = Barrier(2, timeout=10)

        class Source(io.BytesIO):
            def read(self, size=-1):
                if self.tell() == 0:
                    barrier.wait()
                return super().read(size)

        def publish(path, build):
            m = manifest()
            m["os_build"] = build
            try:
                return pair.write_package(path, m, Source(SOURCE))
            except FileExistsError:
                return None

        with tempfile.TemporaryDirectory() as temp, ThreadPoolExecutor(max_workers=2) as workers:
            path = Path(temp) / "pair.knbench"
            results = [workers.submit(publish, path, build) for build in ("10.0.1", "10.0.2")]
            winners = [pin for result in results if (pin := result.result()) is not None]
            raw = path.read_bytes()
            self.assertEqual(winners, [pair.sha(raw)])
            self.assertIn(replay(raw)["reader_os_build"], ("10.0.1", "10.0.2"))
            self.assertEqual(list(path.parent.iterdir()), [path])


def file_pin(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def live(args):
    """Use the real Windows programs and repeat offline after removing the test's source copy."""
    assert file_pin(args.etl) == args.sha256 and file_pin(args.exe) == args.exe_sha256
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        source, package = folder / "original saved.etl", folder / "comparison.knbench"
        shutil.copyfile(args.etl, source)
        def capture(src, pin, exe, exe_pin, dest, *extra):
            return invoke("capture-etl-comparison.py", "--etl", src, "--sha256", pin, "--exe", exe,
                          "--exe-sha256", exe_pin, "--output", dest, *extra)
        for source_pin, exe_pin in ((PIN, args.exe_sha256), (args.sha256, PIN)):
            r = capture(source, source_pin, args.exe, exe_pin, package)
            assert (r.returncode, r.stdout, package.exists()) == (2, b"", False)
        r = capture(source, args.sha256, args.exe, args.exe_sha256, package, "--tracerpt-sha256", PIN)
        assert (r.returncode, r.stdout, package.exists()) == (2, b"", False)
        with source.open("r+b"):
            contested = capture(source, args.sha256, args.exe, args.exe_sha256, package)
        assert (contested.returncode, contested.stdout, package.exists(), file_pin(source)) == (2, b"", False, args.sha256)
        good = capture(source, args.sha256, args.exe, args.exe_sha256, package)
        assert good.returncode == 0, good.stderr
        pin = json.loads(good.stdout)["package_sha256"]
        assert file_pin(package) == pin and file_pin(source) == args.sha256
        collision = capture(source, args.sha256, args.exe, args.exe_sha256, package)
        assert (collision.returncode, file_pin(package)) == (2, pin)
        with package.open("rb") as stream:
            _, size, _ = pair.HEADER.unpack(stream.read(pair.HEADER.size))
            metadata = json.loads(stream.read(size))
            assert hashlib.file_digest(stream, "sha256").hexdigest() == args.sha256
        assert metadata["tools"]["native"]["before_sha256"] == args.exe_sha256
        assert metadata["tools"]["tracerpt"]["before_sha256"] == metadata["tools"]["tracerpt"]["after_sha256"]
        source.unlink()
        moved = package.rename(folder / "moved.data")
        r = invoke("evaluate-corpus.py", "--saved-etl-comparison", moved, "--sha256", pin)
        assert r.returncode == 0, r.stderr
        q = json.loads(r.stdout)
        assert q["agreement_per_planned_family"]["numerator"] == 2
        for name, expected in zip(pair.FAMILIES, (args.expected_cpu, args.expected_switches)):
            assert q["families"][name]["native"]["decoded"] == expected == q["families"][name]["tracerpt"]["supported_descriptors"]
        assert all(q["readers"][role]["counts"]["records"] == args.expected_records for role in pair.ROLES)
        invalid = folder / "invalid.exe"
        invalid.write_bytes(b"not an executable")
        try:
            subprocess.run([str(invalid)], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except OSError as exc:
            original_error = exc.winerror
        else:
            raise AssertionError("invalid executable unexpectedly launched")
        failed = capture(args.etl, args.sha256, invalid, file_pin(invalid), package)
        assert failed.returncode == 0, failed.stderr
        r = invoke("evaluate-corpus.py", "--saved-etl-comparison", package, "--sha256", json.loads(failed.stdout)["package_sha256"])
        q = json.loads(r.stdout)
        assert (q["readers"]["native"]["os_error"], q["readers"]["tracerpt"]["status"]) == (original_error, "observed")
        assert q["agreement_per_comparable_family"]["denominator"] == 0 and q["planned_readers"] == 2
        print("Saved ETL comparison passed at", args.expected_records, "records, including failed native launch.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        unittest.main()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        for key in ("--etl", "--exe"):
            parser.add_argument(key, type=Path, required=True)
        for key in ("--sha256", "--exe-sha256"):
            parser.add_argument(key, required=True)
        for key in ("--expected-records", "--expected-cpu", "--expected-switches"):
            parser.add_argument(key, type=int, required=True)
        live(parser.parse_args())
