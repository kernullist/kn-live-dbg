"""Check Microsoft TraceProcessor marker correspondence, pinned deployment, and native report compatibility."""
import argparse
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import zipfile

import etl_traceprocessor as sdk
from etl_reader_process import WindowsFiles, file_hash, run_reader
from saved_etl_comparison import MIB, original


HERE = Path(__file__).resolve().parent
PAIR = runpy.run_path(str(HERE / "test-etl-activity-comparison.py"))
pin = PAIR["pin"]


def controls(native, source):
    def result(rows, total=8):
        doc = dict(source, rows=rows, matched_rows=len(rows), scoped_marker_rows=len(rows),
                   activity_marker_rows=len(rows), provider_rows=total)
        return sdk.correlate(doc, native)["status"]

    a, b = source["rows"]
    assert result([a, dict(a, table_row=7), b]) == "ambiguous_rows"
    assert result([a, dict(a, table_row=7, timestamp_partial=True), b]) == "clock_unqualified"
    assert result([a, dict(a, table_row=7, raw_timestamp=None, clock_type=None), b]) == "clock_unqualified"
    assert result([a, dict(b, version=b["version"]+1)]) == "row_missing"
    assert result([dict(b, table_row=6), dict(a, table_row=8)]) == "table_order_conflict"
    assert result([]) == "row_missing"
    capped = [dict(a, table_row=i) for i in range(1, 129)]
    doc = dict(source, rows=capped, matched_rows=129, scoped_marker_rows=129, activity_marker_rows=129, provider_rows=129)
    assert sdk.correlate(doc, native)["status"] == "row_limit"
    malformed = []
    for row in (dict(a, raw_timestamp="invalid"), dict(a, raw_timestamp="0"), dict(a, table_row=8),
                dict(a, header_thread_id=0), dict(a, event_id=True)):
        malformed.append(dict(source, rows=[row, b]))
    malformed += [dict(source, source_sha256="0"*64), dict(source, loaded_processing_modules=[]),
                  dict(source, query_filter=dict(source["query_filter"], end_raw="1")), dict(source, provider_rows=True)]
    for doc in malformed:
        try:
            sdk.correlate(doc, native)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted a malformed SDK result")


def whole_activity(oracle, archive, folder, cases):
    files = WindowsFiles()
    with ExitStack() as stack:
        program, image, _ = sdk.admit([archive, pin(archive)], folder, files, stack, set())
        for path, window, count in cases:
            with files.hold(path) as source:
                source_hash = file_hash(source)
                provider, activity = window["provider_guid"], window["activity_id"]
                _, _, groups, _ = PAIR["WINDOW"]["read_oracle"](oracle, path)
                expected = sorted((e for group in groups.values() for e in group if (e["provider_guid"], e["activity_id"]) == (provider, activity)),
                                  key=lambda e: e["record_ordinal"])
                args = [str(path), provider, activity, "--all-markers"]
                attempt = run_reader(program, args, folder, 120000, MIB, files, image)
                assert attempt["exit_code"] == 0 and attempt["image_binding"]["status"] == "matched"
                raw, complete = original(attempt["stdout"], MIB)
                projection = json.loads(raw)
                rows = sdk.validate_projection(projection, source_hash, path.stat().st_size, provider, activity)
                assert complete and len(expected) == projection["matched_rows"] == count and len(rows) == min(count, 128)
                assert projection["provider_rows"] == window["provider_rows"] and rows[-1]["table_row"] > len(rows)
                for row, event in zip(rows, expected[:128], strict=True):
                    assert all(row[k] == event[k] for k in (*sdk.HEADER, "raw_timestamp"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "adapter", "x64", "x86", "taskbar"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--whole-activity-oracle", type=Path, help="also validate sparse and capped whole-activity SDK rows against Windows ETW")
    args = parser.parse_args()
    src = [f.resolve() for f in (args.x64, args.x86, args.taskbar)]
    assert tuple(map(pin, src)) == PAIR["PINS"]
    before, after, taskbar = [(f, h, str(a), str(b)) for f, h, (a, b) in
                              zip(src, PAIR["PINS"], ((135036, 135051), (122133, 122302), (339732, 374019)), strict=True)]
    def command(base, candidate, package):
        arguments = [sys.executable, "-B", PAIR["CLI"], "--exe", args.exe.resolve(), "--exe-sha256", pin(args.exe),
                     "--baseline", *base, "--candidate", *candidate]
        if package:
            arguments += ["--traceprocessor", package, pin(package)]
        return arguments

    with tempfile.TemporaryDirectory() as path:
        folder = Path(path)
        def run(argv, mode, value, code):
            result = subprocess.run([*argv, mode, value], capture_output=True, timeout=240)
            assert result.returncode == code, (result.stdout, result.stderr)
            return json.loads(result.stdout)

        pair = command(before, after, args.adapter.resolve())
        out = folder / "paired.json"
        receipt = run(pair, "--output", out, 0)
        assert receipt["schema"] == "kn.etl_activity_comparison_receipt.v2" and receipt["traceprocessor_status"] == "matched"
        assert pin(out) == receipt["report_sha256"] and run(pair, "--check-report", pin(out), 0)["status"] == "matched"
        report = json.loads(out.read_bytes())
        assert report["schema"] == "kn.etl_activity_comparison.v2"
        tp = report["traceprocessor"]
        assert tp["status"] == "matched" and tp["package_sha256"] == pin(args.adapter) and tp["sdk_files_sha256"] == sdk.SDK_HASH
        for role in ("baseline", "candidate"):
            evidence, native = tp[role], report[role]
            assert evidence["native_page_sha256"] == native["reader"]["stdout_sha256"]
            rows = evidence["projection"]["rows"]
            assert [row["table_row"] for row in rows] == [6, 8] and evidence["projection"]["provider_rows"] == 8
            assert evidence["correspondence"]["matching_table_rows"] == {"start": [6], "stop": [8]}
            for row, name in zip(rows, ("start", "stop"), strict=True):
                marker = native["page"]["activity_window"][name]
                assert all(row[k] == marker[k] for k in (*sdk.HEADER, "raw_timestamp"))
            for item in (receipt, evidence, evidence["correspondence"], evidence["projection"], rows[0], evidence["projection"]["query_filter"]):
                PAIR["WINDOW"]["private"](item)
        controls(report["baseline"], tp["baseline"]["projection"])
        v1 = folder / "native.json"
        native_receipt = run(command(before, after, None), "--output", v1, 0)
        expected = deepcopy(report)
        del expected["traceprocessor"]
        expected["schema"] = "kn.etl_activity_comparison.v1"
        assert json.loads(v1.read_bytes()) == expected and native_receipt["schema"] == "kn.etl_activity_comparison_receipt.v1"
        large = folder / "large.json"
        large_receipt = run(command(taskbar, after, args.adapter), "--output", large, 1)
        assert (large_receipt["comparison_status"], large_receipt["traceprocessor_status"]) == ("descriptor_mismatch", "matched")
        result = json.loads(large.read_bytes())["traceprocessor"]["baseline"]
        p = result["projection"]
        assert [p[k] for k in ("provider_rows", "activity_marker_rows", "scoped_marker_rows", "matched_rows")] == [56702, 7329, 902, 2]
        assert result["correspondence"]["matching_table_rows"] == {"start": [5413], "stop": [7465]}
        if args.whole_activity_oracle:
            whole_activity(args.whole_activity_oracle, args.adapter.resolve(), folder,
                           [(src[0], tp["baseline"]["projection"], 2), (src[2], p, 7329)])
        unavailable = folder / "unavailable.json"
        fail = command(before, (after[0], "0"*64, *after[2:]), args.adapter)
        assert run(fail, "--output", unavailable, 1)["traceprocessor_status"] == "unconfirmed"
        sdk_sides = json.loads(unavailable.read_bytes())["traceprocessor"]
        assert sdk_sides["baseline"]["status"] == "matched"
        assert sdk_sides["candidate"]["status"] == "native_window_unavailable" and sdk_sides["candidate"]["reader"] is None
        wrong = command(before, after, args.adapter)
        wrong[-1] = "0"*64
        target = folder / "rejected.json"
        for variant in ("wrong_pin", "substituted_sdk", "path_escape"):
            invalid = wrong
            if variant != "wrong_pin":
                package = folder / (variant + ".zip")
                with zipfile.ZipFile(args.adapter) as original, zipfile.ZipFile(package, "x", compression=zipfile.ZIP_DEFLATED) as copy:
                    for entry in original.namelist():
                        data = original.read(entry)
                        if entry == "wpt/perfcore.dll":
                            if variant == "path_escape":
                                entry = "../escape.dll"
                            else:
                                data += b"changed"
                        copy.writestr(entry, data)
                invalid = command(before, after, package)
            result = subprocess.run([*invalid, "--output", target], capture_output=True, timeout=60)
            assert result.returncode == 2 and not target.exists() and not list(folder.glob(".kn*"))
        assert not (folder / "escape.dll").exists()
    print("Pinned TraceProcessor matched original headers in all three ETLs; scope, ambiguity, archive and replay controls passed.")


if __name__ == "__main__":
    main()
