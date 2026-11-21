"""Check normalized ETL profile pages and exact replay against Windows tracerpt."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

BASE = runpy.run_path(str(Path(__file__).with_name("test-etl-profile.py")))
AUDIT = runpy.run_path(str(Path(__file__).with_name("validate-public-content.py")))
TRUST = ("collector_authenticated", "execution_independently_verified", "execution_observed",
         "control_flow_observed", "write_observed", "actor_attributed", "continuous_execution")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(exe, args, rc=0, stdin=None):
    result = subprocess.run([exe, *map(str, args)], stdin=stdin, capture_output=True, timeout=90)
    assert result.returncode == rc, (args[0], result.returncode, rc, len(result.stdout), len(result.stderr))
    return result.stdout


def query(exe, path, *options, mode="offline", rc=0):
    if mode == "named":
        raw = command(exe, ["--offline", "!kmon", "trace", path, *options], rc)
    else:
        with path.open("rb") as source:
            raw = command(exe, ["--mode", mode, "trace", "-", *options], rc, source)
    return json.loads(raw)


def assert_page(output, raw, source, expected, offset, limit):
    partial = source["status"] == "partial"
    assert output["schema"] == "kn.execution_trace_query.v2" and output["status"] == ("partial" if partial else "ok")
    assert output["file_sha256"] == digest(raw) and not any(output[k] for k in TRUST)
    for k in ("records_lost", "sequence_gaps", "loss_intervals"):
        assert output[k] is None
    assert output["address_spaces"] == output["code_versions"] == []
    assert output["raw_decoder_used"] is output["live_backend_opened"] is False
    inputs = output["source"]
    assert (inputs["reported_etl_sha256"], int(inputs["reported_etl_bytes"]), inputs["native_schema"]) == (
        source["source_sha256"], source["source_bytes"], source["schema"])
    assert inputs["etl_reopened"] is False and inputs["kind"] == "cpu_sample" and inputs["producer_authenticity"] == "unverified"
    for k in ("architecture", "vtl", "vm_id", "boot_id", "target_id", "first_tick", "last_tick",
              "capture_privilege", "capture_enable_flags", "stack_capture_policy"):
        assert inputs[k] is None
    for k in ("log_header", "clock", "provider_guid", "event_id", "version", "opcode"):
        assert inputs[k] == source[k]
    clock = source["clock"]
    hz = int(clock["header_perf_frequency"])
    rate = (str(hz) if hz > 0 else None) if clock["raw_type"] == 1 else "10000000" if clock["raw_type"] == 2 else None
    assert inputs["ticks_per_second"] == rate
    sp = output["source_page"]
    assert (sp["status"], sp["source_after"], sp["source_next_after"]) == (source["status"], source["after"], source["next_after"])
    for key in ("decoded_samples", "records_seen", "buffers_processed", "loss_marker_records", "unsupported_profile_records", "buffer_comparison"):
        assert sp[key] == source[key]
    ticks = [int(r["raw_timestamp"]) for r in source["samples"]]
    assert sp["page_clock_reversed"] == any(a > b for a, b in zip(ticks, ticks[1:]))
    batch = source["samples"][offset:offset + limit]
    assert len(output["samples"]) == len(batch) and output["offset"] == offset and output["samples_total"] == len(ticks)
    done = len(ticks) == offset + len(batch)
    assert output["query_complete"] is done
    assert output["next_cursor"] == ("" if done else f"kt2:{digest(raw)}:{limit}:{offset + len(batch)}")
    for s, r in zip(output["samples"], batch, strict=True):
        seq = r["sample_ordinal"]
        actual = (s["record_ordinal"], int(s["tick"]), int(s["cpu"]), int(s["ip"]), int(s["tid"]),
                  s["count_field"], s["reserved_field"], s["header_process_id"], s["header_thread_id"],
                  int(s["event_keyword_decimal"]), s["event_channel"], s["event_level"], s["event_task"])
        assert int(s["sequence"]) == seq and actual == expected[seq - 1]
        for key in ("logger_id", "pointer_bytes", "cpu_field", "header_flags", "extended_data_items", "stack_extension_items"):
            assert s[key] == r[key]
        assert s["reported_level"] == "X2" and s["qualified_reported_level"] == s["verified_level"] == "unqualified"
        assert all(s[k] is None for k in ("space", "thread_create_time", "code_version", "loss_interval_overlap"))


def replay(exe, args, pin, expected, source_status, match=True):
    rc = 0 if match and source_status == "read" else 1
    proof = json.loads(command(exe, [*args, "--check-page", pin], rc))
    assert proof["schema"] == "kn.etl_page_replay.v1" and proof["status"] == ("matched" if match else "page_mismatch")
    assert proof["source_status"] == source_status and proof["source_sha256"] == args[3]
    assert proof["expected_source_sha256"] == args[3]
    if "--reference-image" in args:
        assert proof["expected_reference_sha256"] == proof["reference_sha256"] == args[args.index("--reference-image") + 2].lower()
    else:
        assert proof["expected_reference_sha256"] is proof["reference_sha256"] is None
    assert proof["expected_page_sha256"] == pin.lower() and proof["replayed_page_sha256"] == expected
    assert proof["page_bytes_match"] is match and proof["collector_authenticated"] is False
    return proof


def private_parts(items):
    for item in items:
        for enc in ("utf-8", "utf-16-le", "utf-16-be"):
            for data in (json.dumps(item, indent=2), "log\n" + json.dumps(dict(reversed(list(item.items()))))[:-1]):
                assert any(x["rule"] == "private-evidence-bundle" for x in AUDIT["inspect"]("part.txt", data.encode(enc))), (tuple(item), enc)


def adversarial(exe, path, args, raw):
    source = json.loads(raw)
    assert len(source["samples"]) >= 3 and source["schema"] == "kn.etl_profile.v1"
    path.write_bytes(raw)
    first = query(exe, path, "/limit", 1)
    cursor = first["next_cursor"]
    assert all(query(exe, path, "/limit", 1, "/cursor", cursor, mode=mode)["offset"] == 1 for mode in ("named", "observe"))
    wrong = query(exe, path, "/limit", 2, "/cursor", cursor, rc=1)
    assert wrong["status"] == "unavailable" and wrong["schema"] == "kn.execution_trace_query.v2"
    assert wrong["file_sha256"] == digest(raw) and wrong["reported_etl_sha256"] == source["source_sha256"]
    path.write_bytes(raw + b"\n")
    assert query(exe, path, "/limit", 1, "/cursor", cursor, rc=1)["status"] == "unavailable"
    proof = replay(exe, args, digest(path.read_bytes()), digest(raw), "read", False)
    private_parts([first, first["source"], first["source_page"], first["samples"][0], first["source"]["clock"], first["source"]["log_header"], proof, wrong])
    bad_source = list(args)
    bad_source[3] = "0" * 64
    unavailable = json.loads(command(exe, [*bad_source, "--check-page", digest(raw)], 1))
    assert unavailable["status"] == "digest_mismatch" and unavailable["expected_source_sha256"] == bad_source[3]
    assert unavailable["source_sha256"] == source["source_sha256"] and unavailable["page_bytes_match"] is None
    assert unavailable["source_status"] is unavailable["replayed_page_sha256"] is None
    assert not command(exe, [*args, "--check-page", "ABC"], 2)
    assert not command(exe, [*args, "--check-page", digest(raw), "--check-page", digest(raw)], 2)
    # A repeat at a different page boundary reads the same ETL but returns different report bytes.
    other = list(args)
    other[other.index("--limit") + 1] = "1"
    replay(exe, other, digest(raw), digest(command(exe, other)), "read", False)
    for key, field, bad in ((None, "status", "digest_mismatch"), (None, "provider_guid", "unknown"), (None, "opcode", 36),
                            (None, "version", 3), (None, "source_bytes", -1), (None, "records_seen", 2_000_001),
                            (None, "loss_marker_records", source["records_seen"]), (None, "next_after", 0),
                            (None, "schema", "kn.etl_profile.v8"), (None, "schema", "kn.etl_profile.v7"),
                            (None, "capture_settings", []), (None, "after", source["decoded_samples"] + 1),
                            ("qualification", "verified_level", "X2"), ("qualification", "vtl", 0),
                            ("clock", "kind", "other"), ("clock", "header_perf_frequency", "9223372036854775808"),
                            ("row", "sample_ordinal", 0), ("row", "record_ordinal", source["records_seen"] + 1),
                            ("row", "count_field", 65536), ("row", "raw_timestamp", "-9223372036854775809"),
                            ("row", "header_flags", 0), ("row", "event_task", 65536), ("row", "event_channel", 256),
                            ("row", "instruction_pointer", "0x10000000000000000"), ("row", "stack_extension_items", 65536),
                            ("row", "verified_level", "X2")):
        obj = copy.deepcopy(source)
        owner = obj if key is None else obj["samples"][0] if key == "row" else obj[key]
        owner[field] = bad
        path.write_text(json.dumps(obj), encoding="utf8")
        assert query(exe, path, rc=1)["status"] == "unavailable", (key, field)
    duplicate = raw.replace(b'"record_ordinal":', b'"record_ordinal":1,"record_ordinal":', 1)
    assert duplicate != raw
    path.write_bytes(duplicate)
    assert query(exe, path, rc=1)["status"] == "unavailable"
    changed = copy.deepcopy(source)
    changed["samples"][0]["instruction_pointer"] = "0x1"
    path.write_bytes(json.dumps(changed).encode())
    v = query(exe, path)
    assert v["source"]["reported_etl_sha256"] == source["source_sha256"] and v["samples"][0]["ip"] == "1"
    assert v["samples"][0]["verified_level"] == "unqualified"
    replay(exe, args, digest(path.read_bytes()), digest(raw), "read", False)
    changed["samples"][0].update(raw_timestamp="9223372036854775807", instruction_pointer="0xffffffffffffffff")
    changed["samples"][1].update(raw_timestamp="-9223372036854775808", pointer_bytes=4, instruction_pointer="0xffffffff",
                                 header_flags=0x120, cpu_field="processor_number", cpu=255)
    for typ, label, freq, rate in ((1, "qpc", "0", None), (2, "system_time", "2", "10000000"),
                                   (3, "cpu_cycle", "50", None), (0, "unknown", "-1", None)):
        changed["clock"].update(raw_type=typ, kind=label, header_perf_frequency=freq)
        path.write_text(json.dumps(changed), encoding="utf8")
        v = query(exe, path)
        assert v["source_page"]["page_clock_reversed"] and v["source"]["ticks_per_second"] == rate
        assert (v["samples"][1]["ip"], v["samples"][1]["tick"]) == ("4294967295", "-9223372036854775808")
    changed["samples"][1]["instruction_pointer"] = "0x100000000"
    path.write_text(json.dumps(changed), encoding="utf8")
    assert query(exe, path, rc=1)["status"] == "unavailable"
    path.write_bytes(raw)
    alias = path.with_name("query-alias")
    os.link(path, alias)
    for mode in ("offline", "named"):
        cmd = ["--mode", "offline", "trace", "-"] if mode == "offline" else ["--offline", "!kmon", "trace", path]
        for bad in (False, True):
            with path.open("rb") as src, alias.open("ab") as sink:
                r = subprocess.run([exe, *cmd, *(["/limit", "0"] if bad else [])], stdin=src,
                                   stdout=subprocess.DEVNULL if bad else sink, stderr=sink if bad else subprocess.DEVNULL, timeout=60)
            assert r.returncode == 2 and path.read_bytes() == raw
    alias.unlink()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", type=Path, required=True)
    ap.add_argument("--etl", type=Path, required=True)
    ap.add_argument("--sha256", required=True)
    ap.add_argument("--all-pages", action="store_true")
    ap.add_argument("--adversarial", action="store_true")
    ap.add_argument("--check-short-tail", action="store_true")
    ap.add_argument("--reference-image", nargs=2, metavar=("LOCAL_PE", "PE_SHA256"))
    args = ap.parse_args()
    exe = args.exe.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="kn-etl-normalize-") as tmp:
        folder = Path(tmp)
        etl = folder / "source.etl"
        shutil.copyfile(args.etl, etl)
        pin = args.sha256.lower()
        with etl.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == pin
        total, samples, _, _, switches = BASE["oracle"](etl, folder, False, want_switches=True, include_samples=True)
        (folder / "raw.xml").unlink()
        print("Windows tracerpt read", total, "records including", len(samples), "CPU samples and", len(switches), "switches.", flush=True)
        path = folder / "saved report.json"
        base = ["--etl-profile", etl, "--sha256", pin]
        pages = BASE["page_cases"](len(samples), args.all_pages)
        seen = set()
        for after, limit in dict.fromkeys(pages):
            cmd = [*base, "--after", after, "--limit", limit]
            raw = command(exe, cmd)
            path.write_bytes(raw)
            source = json.loads(raw)
            assert source["records_seen"] == total and source["decoded_samples"] == len(samples)
            out = query(exe, path, "/limit", 128)
            assert_page(out, raw, source, samples, 0, 128)
            seen.update(int(s["sequence"]) for s in out["samples"])
        if args.all_pages:
            assert len(seen) == len(samples)
        options = [[], ["--thread-evidence"], ["--image-evidence"], ["--process-evidence"],
                   ["--image-evidence", "--process-evidence"], ["--build-evidence"], ["--capture-settings"],
                   ["--capture-settings", "--build-evidence"]]
        if args.reference_image:
            pe = [str(Path(args.reference_image[0]).resolve(strict=True)), args.reference_image[1]]
            options.extend([["--reference-image", *pe], ["--build-evidence", "--reference-image", *pe],
                            ["--thread-evidence", "--image-evidence", "--process-evidence", "--capture-settings",
                             "--reference-image", *pe, "--build-evidence"]])
            wrong_pin = "0" * 64 if pe[1].lower() != "0" * 64 else "1" * 64
            bad = json.loads(command(exe, [*base, "--reference-image", pe[0], wrong_pin, "--check-page", "0" * 64], 1))
            assert bad["status"] == "reference_digest_mismatch" and bad["source_sha256"] == pin
            assert bad["expected_reference_sha256"] == wrong_pin and bad["reference_sha256"] == pe[1].lower()
            assert bad["page_bytes_match"] is bad["replayed_page_sha256"] is None
        after = len(samples) // 2
        for flags in options:
            cmd = [*base, *flags, "--after", after, "--limit", 4]
            raw = command(exe, cmd)
            source = json.loads(raw)
            path.write_bytes(raw)
            for mode in ("named", "offline", "observe"):
                page = query(exe, path, "/limit", 2, mode=mode)
                assert_page(page, raw, source, samples, 0, 2)
                if page["next_cursor"]:
                    last = query(exe, path, "/limit", 2, "/cursor", page["next_cursor"], mode=mode)
                    assert_page(last, raw, source, samples, 2, 2)
            replay(exe, cmd, digest(raw).upper(), digest(raw), "read")
            if not flags and args.adversarial:
                adversarial(exe, path, cmd, raw)
        for flags in ([], ["--intervals"], ["--capture-settings", "--intervals"]):
            cmd = ["--etl-switches", etl, "--sha256", pin, "--limit", 4, *flags]
            raw = command(exe, cmd)
            replay(exe, cmd, digest(raw), digest(raw), "read")
            path.write_bytes(raw)
            assert query(exe, path, rc=1)["status"] == "unavailable"
        if args.check_short_tail:
            trimmed = folder / "short.etl"
            shutil.copyfile(etl, trimmed)
            with trimmed.open("r+b") as stream:
                stream.truncate(etl.stat().st_size - 1)
            with trimmed.open("rb") as stream:
                short_pin = hashlib.file_digest(stream, "sha256").hexdigest()
            cmd = ["--etl-profile", trimmed, "--sha256", short_pin, "--limit", 4, "--capture-settings"]
            raw = command(exe, cmd, 1)
            source = json.loads(raw)
            path.write_bytes(raw)
            out = query(exe, path, "/limit", 4, rc=1)
            assert source["status"] == "partial" and source["buffer_comparison"] == "fewer_than_declared"
            assert_page(out, raw, source, samples, 0, 4)
            replay(exe, cmd, digest(raw), digest(raw), "partial")
            cmd.extend(["--after", str(source["decoded_samples"] + 1)])
            empty = command(exe, cmd, 1)
            path.write_bytes(empty)
            partial_end = query(exe, path, rc=1)
            assert partial_end["query_complete"] and partial_end["samples"] == [] and partial_end["source_page"]["source_next_after"] is None
            replay(exe, cmd, digest(empty), digest(empty), "partial")
        print("Compared", len(seen), "distinct normalized CPU samples from", total, "raw records;",
              len(switches), "source switches;", len(options), "sample option sets reproduced.")


if __name__ == "__main__":
    main()
