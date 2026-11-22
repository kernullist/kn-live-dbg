"""Compare KnLiveDbg's V8 query with the producing Node runtime and its tick processor."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from runpy import run_path
import shutil
import struct
import subprocess
import tempfile

HEADER = ["v8-version,13,6,233,17,-node.63,0", "v8-platform,windows,unknown", "profiler,begin,1000"]
NATIVE = {10: "Sparkplug", 11: "Maglev", 12: "Opt"}
AUDIT = run_path(str(Path(__file__).with_name("validate-public-content.py")))["inspect"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def invoke(exe, args, rc=0, stdin=None):
    r = subprocess.run([exe, *map(str, args)], stdin=stdin, capture_output=True, timeout=90)
    assert r.returncode == rc, (r.returncode, rc, r.stdout[:240], r.stderr[-300:])
    return r.stdout


def args_for(profile, binary=None):
    args = ["--offline", "!kmon", "trace", profile, "/v8", sha(profile.read_bytes())]
    return args if binary is None else [*args, "/code-log", binary, sha(binary.read_bytes())]


def report(exe, args, rc=0):
    page = json.loads(invoke(exe, args, rc))
    assert page["schema"] == "kn.v8_profile_query.v1" and not page["execution_independently_verified"]
    if page["status"] != "unavailable":
        assert not page["collector_authenticated"] and not page["code_at_sample_time_verified"]
        assert page["raw_decoder_used"] and not page["live_backend_opened"] and page["sample_time_us"] is None
        assert all(page[k] is None for k in ("process_id", "thread_id", "cpu", "vtl", "lost_samples"))
        assert all(row["code_version"] is None and row["verified_level"] == "unqualified" for row in page["samples"])
    return page


def decl(addr=0x20000, size=64, stamp=10, kind=12, name="hot", marker="*"):
    return f"code-creation,JS,{kind},{stamp},{addr:#x},{size},{name},0x55555,{marker}"


def tick(pc=0x20008, stamp=20, tail="", external=0):
    return f"tick,{pc:#x},{stamp},{external},0x0,0{tail}"


def binary_create(addr, code, name=b"JS:*hot"):
    # The two ABI padding words are not semantic fields.
    return b"C" + struct.pack("<iIQiI", len(name), 0xdeadbeef, addr, len(code), 0xdeadbeef) + name + code


def write_log(path, records):
    path.write_bytes(("\n".join(records) + "\n").encode())


def controls(exe, folder, standalone):
    profile, side = folder / "controls.log", folder / "controls.log.ll"
    body = bytes(range(64))
    raw_code = binary_create(0x20000, body)
    blob = b"x64\0" + raw_code

    def inputs(events, binary=blob, end=True):
        write_log(profile, [*HEADER, *events, *(["profiler,end"] if end else [])])
        side.write_bytes(binary)
        return args_for(profile, side)

    def one(events, binary=blob, rc=0, end=True):
        page = report(exe, inputs(events, binary, end), rc)
        return page, page["samples"][0]

    page, row = one([decl(), tick(pc=0x2003f)])
    assert row["byte_relation"] == "matched_code_record" and row["log_order_range"]["pc_offset"] == 63
    window = row["code_record_bytes"]
    assert window["window_bytes"] == 1 and window["window_sha256"] == sha(body[-1:])
    assert window["body_sha256"] == sha(body) and window["body_file_offset"] + 63 == window["window_file_offset"]
    assert page["code_log_status"] == "matching_event_sequence"
    assert one([decl(), tick(pc=0x20040)])[1]["range_relation"] == "no_logged_range"
    assert one([decl(), tick(external=1)])[1]["range_relation"] == "external_callback"
    assert one([decl(), tick(tail=",overflow,0x20000")])[1]["range_relation"] == "sample_buffer_overflow"
    assert one([decl(stamp=20), tick()])[1]["range_relation"] == "clock_unqualified"
    assert one([decl(), tick(), tick(stamp=19)])[0]["clock_reversed"]
    assert one([decl(kind=9, marker="~"), tick()], b"x64\0" + binary_create(0x20000, body, b"JS:~hot"))[1]["range_relation"] == "interpreter_bytecode_range"
    assert one([decl(), "code-deopt,11,64,0x20000,-1,-1,eager,source,reason", tick()])[1]["range_relation"] == "deoptimization_reported"
    assert one([decl(), "code-delete,0x20000", tick()])[1]["range_relation"] == "no_logged_range"
    moved = blob + b"G" + b"M" + struct.pack("<QQ", 0x20000, 0x24000)
    page, row = one([decl(), "code-move,0x20000,0x24000", tick(pc=0x24001)], moved)
    assert page["binary_gc_markers"] == 1 and row["range_relation"] == "relocated_js_range" and row["code_record_bytes"] is None
    assert (row["log_order_range"]["creation_record"], row["log_order_range"]["location_record"]) == (4, 5)
    newer = binary_create(0x20004, b"B" * 5)
    assert one([decl(), tick(), decl(0x20004, 5, 30)], blob + newer)[1]["range_relation"] == "address_reused"
    assert one([decl(), tick(), "code-unknown,0x20000"], rc=1)[1]["code_record_bytes"] is None
    assert one([decl(), "code-delete,0x50000", tick()], rc=1)[0]["unresolved_mapping_change"]
    assert one([decl(), tick()], end=False, rc=1)[1]["range_relation"] == "incomplete_history"

    for wire, label in [(r"comma\x2Cslash\\name", b"comma,slash\\name"), (r"\xe9", "é".encode()),
                        (r"\xce\xbb \ucf54\ub4dc", "λ 코드".encode()), (r"\ud83d\udd0c", "🔌".encode())]:
        side_name = b"JS:*" + label
        assert one([decl(name=wire), tick()], b"x64\0" + binary_create(0x20000, body, side_name))[1]["byte_relation"] == "matched_code_record"
    for field, expected in [("0x0", "0x0"), ("0xffffffffffffffff", "0xffffffffffffffff")]:
        _, row = one([decl().replace("0x55555", field), tick()])
        assert row["log_order_range"]["creation_sfi"] == expected and row["code_record_bytes"] is None
    _, wasm = one([decl(kind=4), tick()])
    assert wasm["log_order_range"]["creation_sfi"] is None and wasm["range_relation"] == "other_code_range"
    assert one([decl(), "code-deopt,11,64,0x20100,-1,-1,eager,source,reason", tick()], rc=1)[0]["unresolved_mapping_change"]
    different = b"x64\0" + binary_create(0x20000, body, b"JS:*other")
    assert one([decl(), tick()], different)[1]["byte_relation"] == "label_unconfirmed"
    for damaged, status in [(blob[:-1], "invalid_binary_record"), (blob + b"X", "invalid_binary_record"),
                            (blob + raw_code, "event_sequence_mismatch"), (b"x64\0", "event_sequence_mismatch"),
                            (b"arm64\0" + raw_code, "unsupported_architecture"), (blob[:5]+b"\xff"*24, "invalid_binary_record")]:
        page, row = one([decl(), tick()], damaged, 1)
        assert page["code_log_status"] == status and row["code_record_bytes"] is None

    args = inputs([decl(), tick(), tick(stamp=21), tick(stamp=22)])
    first = report(exe, [*args, "/limit", 1])
    cursor = first["next_cursor"]
    following = report(exe, [*args, "/cursor", cursor, "/limit", 1, "/json"])
    assert following["samples"][0]["sample_ordinal"] == 2
    different_args = inputs([decl(), tick(), tick(stamp=21), tick(stamp=22)], blob[:-1] + b"\xff")
    assert report(exe, [*different_args, "/limit", 1, "/cursor", cursor], 1)["error"] == "invalid_cursor"
    assert report(exe, [*args, "/limit", 1], 1)["error"] == "code_log_digest_mismatch"
    without = args_for(profile)
    assert report(exe, without)["samples"][0]["byte_relation"] == "not_supplied"
    assert report(exe, [*without, "/cursor", cursor, "/limit", 1], 1)["error"] == "invalid_cursor"
    assert report(exe, [*without[:-1], "0"*64], 1)["error"] == "profile_digest_mismatch"
    assert not invoke(exe, [*without, "/limit", 0], 2)
    assert not invoke(exe, [*without, "/limit", 2, "/limit", 2], 2)
    with profile.open("ab") as sink:
        size = sink.tell()
        cmd = [exe, *map(str, without)]
        assert subprocess.run(cmd, stdout=sink, stderr=subprocess.PIPE, timeout=20).returncode == 2
        assert sink.tell() == size
    if not standalone:
        for mode in ("offline", "observe"):
            with profile.open("rb") as source:
                inherited = ["--mode", mode, "trace", "-", "/v8", without[-1]]
                assert json.loads(invoke(exe, inherited, stdin=source))["samples"] == report(exe, without)["samples"]
                assert not invoke(exe, [*inherited, "/code-log", side, "a"*64], 2, source)
        with profile.open("rb") as source, side.open("ab") as diagnostic:
            size = diagnostic.tell()
            cmd = [exe, *inherited, "/code-log", side, "a"*64]
            assert subprocess.run(cmd, stdin=source, stdout=subprocess.PIPE, stderr=diagnostic, timeout=20).returncode == 2
            assert diagnostic.tell() == size
        bad = subprocess.run([exe, *inherited], input=profile.read_bytes(), capture_output=True, timeout=20)
        assert bad.returncode == 1 and json.loads(bad.stdout)["status"] == "unavailable"
    for invalid in [decl(size=0), decl(addr=0x7fffffffffff, size=2), "tick,0x2,4,0,0x0,0,",
                    "tick,0x2,4,2,0x0,0", "tick,0x2,4,0,0x0,10", "code-move,0x20000,not_an_address", "profiler,end,",
                    HEADER[0], HEADER[1], "code-creation,JS,13,2,0x10000,5,hot", "tick,0x20,7,0,0x0,0,0x12,overflow"]:
        assert report(exe, inputs([decl(), invalid]), 1)["status"] == "unavailable", invalid
    write_log(profile, [HEADER[0].replace("13,6", "14,1"), *HEADER[1:]])
    assert report(exe, args_for(profile), 1)["error"] == "unsupported_v8_version"
    write_log(profile, [*HEADER, decl(), tick(), "profiler,end"])
    with profile.open("ab") as f:
        f.write(b"code-crea")
    truncated = report(exe, args_for(profile), 1)
    assert truncated["incomplete_final_line"] and truncated["samples"][0]["code_record_bytes"] is None
    write_log(profile, [*HEADER, *([decl()] * 65537), "profiler,end"])
    assert report(exe, args_for(profile), 1)["error"] == "mapping_limit"
    print("V8 format, lifetime, byte-boundary, paging and source controls passed.")

def runtime_oracle(exe, node, folder):
    version = subprocess.check_output([node, "-p", "process.versions.v8"], text=True).strip()
    assert version == "13.6.233.17-node.63", version
    program = folder / "owned.js"
    program.write_text("""'use strict';
function profiledArithmetic(seed) {
  let value = seed;
  for (let i = 1; i < 64000; ++i) value = Math.imul(value ^ (i >>> 3), 17) + i | 0;
  return value;
}
let result = 7;
const until = performance.now() + 1800;
do { result = profiledArithmetic(result); } while (performance.now() < until);
console.log(result);
""", encoding="utf8")
    profile, binary = folder / "owned.log", folder / "owned.log.ll"
    subprocess.run([node, "--prof", "--ll-prof", "--no-logfile-per-isolate", "--logfile=owned.log",
                    "--log-code-disassemble", "--no-log-source-code", program], cwd=folder, check=True,
                   capture_output=True, timeout=90)
    processed = subprocess.run([node, "--prof-process", "--preprocess", profile], cwd=folder, check=True,
                               capture_output=True, timeout=120)
    native = json.loads(processed.stdout)
    raw = profile.read_bytes()
    stream = binary.read_bytes()
    prefix = args_for(profile, binary)
    # Extract instruction bytes from V8's independently formatted disassembly.
    # The listing can include metadata, jump tables and padding, so only compare
    # contiguous instruction rows at their exact printed addresses and offsets.
    disassembly, ticks, creations = {}, [], {}
    total_records = 0
    for i, line in enumerate(raw.splitlines(), 1):
        total_records = i
        if line.startswith(b"tick,"):
            ticks.append((i, line.split(b",")))
        elif line.startswith(b"code-creation,"):
            f = line.split(b",")
            creations[i] = (int(f[4], 16), int(f[5]), int(f[2]), int(f[3]))
        elif line.startswith(b"code-disassemble,"):
            _, address, tier, listing = line.split(b",", 3)
            if tier not in (b"BASELINE", b"MAGLEV", b"TURBOFAN_JS"):
                continue
            start = int(address, 16)
            current = {}
            for ins in listing.split(b"\\n"):
                m = re.match(rb"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s", ins)
                if m and int(m[1], 16) == start + int(m[2], 16) and len(m[3]) % 2 == 0:
                    for j, v in enumerate(bytes.fromhex(m[3].decode()), int(m[2], 16)):
                        if j in current:
                            assert current[j] == v
                        current[j] = v
            disassembly[start] = current
    assert stream.startswith(b"x64\0")
    pos, ordinal = 4, 0
    bodies = {}
    while pos < len(stream):
        ordinal += 1
        tag = stream[pos:pos+1]
        pos += 1
        if tag == b"G":
            continue
        if tag == b"M":
            pos += 16
            continue
        assert tag == b"C"
        name_len, base, length = struct.unpack_from("<i4xQi4x", stream, pos)
        pos += 24 + name_len
        assert 0 < length <= len(stream) - pos
        bodies[ordinal] = (base, length, pos)
        pos += length
    assert len(ticks) == len(native["ticks"]) and len(ticks) > 0
    counts = Counter()
    cursor = ""
    while True:
        opts = [*prefix, "/limit", 17, *(["/cursor", cursor] if cursor else [])]
        page = report(exe, opts)
        assert page["status"] == "ok" and page["code_log_status"] == "matching_event_sequence"
        assert page["profile_sha256"] == prefix[5] and page["code_log_sha256"] == prefix[-1]
        assert page["samples_total"] == len(ticks) and page["records_seen"] == total_records
        assert page["binary_records_examined"] == ordinal and page["code_creations"] == len(creations)
        for row in page["samples"]:
            n = row["sample_ordinal"] - 1
            origin, fields = ticks[n]
            expected = native["ticks"][n]
            assert row["record_ordinal"] == origin and int(row["sampled_pc"], 16) == int(fields[1], 16)
            assert int(row["logger_time_us"]) == int(fields[2]) == expected["tm"]
            assert row["vm_state"] == int(fields[5]) == expected["vm"]
            assert row["has_external_callback"] == bool(int(fields[3])) and int(row["tos_or_external_entry"], 16) == int(fields[4], 16)
            counts["ticks"] += 1
            code = native["code"][expected["s"][0]] if expected["s"] and expected["s"][0] >= 0 else None
            owned = code and code.get("kind") in NATIVE.values() and "profiledArithmetic " in code.get("name", "")
            if owned:
                assert row["byte_relation"] == "matched_code_record", (n, row["range_relation"], row["byte_relation"])
            captured = row["code_record_bytes"]
            if not captured:
                continue
            assert row["range_relation"] == "reported_js_range" and row["byte_relation"] == "matched_code_record"
            r = row["log_order_range"]
            base, length, at = bodies[captured["binary_record"]]
            assert (base, length, r["v8_kind"], int(r["creation_logger_us"])) == creations[r["creation_record"]]
            assert int(r["creation_start"], 16) == base and r["reported_size"] == length and r["location_record"] == r["creation_record"]
            off = r["pc_offset"]
            assert code and code["kind"] == NATIVE[r["v8_kind"]] and code["tm"] == int(r["creation_logger_us"])
            assert expected["s"][1] == off == int(row["sampled_pc"], 16) - base
            assert captured["body_file_offset"] == at and captured["body_sha256"] == sha(stream[at:at+length])
            size = min(32, length-off)
            assert captured["window_bytes"] == size and captured["window_file_offset"] == at+off
            window = stream[at+off:at+off+size]
            assert captured["window_sha256"] == sha(window)
            counts["paired"] += 1
            if owned:
                counts["owned"] += 1
            listing = disassembly[base]
            if all(j in listing for j in range(off, off+size)):
                assert bytes(listing[j] for j in range(off, off+size)) == window
                counts["disassembled"] += 1
                if owned:
                    counts["owned_disassembled"] += 1
            if counts["paired"] == 1:
                for obj in (page, row, r, captured):
                    assert "private-evidence-bundle" in {f["rule"] for f in AUDIT("page.txt", json.dumps(obj).encode())}
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert counts["ticks"] == len(ticks) and counts["owned_disassembled"] > 0, counts
    assert "private-v8-code-log" in {f["rule"] for f in AUDIT("renamed.bin", stream)}
    assert "private-v8-profile" in {f["rule"] for f in AUDIT("renamed.txt", raw[:8192])}
    subprocess.run([node, "--prof", "--ll-prof", "--no-logfile-per-isolate", "--logfile=other.log",
                    "--no-log-source-code", "-e", "Math.sqrt(3)"], cwd=folder, check=True, capture_output=True, timeout=60)
    other = report(exe, args_for(profile, folder / "other.log.ll"), 1)
    assert other["code_log_status"] == "event_sequence_mismatch" and other["samples"]
    assert all(s["code_record_bytes"] is None for s in other["samples"])
    print("Producing V8", version, "creations", len(creations), "binary records", ordinal, dict(counts))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--node", help="run an owned workload with this Node.js 24.22.3 executable")
    parser.add_argument("--standalone", action="store_true", help="the native self-test EXE only implements the named offline route")
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="kn-v8-profile-") as tmp:
        folder = Path(tmp)
        controls(exe, folder, args.standalone)
        if args.node:
            node = shutil.which(args.node) or str(Path(args.node).resolve(strict=True))
            runtime_oracle(exe, node, folder)


if __name__ == "__main__":
    main()
