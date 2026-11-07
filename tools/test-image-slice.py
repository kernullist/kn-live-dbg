"""Independent PE, receipt-selection, coverage and fresh-process slice oracle."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import uuid

from image_scope_claim_oracle import check_scope_report

BASE = 0x180000000
EXPECTED = {
    "clean": (8184, 8, 0, 0),
    "modified": (8184, 8, 0, 1),
    "unstable": (4096, 0, 4096, 0),
    "unreadable": (0, 0, 0, 0),
    "guard": (0, 0, 0, 0),
    "identity": (0, 0, 8192, 0),
    "continuation": (4096, 0, 0, 0),
    "secondary": (0, 0, 0, 0),
    "secondary_verified": (8184, 8, 0, 0),
    "secondary_modified": (8184, 8, 0, 1),
    "secondary_unstable": (4096, 0, 4096, 0),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    executable = str(Path(args.exe).resolve())
    root = args.fixtures.resolve()
    checks = 0

    def check(passed, label):
        nonlocal checks
        checks += 1
        assert passed, label

    def replay(path, success=True, current=False):
        command = ([executable, "--offline", "!kmon", "replay-image", str(path), "/json"] +
                   (["/current"] if current else [])) if args.cli else [executable, "--replay", str(path)]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30)
        check(result.returncode == (0 if success else 1), "replay exit status")
        data = json.loads(result.stdout)
        check(data["schema"] == "kn.image_slice_replay.v1", "slice envelope is distinct from single-page replay")
        check((data["status"] == "replayed") == success, "fresh replay state")
        if success:
            envelope = json.loads(path.read_bytes())
            blob = path.parent.parent / "image-references" / (envelope["payload"]["reference_sha256"] + ".knblob")
            check_scope_report(envelope, [envelope], [blob.read_bytes()], data)
        else:
            check(data["claim_assessment"] is None, "failed slice replay withholds current claims")
        return data

    for name, counts in EXPECTED.items():
        path = root / name / "image-reads" / "slice.knslice"
        text = path.read_text(encoding="utf-8")
        envelope = json.loads(text)
        raw = text.split(',"payload":', 1)[1][:-1]
        check(hashlib.sha256(raw.encode()).hexdigest() == envelope["recipe_sha256"], "independent payload SHA-256")
        p = envelope["payload"]
        reference = root / name / "image-references" / (p["reference_sha256"] + ".knblob")
        file_bytes = reference.read_bytes()
        check(hashlib.sha256(file_bytes).hexdigest() == p["reference_sha256"], "independent reference SHA-256")
        check(not (root / name / "original.exe").exists(), "original reference no longer exists")
        check(struct.unpack_from("<Q", file_bytes, 0x420)[0] == 0x140001234, "unrelocated original pointer retained")
        check(p["reference_content_rechecked"] and p["reference_content_stable"], "original reference fence")
        reads = p["target_reads"]
        attempts = reads["attempts"]["reads"]
        check(int(reads["attempts"]["attempts"]) == len(attempts), "all attempts retained")
        for call in reads["parser_reads"]:
            if not call["accepted"]:
                continue
            primary = attempts[int(call["primary_receipt"]) - 1]
            selected = attempts[int(call["returned_receipt"]) - 1]
            check(primary["read"]["status"] == "partial" and primary["read"]["spans"][0]["bytes_hex"] == "41",
                  "failed original prefix remains raw evidence")
            check(selected["fallback"]["from_receipt"] == primary["sequence"] and selected["fallback"]["permitted"],
                  "selected source links original failure")
            check(sum(len(bytes.fromhex(s["bytes_hex"])) for s in selected["read"]["spans"]) == int(call["length"]),
                  "parser consumes complete selected source")
        result = replay(path)
        check(result["result"] == p["recorded_result"], "same-policy result matches original")
        check(result["current_policy"] == p["policy"] and result["recorded_policy"] == p["policy"], "reported policy matches replay engine")
        proof = result["proof"]
        claim_states = [claim["status"] for claim in result["claim_assessment"]["claims"]]
        expected_states = ["contradicted", "supported"] if name in {"modified", "secondary_modified"} else \
            ["supported", "contradicted"] if name == "continuation" else ["unfulfilled", "unfulfilled"]
        check(claim_states == expected_states, "scoped common claims preserve modified and unavailable controls")
        observed = tuple(int(proof[k]) for k in ("compared_bytes", "excluded_bytes", "unreadable_bytes", "changed_bytes"))
        check(observed == counts, "independent slice coverage denominators")
        check(sum(int(r["length"]) for r in proof["differs"]) == counts[3], "independent changed ranges")
        check(sum(int(r["length"]) for r in proof["matches"]) == counts[0] - counts[3], "independent matching ranges")
        check(not proof["execution_observed"] and not proof["atomic_snapshot"] and not proof["collector_authenticated"],
              "replay preserves scope and provenance limits")
        check(not proof["whole_sweep_complete"], "one slice does not establish a whole sweep")
        if name in {"unreadable", "guard", "identity", "secondary"}:
            check(not proof["target_reference_qualified"] and
                  "stable_target_reference_qualification" in proof["unfulfilled_requirements"], "qualification gap remains explicit")
        if name.startswith("secondary_"):
            check(p["slice"]["secondary_opened"] and int(p["slice"]["page_count"]) == 2 and p["secondary_reads"] is not None,
                  "positive actual secondary view captured")
            check(int(p["slice"]["relocation_base"]) not in (BASE, 0x140000000), "independent third relocation basis")
        for row in p["recorded_result"]:
            comparison = row["comparison"]
            if int(comparison["rva"]) == 0x1000 and comparison["expected_hex"]:
                expected = bytes.fromhex(comparison["expected_hex"])
                check(struct.unpack_from("<Q", expected, 0x20)[0] == int(p["slice"]["relocation_base"]) + 0x1234,
                      "normalization uses recorded basis and original relocation")
        if args.cli:
            unavailable = replay(path, False, True)
            check(unavailable["status"] == "slice_current_reanalysis_unavailable", "current reanalysis does not alias original policy")

    # Canonical hashes are not a substitute for structural and policy validation.
    original_path = root / "modified" / "image-reads" / "slice.knslice"
    original = json.loads(original_path.read_text(encoding="utf-8"))
    for mutation in ("accepted_partial", "changed_target", "unknown_field", "wrong_schedule", "oversized"):
        document = copy.deepcopy(original)
        p = document["payload"]
        if mutation == "accepted_partial":
            p["target_reads"]["parser_reads"][0]["returned_receipt"] = "1"
        elif mutation == "changed_target":
            calls = p["target_reads"]["parser_reads"]
            call = next(c for c in calls if int(c["address"]) == BASE + 0x1000)
            read = p["target_reads"]["attempts"]["reads"][int(call["returned_receipt"]) - 1]["read"]
            value = bytearray.fromhex(read["spans"][0]["bytes_hex"])
            value[0x50] ^= 1
            read["spans"][0]["bytes_hex"] = value.hex()
        elif mutation == "unknown_field":
            p["unrecorded_override"] = True
        elif mutation == "wrong_schedule":
            p["slice"]["start_range"] = "1"
        raw = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
        document["recipe_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
        serialized = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
        if mutation == "oversized":
            serialized += " " * (2 * 1024 * 1024)
        path = original_path.parent / ("oracle-" + uuid.uuid4().hex + ".knslice")
        with path.open("x", encoding="utf-8", newline="") as output:
            output.write(serialized)
        denied = replay(path, False)
        check(denied["proof"] is None, "contradictory evidence has no proof")
    print(f"Image slice oracle passed: {checks} checks; cases={len(EXPECTED)}; cli={args.cli}")


if __name__ == "__main__":
    main()
