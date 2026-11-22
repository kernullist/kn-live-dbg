"""Check a pinned rotating ETL file with missing and unrelated numbered neighbors."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import tempfile

HERE = Path(__file__).parent
CAP = runpy.run_path(str(HERE / "test-etl-capabilities.py"))
IMPORT = runpy.run_path(str(HERE / "test-etl-trace-import.py"))


def check_pages(exe, member, pin, info, folder, switches):
    for command, flags in (("--etl-profile", []), ("--etl-switches", ["--intervals"]), ("--etl-disk-io", []), ("--etl-hard-faults", [])):
        after = min(100, max(0, switches - 2)) if command == "--etl-switches" else 0
        args = [command, member, "--sha256", pin, "--limit", "2", "--after", str(after), *flags]
        raw = CAP["invoke"](exe, args, 1)
        page = json.loads(raw)
        assert page["status"] == "partial" and page["source_sha256"] == pin
        assert page["log_header"]["log_mode"] == info["log_mode"] and page["buffer_comparison"] == "not_comparable"
        page_pin = hashlib.sha256(raw).hexdigest()
        IMPORT["replay"](exe, args, page_pin, page_pin, "partial")
        if command == "--etl-switches":
            for event in page["switches"]:
                assert event["on_cpu"]["elapsed_ticks"] is None and event["off_cpu"]["elapsed_ticks"] is None
                ready = event["off_cpu"]["readiness"]
                assert ready["switch_out_to_ready_ticks"] is None and ready["ready_to_switch_in_ticks"] is None
        if command == "--etl-profile":
            saved = folder / "page.json"
            saved.write_bytes(raw)
            imported = IMPORT["query"](exe, saved, rc=1)
            assert imported["status"] == "partial" and imported["file_sha256"] == page_pin
            assert imported["source"]["reported_etl_sha256"] == pin and imported["source"]["log_header"] == page["log_header"]
            assert not any(imported[key] for key in IMPORT["TRUST"])
            page["status"] = "read"
            saved.write_bytes(json.dumps(page).encode("utf-8"))
            assert IMPORT["query"](exe, saved, rc=1)["status"] == "unavailable"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("--exe", "--etl", "--neighbor"):
        parser.add_argument(name, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--neighbor-sha256", required=True)
    args = parser.parse_args()
    exe, source, neighbor = (path.resolve(strict=True) for path in (args.exe, args.etl, args.neighbor))
    pin, other_pin = args.sha256.lower(), args.neighbor_sha256.lower()
    assert pin != other_pin and CAP["sha256"](source) == pin and CAP["sha256"](neighbor) == other_pin
    with tempfile.TemporaryDirectory(prefix="kn-etl-member-") as temp:
        folder = Path(temp)
        expected = CAP["windows_counts"](source, folder)
        assert CAP["windows_counts"](neighbor, folder) != expected, "use a neighbor with distinguishable records"
        member = folder / "part-2.etl"
        shutil.copyfile(source, member)
        probe = CAP["check_scan"](exe, member, pin, 1, expected)["probe"]
        info = probe["rotation_member"]
        assert info == dict(scope="supplied_file", log_mode=info["log_mode"], ordinal=None, set_size=None, session_complete=None)
        assert info["log_mode"] & 8 and probe["coverage"]["buffer_comparison"] == "not_comparable"
        shutil.copyfile(neighbor, folder / "part-1.etl")
        shutil.copyfile(neighbor, folder / "part-3.etl")
        assert CAP["report"](exe, member, pin, 1)[1] == probe
        check_pages(exe, member, pin, info, folder, expected[1]["context_switch"])
        renamed = folder / "arbitrary.etl"
        member.rename(renamed)
        assert CAP["report"](exe, renamed, pin, 1)[1] == probe
        literal = folder / "part-%d.etl"
        renamed.rename(literal)
        assert CAP["report"](exe, literal, pin, 1)[1] == probe
        missing = CAP["report"](exe, member, pin, 1)[1]
        assert missing["status"] == "source_unavailable" and "rotation_member" not in missing and missing["coverage"] is None
        shutil.copyfile(neighbor, member)
        mismatch = CAP["report"](exe, member, pin, 1)[1]
        assert mismatch["status"] == "digest_mismatch" and mismatch["source_sha256"] == other_pin
        assert "rotation_member" not in mismatch and mismatch["coverage"] is None
    assert (CAP["sha256"](source), CAP["sha256"](neighbor)) == (pin, other_pin)
    print(f"Checked one rotating file against tracerpt: {expected[0]} records, {expected[1]}.")


if __name__ == "__main__":
    main()
