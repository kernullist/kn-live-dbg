"""Compare game-manifest observations with a cooperating native C++ game fixture."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess


def run(args, expected=0):
    result = subprocess.run([str(item) for item in args], capture_output=True, timeout=45)
    assert result.returncode == expected, (args[-2:], result.returncode, result.stdout[-240:], result.stderr[-320:])
    return result.stdout


def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()


def observation(fixture, manifest, case):
    data = json.loads(run([fixture, "--observe", manifest, case]))
    assert data["case"] == case and data["manifest_sha256"] == digest(manifest)
    assert data["cursor"] == (data["index"] + 1) % (2 if case == "legacy" else 4)
    return data


def check_samples(fixture, manifest, legacy):
    prior = observation(fixture, legacy, "legacy")
    assert prior["registry_reads"] == 0 and len(prior["rows"]) == 2
    assert all(row["fields"] == {"lifetime_status": "not_declared"} and row["readable"] and not row["modified"]
               for row in prior["rows"])
    for case in ("direct_primary", "direct_secondary", "indirect_primary", "indirect_secondary", "wrong_table", "wrong_slot"):
        data = observation(fixture, manifest, case)
        secondary = data["index"] % 2 != 0
        assert data["subobject"] - data["object"] == (8 if secondary else 0)
        assert data["registry_reads"] == 6 and data["body_reads"] == 3
        assert len(data["rows"]) == 2
        for row in data["rows"]:
            fields = row["fields"]
            assert row["readable"] and row["object"] == data["object"]
            assert fields["lifetime_source"] == "game_reported_registry_slot_v1"
            assert fields["lifetime_status"] == "reported_active_member"
            assert int(fields["subobject_address"]) == data["subobject"]
            assert fields["subobject_type"] == ("game::Secondary" if secondary else "Primary")
            assert fields["vptr_role"] == ("secondary" if secondary else "primary") and int(fields["subobject_size"]) == 8
            for prefix in ("before_", "after_"):
                for suffix in ("sequence_begin", "sequence", "sequence_end"):
                    assert int(fields[prefix + suffix]) == 2
                assert int(fields[prefix + "generation"]) == 0x100000001
                assert int(fields[prefix + "member_address"]) == data["object"]
                assert int(fields[prefix + "container_id"]) == int(fields["expected_container_id"]) == (17 if data["index"] < 2 else 23)
                assert fields[prefix + "phase"] == "2"
            assert row["slot"] == (data["subobject"] if row["vptr"] else data["table"])
            assert row["target"] == (data["table"] if row["vptr"] else data["target"])
            assert row["modified"] == (case == ("wrong_table" if row["vptr"] else "wrong_slot"))
    initial = {
        "vacant": "lifetime_vacant", "constructing": "lifetime_constructing", "destroying": "lifetime_destroying",
        "collecting": "lifetime_collecting", "unknown_phase": "lifetime_phase_unknown", "zero_generation": "lifetime_generation_unknown",
        "wrong_member": "lifetime_member_mismatch", "wrong_container": "lifetime_wrong_container", "unpublished": "lifetime_unpublished",
        "updating": "lifetime_updating", "short_record": "lifetime_unreadable", "split_publication": "lifetime_changed_during_read",
    }
    for case, expected in initial.items():
        data = observation(fixture, manifest, case)
        assert data["body_reads"] == 0 and len(data["rows"]) == 1
        row = data["rows"][0]
        assert not row["readable"] and not row["modified"] and row["fields"]["lifetime_status"] == expected
        assert row["reason"] == expected and "subobject_address" not in row["fields"]
        if case == "split_publication":
            assert row["fields"]["before_sequence_begin"] == "2" and row["fields"]["before_sequence_end"] == "4"
        if case == "wrong_member":
            assert row["object"] == data["object"] != int(row["fields"]["before_member_address"])
    for case, status in (("reuse_during_read", "lifetime_changed_during_read"), ("silent_generation_change", "lifetime_changed_during_read"),
                         ("missing_after", "lifetime_unreadable"), ("root_changed", "lifetime_root_or_vptr_changed")):
        data = observation(fixture, manifest, case)
        assert len(data["rows"]) == 2 and data["body_reads"] >= 2
        for row in data["rows"]:
            fields = row["fields"]
            assert not row["readable"] and not row["modified"] and fields["lifetime_status"] == status
            assert "subobject_address" not in fields and fields["before_generation"] == str(0x100000001)
            if case == "reuse_during_read":
                assert data["overlapped"] and data["current_root"] == data["object"] and data["current_table"] == data["table"]
                assert fields["after_generation"] == str(0x100000002) and fields["after_sequence_end"] == "4"
                assert int(fields["before_member_address"]) == int(fields["after_member_address"]) == data["object"]
            if case == "missing_after":
                assert not any(key.startswith("after_") for key in fields)
            if case == "root_changed":
                assert data["current_root"] != data["object"] and fields["before_sequence"] == fields["after_sequence"]
    print("23 native lifecycle scenarios passed, including synchronized destruction and reconstruction at the same address.")


def check_formats(exe, fixture, legacy):
    folder = legacy.parent
    layout, manifest = folder / "owned-lifetime.txt", folder / "lifetime.knmanifest"
    pdb = fixture.with_suffix(".pdb")
    run([fixture, "--lifetime-layout", layout])
    create = [exe, "--game-manifest", "create", fixture, pdb]
    verify = [exe, "--game-manifest", "verify"]
    run([*create, layout, manifest])
    run([*verify, manifest, fixture])
    assert legacy.read_text().splitlines()[0] == "KNDBG_GAME_MANIFEST 1"
    text = manifest.read_text()
    lines = text.splitlines()
    assert lines[0] == "KNDBG_GAME_MANIFEST 2"
    assert lines[1].split()[1:3] == [digest(fixture), digest(pdb)]
    assert lines[-6:] == ["subobjects 4", "0 Primary 8", "1 game::Secondary 8", "2 Primary 8", "3 game::Secondary 8", "end"]
    slots = lines.index("lifetimes 2") + 1
    object_rows = lines.index("objects 2") + 1
    first, second = (line.split() for line in lines[slots:slots+2])
    root_rva = lines[object_rows].split()[1]
    base_rva = int(first[1], 16)
    section = lines.index("vptrs 4")
    table_rva = lines[section+1].split()[2]
    mutations = {
        "zero-container": (slots, f"0 {base_rva:x} 0"), "misalignment": (slots, f"0 {base_rva+1:x} 11"),
        "wrapped": (slots, "0 fffffff8 11"), "same-slot": (slots+1, f"1 {base_rva:x} 17"),
        "overlap": (slots+1, f"1 {base_rva+8:x} 17"), "root-alias": (slots, f"0 {root_rva} 11"),
        "table-alias": (slots, f"0 {table_rva} 11"), "invalid-index": (slots, f"2 {base_rva:x} 11"),
        "duplicate-owner": (slots+1, f"0 {second[1]} 17"), "subobject-size": (-3, "2 Primary ffffffff"),
        "subobject-name": (-3, "2 game:::Bad 8"), "duplicate-subobject": (-2, "2 Primary 8"),
        "future-version": (0, "KNDBG_GAME_MANIFEST 3"), "missing-subobject": (-6, "subobjects 3"),
    }
    for tag, (index, replacement) in mutations.items():
        rows = lines.copy()
        rows[index] = replacement
        bad = folder / (tag + ".knmanifest")
        bad.write_text("\n".join(rows) + "\n", encoding="ascii")
        run([*verify, bad, fixture], 1)
    original = layout.read_text()
    mixed_layout, mixed = folder / "mixed-layout.txt", folder / "mixed.knmanifest"
    mixed_rows = []
    for line in original.splitlines():
        if line.startswith("lifetime fixture "):
            continue
        mixed_rows.append(line.rsplit(" ", 1)[0] if line.startswith("vptr fixture ") else line)
    mixed_layout.write_text("\n".join(mixed_rows) + "\n", encoding="ascii")
    run([*create, mixed_layout, mixed])
    run([*verify, mixed, fixture])
    raw = observation(fixture, mixed, "direct_secondary")
    assert raw["registry_reads"] == 0 and all(row["fields"] == {"lifetime_status": "not_declared"} for row in raw["rows"])
    guarded = observation(fixture, mixed, "indirect_secondary")
    assert guarded["registry_reads"] == 6 and all(row["fields"]["lifetime_status"] == "reported_active_member" for row in guarded["rows"])
    layout_rows = original.splitlines()
    primary_layout = layout_rows[2].split()
    secondary_layout = layout_rows[3].split()
    swapped = secondary_layout.copy()
    swapped[3] = primary_layout[3]
    for tag, old, new in (
        ("wrong-base-table", " ".join(secondary_layout), " ".join(swapped)),
        ("wrong-slot-type", f"lifetime fixture {first[1]}", f"lifetime fixture {root_rva}"),
        ("wrong-base-offset", " 1 Primary\n", " 1 game::Secondary\n"),
        ("missing-base", " 1 game::Secondary\n", " 1\n"),
        ("unknown-base", " 1 game::Secondary\n", " 1 Missing\n"),
    ):
        assert old in original
        altered, dest = folder / (tag + ".txt"), folder / ("rejected-" + tag + ".knmanifest")
        altered.write_text(original.replace(old, new), encoding="ascii")
        run([*create, altered, dest], 1)
        assert not dest.exists()
    original_hash = digest(manifest)
    with manifest.open("r+b"):
        run([*verify, manifest, fixture], 1)
    denied = folder / "changing-input.knmanifest"
    with layout.open("r+b"):
        run([*create, layout, denied], 1)
    assert not denied.exists()
    oversized = folder / "over-limit.knmanifest"
    with oversized.open("wb") as out:
        out.truncate(32 * 1024 * 1024 + 1)
    run([*verify, oversized, fixture], 1)
    run([*create, layout, manifest], 1)
    assert digest(manifest) == original_hash
    raced = folder / "concurrent.knmanifest"
    writers = [[*create, layout, raced], [*create, layout, raced]]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda cmd: subprocess.run(cmd, capture_output=True, timeout=45).returncode, writers))
    assert sorted(results) == [0, 1] and raced.read_bytes() == manifest.read_bytes()
    assert not list(folder.glob("*.knmanifest.pending-*"))
    alias = folder / "manifest-alias.txt"
    alias.hardlink_to(manifest)
    with alias.open("ab") as out:
        valid = subprocess.run([*verify, manifest, fixture], stdout=out, stderr=subprocess.PIPE, timeout=30)
        invalid = subprocess.run([*verify, manifest, fixture, "extra"], stdout=subprocess.PIPE, stderr=out, timeout=30)
    assert valid.returncode == invalid.returncode == 2 and digest(manifest) == original_hash
    with (folder / "separate-output.txt").open("wb") as out:
        assert subprocess.run([*verify, manifest, fixture], stdout=out, timeout=30).returncode == 0
    run([*create, layout, layout], 1)
    assert layout.read_text() == original
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "fixture", "legacy"):
        parser.add_argument("--" + name, type=Path, required=True)
    opts = parser.parse_args()
    exe, fixture, legacy = (file.resolve(strict=True) for file in (opts.exe, opts.fixture, opts.legacy))
    manifest = check_formats(exe, fixture, legacy)
    check_samples(fixture, manifest, legacy)


if __name__ == "__main__":
    main()
