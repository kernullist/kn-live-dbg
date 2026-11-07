"""Independent PE exports/linker MAP/RSDS oracle for the owned symbol fixture.

No production decoder or DIA APIs are imported. Input is a validation directory
created by validate-symbol-index.ps1; no binary is executed by this oracle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid


def verify(root: Path) -> dict:
    wire = (root / "fixture.knsymidx").read_bytes()
    assert wire[:8] == b"KNSYMIDX" and 256 <= len(wire) <= 32 * 1024 * 1024
    version, size, age, machine, symbol_count, type_count = struct.unpack_from("<6I", wire, 8)
    assert version == 1 and machine == 0x8664 and symbol_count <= 200000 and type_count <= 200000
    image = (root / "fixture-a.exe").read_bytes()
    for i, name in enumerate(("fixture-a.exe", "fixture-a.pdb", "msdia140.dll")):
        assert hashlib.sha256((root / name).read_bytes()).hexdigest().encode() == wire[32 + i * 64:96 + i * 64]
    cursor = 256

    def text() -> str:
        nonlocal cursor
        length, = struct.unpack_from("<I", wire, cursor)
        cursor += 4
        assert 0 < length <= 4096 and cursor + length <= len(wire)
        result = wire[cursor:cursor + length].decode("utf-8", errors="strict")
        cursor += length
        return result

    symbols = []
    for _ in range(symbol_count):
        rva, tag, known, length = struct.unpack_from("<IIIQ", wire, cursor)
        cursor += 20
        name, linkage = text(), text()
        assert known in (0, 1) and rva < size and length <= size - rva
        assert tag in (5, 7, 9, 10, 27) and (known or length == 0)
        assert not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in name)
        symbols.append((rva, name, linkage, tag, known, length))
    assert symbols == sorted(set(symbols))
    type_names = set()
    known_type_sizes = set()
    for _ in range(type_count):
        provider_id, known, length = struct.unpack_from("<IIQ", wire, cursor)
        cursor += 16
        name = text()
        assert name and known in (0, 1) and (known or length == 0)
        type_names.add(name)
        if known:
            known_type_sizes.add((name, length))
    assert cursor == len(wire)
    pe, = struct.unpack_from("<I", image, 0x3C)
    assert image[pe:pe + 4] == b"PE\0\0"
    pe_machine, section_count = struct.unpack_from("<HH", image, pe + 4)
    optional_size, = struct.unpack_from("<H", image, pe + 20)
    optional = pe + 24
    assert pe_machine == machine and struct.unpack_from("<H", image, optional)[0] == 0x20B
    preferred_base, = struct.unpack_from("<Q", image, optional + 24)
    assert struct.unpack_from("<I", image, optional + 56)[0] == size
    sections = []
    for i in range(section_count):
        at = optional + optional_size + i * 40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<4I", image, at + 8)
        sections.append((rva, raw_size, raw_offset))

    def offset(rva: int, length: int) -> int:
        found = [raw + rva - start for start, size, raw in sections if start <= rva and rva - start + length <= size]
        assert len(found) == 1 and found[0] + length <= len(image)
        return found[0]

    def cstring(rva: int) -> str:
        at = offset(rva, 1)
        end = image.index(b"\0", at, min(len(image), at + 2048))
        return image[at:end].decode("ascii")

    debug_rva, debug_size = struct.unpack_from("<II", image, optional + 112 + 6 * 8)
    identities = []
    debug = offset(debug_rva, debug_size)
    for at in range(debug, debug + debug_size, 28):
        kind, length, _, raw = struct.unpack_from("<4I", image, at + 12)
        if kind == 2 and image[raw:raw + 4] == b"RSDS":
            assert length >= 25 and raw + length <= len(image)
            identities.append((uuid.UUID(bytes_le=image[raw + 4:raw + 20]).hex, struct.unpack_from("<I", image, raw + 20)[0]))
    assert identities == [(wire[224:256].decode("ascii"), age)]
    exports_rva, exports_size = struct.unpack_from("<II", image, optional + 112)
    exports = offset(exports_rva, 40)
    functions_count, names_count, functions_rva, names_rva, ordinals_rva = struct.unpack_from("<5I", image, exports + 20)
    names_at, ordinals_at = offset(names_rva, names_count * 4), offset(ordinals_rva, names_count * 2)
    functions_at = offset(functions_rva, functions_count * 4)
    checked_exports = 0
    for i in range(names_count):
        name = cstring(struct.unpack_from("<I", image, names_at + i * 4)[0])
        ordinal, = struct.unpack_from("<H", image, ordinals_at + i * 2)
        assert ordinal < functions_count
        rva, = struct.unpack_from("<I", image, functions_at + ordinal * 4)
        assert not exports_rva <= rva < exports_rva + exports_size  # fixture has no forwarded exports
        assert {row[0] for row in symbols if row[2] == name} == {rva}, f"export mismatch: {name}"
        checked_exports += 1
    assert checked_exports == 4
    map_text = (root / "fixture-a.map").read_text(encoding="ascii")
    assert int(re.search(r"Preferred load address is ([0-9A-Fa-f]+)", map_text)[1], 16) == preferred_base
    for name in ("PrivateSymbolFunction", "PrivateSymbolState"):
        match = re.search(r"^\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+\?" + name + r"\S+\s+([0-9A-Fa-f]+)\s", map_text, re.MULTILINE)
        assert match
        expected = int(match[1], 16) - preferred_base
        assert {row[0] for row in symbols if row[2] == name} == {expected}, f"private MAP mismatch: {name}"
    control_names = sum(any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in row[2]) for row in symbols)
    legacy = (root / "legacy-types.txt").read_text(encoding="utf-8-sig").splitlines()
    legacy_names = set()
    legacy_sizes = set()
    assert legacy[-1].startswith("complete\t")
    assert int(legacy[-1].split("\t")[1]) == len(legacy) - 1
    for line in legacy[:-1]:
        kind, tag, known, length, name = line.split("\t", 4)
        assert kind == "type" and int(tag) in (11, 12, 17) and int(known) in (0, 1)
        legacy_names.add(name)
        if int(known):
            legacy_sizes.add((name, int(length)))
    assert legacy_names <= type_names, f"missing legacy names: {sorted(legacy_names - type_names)}"
    assert legacy_sizes <= known_type_sizes, f"missing legacy sizes: {sorted(legacy_sizes - known_type_sizes)}"
    return {"schema": "kn.symbol_index_oracle.v1", "symbols": symbol_count, "types": type_count,
            "exports_checked": checked_exports, "private_map_symbols_checked": 2,
            "legacy_type_names_checked": len(legacy_names), "legacy_type_sizes_checked": len(legacy_sizes),
            "escaped_control_names": control_names, "index_sha256": hashlib.sha256(wire).hexdigest(), "passed": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.fixtures), sort_keys=True))
