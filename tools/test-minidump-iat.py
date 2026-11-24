"""Check offline IAT observations against a test child's Windows loader and original dump bytes."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import queue
import runpy
import shutil
import struct
import subprocess
import sys
import tempfile
import threading


FIXTURE = runpy.run_path(str(Path(__file__).with_name("test-image-iat-reference.py")))
EXPORTS = FIXTURE["EXPORTS"]
DUMPS = {"regular": 0x82001, "full": 0x802}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def actor(directory):
    # Only the DLL built by this test and the three statically named exports.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_void_p]
    kernel.GetProcAddress.restype = ctypes.c_void_p
    kernel.GetModuleHandleExW.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HMODULE)]
    kernel.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    with os.add_dll_directory(str(directory)):
        dll = ctypes.WinDLL(str(directory / "iat-test.dll"))
        provider = ctypes.WinDLL(str(directory / "iat-provider.dll"))
        observed = {}
        for name, (library, function, ordinal) in EXPORTS.items():
            address = kernel.GetProcAddress(dll._handle, name.encode("ascii"))
            assert address
            code = ctypes.string_at(address, 6)
            assert code[:2] == b"\xff\x25"
            slot = address + 6 + struct.unpack_from("<i", code, 2)[0]
            raw = ctypes.string_at(slot, 8)
            pointer, = struct.unpack("<Q", raw)
            declared = provider if library == "iat-provider.dll" else kernel
            symbol = function.encode("ascii") if function else int(ordinal)
            assert pointer and pointer == kernel.GetProcAddress(declared._handle, symbol)
            owner = wintypes.HMODULE()
            assert kernel.GetModuleHandleExW(0x6, pointer, ctypes.byref(owner))
            path = ctypes.create_unicode_buffer(32768)
            assert 0 < kernel.GetModuleFileNameW(owner, path, len(path)) < len(path)
            observed[name] = dict(rva=address - dll._handle, slot=slot - dll._handle, code=code.hex(),
                                  sha256=digest(raw), owner=Path(path.value).name)
        print(json.dumps(observed), flush=True)
        assert sys.stdin.readline().strip() == "release"


def capture(root, fixtures):
    write_dump = ctypes.WinDLL("dbghelp", use_last_error=True).MiniDumpWriteDump
    write_dump.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD,
                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    write_dump.restype = wintypes.BOOL
    keys = ("SystemRoot", "WINDIR", "TEMP", "TMP", "ComSpec", "PYTHONUTF8",
            "SystemDrive", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS")
    env = {k: os.environ[k] for k in keys if k in os.environ}
    with subprocess.Popen([sys.executable, "-B", __file__, "--actor", str(fixtures)], env=env,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            ready = queue.Queue()
            threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
            observed = json.loads(ready.get(timeout=30))
            birth = runpy.run_path(str(Path(__file__).with_name("test-image-loader-window.py")))["process_birth"]
            generation = birth(ctypes.WinDLL("kernel32"), int(child._handle)) // 10_000_000 - 11_644_473_600
            for name, flags in DUMPS.items():
                with (root / (name + ".dmp")).open("xb") as stream:
                    if not write_dump(int(child._handle), child.pid, msvcrt.get_osfhandle(stream.fileno()),
                                      flags, None, None, None):
                        raise ctypes.WinError(ctypes.get_last_error())
        finally:
            try:
                _, errors = child.communicate(b"release\n", timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise
            if child.returncode:
                raise RuntimeError(errors.decode(errors="replace")[-800:])
        return observed, child.pid, generation


class Layout:
    """Read documented SDK fields independently of the product's parser."""
    def __init__(self, data):
        self.data = data
        count, directory = struct.unpack_from("<II", data, 8)
        self.streams = {}
        for i in range(count):
            descriptor = directory + 12 * i
            kind, size, offset = struct.unpack_from("<III", data, descriptor)
            self.streams[kind] = (descriptor, offset, size)
        _, offset, _ = self.streams[4]
        self.modules = []
        for i in range(struct.unpack_from("<I", data, offset)[0]):
            row = offset + 4 + 108 * i
            base, size, checksum, timestamp, name = struct.unpack_from("<QIIII", data, row)
            length, = struct.unpack_from("<I", data, name)
            basename = Path(data[name + 4:name + 4 + length].decode("utf-16-le")).name
            self.modules.append((row, base, size, checksum, timestamp, basename))
        self.ranges = []
        if 9 in self.streams:
            _, table, _ = self.streams[9]
            count, start = struct.unpack_from("<QQ", data, table)
            for i in range(count):
                addr, size = struct.unpack_from("<QQ", data, table + 16 + i * 16)
                self.ranges.append((addr, size, start))
                start += size
        else:
            _, table, _ = self.streams[5]
            count, = struct.unpack_from("<I", data, table)
            self.ranges = [struct.unpack_from("<QII", data, table + 4 + i * 16) for i in range(count)]

    def find_range(self, address, length):
        matches = [i for i, (va, n, _) in enumerate(self.ranges) if va <= address and address + length <= va + n]
        assert len(matches) == 1
        return matches[0]

    def offset(self, address, length):
        va, _, offset = self.ranges[self.find_range(address, length)]
        return offset + address - va

    def receipt(self, parts, address, length):
        result = b""
        for part in parts:
            index, start, size = map(int, (part["range_index"], part["file_offset"], part["bytes"]))
            va, n, offset = self.ranges[index]
            assert size > 0 and offset <= start and start + size <= offset + n
            assert va + start - offset == address + len(result)
            result += self.data[start:start + size]
        assert len(result) == length
        return result


def split_slot(layout, slot, gap):
    # Rebuild only the normal descriptor table. Put the second half of this
    # cell in a separate file extent so a reader must consult both descriptors.
    data = bytearray(layout.data)
    ranges = list(layout.ranges)
    i = layout.find_range(slot, 8)
    va, length, off = ranges[i]
    delta = slot - va
    boundary = delta + 4
    second = 5 if gap else 4
    pieces = [(va, boundary, off), (slot + second, 8 - second, len(data))]
    data.extend(data[off + delta + second:off + delta + 8])
    if delta + 8 < length:
        pieces.append((slot + 8, length - delta - 8, off + delta + 8))
    ranges[i:i + 1] = pieces
    return replace_ranges(data, layout, ranges)


def replace_ranges(data, layout, ranges):
    table = struct.pack("<I", len(ranges)) + b"".join(struct.pack("<QII", *r) for r in ranges)
    struct.pack_into("<II", data, layout.streams[5][0] + 4, len(table), len(data))
    data.extend(table)
    return data


def field_coverage(layout, address, length, fragments):
    data = bytearray(layout.data)
    ranges = []
    for va, size, offset in layout.ranges:
        end = va + size
        if end <= address or va >= address + length:
            ranges.append((va, size, offset))
            continue
        if va < address:
            ranges.append((va, address - va, offset))
        if end > address + length:
            ranges.append((address + length, end - address - length, offset + address + length - va))
    for delta, raw in fragments:
        assert raw and 0 <= delta <= length - len(raw)
        ranges.append((address + delta, len(raw), len(data)))
        data.extend(raw)
    return replace_ranges(data, layout, ranges)


def declaration_fields(pe, slot):
    nt, = struct.unpack_from("<I", pe, 60)
    count, = struct.unpack_from("<H", pe, nt + 6)
    opt_size, = struct.unpack_from("<H", pe, nt + 20)
    sections = [struct.unpack_from("<IIII", pe, nt + 24 + opt_size + 40 * i + 8) for i in range(count)]

    def file_offset(rva):
        off, = [raw + rva - start for vs, start, size, raw in sections if start <= rva < start + min(size, vs)]
        return off

    def end_of_name(rva):
        return pe.index(0, file_offset(rva)) + 1 - file_offset(rva)

    imports, size = struct.unpack_from("<II", pe, nt + 24 + 112 + 8)
    for step in range(0, size - 19, 20):
        descriptor = imports + step
        lookup, _, _, module, first = struct.unpack_from("<IIIII", pe, file_offset(descriptor))
        if not first:
            break
        for i in range(0, 1 << 17, 8):
            cell = (lookup or first) + i
            symbol, = struct.unpack_from("<Q", pe, file_offset(cell))
            if not symbol:
                break
            if first + i != slot:
                continue
            fields = [("import_descriptor", descriptor, 20), ("dll_name", module, end_of_name(module)), ("lookup_cell", cell, 8)]
            if not symbol >> 63:
                fields.append(("hint_and_name", symbol, 2 + end_of_name(symbol + 2)))
            return {name: (rva, file_offset(rva), length) for name, rva, length in fields}
    raise AssertionError("owned slot missing from reference import table")


def verify_declaration(report, layout, pe, own, name, pin, check):
    proof = report["declaration_check"]
    check(proof["claim"] == "saved_declaration_bytes_match_reference" and
          (proof["expected_dump_sha256"], proof["expected_reference_sha256"], proof["export"]) == (pin, digest(pe), name),
          "declaration claim and independently supplied inputs")
    specs = declaration_fields(pe, own["slot"])
    _, start, length = specs["dll_name"]
    module = pe[start:start + length - 1].decode("ascii")
    function, ordinal = None, None
    if "hint_and_name" in specs:
        _, start, length = specs["hint_and_name"]
        function = pe[start + 2:start + length - 1].decode("ascii")
    else:
        ordinal = str(struct.unpack_from("<H", pe, specs["lookup_cell"][1])[0])
    _, base, _, _, _, basename = layout.modules[int(proof["module_list_index"])]
    check(basename == "iat-test.dll" and int(proof["iat_slot_rva"]) == own["slot"] and
          (proof["reference_module"], proof["reference_import_name"], proof["reference_ordinal"]) ==
          (module, function, ordinal), "PE declaration and importing image")
    check(int(proof["instruction_rva"]) == own["rva"] and
          layout.receipt(proof["instruction_file_spans"], base + own["rva"], 6).hex() == own["code"], "bound original instruction")
    rows = proof["declaration_fields"]
    check([row["field"] for row in rows] == list(specs), "complete named or ordinal declaration")
    def coverage(states):
        return dict(requested_bytes=len(states), captured_bytes=states.count("matched") + states.count("different"),
                    matched_bytes=states.count("matched"), different_bytes=states.count("different"),
                    missing_bytes=states.count("not_retained"), excluded_bytes=states.count("loaded_iat"), read_error_bytes=0)
    by_rva = {}
    reference_offsets = set()
    field_bytes = 0
    for row in rows:
        rva, offset, length = specs[row["field"]]
        expected = pe[offset:offset + length]
        check((int(row["rva"]), int(row["reference_file_offset"]), row["reference_field_sha256"]) ==
              (rva, offset, digest(expected)), "reference file range and digest")
        states = []
        for i, ref_byte in enumerate(expected):
            address = base + rva + i
            saved = [off + address - va for va, n, off in layout.ranges if va <= address < va + n]
            assert len(saved) <= 1
            if own["slot"] <= rva + i < own["slot"] + 8:
                state = "loaded_iat"
            elif saved:
                state = "matched" if layout.data[saved[0]] == ref_byte else "different"
            else:
                state = "not_retained"
            states.append(state)
            assert by_rva.setdefault(rva + i, state) == state
            reference_offsets.add(offset + i)
        position = 0
        for span in row["declaration_spans"]:
            start, count = int(span["field_offset"]), int(span["bytes"])
            assert start == position and 0 < count <= length - start
            assert all(state == span["state"] for state in states[start:start + count])
            if span["state"] in ("matched", "different"):
                raw = layout.receipt([span], base + rva + start, count)
                assert digest(raw) == span["captured_sha256"]
            else:
                assert not {"range_index", "file_offset", "captured_sha256"}.intersection(span)
            position += count
        check(position == length, "field spans partition the original request")
        check({k: int(v) for k, v in row["coverage"].items()} == coverage(states), "independent byte counts")
        field_bytes += length
    total = coverage(list(by_rva.values()))
    check({k: int(v) for k, v in proof["coverage"].items()} == total and
          int(proof["field_bytes"]) == field_bytes and int(proof["unique_reference_bytes"]) == len(reference_offsets),
          "logical fields, unique image bytes and unique reference bytes")
    status = ("contradicted" if total["different_bytes"] else "unfulfilled" if
              total["missing_bytes"] or total["excluded_bytes"] else "supported")
    check(proof["status"] == status, "byte contradiction remains visible with incomplete coverage")


def exercise(exe, root, link):
    checks = 0

    def check(ok, label):
        nonlocal checks
        if not ok:
            raise AssertionError(label)
        checks += 1

    def offline(*args, code=0):
        result = subprocess.run([exe, "--offline", "!kmon", *map(str, args)], capture_output=True, timeout=90)
        check(result.returncode == code, (args[0], code, result.returncode, result.stdout[-350:], result.stderr[-350:]))
        return json.loads(result.stdout)

    check(not root.exists(), "requires a new private store")
    check(offline("init-store", root, "/acl-only", "/json")["root_acl_verified"], "verified private store")
    ref = root / "reference.dll"
    with tempfile.TemporaryDirectory(dir=root) as temp:
        fixtures = Path(temp)
        shutil.copyfile(FIXTURE["build_fixture"](link, fixtures), ref)
        observed, pid, birth = capture(root, fixtures)
    ref_pin = digest(ref.read_bytes())

    def observe(path, pin, name="FixtureTick", pe_pin=ref_pin, code=0, declaration=False):
        options = ["/declaration"] if declaration else []
        return offline("dump-image-iat", path, pin, ref, pe_pin, name, *options, "/json", code=code)

    for kind in DUMPS:
        path = root / (kind + ".dmp")
        data = path.read_bytes()
        layout = Layout(data)
        pin = digest(data)
        for name, (module, function, ordinal) in EXPORTS.items():
            report = observe(path, pin, name)
            own = observed[name]
            check(report["status"] == "observed" and report["slot_value_observed"] and report["expected_dump_sha256"] == pin and
                  report["expected_reference_sha256"] == ref_pin and report["export"] == name, "both inputs and export")
            check(report["memory_stream"] == ("Memory64ListStream" if kind == "full" else "MemoryListStream") and
                  not any(report[k] for k in ("slot_reread", "collector_authenticated", "execution_observed", "mapping_lifetime_bound")),
                  "capture scope")
            check(int(report["dump_time_unix_seconds"]) == struct.unpack_from("<I", data, 20)[0] and
                  int(report["process_id"]) == pid and int(report["process_create_unix_seconds"]) == birth, "SDK clocks and child identity")
            _, base, size, checksum, timestamp, basename = layout.modules[int(report["importer"]["module_list_index"])]
            check(basename == report["importer"]["basename"] == "iat-test.dll" and
                  (size, checksum, timestamp) == tuple(int(report["importer"][k]) for k in ("image_size", "checksum", "coff_timestamp")),
                  "original importer module row")
            lookup = base + int(report["import_lookup_rva"])
            retained = sum(any(a <= lookup + i < a + n for a, n, _ in layout.ranges) for i in range(8))
            basis = {0: "separate_lookup_reference_only", 8: "separate_lookup_matched"}.get(retained, "separate_lookup_partially_retained")
            check((report["import_module"].lower(), report["import_name"], report["import_ordinal"]) ==
                  (module.lower(), function, ordinal) and report["lookup_basis"] == basis and
                  int(report["lookup_bytes_matched"]) == retained and (kind != "full" or retained == 8), "file declaration and retained lookup")
            check(int(report["instruction_rva"]) == own["rva"] and int(report["iat_slot_rva"]) == own["slot"] and
                  layout.receipt(report["instruction_file_spans"], base + own["rva"], 6).hex() == own["code"], "original instruction spans")
            slot = layout.receipt(report["slot_file_spans"], base + own["slot"], 8)
            check(digest(slot) == report["slot_value_sha256"] == own["sha256"], "original slot and Windows loader agree")
            value, = struct.unpack("<Q", slot)
            target = report["target_module"]
            _, start, size, _, _, basename = layout.modules[int(target["module_list_index"])]
            check(start <= value < start + size and basename.lower() == target["basename"].lower() == own["owner"].lower() and
                  report["owner_status"] == "within_reported_module_extent", "module containing the resolved pointer")
            detailed = observe(path, pin, name, declaration=True)
            verify_declaration(detailed, layout, ref.read_bytes(), own, name, pin, check)
            proof = detailed.pop("declaration_check")
            check(detailed == report and (kind != "full" or proof["status"] == "supported"), "original slot preserved with independent declaration")
        if kind == "regular":
            controls(exe, root, path, layout, observe, observed["FixtureTick"], ref, ref_pin, check)
        else:
            _, table, _ = layout.streams[9]
            with tempfile.TemporaryDirectory(dir=root) as directory:
                copy = Path(directory) / "memory64.dmp"
                for at, value, reason in ((table, 1 << 48, "invalid_memory_list"),
                                          (table + 8, len(data) - 1, "invalid_memory_extent"),
                                          (table + 24, (1 << 64) - 1, "invalid_memory_extent"),
                                          (table + 32, layout.ranges[0][0], "overlapping_virtual_memory")):
                    edited = bytearray(data)
                    struct.pack_into("<Q", edited, at, value)
                    copy.write_bytes(edited)
                    failure = observe(copy, digest(edited), code=1)
                    check(failure["reason"] == reason and not failure["slot_value_observed"], "64-bit descriptor bounds")
        declaration_controls(kind, root, layout, ref.read_bytes(), observed, observe, check)
    print(f"minidump IAT: {checks} checks passed after owned target exit")


def declaration_controls(kind, root, layout, pe, observed, observe, check):
    own = observed["FixtureTick"]
    base, = [m[1] for m in layout.modules if m[-1] == "iat-test.dll"]
    specs = declaration_fields(pe, own["slot"])
    with tempfile.TemporaryDirectory(dir=root) as directory:
        path = Path(directory) / "edited.dmp"

        def replay(data, name="FixtureTick", code=0):
            pin = digest(data)
            path.write_bytes(data)
            page = observe(path, pin, name, code=code, declaration=True)
            verify_declaration(page, Layout(data), pe, observed[name], name, pin, check)
            return page

        if kind == "full":
            for name, field, index, code in (("FixtureTick", "dll_name", 0, 0), ("FixtureTick", "dll_name", -1, 0),
                                             ("FixtureTick", "hint_and_name", 0, 0), ("FixtureTick", "hint_and_name", 2, 0),
                                             ("FixtureTick", "hint_and_name", -1, 0), ("FixtureTick", "import_descriptor", 12, 1),
                                             ("FixtureOrdinal", "lookup_cell", 0, 1)):
                rva, _, length = declaration_fields(pe, observed[name]["slot"])[field]
                data = bytearray(layout.data)
                data[layout.offset(base + rva + index % length, 1)] ^= 1
                page = replay(data, name, code)
                proof = page["declaration_check"]
                check(proof["status"] == "contradicted" and proof["coverage"]["different_bytes"] == "1" and
                      page["slot_value_observed"] == (code == 0), "single changed declaration byte and independent slot evidence")
            return

        # These disposable sparse files exercise coverage combinations independent
        # of which optional pages the host's copy of DbgHelp selected.
        complete = layout.data
        for rva, offset, length in specs.values():
            complete = field_coverage(Layout(complete), base + rva, length, [(0, pe[offset:offset + length])])
        gap = replay(split_slot(Layout(complete), base + own["slot"], True), code=1)
        check(gap["reason"] == "slot_bytes_unavailable" and gap["declaration_check"]["status"] == "supported",
              "missing loaded slot does not erase a complete declaration")
        rva, offset, length = specs["dll_name"]
        raw = pe[offset:offset + length]
        partial = field_coverage(Layout(complete), base + rva, length, [(length - 1, raw[-1:]), (0, raw[:4])])
        proof = replay(partial)["declaration_check"]
        check(proof["status"] == "unfulfilled" and int(proof["coverage"]["missing_bytes"]) == length - 5, "interior gap with retained terminator")
        different = field_coverage(Layout(complete), base + rva, length, [(length - 1, b"!"), (0, raw[:4])])
        proof = replay(different)["declaration_check"]
        check(proof["status"] == "contradicted" and proof["coverage"]["different_bytes"] == "1" and
              int(proof["coverage"]["missing_bytes"]) == length - 5, "contradiction alongside an interior gap")
        divided = field_coverage(Layout(complete), base + rva, length, [(4, raw[4:]), (0, raw[:4])])
        proof = replay(divided)["declaration_check"]
        dll, = [field for field in proof["declaration_fields"] if field["field"] == "dll_name"]
        check(proof["status"] == "supported" and len(dll["declaration_spans"]) == 2, "logical bytes from discontiguous dump offsets")


def controls(exe, root, path, layout, observe, own, ref, ref_pin, check):
    original = layout.data
    pin = digest(original)
    report = observe(path, pin)
    idx = int(report["importer"]["module_list_index"])
    row, base, _, _, _, _ = layout.modules[idx]
    slot = base + own["slot"]
    source_offset = layout.offset(slot, 8)

    def denied(page, reason):
        check(page["status"] == "unavailable" and page["reason"] == reason and not page["slot_value_observed"] and
              "slot_file_spans" not in page and "target_module" not in page, reason)

    denied(observe(path, "0" * 64, code=1), "dump_pin_unavailable")
    denied(observe(path, pin, pe_pin="0" * 64, code=1), "reference_pin_unavailable")
    for name in ("FixtureForward", "fixturetick", "Absent"):
        denied(observe(path, pin, name, code=1), "export_instruction_unavailable")
    denied(observe(path, pin, "FixtureAnchor", code=1), "unsupported_export_instruction")
    for dump_pin, pe_digest, name, reason in (("0" * 64, ref_pin, "FixtureTick", "dump_pin_unavailable"),
                                               (pin, "0" * 64, "FixtureTick", "reference_pin_unavailable"),
                                               (pin, ref_pin, "FixtureForward", "export_instruction_unavailable")):
        proof = observe(path, dump_pin, name, pe_digest, code=1, declaration=True)["declaration_check"]
        check(proof["status"] == "unfulfilled" and proof["reason"] == reason and
              "coverage" not in proof and "declaration_fields" not in proof, "qualification before field comparison")
    with tempfile.TemporaryDirectory(dir=root) as directory:
        scratch = Path(directory) / "control.dmp"

        def changed(data, code):
            scratch.write_bytes(data)
            return observe(scratch, digest(data), code=code)

        def patch(reason, at, replacement):
            data = bytearray(original)
            data[at:at + len(replacement)] = replacement
            denied(changed(data, 1), reason)

        for value, owner in ((0, "null_slot"), (1, "outside_reported_modules")):
            data = bytearray(original)
            struct.pack_into("<Q", data, source_offset, value)
            found = changed(data, 0)
            check(found["slot_value_observed"] and found["owner_status"] == owner and found["target_module"] is None and
                  found["slot_value_sha256"] == digest(struct.pack("<Q", value)), "known cell with unavailable owner")
        divided = split_slot(layout, slot, False)
        found = changed(divided, 0)
        check(len(found["slot_file_spans"]) == 2 and
              digest(Layout(divided).receipt(found["slot_file_spans"], slot, 8)) == own["sha256"], "discontiguous file spans")
        denied(changed(split_slot(layout, slot, True), 1), "slot_bytes_unavailable")
        for key, reason in (("instruction_rva", "instruction_bytes_unqualified"),
                            ("import_descriptor_rva", "captured_import_descriptor_unqualified")):
            at = layout.offset(base + int(report[key]), 1)
            patch(reason, at, bytes([original[at] ^ 1]))
        lookup = base + int(report["import_lookup_rva"])
        full = Layout((root / "full.dmp").read_bytes())
        at = full.offset(lookup, 8)
        raw = full.data[at:at + 8]
        for n, basis in ((0, "separate_lookup_reference_only"), (3, "separate_lookup_partially_retained"), (8, "separate_lookup_matched")):
            page = changed(field_coverage(layout, lookup, 8, [(0, raw[:n])] if n else []), 0)
            check(page["lookup_basis"] == basis and int(page["lookup_bytes_matched"]) == n, "actual separate lookup coverage")
        denied(changed(field_coverage(layout, lookup, 8, [(0, bytes([raw[0] ^ 1]))]), 1), "captured_import_lookup_unqualified")
        pe = bytearray(ref.read_bytes())
        nt, = struct.unpack_from("<I", pe, 60)
        sections, = struct.unpack_from("<H", pe, nt + 6)
        optional_size, = struct.unpack_from("<H", pe, nt + 20)
        descriptor = int(report["import_descriptor_rva"])
        for i in range(sections):
            start = nt + 24 + optional_size + i * 40
            length, rva, _, offset = struct.unpack_from("<IIII", pe, start + 8)
            if rva <= descriptor < rva + length:
                struct.pack_into("<I", pe, offset + descriptor - rva, 0)
                break
        else:
            raise AssertionError("fixture descriptor section")
        shared_ref = Path(directory) / "shared-reference.dll"
        shared_ref.write_bytes(pe)
        shared = bytearray(original)
        struct.pack_into("<I", shared, layout.offset(base + descriptor, 4), 0)
        scratch.write_bytes(shared)
        result = subprocess.run([str(exe), "--offline", "!kmon", "dump-image-iat", str(scratch), digest(shared),
                                 str(shared_ref), digest(pe), "FixtureTick", "/declaration", "/json"], capture_output=True, timeout=60)
        shared_result = json.loads(result.stdout)
        check(result.returncode == 0 and shared_result["lookup_basis"] == "shared_iat_reference_only" and
              shared_result["lookup_bytes_matched"] == "0" and shared_result["slot_value_sha256"] == own["sha256"],
              "shared IAT preserves file declaration and independently observed slot")
        verify_declaration(shared_result, Layout(shared), pe, own, "FixtureTick", digest(shared), check)
        proof = shared_result["declaration_check"]
        check(proof["reason"] == "lookup_replaced_by_loader" and proof["coverage"]["excluded_bytes"] == "8",
              "loader-replaced lookup stays outside the byte comparison")
        pe = bytearray(ref.read_bytes())
        alias = bytearray(original)
        specs = declaration_fields(pe, own["slot"])
        target = specs["hint_and_name"][0] + 2
        struct.pack_into("<I", pe, specs["import_descriptor"][1] + 12, target)
        struct.pack_into("<I", alias, layout.offset(base + descriptor + 12, 4), target)
        shared_ref.write_bytes(pe)
        scratch.write_bytes(alias)
        result = subprocess.run([str(exe), "--offline", "!kmon", "dump-image-iat", str(scratch), digest(alias),
                                 str(shared_ref), digest(pe), "FixtureTick", "/declaration", "/json"], capture_output=True, timeout=60)
        proof = json.loads(result.stdout)["declaration_check"]
        check(result.returncode == 0 and int(proof["field_bytes"]) - int(proof["coverage"]["requested_bytes"]) ==
              len(proof["reference_module"]) + 1, "pooled names share one byte denominator")
        verify_declaration(json.loads(result.stdout), Layout(alias), pe, own, "FixtureTick", digest(alias), check)
        patch("captured_importer_identity_unqualified", layout.offset(base, 1), b"Z")
        patch("captured_image_directories_unqualified", layout.offset(base + nt + 24 + 112 + 8, 8), bytes(8))
        _, cv = struct.unpack_from("<II", original, row + 76)
        patch("importing_build_missing", cv + 4, bytes([original[cv + 4] ^ 1]))
        source_dir, table, _ = layout.streams[5]
        first, second = table + 4, table + 20
        patch("overlapping_virtual_memory", second, original[first:first + 8])
        patch("aliased_memory_payload", second + 12, original[first + 12:first + 16])
        patch("metadata_in_memory_payload", first + 12, struct.pack("<I", 0))
        patch("invalid_memory_extent", first + 12, struct.pack("<I", len(original)))
        patch("invalid_memory_list", table, struct.pack("<I", 0xffffffff))
        patch("duplicate_stream", layout.streams[0][0], struct.pack("<I", 5))
        patch("ambiguous_memory_stream", layout.streams[0][0], struct.pack("<I", 9))
        patch("memory_stream_missing", source_dir, struct.pack("<I", 0))
        patch("amd64_system_info_unavailable", layout.streams[7][1], struct.pack("<H", 0))
        patch("overlapping_streams", source_dir + 8, struct.pack("<I", 0))
        patch("overlapping_module_metadata", row + 80, struct.pack("<I", 0))
        patch("invalid_module_list", row + 20, struct.pack("<I", len(original)))
        other, = [m for m in layout.modules if m[5].lower() == "ntdll.dll"]
        patch("overlapping_module_extents", other[0], struct.pack("<Q", base))
        duplicate = bytearray(original)
        duplicate[other[0] + 8:other[0] + 20] = original[row + 8:row + 20]
        cv_size, cv = struct.unpack_from("<II", original, row + 76)
        struct.pack_into("<II", duplicate, other[0] + 76, cv_size, len(duplicate))
        duplicate.extend(original[cv:cv + cv_size])
        denied(changed(duplicate, 1), "ambiguous_importing_module")
        misc = bytearray(original)
        struct.pack_into("<I", misc, layout.streams[15][1] + 4, 0)
        found = changed(misc, 0)
        check(found["process_id"] is None and found["process_create_unix_seconds"] is None, "unreported process metadata")
        cmd = [str(exe), "--offline", "!kmon", "dump-image-iat", str(path), pin, str(ref), ref_pin, "FixtureTick", "/json"]
        for n, evidence in enumerate((path, ref)):
            alias = Path(directory) / ("alias" + str(n))
            os.link(evidence, alias)
            before = digest(evidence.read_bytes())
            for channel, args in (("stdout", cmd), ("stderr", cmd + ["surplus"]), ("stdout", cmd + ["--mode", "offline"]),
                                  ("stdout", [*cmd[:-1], "/declaration", "/json"]),
                                  ("stderr", [*cmd[:-1], "/declaration", "/declaration"])):
                with alias.open("r+b") as stream:
                    result = subprocess.run(args, timeout=30, **{channel: stream,
                                            ("stderr" if channel == "stdout" else "stdout"): subprocess.PIPE})
                check(result.returncode != 0 and digest(evidence.read_bytes()) == before, "redirected evidence preserved")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path)
    parser.add_argument("--link", default="link.exe", help="x64 MSVC linker, with Windows SDK LIB set")
    parser.add_argument("--root", type=Path, help="retain original dumps and reference in a new private store")
    parser.add_argument("--actor", type=Path, help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.actor:
        actor(options.actor)
    elif options.exe:
        link = shutil.which(options.link)
        if not link:
            parser.error("x64 MSVC link.exe is required")
        with tempfile.TemporaryDirectory(prefix="owned-minidump-iat-") as work:
            exercise(options.exe.resolve(strict=True), options.root.resolve() if options.root else Path(work) / "store", link)
    else:
        parser.error("--exe is required")
