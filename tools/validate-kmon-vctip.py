"""Read-only PE32 System.Data view snapshots and an offline KMON coverage gate.

Use 64-bit Python on Windows for snapshot. No target memory is written or executed.
The PE32/HIGHLOW-only parser deliberately rejects other image formats. Snapshots
are bounded observations, not an atomic attestation of an entire process.
"""
import argparse
import ctypes as c
import ctypes.wintypes as w
import datetime
import hashlib
import json
import pathlib
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8-sig"))


class Pe32:
    def __init__(self, data):
        require(64 <= len(data) <= 64 * 1024 * 1024 and data[:2] == b"MZ", "Invalid PE file size/signature")
        nt = struct.unpack_from("<I", data, 60)[0]
        require(nt + 24 <= len(data) and data[nt:nt + 4] == b"PE\0\0", "Invalid NT header")
        count, optional_size = struct.unpack_from("<H", data, nt + 6)[0], struct.unpack_from("<H", data, nt + 20)[0]
        opt = nt + 24
        require(0 < count <= 96 and optional_size >= 224 and opt + optional_size + count * 40 <= len(data), "Invalid header bounds")
        require(struct.unpack_from("<H", data, opt)[0] == 267, "Expected PE32 System.Data.dll")
        self.base_offset = opt + 28
        self.preferred = struct.unpack_from("<I", data, self.base_offset)[0]
        self.size, headers = struct.unpack_from("<II", data, opt + 56)
        require(0 < headers <= self.size <= 64 * 1024 * 1024 and headers <= len(data), "Invalid image bounds")
        directory_count = struct.unpack_from("<I", data, opt + 92)[0]
        require(13 <= directory_count <= 16, "Missing relocation/IAT directories")
        self.mapped = bytearray(self.size)
        self.mapped[:headers] = data[:headers]
        self.sections = []
        for i in range(count):
            off = opt + optional_size + i * 40
            vs, va, rs, raw = struct.unpack_from("<IIII", data, off + 8)
            flags = struct.unpack_from("<I", data, off + 36)[0]
            length = max(vs, rs)
            require(headers <= va and va + length <= self.size and raw + rs <= len(data), "Invalid section bounds")
            require(all(va + length <= s["rva"] or s["rva"] + s["size"] <= va for s in self.sections), "Overlapping sections")
            self.mapped[va:va + rs] = data[raw:raw + rs]
            self.sections.append({"rva": va, "size": length, "executable": bool(flags & 0x20000000)})
        require(any(s["executable"] and s["size"] for s in self.sections), "No executable section")
        self.slots = []
        rr, length = struct.unpack_from("<II", data, opt + 96 + 5 * 8)
        require(rr > 0 and length > 0 and rr + length <= self.size, "Missing/invalid relocations")
        cursor, end = rr, rr + length
        while cursor < end:
            require(cursor + 8 <= end, "Truncated relocation block")
            page, block = struct.unpack_from("<II", self.mapped, cursor)
            require(block >= 8 and block % 2 == 0 and cursor + block <= end, "Invalid relocation block")
            for off in range(cursor + 8, cursor + block, 2):
                token = struct.unpack_from("<H", self.mapped, off)[0]
                if token >> 12 == 0:
                    continue
                rva = page + (token & 4095)
                require(token >> 12 == 3 and rva + 4 <= self.size, "Unsupported relocation")
                self.slots.append(rva)
            cursor += block
        self.slots.sort()
        require(all(a + 4 <= b for a, b in zip(self.slots, self.slots[1:])), "Overlapping relocations")

    def normalized(self, base):
        result = bytearray(self.mapped)
        for rva in self.slots:
            value = struct.unpack_from("<I", self.mapped, rva)[0]
            struct.pack_into("<I", result, rva, (value + base - self.preferred) & 0xffffffff)
        return result


class Windows:
    class Mbi(c.Structure):
        _fields_ = [("base", c.c_uint64), ("allocation", c.c_uint64), ("allocation_protect", w.DWORD),
                    ("partition", w.WORD), ("size", c.c_uint64), ("state", w.DWORD),
                    ("protect", w.DWORD), ("type", w.DWORD)]

    def __init__(self):
        require(c.sizeof(c.c_void_p) == 8, "Use 64-bit Python")
        self.k = c.WinDLL("kernel32", use_last_error=True)
        self.p = c.WinDLL("psapi", use_last_error=True)
        for name, result, args in [
            ("OpenProcess", w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
            ("CloseHandle", w.BOOL, [w.HANDLE]),
            ("GetProcessTimes", w.BOOL, [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4),
            ("GetExitCodeProcess", w.BOOL, [w.HANDLE, c.POINTER(w.DWORD)]),
            ("QueryFullProcessImageNameW", w.BOOL, [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]),
            ("VirtualQueryEx", c.c_size_t, [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t]),
            ("ReadProcessMemory", w.BOOL, [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]),
            ("CreateFileW", w.HANDLE, [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]),
            ("QueryDosDeviceW", w.DWORD, [w.LPCWSTR, w.LPWSTR, w.DWORD]),
        ]:
            fn = getattr(self.k, name)
            fn.restype, fn.argtypes = result, args
        self.p.GetMappedFileNameW.restype = w.DWORD
        self.p.GetMappedFileNameW.argtypes = [w.HANDLE, c.c_void_p, w.LPWSTR, w.DWORD]

    def read(self, process, base, size, allocation):
        data = bytearray()
        for offset in range(0, size, 4096):
            address, length = base + offset, min(4096, size - offset)
            before, after = self.Mbi(), self.Mbi()
            require(self.k.VirtualQueryEx(process, address, c.byref(before), c.sizeof(before)) == c.sizeof(before), "Query failed")
            require(before.allocation == allocation and before.type == 0x1000000 and before.state == 0x1000 and
                    not (before.protect & 0x101) and before.base <= address and address + length <= before.base + before.size,
                    "Mapping changed or unreadable")
            pair = []
            for _ in range(2):
                buffer, got = c.create_string_buffer(length), c.c_size_t()
                require(self.k.ReadProcessMemory(process, address, buffer, length, c.byref(got)) and got.value == length, "Read failed")
                pair.append(buffer.raw)
            require(pair[0] == pair[1], "Unstable bytes")
            require(self.k.VirtualQueryEx(process, address, c.byref(after), c.sizeof(after)) == c.sizeof(after) and
                    bytes(before) == bytes(after), "Mapping changed during read")
            data.extend(pair[0])
        return bytes(data)


def snapshot(args):
    api = Windows()
    root = pathlib.Path(args.out)
    root.mkdir(parents=True, exist_ok=False)
    reference = pathlib.Path(args.reference).resolve(strict=True)
    # Deny concurrent replacement/writes while parsing and reading the target.
    file = api.k.CreateFileW(str(reference), 0x80000000, 1, None, 3, 0, None)
    require(file not in (None, c.c_void_p(-1).value), "Cannot lock reference file")
    process = None
    try:
        disk = reference.read_bytes()
        pe = Pe32(disk)
        process = api.k.OpenProcess(0x410, False, args.pid)
        require(process, "Cannot open target")
        times = [w.FILETIME() for _ in range(4)]
        require(api.k.GetProcessTimes(process, *[c.byref(x) for x in times]), "Cannot identify process")
        creation = times[0].dwLowDateTime + (times[0].dwHighDateTime << 32)
        name, length = c.create_unicode_buffer(32768), w.DWORD(32768)
        require(api.k.QueryFullProcessImageNameW(process, 0, name, c.byref(length)), "Cannot identify executable")
        require(pathlib.Path(name.value).name.lower() == "vctip.exe", "Expected the actual vctip process")
        device = c.create_unicode_buffer(32768)
        require(api.k.QueryDosDeviceW(reference.drive, device, 32768), "Cannot resolve reference volume")
        mapped_name = device.value + str(reference)[len(reference.drive):]
        views, seen, address = [], set(), 0
        while True:
            row = api.Mbi()
            if not api.k.VirtualQueryEx(process, address, c.byref(row), c.sizeof(row)):
                require(c.get_last_error() == 87, "Incomplete address traversal")
                break
            if row.type == 0x1000000 and row.allocation not in seen:
                seen.add(row.allocation)
                mapped = c.create_unicode_buffer(32768)
                if api.p.GetMappedFileNameW(process, row.allocation, mapped, 32768) and mapped.value.lower() == mapped_name.lower():
                    views.append({"base": row.allocation, "name": mapped.value})
            require(row.base + row.size > address, "Nonadvancing memory query")
            address = row.base + row.size
        require(len(views) == 2, "Expected both real System.Data image views")
        for view in views:
            base = view["base"]
            header = api.read(process, base, 4096, base)
            require(pe.base_offset + 4 <= len(header), "Header outside first page")
            header_base = struct.unpack_from("<I", header, pe.base_offset)[0]
            # Identity fields and section table must be identical except ImageBase.
            expected_header = bytearray(disk[:min(4096, len(disk))])
            struct.pack_into("<I", expected_header, pe.base_offset, header_base)
            header_size = struct.unpack_from("<I", pe.mapped, pe.base_offset + 32)[0]
            require(0 < header_size <= 4096 and header[:header_size] == expected_header[:header_size], "PE header identity changed")
            expected = pe.normalized(header_base)
            view.update(header_base=header_base, secondary=base != header_base and header_base != pe.preferred, sections=[])
            for section in pe.sections:
                if not section["executable"]:
                    continue
                rva, size = section["rva"], section["size"]
                observed = api.read(process, base + rva, size, base)
                wanted = bytes(expected[rva:rva + size])
                stem = f"{base:x}-{rva:x}"
                (root / (stem + "-observed.bin")).write_bytes(observed)
                (root / (stem + "-expected.bin")).write_bytes(wanted)
                view["sections"].append({**section, "observed_sha256": sha(observed), "expected_sha256": sha(wanted),
                    "different_bytes": sum(a != b for a, b in zip(observed, wanted)),
                    "relocation_slots": sum(rva <= x < rva + size for x in pe.slots)})
            require(api.read(process, base, 4096, base) == header, "Header changed during snapshot")
        secondary = [v for v in views if v["secondary"]]
        require(len(secondary) == 1 and any(v["base"] == v["header_base"] == secondary[0]["header_base"] for v in views), "Relocation pair is ambiguous")
        code = w.DWORD()
        require(api.k.GetExitCodeProcess(process, c.byref(code)) and code.value == 259, "Process exited")
        report = {"pid": args.pid, "creation_filetime": creation, "process_image": name.value,
                  "process_sha256": sha(pathlib.Path(name.value).read_bytes()), "reference": str(reference),
                  "file_sha256": sha(disk), "preferred_base": pe.preferred, "views": views,
                  "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        (root / "snapshot.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps({"pid": args.pid, "views": views}))
    finally:
        if process:
            api.k.CloseHandle(process)
        api.k.CloseHandle(file)


def audit(args):
    root = pathlib.Path(args.run)
    before, after = load(args.before), load(args.after)
    require(len(before["views"]) == 2 and sum(v["secondary"] for v in before["views"]) == 1,
            "Missing real secondary/loader view pair")
    secondary = next(v for v in before["views"] if v["secondary"])
    require(secondary["base"] != secondary["header_base"] != before["preferred_base"] and
            any(v["base"] == v["header_base"] == secondary["header_base"] and not v["secondary"] for v in before["views"]),
            "Invalid secondary/loader relocation pair")
    require(all(v["sections"] and all(s["executable"] and s["size"] > 0 for s in v["sections"]) for v in before["views"]),
            "Missing executable comparison range")
    require(pathlib.Path(before["process_image"]).name.lower() == "vctip.exe" and
            pathlib.Path(before["reference"]).name.lower() == "system.data.dll", "Unexpected observation target")
    for field in ("pid", "creation_filetime", "file_sha256", "preferred_base", "process_image"):
        require(before[field] == after[field], "Process/reference identity changed: " + field)
    require(before["views"] == after["views"], "View bytes or relocation basis changed between snapshots")
    for snapshot_path, report in ((args.before, before), (args.after, after)):
        for view in report["views"]:
            for section in view["sections"]:
                stem = f'{view["base"]:x}-{section["rva"]:x}'
                for role in ("observed", "expected"):
                    data = pathlib.Path(snapshot_path).parent.joinpath(stem + f"-{role}.bin").read_bytes()
                    require(len(data) == section["size"] and sha(data) == section[role + "_sha256"], "Snapshot bytes/hash mismatch")
                require(section["different_bytes"] == 0 and section["observed_sha256"] == section["expected_sha256"], "Independent snapshot differs")
    results = {v["base"]: {"base": v["base"], "secondary": v["secondary"], "completed_cycles": 0,
               "requested_bytes": sum(s["size"] for s in v["sections"]), "code_findings": 0, "gap_reasons": {}} for v in before["views"]}
    target_findings, pipeline = [], {}
    for file in sorted(root.glob("kmon-events.*.jsonl")):
        with file.open(encoding="utf-8-sig") as source:
            for line in source:
                if f'"pid":{before["pid"]},' not in line and '"kind":"coverage.pipeline"' not in line:
                    continue
                event = json.loads(line)
                ev = event.get("evidence", {})
                if event["kind"] == "coverage.pipeline":
                    pipeline = ev
                    continue
                if event["kind"] in ("finding.code_modified", "finding.layout_image_identity"):
                    target_findings.append(event)
                result = results.get(int(ev.get("image_base", 0)))
                if result is None:
                    continue
                view = next(v for v in before["views"] if v["base"] == result["base"])
                paths = [view["name"], "\\\\?\\GLOBALROOT" + view["name"], before["reference"], "\\\\?\\" + before["reference"]]
                if event["image"].lower() not in [p.lower() for p in paths]:
                    continue
                require(int(ev["process_create_time"]) == before["creation_filetime"], "KMON process generation mismatch")
                if event["kind"] in ("finding.code_modified", "finding.layout_image_identity"):
                    result["code_findings"] += 1
                if event["kind"] != "coverage.image":
                    continue
                if event["summary"] != "cycle_complete":
                    reason = event["summary"]
                    result["gap_reasons"][reason] = result["gap_reasons"].get(reason, 0) + 1
                    continue
                require(int(ev["relocation_base"]) == view["header_base"] and ev["relocation_basis"] ==
                        ("independent_sec_image_no_execute" if view["secondary"] else "mapping_base"), "Wrong KMON relocation basis")
                require(int(ev["compared_bytes"]) == int(ev["requested_bytes"]) == result["requested_bytes"] and
                        int(ev["failed_bytes"]) == int(ev["skipped_bytes"]) == int(ev["remaining_pages"]) == 0, "Incomplete executable traversal")
                result["completed_cycles"] += 1
                result["compared_bytes"] = int(ev["compared_bytes"])
    validation = load(root / "validation.json")
    require(any(int(p["pid"]) == before["pid"] and int(p["creation_filetime"]) == before["creation_filetime"]
                for p in validation["observed_processes"]), "Target was not held through the KMON run")
    passed = all(validation[k] for k in ("passed", "all_process_scope_verified", "queue_health_passed",
        "completed_work_passed", "fresh_layouts_passed", "layout_name_accounting_passed", "same_boot")) and all(
        r["completed_cycles"] > 0 and r["code_findings"] == 0 and not r["gap_reasons"] for r in results.values())
    report = {"passed": passed, "pid": before["pid"], "creation_filetime": before["creation_filetime"],
              "binary_sha256": validation["binary_sha256"], "views": list(results.values()),
              "target_findings": target_findings, "pipeline": pipeline,
              "claim": "bounded System.Data observations and fixture controls; unrelated findings need separate review"}
    (root / "vctip-validation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("passed", "pid", "views")}))
    require(passed, "Actual vctip image coverage gate failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snap = commands.add_parser("snapshot")
    snap.add_argument("--pid", type=int, required=True)
    snap.add_argument("--out", required=True)
    snap.add_argument("--reference", default=r"C:\Windows\Microsoft.NET\assembly\GAC_32\System.Data\v4.0_4.0.0.0__b77a5c561934e089\System.Data.dll")
    check = commands.add_parser("audit")
    check.add_argument("--run", required=True)
    check.add_argument("--before", required=True)
    check.add_argument("--after", required=True)
    arguments = parser.parse_args()
    (snapshot if arguments.command == "snapshot" else audit)(arguments)
