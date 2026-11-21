"""Read the raw merged ImageID events exported by Windows tracerpt on single-logger fixtures."""
from collections import Counter, defaultdict
import hashlib
import struct
import uuid

PROVIDER = "b3e675d7-2554-4f18-830b-2762732560de"
ROLES = {0: "image_id", 32: "no_debug_id", 36: "native_rsds"}


def key(point):
    return point["raw_timestamp"], point["payload_pid"], point["image_base"]


def reference_build(reference):
    data = reference.data
    pe, = struct.unpack_from("<I", data, 60)
    directory = pe + 24 + (96 if reference.source["optional_magic"] == 0x10b else 112)
    declared, = struct.unpack_from("<I", data, directory - 4)
    rva, size = struct.unpack_from("<II", data, directory + 8 * 6) if declared > 6 else (0, 0)

    def raw(address, length):
        if 0 < address < reference.headers and length <= reference.headers - address:
            return address
        for start, virtual, raw_size, offset, _ in reference.sections:
            span = min(virtual, raw_size)
            if start <= address < start + span and address + length <= start + span:
                return offset + address - start
        return None

    result = dict(status="missing_codeview", rsds_guid=None, pdb_age=None)
    if not size and not rva:
        return result
    directory = raw(rva, size)
    if directory is None or not 0 < size <= 28 * 1024 or size % 28 or directory + size > len(data):
        return dict(result, status="invalid_debug_directory")
    entries = [v for v in struct.iter_unpack("<IIHHIIII", data[directory:directory + size]) if v[4] == 2]
    if len(entries) != 1:
        return dict(result, status="multiple_codeview_records" if entries else "missing_codeview")
    length, address, off = entries[0][-3:]
    if not 4 <= length <= 65536 or not off or off + length > len(data) or (address and raw(address, length) != off):
        return dict(result, status="invalid_codeview")
    cv = data[off:off + length]
    if cv[:4] != b"RSDS":
        return dict(result, status="unsupported_codeview")
    if len(cv) < 25 or not cv.endswith(b"\0") or cv[24:].partition(b"\0")[2].strip(b"\0"):
        return dict(result, status="invalid_codeview")
    guid = uuid.UUID(bytes_le=cv[4:20])
    age, = struct.unpack_from("<I", cv, 20)
    return dict(status="unique_rsds", rsds_guid=str(guid), pdb_age=age) if guid.int else dict(result, status="empty_debug_id")


def check_reference_layouts(exe, etl, pin, folder, run):
    """Only metadata and a read-only data section; these fixture files are never loaded."""
    expected_guid = uuid.UUID("10203040-5060-7080-90a0-b0c0d0e0f001")
    cv = b"RSDS" + expected_guid.bytes_le + struct.pack("<I", 0xffffffff) + b"layout-only.pdb\0"
    for width in (4, 8):
        nt = 0x80
        opt = nt + 24
        opt_size = 224 if width == 4 else 240
        prefix = 96 if width == 4 else 112
        debug = opt + prefix + 6 * 8
        buf = bytearray(0x700)
        buf[:2] = b"MZ"
        struct.pack_into("<I", buf, 60, nt)
        buf[nt:nt + 4] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", buf, nt + 4, 0x14c if width == 4 else 0x8664, 1, 1, 0, 0, opt_size, 2)
        struct.pack_into("<H", buf, opt, 0x10b if width == 4 else 0x20b)
        struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
        struct.pack_into("<II", buf, opt + 56, 0x2000, 0x200)
        struct.pack_into("<I", buf, opt + prefix - 4, 16)
        struct.pack_into("<II", buf, debug, 0x1000, 28)
        sec = opt + opt_size
        buf[sec:sec + 6] = b".rdata"
        struct.pack_into("<4I", buf, sec + 8, 0x400, 0x1000, 0x400, 0x200)
        struct.pack_into("<I", buf, sec + 36, 0x40000040)
        struct.pack_into("<4I", buf, 0x20c, 2, len(cv), 0x1100, 0x300)
        buf[0x300:0x300 + len(cv)] = cv
        buf[0x600:0x600 + len(cv)] = cv
        cases = [
            ("mapped", [], "unique_rsds"),
            ("overlay", [(0x214, struct.pack("<II", 0, 0x600))], "unique_rsds"),
            ("absent", [(debug, bytes(8))], "missing_codeview"),
            ("undeclared", [(opt + prefix - 4, struct.pack("<I", 6))], "missing_codeview"),
            ("no-cv", [(0x20c, struct.pack("<I", 16))], "missing_codeview"),
            ("duplicate", [(0x21c, buf[0x200:0x21c]), (debug + 4, struct.pack("<I", 56))], "multiple_codeview_records"),
            ("short-directory", [(debug + 4, struct.pack("<I", 27))], "invalid_debug_directory"),
            ("directory-span", [(debug, struct.pack("<I", 0x13ff))], "invalid_debug_directory"),
            ("virtual-tail", [(sec + 8, struct.pack("<I", 0x80))], "invalid_codeview"),
            ("inconsistent-pointers", [(0x218, struct.pack("<I", 0x310))], "invalid_codeview"),
            ("raw-past-eof", [(0x214, struct.pack("<II", 0, len(buf) - 24))], "invalid_codeview"),
            ("oversize", [(0x210, struct.pack("<I", 65537))], "invalid_codeview"),
            ("short-header", [(0x210, struct.pack("<I", 24))], "invalid_codeview"),
            ("other-format", [(0x300, b"NB10")], "unsupported_codeview"),
            ("nil-guid", [(0x304, bytes(16))], "empty_debug_id"),
            ("unterminated", [(0x300 + len(cv) - 1, b"x")], "invalid_codeview"),
            ("padding", [(0x210, struct.pack("<I", len(cv) + 3))], "unique_rsds"),
            ("trailing-data", [(0x210, struct.pack("<I", len(cv) + 3)), (0x300 + len(cv), b"x")], "invalid_codeview"),
        ]
        for label, changes, status in cases:
            data = buf.copy()
            for offset, new in changes:
                data[offset:offset + len(new)] = new
            path = folder / f"owned-{width}-{label}.bin"
            path.write_bytes(data)
            page = run(exe, etl, pin, "--reference-image", path, hashlib.sha256(data).hexdigest(), "--build-evidence")
            ok = status == "unique_rsds"
            assert page["reference_build"] == dict(status=status, rsds_guid=str(expected_guid) if ok else None,
                                                   pdb_age=0xffffffff if ok else None), (width, label)
            assert "layout-only.pdb" not in str(page)
    print("Owned PE32 and PE32+ CodeView layout controls passed:", 2 * len(cases))


class BuildOracle:
    def __init__(self, reference):
        self.markers = defaultdict(lambda: defaultdict(list))
        self.by_record = {}
        self.other = 0
        self.reference = reference
        self.disk = reference_build(reference) if reference else None

    def add(self, event, ns, record, width):
        system = event.find(ns + "System")
        op = int(system.findtext(ns + "Opcode"))
        if op not in ROLES:
            self.other += 1
            return
        assert width in (4, 8) and system.findtext(ns + "EventID") == "0" and system.findtext(ns + "Version") == "2"
        data = bytes.fromhex(event.findtext(ns + "BinaryEventData"))
        pointer = "I" if width == 4 else "Q"
        base, = struct.unpack_from("<" + pointer, data)
        pid, = struct.unpack_from("<I", data, width * (2 if op == 0 else 1))
        header_pid = int(system.find(ns + "Execution").attrib["ProcessID"], 0)
        point = dict(record_ordinal=record, raw_timestamp=str(int(system.find(ns + "TimeCreated").attrib["RawTime"])),
                     version=2, opcode=op, pointer_bytes=width, payload_pid=pid, header_process_id=header_pid, image_base=hex(base))
        if op == 0:
            size, _, stamp = struct.unpack_from("<" + pointer + "II", data, width)
            point.update(image_size=hex(size), pe_timestamp=stamp)
            name = data[2 * width + 8:].decode("utf-16-le")
            assert name.endswith("\0") and "\0" not in name[:-1]
        elif op == 36:
            pos = width + 4
            point.update(rsds_guid=str(uuid.UUID(bytes_le=data[pos:pos + 16])), pdb_age=int.from_bytes(data[pos + 16:pos + 20], "little"))
            name = data[pos + 20:].decode("utf8")
            assert name.endswith("\0") and "\0" not in name[:-1]
        else:
            assert len(data) == width + 4
        self.by_record[record] = point
        self.markers[key(point)][op].append(point)

    def prepare(self, images):
        self.loaders = Counter(key(p) for p in images.by_ordinal.values())
        self.pid_conflicts = sum(m["payload_pid"] != m["header_process_id"] for m in self.by_record.values())

    def endpoint(self, point, coverage):
        k = key(point)
        markers = self.markers.get(k, {})
        info, none, rsds = (markers.get(op, []) for op in ROLES)
        if not coverage or self.pid_conflicts:
            relation = "coverage_unqualified"
        elif self.loaders[k] != 1 or any(len(c) > 1 for c in (info, none, rsds)):
            relation = "ambiguous_records"
        elif none and rsds:
            relation = "conflicting_debug_markers"
        elif any(m["pointer_bytes"] != point["pointer_bytes"] for group in (info, none, rsds) for m in group):
            relation = "loader_marker_conflict"
        elif info and (info[0]["image_size"] != point["image_size"] or point["pe_timestamp"] not in (0, 0xffffffff)
                       and info[0]["pe_timestamp"] not in (0, 0xffffffff, point["pe_timestamp"])):
            relation = "loader_marker_conflict"
        elif none:
            relation = "reported_no_debug_id"
        elif not info or not rsds:
            relation = "markers_missing"
        elif not uuid.UUID(rsds[0]["rsds_guid"]).int:
            relation = "empty_debug_id"
        else:
            relation = "unique_merge_records"
        out = dict(relation=relation, loader_count=self.loaders[k])
        for op, role in ROLES.items():
            group = markers.get(op, [])
            out[role] = dict(marker_count=len(group), marker_records=[m["record_ordinal"] for m in group[:2]])
        return out

    def expected(self, bound, image, images, coverage):
        result = dict(relation="process_image_unavailable", reference_comparison=None)
        if bound["reported_rva"] is None:
            return result
        witness, = image["witnesses"]
        ends = [self.endpoint(images.by_ordinal[witness[k]], coverage) for k in ("before_record", "after_record")]
        if any(e["relation"] != "unique_merge_records" for e in ends):
            return dict(result, relation="endpoint_unqualified")
        def values(end):
            s, i = (self.by_record[end[role]["marker_records"][0]] for role in ("native_rsds", "image_id"))
            return s["rsds_guid"], s["pdb_age"], i["pe_timestamp"]
        guid, age, stamp = values(ends[0])
        if values(ends[1]) != (guid, age, stamp):
            return dict(result, relation="endpoint_build_conflict")
        result["relation"] = "paired_merge_build"
        if self.reference:
            result["reference_comparison"] = dict(
                rsds_guid_equal=guid == self.disk["rsds_guid"] if self.disk["rsds_guid"] is not None else None,
                pdb_age_equal=age == self.disk["pdb_age"] if self.disk["pdb_age"] is not None else None,
                merge_timestamp_equal=stamp == self.reference.source["pe_timestamp"] if stamp not in (0, 0xffffffff) else None)
        return result

    def check_records(self, report, images):
        source = report["build_source"]
        assert source == dict(provider_guid=PROVIDER, event_id=0, version=2, opcodes=list(ROLES), origin="merge_metadata",
                              producer_authenticity="unverified", runtime_bytes_observed=False, decoded_events=len(self.by_record),
                              retained_events=len(self.by_record), unsupported_events=0, other_opcodes=self.other,
                              header_pid_conflicts=self.pid_conflicts)
        assert report.get("reference_build") == self.disk
        header, clock = report["log_header"], report["clock"]
        coverage = (report["buffer_comparison"] == "matched" and not (header["events_lost"] or header["buffers_lost"] or
                    report["loss_marker_records"]) and (clock["raw_type"] == 2 or clock["raw_type"] == 1 and
                    int(clock["header_perf_frequency"]) > 0))
        referenced = set()
        for entry in report["image_records"]:
            wanted = self.endpoint(images.by_ordinal[entry["record_ordinal"]], coverage)
            assert entry["merge_build"] == wanted
            for role in ROLES.values():
                referenced.update(wanted[role]["marker_records"])
        # tracerpt omits logger IDs. All supported oracle fixtures here are single logger.
        rows = report["samples"]
        expected = [dict(self.by_record[i], logger_id=rows[0]["logger_id"]) for i in sorted(referenced)]
        assert report["build_records"] == expected
