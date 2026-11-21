"""Compare tracerpt image witnesses with an explicitly supplied PE's raw headers and bytes."""
import ctypes
import hashlib
import ntpath
import os
from pathlib import Path
import struct
import subprocess


class ReferenceOracle:
    def __init__(self, path, pin):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        digest = hashlib.sha256(self.data).hexdigest()
        assert digest == pin.lower()
        pe, = struct.unpack_from("<I", self.data, 60)
        assert self.data[:2] == b"MZ" and self.data[pe:pe + 4] == b"PE\0\0"
        machine, count, stamp = struct.unpack_from("<HHI", self.data, pe + 4)
        optional_size, = struct.unpack_from("<H", self.data, pe + 20)
        optional = pe + 24
        magic, = struct.unpack_from("<H", self.data, optional)
        assert magic in (0x10b, 0x20b)
        preferred, = (struct.unpack_from("<I", self.data, optional + 28) if magic == 0x10b
                      else struct.unpack_from("<Q", self.data, optional + 24))
        size, self.headers, checksum = struct.unpack_from("<III", self.data, optional + 56)
        self.source = dict(file_sha256=digest, file_bytes=len(self.data), file_name=self.path.name, machine=machine,
                           optional_magic=magic, image_size=hex(size), pe_timestamp=stamp, image_checksum=checksum,
                           preferred_base=hex(preferred), max_window_bytes=32, runtime_bytes_observed=False)
        self.sections = []
        for i in range(count):
            section = optional + optional_size + 40 * i
            virtual, address, raw, offset = struct.unpack_from("<4I", self.data, section + 8)
            flags, = struct.unpack_from("<I", self.data, section + 36)
            self.sections.append((address, virtual, raw, offset, bool(flags & 0x20000000)))
        self.ordinal_compare = ctypes.WinDLL("kernel32").CompareStringOrdinal
        self.ordinal_compare.argtypes = (ctypes.c_wchar_p, ctypes.c_int, ctypes.c_wchar_p, ctypes.c_int, ctypes.c_int)
        self.ordinal_compare.restype = ctypes.c_int

    def expected(self, bound, image, images):
        result = dict(relation="process_image_unavailable", loader_fields=None, file_location="uncompared", reference_window=None)
        if bound["reported_rva"] is None:
            return result
        witness, = image["witnesses"]
        record = images.by_ordinal[witness["before_record"]]
        after = images.by_ordinal[witness["after_record"]]
        assert all(record[k] == after[k] for k in ("recorded_file_name", "image_size", "pe_timestamp", "image_checksum", "preferred_base"))
        leaf = ntpath.basename(record["recorded_file_name"])
        name = self.source["file_name"]
        default = int(record["preferred_base"], 16)
        matches_preferred = default == int(self.source["preferred_base"], 16)
        matches_load = default == int(record["image_base"], 16)
        roles = {(True, True): "file_preferred_and_recorded_load", (True, False): "file_preferred",
                 (False, True): "recorded_load", (False, False): "unexplained"}
        stamp, checksum = record["pe_timestamp"], record["image_checksum"]
        fields = dict(file_name=self.ordinal_compare(leaf, -1, name, -1, True) == 2,
                      image_size=record["image_size"] == self.source["image_size"],
                      pe_timestamp=(stamp == self.source["pe_timestamp"] if stamp not in (0, 0xffffffff) else None),
                      image_checksum=(checksum == self.source["image_checksum"] if checksum else None),
                      default_base_relation=(roles[matches_preferred, matches_load] if default else "unavailable"))
        result["loader_fields"] = fields
        if False in fields.values():
            result["relation"] = "loader_field_conflict"
        elif fields["pe_timestamp"] is None and fields["image_checksum"] is None:
            result["relation"] = "build_fields_unavailable"
        elif fields["default_base_relation"] == "unexplained":
            result["relation"] = "default_base_unresolved"
        else:
            result["relation"] = "recorded_fields_agree"
            rva = int(bound["reported_rva"], 16)
            result["file_location"] = "pe_headers" if rva < self.headers else "section_gap"
            for start, virtual, raw, offset, executable in self.sections:
                delta = rva - start
                if not 0 <= delta < max(virtual, raw):
                    continue
                if not executable:
                    result["file_location"] = "nonexecutable_section"
                elif delta >= min(virtual, raw):
                    result["file_location"] = "outside_file_backed_extent"
                else:
                    window = self.data[offset + delta:offset + min(delta + 32, raw, virtual)]
                    assert 0 < len(window) <= 32
                    result["file_location"] = "executable_file_bytes"
                    result["reference_window"] = dict(file_offset=offset + delta, byte_count=len(window),
                                                      sha256=hashlib.sha256(window).hexdigest())
                break
        return result

    def controls(self, exe, etl, pin, folder, run):
        """Both source leases and malformed diagnostics must protect explicit inputs."""
        args = ["--reference-image", self.path, self.source["file_sha256"]]
        first = run(exe, etl, pin, *args, "--limit", 2)
        assert run(exe, etl, pin, "--thread-evidence", "--after", 0, "--image-evidence", *args, "--process-evidence", "--limit", 2) == first
        assert run(exe, etl, pin, "--limit", 2, *args) == first
        opposite = ("0" if args[-1][0] != "0" else "1") + args[-1][1:]
        wrong = run(exe, etl, pin, *args[:-1], opposite, rc=1)
        assert (wrong["status"], wrong["reference_sha256"], wrong["source_sha256"]) == ("reference_digest_mismatch", args[-1], pin)
        assert "samples" not in wrong
        trace_alias = folder / "reference-is-trace.bin"
        os.link(etl, trace_alias)
        same_expected = "reference_is_trace" if etl.stat().st_size <= 64 << 20 else "reference_unavailable"
        assert run(exe, etl, pin, args[0], trace_alias, pin, rc=1)["status"] == same_expected
        absent = folder / "missing-reference.bin"
        assert run(exe, etl, pin, args[0], absent, args[-1], rc=1)["status"] == "reference_unavailable"
        invalid = folder / "not-pe.bin"
        invalid.write_bytes(b"not an image")
        assert run(exe, etl, pin, args[0], invalid, hashlib.sha256(invalid.read_bytes()).hexdigest(), rc=1)["status"] == "reference_invalid_pe"
        maximum = folder / "reference-limit.bin"
        with maximum.open("wb") as out:
            out.truncate(64 << 20)
        with maximum.open("rb") as source:
            limit_pin = hashlib.file_digest(source, "sha256").hexdigest()
        assert run(exe, etl, pin, args[0], maximum, limit_pin, rc=1)["status"] == "reference_invalid_pe"
        with maximum.open("ab") as out:
            out.write(b"0")
        assert run(exe, etl, pin, args[0], maximum, limit_pin, rc=1)["status"] == "reference_unavailable"
        for flags in ([args[0]], args[:2], [*args[:-1], "invalid"], [*args, *args]):
            run(exe, etl, pin, *flags, rc=2)
        run(exe, etl, pin, *args, switches=True, rc=2)
        # Work only on a copy, including for redirected error responses.
        alias = folder / "same-reference.bin"
        os.link(self.path, alias)
        wrong_source = ("1" if pin[0] == "0" else "0") + pin[1:]
        for file, digest, flags, stream in ((etl, pin, args, "stdout"), (folder / "absent.etl", pin, args, "stdout"),
                                            (etl, wrong_source, args, "stdout"), (etl, pin, [*args, *args], "stderr"),
                                            (etl, pin, [args[0], invalid, opposite, *args], "stderr"),
                                            (etl, pin, [*args[:-1], "bad"], "stderr")):
            with alias.open("ab", buffering=0) as sink:
                streams = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                streams[stream] = sink
                result = subprocess.run([exe, "--etl-profile", file, "--sha256", digest, *flags], timeout=30, **streams)
            assert result.returncode == 2 and self.path.read_bytes() == self.data
        with alias.open("ab", buffering=0) as sink:
            result = subprocess.run([exe, "--etl-profile", *args], stdout=subprocess.PIPE, stderr=sink, timeout=30)
        assert result.returncode == 2 and self.path.read_bytes() == self.data
