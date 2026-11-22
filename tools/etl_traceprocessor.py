"""Corroborate selected ETL marker headers with the optional Microsoft TraceProcessor adapter."""
import os
from pathlib import Path
import re
import zipfile
import zlib

from etl_reader_process import file_hash, reader_receipt, run_reader
from owned_module_benchmark import check, fields, sha, uint
from saved_etl_comparison import MIB, digest, local_path, original


PROGRAM = "TraceProcessorMarkers.exe"
SDK_HASH = "155f3da1ba1de62d40c75058f8cb5375016fd2d39d4a85a631e9cc168cbb1bd7"
CPU_PROGRAM = "TraceProcessorReadyTest.exe"
CPU_SDK_HASH = "bee8791296225909ead0839cd4f18585062f8efeb4a0654dcae5dcca73c00ab8"
DISK_PROGRAM = "TraceProcessorDisk.exe"
FILE_RECORD_PROGRAM = "FileOperationRecords.exe"
DISK_SDK_HASH = "e4bc270f68380ed51742c961a687e4bbb651130d1ef6a9a503f7db4c54031f62"
TABLE = "IGenericEventDataSource.Events"
SCHEMA = "kn.traceprocessor_activity_rows.v1"
ALL_MARKERS = "kn.traceprocessor_activity_markers.v1"
HEADER = ("provider_guid", "activity_id", "channel", "task", "opcode", "event_id", "version", "header_process_id", "header_thread_id")


def deployment(cpu, disk):
    check(not (cpu and disk), "select one adapter per deployment")
    if disk:
        return DISK_PROGRAM, 52, DISK_SDK_HASH
    return (CPU_PROGRAM, 51, CPU_SDK_HASH) if cpu else (PROGRAM, 50, SDK_HASH)


def unpack(source, folder, *, cpu=False, disk=False):
    program, count, runtime_hash = deployment(cpu, disk)
    assets = {}
    names = set()
    total = 0
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        with_file_reader = disk and any(m.orig_filename == FILE_RECORD_PROGRAM for m in entries)
        check(len(entries) == count + int(with_file_reader), "unexpected TraceProcessor package layout")
        for member in entries:
            name = member.orig_filename
            check(re.fullmatch(r"(?:wpt/(?:Catalog/)?)?[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", name) and
                  not name.endswith(".") and not Path(name).is_reserved() and name.lower() not in names,
                  "invalid or duplicate TraceProcessor package member")
            check(member.compress_type in (zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED) and not member.flag_bits & 1 and
                  0 < member.file_size <= 8 * MIB, "unsupported TraceProcessor package member")
            names.add(name.lower())
            total += member.file_size
            check(total <= 32 * MIB, "TraceProcessor package exceeds expanded limit")
            with archive.open(member) as item:
                raw = item.read(member.file_size + 1)
            check(len(raw) == member.file_size, "incorrect TraceProcessor member extent")
            dest = folder / name
            with dest.open("xb") as output:
                output.write(raw)
            assets[name] = sha(raw)
    check(program in assets and program + ".config" in assets, "missing managed adapter or binding configuration")
    exe_hash, config_hash = assets.pop(program), assets.pop(program + ".config")
    # Digest the untouched runtime files from the locked NuGet packages in canonical path order.
    inventory = "".join(assets[name] + " " + name + "\n" for name in sorted(assets) if not (disk and name == FILE_RECORD_PROGRAM)).encode("ascii")
    check(sha(inventory) == runtime_hash, "TraceProcessor runtime files differ from the locked x64 distribution")
    return exe_hash, config_hash, assets


def admit(values, directory, files, stack, held, *, cpu=False, disk=False, file_records=False):
    program, _, runtime_hash = deployment(cpu, disk)
    path, expected = local_path(values[0]), digest(values[1].lower())
    files.parents(stack, path.parent, held)
    source = stack.enter_context(files.hold(path))
    check(0 < os.fstat(source.fileno()).st_size <= 32 * MIB and file_hash(source) == expected,
          "TraceProcessor package extent or SHA-256 mismatch")
    folder = directory / ("disk-adapter" if disk else "adapter")
    for parent in (folder, folder / "wpt", folder / "wpt" / "Catalog"):
        parent.mkdir()
        files.parents(stack, parent, held)
    source.seek(0)
    try:
        image, config, assets = unpack(source, folder, cpu=cpu, disk=disk)
    except (zipfile.BadZipFile, NotImplementedError, EOFError, zlib.error) as exc:
        raise ValueError("invalid TraceProcessor package") from exc
    # Run from the verified deployment. Keep each admitted file and directory in place through publication.
    binary, record_reader = None, None
    for name, expected_file in {program: image, program + ".config": config, **assets}.items():
        deployed = folder / name
        files.parents(stack, deployed.parent, held)
        stream = stack.enter_context(files.hold(deployed))
        check(file_hash(stream) == expected_file, "TraceProcessor deployment changed")
        if name == program:
            binary = stream
        if disk and name == FILE_RECORD_PROGRAM:
            record_reader = (deployed, stream)
    metadata = dict(package_sha256=expected, executable_sha256=image, config_sha256=config, sdk_files_sha256=runtime_hash,
                    events_package_version="1.12.10", toolkit_package_version="1.11.0", table=TABLE,
                    allow_lost_events=False, allow_time_inversion=False, symbol_lookup="not_requested")
    if cpu or disk:
        del metadata["events_package_version"], metadata["table"]
    if cpu:
        metadata.update(cpu_package_version="1.12.10",
                        tables=["IReadyThreadDataSource.ReadyThreadEvents", "ICpuSchedulingDataSource.ThreadActivity",
                                "ICpuSchedulingDataSource.CpuTimeSlices"])
    if disk:
        metadata.update(disk_package_version="1.12.10", tables=["IDiskActivityDataSource.Activity", "DiskIo classic events 10-15"])
    if file_records:
        check(record_reader is not None, "the disk package lacks the Windows TDH file-operation reader")
        metadata["file_record_reader_sha256"] = assets[FILE_RECORD_PROGRAM]
        return folder / program, binary, metadata, record_reader
    return folder / program, binary, metadata


def verify_modules(modules, required_sdk, optional=()):
    required = {"Microsoft.Windows.EventTracing." + name + ".dll" for name in required_sdk} | {"wpt/perfcore.dll"}
    check(type(modules) is list and len(required) <= len(modules) <= 32 and all(type(name) is str for name in modules) and
          modules == sorted(set(modules)) and required.issubset(modules) and
          all(name in required or name in optional or re.fullmatch(r"wpt/(?:perfg|perf_[a-z0-9_]+)\.dll", name) for name in modules),
          "unexpected loaded processing modules")


def verify_cpu_modules(modules):
    verify_modules(modules, ("Cpu", "Processes", "Processing"),
                   {"Microsoft.Windows.EventTracing.Metadata.dll", "System.Buffers.dll", "System.Memory.dll",
                    "System.Numerics.Vectors.dll", "System.Runtime.CompilerServices.Unsafe.dll", "System.Security.Principal.Windows.dll"})


def validate_projection(document, source_hash, size, provider, activity_id, window=None):
    fields(document, "schema source_sha256 source_bytes table provider_guid activity_id query_filter loaded_processing_modules "
           "provider_rows activity_marker_rows scoped_marker_rows matched_rows row_limit rows" + ("" if window else " trace_metadata"),
           "TraceProcessor query")
    check(document["schema"] == (SCHEMA if window else ALL_MARKERS) and document["source_sha256"] == source_hash and
          uint(document["source_bytes"]) == size and document["table"] == TABLE and
          document["provider_guid"] == provider and document["activity_id"] == activity_id,
          "TraceProcessor source or filter mismatch")
    scope = document["query_filter"]
    if window:
        a, b = window["start"], window["stop"]
        fields(scope, "header_process_id header_thread_id channel task begin_raw end_raw", "TraceProcessor filter")
        for key in ("header_process_id", "header_thread_id", "channel", "task"):
            check(uint(scope[key]) == a[key], "TraceProcessor numeric filter mismatch")
        check((scope["begin_raw"], scope["end_raw"]) == (a["raw_timestamp"], b["raw_timestamp"]), "TraceProcessor clock filter mismatch")
    else:
        fields(scope, "opcodes", "whole-activity filter")
        check(type(scope["opcodes"]) is list and len(scope["opcodes"]) == 2 and
              [uint(v, 255) for v in scope["opcodes"]] == [1, 2], "unexpected whole-activity filter")
        meta = document["trace_metadata"]
        fields(meta, "clock_type context_clock_type timestamp_context_partial performance_counter_hz lost_events lost_buffers", "SDK metadata")
        check(all(type(meta[k]) is str and 0 < len(meta[k]) <= 64 for k in ("clock_type", "context_clock_type")) and
              type(meta["timestamp_context_partial"]) is bool, "invalid SDK clock context")
        hz = meta["performance_counter_hz"]
        check(type(hz) is str and re.fullmatch(r"0|-?[1-9][0-9]{0,18}", hz) and -(1 << 63) <= int(hz) < 1 << 63,
              "invalid SDK counter frequency")
        uint(meta["lost_events"])
        uint(meta["lost_buffers"])
    verify_modules(document["loaded_processing_modules"], ("Events", "Processes", "Processing"))
    total = uint(document["provider_rows"], 2_000_000)
    activity = uint(document["activity_marker_rows"], total)
    scoped = uint(document["scoped_marker_rows"], activity)
    count = uint(document["matched_rows"], scoped)
    rows = document["rows"]
    check(uint(document["row_limit"]) == 128 and type(rows) is list and len(rows) == min(count, 128),
          "invalid TraceProcessor row extent")
    check(window is not None or count == scoped == activity, "whole-activity query omitted markers")
    previous = 0
    for row in rows:
        fields(row, "table_row clock_type timestamp_partial raw_timestamp " + " ".join(HEADER), "TraceProcessor table row")
        ordinal = uint(row["table_row"], total)
        check(previous < ordinal and row["provider_guid"] == provider and row["activity_id"] == activity_id,
              "row outside filtered TraceProcessor table")
        previous = ordinal
        for key, maximum in (("channel", 255), ("task", 65535), ("event_id", 65535), ("version", 255),
                             ("header_process_id", 0xffffffff), ("header_thread_id", 0xffffffff)):
            uint(row[key], maximum)
        check(not window or all(row[k] == scope[k] for k in ("header_process_id", "header_thread_id", "channel", "task")),
              "row outside TraceProcessor header filter")
        opcode = uint(row["opcode"])
        check(opcode in (1, 2) and type(row["timestamp_partial"]) is bool, "invalid marker or clock state")
        raw, clock = row["raw_timestamp"], row["clock_type"]
        if raw is None:
            check(clock is None, "clock kind without a timestamp")
        else:
            check(type(clock) is str and 0 < len(clock) <= 64 and type(raw) is str and
                  re.fullmatch(r"0|-?[1-9][0-9]{0,18}", raw) and -(1 << 63) <= int(raw) < (1 << 63),
                  "invalid raw TraceProcessor timestamp")
            if window and clock == "PerformanceCounter" and not row["timestamp_partial"]:
                check(int(scope["begin_raw"]) <= int(raw) <= int(scope["end_raw"]), "row outside TraceProcessor clock filter")
    return rows


def correlate(document, native):
    window = native["page"]["activity_window"]
    a, b = window["start"], window["stop"]
    rows = validate_projection(document, native["source_sha256"], native["source_bytes"], a["provider_guid"], a["activity_id"], window)
    exact = {"start": [], "stop": []}
    uncertain = {"start": 0, "stop": 0}
    for row in rows:
        opcode, ordinal, raw, clock = (row[k] for k in ("opcode", "table_row", "raw_timestamp", "clock_type"))
        label, marker = ("start", a) if opcode == 1 else ("stop", b)
        if any(row[k] != marker[k] for k in HEADER):
            continue
        if clock != "PerformanceCounter" or row["timestamp_partial"] or raw is None:
            uncertain[label] += 1
        elif raw == marker["raw_timestamp"]:
            exact[label].append(ordinal)

    if document["matched_rows"] > len(rows):
        status = "row_limit"
    elif any(uncertain.values()):
        status = "clock_unqualified"
    elif any(len(values) > 1 for values in exact.values()):
        status = "ambiguous_rows"
    elif not exact["start"] or not exact["stop"]:
        status = "row_missing"
    elif exact["start"][0] >= exact["stop"][0]:
        status = "table_order_conflict"
    else:
        status = "matched"
    return dict(status=status, matching_table_rows=exact, unqualified_clock_rows=uncertain)


def read_query(arguments, native_page_hash, runtime, directory, timeout, files, decode, compare):
    result = dict(status="reader_unavailable", native_page_sha256=native_page_hash, reader=None, projection=None, correspondence=None)
    exe, binary, _ = runtime
    attempt = run_reader(exe, arguments, directory, timeout, MIB, files, binary)
    receipt = reader_receipt(attempt)
    result["reader"] = receipt
    if receipt["state"] != "exited" or receipt["exit_code"] != 0 or receipt["image_binding"] != dict(status="matched", win32_status=0):
        return result
    try:
        raw, complete = original(attempt["stdout"], MIB)
        check(complete, "TraceProcessor output exceeds byte limit")
        document = decode(raw)
        correspondence = compare(document)
    except (KeyError, TypeError, ValueError, RecursionError):
        result["status"] = "invalid_projection"
        return result
    result.update(status=correspondence["status"], projection=document, correspondence=correspondence)
    return result


def verify_side(query, native, measured, runtime, directory, timeout, files, decode):
    page_hash = native["reader"]["stdout_sha256"] if native["reader"] else None
    if measured is None:
        return dict(status="native_window_unavailable", native_page_sha256=page_hash, reader=None, projection=None, correspondence=None)
    window = native["page"]["activity_window"]
    marker = window["start"]
    arguments = [str(query.path), marker["provider_guid"], marker["activity_id"],
                 *(str(marker[key]) for key in ("header_process_id", "header_thread_id", "channel", "task")),
                 marker["raw_timestamp"], window["stop"]["raw_timestamp"]]
    return read_query(arguments, page_hash, runtime, directory, timeout, files, decode, lambda doc: correlate(doc, native))
