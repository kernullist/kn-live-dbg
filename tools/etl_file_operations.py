"""Match enclosing File I/O activities to selected disk requests and independent Windows TDH records."""
from etl_activity_waits import MAX_RECORDS, tick
from etl_disk_waits import Unavailable
from etl_traceprocessor import verify_modules
from owned_module_benchmark import check, decimal, fields, uint

LIMIT = 128
OPS = {"read": (67, 12, 10), "write": (68, 13, 11), "flush": (73, 15, 14)}
# IORequestPacketFlags in the pinned Disk assembly defines bits 0 through 13.
SDK_PACKET_FLAGS = 0x3fff
TABLES = ["IFileActivityDataSource.ReadFileActivity", "IFileActivityDataSource.WriteFileActivity", "IFileActivityDataSource.FlushFileActivity"]


def candidates(doc, common, disk_result):
    fields(doc, "schema source_sha256 source_bytes clock loaded_processing_modules query_filter table_counts records_seen file_records "
           "operation_ends matched_disks matched_files matched_links unplaced row_limit disks files", "file SDK projection")
    source = disk_result["sdk_query"]["page"]
    check(doc["schema"] == "kn.traceprocessor_file_operations.v1" and doc["query_filter"] == source["query_filter"] and
          doc["clock"] == source["clock"] and all(doc[k] == common[k] for k in ("source_sha256", "source_bytes", "records_seen")) and
          uint(doc["row_limit"]) == LIMIT, "file query has different source, clock or scope")
    verify_modules(doc["loaded_processing_modules"], ("Disk", "Processes", "Processing"),
                   {"Microsoft.Windows.EventTracing.Cpu.dll", "Microsoft.Windows.EventTracing.Metadata.dll", "System.Memory.dll",
                    "System.Buffers.dll", "System.Numerics.Vectors.dll", "System.Runtime.CompilerServices.Unsafe.dll",
                    "System.Security.Principal.Windows.dll"})
    counts = doc["table_counts"]
    fields(counts, "disk read write flush", "file table sizes")
    for n in counts.values():
        uint(n, MAX_RECORDS)
    file_records = uint(doc["file_records"], common["records_seen"])
    check(counts["disk"] == source["activity_rows"] and uint(doc["operation_ends"]) <= file_records and
          sum(counts[k] for k in OPS) <= file_records,
          "inconsistent file table counts")
    if max(uint(doc[k]) for k in ("matched_disks", "matched_files", "matched_links")) > LIMIT:
        raise Unavailable("file_context_limit")
    if uint(doc["unplaced"]):
        raise Unavailable("file_rows_unplaced")
    if not doc["operation_ends"] or not sum(counts[k] for k in OPS):
        raise Unavailable("file_operations_unobserved")
    requests = {r["table_row"]: r for r in disk_result["summary"]["requests"]}
    selected = {r["table_row"]: r for r in source["activities"]}
    check(type(doc["disks"]) is list and len(doc["disks"]) == doc["matched_disks"] == len(requests) and
          [r["table_row"] for r in doc["disks"]] == sorted(requests), "disk selection changed")
    for d in doc["disks"]:
        row = selected[uint(d["table_row"], counts["disk"])]
        fields(d, "table_row operation start_ns stop_ns", "enclosed disk row")
        check(all(d[k] == row[k] for k in d), "disk table row changed")
    check(type(doc["files"]) is list and len(doc["files"]) == doc["matched_files"], "file selection extent differs")
    links, seen = [], set()
    for f in doc["files"]:
        fields(f, "table_row operation start_ns stop_ns begin_record end_record begin_matches end_matches packet_conflict ntstatus "
               "requested_bytes actual_bytes io_flags file_offset enclosed", "enclosing file row")
        op = f["operation"]
        check(op in OPS, "unknown file operation")
        row = uint(f["table_row"], counts[op])
        check(row and (op, row) not in seen, "duplicate file table row")
        seen.add((op, row))
        if uint(f["begin_matches"]) != 1 or uint(f["end_matches"]) != 1 or f["packet_conflict"] is not False:
            raise Unavailable("file_packet_history_unconfirmed")
        check(0 < uint(f["begin_record"], common["records_seen"]) < uint(f["end_record"], common["records_seen"]) and
              tick(f["start_ns"]) < tick(f["stop_ns"]), "invalid file endpoints")
        uint(f["ntstatus"], 0xffffffff)
        if op == "flush":
            check(all(f[k] is None for k in ("io_flags", "requested_bytes", "actual_bytes", "file_offset")), "transfer fields on a flush")
        else:
            uint(f["io_flags"], 0xffffffff)
            uint(decimal(f["requested_bytes"]), 0xffffffff)
            decimal(f["actual_bytes"])
            decimal(f["file_offset"])
        enclosed = sorted(n for n, d in selected.items() if d["operation"] == op and
                          tick(f["start_ns"]) <= tick(d["start_ns"]) < tick(d["stop_ns"]) <= tick(f["stop_ns"]))
        check(enclosed and type(f["enclosed"]) is list and [b["disk_table_row"] for b in f["enclosed"]] == enclosed,
              "file nesting differs from the disk table")
        for b in f["enclosed"]:
            fields(b, "disk_table_row packet_value file_object_value", "cross-layer observation")
            links.append((f, requests[b["disk_table_row"]], b))
    check(len(links) == doc["matched_links"], "file link count differs")
    return links


def locations(f, d):
    return f["begin_record"], d["init_record"], d["complete_record"], f["end_record"]


def check_page(query, records, common):
    p = query["page"]
    if p is None or query["reader"]["exit_code"] != 0 or p["status"] != "read":
        raise Unavailable("file_native_records_unavailable")
    fields(p, "schema status source_sha256 source_bytes file_provider_guid disk_provider_guid clock log_header records_seen buffers_processed "
           "buffer_comparison loss_marker_records requested_operation_records next_after operation_records", "Windows operation page")
    check(p["schema"] == "kn.etl_operation_records.v1" and p["requested_operation_records"] == records and
          p["file_provider_guid"] == "90cbdc39-4a3e-11d1-84f4-0000f80464e3" and
          p["disk_provider_guid"] == "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c" and
          all(p[k] == common[k] for k in ("source_sha256", "source_bytes", "clock", "log_header", "records_seen", "buffers_processed",
                                            "buffer_comparison", "loss_marker_records")) and p["next_after"] is None and
          [r["record_ordinal"] for r in p["operation_records"]] == records, "native operation page differs")
    rows = {}
    for r in p["operation_records"]:
        fields(r, "record_ordinal status layer opcode version pointer_bytes logger_id raw_timestamp packet_label file_object_label "
               "issuing_tid file_offset requested_bytes io_flags ntstatus extra_info", "decoded operation record")
        n = uint(r["record_ordinal"], common["records_seen"])
        check(r["status"] == "decoded" and uint(r["version"]) == 3 and uint(r["pointer_bytes"]) in (4, 8), "unqualified native record")
        uint(r["logger_id"], 0xffff)
        uint(r["opcode"], 255)
        if r["issuing_tid"] is not None:
            uint(r["issuing_tid"], 0xffffffff)
        rows[n] = r
        for key in ("packet_label", "file_object_label"):
            label = r[key]
            if label is not None:
                peer = rows[uint(label, n)]
                check(peer[key] == label and all(peer[k] == r[k] for k in ("logger_id", "pointer_bytes")), "invalid local identity label")
    return rows


def relation(a, b):
    return "unreported" if a is None or b is None else "equal" if a == b else "different"


def bind(f, d, link, rows, clock, window):
    op = f["operation"]
    start, init, complete, end = (rows[n] for n in locations(f, d))
    birth, death = (window["thread_evidence"][k] for k in ("before", "after"))
    check(birth["record_ordinal"] < start["record_ordinal"] < init["record_ordinal"] < complete["record_ordinal"] <
          end["record_ordinal"] < death["record_ordinal"], "file and disk records outside nesting or thread lifetime")
    points = (start, init, complete, end)
    ticks = [tick(r["raw_timestamp"]) for r in points]
    check(tick(birth["raw_timestamp"]) < ticks[0] <= ticks[1] < ticks[2] <= ticks[3] < tick(death["raw_timestamp"]) and
          [r["layer"] for r in points] == ["file", "disk", "disk", "file"] and
          [r["opcode"] for r in points] == [*OPS[op], 76] and init["raw_timestamp"] == d["start_qpc"] and
          complete["raw_timestamp"] == d["stop_qpc"] and all(r["logger_id"] == window["start"]["logger_id"] and
          r["pointer_bytes"] == start["pointer_bytes"] for r in points), "file and disk endpoint fields differ")
    tid = window["start"]["header_thread_id"]
    check(all(r["issuing_tid"] == tid for r in points[:3]) and end["issuing_tid"] is None and
          relation(start["packet_label"], end["packet_label"]) == relation(init["packet_label"], complete["packet_label"]) == "equal",
          "different packet or issuer within a layer")
    for qpc, ns in ((ticks[0], tick(f["start_ns"])), (ticks[-1], tick(f["stop_ns"]))):
        hz = decimal(clock["frequency"])
        check(abs((qpc-tick(clock["reference_qpc"]))*1_000_000_000 - (ns-tick(clock["reference_ns"]))*hz) < hz, "file SDK clock mismatch")
    raw_flags = start["io_flags"]
    if op == "flush":
        check(raw_flags is None, "transfer flags on a flush")
    else:
        check(uint(raw_flags, 0xffffffff) & SDK_PACKET_FLAGS == f["io_flags"], "file packet flags differ")
    check(all(start[k] == f[k] for k in ("requested_bytes", "file_offset")) and uint(end["ntstatus"], 0xffffffff) == f["ntstatus"] and
          (op == "flush" or end["extra_info"] == f["actual_bytes"]), "file transfer or completion fields differ")
    check(link["packet_value"] == relation(start["packet_label"], init["packet_label"]) and
          link["file_object_value"] == relation(start["file_object_label"], complete["file_object_label"]), "cross-layer comparison differs")
    return dict(operation=op, file_table_row=f["table_row"], disk_table_row=d["table_row"], file_start_record=start["record_ordinal"],
                disk_init_record=d["init_record"], disk_completion_record=d["complete_record"], file_end_record=end["record_ordinal"],
                file_elapsed_ticks=str(ticks[3]-ticks[0]), before_disk_ticks=str(ticks[1]-ticks[0]), disk_elapsed_ticks=d["elapsed_ticks"],
                after_disk_ticks=str(ticks[3]-ticks[2]), ntstatus=f["ntstatus"], file_offset=f["file_offset"],
                requested_bytes=f["requested_bytes"], actual_bytes=f["actual_bytes"],
                io_flags=raw_flags, sdk_packet_flags=f["io_flags"], synchronous_paging_flags=(raw_flags & 0x42 == 0x42) if raw_flags is not None else None,
                packet_value=link["packet_value"], file_object_value=link["file_object_value"])


def measure(sdk_query, native_query, common, disk_result, window):
    result = dict(status="disk_measurement_unavailable", sdk_query=None, native_pages=[], summary=None)
    if disk_result["status"] != "measured":
        return result
    requests = disk_result["summary"]["requests"]
    if not requests:
        result.update(status="no_disk_requests", summary=dict(disk_requests=0, disk_rows_without_file_context=[], contexts=[]))
        return result
    if len(requests) > LIMIT:
        result["status"] = "file_context_limit"
        return result
    q = sdk_query()
    result["sdk_query"] = q
    if q["page"] is None or q["reader"]["exit_code"] != 0:
        result["status"] = "file_sdk_unavailable"
        return result
    try:
        links = candidates(q["page"], common, disk_result)
        contexts = []
        for i in range(0, len(links), LIMIT//4):
            batch = links[i:i+LIMIT//4]
            records = sorted({n for file, disk, _ in batch for n in locations(file, disk)})
            query = native_query(records)
            result["native_pages"].append(query)
            rows = check_page(query, records, common)
            for f, d, link in batch:
                contexts.append(bind(f, d, link, rows, q["page"]["clock"], window))
        missing = sorted({d["table_row"] for d in requests} - {c["disk_table_row"] for c in contexts})
        result.update(status="compared", summary=dict(disk_requests=len(requests), disk_rows_without_file_context=missing, contexts=contexts))
    except Unavailable as exc:
        result["status"] = str(exc)
    except (ValueError, TypeError, KeyError, RecursionError):
        result["status"] = "inconsistent_file_evidence"
    return result
