"""Compare a marked thread's hard faults, disk reads and enclosing file reads in one ETL."""
from collections import defaultdict

from etl_activity_waits import tick
from etl_disk_waits import STATES, Unavailable
from etl_fault_window import fault_union
from etl_file_operations import LIMIT, check_page, relation
from owned_module_benchmark import check, decimal, uint


def window_faults(query, common, window):
    p = query["page"]
    if p is None or query["reader"]["exit_code"] != 0 or p["status"] != "read" or p["activity_window"]["status"] != "measured":
        raise Unavailable("fault_window_unavailable")
    w = p["activity_window"]
    check(p["schema"] == "kn.etl_hard_faults.v3" and p["provider_guid"] == "3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c" and
          (uint(p["event_id"]), uint(p["opcode"]), uint(p["version"])) == (0, 32, 2) and uint(p["after"]) == 0 and p["next_after"] is None and
          uint(p["unsupported_hard_fault_records"]) == 0 and all(p[k] == common[k] for k in ("source_sha256", "source_bytes", "clock",
          "log_header", "records_seen", "buffers_processed", "buffer_comparison", "loss_marker_records")) and
          all(w[k] == window[k] for k in ("start", "stop", "thread_evidence", "window_ticks")), "different fault source, markers or lifetime")
    fault_union(p, w, tick(w["start"]["raw_timestamp"]), tick(w["stop"]["raw_timestamp"]))
    return p["hard_faults"]


def byte_ranges(file, fault):
    fa, size = decimal(file["file_offset"]), decimal(file["actual_bytes"])
    at, length = decimal(fault["read_offset"]), uint(fault["byte_count"], 0xffffffff)
    if (file["ntstatus"] != 0 or not size or not length or size > decimal(file["requested_bytes"]) or
            max(fa+size, at+length) > 1 << 64):
        return "unavailable"
    if (fa, size) == (at, length):
        return "equal"
    if fa+size <= at or at+length <= fa:
        return "disjoint"
    if fa <= at and at+length <= fa+size:
        return "file_contains_fault"
    if at <= fa and fa+size <= at+length:
        return "fault_contains_file"
    return "partial_overlap"


def object_values(a, b):
    if a["pointer_bytes"] != b["pointer_bytes"]:
        return "different_pointer_width"
    return relation(a["file_object_label"], b["file_object_label"])


def field_match(*conditions):
    if False in conditions:
        return False
    return None if None in conditions else True


def state_ticks(spans, pieces):
    merged = []
    for lo, hi in sorted(spans):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    total = sum(b-a for a, b in merged)
    amounts = dict.fromkeys(STATES, 0)
    i, previous = 0, None
    for p in pieces:
        a, b = tick(p["start_qpc"]), tick(p["stop_qpc"])
        check(a < b and (previous is None or previous <= a), "overlapping scheduler pieces")
        previous = b
        while i < len(merged) and merged[i][1] <= a:
            i += 1
        j = i
        while j < len(merged) and merged[j][0] < b:
            lo, hi = merged[j]
            amounts[p["state"]] += min(b, hi)-max(a, lo)
            j += 1
    check(sum(amounts.values()) == total, "fault/disk overlap missing from the scheduler timeline")
    return dict(total=str(total), **{k: str(v) for k, v in amounts.items()})


def selection(faults, reads, files, window):
    left, right = (tick(window[k]["raw_timestamp"]) for k in ("start", "stop"))
    work, paired_rows, unpaired_faults = [], set(), []
    comparisons = 0
    for f in faults:
        seen = False
        for d in reads:
            lo = max(left, tick(f["initial_time_raw"]), tick(d["start_qpc"]))
            hi = min(right, tick(f["raw_timestamp"]), tick(d["stop_qpc"]))
            if lo >= hi:
                continue
            seen = True
            paired_rows.add(d["table_row"])
            for file in files.get(d["table_row"], [None]):
                comparisons += 1
                if comparisons > LIMIT:
                    raise Unavailable("fault_io_comparison_limit")
                work.append((f, d, file, (lo, hi)))
        if not seen:
            unpaired_faults.append(f["record_ordinal"])
            work.append((f, None, None, None))
    return work, unpaired_faults, sorted({r["table_row"] for r in reads} - paired_rows)


def batches(work):
    group, numbers = [], set()
    for item in work:
        fault, disk, file, _ = item
        needed = {fault["record_ordinal"]}
        if disk:
            needed.update((disk["init_record"], disk["complete_record"]))
        if file:
            needed.update((file["file_start_record"], file["file_end_record"]))
        if len(numbers | needed) > LIMIT:
            yield group, sorted(numbers)
            group, numbers = [], set()
        group.append(item)
        numbers.update(needed)
    # Even an empty selection checks the native reader's capability and whole-source fault count.
    yield group, sorted(numbers)


def check_fault(f, row):
    uint(f["byte_count"], 0xffffffff)
    check(uint(f["pointer_bytes"]) in (4, 8) and row["layer"] == "hard_fault" and
          row["faulting_tid"] == f["faulting_thread_id"] and row["initial_qpc"] == f["initial_time_raw"] and
          all(row[k] == f[k] for k in ("raw_timestamp", "pointer_bytes", "logger_id", "byte_count", "read_offset")) and
          f["timing_status"] == "ordered_qpc" and decimal(f["elapsed_qpc_ticks"]) == tick(row["raw_timestamp"])-tick(row["initial_qpc"]),
          "original hard-fault fields differ")


def compare_disk(f, row, d, table, native, span):
    a, b = (native[d[k]] for k in ("init_record", "complete_record"))
    check(a["layer"] == b["layer"] == "disk" and (a["opcode"], b["opcode"]) == (12, 10) and
          a["logger_id"] == b["logger_id"] == row["logger_id"] and a["pointer_bytes"] == b["pointer_bytes"] and
          a["issuing_tid"] == b["issuing_tid"] == row["faulting_tid"] and (a["raw_timestamp"], b["raw_timestamp"]) == (d["start_qpc"], d["stop_qpc"]) and
          relation(a["packet_label"], b["packet_label"]) == "equal" and b["transfer_bytes"] == decimal(table["size_bytes"]),
          "original disk read differs from the qualified request")
    inside = (tick(row["initial_qpc"]) <= tick(a["raw_timestamp"]) and tick(b["raw_timestamp"]) <= tick(row["raw_timestamp"]) and
              b["record_ordinal"] < row["record_ordinal"])
    obj = object_values(row, b)
    size_matches = b["transfer_bytes"] == row["byte_count"] if b["transfer_bytes"] and row["byte_count"] else None
    return dict(fault_ordinal=f["fault_ordinal"], fault_record=row["record_ordinal"], disk_table_row=d["table_row"],
                disk_init_record=a["record_ordinal"], disk_completion_record=b["record_ordinal"], overlap_start_qpc=str(span[0]),
                overlap_stop_qpc=str(span[1]), disk_inside_fault=inside, fault_disk_object_value=obj, disk_transfer_bytes=b["transfer_bytes"],
                disk_read_fields_match=field_match(inside, {"equal": True, "different": False}.get(obj), size_matches))


def compare_file(file, d, row, native):
    a, b = (native[file[k]] for k in ("file_start_record", "file_end_record"))
    done = native[d["complete_record"]]
    check(a["layer"] == b["layer"] == "file" and (a["opcode"], b["opcode"]) == (67, 76) and
          a["logger_id"] == b["logger_id"] == row["logger_id"] and a["pointer_bytes"] == b["pointer_bytes"] == done["pointer_bytes"] and
          a["issuing_tid"] == row["faulting_tid"] and relation(a["packet_label"], b["packet_label"]) == "equal" and
          object_values(a, done) == file["file_object_value"] and tick(a["raw_timestamp"]) == tick(d["start_qpc"])-decimal(file["before_disk_ticks"]) and
          tick(b["raw_timestamp"]) == tick(d["stop_qpc"])+decimal(file["after_disk_ticks"]) and
          all(a[k] == file[k] for k in ("file_offset", "requested_bytes", "io_flags")) and b["ntstatus"] == file["ntstatus"] and
          b["extra_info"] == file["actual_bytes"], "original file read differs from the qualified file operation")
    inside = (tick(row["initial_qpc"]) <= tick(a["raw_timestamp"]) and tick(b["raw_timestamp"]) <= tick(row["raw_timestamp"]) and
              b["record_ordinal"] < row["record_ordinal"])
    obj, ranges = object_values(row, a), byte_ranges(file, row)
    return dict(file_table_row=file["file_table_row"], file_start_record=a["record_ordinal"], file_end_record=b["record_ordinal"],
                file_inside_fault=inside, fault_file_object_value=obj, file_byte_range=ranges,
                file_read_fields_match=field_match(inside, {"equal": True, "different": False}.get(obj), file["synchronous_paging_flags"],
                                                   file["ntstatus"] == 0, None if ranges == "unavailable" else ranges == "equal"))


def measure(fault_query, records_query, common, window, disks, files):
    query = fault_query()
    result = dict(status="native_window_unavailable", fault_query=query, native_pages=[], summary=None)
    if window is None:
        return result
    try:
        faults = window_faults(query, common, window)
        if disks["status"] != "measured":
            raise Unavailable("disk_measurement_unavailable")
        reads = [r for r in disks["summary"]["requests"] if r["operation"] == "read"]
        tables = {r["table_row"]: r for r in disks["sdk_query"]["page"]["activities"]}
        file_coverage = files["status"] in ("compared", "no_disk_requests")
        by_disk = defaultdict(list)
        if file_coverage:
            for c in files["summary"]["contexts"]:
                if c["operation"] == "read":
                    by_disk[c["disk_table_row"]].append(c)
        work, unpaired, missing = selection(faults, reads, by_disk, window)
        comparisons = {}
        for group, selectors in batches(work):
            page = records_query(selectors)
            result["native_pages"].append(page)
            native = check_page(page, selectors, common, fault_page=query["page"])
            for fault, d, file, span in group:
                row = native[fault["record_ordinal"]]
                check_fault(fault, row)
                if d is None:
                    continue
                key = (row["record_ordinal"], d["table_row"])
                disk = compare_disk(fault, row, d, tables[d["table_row"]], native, span)
                if key not in comparisons:
                    comparisons[key] = dict(disk, file_reads=[] if file_coverage else None)
                else:
                    check(all(comparisons[key][k] == v for k, v in disk.items()), "disk comparison changed across native pages")
                if file:
                    comparisons[key]["file_reads"].append(compare_file(file, d, row, native))
        rows = list(comparisons.values())
        pieces = disks["summary"]["overlaps"]
        def times(group):
            return state_ticks(((tick(r["overlap_start_qpc"]), tick(r["overlap_stop_qpc"])) for r in group), pieces)
        all_ticks = times(rows)
        fault_ticks = query["page"]["activity_window"]["fault_union_ticks"]
        remainder = decimal(fault_ticks) - decimal(all_ticks["total"])
        check(remainder >= 0, "disk overlap exceeds fault time in the activity")
        summary = dict(hard_faults=len(faults), disk_reads=len(reads), faults_without_disk_overlap=unpaired, disk_reads_without_fault_overlap=missing,
                       comparisons=rows, fault_union_ticks=fault_ticks, fault_ticks_without_disk_read=str(remainder),
                       disk_overlap_ticks=all_ticks, matching_disk_ticks=times(r for r in rows if r["disk_read_fields_match"]),
                       matching_file_ticks=times(r for r in rows if any(f["file_read_fields_match"] for f in r["file_reads"])) if file_coverage else None)
        result.update(status="compared", summary=summary)
    except Unavailable as exc:
        result["status"] = str(exc)
    except (ValueError, KeyError, TypeError, RecursionError):
        result["status"] = "inconsistent_fault_io_evidence"
    return result
