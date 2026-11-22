"""Compare a native ready-event batch with the three independent TraceProcessor CPU tables."""
from collections import Counter, defaultdict

from owned_module_benchmark import check, uint
from etl_activity_waits import tick
from etl_traceprocessor import verify_cpu_modules


def key(origin):
    r = origin["selected_ready"]
    return f'{r["payload_tid"]},{r["cpu"]},{r["raw_timestamp"]}'


def correlate(doc, origins, source_sha256, source_bytes):
    check(doc["schema"] == "kn.traceprocessor_ready_contexts.v1" and type(doc["complete"]) is bool, "invalid CPU projection")
    keys = Counter(map(key, origins))
    check(doc["source_sha256"] == source_sha256 and uint(doc["source_bytes"]) == source_bytes and
          doc["requested_keys"] == list(keys), "CPU projection input or filter mismatch")
    verify_cpu_modules(doc["loaded_processing_modules"])
    tables = {}
    for name, total in (("ready_rows", "ready_total"), ("activity_rows", "activity_total"), ("cpu_slices", "slice_total")):
        rows = defaultdict(list)
        seen = set()
        check(type(doc[name]) is list and len(doc[name]) <= 2 * len(keys), "invalid projection extent")
        for row in doc[name]:
            n = uint(row["row"], uint(doc[total]))
            identity = (row["key"], n) if name == "cpu_slices" else n
            check(n and row["key"] in keys and identity not in seen, "invalid SDK table row")
            for field in ("source_tid", "source_pid", "target_tid", "target_pid"):
                if field in row and row[field] is not None:
                    uint(row[field], 0xffffffff)
            if name == "ready_rows":
                check(type(row["dpc"]) is bool and type(row["direct"]) is bool, "invalid SDK ready flags")
            else:
                uint(row["switch_in_cpu"] if name == "activity_rows" else row["cpu"], 65535)
                for field in ("switch_in", "switch_out", "source_created", "source_exited", "previous_out"):
                    if field in row and row[field] is not None:
                        tick(row[field])
            seen.add(identity)
            rows[row["key"]].append(row)
        tables[name] = rows
    results = []
    for origin in origins:
        k = key(origin)
        r, dispatch, edge = origin["selected_ready"], origin["target_dispatch"], origin["relationship"]
        ready, acts, slices = (tables[name][k] for name in ("ready_rows", "activity_rows", "cpu_slices"))
        timed = dispatch["relation"] in ("waiting_ready_switch_in", "ready_switch_in")
        actor = edge["relation"] == "readying_thread_context"
        scope = "readying_thread_and_source_slice" if actor else "target_dispatch" if timed else "ready_event"
        matches = len(ready) == 1 and keys[k] == 1 and doc["complete"]
        if matches:
            matches = ready[0]["dpc"] is origin["executing_dpc"] and ready[0]["direct"] is origin["direct_switch_attempt"]
        if matches and timed:
            a, b = dispatch["switch_out"], dispatch["switch_in"]
            matches = len(acts) == 1 and (acts[0]["previous_out"], acts[0]["switch_in"], acts[0]["switch_in_cpu"],
                acts[0]["target_tid"], acts[0]["target_pid"]) == (
                a["raw_timestamp"], b["raw_timestamp"], b["cpu"], r["payload_tid"], dispatch["thread_evidence"]["paired_record_pid"])
        if matches and actor:
            source = origin["source_cpu_context"]
            tid, pid = edge["readying_tid"], edge["readying_pid"]
            matches = len(slices) == 1 and all((row["source_tid"], row["source_pid"]) == (tid, pid)
                                               for row in (ready[0], acts[0], slices[0]))
            matches = matches and (slices[0]["cpu"], slices[0]["switch_in"], slices[0]["switch_out"]) == (
                r["cpu"], source["switch_in"]["raw_timestamp"], source["switch_out"]["raw_timestamp"])
            at = int(r["raw_timestamp"])
            matches = matches and (acts[0]["source_created"] is None or int(acts[0]["source_created"]) < at) and (
                acts[0]["source_exited"] is None or at < int(acts[0]["source_exited"]))
        results.append(dict(ready_record=r["record_ordinal"], scope=scope, status="matched" if matches else "unconfirmed",
                            ready_table_rows=[x["row"] for x in ready], activity_table_rows=[x["row"] for x in acts],
                            cpu_slice_rows=[x["row"] for x in slices]))
    return results


class TableBindings:
    """Keep SDK table coordinates consistent across independently read pages of one ETL."""
    def __init__(self):
        self.scope = None
        self.bindings = ({}, {}, {})

    def check(self, doc, origins, results):
        scope = (doc["ready_total"], doc["activity_total"], doc["slice_total"], tuple(doc["loaded_processing_modules"]))
        if self.scope is None:
            self.scope = scope
        check(self.scope == scope, "SDK table scope changed between pages")
        for row, origin in zip(results, origins, strict=True):
            if row["status"] != "matched":
                continue
            ready = origin["selected_ready"]["record_ordinal"]
            claims = [(0, row["ready_table_rows"][0], ready)]
            if row["scope"] != "ready_event":
                claims.append((1, row["activity_table_rows"][0], ready))
            if row["scope"] == "readying_thread_and_source_slice":
                start = origin["source_cpu_context"]["switch_in"]["record_ordinal"]
                claims.append((2, row["cpu_slice_rows"][0], start))
            for table, index, record in claims:
                check(self.bindings[table].setdefault(index, record) == record, "SDK row identifies two original events")
