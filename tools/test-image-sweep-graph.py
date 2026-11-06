"""Independent provenance, byte-range, pagination and isolation checks for sweep graphs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    executable, fixtures = str(args.exe.resolve()), args.fixtures.resolve()
    checks = 0

    def check(ok, reason):
        nonlocal checks
        checks += 1
        assert ok, reason

    def run(path, depth=8, limit=128, cursor="", node="", budget=1000, expected=0):
        if args.cli:
            command = [executable, "--offline", "!kmon", "graph", str(path), "/json",
                       "/depth", str(depth), "/limit", str(limit), "/budget-ms", str(budget)]
            if cursor:
                command += ["/cursor", cursor]
            if node:
                command += ["/node", node]
        else:
            command = [executable, "--graph", str(path), str(depth), str(limit), cursor, node, str(budget)]
        result = subprocess.run(command, capture_output=True, timeout=60,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        check(result.returncode == expected and not result.stderr, "graph exit and structured diagnostics")
        value = json.loads(result.stdout.decode("utf-8-sig"))
        check(value["schema"] == "kn.image_sweep_graph.v1", "distinct graph contract")
        check((value["status"] == "ok") == (expected == 0), "no false query success")
        return value

    def read(path):
        return json.loads(path.read_text(encoding="utf-8-sig"))

    def write_envelope(path, value, key):
        payload = json.dumps(value["payload"], ensure_ascii=False, separators=(",", ":"))
        value[key] = hashlib.sha256(payload.encode()).hexdigest()
        path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    def copy_fixture():
        root = fixtures / ("graph-negative-" + uuid.uuid4().hex)
        check(root.resolve().is_relative_to(fixtures), "mutation stays in owned fixture directory")
        shutil.copytree(fixtures / "sweep_clean", root)
        return root, root / "image-sweeps" / "sweep-7-1.knsweep"

    expected = {
        "sweep_clean": (8192, 0, 0, 0), "sweep_modified": (8192, 1, 0, 0),
        "sweep_excluded": (8184, 0, 8, 0), "sweep_gap": (4096, 0, 0, 4096),
        "sweep_interrupted": (4096, 0, 0, 4096), "sweep_secondary": (8192, 0, 0, 0),
        "sweep_unstable": (4096, 0, 0, 0), "sweep_raw_lost": (8192, 0, 0, 0),
    }
    clean = None
    for name, counts in expected.items():
        root = fixtures / name
        path = root / "image-sweeps" / "sweep-7-1.knsweep"
        document = read(path)
        membership, identity = document["payload"], document["payload"]["sweep"]
        graph = run(path)
        check(not (root / "original.exe").exists(), "graph survives original target and reference removal")
        check(graph == run(path), "graph and IDs deterministic across process restart")
        check(graph["context"]["target"] == identity, "exact original target identity preserved")
        check(graph["image_verification_replayed"] and graph["graph_status"] == "materialized", "comparison executed before graph")
        for key in ("cross_source_joins", "live_reads", "collector_authenticated", "atomic_snapshot", "execution_observed",
                    "writer_attributed", "approved_reference", "complete_system_inventory"):
            check(graph[key] is False, "preserved graph trust limit " + key)
        check(graph["query_budget_scope"] == "materialized_traversal_only", "query budget is not a file IO deadline")
        assessment = graph["assessment"]
        canonical_proof = json.dumps(assessment, ensure_ascii=False, separators=(",", ":"))
        digest_input = (graph["policy"] + ":" + document["manifest_sha256"] + ":" +
                        hashlib.sha256(canonical_proof.encode()).hexdigest())
        check(hashlib.sha256(digest_input.encode()).hexdigest() == graph["graph_digest"], "independent graph identity")
        check(tuple(int(assessment[k]) for k in ("compared_bytes", "changed_bytes", "excluded_bytes", "unobserved_bytes")) == counts,
              "graph does not turn absent bytes into matching bytes")
        check(int(assessment["unreadable_bytes"]) == (4096 if name == "sweep_unstable" else 0), "unstable comparison stays unreadable")
        if name == "sweep_raw_lost":
            check(graph["context"]["publication_membership"]["raw_publication_failures"] == "2" and
                  not assessment["whole_sweep_complete"], "lost raw archives remain distinct from replayed recipe inputs")
        nodes = {n["id"]: n for n in graph["nodes"]}
        check(len(nodes) == len(graph["nodes"]) and graph["root"] in nodes, "unique nodes and resolvable root")
        check(len({e["id"] for e in graph["edges"]}) == len(graph["edges"]), "unique directed edges")
        check(int(graph["total_records"]) == len(nodes) + len(graph["edges"]), "query records distinct from target coverage")
        artifacts = {"manifest:" + document["manifest_sha256"]: document}
        intervals = {0: (int(identity["started_tick"]), int(membership["last_ended_tick"]))}
        for row in membership["slices"]:
            intervals[int(row["ordinal"])] = (int(row["started_tick"]), int(row["ended_tick"]))
            for extension, kind, digest_key in ((".knslice", "recipe", "recipe_sha256"), (".knreads", "raw", "raw_payload_sha256")):
                if kind == "raw" and not row["raw_written"]:
                    continue
                artifacts[kind + ":" + row[digest_key]] = read(root / "image-reads" / f"reads-7-{row['read_set_id']}{extension}")
            reference = root / "image-references" / (row["reference_sha256"] + ".knblob")
            check(hashlib.sha256(reference.read_bytes()).hexdigest() == row["reference_sha256"], "reference evidence is actual retained content")
            artifacts["reference:" + row["reference_sha256"]] = None
        for entry in graph["nodes"] + graph["edges"]:
            provenance = entry["provenance"]
            check(provenance["evidence_id"] in artifacts, "every graph element cites exact retained evidence")
            check((int(provenance["started_tick"]), int(provenance["ended_tick"])) == intervals[int(provenance["slice_ordinal"])],
                  "every element preserves original observation interval")
            check(provenance["context_ref"] == "#/context" and provenance["interval_semantics"] == "observation_window_not_mapping_lifetime",
                  "interval is not an inferred mapping lifetime")
            pointer = provenance["json_pointer"]
            artifact = artifacts[provenance["evidence_id"]]
            if artifact is not None:
                check(pointer.startswith("/payload"), "JSON evidence pointer is scoped")
                for component in pointer.split("/")[1:]:
                    artifact = artifact[int(component)] if isinstance(artifact, list) else artifact[component]
                check(artifact is not None, "evidence JSON pointer resolves")
            else:
                check(pointer == "", "binary reference has no invented JSON pointer")
        for edge in graph["edges"]:
            check(edge["from"] in nodes and edge["to"] in nodes and edge["kind"] == "derived_from", "only supported provenance edges")
        ranges = [n for n in nodes.values() if n["kind"] == "executable_range_comparison"]
        check(sum(n["kind"] == "read_archive" for n in nodes.values()) == sum(row["raw_written"] for row in membership["slices"]),
              "unpublished raw archives have no retained evidence nodes")
        check(len(ranges) == sum(int(r["range_count"]) for r in membership["slices"]), "one comparison node per executed range")
        observed_counts = tuple(sum(int(n["details"][k]) for n in ranges) for k in ("compared_bytes", "changed_bytes", "excluded_bytes"))
        check(observed_counts == counts[:3], "independent per-range accounting")
        for node in ranges:
            detail = node["details"]
            index = int(detail["schedule_range_index"])
            check(int(node["address"]) == int(identity["image_base"]) + 4096 * (index + 1) and node["length"] == "4096",
                  "actual executable address and size, not a coalesced image lifetime")
            if name == "sweep_unstable" and index == 0:
                check(detail["target_reference_qualified"] and detail["unreadable_bytes"] == "4096" and
                      node["state"] == "inconclusive", "unstable original reads cannot produce a graph match")
            else:
                check(detail["target_reference_qualified"] and detail["unreadable_bytes"] == "0", "owned fixture qualified comparison")
            changes = detail["changed_ranges"]
            if name == "sweep_modified" and index == 0:
                check(changes == [{"address": str(int(identity["image_base"]) + 0x1050), "length": "1"}] and
                      node["state"] == "changed_bytes_established", "independent single-byte modification address")
            else:
                check(not changes, "no invented changed ranges")
            if name == "sweep_excluded" and index == 0:
                check(detail["excluded_ranges"] == [{"address": str(int(identity["image_base"]) + 0x1100), "length": "8"}] and
                      node["state"] == "incomplete_comparison", "loader exclusion not interpreted as clean match")
        if name == "sweep_clean":
            clean = graph

    path = fixtures / "sweep_clean" / "image-sweeps" / "sweep-7-1.knsweep"
    first = page = run(path, limit=2)
    node_ids, edge_ids = [], []
    while True:
        node_ids.extend(n["id"] for n in page["nodes"])
        edge_ids.extend(e["id"] for e in page["edges"])
        check(len(page["nodes"]) + len(page["edges"]) <= 2, "shared node and edge page limit")
        check(len(node_ids) + len(edge_ids) <= int(first["total_records"]), "cursor makes bounded progress")
        if page["next_cursor"] is None:
            break
        page = run(path, limit=2, cursor=page["next_cursor"])
    check(set(node_ids) == {n["id"] for n in clean["nodes"]} and len(node_ids) == len(set(node_ids)), "complete node pagination")
    check(set(edge_ids) == {e["id"] for e in clean["edges"]} and len(edge_ids) == len(set(edge_ids)), "complete edge pagination")
    for options in ({"limit": 3}, {"depth": 7, "limit": 2}, {"node": node_ids[-1], "limit": 2}):
        stale = run(path, cursor=first["next_cursor"], expected=1, **options)
        check(stale["status"] == "stale_or_invalid_cursor" and not stale["nodes"] and not stale["edges"], "cursor bound to exact query")
    empty = run(path, depth=0)
    check(len(empty["nodes"]) == 1 and not empty["edges"] and empty["assessment"] == clean["assessment"], "depth does not change observation coverage")
    deferred = run(path, budget=0, expected=1)
    check(deferred["status"] == "query_budget_deferred" and not deferred["nodes"] and deferred["total_records"] is None,
          "no empty successful traversal on time budget")

    for mutation in ("missing_raw", "missing_recipe", "corrupt_reference", "rehashed_verdict", "oversized_graph", "identity_reuse"):
        root, path = copy_fixture()
        document = read(path)
        p = document["payload"]
        if mutation in ("missing_raw", "missing_recipe"):
            extension = ".knreads" if mutation == "missing_raw" else ".knslice"
            (root / "image-reads" / ("reads-7-1" + extension)).unlink()
        elif mutation == "corrupt_reference":
            blob = next((root / "image-references").glob("*.knblob"))
            content = bytearray(blob.read_bytes()); content[-1] ^= 1; blob.write_bytes(content)
        elif mutation == "rehashed_verdict":
            recipe_path = root / "image-reads" / "reads-7-1.knslice"
            recipe = read(recipe_path); recipe["payload"]["recorded_result"] = []
            write_envelope(recipe_path, recipe, "recipe_sha256")
            p["slices"][0]["recipe_sha256"] = recipe["recipe_sha256"]
        elif mutation == "oversized_graph":
            p["sweep"]["total_ranges"], p["sweep"]["expected_bytes"] = "253", str(253 * 4096)
            p["slices"] = [p["slices"][-1]]
            p["slices"][0].update(ordinal="1", start_range="0", range_count="253")
            p["observed_slices"] = p["retained_entries"] = "1"
        else:
            p["sweep"]["boot_id"], p["sweep"]["creation_time"] = "synthetic:another-boot", "2"
            for row in p["slices"]:
                raw_path = root / "image-reads" / f"reads-7-{row['read_set_id']}.knreads"
                raw = read(raw_path)
                raw["payload"]["boot_id"], raw["payload"]["creation_time"] = "synthetic:another-boot", "2"
                write_envelope(raw_path, raw, "payload_sha256")
                row["raw_payload_sha256"] = raw["payload_sha256"]
        write_envelope(path, document, "manifest_sha256")
        graph = run(path, expected=0 if mutation == "identity_reuse" else 1)
        if mutation == "identity_reuse":
            check(not ({n["id"] for n in graph["nodes"]} & set(node_ids)), "same PID/VA/reference bytes never join another declared boot or generation")
            stale = run(path, limit=2, cursor=first["next_cursor"], expected=1)
            check(stale["status"] == "stale_or_invalid_cursor", "old cursor cannot traverse changed evidence")
        else:
            check(not graph["nodes"] and not graph["edges"] and graph["assessment"] is None and not graph["image_verification_replayed"],
                  "failed admission/replay exposes neither graph nor assessment")
            if mutation == "oversized_graph":
                check(graph["status"] == "graph_budget_exceeded", "bounded graph preflight is explicit")
    print(f"Image sweep graph oracle passed: {checks} checks; cases={len(expected)}; cli={args.cli}")


if __name__ == "__main__":
    main()
