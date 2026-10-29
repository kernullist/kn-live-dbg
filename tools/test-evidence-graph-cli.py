"""Check retained graph queries through the public, driver-free CLI."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    count = 0

    def check(ok, message):
        nonlocal count
        if not ok:
            raise AssertionError(message)
        count += 1

    def run(path, *options, expected=0, structured=True):
        result = subprocess.run(
            [str(args.exe.resolve()), "--offline", "!kmon", "graph", str(path), *options],
            capture_output=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        check(result.returncode == expected, "graph command exit status: " + result.stderr.decode("utf-8", errors="replace"))
        check(b"preflight checks" not in result.stdout and b"must run elevated" not in result.stderr,
              "graph command precedes live startup")
        if not structured:
            return result
        check(not result.stderr, "structured graph writes no side-channel diagnostics")
        data = json.loads(result.stdout.decode("utf-8-sig"))
        check(data["schema"] == "kn.evidence_graph.v1", "graph schema is versioned")
        return data

    path = args.fixtures / "graph.kncase"
    retained = json.loads(path.read_text(encoding="utf-8-sig"))
    full = run(path, "/depth", "8", "/limit", "128", "/json")
    check(full["status"] == "ok" and full["graph_status"] == "materialized" and int(full["total_records"]) == 12,
          "known fixture has six nodes and six edges")
    check(full == run(path, "/depth", "8", "/limit", "128", "/json"), "fresh processes reconstruct identical graph")
    check(full["context"]["original_comparison_coverage"] == retained["payload"]["observation_coverage"] and
          full["context"]["original_receipt"] == retained["payload"]["receipt"], "receipt and coverage survive graph projection")
    check(full["context"]["state"] == "historical" and full["context"]["layout_identity"] == "unavailable" and
          full["context"]["capture_clock"] == "collector_monotonic_ms", "graph preserves time and layout qualification")
    for field in ("live_reads", "cross_source_joins", "collector_authenticated", "complete_system_inventory",
                  "execution_observed", "image_verification_replayed"):
        check(full[field] is False, "graph preserves " + field + " boundary")
    check(full["query_budget_scope"] == "materialized_traversal_only", "time budget does not claim to bound file I/O")
    nodes = {node["id"]: node for node in full["nodes"]}
    for edge in full["edges"]:
        check(edge["from"] in nodes and edge["to"] in nodes and edge["context_ref"] == "#/context" and
              edge["kind"] in ("derived_from", "references"), "every edge has resolvable typed endpoints and context")
        check(edge["evidence_id"] == retained["payload_sha256"] and edge["receipt_id"] == "1",
              "each edge retains exact evidence and receipt identity")
        for span_ref in edge["span_refs"]:
            source, ordinal = span_ref.split("#span:")
            check(source == "bundle:" + retained["payload_sha256"] and
                  retained["payload"]["spans"][int(ordinal)], "edge evidence reference resolves to a retained span")
    static = [edge for edge in full["edges"] if edge["kind"] == "references"]
    check(len(static) == 1 and static[0]["basis"] == "reconstructed_static_pointer" and
          nodes[static[0]["from"]]["address"] == "73728" and nodes[static[0]["to"]]["address"] == "69632",
          "saved pointer bytes establish the expected reference direction")
    first = run(path, "/limit", "2", "/depth", "8")
    page = first
    seen_nodes, seen_edges = [], []
    while True:
        seen_nodes.extend(node["id"] for node in page["nodes"])
        seen_edges.extend(edge["id"] for edge in page["edges"])
        check(len(seen_nodes) + len(seen_edges) <= int(first["total_records"]), "continuation makes bounded progress")
        check(len(page["nodes"]) + len(page["edges"]) <= 2, "shared page limit includes nodes and edges")
        if page["next_cursor"] is None:
            break
        page = run(path, "/limit", "2", "/depth", "8", "/cursor", page["next_cursor"])
    check(len(seen_nodes) == len(set(seen_nodes)) == len(nodes) and set(seen_nodes) == set(nodes) and
          len(seen_edges) == len(set(seen_edges)) == len(full["edges"]), "fresh-process pages neither omit nor duplicate records")
    for options in (("/limit", "3", "/depth", "8"), ("/limit", "2", "/depth", "7"),
                    ("/limit", "2", "/depth", "8", "/node", static[0]["from"])):
        stale = run(path, *options, "/cursor", first["next_cursor"], expected=1)
        check(stale["status"] == "stale_or_invalid_cursor" and stale["nodes"] == [] and stale["total_records"] is None,
              "changed query cannot reuse continuation or report an empty success")
    zero = run(path, "/node", static[0]["from"], "/depth", "0")
    check([node["id"] for node in zero["nodes"]] == [static[0]["from"]] and zero["edges"] == [], "explicit root respects depth zero")
    deferred = run(path, "/budget-ms", "0", expected=1)
    check(deferred["status"] == "query_budget_deferred" and not deferred["nodes"] and not deferred["edges"] and
          deferred["total_records"] is None, "exhausted budget is not complete absence")
    check(run(path, "/node", "unknown", expected=1)["status"] == "node_not_found", "unknown node fails explicitly")
    for options in (("/limit", "0"), ("/limit", "129"), ("/depth", "9"), ("/depth", "-1"),
                    ("/budget-ms", "5001"), ("/limit", "18446744073709551616"),
                    ("/json", "/json"), ("/limit", "2", "/limit", "3"), ("/cursor",), ("/bogus",)):
        run(path, *options, expected=2, structured=False)
    absent = run(args.fixtures / "missing-graph.kncase", expected=1)
    check(absent["status"] == "unavailable" and absent["context"] is None and absent["total_records"] is None,
          "unavailable input cannot invent a source receipt")
    with tempfile.TemporaryDirectory(prefix="kn-graph-") as folder:
        root = Path(folder)
        alias = root / "same-evidence.kncase"
        alias.write_bytes(path.read_bytes())
        check(run(alias, "/depth", "8", "/limit", "128") == full, "file aliases retain content-scoped graph identity")
        legacy = json.loads(path.read_text(encoding="utf-8-sig"))
        del legacy["payload"]["receipt"]["reference"]["address_space"]
        payload = json.dumps(legacy["payload"], ensure_ascii=False, separators=(",", ":"))
        legacy["payload_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        legacy_path = root / "legacy.kncase"
        legacy_path.write_text(json.dumps(legacy, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        imported = run(legacy_path)
        check(imported["context"]["original_receipt"]["reference"]["address_space"]["legacy_assumed"] and
              imported["source_evidence_id"] == legacy["payload_sha256"] and imported["graph_digest"] != full["graph_digest"],
              "legacy normalization preserves original source digest and explicit paging assumption")
        changed = json.loads(path.read_text(encoding="utf-8-sig"))
        changed["payload"]["receipt"]["reference"]["create_time"] = "51"
        payload = json.dumps(changed["payload"], ensure_ascii=False, separators=(",", ":"))
        changed["payload_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        other = root / "reused.kncase"
        other.write_text(json.dumps(changed, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        reused = run(other, "/depth", "8", "/limit", "128")
        check(reused["graph_digest"] != full["graph_digest"] and
              not set(nodes).intersection(node["id"] for node in reused["nodes"]), "reused PID is a different scoped graph")
        check(run(other, "/limit", "2", "/depth", "8", "/cursor", first["next_cursor"], expected=1)["status"] ==
              "stale_or_invalid_cursor", "replacement bundle invalidates old continuation")
        corrupted = root / "corrupted.kncase"
        corrupted.write_bytes(path.read_bytes()[:-8])
        check(run(corrupted, expected=1)["status"] == "unavailable", "truncated evidence is rejected")
        oversize = root / "oversize.kncase"
        oversize.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        check(run(oversize, expected=1)["status"] == "unavailable", "materialization obeys source byte limit")
        wrong_extension = root / "copied.json"
        wrong_extension.write_bytes(path.read_bytes())
        check(run(wrong_extension, expected=1)["status"] == "unavailable", "only published bundle paths are accepted")
    print(f"[evidence.graph.cli] passed={count}")


if __name__ == "__main__":
    main()
