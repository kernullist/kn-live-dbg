"""Independent identity, interval, cursor and negative-join oracle on owned fixtures."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import uuid


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cli", type=Path)
    args = parser.parse_args()
    root = args.output.resolve() / ("run-" + uuid.uuid4().hex)
    root.mkdir()
    subprocess.run([str(args.exe.resolve()), "--fixtures", str(root)], check=True, timeout=30)
    original = [root / (str(i) + ".kncase") for i in range(1, 4)]
    documents = [json.loads(p.read_bytes()) for p in original]
    original_bytes = [p.read_bytes() for p in original]
    checks = 0

    def check(condition, label):
        nonlocal checks
        if not condition:
            raise AssertionError(label)
        checks += 1

    def query(paths, gap=30000, limit=64, cursor="", budget=1000, expected=0, cli=False):
        if cli:
            command = [str(args.cli.resolve()), "--offline", "!kmon", "relate", *map(str, paths),
                       "/gap-ms", str(gap), "/limit", str(limit), "/budget-ms", str(budget), "/json"]
            if cursor:
                command += ["/cursor", cursor]
        else:
            command = [str(args.exe.resolve()), "--query", str(gap), str(limit), cursor, str(budget), *map(str, paths)]
        result = subprocess.run(command, capture_output=True, timeout=30)
        check(result.returncode == expected and not result.stderr,
              f"query exit={result.returncode}, expected={expected}; " + result.stderr.decode("utf-8", "replace")[-1000:])
        return json.loads(result.stdout)

    def save(name, change, base=1):
        value = copy.deepcopy(documents[base])
        change(value)
        value["payload_sha256"] = sha(canonical(value["payload"]))
        path = root / (name + ".kncase")
        path.write_text(canonical(value), encoding="utf-8")
        return path

    full = query(original)
    check(full["schema"] == "kn.temporal_facts.v1" and full["status"] == "ok", "materialized contract")
    check(int(full["total_pairs"]) == 3 and int(full["supported_candidates_in_page"]) == 3, "all scoped pairs represented")
    check(full == query(original), "deterministic fresh-process reconstruction")
    reverse = query(original[::-1])
    check(reverse == full, "input ordering is not temporal ordering")
    observations = {row["id"]: row for row in full["observations"]}
    expected_ids = {"observation:" + sha(canonical(d)): d for d in documents}
    check(set(observations) == set(expected_ids), "independent content-bound observation IDs")
    expected_store = sha("kn.local_temporal_candidate.v1:" + "".join(
        k + ":" + expected_ids[k]["payload_sha256"] + ";" for k in sorted(expected_ids)))
    check(full["store_digest"] == expected_store, "independent membership identity")
    check(full["query_digest"] == sha(expected_store + ":30000:64"), "independent policy-query identity")
    for decision in full["decisions"]:
        a, b = observations[decision["left"]], observations[decision["right"]]
        check(a["evidence_id"] == "bundle_payload:" + expected_ids[a["id"]]["payload_sha256"], "resolvable original evidence")
        left_first = int(a["capture_end_tick"]) < int(b["capture_begin_tick"])
        earlier, later = (a, b) if left_first else (b, a)
        check(decision["recorded_order"] == ("left_before_right" if left_first else "right_before_left"), "recorded capture order")
        check(int(earlier["arrival_sequence"]) > int(later["arrival_sequence"]), "late arrival does not overwrite event order")
        check(int(decision["recorded_gap_ms"]) == int(later["capture_begin_tick"]) - int(earlier["capture_end_tick"]), "exact recorded gap")
        for key in ("mapping_lifetime_bound", "changed_between_established", "execution_established", "write_established", "causality_established"):
            check(decision[key] is False, "same address/generation/PFN does not imply " + key)

    mutations = [
        ("collector", lambda d: d["payload"]["origin"].update(collector_scope="d" * 32), "different_collector_namespace"),
        ("collection", lambda d: d["payload"].update(collection_id="other_collection"), "different_collector_namespace"),
        ("boot", lambda d: (d["payload"]["origin"].update(local_boot_id="d" * 32),
                            d["payload"]["receipt"]["reference"].update(boot_id="d" * 32)), "different_local_target_boot"),
        ("generation", lambda d: d["payload"]["receipt"]["reference"].update(create_time="51"), "different_target_process_generation"),
        ("pid", lambda d: d["payload"]["receipt"]["reference"].update(pid=56), "different_target_process_generation"),
        ("epoch", lambda d: d["payload"]["origin"].update(native_epoch="8"), "source_connection_changed"),
        ("object", lambda d: d["payload"]["receipt"]["reference"].update(eprocess="4096"), "matching_object_identity_assertions"),
        ("session", lambda d: d["payload"]["receipt"]["reference"].update(session_known=True, session_id=1), "matching_session_assertions"),
    ]
    for name, change, reason in mutations:
        path = save(name, change)
        report = query([original[0], path])
        decision = report["decisions"][0]
        check(decision["status"] != "supported" and reason in decision["contradictions"] + decision["unfulfilled_requirements"], name + " cannot join by equal PID/VA/PFN")

    known_a = save("known-a", lambda d: d["payload"]["receipt"]["reference"].update(eprocess="4096"), base=0)
    known_b = save("known-b", lambda d: d["payload"]["receipt"]["reference"].update(eprocess="8192"), base=2)
    unknown = query([known_a, original[1], known_b])
    check(int(unknown["supported_candidates_in_page"]) == 0, "unknown assertion cannot transitively bridge conflicting known identities")
    check(len(unknown["observations"]) == 3 and len(unknown["decisions"]) == 3, "conflicts preserve original observations and pair denominators")
    session_a = save("session-a", lambda d: d["payload"]["receipt"]["reference"].update(session_known=True, session_id=1), base=0)
    session_b = save("session-b", lambda d: d["payload"]["receipt"]["reference"].update(session_known=True, session_id=2), base=2)
    check("conflicting_session_assertions" in query([session_a, session_b])["decisions"][0]["contradictions"], "conflicting known sessions stay separate")
    address = save("address-contract", lambda d: d["payload"]["receipt"]["reference"]["address_space"].update(physical_bits="32"))
    check("different_address_contract" in query([original[0], address])["decisions"][0]["contradictions"], "address contracts are not inferred from equal VA")
    conflict = save("identity-conflict", lambda d: (d["payload"]["receipt"].update(current_disposition="identity_conflict"),
                                                  d["payload"]["receipt"]["reference"].update(id=0)))
    check("consistent_original_reference" in query([original[0], conflict])["decisions"][0]["unfulfilled_requirements"], "identity conflict cannot become a qualified candidate")

    def legacy(d):
        d["schema"] = "kmon.bundle.v1"
        d["payload"]["schema"] = "kmon.evidence.v1"
        d["payload"].pop("origin")
    legacy_path = save("legacy", legacy)
    report = query([original[0], legacy_path])
    check(report["decisions"][0]["status"] == "unfulfilled" and report["decisions"][0]["recorded_gap_ms"] is None, "legacy remains readable but gains no source or clock binding")
    legacy_address = save("legacy-without-address", lambda d: (legacy(d), d["payload"]["receipt"]["reference"].pop("address_space")))
    legacy_report = query([original[0], legacy_address])
    legacy_row = next(o for o in legacy_report["observations"] if o["origin"] is None)
    check(legacy_row["reference_representation"] == "normalized_legacy_compatible" and legacy_row["reference"]["address_space"]["legacy_assumed"] and
          legacy_report["decisions"][0]["status"] == "unfulfilled", "legacy descriptor normalization is explicit and never authorizes a join")

    close = query(original[:2], gap=9)
    check(close["decisions"][0]["status"] == "contradicted" and "outside_requested_recorded_gap" in close["decisions"][0]["contradictions"], "gap threshold does not alter evidence")
    check(query(original[:2], gap=10)["decisions"][0]["status"] == "supported", "inclusive exact gap boundary")
    check(close["decisions"][0]["id"] != query(original[:2], gap=10)["decisions"][0]["id"], "policy parameters version relation interpretation")
    overlap = save("overlap", lambda d: d["payload"].update(capture_started_ms="125", capture_ended_ms="130"))
    report = query([original[0], overlap], gap=0)
    check(report["decisions"][0]["recorded_order"] == "overlapping_recorded_intervals" and report["decisions"][0]["status"] == "supported", "overlap is partial order, not arbitrary before/after")

    for name, change in [
        ("bad-scope", lambda d: d["payload"]["origin"].update(collector_scope="unqualified")),
        ("missing-address-contract", lambda d: d["payload"]["receipt"]["reference"].pop("address_space")),
        ("wrong-clock", lambda d: d["payload"]["origin"].update(clock_domain="external_vm_tsc")),
        ("invented-auth", lambda d: d["payload"]["origin"].update(collector_authenticated=True)),
        ("bad-boot-binding", lambda d: d["payload"]["origin"].update(local_boot_id="f" * 32)),
        ("user-reader-kernel-identity", lambda d: d["payload"]["receipt"]["reference"].update(pid=0, address=str(0xffff800000011000), root=str(0xffff800000011000))),
        ("backward-capture", lambda d: d["payload"].update(capture_ended_ms="1")),
        ("overflow", lambda d: d["payload"]["origin"].update(native_epoch=str(2**64))),
    ]:
        path = save(name, change)
        report = query([original[0], path], expected=1)
        check(not report["observations"] and not report["decisions"] and report["status"] == "input_unavailable_or_corrupt", "invalid input never publishes partial joins: " + name)
    check(query([original[0], original[0]], expected=1)["status"] == "duplicate_observation", "duplicate evidence is not two observations")
    check(query(original, budget=0, expected=1)["status"] == "query_budget_deferred", "zero query budget explicit")
    first = query(original, limit=1)
    cursor = first["next_cursor"]
    pages = first["decisions"][:]
    while cursor:
        page = query(original, limit=1, cursor=cursor)
        pages += page["decisions"]
        cursor = page["next_cursor"]
    check([(d["left"], d["right"]) for d in pages] == [(d["left"], d["right"]) for d in full["decisions"]], "pagination preserves every pair exactly once")
    for kwargs in ({"gap":100}, {"limit":2}, {"cursor":first["next_cursor"] + "0"}, {"cursor":first["next_cursor"].rsplit(":",1)[0] + ":01"}):
        options = {"limit":1, "cursor":first["next_cursor"], **kwargs}
        check(query(original, expected=1, **options)["status"] == "stale_or_invalid_cursor", "cursor binds exact query and canonical offset")
    check(query([original[0], original[1], known_b], limit=1, cursor=first["next_cursor"], expected=1)["status"] == "stale_or_invalid_cursor", "changed source invalidates cursor")
    check(query([original[0], root / "missing.kncase"], expected=1)["status"] == "input_unavailable_or_corrupt", "missing input is not partial success")
    oversized = root / "oversized.kncase"
    oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    check(query([original[0], oversized], expected=1)["status"] == "input_unavailable_or_corrupt", "per-file byte limit")
    for action, expected in (("--cancel-load", "cancelled"), ("--cancel-query", "cancelled"), ("--zero-load-budget", "input_budget_deferred")):
        result = subprocess.run([str(args.exe.resolve()), action, *map(str, original)], capture_output=True, check=True, timeout=30)
        report = json.loads(result.stdout)
        check(report["status"] == expected and not report["decisions"] and not report["next_cursor"], "cooperative boundary: " + action)
    many = []
    for i in range(32):
        many.append(save("bounded-" + str(i), lambda d, i=i: d["payload"]["origin"].update(capture_id=f"{i + 1:032x}")))
    page = query(many, limit=128)
    returned, ids = 0, set()
    while True:
        check(int(page["total_pairs"]) == 496 and len(page["observations"]) == 32, "maximum membership denominator")
        check(int(page["supported_candidates_in_page"]) == int(page["returned_pairs"]), "same qualified context across bounded membership")
        returned += int(page["returned_pairs"])
        ids.update(d["id"] for d in page["decisions"])
        if not page["next_cursor"]:
            break
        page = query(many, limit=128, cursor=page["next_cursor"])
    check(returned == len(ids) == 496, "bounded maximum has no missing or repeated pairs")
    check(query(many + [original[0]], expected=1)["status"] == "invalid_input_scope", "above maximum membership rejected before loading")
    if args.cli:
        check(query(original, cli=True) == full, "actual offline CLI uses same original-bound policy")
        check(query(original, budget=0, expected=1, cli=True)["status"] == "query_budget_deferred", "actual CLI budget status")
        for parts in ([], [str(original[0])], [*map(str, original), "/gap-ms", "300001"], [*map(str, original), "/limit", "0"], [*map(str, original), "/json", "/json"]):
            result = subprocess.run([str(args.cli.resolve()), "--offline", "!kmon", "relate", *parts], capture_output=True, timeout=30)
            check(result.returncode == 2, "actual CLI grammar failure")
        unicode_path = root / "관측 한글.kncase"
        unicode_path.write_bytes(original[0].read_bytes())
        unicode_report = query([unicode_path, original[1]], cli=True)
        check(str(unicode_path) in [o["source_path"] for o in unicode_report["observations"]], "actual UTF-8 path roundtrip")
        check(unicode_report["store_digest"] == query(original[:2])["store_digest"], "path alias cannot alter source identity")
        for path in (original[0], legacy_path):
            result = subprocess.run([str(args.cli.resolve()), "--offline", "!kmon", "graph", str(path), "/json"], capture_output=True, timeout=30)
            report = json.loads(result.stdout)
            check(result.returncode == 0 and report["schema"] == "kn.evidence_graph.v1" and report["status"] == "ok", "single-bundle graph still accepts v1 and v2")
        child = subprocess.Popen([str(args.cli.resolve()), "--offline", "!kmon", "relate", *map(str, original)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            child.stdout.close()
            child.wait(timeout=30)
            check(child.returncode == 3, "actual CLI broken output exit")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=15)
            child.stderr.close()
    check([p.read_bytes() for p in original] == original_bytes, "original bytes unchanged")
    print(f"[temporal.facts] checks={checks} fixtures={root} cli={bool(args.cli)}")


if __name__ == "__main__":
    main()
