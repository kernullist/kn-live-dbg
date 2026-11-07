"""Independent truth and interval sweep for owned original IRP captures."""
from collections import Counter, defaultdict
import hashlib
import json


MEMBER = "irp_thread_list_member_observed"
OWNER = "irp_packet_owner_matches_thread_observed"
REGISTERED = "irp_completion_registration_observed"
COMPLETED = "irp_request_completion_observed"
CANCELLED = "irp_request_cancellation_observed"
EXECUTED = "irp_completion_execution_observed"
DEVICE_OWNER = "irp_device_driver_ownership_observed"
POLICIES = {MEMBER, OWNER, REGISTERED, COMPLETED, CANCELLED, EXECUTED, DEVICE_OWNER}
STATUSES = {"supported", "contradicted", "unfulfilled", "not_applicable"}
GATES = {"original_capture", "source_scope", "schema_image_binding", "request_invariants"}
EXTRA = {
    MEMBER: {"list_path_rechecked"}, OWNER: {"owner_field_matches_thread"},
    REGISTERED: {"typed_completion_slot", "completion_enabled", "completion_target_present"},
    COMPLETED: {"request_generation", "completion_event_and_outcome"},
    CANCELLED: {"request_generation", "cancellation_event_and_outcome"},
    EXECUTED: {"request_generation", "execution_event", "code_version_binding"},
    DEVICE_OWNER: {"device_pointer_read", "device_and_driver_lifetimes", "device_driver_owner_relation"},
}


def validate(raw, report, *, replay=False, reference_available=True):
    capture = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert report["schema"] == "kn.irp_claim_report.v1"
    assert report["registry"] == "kn.claim_registry.v1" and report["policy"] == "kn.irp_claim_policy.v1"
    assert report["capture_sha256"] == digest and report["source_id"] == capture["source_contract"]["id"]
    assert report["scope"] == "captured_recorded_policy_invariants"
    assert report["evaluation_mode"] == ("current_policy_on_replayed_observations" if replay else "capture_time_policy")
    assert len(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-16-le")) // 2 <= 128 * 1024
    registry = {p["claim"]: p["requires"] for p in report["policy_registry"]}
    assert set(registry) == POLICIES and len(report["policy_registry"]) == 7
    for name, requirements in registry.items():
        assert len({r["id"] for r in requirements}) == len(requirements)
        assert {r["id"] for r in requirements} == GATES | EXTRA[name]
        assert {r["id"] for r in requirements if r["scope_gate"]} == GATES | ({"typed_completion_slot"} if name == REGISTERED else set())
        assert all(r["next_observation"] and r["mode"] for r in requirements)

    def evidence(ref):
        assert ref["capture_sha256"] == digest
        parts = ref["json_pointer"].split("/")
        assert parts[0] == "" and len(parts) > 1
        selected = capture
        for part in parts[1:]:
            key = part.replace("~1", "/").replace("~0", "~")
            selected = selected[int(key)] if isinstance(selected, list) else selected[key]
        return selected

    qualified = capture["runtime_qualified"] and reference_available
    expected = []
    for i, request in enumerate(capture["requests"]):
        for kind in (MEMBER, OWNER, COMPLETED, CANCELLED):
            expected.append((kind, str(i), None, "supported" if qualified and kind in (MEMBER, OWNER) else "unfulfilled"))
        for j, stack in enumerate(request["stacks"]):
            registered = bool(int(stack["control"]) & 0xe0) and int(stack["completion"]) != 0
            expected += [
                (REGISTERED, str(i), str(j), ("supported" if registered else "contradicted") if qualified else "unfulfilled"),
                (EXECUTED, str(i), str(j), "not_applicable" if qualified and not registered else "unfulfilled"),
                (DEVICE_OWNER, str(i), str(j), "not_applicable" if qualified and stack["device"] == "0" else "unfulfilled"),
            ]
    rows = report["claims"]
    assert [(r["claim"], r["request_index"], r["stack_index"], r["status"]) for r in rows] == expected[:len(rows)]
    assert int(report["claims_possible"]) == len(expected)
    assert int(report["claims_emitted"]) == len(rows) <= int(report["claim_limit"]) == 128
    assert int(report["claims_omitted"]) == len(expected) - len(rows)
    assert report["report_complete"] == (len(expected) == len(rows))
    counts = Counter(r["status"] for r in rows)
    assert {key: int(value) for key, value in report["counts"].items()} == {s: counts[s] for s in STATUSES}
    for row in rows:
        assert row["policy"] == report["policy"]
        required = {r["id"] for r in registry[row["claim"]]}
        seen = set()
        for group in ("supports", "contradicts"):
            for fact in row[group]:
                assert fact["requirement"] in required and fact["requirement"] not in seen
                seen.add(fact["requirement"])
                evidence(fact["evidence"])
        missing = set(row["unfulfilled_requirements"])
        assert len(missing) == len(row["unfulfilled_requirements"]) and not (missing & seen)
        assert missing <= required
        if row["status"] == "not_applicable":
            evidence(row["not_applicable_basis"])
            assert row["next_best_observation"] is None
        else:
            assert seen | missing == required and row["not_applicable_basis"] is None
        if row["status"] == "supported":
            assert not missing and not row["contradicts"]
        if row["status"] == "contradicted":
            assert row["contradicts"] and not row["issue"]
        if row["status"] == "unfulfilled":
            next_observation = row["next_best_observation"]
            assert next_observation["resolves_requirement"] in missing
            assert next_observation["authorization_required"] and not next_observation["automatic_execution"]

    ledgers = report["ledgers"]
    assert set(ledgers) == {"discovery", "address", "temporal", "semantic", "persistence", "replay", "trust"}
    discovery = ledgers["discovery"]
    assert int(discovery["supplied_threads"]) == len(capture["thread_inputs"])
    for field in ("threads_visited", "irps_inspected", "unstable_observations"):
        assert discovery[field] == capture[field]
    assert int(discovery["requests_retained"]) == len(capture["requests"])
    assert discovery["complete_for_supplied_inventory"] == (capture["enumeration_complete"] and reference_available)
    assert not discovery["global_inventory"] and evidence(discovery["cursor_evidence"]) == capture["next_cursor"]

    # Sweep event multiplicities rather than summing repeat reads or merging
    # the implementation's intervals. A later accepted read covers an earlier
    # rejected range only in this observed address denominator, never in time.
    boundaries = defaultdict(lambda: [0, 0])
    traffic = 0
    calls = capture["reads"]["parser_reads"]
    for call in calls:
        start, length = int(call["address"]), int(call["length"])
        assert length > 0 and start + length <= 2**64 - 1
        traffic += length
        for point, sign in ((start, 1), (start + length, -1)):
            boundaries[point][0] += sign
            if call["accepted"]:
                boundaries[point][1] += sign
    active = [0, 0]
    totals = [0, 0]
    previous = 0
    for point, delta in sorted(boundaries.items()):
        for index in range(2):
            totals[index] += point - previous if active[index] else 0
            active[index] += delta[index]
            assert active[index] >= 0
        previous = point
    assert active == [0, 0]
    address = ledgers["address"]
    assert int(address["requested_union_bytes"]) == totals[0]
    assert int(address["accepted_union_bytes"]) == totals[1]
    assert int(address["failed_only_union_bytes"]) == totals[0] - totals[1]
    assert int(address["requested_traffic_bytes"]) == traffic
    assert int(address["rejected_parser_calls"]) == sum(not c["accepted"] for c in calls)
    assert address["exact_recorded_denominator"] == capture["readset_complete"]
    assert address["unvisited_outside_recorded_calls"] is None and address["compared_bytes"] == "0"
    assert evidence(address["range_evidence"]) == calls
    assert ledgers["temporal"]["started"] == capture["scan_started_tick_ms"]
    assert ledgers["temporal"]["finished"] == capture["scan_finished_tick_ms"]
    assert not ledgers["temporal"]["atomic_snapshot"] and not ledgers["temporal"]["continuous_observation"]
    assert ledgers["temporal"]["event_loss_intervals"] is None and ledgers["temporal"]["revisit_gaps"] is None
    assert ledgers["semantic"]["schema_image_bound"] == qualified
    assert not ledgers["semantic"]["request_lifetime_bound"] and ledgers["semantic"]["build_approval"] == "not_established"
    assert ledgers["persistence"]["capture"] == ("file_hash_verified" if replay else "encoded_in_memory")
    assert ledgers["persistence"]["journal_membership"] == "not_checked"
    assert ledgers["persistence"]["claim_report_persistence"] == "not_established"
    assert ledgers["replay"]["ordered_read_replay"] == ("canonical_result_matched" if replay else "not_attempted")
    assert not ledgers["replay"]["original_claim_policy_reproduced"]
    for flag in ("collector_authenticated", "external_final_state_authenticated", "checksum_is_authentication"):
        assert ledgers["trust"][flag] is False
    assert set(report["never_implies"]) == {"execution_observed", "writer_attributed", "maliciousness_established",
                                           "whole_host_clean", "referenced_request_lifetime", "deadlock_established"}
    return counts
