"""Independent original-receipt and PE-byte oracle for slice/sweep claims."""
import hashlib
import json

from image_claim_oracle import normalized_pe


GATES = ["verified_original_inputs", "valid_per_policy_range_partitions", "supported_recorded_comparison_policy"]
MATCH = ["complete_scope_membership", "all_range_identities_qualified", "full_scope_match"]
DIFF = "stable_difference_with_two_original_reads"


def digest(envelope, key):
    actual = hashlib.sha256(json.dumps(envelope["payload"], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    assert actual == envelope[key]
    return actual


def reference(sha, pointer):
    return {"capture_sha256": sha, "json_pointer": pointer}


def derive_slice(recipe, blob):
    sha, p = digest(recipe, "recipe_sha256"), recipe["payload"]
    assert hashlib.sha256(blob).hexdigest() == p["reference_sha256"]
    trace, reads = p["slice"], p["target_reads"]
    calls, receipts = reads["parser_reads"], reads["attempts"]["reads"]
    base, relocation = int(p["image_base"]), int(trace["relocation_base"])
    result = dict(sha=sha, reference=p["reference_sha256"], policy=p["policy"], base=base, relocation=relocation,
                  target=reads["attempts"]["target_id"], address_space=reads["attempts"]["address_space_id"],
                  start=int(trace["start_range"]), count=int(trace["page_count"]), secondary=trace["secondary_needed"],
                  first=reads["attempts"]["started_tick"], last=reads["attempts"]["snapshot_tick"],
                  requested=0, compared=0, skipped=0, failed=0, unvisited=0, difference_bytes=0, difference_ranges=0,
                  identity=bool(p["recorded_result"]) and not trace["rejection_reason"],
                  match=bool(p["recorded_result"]) and not trace["rejection_reason"], witness=None)
    assert len(p["recorded_result"]) == result["count"]
    seen = set()
    for page_index, row in enumerate(p["recorded_result"]):
        c = row["comparison"]
        rva, size = int(c["rva"]), int(c["requested_bytes"])
        start = base + rva
        assert 0 < size <= 4096 and not c["ranges_truncated"]
        assert not seen.intersection(range(start, start + size))
        seen.update(range(start, start + size))
        classes = [None] * size
        for kind in ("compared", "skipped", "failed"):
            for address, length in c[kind]:
                offset, length = int(address) - start, int(length)
                assert 0 <= offset < size and 0 < length <= size - offset
                assert all(value is None for value in classes[offset:offset + length])
                classes[offset:offset + length] = [kind] * length
            assert classes.count(kind) == int(c[kind + "_bytes"])
            result[kind] += classes.count(kind)
        result["requested"] += size
        result["unvisited"] += classes.count(None)
        observed, expected = bytes.fromhex(c["observed_hex"]), bytes.fromhex(c["expected_hex"])
        changed = []
        supported = []
        if "compared" in classes:
            assert len(observed) == len(expected) == size
            assert int(c["relocation_base"]) == relocation and row["secondary_basis"] == trace["secondary_needed"]
            normalized = normalized_pe(blob, relocation, rva, size)
            for offset, kind in enumerate(classes):
                if kind == "compared":
                    assert expected[offset] == normalized[offset], "expected bytes independently reconstructed from retained PE"
                    if observed[offset] != normalized[offset]:
                        changed.append(start + offset)
            for index, call in enumerate(calls):
                if not call["accepted"] or int(call["address"]) != start or int(call["length"]) != size:
                    continue
                selected = int(call["returned_receipt"])
                read = receipts[selected - 1]["read"]
                if read["status"] != "complete" or read["cancellation_observed"] or read["operation_deadline_exceeded"]:
                    continue
                data = b"".join(bytes.fromhex(span["bytes_hex"]) for span in read["spans"])
                assert len(data) == size
                if all(data[i] == observed[i] for i, kind in enumerate(classes) if kind == "compared") and selected not in [r[1] for r in supported]:
                    supported.append((index, selected))
                    if len(supported) == 2:
                        break
            assert supported, "compared bytes need an original accepted returned receipt"
        claimed = {base + int(address) + n for address, length in c["changes"] for n in range(int(length))}
        assert set(changed) == claimed
        qualified = not trace["rejection_reason"] and c["inventory_available"] and c["attempted"]
        result["identity"] &= qualified
        full = qualified and c["traversal_complete"] and classes.count("compared") == size and not changed and bool(supported)
        assert not full or c["ownership"] == "owned_verified"
        result["match"] &= full
        if qualified and c["traversal_complete"] and changed and len(supported) >= 2:
            assert c["ownership"] == "owned_modified"
            runs = []
            for address in changed:
                if runs and runs[-1][0] + runs[-1][1] == address:
                    runs[-1][1] += 1
                else:
                    runs.append([address, 1])
            result["difference_bytes"] += len(changed)
            result["difference_ranges"] += len(runs)
            if result["witness"] is None:
                result["witness"] = dict(selection="first_stable_changed_range", recipe_sha256=sha,
                    address=str(runs[0][0]), length=str(runs[0][1]),
                    normalization=reference(sha, f"/payload/normalization/{page_index}"),
                    secondary_inputs=reference(sha, "/payload/secondary_reads") if trace["secondary_needed"] else None,
                    original_reads=[dict(parser_call=reference(sha, f"/payload/target_reads/parser_reads/{index}"),
                                         returned_receipt=reference(sha, f"/payload/target_reads/attempts/reads/{receipt - 1}"))
                                    for index, receipt in supported])
    for label, routed in (("target", reads), ("secondary", p["secondary_reads"])):
        result[label + "_traffic"] = int(routed["attempts"]["charged_requested_bytes"]) if routed else 0
        result[label + "_stored"] = sum(len(bytes.fromhex(span["bytes_hex"])) for row in routed["attempts"]["reads"]
                                       for span in row["read"]["spans"]) if routed else 0
    return result


def check_scope_report(envelope, recipes, blobs, replay):
    sweep = envelope["schema"] == "kn.image_sweep.v1"
    sha = digest(envelope, "manifest_sha256" if sweep else "recipe_sha256")
    p = envelope["payload"]
    report = replay["claim_assessment"]
    assert report and report["schema"] == "kn.image_claim_report.v1" and report["registry"] == "kn.claim_registry.v1"
    assert report["policy"] == ("kn.image_claim_policy.sweep.v1" if sweep else "kn.image_claim_policy.slice.v1")
    assert report["capture_sha256"] == sha and report["claim_count"] == "2" and report["report_complete"]
    assert report["scope"] == ("temporal_sweep_schedule" if sweep else "executed_slice_ranges")
    assert report["evaluation"] == "current_claim_policy_on_replayed_observations" and not report["original_claim_policy_reproduced"]
    assert len(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-16-le")) // 2 <= 2 * 1024 * 1024
    derived = [derive_slice(recipe, blob) for recipe, blob in zip(recipes, blobs)]
    assert len(derived) == len(recipes) == len(blobs) > 0
    artifacts = {sha: envelope, **{row["sha"]: recipe for row, recipe in zip(derived, recipes)}}
    def pointers(value):
        if isinstance(value, dict):
            if set(value) == {"capture_sha256", "json_pointer"}:
                selected = artifacts[value["capture_sha256"]]
                for part in value["json_pointer"].split("/")[1:]:
                    selected = selected[int(part)] if isinstance(selected, list) else selected[part.replace("~1", "/").replace("~0", "~")]
            else:
                for child in value.values():
                    pointers(child)
        elif isinstance(value, list):
            for child in value:
                pointers(child)
    pointers(report)
    first = derived[0]
    assert report["reference_sha256"] == first["reference"] and report["image_base"] == str(first["base"])
    assert report["target_id"] == first["target"] and report["address_space_id"] == first["address_space"]
    if sweep:
        assert len(p["slices"]) == len(derived)
        for membership, child in zip(p["slices"], derived):
            assert membership["recipe_sha256"] == child["sha"] and membership["reference_sha256"] == child["reference"]
            assert membership["started_tick"] == child["first"] and membership["ended_tick"] == child["last"]
            assert int(membership["start_range"]) == child["start"] and int(membership["range_count"]) == child["count"]
    requested, ranges = sum(r["requested"] for r in derived), sum(r["count"] for r in derived)
    expected = int(p["sweep"]["expected_bytes"]) if sweep else requested
    total_ranges = int(p["sweep"]["total_ranges"]) if sweep else ranges
    missing = int(p["observed_slices"]) - len(derived) if sweep else 0
    membership = (p["terminal_observed"] and p["traversal_complete"] and missing == 0 and requested == expected and ranges == total_ranges) if sweep else True
    match = all(r["match"] for r in derived) and membership and ranges != 0
    identities = all(r["identity"] for r in derived)
    witnesses = [(i, r["witness"]) for i, r in enumerate(derived) if r["witness"]]
    states = ["contradicted", "supported"] if witnesses else ["supported", "contradicted"] if match else ["unfulfilled", "unfulfilled"]
    assert report["stable_difference_witness"] == (witnesses[0][1] if witnesses else None)
    assert int(report["stable_difference_bytes"]) == sum(r["difference_bytes"] for r in derived)
    assert int(report["stable_difference_ranges"]) == sum(r["difference_ranges"] for r in derived)
    kind = "sweep" if sweep else "slice"
    names = [f"image_{kind}_{'scheduled' if sweep else 'requested'}_ranges_match_reference", f"image_{kind}_contains_stable_difference"]
    root_pointer = "/payload/slices" if sweep else "/payload/target_reads"
    assert len(report["policies"]) == len(report["claims"]) == 2
    for i, (rule, claim) in enumerate(zip(report["policies"], report["claims"])):
        required = GATES + (MATCH if i == 0 else [DIFF])
        assert rule["claim"] == claim["claim"] == names[i] and claim["status"] == states[i]
        assert [r["id"] for r in rule["requirements"]] == required
        assert [r["gate"] for r in rule["requirements"]] == [True] * 3 + [False] * (len(required) - 3)
        known, gaps, contrary = GATES.copy(), [], []
        if i == 0:
            for requirement, met in zip(MATCH[:2], (membership and ranges != 0, identities)):
                (known if met else gaps).append(requirement)
        (known if states[i] == "supported" else contrary if states[i] == "contradicted" else gaps).append(required[-1])
        assert [f["requirement"] for f in claim["supports"]] == known
        assert [f["requirement"] for f in claim["contradicts"]] == contrary
        assert claim["unfulfilled_requirements"] == gaps and claim["issue"] == "" and claim["not_applicable_basis"] is None
        assert claim["scope_evidence"] == reference(sha, root_pointer)
        for fact in claim["supports"] + claim["contradicts"]:
            pointer = f"/payload/slices/{witnesses[0][0]}" if sweep and witnesses and fact["requirement"] == required[-1] else root_pointer
            assert fact["evidence"] == reference(sha, pointer)
        suggestion = claim["next_best_observation"]
        if states[i] == "unfulfilled":
            assert suggestion["resolves_requirement"] == gaps[0] and not suggestion["automatic_execution"]
            assert suggestion["alternative_hypotheses"] and "mapping_lifetime" in suggestion["remaining_unknown"]
        else:
            assert suggestion is None
    assert report["membership_refs"] == [reference(sha, f"/payload/slices/{i}" if sweep else "/payload") for i in range(len(derived))]
    ledgers = report["ledgers"]
    assert set(ledgers) == {"discovery", "address", "temporal", "semantic", "persistence", "replay", "trust"}
    assert ledgers["discovery"] == dict(scheduled_ranges=str(total_ranges), replayed_ranges=str(ranges), scheduled_bytes=str(expected),
        unscheduled_or_unvisited_bytes=str(expected - requested), retained_slices=str(len(derived)), missing_slice_entries=str(missing),
        membership_complete=membership, whole_host_inventory_complete=False)
    assert ledgers["address"]["status"] == "per_original_policy_partitions" and not ledgers["address"]["combined_coverage_asserted"]
    assert len(ledgers["address"]["partitions"]) == len(derived)
    for row, actual in zip(ledgers["address"]["partitions"], derived):
        assert row == dict(recipe_sha256=actual["sha"], comparison_policy=actual["policy"], relocation_base=str(actual["relocation"]),
            secondary_basis=actual["secondary"], start_range=str(actual["start"]), range_count=str(actual["count"]),
            status="not_attempted" if not actual["requested"] else "complete" if actual["compared"] == actual["requested"] else "partial",
            **{key + "_bytes": str(actual[key]) for key in ("requested", "compared", "skipped", "failed", "unvisited")},
            started_tick=actual["first"], ended_tick=actual["last"], replayed_ranges=reference(actual["sha"], "/payload/recorded_result"))
    assert ledgers["temporal"] == dict(clock_domain="collector_steady_clock_ms", intervals_in_address_partitions=True,
        tail_unknown=sweep and not p["terminal_observed"], atomic_snapshot=False, continuous_observation=False, event_loss_known=False, mapping_lifetime_bound=False)
    assert ledgers["semantic"] == dict(basis_in_address_partitions=True, all_range_identities_qualified=identities,
                                      function_equivalence_proven=False, hotpatch_epoch="unavailable")
    assert ledgers["persistence"] == dict(recipe_and_reference_verified=True,
        target_requested_read_bytes=str(sum(r["target_traffic"] for r in derived)), secondary_requested_read_bytes=str(sum(r["secondary_traffic"] for r in derived)),
        target_stored_bytes_with_repeats=str(sum(r["target_stored"] for r in derived)), secondary_stored_bytes_with_repeats=str(sum(r["secondary_stored"] for r in derived)),
        raw_publication_failures=str(sum(not r["raw_written"] for r in p["slices"])) if sweep else None,
        claim_report_persistence="not_established", journal_membership_checked=False)
    assert ledgers["replay"] == dict(comparison_mode="original_policy", original_results_reproduced=True,
                                    current_claim_policy_evaluated=True, original_claim_policy_reproduced=False)
    assert ledgers["trust"] == dict(target_identity_scope="collector_declared", collector_authenticated=False,
                                   checksum_is_authentication=False, approved_reference=False)
    assert {"atomic_snapshot", "mapping_lifetime", "execution", "writer_identity", "maliciousness", "authorized_change",
            "whole_image_integrity_at_one_time", "continuous_target_observation"} <= set(report["not_proven"])
    return states
