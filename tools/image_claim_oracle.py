"""Independent direct-recipe claim checks for owned AMD64 PE fixtures.

Derive byte ranges and confirmation from retained reads; normalize DIR64 from
the retained PE rather than accepting the report's claim or proof strings.
This bounded test oracle is not a general PE parser or a source authenticator.
"""
import hashlib
import json
import struct


CLAIMS = ("image_requested_range_matches_reference", "image_compared_range_differs_reference")
GATES = ("retained_recipe_and_reference", "selected_comparison_policy", "mapped_image_identity",
         "typed_comparison_consistent", "completed_comparison_observations")
PROPERTIES = ("full_requested_range_match", "stable_difference_in_compared_range")


def normalized_pe(blob, image_base, rva, length):
    def unpack(fmt, offset):
        return struct.unpack_from("<" + fmt, blob, offset)[0]

    nt = unpack("I", 0x3c)
    assert blob[nt:nt + 4] == b"PE\0\0" and unpack("H", nt + 4) == 0x8664
    opt = nt + 24
    assert unpack("H", opt) == 0x20b
    section_table = opt + unpack("H", nt + 20)
    sections = [struct.unpack_from("<IIII", blob, section_table + n * 40 + 8)
                for n in range(unpack("H", nt + 6))]

    def file_bytes(start, size):
        result = bytearray()
        for address in range(start, start + size):
            if address < unpack("I", opt + 60):
                result.append(blob[address])
                continue
            rows = [row for row in sections if row[1] <= address < row[1] + max(row[0], row[2])]
            assert len(rows) == 1, "owned fixture has one section for each requested RVA"
            _, base, raw_size, raw = rows[0]
            result.append(blob[raw + address - base] if address - base < raw_size else 0)
        return result

    expected = file_bytes(rva, length)
    delta = image_base - unpack("Q", opt + 24)
    reloc_rva, reloc_size = struct.unpack_from("<II", blob, opt + 112 + 5 * 8)
    entries = file_bytes(reloc_rva, reloc_size) if reloc_size else b""
    cursor = 0
    while cursor < len(entries):
        page, block = struct.unpack_from("<II", entries, cursor)
        assert block >= 8 and block % 2 == 0 and cursor + block <= len(entries)
        for pos in range(cursor + 8, cursor + block, 2):
            entry = struct.unpack_from("<H", entries, pos)[0]
            if entry >> 12 == 0:
                continue
            assert entry >> 12 == 10, "owned oracle supports AMD64 DIR64 only"
            address = page + (entry & 4095)
            adjusted = ((int.from_bytes(file_bytes(address, 8), "little") + delta) & ((1 << 64) - 1)).to_bytes(8, "little")
            for n in range(max(rva, address), min(rva + length, address + 8)):
                expected[n - rva] = adjusted[n - address]
        cursor += block
    return expected


def check_report(recipe, blob, replay):
    """Raise on overclaim, lost scope, unresolved original pointer or bad ledger."""
    report, payload, comparison = replay["claim_assessment"], recipe["payload"], replay["result"]
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    assert digest == recipe["recipe_sha256"] == report["capture_sha256"] == replay["recipe_sha256"]
    assert hashlib.sha256(blob).hexdigest() == payload["reference_sha256"] == report["reference_sha256"]
    assert report["schema"] == "kn.image_claim_report.v1" and report["registry"] == "kn.claim_registry.v1"
    assert report["policy"] == "kn.image_claim_policy.direct.v1"
    assert report["evaluation"] == "current_claim_policy_on_replayed_observations"
    assert report["original_claim_policy_reproduced"] is False
    current = replay["mode"] == "current_reanalysis"
    assert report["recorded_normalization_reproduced"] == (not current)
    assert report["claim_report_persistence"] == "not_established" and not report["journal_membership_checked"]
    assert report["source_id"] == payload["source_id"] and report["source_identity_scope"] == "collector_declared"
    assert report["scope"] == {key: payload[key] for key in ("image_base", "rva", "length")}
    assert report["report_complete"] and report["claim_count"] == "2"
    assert report["report_completeness_scope"] == "two_direct_range_policies_only"
    assert len(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-16-le")) // 2 <= 256 * 1024
    base, rva, size = (int(payload[key]) for key in ("image_base", "rva", "length"))
    start = base + rva
    v2 = recipe["schema"] == "kn.image_recipe.v2"
    path = "/payload/read_set/reads" if v2 else "/payload/reads"
    reads = payload["read_set"]["reads"] if v2 else payload["reads"]

    def resolve(evidence):
        assert evidence["capture_sha256"] == digest
        value = recipe
        for key in evidence["json_pointer"].split("/")[1:]:
            value = value[int(key)] if isinstance(value, list) else value[key.replace("~1", "/").replace("~0", "~")]
        return value

    classes = [set() for _ in range(size)]
    for kind in ("compared", "skipped", "failed"):
        for address, length in comparison[kind]:
            offset, count = int(address) - start, int(length)
            assert 0 <= offset < size and 0 < count <= size - offset
            for cell in classes[offset:offset + count]:
                cell.add(kind)
    assert all(len(cell) <= 1 for cell in classes), "classification must be disjoint"
    counts = {kind: sum(cell == {kind} for cell in classes) for kind in ("compared", "skipped", "failed")}
    counts["unvisited"] = sum(not cell for cell in classes)
    assert sum(counts.values()) == size
    accounting = (not comparison["ranges_truncated"] and int(comparison["rva"]) == rva and
                  int(comparison["requested_bytes"]) == size and
                  all(counts[kind] == int(comparison[kind + "_bytes"]) for kind in ("compared", "skipped", "failed")))
    expected, observed = (bytes.fromhex(comparison[key + "_hex"]) for key in ("expected", "observed"))
    changed = set()
    if counts["compared"]:
        assert len(expected) == len(observed) == size
        normalized = normalized_pe(blob, base, rva, size)
        for i, kind in enumerate(classes):
            if kind == {"compared"}:
                assert expected[i] == normalized[i], "selected comparison expected bytes agree with the retained PE"
                if observed[i] != normalized[i]:
                    changed.add(i)
    reported_changes = {address - rva + n for address, length in map(lambda row: map(int, row), comparison["changes"])
                        for n in range(length)}
    bytes_agree = changed == reported_changes
    retained, supporters, intervals = set(), [], []
    traffic = stored = 0
    for index, row in enumerate(reads):
        read = row["read"] if v2 else row
        traffic += int(row["requested_bytes"] if v2 else row["length"])
        intervals.append({"read_index": str(index), "started_tick": read["started_tick"], "ended_tick": read["ended_tick"]})
        available = {}
        for span in read["spans"]:
            data = bytes.fromhex(span["bytes_hex"] if v2 else span["bytes"])
            stored += len(data)
            if span["state"] != "complete":
                continue
            for i, byte in enumerate(data):
                offset = int(span["address"]) + i - start
                if 0 <= offset < size:
                    available[offset] = byte
                    retained.add(offset)
        cancelled = read["cancellation_observed"] if v2 else read["cancelled"]
        if accounting and bytes_agree and counts["compared"] and not cancelled and read["source_id"] == payload["source_id"] and \
                read["consistency"] == payload["source_consistency"] and \
                all(available.get(i) == observed[i] for i, kind in enumerate(classes) if kind == {"compared"}):
            supporters.append(index)
    consistent = accounting and bytes_agree and (not counts["compared"] or (int(comparison["relocation_base"]) == base and supporters))
    completed = comparison["attempted"] and comparison["inventory_available"] and comparison["traversal_complete"]
    gates = [True, current or payload["policy"] == "kn.executable_page.direct.v1",
             comparison["reference_qualified"], bool(consistent), completed]
    match = all(gates) and counts["compared"] == size and not changed and supporters and comparison["ownership"] == "owned_verified"
    differs = all(gates) and changed and len(supporters) >= 2 and comparison["ownership"] == "owned_modified"
    expected_states = ("supported", "contradicted") if match else (("contradicted", "supported") if differs else ("unfulfilled", "unfulfilled"))
    changed_ranges = []
    for address in sorted(start + i for i in changed):
        if changed_ranges and int(changed_ranges[-1]["address"]) + int(changed_ranges[-1]["length"]) == address:
            changed_ranges[-1]["length"] = str(int(changed_ranges[-1]["length"]) + 1)
        else:
            changed_ranges.append({"address": str(address), "length": "1"})
    full = [{"address": str(start), "length": str(size)}]
    assert len(report["policies"]) == len(report["claims"]) == 2
    for i, (definition, claim) in enumerate(zip(report["policies"], report["claims"])):
        assert definition["claim"] == claim["claim"] == CLAIMS[i]
        requirements = definition["requirements"]
        assert [row["id"] for row in requirements] == list(GATES) + [PROPERTIES[i]]
        assert [row["gate"] for row in requirements] == [True] * 5 + [False]
        assert all(row["next_observation"] and row["mode"] in ("offline_replay", "collect") for row in requirements)
        assert claim["status"] == expected_states[i]
        supports = [name for name, met in zip(GATES, gates) if met]
        missing = [name for name, met in zip(GATES, gates) if not met]
        contradicts = []
        if expected_states[i] == "supported":
            supports.append(PROPERTIES[i])
        elif expected_states[i] == "contradicted":
            contradicts.append(PROPERTIES[i])
        else:
            missing.append(PROPERTIES[i])
        assert [fact["requirement"] for fact in claim["supports"]] == supports
        assert [fact["requirement"] for fact in claim["contradicts"]] == contradicts
        assert claim["unfulfilled_requirements"] == missing
        assert claim["issue"] == ("" if all(gates) else "observation_scope_unqualified")
        for fact in claim["supports"] + claim["contradicts"]:
            resolve(fact["evidence"])
            pointer = {GATES[0]: "/payload/reference_sha256", GATES[1]: "/payload"}.get(fact["requirement"], path)
            assert fact["evidence"]["json_pointer"] == pointer
        assert claim["supported_ranges"] == ((full if i == 0 else changed_ranges) if expected_states[i] == "supported" else [])
        assert claim["counterexample_ranges"] == ((changed_ranges if i == 0 else full) if expected_states[i] == "contradicted" else [])
        assert claim["not_applicable_basis"] is None, "unobserved/excluded bytes are not N/A"
        next_observation = claim["next_best_observation"]
        if missing and expected_states[i] == "unfulfilled":
            assert next_observation["resolves_requirement"] == missing[0] and not next_observation["automatic_execution"]
            assert {"execution", "writer_identity", "maliciousness", "continuous_target_observation"} <= set(next_observation["remaining_unknown"])
        else:
            assert next_observation is None
    assert [ref["json_pointer"] for ref in report["supporting_read_refs"]] == [path + "/" + str(i) for i in supporters]
    for ref in report["supporting_read_refs"]:
        resolve(ref)
    ledgers = report["ledgers"]
    assert set(ledgers) == {"discovery", "address", "temporal", "semantic", "persistence", "replay", "trust"}
    assert ledgers["discovery"] == {"scope": "explicit_requested_range", "whole_image_inventory_complete": False}
    assert ledgers["address"] == dict(status="invalid" if not accounting else ("complete" if counts["compared"] == size else "partial"),
                                      denominator="requested_comparison_range", requested_bytes=str(size),
                                      **{kind + "_bytes": str(value) for kind, value in counts.items()})
    assert ledgers["temporal"]["intervals"] == intervals and not ledgers["temporal"]["continuous_observation"]
    assert not ledgers["temporal"]["target_time_available"] and ledgers["temporal"]["clock_domain"] == "collector_steady_clock_ms"
    assert ledgers["temporal"]["first_tick"] == intervals[0]["started_tick"] and ledgers["temporal"]["last_tick"] == intervals[-1]["ended_tick"]
    persistence = ledgers["persistence"]
    assert (int(persistence["requested_read_bytes"]), int(persistence["retained_read_bytes_including_repeats"]),
            int(persistence["unique_target_bytes_retained"])) == (traffic, stored, len(retained))
    assert persistence["reference_artifact_verified"] and not persistence["full_source_preserved"]
    assert ledgers["semantic"]["mapped_identity_qualified"] == comparison["reference_qualified"]
    assert not ledgers["semantic"]["function_equivalence_proven"] and ledgers["semantic"]["hotpatch_epoch"] == "unavailable"
    assert ledgers["replay"]["status"] == ("current_policy_reanalysis" if current else "original_result_reproduced")
    assert ledgers["replay"]["recorded_policy"] == payload["policy"] and ledgers["replay"]["current_policy"] == "kn.executable_page.direct.v1"
    assert not ledgers["trust"]["collector_authenticated"] and not ledgers["trust"]["approved_distribution"]
    assert {"execution", "writer_identity", "maliciousness", "authorized_change", "whole_image_integrity",
            "continuous_target_observation", "collector_authentication"} <= set(report["not_proven"])
    assert ["unfulfilled" if claim["status"] == "not_established" else claim["status"] for claim in replay["proof"]["claims"]] == list(expected_states)
    return expected_states
