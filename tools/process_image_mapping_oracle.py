"""Recompute v3 mapping fences from original native query records and read times.

These checks cannot authenticate a producer or detect unobserved mapping ABA.
"""


def check_mappings(recipe, comparison):
    p = recipe["payload"]
    m, read_set = p["mapping_set"], p["read_set"]
    assert set(m) == {"schema", "policy", "query_contract", "clock_domain", "reads", "final"}
    assert m["schema"] == "kn.process_image_mappings.v1"
    assert m["policy"] == "kn.process_image_mapping.observed.v1"
    assert m["query_contract"] == "win32_virtualqueryex.amd64.v1"
    assert m["clock_domain"] == "collector_steady_clock_ms"
    assert 0 < len(m["reads"]) == len(read_set["reads"]) <= 64
    observations, unique = [], []
    end = int(read_set["started_tick"])
    for pair, read in zip(m["reads"], read_set["reads"]):
        assert set(pair) == {"before", "after"}
        address, length = int(read["address"]), int(read["requested_bytes"])
        assert int(pair["before"]["started_tick"]) >= end
        assert int(pair["before"]["ended_tick"]) <= int(read["read"]["started_tick"])
        assert int(read["read"]["ended_tick"]) <= int(pair["after"]["started_tick"])
        for record in (pair["before"], pair["after"]):
            assert (int(record["address"]), int(record["length"])) == (address, length)
            observations.append(record)
        end = int(pair["after"]["ended_tick"])
        if (address, length) not in unique:
            unique.append((address, length))
    assert len(m["final"]) == len(unique)
    for record, expected in zip(m["final"], unique):
        assert (int(record["address"]), int(record["length"])) == expected
        assert int(record["started_tick"]) >= end
        end = int(record["ended_tick"])
        observations.append(record)
    assert end <= int(read_set["snapshot_tick"])

    counts = dict(observations=len(observations), queries=0, failed_observations=0, uncommitted_queries=0,
                  requested_query_bytes=0, observed_query_bytes=0, compared_pairs=0, conflicting_pairs=0)
    spans, image, identity = [], True, False
    for record in observations:
        assert set(record) == {"source_id", "address", "length", "started_tick", "ended_tick", "status",
                               "identity_revalidated", "queries"}
        assert record["source_id"] == p["source_id"] and int(record["ended_tick"]) >= int(record["started_tick"])
        address, length, status = int(record["address"]), int(record["length"]), record["status"]
        assert 0 < length <= 4096 and 0 <= address < address + length < 1 << 64
        assert status in ("complete", "identity_changed", "unsupported", "cancelled", "query_failed", "malformed_result")
        assert record["identity_revalidated"] == (status not in ("identity_changed", "unsupported"))
        assert len(record["queries"]) <= 2
        counts["requested_query_bytes"] += length
        counts["failed_observations"] += status != "complete"
        identity |= status == "identity_changed"
        cursor, failed, malformed = address, False, False
        for q in record["queries"]:
            assert set(q) == {"address", "returned_bytes", "native_status", "region_base", "region_bytes", "state",
                              "allocation_base", "allocation_protect", "type", "protect"}
            counts["queries"] += 1
            assert int(q["address"]) == cursor and cursor < address + length and not failed and not malformed
            returned = int(q["returned_bytes"])
            assert (q["native_status"] is not None) == (returned == 0)
            failed = returned == 0
            if returned != 48:
                assert all(q[key] is None for key in ("region_base", "region_bytes", "state", "allocation_base",
                                                       "allocation_protect", "type", "protect"))
                malformed = returned != 0
                image = False
                continue
            begin, size, state = int(q["region_base"]), int(q["region_bytes"]), int(q["state"])
            assert (q["protect"] is None) == (state != 0x1000)
            assert all((q[key] is None) == (state == 0x10000) for key in ("allocation_base", "allocation_protect", "type"))
            malformed = not (begin <= cursor < begin + size < 1 << 64 and state in (0x1000, 0x2000, 0x10000) and
                             (state == 0x10000 or (int(q["allocation_base"]) <= begin and
                                                   int(q["type"]) in (0x20000, 0x40000, 0x1000000))))
            if malformed:
                image = False
                continue
            stop = min(address + length, begin + size)
            attributes = tuple(q[k] for k in ("state", "type", "allocation_base", "allocation_protect", "protect"))
            # Only the queried intersection is evidence. Adjacent, unqueried
            # region growth/shrinkage must not turn into a false conflict.
            for previous_begin, previous_end, previous_attributes in spans:
                if cursor < previous_end and previous_begin < stop:
                    counts["compared_pairs"] += 1
                    counts["conflicting_pairs"] += attributes != previous_attributes
            spans.append((cursor, stop, attributes))
            counts["observed_query_bytes"] += stop - cursor
            counts["uncommitted_queries"] += state != 0x1000
            image &= state == 0x1000 and q["type"] == str(0x1000000) and q["allocation_base"] == p["image_base"]
            cursor = stop
        if status == "complete":
            assert not failed and not malformed and cursor == address + length
        elif status == "query_failed":
            assert failed
        elif status == "malformed_result":
            assert malformed or (len(record["queries"]) == 2 and cursor < address + length)
        elif status == "cancelled":
            assert not failed and not malformed and cursor < address + length
        elif status == "unsupported":
            assert not record["queries"]
    status = ("inconsistent_capture" if identity or counts["conflicting_pairs"] else
              "unavailable" if counts["failed_observations"] or counts["uncommitted_queries"] else "consistent_observations")
    expected = dict(schema="kn.process_image_mapping_assessment.v1", policy=m["policy"], status=status,
                    **{key: str(value) for key, value in counts.items()},
                    native_image_mapping_observed=bool(image and status == "consistent_observations"),
                    **{key: False for key in ("mapping_lifetime_bound", "aba_excluded", "physical_identity_known",
                                              "original_backing_verified", "atomic_snapshot", "current_state_known",
                                              "execution_observed", "collector_authenticated")})
    assert comparison["mapping"] == expected, "mapping assessment must follow original query evidence"
    if status != "consistent_observations":
        assert not comparison["reference_qualified"] and comparison["ownership"] == "owned_unverified"
        assert comparison["compared_bytes"] == comparison["skipped_bytes"] == "0"
        assert comparison["failed_bytes"] == p["length"]
        assert comparison["failed"] == [[str(int(p["image_base"]) + int(p["rva"])), p["length"]]]
        assert not comparison["changes"] and not comparison["compared"] and not comparison["skipped"]
        assert comparison["reason"] == ("image_mapping_conflict" if status == "inconsistent_capture" else "image_mapping_unavailable")
    return status == "consistent_observations"
