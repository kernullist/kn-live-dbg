"""Check native source retention against the files of owned, closed acquisitions."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_inventory(store, expected, cli, check):
    snapshot = cli("store", store, "/retention", "/artifacts")
    budget = snapshot["collection_retention"]
    rows = {row["collection_id"]: row for row in budget["roots"]}
    check(budget["status"] == "verified" and rows.keys() == expected.keys(), "complete active root set")
    classes = ("first_observation", "observation_gap", "unclassified", "routine_only", "empty")
    groups, owners, sizes = {}, {}, {}
    for key, (priority, keeper) in expected.items():
        folder = store / "collections" / key / "journal-segments"
        first, last = sorted(folder.glob("*.knjseg"))
        members = json.loads(first.read_bytes())["payload"]["transaction"]["members"]
        pins = {}
        for member in [*members, *json.loads(last.read_bytes())["payload"]["transaction"]["members"]]:
            name = member["path"]
            data = (store / name).read_bytes()
            check(sha(data) == member["sha256"] and len(data) == int(member["bytes"]), "original member and size")
            pins[Path(name).suffix] = sha(data)
            sizes[name] = len(data)
            owners.setdefault(name, set()).add(key)
        identity = pins[".knsource"], pins.get(".kncapture"), pins.get(".knblob")
        group = groups.setdefault(identity, [])
        group.append(key)
        copy = rows[key]["source_copies"]
        check(tuple(copy[k] for k in ("report_sha256", "claim_file_sha256", "reference_sha256")) == identity,
              "three original file pins, including absent files")
        check(rows[key]["class"] == priority and copy["retained_collection_id"] == keeper, ("retention", key))
    for group in groups.values():
        check(all(int(rows[k]["source_copies"]["active_copies"]) == len(group) for k in group), "active exact file copies")
    totals = {lane: [0, 0] for lane in (*classes, "ledgers")}
    exclusive = dict.fromkeys(rows, 0)
    for name, keys in owners.items():
        lane = "ledgers" if name.endswith(".knsourceledger") else min((expected[k][0] for k in keys), key=classes.index)
        totals[lane][0] += 1
        totals[lane][1] += sizes[name]
        if lane == "routine_only" and len(keys) == 1:
            exclusive[next(iter(keys))] += sizes[name]
    for row in [*budget["classes"], dict(budget["failure_ledgers"], **{"class": "ledgers"})]:
        check([int(row["paths"]), int(row["named_bytes"])] == totals[row["class"]], ("global bytes", row["class"]))
    check(all(int(rows[k]["exclusive_routine_bytes"]) == size for k, size in exclusive.items()), "independent exclusive sizes")
    return snapshot


def change_outer_file(store, key):
    """Vary only the JSON envelope order in a disposable copy; keep every payload byte."""
    file, = (store / "image-captures").glob(f"case-{key}-*.kncapture")
    original = file.read_bytes()
    schema, seal, payload = original[1:].split(b",", 2)
    assert schema.startswith(b'"schema":') and seal.startswith(b'"publication_sha256":') and payload.startswith(b'"payload":')
    replacement = b"{" + b",".join((seal, schema, payload))
    assert replacement != original and len(replacement) == len(original)
    file.write_bytes(replacement)
    folder = store / "collections" / key
    previous = sha((folder / "session.knsession").read_bytes())
    for segment in sorted((folder / "journal-segments").glob("*.knjseg")):
        wrapper = json.loads(segment.read_bytes())
        payload = wrapper["payload"]
        for member in payload["transaction"]["members"]:
            if member["path"] == file.relative_to(store).as_posix():
                member["sha256"] = sha(replacement)
        payload["previous_sha256"] = previous
        wrapper["payload_sha256"] = sha(encode(payload))
        data = encode(wrapper)
        segment.write_bytes(data)
        previous = sha(data)


def check_source_copies(original, work, cli, check):
    first, gap, repeat = "first_observation", "observation_gap", "routine_only"
    expected = {str(k): (gap, str(k)) for k in range(1, 5)}
    expected.update({"5": (first, "5"), "6": (first, "6"), "7": (repeat, "5")})
    check_inventory(original, expected, cli, check)

    store = work / "source-budget"
    cli("init-store", store, "/acl-only")

    def archive(source_id, dest_id):
        report, = (original / "image-captures").glob(f"source-{source_id}-*.knsource")
        return cli("journal-image-source", report, sha(report.read_bytes()), store, dest_id)

    def policy(snapshot, name, *selection):
        input_file = work / (name + "-inventory.json")
        input_file.write_bytes(encode(snapshot))
        output = work / (name + "-policy.json")
        subprocess.run([sys.executable, "-B", str(Path(__file__).with_name("new-evidence-gc-policy.py")),
                        "--inventory", str(input_file), *selection, "--minimum-age-seconds", "0",
                        "--reason", "owned source copy budget", "--output", str(output)], check=True, capture_output=True, timeout=30)
        return output

    first_copy = archive("5", "12")
    archive("5", "2")  # Published later, earlier numeric ID.
    archive("6", "4")  # Same target, range and PE; a different acquisition.
    snap = check_inventory(store, {"2": (first, "2"), "4": (first, "4"), "12": (repeat, "2")}, cli, check)
    stale = policy(snap, "stale-source", "--retire-excess-routine", "0")
    check(json.loads(stale.read_bytes())["collection_id"] == "12" and cli("retire-collection", store, stale)["status"] == "planned",
          "explicit budget selects the extra physical copy")
    manual = policy(snap, "explicit-source", "--retire-collection", "2")
    cli("retire-collection", store, manual, "/apply")
    check(cli("retire-collection", store, stale, "/apply", code=1)["issue"] == "routine_budget_inventory_changed",
          "stale plan cannot retire the only surviving active owner")
    check_inventory(store, {"4": (first, "4"), "12": (first, "12")}, cli, check)

    retained = archive("5", "3")
    snap = check_inventory(store, {"3": (first, "3"), "4": (first, "4"), "12": (repeat, "3")}, cli, check)
    fresh = policy(snap, "refreshed-source", "--retire-excess-routine", "0")
    check(cli("retire-collection", store, fresh, "/apply")["status"] == "retired", "routine copy retired under fresh review")
    witness = store / "image-captures/session-12.knsourceledger"
    witness_bytes = witness.read_bytes()
    for index, name in enumerate((first_copy["report_path"], first_copy["capture_path"]), 1):
        gc = policy(cli("store", store, "/artifacts"), "source-reclaim-" + str(index), "--path", name, "--from-retired-collection", "12")
        cli("gc", store, gc, "/apply", str(index))
        check(not (store / name).exists() and witness.read_bytes() == witness_bytes, "reclaimed only the reviewed copy, ledger intact")
    check(cli("replay-image-source", store / retained["report_path"], retained["report_sha256"])["original_claim_matched"],
          "survivor replays with its own original claim and shared PE after physical reclamation")

    archive("1", "10")
    archive("1", "8")
    archive("3", "9")
    denied = {"3": (first, "3"), "4": (first, "4"), "8": (gap, "8"), "9": (gap, "9"), "10": (repeat, "8")}
    snap = check_inventory(store, denied, cli, check)
    failed = policy(snap, "repeated-failure", "--retire-excess-routine", "0")
    check(json.loads(failed.read_bytes())["collection_id"] == "10", "same failed attempt distinct from other failures")
    cli("retire-collection", store, failed, "/apply")
    del denied["10"]
    check_inventory(store, denied, cli, check)
    archive("5", "20")
    change_outer_file(store, "20")
    denied["20"] = first, "20"
    check_inventory(store, denied, cli, check)

    obstacle = store / "image-captures/session-21.knsourceledger"
    obstacle.mkdir()
    refused, = (original / "image-captures").glob("source-1-*.knsource")
    pin = sha(refused.read_bytes())
    partial = cli("journal-image-source", refused, pin, store, "21", code=1)
    check(partial["report_committed"] and not partial["closed"], "open source prefix has an actual first transaction")
    obstacle.rmdir()
    incomplete = cli("store", store, "/retention", code=1)
    check(incomplete["open_collections"] == "1" and incomplete["collection_retention"]["status"] == "unavailable" and
          not incomplete["collection_retention"]["roots"], "a partly published copy withholds the global budget")
    archive("1", "21")
    denied["21"] = repeat, "8"
    check_inventory(store, denied, cli, check)
