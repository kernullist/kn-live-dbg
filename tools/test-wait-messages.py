"""Compare native WCT receipts with the sender and window procedure of an owned workload."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


REPLAY = Path(__file__).resolve().with_name("replay-wait-chain.py")
CLAIM = "primary_waited_for_message_receiver"
V1, V2 = "kn.wait_claim_policy.v1", "kn.wait_claim_policy.v2"


def views(doc):
    if "rounds" in doc:
        return [view["receipt"] for entry in doc["rounds"] for view in entry["views"]]
    return [doc]


def pointer(doc, path):
    for part in path.split("/")[1:]:
        doc = doc[int(part)] if isinstance(doc, list) else doc[part]
    return doc


def acquire(exe, fixture, folder, mode):
    with subprocess.Popen([fixture, mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            ready = json.loads(child.stdout.readline())
            args = [exe, "--wait-chain", str(ready["pid"]), ready["process_created"],
                    str(ready["sender_tid"]), ready["sender_created"]]
            paired = ["--corroborate", str(ready["receiver_tid"]), ready["receiver_created"], "2", "35"]
            for shape, extra in (("single", []), ("series", paired)):
                deadline = time.monotonic() + 7
                while True:
                    raw = subprocess.run(args + extra, capture_output=True, timeout=8, check=True).stdout
                    records = views(json.loads(raw))
                    # A receiver waiting on the sender's mutex wakes periodically to check its bounded finish event.
                    # Admit mixed fixtures only when both traversals actually observed the intended ring.
                    if mode != "mixed" or all(r["query"] and r["query"]["cycle"] and
                                              {n["type"] for n in r["query"]["nodes"]} == {2, 3, 8} for r in records):
                        break
                    if time.monotonic() >= deadline:
                        raise AssertionError("WCT did not report the owned message/mutex ring")
                (folder / f"{mode}-{shape}.json").write_bytes(raw)
            if mode == "timeout":
                returned = json.loads(child.stdout.readline())
                if returned["phase"] != "sender_returned" or returned["send_ok"] or returned["send_error"] != 1460:
                    raise AssertionError("the owned send did not report ERROR_TIMEOUT")
                after = subprocess.run(args, capture_output=True, timeout=8, check=True).stdout
                (folder / "timeout-after.json").write_bytes(after)
                (folder / "timeout-returned.json").write_text(json.dumps(returned), encoding="utf-8")
        finally:
            try:
                output, errors = child.communicate(b"R", timeout=24)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise
        if child.returncode or errors:
            raise AssertionError(f"message fixture failed for {mode}, exit {child.returncode}")
        completed = json.loads(output)
        (folder / f"{mode}-oracle.json").write_text(json.dumps([ready, completed]), encoding="utf-8")
        return ready, completed


class MessageWaitTests(unittest.TestCase):
    def replay(self, path, *options, proposal=None, code=0):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, "-I", "-B", REPLAY, path, "--sha256", digest, *options],
                                input=None if proposal is None else json.dumps(proposal).encode(),
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stderr[:500])
        if code == 2:
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"Traceback", result.stderr)
            return None
        self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def test_originals_and_independent_outcomes(self):
        expected_flags = {"send": (1, 1), "mixed": (1, 1), "posted": (0, 0), "replied": (1, 9), "timeout": (1, 1)}
        answers = {"send": 71, "mixed": 71, "posted": None, "replied": 83, "timeout": None}
        for mode, (ready, end) in self.oracles.items():
            with self.subTest(mode=mode):
                blocked = mode in ("send", "mixed", "timeout")
                self.assertEqual((ready["mode"], end["mode"]), (mode, mode))
                self.assertEqual(ready["handler_tid"], ready["receiver_tid"])
                self.assertNotEqual(ready["sender_tid"], ready["receiver_tid"])
                self.assertEqual((ready["entry_flags"], ready["after_flags"]), expected_flags[mode])
                self.assertEqual(ready["sender_wait"], 258 if blocked else 0)
                self.assertEqual(ready["reply_ok"], 1 if mode == "replied" else None)
                self.assertEqual(ready["mutex_wait"], 258 if mode == "mixed" else None)
                self.assertEqual((end["send_ok"], end["handled"], end["send_error"]),
                                 (int(mode != "timeout"), 1, 1460 if mode == "timeout" else None))
                self.assertEqual(end["result"], answers[mode])
                for shape in ("single", "series"):
                    path = self.folder / f"{mode}-{shape}.json"
                    doc = json.loads(path.read_bytes())
                    report = self.replay(path)
                    results = [v for entry in report["rounds"] for v in entry["views"]] if shape == "series" else [report]
                    self.assertEqual(len(results), len(views(doc)))
                    for raw, result in zip(views(doc), results):
                        q = raw["query"]
                        self.assertTrue(q["ok"])
                        self.assertLessEqual(max(end["send_begin_tick"], end["handler_entry_tick"]), q["start"])
                        self.assertLessEqual(q["end"], end["handler_leave_tick"])
                        if blocked:
                            self.assertLessEqual(q["end"], end["send_return_tick"])
                        else:
                            self.assertLessEqual(end["send_return_tick"], q["start"])
                        self.assertEqual(q["cycle"], mode == "mixed")
                        self.assertEqual(result["potential_cycle"] is not None, mode == "mixed")
                        edges = [e for e in result["edges"] if e["relation"] == "waits_for_message_receiver"]
                        want = blocked and (raw["requested"]["tid"] == ready["sender_tid"] or mode == "mixed")
                        self.assertEqual(len(edges), int(want))
                        for e in edges:
                            self.assertEqual((e["thread_id"], e["thread_created"], e["receiver_tid"], e["receiver_created"]),
                                             (ready["sender_tid"], ready["sender_created"], ready["receiver_tid"], ready["receiver_created"]))
                            self.assertEqual(e["reply_status"], "unobserved")
                            nodes = [pointer(doc, p) for p in e["evidence"][:3]]
                            self.assertEqual([q["nodes"][i] for i in e["node_indices"]], nodes)
                            self.assertEqual([n["type"] for n in nodes], [8, 2, 8])
                            self.assertEqual([n["status"] for n in nodes[:2]], [3, 6])
                            process, sender, receiver = [pointer(doc, p) for p in e["evidence"][3:]]
                            self.assertEqual((process["created"], sender["created"], receiver["created"]),
                                             (ready["process_created"], ready["sender_created"], ready["receiver_created"]))

    def test_message_claim_and_policy_replay(self):
        for mode in self.oracles:
            for shape in ("single", "series"):
                path = self.folder / f"{mode}-{shape}.json"
                report = self.replay(path, "--investigate")
                self.assertFalse(report["deadlock_established"] or report["cause_of_hang_established"])
                h, = [row for row in report["hypotheses"] if row["claim"] == CLAIM]
                blocked = mode in ("send", "mixed", "timeout")
                self.assertEqual((report["policy"], report["plan"]["max_claims"], h["verdict"]),
                                 (V2, 7, "supported" if blocked else "inconclusive"))
                legacy = self.replay(path, "--investigate", "--policy", V1)
                self.assertEqual((legacy["policy"], legacy["plan"]["max_claims"]), (V1, 6))
                self.assertNotIn(CLAIM, legacy["plan"]["hypotheses"])
                self.assertFalse(any(f["kind"] == "synchronous_message_wait_observed" for f in legacy["facts"]))
                old_cycle, = [row for row in legacy["hypotheses"] if row["claim"] == "primary_cycle_observed"]
                self.assertEqual(old_cycle["verdict"], "inconclusive")
                if not blocked:
                    self.assertEqual(h["required_evidence_groups"], [])
                    self.assertTrue(report["unclassified_views"])
                    continue
                gap, = [entry for entry in report["missing_observations"] if entry["candidate"] == CLAIM]
                self.assertIn("handler_execution", gap["unobserved"])
                self.assertIn("reply_or_timeout", gap["unobserved"])
                ids, = h["required_evidence_groups"]
                fact = next(f for f in report["facts"] if f["id"] == ids[0])
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                value = {k: v for k, v in fact.items() if k != "id"}
                content = json.dumps(["kn.wait_fact.v1", digest, value], sort_keys=True, separators=(",", ":")).encode("ascii")
                self.assertEqual(ids[0], hashlib.sha256(content).hexdigest())
                packet = dict(schema="kn.wait_claim_proposal.v1", policy=V2, target=report["target"], receipt_sha256=digest,
                              claims=[dict(claim=CLAIM, verdict="supported", evidence_ids=ids[:1])])
                checked = self.replay(path, "--check-claims", proposal=packet)
                self.assertEqual(checked["proposal_checks"][0]["result"], "verified")
                self.replay(path, "--check-claims", "--policy", V1, proposal=packet, code=2)
                self.replay(path, "--check-claims", proposal=dict(packet, policy=V1), code=2)
                packet["claims"][0]["evidence_ids"] = ["0" * 64]
                denied = self.replay(path, "--check-claims", proposal=packet, code=1)
                self.assertEqual(denied["proposal_checks"][0]["result"], "citation_outside_decisive_evidence")

    def test_sender_timeout_while_handler_remains_active(self):
        path = self.folder / "timeout-after.json"
        ready, end = self.oracles["timeout"]
        raw = json.loads(path.read_bytes())
        self.assertEqual((raw["requested"]["tid"], raw["requested"]["thread_created"]),
                         (ready["sender_tid"], ready["sender_created"]))
        returned = json.loads((self.folder / "timeout-returned.json").read_bytes())
        self.assertEqual((returned["send_error"], returned["send_return_tick"]), (1460, end["send_return_tick"]))
        self.assertLessEqual(end["send_return_tick"], raw["query"]["start"])
        self.assertLessEqual(raw["query"]["end"], end["handler_leave_tick"])
        self.assertFalse(any(n["type"] == 2 for n in raw["query"]["nodes"]))
        finding, = [h for h in self.replay(path, "--investigate")["hypotheses"] if h["claim"] == CLAIM]
        self.assertEqual((finding["verdict"], finding["counterevidence"]), ("inconclusive", []))

    def test_message_requires_complete_bound_endpoints(self):
        raw = (self.folder / "send-single.json").read_bytes()
        path = self.scratch / "changed.json"
        for mutate in (lambda d: d["query"]["nodes"][0].update(status=2),
                       lambda d: d["query"]["nodes"][1].update(status=7),
                       lambda d: d["query"]["nodes"][1].update(type=7),
                       lambda d: d["query"]["nodes"][2].update(status=1),
                       lambda d: d["query"]["nodes"][2].update(pid=d["requested"]["pid"] + 1),
                       lambda d: d["query"]["nodes"][2].update(tid=d["requested"]["tid"]),
                       lambda d: d["query"]["nodes"][2].update(tid=0),
                       lambda d: d["threads"][1]["after"].update(result=0),
                       lambda d: d["process"]["after"].update(result=0),
                       lambda d: d["query"].update(nodes=d["query"]["nodes"][:2], reported=2),
                       lambda d: d["query"].update(ok=False, error=234, cycle=None)):
            doc = json.loads(raw)
            mutate(doc)
            path.write_text(json.dumps(doc), encoding="utf-8")
            finding, = [h for h in self.replay(path, "--investigate")["hypotheses"] if h["claim"] == CLAIM]
            self.assertEqual((finding["verdict"], finding["supporting_facts"]), ("inconclusive", []))

    def test_mixed_cycle_uses_receiver_role_in_both_roots(self):
        path = self.folder / "mixed-series.json"
        known = self.oracles["mixed"][0]
        d = self.replay(path, "--diagnose")
        relations = d["candidates"][0]["relations"]
        send, = [r for r in relations if r.get("wait_semantics") == "synchronous_message"]
        lock, = [r for r in relations if r.get("lock_semantics") == "mutex"]
        self.assertNotIn("owner_tid", send)
        self.assertEqual((send["waiter_tid"], send["receiver_tid"], lock["owner_tid"], lock["waiter_tid"]),
                         (known["sender_tid"], known["receiver_tid"], known["sender_tid"], known["receiver_tid"]))
        self.assertIn("message_reply_or_timeout", d["candidates"][0]["unobserved"])
        self.assertIn("lock_lifetimes", d["candidates"][0]["unobserved"])
        doc = json.loads(path.read_bytes())
        for entry in doc["rounds"]:
            nodes = entry["views"][1]["receipt"]["query"]["nodes"]
            next(n for n in nodes if n["type"] == 2)["type"] = 6
        altered = self.scratch / "other-dependency.json"
        altered.write_text(json.dumps(doc), encoding="utf-8")
        result = self.replay(altered)
        self.assertTrue(all(r["status"] == "different_directed_cycles" for r in result["rounds"]))
        self.assertEqual(result["repeated_groups"], [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--keep", type=Path, help="new private directory for original receipts and fixture observations")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as scratch:
        MessageWaitTests.scratch = Path(scratch)
        folder = args.keep or Path(scratch) / "originals"
        folder.mkdir()
        MessageWaitTests.folder = folder
        exe, fixture = args.exe.resolve(strict=True), args.fixture.resolve(strict=True)
        MessageWaitTests.oracles = {m: acquire(exe, fixture, folder, m) for m in ("send", "posted", "replied", "mixed", "timeout")}
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(MessageWaitTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
