# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit tests for the independent pure-Python Experience Ledger replayer."""

from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from experience_ledger import (
    SCHEMA_VERSION,
    LocalVFSStore,
    canonical_json,
    compute_policy_sha256,
    create_checkpoint,
    ed25519_public_key_from_seed,
    generate_merkle_proof,
    replay,
    replay_from_checkpoint,
    sha256_hex,
    sign_event,
    verify_merkle_proof,
)


def _make_identity(label: str, role: str) -> dict:
    seed = bytes.fromhex(sha256_hex(f"zoo-xel-py-test:{label}".encode("utf-8")))
    pub = ed25519_public_key_from_seed(seed).hex()
    return {"id": label, "role": role, "seed": seed, "pub": pub}


def _make_policy() -> tuple[dict, dict[str, dict]]:
    specs = [
        ("did:key:researcher-alice", "human_researcher"),
        ("did:key:researcher-bob", "human_researcher"),
        ("did:key:agent-zen-01", "ai_agent"),
        ("did:key:steward-carol", "steward"),
        ("did:key:steward-dave", "steward"),
    ]
    ids = {label: _make_identity(label, role) for label, role in specs}
    policy = {
        "schema_version": SCHEMA_VERSION,
        "policy_id": "zoo-py-test-policy-v1",
        "principals": [
            {
                "principal_id": v["id"],
                "role": v["role"],
                "public_key_hex": v["pub"],
                "active": True,
            }
            for v in ids.values()
        ],
    }
    policy["policy_sha256"] = compute_policy_sha256(policy)
    return policy, ids


def _make_entry(
    ident: dict,
    vfs: LocalVFSStore,
    domain: str,
    claim_key: str,
    claim_val: str,
    summary: str,
    conf_bps: int,
    parents: list[str],
    payload: bytes,
    ts: int,
    nonce: str,
) -> dict:
    put_res = vfs.put(payload)
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_type": "experience_entry",
        "contributor_id": ident["id"],
        "domain": domain,
        "claim_key": claim_key,
        "claim_value_hash": sha256_hex(claim_val.encode("utf-8")),
        "summary": summary,
        "confidence_bps": conf_bps,
        "artifact_sha256": put_res.sha256,
        "artifact_uri": put_res.uri,
        "artifact_size_bytes": put_res.size_bytes,
        "external_uris": [],
        "parent_hashes": sorted(parents),
        "receipt_hash": "",
        "created_at_unix": ts,
        "nonce": nonce,
    }
    return sign_event(ev, ident["seed"])


class TestExperienceLedgerPython(unittest.TestCase):
    def test_canonical_json_no_html_escape(self) -> None:
        raw = canonical_json({"b": "x < y & z > 0", "a": []})
        self.assertEqual(raw, b'{"a":[],"b":"x < y & z > 0"}')

    def test_permutation_invariance_and_revocation_taint(self) -> None:
        policy, ids = _make_policy()
        with tempfile.TemporaryDirectory() as tmp:
            vfs = LocalVFSStore(tmp, s3_bucket="hanzo-research-bucket")
            alice = ids["did:key:researcher-alice"]
            bob = ids["did:key:researcher-bob"]
            agent = ids["did:key:agent-zen-01"]
            carol = ids["did:key:steward-carol"]

            e_root = _make_entry(
                alice, vfs, "math.geometry", "lemma-1", "v1",
                "When finding intersections, check segment bounds.", 9000, [], b"root-blob", 100, "r1",
            )
            e_child = _make_entry(
                bob, vfs, "math.geometry", "cor-1", "v2",
                "When computing area, apply lemma-1.", 8700, [e_root["event_id"]], b"child-blob", 200, "c1",
            )
            e_leaf = _make_entry(
                agent, vfs, "math.geometry", "heur-1", "v3",
                "When pruning paths, apply cor-1.", 8100, [e_child["event_id"]], b"leaf-blob", 300, "l1",
            )
            e_clean = _make_entry(
                bob, vfs, "math.algebra", "poly-1", "v4",
                "When solving complex polynomials, split real and imaginary parts.", 9200, [], b"clean-blob", 400, "k1",
            )
            bad_rev = sign_event(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "revocation_record",
                    "issuer_id": agent["id"],
                    "target_event_id": e_root["event_id"],
                    "reason_code": "falsified_claim",
                    "reason": "Unauthorized AI revocation attempt",
                    "evidence_sha256": "",
                    "evidence_uri": "",
                    "created_at_unix": 450,
                },
                agent["seed"],
            )
            good_rev = sign_event(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "revocation_record",
                    "issuer_id": carol["id"],
                    "target_event_id": e_root["event_id"],
                    "reason_code": "falsified_claim",
                    "reason": "Steward verified counterexample",
                    "evidence_sha256": "",
                    "evidence_uri": "",
                    "created_at_unix": 500,
                },
                carol["seed"],
            )

            events = [e_root, e_child, e_leaf, e_clean, bad_rev, good_rev]
            base = replay(policy, events)
            self.assertEqual(base["active_event_ids"], [e_clean["event_id"]])
            by_id = {es["event_id"]: es for es in base["commitment"]["entry_states"]}
            self.assertEqual(by_id[e_root["event_id"]]["status"], "revoked")
            self.assertEqual(by_id[e_child["event_id"]]["status"], "tainted")
            self.assertEqual(by_id[e_leaf["event_id"]]["status"], "tainted")
            self.assertEqual(by_id[e_leaf["event_id"]]["tainted_by_ancestors"], [e_root["event_id"]])
            self.assertEqual(
                base["commitment"]["rejected_events"],
                [{"event_id": bad_rev["event_id"], "event_type": "revocation_record", "error_code": "ERR_UNAUTHORIZED_REVOCATION"}],
            )

            # Reverse + 20 random permutations must produce identical state_root_hash
            self.assertEqual(replay(policy, list(reversed(events)))["state_root_hash"], base["state_root_hash"])
            rng = random.Random(1352)
            for _ in range(20):
                shuf = list(events)
                rng.shuffle(shuf)
                self.assertEqual(replay(policy, shuf)["state_root_hash"], base["state_root_hash"])

    def test_conflicts_and_constitutional_separation(self) -> None:
        policy, ids = _make_policy()
        with tempfile.TemporaryDirectory() as tmp:
            vfs = LocalVFSStore(tmp)
            alice = ids["did:key:researcher-alice"]
            bob = ids["did:key:researcher-bob"]
            agent = ids["did:key:agent-zen-01"]
            carol = ids["did:key:steward-carol"]
            dave = ids["did:key:steward-dave"]

            e_a = _make_entry(alice, vfs, "ml.grpo", "clip-ratio", "0.20", "When training GRPO, clip=0.20.", 8500, [], b"a", 10, "1")
            e_b = _make_entry(bob, vfs, "ml.grpo", "clip-ratio", "0.10", "When training GRPO, clip=0.10.", 8900, [], b"b", 20, "2")
            pair = sorted([e_a["event_id"], e_b["event_id"]])

            ev_put = vfs.put(b"agent-conflict-bundle")
            ai_flag = sign_event(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "conflict_flag",
                    "flagger_id": agent["id"],
                    "domain": "ml.grpo",
                    "claim_key": "clip-ratio",
                    "conflicting_event_ids": pair,
                    "evidence_sha256": ev_put.sha256,
                    "evidence_uri": ev_put.uri,
                    "rationale": "Contradictory GRPO clip ratios",
                    "created_at_unix": 30,
                },
                agent["seed"],
            )
            rat_put = vfs.put(b"resolution-rationale")
            ai_res = sign_event(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "resolution_decision",
                    "steward_id": agent["id"],
                    "domain": "ml.grpo",
                    "claim_key": "clip-ratio",
                    "reviewed_event_ids": pair,
                    "outcome": "select_canonical",
                    "winning_event_id": e_a["event_id"],
                    "rationale_sha256": rat_put.sha256,
                    "rationale_uri": rat_put.uri,
                    "governance_ref": "illegal-ai",
                    "created_at_unix": 40,
                },
                agent["seed"],
            )
            carol_res = sign_event(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "resolution_decision",
                    "steward_id": carol["id"],
                    "domain": "ml.grpo",
                    "claim_key": "clip-ratio",
                    "reviewed_event_ids": pair,
                    "outcome": "select_canonical",
                    "winning_event_id": e_a["event_id"],
                    "rationale_sha256": rat_put.sha256,
                    "rationale_uri": rat_put.uri,
                    "governance_ref": "hip-1352:prop-1",
                    "created_at_unix": 50,
                },
                carol["seed"],
            )
            st = replay(policy, [ai_res, carol_res, ai_flag, e_b, e_a])
            self.assertEqual(st["commitment"]["conflicts"][0]["status"], "resolved")
            self.assertEqual(st["commitment"]["conflicts"][0]["canonical_event_id"], e_a["event_id"])
            self.assertEqual(st["active_event_ids"], [e_a["event_id"]])
            self.assertEqual(
                st["commitment"]["rejected_events"][0]["error_code"],
                "ERR_AI_AGENT_RESOLUTION_FORBIDDEN",
            )

            # Disagreeing second steward -> escalated_steward_disagreement
            dave_res = sign_event(
                {
                    "schema_version": SCHEMA_VERSION,
                    "event_type": "resolution_decision",
                    "steward_id": dave["id"],
                    "domain": "ml.grpo",
                    "claim_key": "clip-ratio",
                    "reviewed_event_ids": pair,
                    "outcome": "select_canonical",
                    "winning_event_id": e_b["event_id"],
                    "rationale_sha256": rat_put.sha256,
                    "rationale_uri": rat_put.uri,
                    "governance_ref": "hip-1352:prop-2",
                    "created_at_unix": 60,
                },
                dave["seed"],
            )
            st_esc = replay(policy, [dave_res, carol_res, e_a, e_b])
            self.assertEqual(st_esc["commitment"]["conflicts"][0]["status"], "escalated_steward_disagreement")

    def test_merkle_vfs_and_checkpoint_parity(self) -> None:
        policy, ids = _make_policy()
        with tempfile.TemporaryDirectory() as tmp:
            vfs = LocalVFSStore(tmp)
            alice = ids["did:key:researcher-alice"]
            prefix = [
                _make_entry(alice, vfs, "sys.vfs", f"k-{i}", f"v-{i}", f"When caching {i}, hash first.", 8500, [], b"shared-payload" if i % 2 == 0 else f"uniq-{i}".encode(), 100 + i, f"n{i}")
                for i in range(10)
            ]
            delta = [
                _make_entry(alice, vfs, "sys.vfs", f"k-{i}", f"v-{i}", f"When caching {i}, hash first.", 8500, [], f"uniq-{i}".encode(), 100 + i, f"n{i}")
                for i in range(10, 14)
            ]
            ckpt = create_checkpoint(policy, prefix, vfs)
            full = replay(policy, prefix + delta)
            inc = replay_from_checkpoint(policy, ckpt["checkpoint_hash"], vfs, delta)
            self.assertEqual(full["state_root_hash"], inc["state_root_hash"])
            self.assertGreater(vfs.stats()["dedup_hits"], 0)

            for eid in full["active_event_ids"]:
                proof = generate_merkle_proof(full["active_event_ids"], eid)
                self.assertTrue(verify_merkle_proof(proof, full["commitment"]["active_merkle_root"]))

            # Corrupt a stored VFS object and confirm integrity check raises
            sample_hash = prefix[0]["artifact_sha256"]
            p = Path(tmp) / "sha256" / sample_hash[:2] / sample_hash
            p.write_bytes(b"corrupted-bytes")
            with self.assertRaises(ValueError):
                vfs.get(sample_hash)

    def test_corpus_fixture_parity_and_cycles(self) -> None:
        import json
        from experience_ledger.replay import _detect_cycle_nodes

        # Synthetic 2-node cycle + self-loop detection
        h1, h2, h3, h4 = [sha256_hex(f"n{i}".encode()) for i in range(4)]
        cyc = _detect_cycle_nodes(
            {
                h1: {"event_id": h1, "parent_hashes": [h2]},
                h2: {"event_id": h2, "parent_hashes": [h1]},
                h3: {"event_id": h3, "parent_hashes": [h3]},
                h4: {"event_id": h4, "parent_hashes": []},
            }
        )
        self.assertEqual(cyc, {h1, h2, h3})

        # Committed real-paper fixture parity
        ref_root = Path(__file__).resolve().parent.parent.parent
        bundle = json.loads((ref_root / "fixtures" / "corpus_events.json").read_text(encoding="utf-8"))
        expected = json.loads((ref_root / "fixtures" / "expected_state.json").read_text(encoding="utf-8"))
        got = replay(bundle["policy"], bundle["events"])
        self.assertEqual(got["state_root_hash"], expected["state_root_hash"])
        self.assertEqual(got["commitment"], expected["commitment"])


if __name__ == "__main__":
    unittest.main()
