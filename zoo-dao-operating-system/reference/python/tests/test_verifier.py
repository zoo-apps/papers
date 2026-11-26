# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

"""Pure-stdlib unittest suite for the independent Python ResearchDAO OS verifier."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from researchdao_verifier.canonical import canonical_json, signing_bytes
from researchdao_verifier.ed25519 import L, public_key_from_seed, sign, verify
from researchdao_verifier.verifier import (
    GENESIS_PREV_HASH,
    SPEC_VERSION,
    TransitionError,
    VerifierMachine,
    replay_from_latest_checkpoint,
    replay_full,
)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def derive_seed(seed: int, actor_id: str) -> bytes:
    return hashlib.sha256(f"researchdao-os.v1:keygen:{seed}:{actor_id}".encode("utf-8")).digest()


def make_fixture(seed: int = 1352) -> tuple[Dict[str, Any], Dict[str, bytes], int]:
    base_time = 1760000000
    seeds: Dict[str, bytes] = {}
    actors: List[Dict[str, Any]] = []

    def add(aid: str, kind: str, roles: List[str], affs: List[str], rep: int = 1000, exp: int = 0) -> None:
        sd = derive_seed(seed, aid)
        seeds[aid] = sd
        actors.append(
            {
                "id": aid,
                "pubkey_hex": public_key_from_seed(sd).hex(),
                "kind": kind,
                "roles": roles,
                "affiliations": affs,
                "reputation": rep,
                "active": True,
                "effective_until": exp,
                "revoked_at": 0,
                "last_nonce": 0,
            }
        )

    add("pi-01", "HUMAN", ["RESEARCHER"], ["zoo-conservation-lab"])
    add("pi-dual", "HUMAN", ["RESEARCHER", "PEER_REVIEWER"], ["dual-role-lab"])
    add("rev-01", "HUMAN", ["PEER_REVIEWER"], ["nordic-univ"])
    add("rev-02", "HUMAN", ["PEER_REVIEWER"], ["andes-station"])
    add("rev-03", "HUMAN", ["PEER_REVIEWER"], ["kyoto-inst"])
    add("rev-coi", "HUMAN", ["PEER_REVIEWER"], ["zoo-conservation-lab"])
    add("mc-01", "HUMAN", ["MILESTONE_COMMITTEE"], ["wildlife-council"])
    add("mc-02", "HUMAN", ["MILESTONE_COMMITTEE"], ["open-science-board"])
    add("steward-01", "HUMAN", ["TREASURY_STEWARD"], ["zoo-treasury"])
    add("steward-02", "HUMAN", ["TREASURY_STEWARD"], ["trust-uk"])
    add("steward-exp", "HUMAN", ["TREASURY_STEWARD"], ["temp-term"], exp=base_time + 50)
    add("verif-01", "HUMAN", ["INDEPENDENT_VERIFIER"], ["repro-berlin"])
    add("board-01", "HUMAN", ["BOARD_GUARDIAN"], ["foundation-board"])
    add("ec-01", "HUMAN", ["EMERGENCY_COUNCIL"], ["sec-a"])
    add("ec-02", "HUMAN", ["EMERGENCY_COUNCIL"], ["sec-b"])
    add("meta-01", "HUMAN", ["META_GOVERNOR"], ["meta-a"])
    add("meta-02", "HUMAN", ["META_GOVERNOR"], ["meta-b"])
    add("meta-03", "HUMAN", ["META_GOVERNOR"], ["meta-c"])
    add("ai-advisor-01", "AI_AGENT", ["AI_ADVISOR"], ["hllm-gov-v1"], rep=0)

    genesis = {
        "spec_version": SPEC_VERSION,
        "chain_id": "py-unit-test",
        "created_at": base_time,
        "initial_treasury_balance": 100_000_000,
        "config": {
            "min_peer_reviews": 3,
            "min_review_score_bps": 6000,
            "milestone_quorum": 2,
            "treasury_quorum": 2,
            "emergency_pause_quorum": 2,
            "meta_governance_quorum": 3,
            "timelock_seconds": 72 * 3600,
            "epoch_duration_seconds": 30 * 24 * 3600,
            "epoch_spend_cap_bps": 1000,
            "max_emergency_duration_sec": 72 * 3600,
            "holdback_bps": 1000,
        },
        "actors": actors,
    }
    return genesis, seeds, base_time


def sign_next(
    m: VerifierMachine,
    seeds: Dict[str, bytes],
    actor_id: str,
    ts: int,
    ev_type: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    env: Dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "seq": m.state["seq"] + 1,
        "prev_event_hash": m.state["last_event_hash"],
        "timestamp": ts,
        "actor_id": actor_id,
        "nonce": m.state["actors"][actor_id]["last_nonce"] + 1,
        "type": ev_type,
        "payload": payload,
    }
    sig = sign(seeds[actor_id], signing_bytes(env))
    env["signature_hex"] = sig.hex()
    return env


class TestRFC8032Ed25519(unittest.TestCase):
    """Verify pure-stdlib Ed25519 against official RFC 8032 Section 7.1 test vectors."""

    def test_rfc8032_vectors_1_2_3(self) -> None:
        vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ]
        for seed_hex, pub_hex, msg_hex, sig_hex in vectors:
            seed = bytes.fromhex(seed_hex)
            expected_pub = bytes.fromhex(pub_hex)
            msg = bytes.fromhex(msg_hex)
            expected_sig = bytes.fromhex(sig_hex)

            self.assertEqual(public_key_from_seed(seed), expected_pub)
            sig = sign(seed, msg)
            self.assertEqual(sig, expected_sig)
            self.assertTrue(verify(expected_pub, msg, sig))
            self.assertFalse(verify(expected_pub, msg + b"\x00", sig))

            # Reject malleable S >= L
            s_val = int.from_bytes(sig[32:], "little") + L
            if s_val < (1 << 256):
                malleated = sig[:32] + s_val.to_bytes(32, "little")
                self.assertFalse(verify(expected_pub, msg, malleated))

    def test_canonical_json_rules(self) -> None:
        raw = canonical_json({"b": "x<y>&z", "a": [1, True, None]})
        self.assertEqual(raw, b'{"a":[1,true,null],"b":"x<y>&z"}')
        with self.assertRaises(ValueError):
            canonical_json({"x": 1.5})


class TestPythonVerifierLifecycleAndAdversarial(unittest.TestCase):
    def test_full_lifecycle_and_adversarial_rejections(self) -> None:
        genesis, seeds, base_time = make_fixture(1352)
        m = VerifierMachine(genesis)
        ts = base_time + 10
        plan_hash = sha256_hex("plan-1")
        ev_hash = sha256_hex("ev-1")

        def apply(aid: str, t: int, ev: str, payload: Dict[str, Any]) -> str:
            return m.apply(sign_next(m, seeds, aid, t, ev, payload))

        def expect_err(aid: str, t: int, ev: str, payload: Dict[str, Any], code: str) -> None:
            sr0, ar0 = m.roots()
            with self.assertRaises(TransitionError) as ctx:
                m.apply(sign_next(m, seeds, aid, t, ev, payload))
            self.assertEqual(ctx.exception.code, code)
            self.assertEqual(m.roots(), (sr0, ar0))

        # 1. ProposalSubmitted + non-binding AI advisory
        apply(
            "pi-01",
            ts,
            "ProposalSubmitted",
            {
                "proposal_id": "PY-1",
                "title": "Python Lifecycle Check",
                "category": "CONSERVATION_RESEARCH",
                "plan_hash": plan_hash,
                "source_paper": "zoo-dao-operating-system/zoo-dao-operating-system.tex",
                "requested_amount": 40_000,
                "declared_coi_actors": [],
            },
        )
        ts += 2
        apply(
            "ai-advisor-01",
            ts,
            "AdvisoryRecorded",
            {
                "proposal_id": "PY-1",
                "advisory_only": True,
                "analysis_hash": sha256_hex("adv-1"),
                "summary": "Non-binding AI risk scan",
                "conflict_flags": [],
                "estimated_value": 40_000,
            },
        )
        self.assertEqual(m.state["proposals"]["PY-1"]["status"], "SUBMITTED")

        # Constitutional AI blocks
        expect_err("ai-advisor-01", ts + 1, "FundingAuthorized", {"proposal_id": "PY-1"}, "ERR_AI_TREASURY_FORBIDDEN")
        expect_err(
            "ai-advisor-01",
            ts + 1,
            "GovernanceRuleAmended",
            {"change_id": "rc1", "parameter": "treasury_quorum", "new_value": 1},
            "ERR_AI_RULE_CHANGE_FORBIDDEN",
        )
        expect_err(
            "ai-advisor-01",
            ts + 1,
            "IndependentAcceptanceRecorded",
            {"proposal_id": "PY-1", "bound_evidence_hash": ev_hash, "repro_check_hash": sha256_hex("r"), "verdict": "ACCEPTED"},
            "ERR_AI_VALIDATION_FORBIDDEN",
        )
        expect_err(
            "rev-coi",
            ts + 1,
            "PeerReviewRecorded",
            {"proposal_id": "PY-1", "score_bps": 9000, "report_hash": sha256_hex("c"), "recommend": True, "coi_declared": False},
            "ERR_COI_CONFLICT",
        )

        # Self-review check using pi-dual
        ts += 2
        apply(
            "pi-dual",
            ts,
            "ProposalSubmitted",
            {
                "proposal_id": "PY-SELF",
                "title": "Self",
                "category": "EDUCATION",
                "plan_hash": sha256_hex("self-plan"),
                "source_paper": "p.tex",
                "requested_amount": 5000,
            },
        )
        expect_err(
            "pi-dual",
            ts + 1,
            "PeerReviewRecorded",
            {"proposal_id": "PY-SELF", "score_bps": 9900, "report_hash": sha256_hex("sr"), "recommend": True, "coi_declared": False},
            "ERR_SELF_REVIEW_FORBIDDEN",
        )

        # 2. Peer reviews -> PEER_REVIEWED
        for r in ("rev-01", "rev-02", "rev-03"):
            ts += 2
            apply(
                r,
                ts,
                "PeerReviewRecorded",
                {"proposal_id": "PY-1", "score_bps": 8100, "report_hash": sha256_hex(r), "recommend": True, "coi_declared": False},
            )
        self.assertEqual(m.state["proposals"]["PY-1"]["status"], "PEER_REVIEWED")

        # 3. Milestone approvals -> MILESTONE_APPROVED
        for mc in ("mc-01", "mc-02"):
            ts += 2
            apply(
                mc,
                ts,
                "MilestoneApproved",
                {"proposal_id": "PY-1", "milestone_index": 1, "evidence_hash": ev_hash, "notes_hash": sha256_hex(mc)},
            )
        self.assertEqual(m.state["proposals"]["PY-1"]["status"], "MILESTONE_APPROVED")

        # 4. FundingQueued -> FundingCosigned -> Timelock -> FundingAuthorized
        ts += 2
        apply("steward-01", ts, "FundingQueued", {"proposal_id": "PY-1", "amount": 40_000})
        expect_err("steward-exp", base_time + 200, "FundingCosigned", {"proposal_id": "PY-1"}, "ERR_ACTOR_EXPIRED")
        ts += 2
        apply("steward-02", ts, "FundingCosigned", {"proposal_id": "PY-1"})
        expect_err("steward-01", ts + 10, "FundingAuthorized", {"proposal_id": "PY-1"}, "ERR_TIMELOCK_NOT_ELAPSED")

        ts += 72 * 3600 + 10
        apply("steward-01", ts, "FundingAuthorized", {"proposal_id": "PY-1"})
        expect_err("steward-01", ts + 5, "FundingAuthorized", {"proposal_id": "PY-1"}, "ERR_TRANCHE_ALREADY_DISBURSED")

        # 5. IndependentAcceptanceRecorded -> ACCEPTED
        ts += 50
        apply(
            "verif-01",
            ts,
            "IndependentAcceptanceRecorded",
            {
                "proposal_id": "PY-1",
                "bound_evidence_hash": ev_hash,
                "repro_check_hash": sha256_hex("repro-1"),
                "verdict": "ACCEPTED",
            },
        )
        self.assertEqual(m.state["proposals"]["PY-1"]["status"], "ACCEPTED")
        tr = m.state["treasury"]
        self.assertEqual(tr["balance"] + tr["escrowed_total"] + tr["total_disbursed"], 100_000_000)


class TestGoPythonCrossLanguageParity(unittest.TestCase):
    """Independently replay a full 100-proposal Go-exported WAL in pure Python stdlib."""

    def test_go_exported_wal_bit_identical_replay(self) -> None:
        if shutil.which("go") is None:
            self.skipTest("go toolchain not found in PATH")
        ref_dir = Path(__file__).resolve().parents[2]
        go_dir = ref_dir / "go"
        papers_root = ref_dir.parents[1]

        with tempfile.TemporaryDirectory(prefix="daoos-parity-") as tmp:
            wal_dir = Path(tmp) / "wal"
            out_json = Path(tmp) / "report.json"
            proc = subprocess.run(
                [
                    "go",
                    "run",
                    "./cmd/researchdao-bench",
                    "--seed",
                    "1352",
                    "--papers-root",
                    str(papers_root),
                    "--export-wal",
                    str(wal_dir),
                    "--out",
                    str(out_json),
                ],
                cwd=str(go_dir),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"go bench failed: {proc.stderr}")
            report = json.loads(out_json.read_text(encoding="utf-8"))

            # Independent pure-Python full WAL replay (verifies all ~1,098 Ed25519 signatures!)
            py_full = replay_full(wal_dir)
            py_sr_full, py_ar_full = py_full.roots()

            # Independent pure-Python checkpoint+delta replay
            py_delta, cp_seq = replay_from_latest_checkpoint(wal_dir)
            py_sr_delta, py_ar_delta = py_delta.roots()

            self.assertEqual(py_full.state["seq"], report["total_events"])
            self.assertEqual(cp_seq, report["total_events"])
            self.assertEqual(py_sr_full, report["final_state_root_hash"])
            self.assertEqual(py_ar_full, report["final_audit_merkle_root"])
            self.assertEqual(py_sr_delta, report["final_state_root_hash"])
            self.assertEqual(py_ar_delta, report["final_audit_merkle_root"])

            # Verify tampering with WAL fails in Python identically to Go
            events_path = wal_dir / "events.jsonl"
            orig = events_path.read_text(encoding="utf-8")
            tampered = orig.replace("ZGP-0001", "ZGP-9999", 1)
            events_path.write_text(tampered, encoding="utf-8")
            with self.assertRaises(TransitionError) as ctx:
                replay_full(wal_dir)
            self.assertEqual(ctx.exception.code, "ERR_INVALID_SIGNATURE")

    def test_board_veto_emergency_pause_and_meta_governance(self) -> None:
        genesis, seeds, base_time = make_fixture(1352)
        m = VerifierMachine(genesis)
        ts = base_time + 10

        def apply(aid: str, t: int, ev: str, payload: Dict[str, Any]) -> str:
            return m.apply(sign_next(m, seeds, aid, t, ev, payload))

        # Meta-governance 3-of-3 rule amendment changes timelock_seconds to 1200
        for mg in ("meta-01", "meta-02", "meta-03"):
            ts += 2
            apply(mg, ts, "GovernanceRuleAmended", {"change_id": "py-rc-1", "parameter": "timelock_seconds", "new_value": 1200})
        self.assertEqual(m.state["config"]["timelock_seconds"], 1200)

        # DEFCON 1 emergency pause (2-of-2) blocks funding queue
        ts += 2
        apply("ec-01", ts, "EmergencyPauseSigned", {"action_id": "em-py-1", "reason": "exploit", "duration_seconds": 3600})
        ts += 2
        apply("ec-02", ts, "EmergencyPauseSigned", {"action_id": "em-py-1", "reason": "exploit", "duration_seconds": 3600})
        self.assertTrue(m.state["emergency_pause"]["active"])

        # Lift with post_review_hash
        rev_hash = sha256_hex("post-review-em-py-1")
        ts += 5
        apply("ec-01", ts, "EmergencyPauseLifted", {"action_id": "em-py-1", "post_review_hash": rev_hash})
        ts += 2
        apply("ec-02", ts, "EmergencyPauseLifted", {"action_id": "em-py-1", "post_review_hash": rev_hash})
        self.assertFalse(m.state["emergency_pause"]["active"])

        # Board veto on queued proposal blocks subsequent FundingAuthorized
        plan_hash = sha256_hex("veto-plan")
        ev_hash = sha256_hex("veto-ev")
        ts += 2
        apply("pi-01", ts, "ProposalSubmitted", {
            "proposal_id": "VETO-1", "title": "Veto Check", "category": "EDUCATION",
            "plan_hash": plan_hash, "source_paper": "p.tex", "requested_amount": 10000,
        })
        for r in ("rev-01", "rev-02", "rev-03"):
            ts += 2
            apply(r, ts, "PeerReviewRecorded", {
                "proposal_id": "VETO-1", "score_bps": 7800, "report_hash": sha256_hex(r), "recommend": True, "coi_declared": False,
            })
        for mc in ("mc-01", "mc-02"):
            ts += 2
            apply(mc, ts, "MilestoneApproved", {
                "proposal_id": "VETO-1", "milestone_index": 1, "evidence_hash": ev_hash, "notes_hash": sha256_hex(mc),
            })
        ts += 2
        apply("steward-01", ts, "FundingQueued", {"proposal_id": "VETO-1", "amount": 10000})
        ts += 2
        apply("board-01", ts, "BoardVetoRecorded", {"proposal_id": "VETO-1", "justification": "501(c)(3) compliance hold"})
        self.assertEqual(m.state["proposals"]["VETO-1"]["status"], "VETOED")
        with self.assertRaises(TransitionError) as ctx:
            apply("steward-02", ts + 5, "FundingCosigned", {"proposal_id": "VETO-1"})
        self.assertEqual(ctx.exception.code, "ERR_PROPOSAL_VETOED")


if __name__ == "__main__":
    unittest.main()
