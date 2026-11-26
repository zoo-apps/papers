# SPDX-License-Identifier: Apache-2.0
"""Independent Python unit, tamper-detection, and cross-language audit tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from qf_verifier.mechanisms import (
    ALL_MECHANISMS,
    allocate_pool_capped,
    allocate_pool_hamilton,
    compute_gini_bps,
    evaluate_mechanism,
    rep_weight_fp,
)
from qf_verifier.verifier import verify_artifacts, verify_files

REFERENCE_DIR = Path(__file__).resolve().parents[2]
PAPERS_ROOT = REFERENCE_DIR.parents[1]
RESULTS_PATH = REFERENCE_DIR / "results.json"
SCENARIOS_PATH = REFERENCE_DIR / "scenarios.json"


class TestQFVerifier(unittest.TestCase):
    def test_cross_language_bit_identical_audit_merkle_root(self) -> None:
        report = verify_files(RESULTS_PATH, SCENARIOS_PATH, papers_root=PAPERS_ROOT)
        self.assertTrue(report.ok, f"Verification errors: {report.errors}")
        self.assertEqual(report.scenarios_verified, 15)
        self.assertEqual(report.evaluations_verified, 90)
        raw = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(report.audit_merkle_root, raw["audit_merkle_root"])
        self.assertEqual(report.eval_merkle_root, raw["eval_merkle_root"])
        self.assertEqual(report.corpus_hash, raw["corpus_hash"])
        self.assertEqual(report.governance_hash, raw["governance_hash"])

    def test_tamper_single_micro_zoo_allocation_detected(self) -> None:
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        scenarios = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
        tampered = copy.deepcopy(results)
        tampered["evaluations"][0]["allocations"][0]["match_micro_zoo"] += 1
        report = verify_artifacts(tampered, scenarios, papers_root=PAPERS_ROOT)
        self.assertFalse(report.ok)
        self.assertTrue(any("mismatch" in e for e in report.errors))

    def test_tamper_ai_constitutional_gate_detected(self) -> None:
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        scenarios = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
        tampered = copy.deepcopy(results)
        for chk in tampered["governance_checks"]:
            if chk["check_id"] == "gov-05-ai-treasury-auth-denied":
                chk["allowed"] = True
        report = verify_artifacts(tampered, scenarios, papers_root=PAPERS_ROOT)
        self.assertFalse(report.ok)
        self.assertTrue(any("constitutional violation" in e for e in report.errors))

    def test_tamper_corpus_digest_detected(self) -> None:
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        scenarios = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
        tampered = copy.deepcopy(results)
        tampered["corpus_proposals"][0]["tex_sha256"] = "0" * 64
        report = verify_artifacts(tampered, scenarios, papers_root=PAPERS_ROOT)
        self.assertFalse(report.ok)
        self.assertTrue(any("SHA-256 mismatch" in e for e in report.errors))

    def test_hamilton_and_capped_conservation(self) -> None:
        alloc, unalloc = allocate_pool_hamilton(100, ["a", "b", "c"], [1, 1, 1])
        self.assertEqual(unalloc, 0)
        self.assertEqual(alloc, [34, 33, 33])

        c_alloc, c_unalloc = allocate_pool_capped(100, 30, ["a", "b", "c", "d"], [900, 10, 10, 10])
        self.assertEqual(c_unalloc, 0)
        self.assertEqual(sum(c_alloc), 100)
        self.assertEqual(c_alloc[0], 30)
        self.assertTrue(all(v <= 30 for v in c_alloc))

    def test_zoorep_weights_and_gini(self) -> None:
        self.assertEqual(rep_weight_fp(0, 10, 40_000), 40_000)
        self.assertEqual(rep_weight_fp(10, 10, 40_000), 400_000)
        self.assertEqual(rep_weight_fp(50, 10, 40_000), 480_000)
        self.assertEqual(rep_weight_fp(200, 10, 40_000), 600_000)
        self.assertEqual(rep_weight_fp(500, 10, 40_000), 800_000)
        self.assertEqual(rep_weight_fp(1000, 10, 40_000), 1_000_000)
        self.assertEqual(rep_weight_fp(49, 50, 0), 0)
        self.assertEqual(compute_gini_bps([100, 100, 100, 100]), 0)
        self.assertEqual(compute_gini_bps([0, 0, 0, 1000]), 7500)

    def test_negative_regimes_independently_confirmed(self) -> None:
        scenarios = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))["scenarios"]
        by_id = {s["id"]: s for s in scenarios}

        # Negative Regime #1: Strict 50-ZooRep gate blocks Sybils (0%) but starves newcomers (0%).
        neg1 = by_id["neg_regime_1_strict_rep_newcomer_starvation"]
        ev_neg1_rep = evaluate_mechanism(neg1, "reputation_weighted_qf")
        ev_neg1_clr = evaluate_mechanism(neg1, "standard_clr_qf")
        self.assertEqual(ev_neg1_rep["metrics"]["pool_extraction_bps"], 0)
        self.assertEqual(ev_neg1_rep["metrics"]["newcomer_share_bps"], 0)
        self.assertGreater(ev_neg1_clr["metrics"]["newcomer_share_bps"], 0)

        # Negative Regime #2: Honest lab suffers false-positive suppression under Pairwise & COCM.
        neg2 = by_id["neg_regime_2_honest_lab_cocm_false_positive"]
        ev_neg2_clr = evaluate_mechanism(neg2, "standard_clr_qf")
        ev_neg2_pair = evaluate_mechanism(neg2, "pairwise_bounded_qf")
        ev_neg2_hyb = evaluate_mechanism(neg2, "hybrid_cocm_reputation_capped_qf")
        self.assertLess(
            ev_neg2_pair["metrics"]["lab_share_bps"],
            ev_neg2_clr["metrics"]["lab_share_bps"],
        )
        self.assertLess(
            ev_neg2_hyb["metrics"]["lab_share_bps"],
            ev_neg2_clr["metrics"]["lab_share_bps"],
        )

        # Negative Regime #3: Costless S=50 Sybils drain >70% on uncapped Standard CLR QF.
        s50 = by_id["sybil_identity_splitting_s50"]
        ev_s50_clr = evaluate_mechanism(s50, "standard_clr_qf")
        ev_s50_hyb = evaluate_mechanism(s50, "hybrid_cocm_reputation_capped_qf")
        self.assertGreaterEqual(ev_s50_clr["metrics"]["pool_extraction_bps"], 7000)
        self.assertEqual(ev_s50_hyb["metrics"]["pool_extraction_bps"], 0)
        self.assertEqual(len(ALL_MECHANISMS), 6)


if __name__ == "__main__":
    unittest.main()
