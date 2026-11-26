# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation
"""Unit and cross-language parity tests for independent Python 3.12 DSO audit verifier."""

from __future__ import annotations

import copy
import json
import math
import unittest
from pathlib import Path

from dso_verifier.canonical import canonical_cell_leaf_hash, compute_merkle_root
from dso_verifier.verifier import (
    gini_coefficient,
    jains_fairness_index,
    verify_audit_trace,
    verify_contribution,
    verify_results_report,
)

REF_DIR = Path(__file__).resolve().parents[2]
RESULTS_PATH = REF_DIR / "results.json"
TRACE_PATH = REF_DIR / "audit_trace.json"


class TestDSOAuditVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        cls.trace = json.loads(TRACE_PATH.read_text(encoding="utf-8"))

    def test_results_merkle_and_invariants_parity(self) -> None:
        summary = verify_results_report(self.report)
        self.assertEqual(summary["cells_verified"], 120)
        self.assertEqual(summary["corpus_papers"], 88)
        self.assertEqual(summary["audit_merkle_root"], self.report["audit_merkle_root"])

    def test_audit_trace_ed25519_and_all_five_aggregators_parity(self) -> None:
        summary = verify_audit_trace(self.trace, expected_report_merkle=self.report["audit_merkle_root"])
        self.assertEqual(summary["rounds_verified"], 5)
        self.assertEqual(summary["ed25519_signatures_verified"], 150)
        self.assertEqual(summary["aggregator_runs_verified"], 25)
        self.assertEqual(summary["trace_merkle_root"], self.trace["trace_merkle_root"])

    def test_single_byte_tamper_rejected_by_ed25519(self) -> None:
        env = copy.deepcopy(self.trace["rounds"][0]["contributions"][0])
        ok, err = verify_contribution(env)
        self.assertTrue(ok, f"expected clean envelope to verify, got {err}")

        # Tamper 1: mutate one delta coordinate without changing digest -> digest mismatch
        t1 = copy.deepcopy(env)
        t1["body"]["delta_micro"][0] += 1
        ok1, err1 = verify_contribution(t1)
        self.assertFalse(ok1)
        self.assertEqual(err1, "ERR_DIGEST_MISMATCH")

        # Tamper 2: mutate signature byte -> Ed25519 verification failure
        t2 = copy.deepcopy(env)
        first = "b" if t2["signature_hex"][0] == "a" else "a"
        t2["signature_hex"] = first + t2["signature_hex"][1:]
        ok2, err2 = verify_contribution(t2)
        self.assertFalse(ok2)
        self.assertEqual(err2, "ERR_INVALID_SIGNATURE")

    def test_results_tamper_breaks_audit_merkle_root(self) -> None:
        tampered = copy.deepcopy(self.report)
        tampered["cells"][0]["global_test_accuracy"] += 0.01
        with self.assertRaises(AssertionError):
            verify_results_report(tampered)

    def test_fairness_metrics_closed_form(self) -> None:
        self.assertAlmostEqual(jains_fairness_index([1.0, 1.0, 1.0, 1.0]), 1.0, places=9)
        self.assertAlmostEqual(gini_coefficient([1.0, 1.0, 1.0, 1.0]), 0.0, places=9)
        self.assertAlmostEqual(jains_fairness_index([1.0, 0.0, 0.0, 0.0]), 0.25, places=9)
        self.assertAlmostEqual(gini_coefficient([1.0, 0.0, 0.0, 0.0]), 0.75, places=9)
        self.assertEqual(jains_fairness_index([0.0, 0.0]), 0.0)
        self.assertEqual(gini_coefficient([0.0, 0.0]), 1.0)

    def test_negative_regimes_verified_in_results(self) -> None:
        neg = self.report["negative_regimes"]
        # Regime 1: Geometric-Filter Minority Erasure at f=0%
        r1 = {e["aggregator"]: e for e in neg["regime_1_minority_erasure_at_zero_adv"]}
        self.assertLess(r1["multi_krum"]["minority_honest_acceptance_rate"], 0.05)
        self.assertLess(r1["coord_median"]["minority_honest_acceptance_rate"], 0.05)
        self.assertLess(r1["trimmed_mean"]["minority_honest_acceptance_rate"], 0.05)
        self.assertGreater(r1["dso_reputation_eval_gated"]["minority_honest_acceptance_rate"], 0.90)

        # Regime 2: Unmonitored Trigger Backdoor fools even eval-gated aggregation
        r2_dso = [
            e for e in neg["regime_2_unmonitored_backdoor"]
            if e["aggregator"] == "dso_reputation_eval_gated" and math.isclose(e["adversary_fraction"], 0.20)
        ]
        self.assertEqual(len(r2_dso), 1)
        self.assertGreaterEqual(r2_dso[0]["backdoor_attack_success_rate"], 0.90)

        # Regime 3: 66% committee liveness collapse at f>=40% and Goodhart eval overfitting
        r3_coll = [
            e for e in neg["regime_3_fifty_pct_and_committee"]
            if e["mode"] == "decentralized_committee_66pct_supermajority" and e["adversary_fraction"] >= 0.40
        ]
        self.assertEqual(len(r3_coll), 2)
        for e in r3_coll:
            self.assertEqual(e["honest_liveness_rate"], 0.0)
        r3_overfit = [
            e for e in neg["regime_3_fifty_pct_and_committee"]
            if e["mode"] == "static_small_eval_goodhart_overfit_30r"
        ]
        self.assertEqual(len(r3_overfit), 1)
        self.assertGreater(r3_overfit[0]["goodhart_overfit_gap"], 0.15)

    def test_merkle_tree_empty_and_single(self) -> None:
        h_empty = compute_merkle_root([])
        self.assertEqual(len(h_empty), 64)
        h_one = compute_merkle_root([canonical_cell_leaf_hash(self.report["cells"][0])])
        self.assertEqual(len(h_one), 64)


if __name__ == "__main__":
    unittest.main()
