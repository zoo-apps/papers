# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Unit, property, and Go<->Python 120/120 parity tests for evidence_verifier."""

from __future__ import annotations

import copy
import json
import math
import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON_DIR = os.path.abspath(os.path.join(TESTS_DIR, ".."))
VERIFIER_ROOT = os.path.abspath(os.path.join(PYTHON_DIR, ".."))
REPO_ROOT = os.path.abspath(os.path.join(VERIFIER_ROOT, "../.."))
DATASET_PATH = os.path.join(VERIFIER_ROOT, "dataset", "benchmark-claims.v1.json")
MANIFEST_PATH = os.path.join(VERIFIER_ROOT, "dataset", "corpus-manifest.json")
RESULTS_PATH = os.path.join(VERIFIER_ROOT, "results.json")

if PYTHON_DIR not in sys.path:
    sys.path.insert(0, PYTHON_DIR)

from evidence_verifier import (  # noqa: E402
    ALL_CLAIM_CLASSES,
    SCHEMA_VERSION,
    Verifier,
    canonical_json,
    compute_audit_merkle_root,
    format_canonical_float,
)
from evidence_verifier.expr import (  # noqa: E402
    EXPR_ERR_DOMAIN,
    EXPR_ERR_SYNTAX,
    EXPR_ERR_UNDEFINED_VAR,
    ExprError,
    eval_expression,
)
from evidence_verifier.types import (  # noqa: E402
    REASON_FORBIDDEN_GOV_ACTION,
    REASON_REASONING_CYCLE,
    REASON_SELF_VALIDATION,
    VERDICT_REFUTED,
    VERDICT_VERIFIED,
    sha256_hex,
)


class TestEvidenceVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = Verifier(REPO_ROOT)
        with open(DATASET_PATH, "r", encoding="utf-8") as f:
            cls.bundle = json.load(f)

    def test_corpus_manifest_integrity(self) -> None:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(len(manifest["documents"]), 8)
        for doc in manifest["documents"]:
            full = os.path.join(REPO_ROOT, doc["path"])
            with open(full, "rb") as df:
                actual = sha256_hex(df.read())
            self.assertEqual(actual, doc["sha256"], f"SHA mismatch for {doc['path']}")

    def test_expr_evaluator(self) -> None:
        self.assertAlmostEqual(eval_expression("2 + 3 * 4 ^ 2"), 50.0, places=9)
        self.assertAlmostEqual(eval_expression("2 ^ 3 ^ 2"), 512.0, places=9)
        self.assertAlmostEqual(eval_expression("0.1 + 0.2", exact_rational=True), 0.3, places=12)
        self.assertAlmostEqual(eval_expression("ratio(140, 0.7)", exact_rational=True), 200.0, places=12)
        self.assertAlmostEqual(
            eval_expression("hoeffding_upper(21, 0.67, 0.25)"),
            math.exp(-2 * 21 * 0.42 * 0.42),
            places=12,
        )
        self.assertAlmostEqual(eval_expression("median(10, 2, 8, 4)"), 6.0, places=9)
        with self.assertRaises(ExprError) as cm:
            eval_expression("10 / 0")
        self.assertEqual(cm.exception.kind, EXPR_ERR_DOMAIN)
        with self.assertRaises(ExprError) as cm2:
            eval_expression("x + 1")
        self.assertEqual(cm2.exception.kind, EXPR_ERR_UNDEFINED_VAR)
        with self.assertRaises(ExprError) as cm3:
            eval_expression("1 + * 2")
        self.assertEqual(cm3.exception.kind, EXPR_ERR_SYNTAX)

    def test_canonical_json_and_format_float(self) -> None:
        self.assertEqual(format_canonical_float(-0.0), "0")
        self.assertEqual(format_canonical_float(10.9000000001), "10.9")
        a = canonical_json({"b": 2, "a": 1, "c": [1.5, -0.0, "hi"]})
        b = canonical_json({"c": [1.5, 0.0, "hi"], "a": 1, "b": 2})
        self.assertEqual(a, b)
        self.assertEqual(a, b'{"a":1,"b":2,"c":[1.5,0,"hi"]}')
        self.assertEqual(len(compute_audit_merkle_root([])), 64)

    def test_constitutional_guards(self) -> None:
        base = {
            "schema_version": SCHEMA_VERSION,
            "claim_id": "CONST-PY-1",
            "claim_class": "calc_check",
            "statement": "2+2=4",
            "author_id": "agent-1",
            "verifier_id": "agent-1",
            "calculation": {"expression": "2 + 2", "claimed_value": 4, "has_claimed_value": True},
        }
        res = self.verifier.verify_claim(base)
        self.assertEqual(res["verdict"], VERDICT_REFUTED)
        self.assertEqual(res["reason_code"], REASON_SELF_VALIDATION)

        for action in ("redefine_voting_rules", "authorize_treasury", "self_declare_valid"):
            c = copy.deepcopy(base)
            c["verifier_id"] = "verifier-2"
            c["governance_action"] = action
            r = self.verifier.verify_claim(c)
            self.assertEqual(r["verdict"], VERDICT_REFUTED)
            self.assertEqual(r["reason_code"], REASON_FORBIDDEN_GOV_ACTION)

        for action in ("recommend", "flag_conflict", "estimate_value", "prepare_plan"):
            c = copy.deepcopy(base)
            c["verifier_id"] = "verifier-2"
            c["governance_action"] = action
            r = self.verifier.verify_claim(c)
            self.assertEqual(r["verdict"], VERDICT_VERIFIED)

    def test_reasoning_cycle_detection(self) -> None:
        claim = {
            "schema_version": SCHEMA_VERSION,
            "claim_id": "CYCLE-PY",
            "claim_class": "reasoning_chain_check",
            "statement": "cycle",
            "author_id": "a",
            "verifier_id": "b",
            "reasoning_chain": {
                "conclusion_step_id": "s2",
                "steps": [
                    {"step_id": "s1", "kind": "inference", "depends_on": ["s2"], "public_rationale": "x"},
                    {"step_id": "s2", "kind": "conclusion", "depends_on": ["s1"], "public_rationale": "y"},
                ],
            },
        }
        res = self.verifier.verify_claim(claim)
        self.assertEqual(res["verdict"], VERDICT_REFUTED)
        self.assertEqual(res["reason_code"], REASON_REASONING_CYCLE)

    def test_full_120_claim_benchmark_and_label_blindness(self) -> None:
        self.assertEqual(len(self.bundle["claims"]), 120)
        self.assertEqual(self.bundle["seed"], 1352)
        report = self.verifier.run_benchmark(self.bundle, "python-test")

        self.assertEqual(report["mechanical_fv_count"], 0)
        self.assertEqual(report["mechanical_fvr"], 0.0)
        self.assertEqual(report["correct_claims"], 107)
        for cc in ALL_CLAIM_CLASSES:
            self.assertEqual(report["per_claim_class"][cc]["total"], 30)

        stripped = copy.deepcopy(self.bundle)
        for c in stripped["claims"]:
            c.pop("expected_verdict", None)
            c.pop("negative_regime", None)
            c.pop("notes", None)
        _, stripped_root = self.verifier.verify_bundle(stripped)
        self.assertEqual(stripped_root, report["audit_merkle_root"])

    def test_go_python_120_of_120_bit_identical_parity(self) -> None:
        self.assertTrue(os.path.exists(RESULTS_PATH), "results.json generated by Go verifier must exist")
        with open(RESULTS_PATH, "r", encoding="utf-8") as f:
            go_report = json.load(f)
        py_report = self.verifier.run_benchmark(self.bundle, "python-3.12-stdlib")

        self.assertEqual(len(go_report["results"]), 120)
        self.assertEqual(len(py_report["results"]), 120)
        for g, p in zip(go_report["results"], py_report["results"]):
            self.assertEqual(g, p, f"Parity mismatch on {g.get('claim_id')}")
        self.assertEqual(go_report["audit_merkle_root"], py_report["audit_merkle_root"])
        self.assertEqual(go_report["confusion_matrix"], py_report["confusion_matrix"])
        self.assertEqual(go_report["per_verdict_metrics"], py_report["per_verdict_metrics"])
        self.assertEqual(go_report["per_claim_class"], py_report["per_claim_class"])


if __name__ == "__main__":
    unittest.main()
