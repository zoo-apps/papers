# Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
# SPDX-License-Identifier: Apache-2.0
"""Independent pure-Python unittest suite for poai-transcript.v1 and Go <-> Python parity."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from poai_verifier.ed25519 import verify as ed25519_verify
from poai_verifier.field import FIELD_MODULUS, exact_int_gemm, matvec_int8_mod_p, mod_p
from poai_verifier.verifier import (
    ERR_FORBIDDEN_GOVERNANCE_ACTION,
    ERR_FORBIDDEN_SEMANTIC_CLAIM,
    ERR_INVALID_SIGNATURE,
    KERNEL_PROFILE,
    SCHEMA_VERSION,
    SPEC_VERSION,
    VERDICT_COMPUTE_CORRUPTED,
    VERDICT_COMPUTE_VERIFIED,
    VERDICT_INVALID_TRANSCRIPT,
    VERDICT_POLICY_REJECTED,
    verify_parity_suite,
    verify_transcript,
)

REF_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = REF_DIR.parents[1]
FIXTURES_PATH = REF_DIR / "fixtures" / "parity-suite.v1.json"
RESULTS_PATH = REF_DIR / "results.json"
MANIFEST_PATH = REF_DIR / "corpus-manifest.json"
SCHEMA_PATH = REF_DIR / "schema" / "poai-transcript.v1.schema.json"


class TestPoAIVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
        cls.results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_01_rfc8032_ed25519_test_vector_1(self) -> None:
        """Pure-Python Ed25519 verifies RFC 8032 Section 7.1 TEST 1 (empty message) and rejects mutations."""
        pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(ed25519_verify(pub, b"", sig))
        self.assertFalse(ed25519_verify(pub, b"x", sig))
        bad_sig = bytes([sig[0] ^ 1]) + sig[1:]
        self.assertFalse(ed25519_verify(pub, b"", bad_sig))

    def test_02_corpus_manifest_pinned_sha256_integrity(self) -> None:
        """All 6 pinned .tex sources in corpus-manifest.json match exact disk bytes and SHA-256."""
        self.assertEqual(len(self.manifest["files"]), 6)
        for entry in self.manifest["files"]:
            path = REPO_ROOT / entry["path"]
            self.assertTrue(path.exists(), f"missing pinned paper: {entry['path']}")
            raw = path.read_bytes()
            self.assertEqual(len(raw), entry["bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])

    def test_03_go_python_bit_identical_parity_and_audit_merkle_root(self) -> None:
        """100% (16/16) bit-identical verdicts, error_codes, round digests, and audit_merkle_root across Go and Python."""
        self.assertEqual(len(self.suite["cases"]), 16)
        ok, got_root, mismatches = verify_parity_suite(self.suite)
        self.assertTrue(ok, f"Go <-> Python parity mismatches: {mismatches}")
        self.assertEqual(got_root, self.suite["audit_merkle_root"])
        self.assertEqual(got_root, self.results["audit_merkle_root"])

    def test_04_exact_int_gemm_matches_honest_fixtures(self) -> None:
        """Independent Python exact_int_gemm reproduces Go exact int64 output bit-for-bit on honest cases."""
        honest_cases = [c for c in self.suite["cases"] if c["category"] == "honest"]
        self.assertEqual(len(honest_cases), 3)
        for tc in honest_cases:
            dims = tc["transcript"]["header"]["dims"]
            recomputed = exact_int_gemm(tc["matrix_a"], dims["m"], dims["d"], tc["matrix_b"], dims["n"])
            self.assertEqual(recomputed, tc["matrix_c"], f"GEMM mismatch on {tc['case_id']}")

    def test_05_all_five_corruption_classes_caught(self) -> None:
        """All 5 corruption classes in parity suite produce COMPUTE_CORRUPTED in Python."""
        corrupt_cases = [c for c in self.suite["cases"] if c["category"].startswith("corruption_")]
        self.assertEqual(len(corrupt_cases), 8)
        for tc in corrupt_cases:
            receipt = verify_transcript(tc["transcript"], tc["matrix_a"], tc["matrix_b"], tc["matrix_c"])
            self.assertEqual(receipt["constitutional_boundary"]["compute_verdict"], VERDICT_COMPUTE_CORRUPTED)
            self.assertGreaterEqual(receipt["first_failing_round"], 0)

    def test_06_negative_regime_1_fiat_shamir_grinding_warning(self) -> None:
        """Negative Regime #1: forged Fiat-Shamir k=4 passes binary_01 but emits grinding_risk_warning=True."""
        tc = next(c for c in self.suite["cases"] if c["category"] == "negative_regime_1")
        receipt = verify_transcript(tc["transcript"], tc["matrix_a"], tc["matrix_b"], tc["matrix_c"])
        cb = receipt["constitutional_boundary"]
        self.assertEqual(cb["compute_verdict"], VERDICT_COMPUTE_VERIFIED)
        self.assertTrue(cb["grinding_risk_warning"])
        self.assertIn("ERR_WEAK_FIAT_SHAMIR_GRINDING_RISK", cb["error_codes"])
        # Confirm the matrix C really IS corrupted (C != A*B)!
        dims = tc["transcript"]["header"]["dims"]
        true_c = exact_int_gemm(tc["matrix_a"], dims["m"], dims["d"], tc["matrix_b"], dims["n"])
        self.assertNotEqual(true_c, tc["matrix_c"])

    def test_07_negative_regime_2_semantic_blindness_constitutional_lock(self) -> None:
        """Negative Regime #2: valid matmul with backdoor weights/false claim keeps semantic proof flags strictly False."""
        tc = next(c for c in self.suite["cases"] if c["category"] == "negative_regime_2")
        receipt = verify_transcript(tc["transcript"], tc["matrix_a"], tc["matrix_b"], tc["matrix_c"])
        cb = receipt["constitutional_boundary"]
        self.assertEqual(cb["compute_verdict"], VERDICT_COMPUTE_VERIFIED)
        self.assertTrue(cb["proves_matrix_product_only"])
        self.assertFalse(cb["proves_full_model_inference"])
        self.assertFalse(cb["proves_scientific_truth"])
        self.assertFalse(cb["proves_weight_provenance"])

    def test_08_constitutional_policy_rejection(self) -> None:
        """Forbidden autonomous governance actions and forged semantic proof flags yield POLICY_REJECTED."""
        tc = next(c for c in self.suite["cases"] if c["category"] == "constitutional_guard")
        receipt = verify_transcript(tc["transcript"], tc["matrix_a"], tc["matrix_b"], tc["matrix_c"])
        cb = receipt["constitutional_boundary"]
        self.assertEqual(cb["compute_verdict"], VERDICT_POLICY_REJECTED)
        self.assertIn(ERR_FORBIDDEN_GOVERNANCE_ACTION, cb["error_codes"])

        # Mutate an honest transcript to claim proves_scientific_truth = True.
        honest = copy.deepcopy(self.suite["cases"][0])
        honest["transcript"]["constitutional_boundary"]["proves_scientific_truth"] = True
        r2 = verify_transcript(honest["transcript"], honest["matrix_a"], honest["matrix_b"], honest["matrix_c"])
        self.assertEqual(r2["constitutional_boundary"]["compute_verdict"], VERDICT_POLICY_REJECTED)
        self.assertIn(ERR_FORBIDDEN_SEMANTIC_CLAIM, r2["constitutional_boundary"]["error_codes"])
        self.assertFalse(r2["constitutional_boundary"]["proves_scientific_truth"])

    def test_09_signature_and_commitment_tampering_rejected(self) -> None:
        """Tampered Ed25519 signature or post-commitment matrix mutation yields INVALID_TRANSCRIPT."""
        sig_tc = next(c for c in self.suite["cases"] if c["case_id"] == "parity-12-invalid-ed25519-sig")
        r_sig = verify_transcript(sig_tc["transcript"], sig_tc["matrix_a"], sig_tc["matrix_b"], sig_tc["matrix_c"])
        self.assertEqual(r_sig["constitutional_boundary"]["compute_verdict"], VERDICT_INVALID_TRANSCRIPT)
        self.assertIn(ERR_INVALID_SIGNATURE, r_sig["constitutional_boundary"]["error_codes"])

        com_tc = next(c for c in self.suite["cases"] if c["case_id"] == "parity-13-commitment-mismatch-c")
        r_com = verify_transcript(com_tc["transcript"], com_tc["matrix_a"], com_tc["matrix_b"], com_tc["matrix_c"])
        self.assertEqual(r_com["constitutional_boundary"]["compute_verdict"], VERDICT_INVALID_TRANSCRIPT)
        self.assertIn("ERR_COMMITMENT_MISMATCH_C", r_com["constitutional_boundary"]["error_codes"])

    def test_10_schema_structural_invariants(self) -> None:
        """Verify schema file and every fixture transcript obey required top-level fields and constitutional const locks."""
        cb_props = self.schema["properties"]["constitutional_boundary"]["properties"]
        self.assertIs(cb_props["proves_matrix_product_only"]["const"], True)
        self.assertIs(cb_props["proves_full_model_inference"]["const"], False)
        self.assertIs(cb_props["proves_scientific_truth"]["const"], False)
        self.assertIs(cb_props["proves_weight_provenance"]["const"], False)

        required_top = set(self.schema["required"])
        for tc in self.suite["cases"]:
            tx = tc["transcript"]
            self.assertEqual(set(tx.keys()), required_top)
            self.assertEqual(tx["schema_version"], SCHEMA_VERSION)
            self.assertEqual(tx["spec_version"], SPEC_VERSION)
            self.assertEqual(tx["header"]["kernel_profile"], KERNEL_PROFILE)
            self.assertEqual(tx["header"]["field_modulus"], FIELD_MODULUS)

    def test_11_field_arithmetic_edge_cases(self) -> None:
        """Modular reduction and matvec stay canonical in [0, p-1] for negative and extreme inputs."""
        self.assertEqual(mod_p(-1), FIELD_MODULUS - 1)
        self.assertEqual(mod_p(FIELD_MODULUS), 0)
        res = matvec_int8_mod_p([-128, -128], 1, 2, [FIELD_MODULUS - 1, FIELD_MODULUS - 1])
        self.assertEqual(res, [256])

    def test_12_benchmark_results_invariants(self) -> None:
        """Published results.json meets empirical detection bounds, 0% FRR, and all 3 negative regimes."""
        for row in self.results["honest_baseline"]:
            self.assertEqual(row["false_rejects"], 0)
            self.assertEqual(row["frr_pct"], 0.0)

        # Verify field_fp achieves 100.0% empirical detection at k=1 across all 5 corruption classes.
        fp_rows = [r for r in self.results["soundness_matrix"] if r["challenge_mode"] == "field_fp" and r["rounds_k"] == 1]
        self.assertEqual(len(fp_rows), 5)
        for row in fp_rows:
            self.assertEqual(row["empirical_detection_pct"], 100.0)

        # Verify binary_01 at k=40 achieves 100.0% across all 5 corruption classes.
        bin40_rows = [r for r in self.results["soundness_matrix"] if r["challenge_mode"] == "binary_01" and r["rounds_k"] == 40]
        self.assertEqual(len(bin40_rows), 5)
        for row in bin40_rows:
            self.assertEqual(row["empirical_detection_pct"], 100.0)

        # Verify Negative Regime #3 shows < 1.0x speedup at n=16, k=40.
        neg3_16_40 = [
            r for r in self.results["neg_small_matrix_verification_overhead"]["rows"]
            if r["dim"] == 16 and r["rounds_k"] == 40
        ]
        self.assertEqual(len(neg3_16_40), 2)
        for row in neg3_16_40:
            self.assertLess(row["speedup"], 1.0)


if __name__ == "__main__":
    unittest.main()
