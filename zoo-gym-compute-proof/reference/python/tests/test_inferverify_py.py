# Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
# Licensed under the Apache License, Version 2.0.
"""Comprehensive pure-Python unittest suite verifying Go <-> Python parity & security."""

from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from inferverify_py import ed25519, inference, tlog, verifier

REF_DIR = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REF_DIR / "fixtures" / "verification-suite.v1.json"
RESULTS_PATH = REF_DIR / "results.json"
MANIFEST_PATH = REF_DIR / "corpus-manifest.json"
REPO_ROOT = REF_DIR.parents[1]


class TestInferVerifyPy(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        cls.go_results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        cls.model = inference.QuantizedMLP(
            cls.suite["corpus_root_sha256"], cls.suite["model_id"]
        )
        cls.audit = verifier.audit_suite(cls.suite)

    def test_01_rfc8032_ed25519_test_vector(self) -> None:
        """RFC 8032 Section 7.1 Test Vector 1 (empty message) & tamper rejection."""
        pub = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(ed25519.verify(pub, b"", sig))
        self.assertFalse(ed25519.verify(pub, b"x", sig))
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0x01
        self.assertFalse(ed25519.verify(pub, b"", bytes(bad_sig)))

    def test_02_corpus_manifest_pinning_and_model_digest_parity(self) -> None:
        """Verify all 7 real .tex papers match manifest SHA-256 and Go model_digest."""
        import hashlib

        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["files"]), 7)
        root_lines = []
        for entry in manifest["files"]:
            data = (REPO_ROOT / entry["path"]).read_bytes()
            self.assertEqual(len(data), entry["bytes"])
            digest = hashlib.sha256(data).hexdigest()
            self.assertEqual(digest, entry["sha256"])
            root_lines.append(f"{entry['path']}:{entry['sha256']}\n")
        corpus_root = hashlib.sha256("".join(root_lines).encode("utf-8")).hexdigest()
        self.assertEqual(corpus_root, self.suite["corpus_root_sha256"])
        self.assertEqual(self.model.model_digest, self.suite["model_digest"])
        self.assertEqual(self.model.model_digest, self.go_results["model_digest"])

    def test_03_full_225_case_go_python_bit_identical_parity(self) -> None:
        """100.00% Go <-> Python bit-identical verdicts, error codes & audit_merkle_root."""
        self.assertEqual(self.audit.golden_cases, 200)
        self.assertEqual(self.audit.adversarial_cases, 25)
        self.assertEqual(self.audit.total_cases, 225)
        self.assertEqual(self.audit.matches_expected, 225)
        self.assertEqual(
            self.audit.audit_merkle_root, self.suite["expected_audit_merkle_root"]
        )
        self.assertEqual(
            self.audit.audit_merkle_root,
            self.go_results["parity_summary"]["audit_merkle_root"],
        )

    def test_04_adversarial_case_coverage(self) -> None:
        """Every required adversarial attack class is detected with exact normative error code."""
        by_id = {r.case_id: r for r in self.audit.results}
        expected_map = {
            "adv_01_forged_dsse_signature": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_INVALID_DSSE_SIG",
            ),
            "adv_03_missing_tlog_proof": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_MISSING_TLOG_PROOF",
            ),
            "adv_04_tampered_tlog_merkle_path": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_INVALID_TLOG_PROOF",
            ),
            "adv_05_forged_tlog_checkpoint_sig": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_INVALID_TLOG_CHECKPOINT_SIG",
            ),
            "adv_07_revoked_worker_key": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_KEY_REVOKED",
            ),
            "adv_08_expired_worker_key": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_KEY_EXPIRED",
            ),
            "adv_10_epoch_replay_attack": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_EPOCH_MISMATCH",
            ),
            "adv_11_equivocating_duplicate_job": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_EQUIVOCATION_DETECTED",
            ),
            "adv_15_lazy_cheater_caught_reexecution": (
                verifier.VERDICT_FRAUD_DETECTED,
                "ERR_OUTPUT_MISMATCH_REEXEC",
            ),
            "adv_16_lazy_cheater_caught_challenge": (
                verifier.VERDICT_FRAUD_DETECTED,
                "ERR_CHALLENGE_FRAUD_PROVEN",
            ),
            "adv_18_colluding_same_operator_reexec": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_COLLUDING_OPERATOR_GROUP",
            ),
            "adv_19_colluding_self_challenger": (
                verifier.VERDICT_INVALID_ATTESTATION,
                "ERR_COLLUDING_OPERATOR_GROUP",
            ),
            "adv_22_ai_self_certification": (
                verifier.VERDICT_POLICY_REJECTED,
                "ERR_AI_SELF_CERT_FORBIDDEN",
            ),
            "adv_23_ai_policy_mutation": (
                verifier.VERDICT_POLICY_REJECTED,
                "ERR_AI_POLICY_MUTATION_FORBIDDEN",
            ),
            "adv_24_ai_slashing_approval": (
                verifier.VERDICT_POLICY_REJECTED,
                "ERR_AI_SLASH_APPROVAL_FORBIDDEN",
            ),
            "adv_25_overclaimed_tee_proof_scope": (
                verifier.VERDICT_POLICY_REJECTED,
                "ERR_OVERCLAIMED_PROOF_SCOPE",
            ),
        }
        for cid, (exp_verdict, exp_err) in expected_map.items():
            self.assertIn(cid, by_id)
            self.assertEqual(by_id[cid].verdict, exp_verdict, cid)
            self.assertEqual(by_id[cid].error_code, exp_err, cid)

    def test_05_honest_negative_attestation_blind_to_lazy_cheating(self) -> None:
        """Valid-key lazy dummy cheater MUST escape signed_attestation_only (fraud_escaped=True)."""
        by_id = {r.case_id: r for r in self.audit.results}
        r = by_id["adv_14_lazy_cheater_escapes_attestation_only"]
        self.assertEqual(r.verdict, verifier.VERDICT_VERIFIED)
        self.assertEqual(r.error_code, "OK")
        self.assertTrue(r.fraud_escaped)

    def test_06_live_tamper_mutations_caught_independently(self) -> None:
        """Mutating a golden case in Python immediately flips verification to rejected."""
        golden0 = copy.deepcopy(self.suite["cases"][0])
        # Verify unmutated passes
        r_ok = verifier.verify_case(
            golden0, self.model, self.suite["trust_root"], self.suite["policy"]
        )
        self.assertEqual(r_ok.verdict, verifier.VERDICT_VERIFIED)

        # Mutate DSSE signature byte
        mut_sig = copy.deepcopy(golden0)
        sb = bytearray(base64.b64decode(mut_sig["worker_envelope"]["signatures"][0]["sig"]))
        sb[5] ^= 0x80
        mut_sig["worker_envelope"]["signatures"][0]["sig"] = base64.b64encode(
            bytes(sb)
        ).decode("ascii")
        r_bad_sig = verifier.verify_case(
            mut_sig, self.model, self.suite["trust_root"], self.suite["policy"]
        )
        self.assertEqual(r_bad_sig.verdict, verifier.VERDICT_INVALID_ATTESTATION)
        self.assertEqual(r_bad_sig.error_code, "ERR_INVALID_DSSE_SIG")

        # Mutate tlog leaf index
        mut_tlog = copy.deepcopy(golden0)
        mut_tlog["tlog_bundle"]["log_index"] ^= 1
        r_bad_tlog = verifier.verify_case(
            mut_tlog, self.model, self.suite["trust_root"], self.suite["policy"]
        )
        self.assertEqual(r_bad_tlog.verdict, verifier.VERDICT_INVALID_ATTESTATION)
        self.assertEqual(r_bad_tlog.error_code, "ERR_INVALID_TLOG_PROOF")

    def test_07_rfc6962_merkle_root_domain_separation(self) -> None:
        """Ensure RFC 6962 leaf (0x00) vs node (0x01) domain separation prevents second-preimage attacks."""
        a = b"leaf-a"
        b = b"leaf-b"
        root_two = tlog.compute_merkle_root_rfc6962([a, b])
        # Attempting to pass concatenated child hashes as a single leaf MUST NOT match
        forged_leaf = tlog.hash_leaf_rfc6962(a) + tlog.hash_leaf_rfc6962(b)
        root_one = tlog.compute_merkle_root_rfc6962([forged_leaf])
        self.assertNotEqual(root_two, root_one)

    def test_08_negative_regimes_in_results_json(self) -> None:
        """Verify all 3 honest negative regimes are present and mathematically sound."""
        negs = {n["id"]: n for n in self.go_results["negative_regimes"]}
        self.assertEqual(len(negs), 3)
        self.assertEqual(
            negs["neg_attestation_blind_to_valid_key_cheating"]["metrics"][
                "cheat_detection_rate_pct"
            ],
            0.0,
        )
        self.assertGreater(
            negs["neg_undercollateralized_challenge_profitable_cheating"]["metrics"][
                "cheating_advantage_per_job"
            ],
            0.0,
        )
        self.assertEqual(
            negs["neg_full_reexecution_cost_ceiling"]["metrics"][
                "reexec_k3_compute_multiplier"
            ],
            3.0,
        )


if __name__ == "__main__":
    unittest.main()
