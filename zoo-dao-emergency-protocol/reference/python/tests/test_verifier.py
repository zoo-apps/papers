# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Independent Python stdlib unittest suite for constitutional-gov.v1."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from govcheck_verifier.canonical import audit_merkle_root, case_digest, signing_preimage
from govcheck_verifier.cli import main as cli_main
from govcheck_verifier.ed25519 import verify_ed25519
from govcheck_verifier.engine import apply_action, evaluate_policy_hierarchy
from govcheck_verifier.rego_lint import validate_rego_bundle
from govcheck_verifier.verifier import VerificationError, verify_case, verify_results_bundle

REF_DIR = Path(__file__).resolve().parents[2]
RESULTS_PATH = REF_DIR / "results.json"
REGO_DIR = REF_DIR / "rego"


class TestConstitutionalGovVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))

    def test_01_full_bundle_go_python_parity(self) -> None:
        summary = verify_results_bundle(RESULTS_PATH, REGO_DIR)
        self.assertGreaterEqual(summary["verified_cases"], 47)
        self.assertEqual(summary["audit_merkle_root"], self.results["audit_merkle_root"])
        self.assertEqual(summary["rego_bundle_sha256"], self.results["rego_bundle"]["bundle_sha256"])
        self.assertEqual(summary["mutants_killed"], "10/10")
        self.assertGreaterEqual(summary["mc_states_and_transitions"], 50000)

    def test_02_every_adversarial_case_bit_identical(self) -> None:
        cases = self.results["adversarial_suite"]["cases"]
        self.assertEqual(len(cases), 47)
        for case_obj in cases:
            with self.subTest(case_id=case_obj["case_id"]):
                recomputed = verify_case(case_obj)
                self.assertEqual(recomputed["actual_verdict"], case_obj["actual_verdict"])
                self.assertEqual(recomputed["actual_error_code"], case_obj["actual_error_code"])
                self.assertEqual(case_digest(recomputed), case_obj["case_digest"])

    def test_03_ed25519_tamper_rejected(self) -> None:
        # Take a valid ALLOW case and flip one hex character in the Ed25519 signature.
        ok_case = next(c for c in self.results["adversarial_suite"]["cases"] if c["expected_verdict"] == "ALLOW")
        tampered = copy.deepcopy(ok_case)
        sig = tampered["actions"][-1]["signers"][0]["signature_hex"]
        flipped = sig[:-1] + ("1" if sig[-1] == "0" else "0")
        tampered["actions"][-1]["signers"][0]["signature_hex"] = flipped
        state = copy.deepcopy(tampered["initial_state"])
        for act in tampered["actions"][:-1]:
            apply_action(state, act, verify_sigs=True)
        verdict, code, _ = apply_action(state, tampered["actions"][-1], verify_sigs=True)
        self.assertEqual(verdict, "DENY")
        self.assertEqual(code, "ERR_INVALID_SIGNATURE")

    def test_04_ed25519_direct_verify_valid_and_invalid(self) -> None:
        ok_case = next(c for c in self.results["adversarial_suite"]["cases"] if c["case_id"] == "ok_06_ai_advisory_recommendation")
        act = ok_case["actions"][0]
        sig = act["signers"][0]
        actor = next(a for a in ok_case["initial_state"]["actors"] if a["id"] == sig["actor_id"])
        msg = signing_preimage(act, sig["actor_id"], int(sig["nonce"]))
        self.assertTrue(verify_ed25519(actor["pubkey_hex"], msg, sig["signature_hex"]))
        self.assertFalse(verify_ed25519(actor["pubkey_hex"], msg + b"x", sig["signature_hex"]))

    def test_05_inv07_conflict_witness_parity(self) -> None:
        conflict_cases = [
            c for c in self.results["adversarial_suite"]["cases"]
            if c["actual_error_code"] == "ERR_DENY_RULE_CONFLICT"
        ]
        self.assertGreaterEqual(len(conflict_cases), 2)
        for c in conflict_cases:
            w = c.get("conflict_witness")
            self.assertIsNotNone(w)
            self.assertEqual(w["resolution"], "DENY_RULE_CONFLICT")
            self.assertGreaterEqual(len(w["allow_rule_ids"]), 1)
            self.assertGreaterEqual(len(w["deny_rule_ids"]), 1)
            ok, code, py_w = evaluate_policy_hierarchy(c["initial_state"], c["actions"][-1])
            self.assertFalse(ok)
            self.assertEqual(code, "ERR_DENY_RULE_CONFLICT")
            self.assertEqual(py_w, w)

    def test_06_merkle_root_tamper_detection(self) -> None:
        cases = copy.deepcopy(self.results["adversarial_suite"]["cases"])
        orig_root = audit_merkle_root(cases)
        self.assertEqual(orig_root, self.results["audit_merkle_root"])
        cases[0]["actual_error_code"] = "TAMPERED_CODE"
        self.assertNotEqual(audit_merkle_root(cases), orig_root)

    def test_07_rego_v1_bundle_syntax_and_hash(self) -> None:
        files, sha, stats = validate_rego_bundle(REGO_DIR)
        self.assertEqual(len(files), 5)
        self.assertEqual(sha, self.results["rego_bundle"]["bundle_sha256"])
        self.assertGreaterEqual(stats["rego_unit_tests"], 6)

    def test_08_fuzzer_regression_dormant_cycle_resurrection(self) -> None:
        c = next(
            x for x in self.results["adversarial_suite"]["cases"]
            if x["case_id"] == "adv_47_dormant_suspension_cycle_resurrection"
        )
        res = verify_case(c)
        self.assertEqual(res["actual_verdict"], "DENY")
        self.assertEqual(res["actual_error_code"], "ERR_DELEGATION_CYCLE")

    def test_09_all_ten_invariants_covered(self) -> None:
        invs = {c["invariant_id"] for c in self.results["adversarial_suite"]["cases"]}
        expected = {f"INV-{i:02d}" for i in range(1, 11)}
        self.assertEqual(invs, expected)

    def test_10_negative_regimes_honest_bounds(self) -> None:
        neg = self.results["negative_regimes"]
        n1 = neg["neg_first_match_masks_rule_conflict"]
        self.assertGreater(n1["naive_first_match_unsafe_allows"], 0)
        self.assertEqual(n1["fail_closed_blocked"], n1["trials"])
        n2 = neg["neg_fail_closed_liveness_deadlock"]
        self.assertEqual(n2["liveness_under_conflict_bps"], 0)
        self.assertEqual(n2["liveness_under_pause_bps"], 0)
        self.assertEqual(n2["safety_violations"], 0)
        n3 = neg["neg_bounded_mc_depth_horizon"]
        self.assertTrue(n3["unbounded_proof_required"])
        self.assertEqual(n3["planted_bug_min_depth"], 8)

    def test_11_verify_case_raises_on_verdict_mismatch(self) -> None:
        bad = copy.deepcopy(self.results["adversarial_suite"]["cases"][0])
        bad["actual_verdict"] = "ALLOW"
        with self.assertRaises(VerificationError):
            verify_case(bad)

    def test_12_cli_returns_zero(self) -> None:
        rc = cli_main(["--in", str(RESULTS_PATH), "--rego-dir", str(REGO_DIR)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
