# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Zero-dependency unittest suite asserting 100% Go <-> Python bit-identical parity."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from infnet_verifier.canonical import (
    canonical_delivery_receipt_bytes,
    canonical_node_advertisement_bytes,
    compute_output_merkle_root,
)
from infnet_verifier.ed25519 import verify_ed25519
from infnet_verifier.verifier import (
    ERR_CAPACITY_CONSERVATION,
    ERR_CONSTITUTIONAL_VIOLATION,
    ERR_INVALID_NODE_ADVERTISEMENT,
    ERR_INVALID_RECEIPT_SIGNATURE,
    ERR_KEY_MISMATCH,
    ERR_OK,
    ERR_OUTPUT_MERKLE_MISMATCH,
    ERR_PRIVACY_BOUNDARY_VIOLATION,
    ERR_STALE_HEARTBEAT_EPOCH,
    verify_capacity_conservation,
    verify_node_advertisement,
    verify_parity_case,
    verify_parity_suite,
)

REF_DIR = Path(__file__).resolve().parents[2]
SUITE_PATH = REF_DIR / "fixtures" / "parity-suite.v1.json"
RESULTS_PATH = REF_DIR / "results.json"
SCHEMA_PATH = REF_DIR / "schema" / "inference-net.v1.schema.json"
MANIFEST_PATH = REF_DIR / "corpus-manifest.json"


class TestInfnetVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = json.loads(SUITE_PATH.read_text(encoding="utf-8"))
        cls.results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        cls.cases_by_id = {c["case_id"]: c for c in cls.suite["cases"]}

    def test_01_full_go_python_bit_identical_parity_and_audit_merkle_root(self) -> None:
        verdicts, audit_root = verify_parity_suite(self.suite)
        self.assertEqual(len(verdicts), 18)
        for case, vr in zip(self.suite["cases"], verdicts):
            self.assertEqual(vr.valid, case["expected_valid"], f"valid mismatch for {case['case_id']}")
            self.assertEqual(vr.error_code, case["expected_error_code"], f"code mismatch for {case['case_id']}")
            self.assertEqual(
                vr.verdict_digest,
                case["expected_verdict_digest"],
                f"verdict_digest mismatch for {case['case_id']}",
            )
        self.assertEqual(audit_root, self.suite["audit_merkle_root"])
        self.assertEqual(audit_root, self.results["audit_merkle_root"])

    def test_02_pure_python_ed25519_verifies_real_go_signatures(self) -> None:
        case = self.cases_by_id["valid_dynamo_disaggregated_replica"]
        for ad in case["nodes"]:
            code, detail = verify_node_advertisement(ad)
            self.assertEqual(code, ERR_OK, detail)
        rcpt = case["receipt"]
        pub = bytes.fromhex(rcpt["provider_public_key_hex"])
        sig = bytes.fromhex(rcpt["signature_hex"])
        msg = canonical_delivery_receipt_bytes(rcpt)
        self.assertTrue(verify_ed25519(pub, msg, sig))
        # Flipping 1 bit in signature must fail verification.
        bad_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
        self.assertFalse(verify_ed25519(pub, msg, bad_sig))

    def test_03_valid_topologies_and_failover_cases(self) -> None:
        valid_ids = [
            "valid_centralized_h100_baseline",
            "valid_dynamo_disaggregated_replica",
            "valid_dynamo_live_failover_recovery",
            "valid_petals_4hop_wan_pipeline",
            "valid_petals_pipeline_failover_recovery",
            "valid_strict_privacy_tee_enclave",
            "valid_monotonic_heartbeat_epoch_refresh",
        ]
        for cid in valid_ids:
            vr = verify_parity_case(self.cases_by_id[cid])
            self.assertTrue(vr.valid, f"{cid} failed: {vr.error_code} {vr.detail}")
            self.assertEqual(vr.error_code, ERR_OK)
            self.assertTrue(vr.signature_valid)
            self.assertTrue(vr.privacy_compliant)
            self.assertTrue(vr.capacity_conserved)
            self.assertTrue(vr.constitutional_valid)

    def test_04_rejects_tampered_receipt_signature(self) -> None:
        vr = verify_parity_case(self.cases_by_id["reject_tampered_receipt_signature"])
        self.assertFalse(vr.valid)
        self.assertEqual(vr.error_code, ERR_INVALID_RECEIPT_SIGNATURE)
        self.assertFalse(vr.signature_valid)

    def test_05_rejects_output_merkle_tampering(self) -> None:
        vr = verify_parity_case(self.cases_by_id["reject_output_merkle_tampering"])
        self.assertFalse(vr.valid)
        self.assertEqual(vr.error_code, ERR_OUTPUT_MERKLE_MISMATCH)

    def test_06_rejects_privacy_boundary_violations(self) -> None:
        vr1 = verify_parity_case(self.cases_by_id["reject_privacy_boundary_public_relay_leak"])
        self.assertFalse(vr1.valid)
        self.assertEqual(vr1.error_code, ERR_PRIVACY_BOUNDARY_VIOLATION)
        self.assertFalse(vr1.privacy_compliant)

        vr2 = verify_parity_case(self.cases_by_id["reject_privacy_boundary_failed_hop_leak"])
        self.assertFalse(vr2.valid)
        self.assertEqual(vr2.error_code, ERR_PRIVACY_BOUNDARY_VIOLATION)
        self.assertFalse(vr2.privacy_compliant)

    def test_07_rejects_capacity_leaks_and_oversubscription(self) -> None:
        vr1 = verify_parity_case(self.cases_by_id["reject_capacity_vram_kv_leak"])
        self.assertFalse(vr1.valid)
        self.assertEqual(vr1.error_code, ERR_CAPACITY_CONSERVATION)
        self.assertFalse(vr1.capacity_conserved)

        vr2 = verify_parity_case(self.cases_by_id["reject_capacity_vram_oversubscription"])
        self.assertFalse(vr2.valid)
        self.assertEqual(vr2.error_code, ERR_CAPACITY_CONSERVATION)
        self.assertFalse(vr2.capacity_conserved)

    def test_08_rejects_stale_epoch_key_spoof_and_forged_advertisement(self) -> None:
        vr1 = verify_parity_case(self.cases_by_id["reject_stale_heartbeat_epoch_replay"])
        self.assertFalse(vr1.valid)
        self.assertEqual(vr1.error_code, ERR_STALE_HEARTBEAT_EPOCH)

        vr2 = verify_parity_case(self.cases_by_id["reject_node_key_spoofing"])
        self.assertFalse(vr2.valid)
        self.assertEqual(vr2.error_code, ERR_KEY_MISMATCH)

        vr3 = verify_parity_case(self.cases_by_id["reject_invalid_node_advertisement_signature"])
        self.assertFalse(vr3.valid)
        self.assertEqual(vr3.error_code, ERR_INVALID_NODE_ADVERTISEMENT)

    def test_09_enforces_constitutional_locks(self) -> None:
        vr1 = verify_parity_case(self.cases_by_id["reject_constitutional_scientific_truth_claim"])
        self.assertFalse(vr1.valid)
        self.assertEqual(vr1.error_code, ERR_CONSTITUTIONAL_VIOLATION)
        self.assertFalse(vr1.constitutional_valid)

        vr2 = verify_parity_case(self.cases_by_id["reject_constitutional_treasury_spend_claim"])
        self.assertFalse(vr2.valid)
        self.assertEqual(vr2.error_code, ERR_CONSTITUTIONAL_VIOLATION)
        self.assertFalse(vr2.constitutional_valid)

    def test_10_output_merkle_root_empty_and_mutation(self) -> None:
        empty_root = compute_output_merkle_root([])
        self.assertEqual(len(empty_root), 64)
        case = self.cases_by_id["valid_centralized_h100_baseline"]
        root = compute_output_merkle_root(case["output_chunks"])
        self.assertEqual(root, case["receipt"]["output_merkle_root"])
        mutated = list(case["output_chunks"])
        mutated[-1] = "mutated_tail_token"
        self.assertNotEqual(compute_output_merkle_root(mutated), root)

    def test_11_capacity_conservation_rejects_double_release_and_non_monotonic_seq(self) -> None:
        case = self.cases_by_id["valid_centralized_h100_baseline"]
        node_map = {n["node_id"]: n for n in case["nodes"]}
        ledger = copy.deepcopy(case["capacity_ledger"])
        self.assertTrue(verify_capacity_conservation(node_map, ledger)[0])

        # Duplicate RELEASE event must fail conservation.
        dup = copy.deepcopy(ledger)
        extra = copy.deepcopy(dup[-1])
        extra["seq"] = dup[-1]["seq"] + 1
        dup.append(extra)
        self.assertFalse(verify_capacity_conservation(node_map, dup)[0])

        # Out-of-order seq must fail conservation.
        bad_seq = copy.deepcopy(ledger)
        bad_seq[-1]["seq"] = bad_seq[0]["seq"]
        self.assertFalse(verify_capacity_conservation(node_map, bad_seq)[0])

    def test_12_results_json_and_schema_constitutional_invariants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        rcpt_props = schema["$defs"]["DeliveryReceipt"]["properties"]
        self.assertIs(rcpt_props["proves_scientific_truth"]["const"], False)
        self.assertIs(rcpt_props["authorizes_treasury_spend"]["const"], False)

        self.assertIs(self.results["proves_scientific_truth"], False)
        self.assertIs(self.results["authorizes_treasury_spend"], False)
        self.assertEqual(self.results["total_privacy_leaks"], 0)
        self.assertEqual(self.results["total_capacity_leaks"], 0)
        self.assertEqual(len(self.results["negative_regimes"]), 3)
        self.assertEqual(self.results["seed"], 1350)

        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(self.results["corpus_files_verified"], len(manifest["files"]))


if __name__ == "__main__":
    unittest.main()
