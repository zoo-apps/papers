# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Independent Python unittest suite for settlement-receipt.v1 and Go<->Python parity."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from settlement_verifier.ed25519 import verify_ed25519
from settlement_verifier.merkle import (
    compute_merkle_root,
    compute_receipt_merkle_leaf,
    empty_merkle_root,
    hash_merkle_node,
    verify_merkle_proof,
)
from settlement_verifier.verifier import (
    ERR_ACCOUNTING_MISMATCH,
    ERR_BUDGET_OVERFLOW,
    ERR_INVALID_MERKLE_PROOF,
    ERR_INVALID_NULLIFIER,
    ERR_INVALID_SIGNATURE,
    compute_exact_split,
    verify_trace_bundle,
)

REF_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = REF_DIR.parents[1]
FIXTURE_PATH = REF_DIR / "fixtures" / "settlement-trace.v1.json"
MANIFEST_PATH = REF_DIR / "corpus-manifest.json"
GO_DIR = REF_DIR / "go"


class TestRFC8032Ed25519(unittest.TestCase):
    """Official RFC 8032 Section 7.1 Ed25519 test vectors."""

    def test_rfc8032_vectors(self) -> None:
        vectors = [
            (
                # TEST 1: empty message
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                b"",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                # TEST 2: 1-byte message 0x72
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                b"\x72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                # TEST 3: 2-byte message 0xaf82
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                b"\xaf\x82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ]
        for pub_hex, msg, sig_hex in vectors:
            pub = bytes.fromhex(pub_hex)
            sig = bytes.fromhex(sig_hex)
            self.assertTrue(verify_ed25519(pub, msg, sig))
            # Flip 1 bit in signature -> MUST fail.
            bad_sig = bytearray(sig)
            bad_sig[0] ^= 0x01
            self.assertFalse(verify_ed25519(pub, msg, bytes(bad_sig)))
            # Wrong message -> MUST fail.
            self.assertFalse(verify_ed25519(pub, msg + b"x", sig))


class TestMerkleAndAccounting(unittest.TestCase):
    def test_merkle_empty_and_three_leaves(self) -> None:
        self.assertEqual(compute_merkle_root([]), empty_merkle_root())
        l0 = compute_receipt_merkle_leaf("a" * 64, "1" * 64, 100)
        l1 = compute_receipt_merkle_leaf("b" * 64, "2" * 64, 200)
        l2 = compute_receipt_merkle_leaf("c" * 64, "3" * 64, 300)
        root = compute_merkle_root([l0, l1, l2])
        # Level 1: H(l0, l1), H(l2, l2)
        h01 = hash_merkle_node(l0, l1)
        h22 = hash_merkle_node(l2, l2)
        self.assertEqual(root, hash_merkle_node(h01, h22))
        proof_l0 = [
            {"sibling_hex": l1, "position": "right"},
            {"sibling_hex": h22, "position": "right"},
        ]
        self.assertTrue(verify_merkle_proof(l0, proof_l0, root))
        self.assertFalse(verify_merkle_proof(l1, proof_l0, root))

    def test_exact_integer_split_zero_dust(self) -> None:
        for max_b, cons in [(1_000_007, 999_999), (50_003, 17_333), (10, 1)]:
            split, err = compute_exact_split(max_b, cons, 200, 100)
            self.assertEqual(err, "")
            assert split is not None
            prov, conserv, proto, refund = split
            self.assertEqual(prov + conserv + proto, cons)
            self.assertEqual(cons + refund, max_b)
        _, err = compute_exact_split(100, 101, 200, 100)
        self.assertEqual(err, ERR_BUDGET_OVERFLOW)


class TestCorpusAndFullTraceParity(unittest.TestCase):
    def test_corpus_manifest_sha256(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["papers"]), 8)
        for p in manifest["papers"]:
            data = (REPO_ROOT / p["path"]).read_bytes()
            self.assertEqual(len(data), p["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), p["sha256"])

    def test_full_trace_verification_and_go_python_bit_identical_parity(self) -> None:
        bundle = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        py_report = verify_trace_bundle(bundle)

        self.assertEqual(py_report["total_cases"], 224)
        self.assertEqual(py_report["accepted_cases"], 200)
        self.assertEqual(py_report["rejected_cases"], 24)
        self.assertTrue(py_report["all_matched"])
        self.assertTrue(py_report["conservation_exact"])
        self.assertTrue(py_report["audit_root_matched"])
        self.assertEqual(py_report["audit_merkle_root"], bundle["expected_audit_merkle_root"])
        self.assertEqual(py_report["balance_sheet"], bundle["expected_balance_sheet"])

        # Cross-verify bit-identical output against independent Go CLI verifier.
        proc = subprocess.run(
            ["go", "run", "./cmd/settle-verify", "--trace", str(FIXTURE_PATH)],
            cwd=str(GO_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        go_summary = json.loads(proc.stdout)
        bs = py_report["balance_sheet"]
        self.assertEqual(py_report["total_cases"], go_summary["total_cases"])
        self.assertEqual(py_report["accepted_cases"], go_summary["accepted_cases"])
        self.assertEqual(py_report["rejected_cases"], go_summary["rejected_cases"])
        self.assertEqual(py_report["matched_count"], go_summary["matched_count"])
        self.assertEqual(py_report["conservation_exact"], go_summary["conservation_exact"])
        self.assertEqual(py_report["audit_merkle_root"], go_summary["audit_merkle_root"])
        self.assertEqual(bs["total_finalized_escrow_micro_zoo"], go_summary["total_finalized_escrow"])
        self.assertEqual(bs["total_authorized_payout_micro_zoo"], go_summary["total_authorized"])
        self.assertEqual(bs["conservation_fund_micro_zoo"], go_summary["conservation_fund"])
        self.assertEqual(bs["protocol_fee_pool_micro_zoo"], go_summary["protocol_fee_pool"])
        self.assertEqual(bs["total_payer_refunds_micro_zoo"], go_summary["total_payer_refunds"])

    def test_tamper_detection_on_lifecycle_case(self) -> None:
        base_bundle = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

        # 1. Tamper validator signature in case 0 -> ERR_INVALID_SIGNATURE
        b1 = copy.deepcopy(base_bundle)
        sig = bytearray.fromhex(b1["cases"][0]["attestations"][0]["signature_hex"])
        sig[0] ^= 0xFF
        b1["cases"][0]["attestations"][0]["signature_hex"] = sig.hex()
        r1 = verify_trace_bundle(b1)
        self.assertEqual(r1["case_verdicts"][0]["verdict"], "REJECT")
        self.assertEqual(r1["case_verdicts"][0]["error_code"], ERR_INVALID_SIGNATURE)

        # 2. Tamper Merkle sibling in case 0 -> ERR_INVALID_MERKLE_PROOF
        b2 = copy.deepcopy(base_bundle)
        sib = bytearray.fromhex(b2["cases"][0]["authorization"]["merkle_proof"][0]["sibling_hex"])
        sib[0] ^= 0xFF
        b2["cases"][0]["authorization"]["merkle_proof"][0]["sibling_hex"] = sib.hex()
        r2 = verify_trace_bundle(b2)
        self.assertEqual(r2["case_verdicts"][0]["verdict"], "REJECT")
        self.assertEqual(r2["case_verdicts"][0]["error_code"], ERR_INVALID_MERKLE_PROOF)

        # 3. Tamper micro-ZOO split in case 0 -> ERR_ACCOUNTING_MISMATCH
        b3 = copy.deepcopy(base_bundle)
        b3["cases"][0]["receipt"]["provider_share_micro_zoo"] += 1
        r3 = verify_trace_bundle(b3)
        self.assertEqual(r3["case_verdicts"][0]["verdict"], "REJECT")
        self.assertEqual(r3["case_verdicts"][0]["error_code"], ERR_ACCOUNTING_MISMATCH)

        # 4. Tamper nullifier in case 0 -> ERR_INVALID_NULLIFIER
        b4 = copy.deepcopy(base_bundle)
        nf = bytearray.fromhex(b4["cases"][0]["receipt"]["nullifier"])
        nf[0] ^= 0xFF
        b4["cases"][0]["receipt"]["nullifier"] = nf.hex()
        r4 = verify_trace_bundle(b4)
        self.assertEqual(r4["case_verdicts"][0]["verdict"], "REJECT")
        self.assertEqual(r4["case_verdicts"][0]["error_code"], ERR_INVALID_NULLIFIER)


if __name__ == "__main__":
    unittest.main()
