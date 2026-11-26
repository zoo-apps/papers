# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Comprehensive zero-dependency test suite for tc_receipt (Python stdlib)."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PY_DIR = TESTS_DIR.parent
REF_DIR = PY_DIR.parent
REPO_ROOT = REF_DIR.parent.parent
FIXTURES_DIR = REF_DIR / "fixtures"

if str(PY_DIR) not in sys.path:
    sys.path.insert(0, str(PY_DIR))

from tc_receipt.canonical import CanonicalError, canonical_json, parse_strict_json
from tc_receipt.ed25519 import (
    L as ED25519_L,
    ed25519_public_key_from_seed,
    ed25519_sign,
    ed25519_verify,
)
from tc_receipt.merkle import build_inclusion_proof, merkle_root, verify_inclusion_proof
from tc_receipt.verify import (
    VerificationError,
    load_policy,
    verify_batch,
    verify_receipt_bytes,
)


class TestRFC8032Ed25519(unittest.TestCase):
    """Validate pure-Python Ed25519 against official RFC 8032 Section 7.1 vectors."""

    def test_rfc8032_test1_empty_message(self) -> None:
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        expected_pub = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        expected_sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        pub = ed25519_public_key_from_seed(seed)
        self.assertEqual(pub, expected_pub)
        sig = ed25519_sign(seed, b"")
        self.assertEqual(sig, expected_sig)
        self.assertTrue(ed25519_verify(pub, b"", sig))
        self.assertFalse(ed25519_verify(pub, b"x", sig))

    def test_rfc8032_test2_single_byte(self) -> None:
        seed = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        expected_pub = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        msg = bytes.fromhex("72")
        expected_sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertEqual(ed25519_public_key_from_seed(seed), expected_pub)
        sig = ed25519_sign(seed, msg)
        self.assertEqual(sig, expected_sig)
        self.assertTrue(ed25519_verify(expected_pub, msg, sig))

    def test_rfc8032_test3_two_bytes(self) -> None:
        seed = bytes.fromhex(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
        )
        expected_pub = bytes.fromhex(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        )
        msg = bytes.fromhex("af82")
        expected_sig = bytes.fromhex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        )
        self.assertEqual(ed25519_public_key_from_seed(seed), expected_pub)
        sig = ed25519_sign(seed, msg)
        self.assertEqual(sig, expected_sig)
        self.assertTrue(ed25519_verify(expected_pub, msg, sig))

    def test_non_canonical_s_rejected(self) -> None:
        seed = hashlib.sha256(b"non-canonical-s-test").digest()
        pub = ed25519_public_key_from_seed(seed)
        sig = ed25519_sign(seed, b"hello")
        s_val = int.from_bytes(sig[32:], "little")
        # Construct malleable signature with S' = S + L >= L (still fits in 32 bytes if < 2^256).
        s_malleated = (s_val + ED25519_L).to_bytes(32, "little")
        bad_sig = sig[:32] + s_malleated
        self.assertFalse(ed25519_verify(pub, b"hello", bad_sig))


class TestCanonicalJSON(unittest.TestCase):
    def test_key_order_and_html_unescaped_and_unicode(self) -> None:
        obj = {"z": 1, "a": "<script>&\"\\'\n\x00\x1f", "m": "éΩ"}
        encoded = canonical_json(obj).decode("utf-8")
        self.assertEqual(
            encoded,
            '{"a":"<script>&\\"\\\\\'\\n\\u0000\\u001f","m":"éΩ","z":1}',
        )

    def test_reject_float_and_exponent(self) -> None:
        for payload in (b'{"x":1.0}', b'{"x":1e5}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(CanonicalError) as ctx:
                parse_strict_json(payload)
            self.assertEqual(ctx.exception.code, "ERR_FLOAT_FORBIDDEN")

    def test_reject_duplicate_keys(self) -> None:
        with self.assertRaises(CanonicalError) as ctx:
            parse_strict_json(b'{"a":1,"a":2}')
        self.assertEqual(ctx.exception.code, "ERR_DUPLICATE_KEY")

    def test_reject_utf8_bom(self) -> None:
        with self.assertRaises(CanonicalError) as ctx:
            parse_strict_json(b"\xef\xbb\xbf{\"a\":1}")
        self.assertEqual(ctx.exception.code, "ERR_INVALID_JSON")


class TestMerkleTree(unittest.TestCase):
    def test_inclusion_proofs_all_sizes_1_to_17(self) -> None:
        for size in range(1, 18):
            leaves = [f"leaf-{i}".encode("ascii") for i in range(size)]
            root = merkle_root("evidence", leaves)
            for idx, leaf in enumerate(leaves):
                proof = build_inclusion_proof("evidence", leaves, idx)
                self.assertTrue(verify_inclusion_proof(proof, leaf, root))
                # Tampered leaf must fail verification.
                self.assertFalse(verify_inclusion_proof(proof, leaf + b"!", root))
            # Domain separation must produce a distinct root.
            self.assertNotEqual(root, merkle_root("inputs", leaves))

    def test_empty_tree_domain_separation(self) -> None:
        self.assertNotEqual(merkle_root("tools", []), merkle_root("inputs", []))


class TestFixtureAndAdversarialSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_policy(FIXTURES_DIR / "policy.json")
        cls.jobs_fixture = parse_strict_json((FIXTURES_DIR / "jobs_100.json").read_bytes())
        cls.expected_hashes = parse_strict_json(
            (FIXTURES_DIR / "expected_hashes_100.json").read_bytes()
        )
        cls.adv_suite = json.loads(
            (FIXTURES_DIR / "adversarial_suite.json").read_text(encoding="utf-8")
        )

    def test_100_job_fixture_and_pinned_hashes(self) -> None:
        jobs = self.jobs_fixture["jobs"]
        self.assertEqual(len(jobs), 100)
        results = verify_batch(jobs, self.policy)
        self.assertEqual(len(results), 100)
        for res, exp in zip(results, self.expected_hashes["entries"]):
            self.assertEqual(res.job_id, exp["job_id"])
            self.assertEqual(res.canonical_receipt_hash, exp["canonical_receipt_hash"])
            self.assertEqual(res.provenance_root, exp["provenance_root"])

    def test_grounded_repo_input_hashes_match_actual_files(self) -> None:
        # Verify that every repo:// input across all 100 jobs matches the real file on disk.
        checked_paths: set[str] = set()
        for job in self.jobs_fixture["jobs"]:
            for inp in job["inputs"]:
                uri = inp["uri"]
                self.assertTrue(uri.startswith("repo://"))
                rel = uri[len("repo://") :]
                if rel in checked_paths:
                    continue
                disk_path = REPO_ROOT / rel
                self.assertTrue(disk_path.is_file(), f"missing grounded file {disk_path}")
                raw = disk_path.read_bytes()
                self.assertEqual(inp["byte_length"], len(raw))
                self.assertEqual(inp["sha256"], hashlib.sha256(raw).hexdigest())
                checked_paths.add(rel)
        self.assertGreaterEqual(len(checked_paths), 25)

    def test_all_adversarial_cases_rejected(self) -> None:
        cases = self.adv_suite["cases"]
        self.assertGreaterEqual(len(cases), 30)
        for case in cases:
            with self.subTest(case_id=case["case_id"]):
                kind = case.get("kind", "single")
                expected = case["expected_error_code"]
                with self.assertRaises(VerificationError) as ctx:
                    if kind == "raw_json":
                        verify_receipt_bytes(case["raw_json"].encode("utf-8"), self.policy)
                    elif kind == "batch":
                        verify_batch(case["receipts"], self.policy)
                    else:
                        verify_receipt_bytes(
                            json.dumps(case["receipt"]).encode("utf-8"), self.policy
                        )
                self.assertEqual(ctx.exception.code, expected)


if __name__ == "__main__":
    unittest.main()
