# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Unit, RFC 8032 Ed25519, adversarial, and Go<->Python bit-exact parity tests."""

import json
import subprocess
import unittest
from pathlib import Path

from forkorg_py.canonical import canonical_json_bytes, div_trunc, merkle_root_rfc6962, sha256_hex
from forkorg_py.ed25519 import verify_ed25519
from forkorg_py.model import apply_bitdelta, compress_bitdelta
from forkorg_py.verifier import verify_adversarial_case, verify_suite

REF_DIR = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REF_DIR / "fixtures" / "fork-exchange-suite.v1.json"
RESULTS_PATH = REF_DIR / "results.json"
GO_DIR = REF_DIR / "go"


class TestPurePythonEd25519RFC8032(unittest.TestCase):
    """Validate pure-Python Ed25519 verifier against official RFC 8032 Section 7.1 vectors."""

    def test_rfc8032_test_vector_1_empty_message(self) -> None:
        pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        msg = b""
        sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(verify_ed25519(pk, msg, sig))
        # Flip one bit in signature -> must reject.
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0x01
        self.assertFalse(verify_ed25519(pk, msg, bytes(bad_sig)))

    def test_rfc8032_test_vector_2_one_byte(self) -> None:
        pk = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        msg = bytes.fromhex("72")
        sig = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertTrue(verify_ed25519(pk, msg, sig))
        self.assertFalse(verify_ed25519(pk, b"\x73", sig))

    def test_rfc8032_test_vector_3_two_bytes(self) -> None:
        pk = bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
        msg = bytes.fromhex("af82")
        sig = bytes.fromhex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        )
        self.assertTrue(verify_ed25519(pk, msg, sig))


class TestCanonicalAndBitDeltaPrimitives(unittest.TestCase):
    def test_div_trunc_matches_go(self) -> None:
        self.assertEqual(div_trunc(7, 2), 3)
        self.assertEqual(div_trunc(-7, 2), -3)
        self.assertEqual(div_trunc(7, -2), -3)
        self.assertEqual(div_trunc(-7, -2), 3)

    def test_canonical_json_no_html_escape(self) -> None:
        raw = canonical_json_bytes({"b": 2, "a": "x<y>&z", "c": [1, 2, 3]})
        self.assertEqual(raw, b'{"a":"x<y>&z","b":2,"c":[1,2,3]}')

    def test_merkle_empty_and_order_sensitive(self) -> None:
        self.assertEqual(merkle_root_rfc6962([]), sha256_hex(b""))
        r1 = merkle_root_rfc6962(["a", "b", "c"])
        r2 = merkle_root_rfc6962(["a", "c", "b"])
        self.assertNotEqual(r1, r2)

    def test_bitdelta_roundtrip(self) -> None:
        base = [i * 1000 for i in range(64)]
        fine = [base[i] + (50_000 if i % 2 == 0 else -30_000) for i in range(64)]
        sign_hex, scale = compress_bitdelta(base, fine)
        self.assertEqual(scale, 40_000)
        recon = apply_bitdelta(base, {"dim": 64, "sign_bits_hex": sign_hex, "scale_micro": scale})
        for i in range(64):
            expected = base[i] + (40_000 if i % 2 == 0 else -40_000)
            self.assertEqual(recon[i], expected)


class TestSuiteVerificationAndGoParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        cls.results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        cls.py_report = verify_suite(cls.suite)

    def test_workflow_and_adversarial_all_pass(self) -> None:
        self.assertTrue(self.py_report["all_workflow_passed"])
        self.assertTrue(self.py_report["all_adversarial_matched"])
        self.assertEqual(self.py_report["adversarial_total"], 19)
        self.assertEqual(self.py_report["adversarial_caught"], 19)
        self.assertEqual(
            self.py_report["audit_merkle_root"],
            self.results["verification"]["audit_merkle_root"],
        )

    def test_all_20_adversarial_and_constitutional_cases(self) -> None:
        ds = self.suite["eval_dataset"]
        for c in self.suite["adversarial_cases"]:
            with self.subTest(case_id=c["case_id"], expected=c["expected_code"]):
                out = verify_adversarial_case(c, ds)
                self.assertTrue(
                    out["matched"],
                    f"{c['case_id']} mismatch: expected ({out['expected_valid']}, {out['expected_code']}), "
                    f"got ({out['actual_valid']}, {out['actual_code']})",
                )

    def test_go_python_cli_bit_exact_parity(self) -> None:
        go_proc = subprocess.run(
            ["go", "run", "./cmd/fork-verify", "--fixture", str(FIXTURE_PATH), "--compact"],
            cwd=str(GO_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        go_bytes = go_proc.stdout.strip().encode("utf-8")
        py_bytes = canonical_json_bytes(self.py_report)
        self.assertEqual(
            py_bytes,
            go_bytes,
            "Go and Python canonical verification reports MUST be 100% byte-identical!",
        )


if __name__ == "__main__":
    unittest.main()
