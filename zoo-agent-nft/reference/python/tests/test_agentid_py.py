# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Unit, RFC 8032 vector, W3C bitstring, threat-model, and Go<->Python parity tests."""

import json
import subprocess
import unittest
from pathlib import Path

from agentid_py.bitstring import ENCODING_GZIP_BASE64URL, bitstring_is_revoked, decode_bitstring
from agentid_py.canonical import canonical_json, public_key_from_did_key
from agentid_py.ed25519 import verify_ed25519
from agentid_py.verifier import verify_suite

REF_DIR = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REF_DIR / "fixtures" / "identity-delegation-suite.v1.json"
GO_DIR = REF_DIR / "go"


class TestAgentIDPy(unittest.TestCase):
    def test_rfc8032_ed25519_vectors(self) -> None:
        # RFC 8032 Section 7.1 Test Vector 1 (empty message)
        pub1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig1 = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(verify_ed25519(pub1, b"", sig1))
        self.assertFalse(verify_ed25519(pub1, b"x", sig1))

        # RFC 8032 Section 7.1 Test Vector 2 (1-byte message 0x72)
        pub2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig2 = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertTrue(verify_ed25519(pub2, b"\x72", sig2))
        bad_sig = bytearray(sig2)
        bad_sig[0] ^= 0x01
        self.assertFalse(verify_ed25519(pub2, b"\x72", bytes(bad_sig)))

    def test_did_key_multicodec_decoding(self) -> None:
        suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        docs = suite["stages"][2]["context"]["did_documents"]
        did_key_docs = [d for d in docs if d["id"].startswith("did:key:z")]
        self.assertEqual(len(did_key_docs), 1)
        pub = public_key_from_did_key(did_key_docs[0]["id"])
        self.assertEqual(len(pub), 32)
        with self.assertRaises(ValueError):
            public_key_from_did_key("did:key:invalid")

    def test_w3c_bitstring_status_list_131k(self) -> None:
        suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        sl = suite["stages"][0]["context"]["status_lists"][0]["credential_subject"]
        self.assertEqual(sl["bit_length"], 131072)
        self.assertEqual(sl["encoding"], ENCODING_GZIP_BASE64URL)
        raw = decode_bitstring(sl["encoded_list"], sl["encoding"], sl["bit_length"])
        self.assertEqual(len(raw), 16384)
        self.assertTrue(bitstring_is_revoked(raw, 131072, 7))
        self.assertTrue(bitstring_is_revoked(raw, 131072, 4096))
        self.assertTrue(bitstring_is_revoked(raw, 131072, 99999))
        self.assertFalse(bitstring_is_revoked(raw, 131072, 100))
        self.assertFalse(bitstring_is_revoked(raw, 131072, 103))

    def test_verify_full_suite_all_stages_and_25_threat_cases(self) -> None:
        suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        report = verify_suite(suite)
        self.assertTrue(report["all_stages_valid"], f"stage failure: {report['stage_reports']}")
        self.assertEqual(report["total_stages"], 5)
        self.assertEqual(report["passed_stages"], 5)
        self.assertTrue(report["all_threat_pass"], f"threat failure: {report['threat_reports']}")
        self.assertEqual(report["attacks_total"], 24)
        self.assertEqual(report["attacks_caught"], 24)
        self.assertEqual(report["positive_controls"], 1)
        self.assertEqual(report["positive_controls_ok"], 1)
        self.assertEqual(len(report["audit_merkle_root"]), 64)

    def test_go_python_byte_exact_cli_parity(self) -> None:
        suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        py_out = canonical_json(verify_suite(suite)).decode("utf-8")

        proc = subprocess.run(
            ["go", "run", "./cmd/id-verify", "--fixture", str(FIXTURE_PATH), "--compact"],
            cwd=str(GO_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        go_out = proc.stdout.strip()
        self.assertEqual(py_out, go_out, "Go and Python compact JSON reports must match byte-for-byte")


if __name__ == "__main__":
    unittest.main()
