# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Unit, RFC 8032 Ed25519, boundary audit, and live Go<->Python parity tests."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from feda2a_py.canonical import canonical_json, merkle_root_rfc6962
from feda2a_py.ed25519 import verify_ed25519
from feda2a_py.verifier import verify_suite

REF_DIR = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REF_DIR / "fixtures" / "a2a-exchange-suite.v1.json"
GO_DIR = REF_DIR / "go"


class TestFedA2APythonVerifier(unittest.TestCase):
    def test_rfc8032_ed25519_vectors(self) -> None:
        # RFC 8032 Section 7.1 TEST 1 (empty message)
        pk1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig1 = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertTrue(verify_ed25519(pk1, b"", sig1))
        self.assertFalse(verify_ed25519(pk1, b"x", sig1))

        # RFC 8032 Section 7.1 TEST 2 (1-byte message 0x72)
        pk2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig2 = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertTrue(verify_ed25519(pk2, b"\x72", sig2))
        bad_sig2 = bytearray(sig2)
        bad_sig2[0] ^= 0x01
        self.assertFalse(verify_ed25519(pk2, b"\x72", bytes(bad_sig2)))

    def test_canonical_json_and_rfc6962_merkle(self) -> None:
        self.assertEqual(canonical_json({"b": 2, "a": 1, "c": "<&>"}), b'{"a":1,"b":2,"c":"<&>"}')
        self.assertEqual(
            merkle_root_rfc6962([]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_full_live_fixture_verification(self) -> None:
        suite = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        report = verify_suite(suite)
        self.assertTrue(report["all_stages_valid"])
        self.assertTrue(report["all_adversarial_pass"])
        self.assertEqual(report["attacks_detected"], 18)
        self.assertEqual(report["attacks_total"], 18)
        self.assertEqual(report["positive_cases_pass"], 1)
        self.assertEqual(report["wire_audit"]["credential_leak_bytes"], 0)
        self.assertEqual(report["wire_audit"]["private_memory_leak_bytes"], 0)
        self.assertEqual(report["wire_audit"]["raw_trace_leak_bytes"], 0)
        self.assertTrue(report["wire_audit"]["zero_boundary_leakage"])
        self.assertTrue(report["wire_audit"]["all_frame_hashes_valid"])
        self.assertEqual(report["wire_audit"]["total_frames"], 8)

    def test_bit_exact_go_python_cli_parity(self) -> None:
        go_proc = subprocess.run(
            ["go", "run", "./cmd/a2a-verify", "--fixture", str(FIXTURE_PATH), "--compact"],
            cwd=str(GO_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        py_proc = subprocess.run(
            [sys.executable, "-m", "feda2a_py.cli", "--fixture", str(FIXTURE_PATH), "--compact"],
            cwd=str(REF_DIR / "python"),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(go_proc.stdout, py_proc.stdout)


if __name__ == "__main__":
    unittest.main()
