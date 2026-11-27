# SPDX-License-Identifier: Apache-2.0
"""Comprehensive stdlib unittest suite for attrrep_py (HIP-1352, zoo-apps/papers#11)."""

from __future__ import annotations

import copy
import json
import random
import subprocess
import unittest
from pathlib import Path

from attrrep_py import ed25519, verify_suite
from attrrep_py.canonical import canonical_json, sha256_hex
from attrrep_py.fingerprint import BPS_SCALE, compute_fingerprints, containment_bps

REF_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = REF_DIR.parents[1]
FIXTURE_PATH = REF_DIR / "fixtures" / "attribution-suite.v1.json"
RESULTS_PATH = REF_DIR / "results.json"
MANIFEST_PATH = REF_DIR / "corpus-manifest.json"
GO_DIR = REF_DIR / "go"


class TestRFC8032Ed25519(unittest.TestCase):
    """Official RFC 8032 Section 7.1 test vectors for pure-Python Ed25519."""

    def test_rfc8032_test_vectors(self) -> None:
        vectors = [
            # Test 1: empty message
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            # Test 2: 1-byte message 0x72
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            # Test 3: 2-byte message 0xaf82
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ]
        for seed_hex, expected_pub, msg_hex, expected_sig in vectors:
            seed = bytes.fromhex(seed_hex)
            msg = bytes.fromhex(msg_hex)
            pub = ed25519.public_key_from_seed(seed)
            self.assertEqual(pub.hex(), expected_pub)
            sig = ed25519.sign(seed, msg)
            self.assertEqual(sig.hex(), expected_sig)
            self.assertTrue(ed25519.verify(pub, msg, sig))
            # Flip 1 bit in signature -> must reject.
            bad_sig = bytearray(sig)
            bad_sig[0] ^= 0x01
            self.assertFalse(ed25519.verify(pub, msg, bytes(bad_sig)))
            # Flip 1 bit in message -> must reject.
            self.assertFalse(ed25519.verify(pub, msg + b"\x00", sig))


class TestNormalizationAndWinnowing(unittest.TestCase):
    def test_reformat_invariance(self) -> None:
        base = (
            "\\section{Model}\n"
            "Non-transferable ZOO-REP tokens are issued to contributors based on verified activities."
        )
        reformatted = (
            "% comment line\n\\vspace{2mm}\n\\section*{Model}\\label{sec:a}\n"
            "\\emph{Non-transferable}   \\textbf{ZOO-REP} tokens are issued to contributors "
            "based on verified activities.\\cite{zip0026}\n"
        )
        fp_a = compute_fingerprints(base)
        fp_b = compute_fingerprints(reformatted)
        self.assertNotEqual(fp_a.raw_sha256, fp_b.raw_sha256)
        self.assertEqual(fp_a.canonical_digest, fp_b.canonical_digest)
        self.assertEqual(fp_a.fingerprint_digest, fp_b.fingerprint_digest)
        self.assertEqual(containment_bps(fp_a.winnow_fingerprint, fp_b.winnow_fingerprint), BPS_SCALE)


class TestPublishedSuiteAndCrossParity(unittest.TestCase):
    def test_published_suite_verification(self) -> None:
        bundle = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))

        report = verify_suite(bundle)
        self.assertGreaterEqual(report["total_contributions"] + report["total_attestations"], 150)
        self.assertGreaterEqual(report["adversarial_total"], 25)
        self.assertEqual(report["adversarial_passed"], report["adversarial_total"])
        self.assertTrue(report["conservation_exact"])
        self.assertEqual(report["total_intrinsic_micro"], report["total_attributed_micro"])
        self.assertEqual(report["audit_merkle_root"], results["audit_merkle_root"])

        # Verify Sybil boss holds 0 ZooRep despite #1 naive rank.
        by_id = {s["identity_id"]: s for s in report["identity_summaries"]}
        self.assertEqual(by_id["mallory_sybil_boss"]["naive_reputation_rank"], 1)
        self.assertEqual(by_id["mallory_sybil_boss"]["zoo_rep_points"], 0)
        self.assertEqual(by_id["mallory_sybil_boss"]["tier"], "Observer")

    def test_order_permutation_invariance(self) -> None:
        bundle = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        base_root = verify_suite(bundle)["audit_merkle_root"]

        rng = random.Random(1352)
        for _ in range(2):
            perm = copy.deepcopy(bundle)
            rng.shuffle(perm["identities"])
            rng.shuffle(perm["contributions"])
            rng.shuffle(perm["attestations"])
            self.assertEqual(verify_suite(perm)["audit_merkle_root"], base_root)

    def test_go_python_bit_identical_parity(self) -> None:
        bundle = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        py_report = verify_suite(bundle)

        proc = subprocess.run(
            ["go", "run", "./cmd/attr-verify", "--suite", str(FIXTURE_PATH)],
            cwd=str(GO_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        go_report = json.loads(proc.stdout)

        # Bit-identical check on Merkle root and top-level counters.
        self.assertEqual(py_report["audit_merkle_root"], go_report["audit_merkle_root"])
        for key in (
            "schema_version",
            "spec_version",
            "suite_name",
            "total_contributions",
            "accepted_contributions",
            "rejected_contributions",
            "total_attestations",
            "accepted_attestations",
            "advisory_attestations",
            "rejected_attestations",
            "total_intrinsic_micro",
            "total_attributed_micro",
            "total_naive_attributed_micro",
            "conservation_exact",
            "adversarial_passed",
            "adversarial_total",
        ):
            self.assertEqual(py_report[key], go_report[key], f"mismatch on {key}")

        # Exact field-by-field parity across all contribution verdicts, attestations, collusion findings, and identities.
        self.assertEqual(len(py_report["contribution_verdicts"]), len(go_report["contribution_verdicts"]))
        for pv, gv in zip(py_report["contribution_verdicts"], go_report["contribution_verdicts"]):
            for k in (
                "contribution_id",
                "author_id",
                "status",
                "error_code",
                "canonical_origin_id",
                "best_overlap_bps",
                "novelty_bps",
                "intrinsic_micro",
                "self_credit_micro",
                "upstream_flow_micro",
            ):
                self.assertEqual(pv[k], gv[k], f"contrib {pv['contribution_id']} mismatch on {k}")

        self.assertEqual(len(py_report["attestation_verdicts"]), len(go_report["attestation_verdicts"]))
        for pv, gv in zip(py_report["attestation_verdicts"], go_report["attestation_verdicts"]):
            for k in ("uid", "attester", "recipient", "ref_uid", "status", "error_code", "effective_weight_bps"):
                self.assertEqual(pv[k], gv[k], f"attestation {pv['uid']} mismatch on {k}")

        self.assertEqual(py_report["collusion_findings"], go_report["collusion_findings"])
        self.assertEqual(py_report["identity_summaries"], go_report["identity_summaries"])
        self.assertEqual(py_report["adversarial_results"], go_report["adversarial_results"])

    def test_corpus_manifest_pins_real_papers(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["paper_count"], 12)
        for entry in manifest["papers"]:
            rel = entry["rel_path"]
            self.assertFalse(Path(rel).is_absolute())
            raw = (REPO_ROOT / rel).read_text(encoding="utf-8")
            fp = compute_fingerprints(raw)
            self.assertEqual(fp.raw_sha256, entry["sha256"])
            self.assertEqual(fp.canonical_digest, entry["canonical_digest"])
            self.assertEqual(fp.fingerprint_digest, entry["fingerprint_digest"])
            self.assertEqual(fp.token_count, entry["normalized_tokens"])
        recomputed_hash = sha256_hex(canonical_json(manifest["papers"]))
        self.assertEqual(recomputed_hash, manifest["manifest_sha256"])


if __name__ == "__main__":
    unittest.main()
