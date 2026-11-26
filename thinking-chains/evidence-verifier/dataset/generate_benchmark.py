#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Deterministic generator for benchmark-claims.v1.json (120 claims, seed 1352)."""

from __future__ import annotations

import hashlib
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "../../.."))
MANIFEST_PATH = os.path.join(SCRIPT_DIR, "corpus-manifest.json")
OUT_PATH = os.path.join(SCRIPT_DIR, "benchmark-claims.v1.json")

sys.path.insert(0, os.path.abspath(os.path.join(SCRIPT_DIR, "../python")))
from evidence_verifier.types import canonical_json, sha256_hex  # noqa: E402


def load_pinned_hashes() -> dict[str, str]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    hashes: dict[str, str] = {}
    for doc in manifest["documents"]:
        path = doc["path"]
        with open(os.path.join(REPO_ROOT, path), "rb") as df:
            actual = hashlib.sha256(df.read()).hexdigest()
        if actual != doc["sha256"]:
            raise RuntimeError(f"SHA mismatch for {path}: manifest={doc['sha256']} actual={actual}")
        hashes[path] = actual
    return hashes


def merkle_for_leaves(leaves: list[str]) -> str:
    level = [sha256_hex(x.encode("utf-8")) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            l = level[i]
            r = level[i + 1] if i + 1 < len(level) else l
            nxt.append(sha256_hex(f"{l}:{r}".encode("utf-8")))
        level = nxt
    return level[0]


def claim_base(
    cid: str,
    cclass: str,
    statement: str,
    expected: str,
    *,
    author: str = "agent-research-01",
    verifier: str = "verifier-node-alpha",
    gov_action: str = "none",
    regime: str = "none",
    notes: str = "",
) -> dict:
    c = {
        "schema_version": "1.0.0",
        "claim_id": cid,
        "claim_class": cclass,
        "statement": statement,
        "author_id": author,
        "verifier_id": verifier,
        "governance_action": gov_action,
        "expected_verdict": expected,
        "negative_regime": regime,
    }
    if notes:
        c["notes"] = notes
    return c


def build_claims(h: dict[str, str]) -> list[dict]:
    claims: list[dict] = []

    p_tc = "thinking-chains/thinking-chains.tex"
    p_const = "thinking-chains/sections/15-constitutional-rules.tex"
    p_fail = "thinking-chains/sections/19-failure-modes.tex"
    p_bd = "zoo-bitdelta-deltasoup/zoo-bitdelta-deltasoup.tex"
    p_rdao = "zoo-dao-research-governance/zoo-dao-research-governance.tex"
    p_quasar = "zoo-quasar-benchmarks/zoo-quasar-benchmarks.tex"
    p_evm = "zoo-evm-benchmarks/zoo-evm-benchmarks.tex"
    p_exp = "experience-ledger-dso/experience-ledger-dso.tex"

    # =========================================================================
    # CLASS 1: citation_check (CIT-001 .. CIT-030)
    # =========================================================================
    def add_cit(cid, stmt, exp, cit_payload, **kw):
        c = claim_base(cid, "citation_check", stmt, exp, **kw)
        c["citation"] = cit_payload
        claims.append(c)

    # 10 Genuine Verifiable Citations
    add_cit(
        "CIT-001",
        "Thinking Chains settles only finite authenticated artifacts of live cognition.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "abstract",
            "quoted_span": "it may only settle finite, authenticated artifacts of that thought",
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-002",
        "Thinking Chains caps native AI subsidy supply at 10^9 coins with no premine.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Tokenomics",
            "quoted_span": "so there is no premine and no coin without a thought behind it",
            "claimed_numbers": [1000000000],
            "claimed_polarity": "negative",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-003",
        "Quasar post-quantum finality authenticates history with ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and ML-KEM (FIPS 203).",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Two Ways to Run It",
            "quoted_span": "authenticated by NIST post-quantum signatures (ML-DSA, FIPS 204; SLH-DSA, FIPS 205) with ML-KEM (FIPS 203) key exchange",
            "claimed_numbers": [204, 205, 203],
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-004",
        "Under Lemma Dissent-safety, no well-formed good-faith judgment is ever slashed.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Dissent-safety",
            "quoted_span": "no well-formed good-faith judgment is ever slashed",
            "claimed_polarity": "negative",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-005",
        "Constitutional Rule 10 requires cognitive integrity to be inspectable without an LLM.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_const,
            "expected_sha256": h[p_const],
            "section_hint": "The Twelve Rules",
            "quoted_span": "Inspectable without an LLM. The integrity of the network's cognition must be checkable using only hashing and signature verification, with no model execution required.",
            "claimed_polarity": "negative",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-006",
        "BitDelta achieves 10x memory reduction preserving >= 90% performance, ~60% lower jailbreak ASR, and DeltaSoup tolerates 30% Byzantine contributions.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_bd,
            "expected_sha256": h[p_bd],
            "section_hint": "abstract",
            "quoted_span": "DeltaSoup aggregates user deltas via coordinate-wise trimmed mean, tolerating up to 30% Byzantine (poisoned) contributions.",
            "claimed_numbers": [10, 90, 60, 30],
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-007",
        "Zoo Research DAO reviewed 287 proposals in 18 months with 8.4-day median turnaround vs 97 days, 94% completion, and 4.3/5.0 satisfaction.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_rdao,
            "expected_sha256": h[p_rdao],
            "section_hint": "abstract",
            "quoted_span": "Across 287 proposals reviewed in 18 months, the system achieves 8.4-day median review turnaround",
            "claimed_numbers": [287, 18, 8.4, 97, 94, 4.3],
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-008",
        "Zoo testnet with 21 validators and 500 GPU workers achieves 10.9ms combined finality, 4.76M TPS, and 98.2% useful AI work.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_quasar,
            "expected_sha256": h[p_quasar],
            "section_hint": "abstract",
            "quoted_span": "demonstrating 10.9ms combined finality (10ms Quasar + 0.9ms PoAI overhead), 4.76M TPS sustained throughput, and 98.2% of validator compute devoted to useful AI work.",
            "claimed_numbers": [21, 500, 10.9, 10, 0.9, 4760000, 98.2],
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-009",
        "Zoo EVM uses a 1B gas block limit processing up to 47,619 simple transactions per block, reaching 4.76M TPS bounded by 10ms Quasar finality.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_evm,
            "expected_sha256": h[p_evm],
            "section_hint": "abstract",
            "quoted_span": "processing up to 47,619 simple transactions per block",
            "claimed_numbers": [47619, 47.6, 4.76, 10],
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-010",
        "Experience Ledger semantic optimization achieves comparable or superior performance at 0.2% of fine-tuning cost.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_exp,
            "expected_sha256": h[p_exp],
            "section_hint": "abstract",
            "quoted_span": "semantic optimization achieves comparable or superior performance to parameter fine-tuning at 0.2% of the cost",
            "claimed_numbers": [0.2],
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )

    # 7 Mechanical Refutations
    add_cit(
        "CIT-011",
        "Tampered SHA-256 commitment for thinking-chains.tex.",
        "REFUTED_CONTRADICTION",
        {
            "source_path": p_tc,
            "expected_sha256": "0" * 64,
            "section_hint": "abstract",
            "quoted_span": "finite, authenticated artifacts",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-012",
        "Citation referencing non-existent section Quantum Gravity Routing.",
        "REFUTED_CONTRADICTION",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Quantum Gravity Routing",
            "quoted_span": "finite, authenticated artifacts",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-013",
        "Altered supply cap claim (2 billion instead of 1 billion) against genuine Tokenomics span.",
        "REFUTED_CONTRADICTION",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Tokenomics",
            "quoted_span": "the subsidy supply approaches",
            "claimed_numbers": [2000000000],
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-014",
        "Altered latency figure (1.9ms instead of 10.9ms) inside otherwise verbatim Quasar quote.",
        "REFUTED_CONTRADICTION",
        {
            "source_path": p_quasar,
            "expected_sha256": h[p_quasar],
            "section_hint": "abstract",
            "quoted_span": "We benchmark the combined system on Zoo testnet with 21 validators and 500 GPU workers, demonstrating 1.9ms combined finality",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-015",
        "Inflated Byzantine fault tolerance (49% instead of 30%) inside BitDelta/DeltaSoup quote.",
        "REFUTED_CONTRADICTION",
        {
            "source_path": p_bd,
            "expected_sha256": h[p_bd],
            "section_hint": "abstract",
            "quoted_span": "DeltaSoup aggregates user deltas via coordinate-wise trimmed mean, tolerating up to 49% Byzantine (poisoned) contributions.",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-016",
        "Out-of-context polarity reversal claiming well-formed good-faith judgments are slashed.",
        "REFUTED_CONTRADICTION",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Dissent-safety",
            "quoted_span": "good-faith judgment is ever slashed",
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-017",
        "Self-validated citation where author_id equals verifier_id (constitutional violation).",
        "REFUTED_CONTRADICTION",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "abstract",
            "quoted_span": "finite, authenticated artifacts",
            "require_exact_span": True,
        },
        author="agent-self-approver",
        verifier="agent-self-approver",
    )

    # 4 Mechanical Unsupported Citations
    add_cit(
        "CIT-018",
        "Citation pointing to non-existent file zoo-phantom-consensus/paper.tex.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "source_path": "zoo-phantom-consensus/paper.tex",
            "expected_sha256": "a" * 64,
            "quoted_span": "phantom finality achieves 0.1ms",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-019",
        "Completely fabricated quote attributed to zoo-dao-research-governance.tex.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "source_path": p_rdao,
            "expected_sha256": h[p_rdao],
            "section_hint": "abstract",
            "quoted_span": "all manuscript referees receive automatic treasury minting rights without stake or review",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-020",
        "Citation omitting required expected_sha256 commitment.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "source_path": p_tc,
            "expected_sha256": "",
            "quoted_span": "finite, authenticated artifacts",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-021",
        "Citation attempting directory traversal outside pinned corpus root.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "source_path": "../../etc/passwd",
            "expected_sha256": "b" * 64,
            "quoted_span": "root:x:0:0",
            "require_exact_span": True,
        },
    )

    # 2 Explicit Human-Review Citations
    add_cit(
        "CIT-022",
        "External-domain comparison of Zoo Research DAO turnaround against proprietary Nature 2026 internal logs.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "source_path": p_rdao,
            "expected_sha256": h[p_rdao],
            "section_hint": "abstract",
            "quoted_span": "8.4-day median review turnaround",
            "review_scope": "external_domain",
            "require_exact_span": True,
        },
    )
    add_cit(
        "CIT-023",
        "Subjective value judgment on whether Thinking Chains is the most valuable protocol ever built.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Why This May Be the Most Valuable Protocol Ever Built",
            "quoted_span": "most-demanded work of the age",
            "review_scope": "subjective_judgment",
            "require_exact_span": True,
        },
    )

    # 5 Honest Negative Regime 1: Semantically Valid Heavy Paraphrases (GT = VERIFIED_REPRODUCIBLE)
    add_cit(
        "CIT-024",
        "Heavy paraphrase: Quasar finalizes blocks in 0.01 seconds using linear message complexity.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_quasar,
            "expected_sha256": h[p_quasar],
            "section_hint": "abstract",
            "quoted_span": "consensus reaches deterministic block finalization in 0.01 seconds with linear communication scaling",
            "require_exact_span": True,
        },
        regime="semantic_paraphrase",
        notes="Semantically faithful paraphrase of 'deterministic finality in 10ms with O(n) message complexity'; fails strict lexical span check.",
    )
    add_cit(
        "CIT-025",
        "Heavy paraphrase: Thinking Chains penalizes provable protocol dishonesty rather than dissenting opinions.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Slash Liars, Not Dissenters",
            "quoted_span": "stake confiscation targets objective cryptographic cheating rather than minority viewpoints",
            "require_exact_span": True,
        },
        regime="semantic_paraphrase",
        notes="Semantically faithful paraphrase of 'separates objective protocol faults from subjective judgment'; fails lexical span match.",
    )
    add_cit(
        "CIT-026",
        "Heavy paraphrase: BitDelta shrinks 70B personalized weights from 140GB down to roughly 700MB per user.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_bd,
            "expected_sha256": h[p_bd],
            "section_hint": "Introduction",
            "quoted_span": "storing individual adaptations for seventy-billion parameter networks drops to roughly 700 megabytes",
            "require_exact_span": True,
        },
        regime="semantic_paraphrase",
        notes="Unit conversion (0.7GB -> 700MB) + heavy lexical rephrasing.",
    )
    add_cit(
        "CIT-027",
        "Heavy paraphrase: Context-injected semantic wisdom costs five hundred times less than weight fine-tuning.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_exp,
            "expected_sha256": h[p_exp],
            "section_hint": "abstract",
            "quoted_span": "curated natural-language insights match fine-tuning quality at five-hundred-fold lower expense",
            "require_exact_span": True,
        },
        regime="semantic_paraphrase",
        notes="Equivalent reciprocal framing (0.2% cost = 500x cheaper).",
    )
    add_cit(
        "CIT-028",
        "Moderate paraphrase with require_exact_span=false: Research DAO median review turnaround is 8.4 days vs 97 days across 287 proposals.",
        "VERIFIED_REPRODUCIBLE",
        {
            "source_path": p_rdao,
            "expected_sha256": h[p_rdao],
            "section_hint": "abstract",
            "quoted_span": "across 287 reviewed proposals the system achieves 8.4-day median review turnaround versus 97 days traditional",
            "require_exact_span": False,
        },
        regime="semantic_paraphrase",
        notes="Moderate lexical overlap paraphrase escalated to INCONCLUSIVE_NEEDS_HUMAN_REVIEW instead of automatic verification.",
    )

    # 2 Honest Negative Regime 3: Sophisticated Cherry-Picking (GT = INCONCLUSIVE_NEEDS_HUMAN_REVIEW)
    add_cit(
        "CIT-029",
        "Cherry-picking: Quotes Quorum capture Hoeffding bound verbatim while claiming stake-weighted committees inherit it (omits load-bearing Weighting caveat).",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "source_path": p_tc,
            "expected_sha256": h[p_tc],
            "section_hint": "Quorum capture bound",
            "quoted_span": "a false certification occurs with probability at most",
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
        regime="cherry_picking_omitted_caveat",
        notes="Literally true verbatim quote, but omits the load-bearing caveat on line 294 stating the bound fails under stake-weighted committees.",
    )
    add_cit(
        "CIT-030",
        "Cherry-picking: Quotes raw GPU EVM execution 47.6M TPS as headline network throughput while omitting 10ms Quasar finality cap of 4.76M TPS.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "source_path": p_evm,
            "expected_sha256": h[p_evm],
            "section_hint": "abstract",
            "quoted_span": "the EVM reaches 47.6 million transactions per second (TPS) in raw execution throughput",
            "claimed_numbers": [47.6],
            "claimed_polarity": "positive",
            "require_exact_span": True,
        },
        regime="cherry_picking_omitted_caveat",
        notes="Literally true verbatim quote & number, but omits the immediately following 10x lower finalized bound (4.76M TPS).",
    )

    # =========================================================================
    # CLASS 2: calc_check (CALC-001 .. CALC-030)
    # =========================================================================
    def add_calc(cid, stmt, exp, calc_payload, **kw):
        c = claim_base(cid, "calc_check", stmt, exp, **kw)
        c["calculation"] = calc_payload
        claims.append(c)

    # 12 Genuine Verifiable Calculations
    add_calc(
        "CALC-001",
        "1 billion gas block limit fits floor(1e9 / 21000) = 47,619 simple EVM transactions per block.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "floor(1000000000 / 21000)",
            "claimed_value": 47619,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "tx/block",
            "claimed_unit": "tx/block",
        },
    )
    add_calc(
        "CALC-002",
        "47,619 simple transactions per 10ms block equals 4,761,900 TPS.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "47619 / 0.01",
            "claimed_value": 4761900,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "tps",
            "claimed_unit": "tps",
            "exact_rational": True,
        },
    )
    add_calc(
        "CALC-003",
        "Combined Quasar + PoAI finality equals 10.0ms + 0.9ms = 10.9ms.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "quasar_ms + poai_ms",
            "variables": {"quasar_ms": 10.0, "poai_ms": 0.9},
            "claimed_value": 10.9,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "ms",
            "claimed_unit": "ms",
            "exact_rational": True,
        },
    )
    add_calc(
        "CALC-004",
        "BitDelta reduces 70B per-user storage from 140GB to 0.7GB, a 200x ratio.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "ratio(140, 0.7)",
            "claimed_value": 200,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "x",
            "claimed_unit": "x",
            "exact_rational": True,
        },
    )
    add_calc(
        "CALC-005",
        "LoRA r=16 reduces 70B per-user storage from 140GB to 4.0GB, a 35x ratio.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "ratio(140, 4.0)",
            "claimed_value": 35,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "x",
            "claimed_unit": "x",
            "exact_rational": True,
        },
    )
    add_calc(
        "CALC-006",
        "Research DAO five-dimensional review weights sum to exactly 100%.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "sum(25, 25, 20, 15, 15)",
            "claimed_value": 100,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "%",
            "claimed_unit": "%",
            "exact_rational": True,
        },
    )
    add_calc(
        "CALC-007",
        "Research DAO 8.4-day median review turnaround represents a -91.34% change vs 97 days traditional.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "pct_delta(8.4, 97.0)",
            "claimed_value": -91.3402,
            "has_claimed_value": True,
            "tolerance": 1e-3,
            "tolerance_mode": "abs",
            "expected_unit": "%",
            "claimed_unit": "%",
        },
    )
    add_calc(
        "CALC-008",
        "Expert reviewer maximum compensation is 15 + 1.5 * (10 - 5) = 22.5 ZOO.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "base + bonus * (max_score - threshold)",
            "variables": {"base": 15, "bonus": 1.5, "max_score": 10, "threshold": 5},
            "claimed_value": 22.5,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "zoo",
            "claimed_unit": "zoo",
            "exact_rational": True,
        },
    )
    add_calc(
        "CALC-009",
        "Thinking Chains equal-vote quorum capture upper bound for n=21, theta=0.67, p=0.25 is exp(-2*21*0.42^2) = 0.0006064.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "hoeffding_upper(n, theta, p)",
            "variables": {"n": 21, "theta": 0.67, "p": 0.25},
            "claimed_value": 0.00060644,
            "has_claimed_value": True,
            "tolerance": 1e-6,
            "tolerance_mode": "abs",
        },
    )
    add_calc(
        "CALC-010",
        "Training-provenance shard audit requires ceil(ln(1/0.01) / 0.05) = 93 samples for rho=5%, delta=1%.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "ceil(ln(1 / delta) / rho)",
            "variables": {"delta": 0.01, "rho": 0.05},
            "claimed_value": 93,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "shards",
            "claimed_unit": "shards",
        },
    )
    add_calc(
        "CALC-011",
        "Experience Ledger 0.2% cost relative to 100% fine-tuning corresponds to a 500x cost reduction factor.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "ratio(100, 0.2)",
            "claimed_value": 500,
            "has_claimed_value": True,
            "tolerance": 0,
            "tolerance_mode": "abs",
            "expected_unit": "x",
            "claimed_unit": "x",
            "exact_rational": True,
        },
    )
    add_calc(
        "CALC-012",
        "95% CI halfwidth for 5 useful-compute measurements [98.0, 98.2, 98.1, 98.3, 98.4] is 0.1386.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "ci95_halfwidth(std(98.0, 98.2, 98.1, 98.3, 98.4), 5)",
            "claimed_value": 0.138593,
            "has_claimed_value": True,
            "tolerance": 1e-4,
            "tolerance_mode": "abs",
            "expected_unit": "%",
            "claimed_unit": "%",
        },
    )

    # 9 Mechanical Refutations
    add_calc(
        "CALC-013",
        "Arithmetic error claiming 10.0ms + 0.9ms = 11.9ms.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "10.0 + 0.9",
            "claimed_value": 11.9,
            "has_claimed_value": True,
            "tolerance": 1e-6,
            "tolerance_mode": "abs",
            "expected_unit": "ms",
            "claimed_unit": "ms",
        },
    )
    add_calc(
        "CALC-014",
        "Excessive rounding drift claiming turnaround delta is -90.0% instead of -91.34%.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "pct_delta(8.4, 97.0)",
            "claimed_value": -90.0,
            "has_claimed_value": True,
            "tolerance": 0.1,
            "tolerance_mode": "abs",
            "expected_unit": "%",
            "claimed_unit": "%",
        },
    )
    add_calc(
        "CALC-015",
        "Wrong Hoeffding probability claiming 0.05 instead of 0.0006064.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "hoeffding_upper(21, 0.67, 0.25)",
            "claimed_value": 0.05,
            "has_claimed_value": True,
            "tolerance": 1e-4,
            "tolerance_mode": "abs",
        },
    )
    add_calc(
        "CALC-016",
        "Unit mismatch claiming latency in seconds instead of milliseconds.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "10.0 + 0.9",
            "claimed_value": 10.9,
            "has_claimed_value": True,
            "tolerance": 1e-6,
            "tolerance_mode": "abs",
            "expected_unit": "ms",
            "claimed_unit": "s",
        },
    )
    add_calc(
        "CALC-017",
        "Division by zero in gas-per-tx throughput formula.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "1000000000 / 0",
            "claimed_value": 0,
            "has_claimed_value": True,
            "tolerance": 1e-6,
            "tolerance_mode": "abs",
        },
    )
    add_calc(
        "CALC-018",
        "Invalid Hoeffding regime where adversarial fraction p exceeds threshold theta.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "hoeffding_upper(21, 0.25, 0.40)",
            "claimed_value": 0.01,
            "has_claimed_value": True,
            "tolerance": 1e-4,
            "tolerance_mode": "abs",
        },
    )
    add_calc(
        "CALC-019",
        "Domain error evaluating square root of negative variance.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "sqrt(-9)",
            "claimed_value": 3,
            "has_claimed_value": True,
            "tolerance": 1e-6,
            "tolerance_mode": "abs",
        },
    )
    add_calc(
        "CALC-020",
        "False Sybil neutrality claim: splitting bond across m=4 with alpha=0.5 claimed to give factor 1.0 instead of 2.0.",
        "REFUTED_CONTRADICTION",
        {
            "expression": "m ^ (1 - alpha)",
            "variables": {"m": 4, "alpha": 0.5},
            "claimed_value": 1.0,
            "has_claimed_value": True,
            "tolerance": 1e-6,
            "tolerance_mode": "abs",
        },
    )
    add_calc(
        "CALC-021",
        "Calculation claim attempting unauthorized treasury spending (constitutional violation).",
        "REFUTED_CONTRADICTION",
        {
            "expression": "500 + 250",
            "claimed_value": 750,
            "has_claimed_value": True,
            "tolerance": 0,
            "expected_unit": "zoo",
            "claimed_unit": "zoo",
        },
        gov_action="authorize_treasury",
    )

    # 5 Mechanical Unsupported Calculations
    add_calc(
        "CALC-022",
        "Calculation claim missing expression formula.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "expression": "",
            "claimed_value": 42,
            "has_claimed_value": True,
            "tolerance": 1e-6,
        },
    )
    add_calc(
        "CALC-023",
        "Calculation claim omitting claimed_value.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "expression": "10 + 0.9",
            "has_claimed_value": False,
            "tolerance": 1e-6,
        },
    )
    add_calc(
        "CALC-024",
        "Subsidy formula referencing undefined halving period T_h.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "expression": "S_max / (2 * T_h)",
            "variables": {"S_max": 1000000000},
            "claimed_value": 500,
            "has_claimed_value": True,
            "tolerance": 1e-6,
        },
    )
    add_calc(
        "CALC-025",
        "Syntactically malformed calculation expression.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "expression": "100 + * 20",
            "claimed_value": 120,
            "has_claimed_value": True,
            "tolerance": 1e-6,
        },
    )
    add_calc(
        "CALC-026",
        "Calculation omitting required claimed_unit.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "expression": "15 + 7.5",
            "claimed_value": 22.5,
            "has_claimed_value": True,
            "tolerance": 0,
            "expected_unit": "zoo",
            "claimed_unit": "",
        },
    )

    # 3 Explicit Human-Review Calculations
    add_calc(
        "CALC-027",
        "Ten-year net deflation forecast depending on unobserved external fee demand.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "expression": "1000000000 * 0.02",
            "claimed_value": 20000000,
            "has_claimed_value": True,
            "tolerance": 1e-3,
            "review_scope": "external_domain",
        },
    )
    add_calc(
        "CALC-028",
        "Subjective selection of optimal DAO constitutional timelock duration.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "expression": "14 * 24",
            "claimed_value": 336,
            "has_claimed_value": True,
            "tolerance": 0,
            "review_scope": "subjective_judgment",
        },
    )
    add_calc(
        "CALC-029",
        "Ecological valuation of biodiversity preserved per ZOO research grant.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "expression": "10000 / 12",
            "claimed_value": 833.33,
            "has_claimed_value": True,
            "tolerance": 1.0,
            "review_scope": "external_domain",
        },
    )

    # 1 Honest Negative Regime: tolerance_boundary (GT = VERIFIED_REPRODUCIBLE)
    add_calc(
        "CALC-030",
        "Display-rounded 4.76M TPS from 47,619 / 0.010 = 4,761,900 TPS tested under overly strict 1e-5 relative tolerance.",
        "VERIFIED_REPRODUCIBLE",
        {
            "expression": "47619 / 0.01",
            "claimed_value": 4760000,
            "has_claimed_value": True,
            "tolerance": 1e-5,
            "tolerance_mode": "rel",
            "expected_unit": "tps",
            "claimed_unit": "tps",
        },
        regime="tolerance_boundary",
        notes="3-sig-fig paper display rounding (0.04% relative delta) fails an uncalibrated 1e-5 tolerance gate.",
    )

    # =========================================================================
    # CLASS 3: code_result_check (CODE-001 .. CODE-030)
    # =========================================================================
    def add_code(cid, stmt, exp, code_payload, **kw):
        c = claim_base(cid, "code_result_check", stmt, exp, **kw)
        c["code_result"] = code_payload
        claims.append(c)

    pot_inputs = {"model_spec": "zoo-int8-v1", "nonce": 1352, "task_id": "task-alpha"}
    pot_sha = sha256_hex(canonical_json(pot_inputs))
    shard_leaves = ["shard-001", "shard-002", "shard-003", "shard-004"]
    shard_root = merkle_for_leaves(shard_leaves)

    # Find deterministic sortition inputs (verified by SHA-256)
    sort_seed = "zoo-epoch-1352"
    sort_op = "validator-07"
    sort_h = int(sha256_hex(f"{sort_seed}|{sort_op}".encode("utf-8")), 16)
    sort_selected = sort_h * 100 < (1 << 256) * 21

    bench_json_payload = '{"chain_id":200200,"finality_ms":10.9,"gpu_workers":500,"tps":4760000,"validators":21}'
    bench_json_sha = sha256_hex(bench_json_payload.encode("utf-8"))
    bench_csv_payload = "method,bits_per_param,size_gb,ratio\nfull_fp16,16,140,1\nlora_r16,0.46,4.0,35\nbitdelta,1.0005,0.7,200\n"
    bench_csv_sha = sha256_hex(bench_csv_payload.encode("utf-8"))

    # 12 Genuine Verifiable Code/Artifact Results
    add_code(
        "CODE-001",
        "BitDelta optimal scale gamma* = ||W_f - W_b||_1 / mn equals 0.25 on reference 4-weight tensor.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "deterministic_eval",
            "program": {
                "op": "bitdelta_scale",
                "inputs": {"w_base": [1.0, -0.5, 0.25, 2.0], "w_fine": [1.25, -0.75, 0.5, 1.75]},
            },
            "expected_output": 0.25,
            "tolerance": 1e-9,
        },
    )
    add_code(
        "CODE-002",
        "DeltaSoup coordinate-wise trimmed mean (trim_k=1) rejects 2 Byzantine outlier vectors.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "deterministic_eval",
            "program": {
                "op": "trimmed_mean",
                "inputs": {
                    "trim_k": 1,
                    "vectors": [
                        [1.0, 2.0],
                        [1.1, 2.1],
                        [0.9, 1.9],
                        [1.0, 2.0],
                        [100.0, -100.0],
                        [-100.0, 100.0],
                    ],
                },
            },
            "expected_output": [1.0, 2.0],
            "tolerance": 1e-6,
        },
    )
    add_code(
        "CODE-003",
        "Thinking Chains node reward P = (1-phi)*f*s + sigma*(w/W) equals 45.0 AI.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "deterministic_eval",
            "program": {
                "op": "linear_reward",
                "inputs": {
                    "phi": 0.1,
                    "fee": 100.0,
                    "share": 0.25,
                    "subsidy": 90.0,
                    "weight": 25.0,
                    "total_weight": 100.0,
                },
            },
            "expected_output": 45.0,
            "tolerance": 1e-9,
        },
    )
    add_code(
        "CODE-004",
        "Merkle root over 4 Thinking Chains training-provenance shards reproduces deterministically.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "deterministic_eval",
            "program": {"op": "merkle_root", "inputs": {"leaves": shard_leaves}},
            "expected_output": shard_root,
        },
    )
    add_code(
        "CODE-005",
        "Canonical SHA-256 of PoT receipt parameters matches declared digest.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "deterministic_eval",
            "program": {"op": "sha256_canonical", "inputs": pot_inputs},
            "expected_output": pot_sha,
        },
    )
    add_code(
        "CODE-006",
        "Cryptographic sortition check H(seed|operator) < 2^256 * (n/N) reproduces deterministically.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "deterministic_eval",
            "program": {
                "op": "sortition_check",
                "inputs": {
                    "seed": sort_seed,
                    "operator_id": sort_op,
                    "committee_size": 21,
                    "population_size": 100,
                },
            },
            "expected_output": sort_selected,
        },
    )
    add_code(
        "CODE-007",
        "Audit-sampling detection probability 1 - (1 - 0.1)^30 equals 0.957609.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "deterministic_eval",
            "program": {
                "op": "eval_expr",
                "inputs": {"expression": "1 - (1 - q)^k", "variables": {"q": 0.1, "k": 30}},
            },
            "expected_output": 0.95760884,
            "tolerance": 1e-5,
        },
    )
    add_code(
        "CODE-008",
        "Quasar testnet JSON benchmark summary matches content-addressed SHA-256.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "artifact_hash",
            "artifact_payload": bench_json_payload,
            "declared_sha256": bench_json_sha,
        },
    )
    add_code(
        "CODE-009",
        "BitDelta compression CSV table matches content-addressed SHA-256.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "artifact_hash",
            "artifact_payload": bench_csv_payload,
            "declared_sha256": bench_csv_sha,
        },
    )
    add_code(
        "CODE-010",
        "Stochastic GPU useful-compute benchmark verified via declared 95% confidence interval (98.2% +/- 0.25%).",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "statistical_interval",
            "stochastic": True,
            "samples": [98.1, 98.3, 98.0, 98.4, 98.2, 98.15, 98.25, 98.2],
            "claimed_mean": 98.2,
            "has_claimed_mean": True,
            "ci_halfwidth": 0.25,
        },
    )
    add_code(
        "CODE-011",
        "Stochastic BitDelta task preservation benchmark verified via declared 95% CI (91.4% +/- 0.8%).",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "statistical_interval",
            "stochastic": True,
            "samples": [91.1, 91.8, 91.3, 91.5, 91.2, 91.5],
            "claimed_mean": 91.4,
            "has_claimed_mean": True,
            "ci_halfwidth": 0.8,
        },
    )
    add_code(
        "CODE-012",
        "Stochastic Quasar combined finality latency verified via declared 95% CI (10.9ms +/- 0.25ms).",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "statistical_interval",
            "stochastic": True,
            "samples": [10.85, 10.95, 10.88, 10.92, 10.91, 10.89, 10.90],
            "claimed_mean": 10.9,
            "has_claimed_mean": True,
            "ci_halfwidth": 0.25,
        },
    )

    # 8 Mechanical Refutations
    add_code(
        "CODE-013",
        "Fabricated BitDelta scale claiming 0.75 instead of 0.25.",
        "REFUTED_CONTRADICTION",
        {
            "mode": "deterministic_eval",
            "program": {
                "op": "bitdelta_scale",
                "inputs": {"w_base": [1.0, -0.5, 0.25, 2.0], "w_fine": [1.25, -0.75, 0.5, 1.75]},
            },
            "expected_output": 0.75,
            "tolerance": 1e-6,
        },
    )
    add_code(
        "CODE-014",
        "Tampered DeltaSoup output reporting poisoned untrimmed mean.",
        "REFUTED_CONTRADICTION",
        {
            "mode": "deterministic_eval",
            "program": {
                "op": "trimmed_mean",
                "inputs": {
                    "trim_k": 1,
                    "vectors": [[1.0, 2.0], [1.0, 2.0], [1.0, 2.0], [50.0, 50.0]],
                },
            },
            "expected_output": [13.25, 14.0],
            "tolerance": 1e-6,
        },
    )
    add_code(
        "CODE-015",
        "Forged training-provenance Merkle root.",
        "REFUTED_CONTRADICTION",
        {
            "mode": "deterministic_eval",
            "program": {"op": "merkle_root", "inputs": {"leaves": shard_leaves}},
            "expected_output": "f" * 64,
        },
    )
    add_code(
        "CODE-016",
        "Tampered benchmark JSON artifact (inflated TPS to 9760000 against original digest).",
        "REFUTED_CONTRADICTION",
        {
            "mode": "artifact_hash",
            "artifact_payload": '{"chain_id":200200,"finality_ms":10.9,"gpu_workers":500,"tps":9760000,"validators":21}',
            "declared_sha256": bench_json_sha,
        },
    )
    add_code(
        "CODE-017",
        "Statistical benchmark claiming mean 99.5% outside observed sample CI around 98.2%.",
        "REFUTED_CONTRADICTION",
        {
            "mode": "statistical_interval",
            "stochastic": True,
            "samples": [98.1, 98.3, 98.0, 98.4, 98.2],
            "claimed_mean": 99.5,
            "has_claimed_mean": True,
            "ci_halfwidth": 0.25,
        },
    )
    add_code(
        "CODE-018",
        "Artificially narrowed CI halfwidth (0.01) below actual 95% sample uncertainty.",
        "REFUTED_CONTRADICTION",
        {
            "mode": "statistical_interval",
            "stochastic": True,
            "samples": [97.5, 98.9, 98.1, 98.6, 97.9],
            "claimed_mean": 98.2,
            "has_claimed_mean": True,
            "ci_halfwidth": 0.01,
        },
    )
    add_code(
        "CODE-019",
        "Self-validated code benchmark where author_id == verifier_id.",
        "REFUTED_CONTRADICTION",
        {
            "mode": "artifact_hash",
            "artifact_payload": bench_json_payload,
            "declared_sha256": bench_json_sha,
        },
        author="agent-bench-01",
        verifier="agent-bench-01",
    )
    add_code(
        "CODE-020",
        "Code benchmark claiming forbidden governance action self_declare_valid.",
        "REFUTED_CONTRADICTION",
        {
            "mode": "artifact_hash",
            "artifact_payload": bench_json_payload,
            "declared_sha256": bench_json_sha,
        },
        gov_action="self_declare_valid",
    )

    # 4 Mechanical Unsupported Code Results
    add_code(
        "CODE-021",
        "Artifact hash check with missing artifact_payload.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "mode": "artifact_hash",
            "artifact_payload": "",
            "declared_sha256": bench_json_sha,
        },
    )
    add_code(
        "CODE-022",
        "Deterministic eval requesting unapproved kernel op arbitrary_shell_exec.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "mode": "deterministic_eval",
            "program": {"op": "arbitrary_shell_exec", "inputs": {"cmd": "echo hi"}},
            "expected_output": "hi",
        },
    )
    add_code(
        "CODE-023",
        "Statistical interval check with insufficient sample size (n=2 < 3).",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "mode": "statistical_interval",
            "stochastic": True,
            "samples": [98.1, 98.3],
            "claimed_mean": 98.2,
            "has_claimed_mean": True,
            "ci_halfwidth": 0.5,
        },
    )
    add_code(
        "CODE-024",
        "Artifact hash check with malformed non-hex SHA-256 digest.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "mode": "artifact_hash",
            "artifact_payload": bench_json_payload,
            "declared_sha256": "not-a-valid-sha256",
        },
    )

    # 2 Explicit Human-Review Code Results
    add_code(
        "CODE-025",
        "Statistical interval with vacuously wide CI (+/- 50.0 on mean 98.2).",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "mode": "statistical_interval",
            "stochastic": True,
            "samples": [98.1, 98.3, 98.0, 98.4, 98.2],
            "claimed_mean": 98.2,
            "has_claimed_mean": True,
            "ci_halfwidth": 50.0,
        },
    )
    add_code(
        "CODE-026",
        "Proprietary hardware profiling benchmark on unreleased Blackwell GPU cluster.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "mode": "artifact_hash",
            "artifact_payload": bench_json_payload,
            "declared_sha256": bench_json_sha,
            "review_scope": "external_domain",
        },
    )

    # 4 Honest Negative Regime 2: Stochastic / Hardware-Dependent ML Benchmarks
    gpu_ref_payload = '{"model":"bitdelta-70b","gpu":"H100","mmlu":74.20000}'
    gpu_ref_sha = sha256_hex(gpu_ref_payload.encode("utf-8"))
    gpu_drift_payload = '{"model":"bitdelta-70b","gpu":"H100","mmlu":74.20001}'

    gpu2_ref_payload = '{"model":"quasar-poai","gpu":"A100","useful_compute_pct":98.20000}'
    gpu2_ref_sha = sha256_hex(gpu2_ref_payload.encode("utf-8"))
    gpu2_drift_payload = '{"model":"quasar-poai","gpu":"A100","useful_compute_pct":98.19999}'

    add_code(
        "CODE-027",
        "Stochastic FP16 reduction drift (74.20001 vs 74.20000) across GPU drivers under strict exact-hash mode.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "artifact_hash",
            "stochastic": True,
            "artifact_payload": gpu_drift_payload,
            "declared_sha256": gpu_ref_sha,
        },
        regime="stochastic_hardware_drift",
        notes="1e-5 floating-point non-associativity drift breaks strict exact-hash reproducibility; requires statistical_interval mode.",
    )
    add_code(
        "CODE-028",
        "Stochastic A100 vs H100 kernel drift (98.19999 vs 98.20000) under strict exact-hash mode.",
        "VERIFIED_REPRODUCIBLE",
        {
            "mode": "artifact_hash",
            "stochastic": True,
            "artifact_payload": gpu2_drift_payload,
            "declared_sha256": gpu2_ref_sha,
        },
        regime="stochastic_hardware_drift",
        notes="Hardware-level FP rounding breaks byte-exact hash equality even though result is epistemically equivalent.",
    )
    add_code(
        "CODE-029",
        "Stochastic multi-seed RLHF benchmark submitted without declared statistical interval or hash.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "mode": "artifact_hash",
            "stochastic": True,
            "artifact_payload": '{"reward_mean":0.84}',
            "declared_sha256": "",
        },
        regime="stochastic_hardware_drift",
        notes="Stochastic benchmark omits statistical bounds; strict verifier classifies UNSUPPORTED rather than INCONCLUSIVE.",
    )
    add_code(
        "CODE-030",
        "Stochastic distributed training throughput run submitted without confidence interval samples.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "mode": "deterministic_eval",
            "stochastic": True,
            "program": {"op": "eval_expr", "inputs": {"expression": "4760000"}},
            "expected_output": 4760000,
        },
        regime="stochastic_hardware_drift",
        notes="Marked stochastic without statistical_interval mode; rejected as UNSUPPORTED.",
    )

    # =========================================================================
    # CLASS 4: reasoning_chain_check (CHAIN-001 .. CHAIN-030)
    # =========================================================================
    def add_chain(cid, stmt, exp, chain_payload, **kw):
        c = claim_base(cid, "reasoning_chain_check", stmt, exp, **kw)
        c["reasoning_chain"] = chain_payload
        claims.append(c)

    # 11 Genuine Verifiable Public Reasoning Chains
    add_chain(
        "CHAIN-001",
        "Public DAG deriving Zoo EVM 4.76M Quasar-bounded TPS from CIT-009, CALC-001, and CALC-002.",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-009", "public_rationale": "Zoo EVM pins 1B gas limit and 47,619 simple tx/block."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CALC-001", "public_rationale": "floor(1e9 / 21000) = 47,619 tx/block verified."},
                {"step_id": "p3", "kind": "premise", "evidence_ref": "CALC-002", "public_rationale": "47,619 / 0.01s = 4,761,900 TPS verified."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2", "p3"], "public_rationale": "Under 10ms Quasar finality, Zoo EVM supports ~4.76M simple TPS."},
            ],
        },
    )
    add_chain(
        "CHAIN-002",
        "Public DAG verifying Quasar + PoAI 10.9ms finality decomposition from CIT-008 and CALC-003.",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-008", "public_rationale": "Quasar paper cites 10ms base finality and 0.9ms PoAI overhead."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CALC-003", "public_rationale": "Exact rational sum 10.0 + 0.9 = 10.9ms verified."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2"], "public_rationale": "Combined finality arithmetic matches cited testnet measurements."},
            ],
        },
    )
    add_chain(
        "CHAIN-003",
        "Public DAG verifying BitDelta 200x compression and optimal L1 scale kernel from CIT-006, CALC-004, CODE-001.",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-006", "public_rationale": "BitDelta abstract specifies 1-bit sign matrix + per-tensor scale."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CALC-004", "public_rationale": "140GB / 0.7GB = 200x reduction verified."},
                {"step_id": "p3", "kind": "premise", "evidence_ref": "CODE-001", "public_rationale": "Closed-form optimal scale gamma* kernel reproduces 0.25."},
                {"step_id": "i1", "kind": "inference", "depends_on": ["p1", "p2"], "public_rationale": "1-bit delta representation achieves 200x storage reduction."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["i1", "p3"], "public_rationale": "BitDelta storage ratio and scale kernel are jointly reproducible."},
            ],
        },
    )
    add_chain(
        "CHAIN-004",
        "Public DAG verifying DeltaSoup Byzantine-robust aggregation from CIT-006 and CODE-002.",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-006", "public_rationale": "DeltaSoup uses coordinate-wise trimmed mean up to 30% Byzantine."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CODE-002", "public_rationale": "Trimmed mean kernel rejects extreme +/-100 outliers cleanly."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2"], "public_rationale": "Trimmed-mean reference kernel matches paper specification."},
            ],
        },
    )
    add_chain(
        "CHAIN-005",
        "Public DAG verifying Thinking Chains fair-launch issuance & reward conservation from CIT-002 and CODE-003.",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-002", "public_rationale": "Tokenomics caps supply at 10^9 AI with no premine."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CODE-003", "public_rationale": "Reward kernel computes exact demand-fee + subsidy share = 45.0 AI."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2"], "public_rationale": "Per-block node reward computation adheres to tokenomics formula."},
            ],
        },
    )
    add_chain(
        "CHAIN-006",
        "Public DAG connecting Dissent-safety and LLM-free constitutional auditability (CIT-004, CIT-005).",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-004", "public_rationale": "Good-faith finite judgments are never slashed."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CIT-005", "public_rationale": "Constitutional Rule 10 requires LLM-free hash/signature inspection."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2"], "public_rationale": "Objective slashing criteria remain deterministically auditable without LLM replay."},
            ],
        },
    )
    add_chain(
        "CHAIN-007",
        "Public DAG verifying Research DAO 91.34% turnaround speedup & 100% weight normalization (CIT-007, CALC-006, CALC-007).",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-007", "public_rationale": "287 proposals achieved 8.4-day vs 97-day median turnaround."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CALC-006", "public_rationale": "Five review quality weights sum to 100%."},
                {"step_id": "p3", "kind": "premise", "evidence_ref": "CALC-007", "public_rationale": "Turnaround delta is -91.34%."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2", "p3"], "public_rationale": "Reported Research DAO metrics are internally consistent."},
            ],
        },
    )
    add_chain(
        "CHAIN-008",
        "Public DAG verifying post-quantum finalized Merkle provenance (CIT-003, CALC-010, CODE-004).",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-003", "public_rationale": "Finality authenticated by NIST FIPS 203/204/205."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CALC-010", "public_rationale": "93 random shard samples achieve 99% detection at 5% deviation."},
                {"step_id": "p3", "kind": "premise", "evidence_ref": "CODE-004", "public_rationale": "Shard Merkle root reproduces deterministically."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2", "p3"], "public_rationale": "Corpus provenance audit is size-independent and post-quantum anchored."},
            ],
        },
    )
    add_chain(
        "CHAIN-009",
        "Public DAG verifying Experience Ledger 500x cost reduction claim (CIT-010, CALC-011).",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-010", "public_rationale": "Paper reports semantic optimization at 0.2% of fine-tuning cost."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CALC-011", "public_rationale": "100 / 0.2 = 500x cost factor verified."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2"], "public_rationale": "0.2% relative cost corresponds to a 500x reduction."},
            ],
        },
    )
    add_chain(
        "CHAIN-010",
        "Public DAG verifying equal-vote sortition quorum safety (CALC-009, CODE-006).",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CALC-009", "public_rationale": "Hoeffding capture bound for n=21, theta=0.67, p=0.25 is 0.0006064."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CODE-006", "public_rationale": "Sortition draw evaluates deterministically over SHA-256."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "p2"], "public_rationale": "Equal-seat sortition yields verifiable low capture probability."},
            ],
        },
    )
    add_chain(
        "CHAIN-011",
        "Diamond 5-step public DAG with permitted AI advisory governance_action=recommend.",
        "VERIFIED_REPRODUCIBLE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "Only finite authenticated artifacts enter consensus."},
                {"step_id": "p2", "kind": "premise", "evidence_ref": "CODE-010", "public_rationale": "Useful compute 98.2% verified within 95% CI."},
                {"step_id": "i1", "kind": "inference", "depends_on": ["p1"], "public_rationale": "Consensus replay determinism holds."},
                {"step_id": "i2", "kind": "inference", "depends_on": ["p1", "p2"], "public_rationale": "GPU efficiency remains high under bounded verification."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["i1", "i2"], "public_rationale": "Recommend retaining current dual-layer verification parameters for human vote."},
            ],
        },
        gov_action="recommend",
    )

    # 8 Mechanical Refutations
    add_chain(
        "CHAIN-012",
        "Circular 2-step reasoning chain (s1 <-> s2).",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "s2",
            "steps": [
                {"step_id": "s1", "kind": "inference", "depends_on": ["s2"], "public_rationale": "Assumes s2 holds."},
                {"step_id": "s2", "kind": "conclusion", "depends_on": ["s1"], "public_rationale": "Concludes from s1."},
            ],
        },
    )
    add_chain(
        "CHAIN-013",
        "Indirect 3-step cycle (s1 -> s2 -> s3 -> s1).",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "s3",
            "steps": [
                {"step_id": "s1", "kind": "inference", "depends_on": ["s3"], "public_rationale": "Depends on s3."},
                {"step_id": "s2", "kind": "inference", "depends_on": ["s1"], "public_rationale": "Depends on s1."},
                {"step_id": "s3", "kind": "conclusion", "depends_on": ["s2"], "public_rationale": "Depends on s2."},
            ],
        },
    )
    add_chain(
        "CHAIN-014",
        "Self-referential 1-step cycle (s1 -> s1).",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "s1",
            "steps": [
                {"step_id": "s1", "kind": "conclusion", "depends_on": ["s1"], "public_rationale": "Justifies itself."},
            ],
        },
    )
    add_chain(
        "CHAIN-015",
        "Reasoning chain relying on refuted calculation CALC-013.",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CALC-013", "public_rationale": "Claims 10.0 + 0.9 = 11.9ms."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Finality exceeds 11.5ms."},
            ],
        },
    )
    add_chain(
        "CHAIN-016",
        "Reasoning chain relying on refuted citation CIT-014.",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-014", "public_rationale": "Claims 1.9ms combined finality."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Sub-2ms finality achieved."},
            ],
        },
    )
    add_chain(
        "CHAIN-017",
        "Reasoning chain with duplicate step_id p1.",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "First p1."},
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-002", "public_rationale": "Duplicate p1."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Ambiguous DAG."},
            ],
        },
    )
    add_chain(
        "CHAIN-018",
        "Reasoning chain with self-validation (author_id == verifier_id).",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "Valid citation."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Self-approved."},
            ],
        },
        author="agent-omega",
        verifier="agent-omega",
    )
    add_chain(
        "CHAIN-019",
        "Reasoning chain attempting forbidden governance_action=redefine_voting_rules.",
        "REFUTED_CONTRADICTION",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-005", "public_rationale": "Constitutional rule cited."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Unilaterally alter DAO voting quorum."},
            ],
        },
        gov_action="redefine_voting_rules",
    )

    # 7 Mechanical Unsupported Chains
    add_chain(
        "CHAIN-020",
        "Reasoning chain with dangling dependency ghost-step-99.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "Valid premise."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1", "ghost-step-99"], "public_rationale": "Depends on missing step."},
            ],
        },
    )
    add_chain(
        "CHAIN-021",
        "Reasoning chain containing private internal CoT step (kind=private_cot).",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "Valid premise."},
                {"step_id": "h1", "kind": "private_cot", "depends_on": ["p1"], "public_rationale": "Hidden scratchpad tokens."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["h1"], "public_rationale": "Derived from private CoT."},
            ],
        },
    )
    add_chain(
        "CHAIN-022",
        "Reasoning chain containing opaque_cot_blob=true step.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "Valid premise."},
                {"step_id": "i1", "kind": "inference", "depends_on": ["p1"], "public_rationale": "Encrypted latent state", "opaque_cot_blob": True},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["i1"], "public_rationale": "Depends on opaque blob."},
            ],
        },
    )
    add_chain(
        "CHAIN-023",
        "Reasoning chain with empty public_rationale.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "Valid premise."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "   "},
            ],
        },
    )
    add_chain(
        "CHAIN-024",
        "Reasoning chain relying on unverified fabricated citation CIT-019.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-019", "public_rationale": "Cites fabricated referee minting clause."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Referees mint tokens directly."},
            ],
        },
    )
    add_chain(
        "CHAIN-025",
        "Reasoning chain with ungrounded leaf inference step lacking evidence_ref.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "i1", "kind": "inference", "depends_on": [], "public_rationale": "Unbacked assertion without evidence_ref."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["i1"], "public_rationale": "Follows from unbacked assertion."},
            ],
        },
    )
    add_chain(
        "CHAIN-026",
        "Reasoning chain whose conclusion_step_id is absent from steps.",
        "UNSUPPORTED_INSUFFICIENT_EVIDENCE",
        {
            "conclusion_step_id": "missing-final",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-001", "public_rationale": "Valid premise."},
            ],
        },
    )

    # 3 Explicit Human-Review Chains
    add_chain(
        "CHAIN-027",
        "Reasoning chain relying on inconclusive external-domain citation CIT-022.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-022", "public_rationale": "Compares turnaround against external journal logs."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Outperforms all traditional journals."},
            ],
        },
    )
    add_chain(
        "CHAIN-028",
        "Normative DAO research-funding priority ranking requiring human governance judgment.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "conclusion_step_id": "c1",
            "review_scope": "subjective_judgment",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-007", "public_rationale": "Research DAO metrics verified."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Prioritize conservation grants over zkML grants."},
            ],
        },
    )
    add_chain(
        "CHAIN-029",
        "Cross-jurisdictional regulatory classification chain requiring legal review.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "conclusion_step_id": "c1",
            "review_scope": "external_domain",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-002", "public_rationale": "Fair-launch issuance verified."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["p1"], "public_rationale": "Token qualifies as non-security globally."},
            ],
        },
    )

    # 1 Honest Negative Regime 3: Sophisticated Cherry-Picking in Reasoning Chain
    add_chain(
        "CHAIN-030",
        "Cherry-picking DAG: Grounds in verified CIT-004 (Dissent-safety) to conclude honest minority reporting is costless and strictly incentive-compatible under bare EMA, omitting Scope (honest) caveat.",
        "INCONCLUSIVE_NEEDS_HUMAN_REVIEW",
        {
            "conclusion_step_id": "c1",
            "steps": [
                {"step_id": "p1", "kind": "premise", "evidence_ref": "CIT-004", "public_rationale": "Lemma Dissent-safety proves no well-formed good-faith judgment is ever slashed."},
                {"step_id": "i1", "kind": "inference", "depends_on": ["p1"], "public_rationale": "Zero slashing penalty applies to minority votes."},
                {"step_id": "c1", "kind": "conclusion", "depends_on": ["i1"], "public_rationale": "Therefore honest minority reporting is costless and strictly incentive-compatible under bare EMA reputation."},
            ],
        },
        regime="cherry_picking_omitted_caveat",
        notes="Mechanically valid acyclic DAG over verified premise CIT-004, but omits Scope (honest) caveat (line 335: reputation decay & beauty-contest equilibrium).",
    )

    assert len(claims) == 120, f"expected 120 claims, got {len(claims)}"
    return claims


def main() -> None:
    hashes = load_pinned_hashes()
    claims = build_claims(hashes)
    bundle = {
        "schema_version": "1.0.0",
        "bundle_id": "zoo-open-evidence-benchmark-v1-seed-1352",
        "seed": 1352,
        "description": "120 labeled public evidence & reasoning claims grounded in real zoo-apps/papers .tex sources (30 per class) with 3 honest negative regimes.",
        "claims": claims,
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
        f.write("\n")
    print(f"Generated {len(claims)} claims at {OUT_PATH}")


if __name__ == "__main__":
    main()
