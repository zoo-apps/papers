#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic fixture generator (--seed 1352) grounded in real zoo-apps/papers .tex files."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT_REF = Path(__file__).resolve().parent.parent
REPO_ROOT = ROOT_REF.parent.parent
sys.path.insert(0, str(ROOT_REF / "python"))

from experience_ledger import (  # noqa: E402
    SCHEMA_VERSION,
    compute_event_id,
    compute_policy_sha256,
    ed25519_public_key_from_seed,
    replay,
    sha256_hex,
    sign_event,
)

DOMAINS = [
    "ledger.merkle",
    "ledger.storage",
    "ml.grpo",
    "ml.memory",
    "dao.governance",
    "consensus.bft",
    "desci.provenance",
    "math.reasoning",
]


def discover_real_tex_files(limit: int = 40) -> list[Path]:
    """Deterministically discover real .tex source files in zoo-apps/papers."""
    candidates: list[Path] = []
    # Prioritize zoo-experience-ledger and experience-ledger-dso sections first
    for subdir in ("zoo-experience-ledger/sections", "experience-ledger-dso/sections"):
        d = REPO_ROOT / subdir
        if d.is_dir():
            candidates.extend(sorted(d.glob("*.tex")))
    # Then top-level paper .tex files
    for p in sorted(REPO_ROOT.glob("*/*.tex")):
        if p not in candidates and p.parent.name not in ("shared",):
            candidates.append(p)
    return candidates[:limit]


def make_identity(principal_id: str, role: str, active: bool = True) -> dict:
    seed = bytes.fromhex(sha256_hex(f"zoo-papers-10-seed-1352:{principal_id}".encode("utf-8")))
    pub = ed25519_public_key_from_seed(seed).hex()
    return {
        "principal_id": principal_id,
        "role": role,
        "active": active,
        "seed": seed,
        "public_key_hex": pub,
    }


def vfs_uri(digest: str, use_s3: bool = False) -> str:
    if use_s3:
        return f"s3://hanzo-research-vfs/sha256/{digest[:2]}/{digest}"
    return f"vfs://sha256/{digest}"


def build_entry(
    ident: dict,
    domain: str,
    claim_key: str,
    claim_value: str,
    summary: str,
    conf_bps: int,
    artifact_bytes: bytes,
    use_s3: bool,
    parents: list[str],
    ts: int,
    nonce: str,
    receipt_hash: str = "",
    external_uris: list[str] | None = None,
) -> dict:
    art_hash = sha256_hex(artifact_bytes)
    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_type": "experience_entry",
        "contributor_id": ident["principal_id"],
        "domain": domain,
        "claim_key": claim_key,
        "claim_value_hash": sha256_hex(claim_value.encode("utf-8")),
        "summary": summary[:1024],
        "confidence_bps": conf_bps,
        "artifact_sha256": art_hash,
        "artifact_uri": vfs_uri(art_hash, use_s3=use_s3),
        "artifact_size_bytes": len(artifact_bytes),
        "external_uris": sorted(external_uris or []),
        "parent_hashes": sorted(set(parents)),
        "receipt_hash": receipt_hash,
        "created_at_unix": ts,
        "nonce": nonce,
    }
    return sign_event(ev, ident["seed"])


def generate(seed: int) -> tuple[dict, dict, dict]:
    rng = random.Random(seed)
    tex_files = discover_real_tex_files(limit=40)
    if len(tex_files) < 20:
        raise RuntimeError(f"Expected >= 20 real .tex files in {REPO_ROOT}, found {len(tex_files)}")

    tex_blobs = [(p.relative_to(REPO_ROOT).as_posix(), p.read_bytes()) for p in tex_files]

    identities = [
        make_identity("did:key:researcher-alice", "human_researcher", True),
        make_identity("did:key:researcher-bob", "human_researcher", True),
        make_identity("did:key:agent-zen-01", "ai_agent", True),
        make_identity("did:key:agent-zen-02", "ai_agent", True),
        make_identity("did:key:steward-carol", "steward", True),
        make_identity("did:key:steward-dave", "steward", True),
        make_identity("did:key:retired-eve", "human_researcher", False),
    ]
    id_map = {x["principal_id"]: x for x in identities}

    policy = {
        "schema_version": SCHEMA_VERSION,
        "policy_id": "zoo-experience-ledger-corpus-policy-v1",
        "principals": [
            {
                "principal_id": x["principal_id"],
                "role": x["role"],
                "public_key_hex": x["public_key_hex"],
                "active": x["active"],
            }
            for x in identities
        ],
    }
    policy["policy_sha256"] = compute_policy_sha256(policy)

    alice = id_map["did:key:researcher-alice"]
    bob = id_map["did:key:researcher-bob"]
    agent1 = id_map["did:key:agent-zen-01"]
    agent2 = id_map["did:key:agent-zen-02"]
    carol = id_map["did:key:steward-carol"]
    dave = id_map["did:key:steward-dave"]
    retired = id_map["did:key:retired-eve"]

    events: list[dict] = []
    base_ts = 1764100000

    # 1. 60 grounded multi-writer contributions across real .tex papers (with ~30% intentional
    #    shared artifact hashes to represent realistic VFS/S3 deduplication across derived insights)
    active_writers = [alice, bob, agent1, agent2, carol, dave]
    base_entries: list[dict] = []
    for i in range(60):
        writer = active_writers[i % len(active_writers)]
        # Reuse first 24 .tex blobs periodically so dedup ratio is grounded in real paper bytes
        blob_idx = i % len(tex_blobs) if i < 40 else (i % 20)
        rel_path, raw_bytes = tex_blobs[blob_idx]
        dom = DOMAINS[i % len(DOMAINS)]
        parents = [base_entries[i - 1]["event_id"]] if i >= 8 and i % 4 == 0 else []
        receipt = sha256_hex(f"tc-receipt-v1:{seed}:{i}".encode("utf-8")) if i % 3 == 0 else ""
        ext_uris = [f"ipfs://bafybeix{sha256_hex(raw_bytes)[:48]}"] if i % 5 == 0 else []
        entry = build_entry(
            ident=writer,
            domain=dom,
            claim_key=f"paper-insight-{i:03d}",
            claim_value=f"canonical-insight-{i}:{rel_path}",
            summary=f"When applying findings from {rel_path}, verify SHA-256 provenance and bounded invariants (case {i}).",
            conf_bps=7500 + (i * 37) % 2400,
            artifact_bytes=raw_bytes,
            use_s3=(i % 2 == 1),
            parents=parents,
            ts=base_ts + i * 15,
            nonce=f"base-{i:03d}",
            receipt_hash=receipt,
            external_uris=ext_uris,
        )
        base_entries.append(entry)
        events.append(entry)

    # 2. Cascading Revocation DAG 1: Author self-revocation (root -> mid -> leaf)
    r_root = build_entry(
        alice, "math.reasoning", "rev-root-lemma", "lemma-draft",
        "When estimating intersection bounds, assume convex closure without check.",
        8100, tex_blobs[0][1], False, [], base_ts + 2000, "rev1-root",
    )
    r_mid = build_entry(
        bob, "math.reasoning", "rev-mid-cor", "cor-draft",
        "When optimizing polygon partition, depend on rev-root-lemma.",
        8300, tex_blobs[1][1], True, [r_root["event_id"]], base_ts + 2010, "rev1-mid",
    )
    r_leaf = build_entry(
        agent1, "math.reasoning", "rev-leaf-heur", "heur-draft",
        "When pruning geometry search tree, depend on rev-mid-cor.",
        7900, tex_blobs[2][1], False, [r_mid["event_id"]], base_ts + 2020, "rev1-leaf",
    )
    author_self_rev = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "revocation_record",
            "issuer_id": alice["principal_id"],
            "target_event_id": r_root["event_id"],
            "reason_code": "retracted_by_author",
            "reason": "Author found non-convex counterexample; retracting root lemma.",
            "evidence_sha256": "",
            "evidence_uri": "",
            "created_at_unix": base_ts + 2030,
        },
        alice["seed"],
    )
    events.extend([r_root, r_mid, r_leaf, author_self_rev])

    # 3. Cascading Revocation DAG 2: Steward governance revocation + unauthorized AI/peer attempts
    g_root = build_entry(
        bob, "ledger.merkle", "gov-rev-target", "merkle-dup-bug",
        "When hashing odd Merkle levels, skip last node without duplication.",
        7200, tex_blobs[3][1], False, [], base_ts + 2100, "rev2-root",
    )
    g_child = build_entry(
        agent2, "ledger.merkle", "gov-rev-child", "merkle-child",
        "When verifying odd Merkle trees, assume omitted trailing node.",
        7100, tex_blobs[4][1], True, [g_root["event_id"]], base_ts + 2110, "rev2-child",
    )
    unauth_ai_rev = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "revocation_record",
            "issuer_id": agent1["principal_id"],
            "target_event_id": g_root["event_id"],
            "reason_code": "falsified_claim",
            "reason": "AI agent illegally attempting to revoke human entry",
            "evidence_sha256": "",
            "evidence_uri": "",
            "created_at_unix": base_ts + 2115,
        },
        agent1["seed"],
    )
    unauth_peer_rev = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "revocation_record",
            "issuer_id": alice["principal_id"],
            "target_event_id": g_root["event_id"],
            "reason_code": "falsified_claim",
            "reason": "Peer human researcher illegally attempting to revoke Bob's entry",
            "evidence_sha256": "",
            "evidence_uri": "",
            "created_at_unix": base_ts + 2116,
        },
        alice["seed"],
    )
    ev_rev_hash = sha256_hex(tex_blobs[5][1])
    steward_rev = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "revocation_record",
            "issuer_id": carol["principal_id"],
            "target_event_id": g_root["event_id"],
            "reason_code": "falsified_claim",
            "reason": "Violates experience-ledger-dso Algorithm 1 odd-leaf duplication invariant.",
            "evidence_sha256": ev_rev_hash,
            "evidence_uri": vfs_uri(ev_rev_hash, False),
            "created_at_unix": base_ts + 2120,
        },
        carol["seed"],
    )
    pending_rev = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "revocation_record",
            "issuer_id": dave["principal_id"],
            "target_event_id": sha256_hex(b"not-yet-synced-event-id"),
            "reason_code": "corrupted_artifact",
            "reason": "Pre-emptive revocation for unsynced partition event",
            "evidence_sha256": "",
            "evidence_uri": "",
            "created_at_unix": base_ts + 2125,
        },
        dave["seed"],
    )
    # Place steward_rev BEFORE g_root intentionally to exercise out-of-order replay
    events.extend([steward_rev, unauth_ai_rev, unauth_peer_rev, g_child, g_root, pending_rev])

    # 4. Conflict Scenario A: Resolved via distinct steward (select_canonical) + rejected AI/human resolutions
    c1_a = build_entry(
        alice, "ml.grpo", "clip-epsilon", "epsilon=0.20",
        "When training GRPO without critic, set clip epsilon to 0.20.",
        8800, tex_blobs[6][1], False, [], base_ts + 3000, "c1-a",
    )
    c1_b = build_entry(
        bob, "ml.grpo", "clip-epsilon", "epsilon=0.05",
        "When training GRPO without critic, set clip epsilon to 0.05.",
        8750, tex_blobs[7][1], True, [], base_ts + 3005, "c1-b",
    )
    c1_pair = sorted([c1_a["event_id"], c1_b["event_id"]])
    ev_c1 = sha256_hex(tex_blobs[8][1])
    c1_flag = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "conflict_flag",
            "flagger_id": agent1["principal_id"],
            "domain": "ml.grpo",
            "claim_key": "clip-epsilon",
            "conflicting_event_ids": c1_pair,
            "evidence_sha256": ev_c1,
            "evidence_uri": vfs_uri(ev_c1, False),
            "rationale": "AI agent detected divergent GRPO clip-epsilon values across ablation runs.",
            "created_at_unix": base_ts + 3010,
        },
        agent1["seed"],
    )
    rat_c1 = sha256_hex(tex_blobs[9][1])
    c1_ai_illegal = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": agent1["principal_id"],
            "domain": "ml.grpo",
            "claim_key": "clip-epsilon",
            "reviewed_event_ids": c1_pair,
            "outcome": "select_canonical",
            "winning_event_id": c1_b["event_id"],
            "rationale_sha256": rat_c1,
            "rationale_uri": vfs_uri(rat_c1, False),
            "governance_ref": "illegal-agent-decision",
            "created_at_unix": base_ts + 3015,
        },
        agent1["seed"],
    )
    c1_human_illegal = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": alice["principal_id"],
            "domain": "ml.grpo",
            "claim_key": "clip-epsilon",
            "reviewed_event_ids": c1_pair,
            "outcome": "select_canonical",
            "winning_event_id": c1_a["event_id"],
            "rationale_sha256": rat_c1,
            "rationale_uri": vfs_uri(rat_c1, False),
            "governance_ref": "illegal-non-steward-decision",
            "created_at_unix": base_ts + 3016,
        },
        alice["seed"],
    )
    c1_steward_res = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": carol["principal_id"],
            "domain": "ml.grpo",
            "claim_key": "clip-epsilon",
            "reviewed_event_ids": c1_pair,
            "outcome": "select_canonical",
            "winning_event_id": c1_a["event_id"],
            "rationale_sha256": rat_c1,
            "rationale_uri": vfs_uri(rat_c1, False),
            "governance_ref": "hip-1352:prop-101",
            "created_at_unix": base_ts + 3020,
        },
        carol["seed"],
    )
    events.extend([c1_a, c1_b, c1_flag, c1_ai_illegal, c1_human_illegal, c1_steward_res])

    # 5. Conflict Scenario B: Open conflict + rejected steward self-validation
    c2_carol = build_entry(
        carol, "dao.governance", "quorum-floor", "quorum=10pct",
        "When ratifying experience libraries, enforce 10% quorum floor.",
        9100, tex_blobs[10][1], False, [], base_ts + 3100, "c2-carol",
    )
    c2_bob = build_entry(
        bob, "dao.governance", "quorum-floor", "quorum=8pct",
        "When ratifying high-reputation libraries, allow 8% quorum floor.",
        8950, tex_blobs[11][1], True, [], base_ts + 3105, "c2-bob",
    )
    c2_pair = sorted([c2_carol["event_id"], c2_bob["event_id"]])
    rat_c2 = sha256_hex(tex_blobs[12][1])
    c2_self_val = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": carol["principal_id"],
            "domain": "dao.governance",
            "claim_key": "quorum-floor",
            "reviewed_event_ids": c2_pair,
            "outcome": "select_canonical",
            "winning_event_id": c2_carol["event_id"],
            "rationale_sha256": rat_c2,
            "rationale_uri": vfs_uri(rat_c2, False),
            "governance_ref": "illegal-steward-self-validation",
            "created_at_unix": base_ts + 3110,
        },
        carol["seed"],
    )
    events.extend([c2_carol, c2_bob, c2_self_val])

    # 6. Conflict Scenario C: Escalated steward disagreement (Carol picks A, Dave picks B -> no LWW)
    c3_a = build_entry(
        alice, "consensus.bft", "byzantine-bound", "f<n/3",
        "When configuring BFT committee, require strictly f < n/3 faulty nodes.",
        9600, tex_blobs[13][1], False, [], base_ts + 3200, "c3-a",
    )
    c3_b = build_entry(
        bob, "consensus.bft", "byzantine-bound", "f<n/2-sync",
        "When assuming synchronous bounds, allow f < n/2 availability pinning.",
        8400, tex_blobs[14][1], True, [], base_ts + 3205, "c3-b",
    )
    c3_pair = sorted([c3_a["event_id"], c3_b["event_id"]])
    rat_c3 = sha256_hex(tex_blobs[15][1])
    c3_res_carol = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": carol["principal_id"],
            "domain": "consensus.bft",
            "claim_key": "byzantine-bound",
            "reviewed_event_ids": c3_pair,
            "outcome": "select_canonical",
            "winning_event_id": c3_a["event_id"],
            "rationale_sha256": rat_c3,
            "rationale_uri": vfs_uri(rat_c3, False),
            "governance_ref": "hip-1352:prop-102a",
            "created_at_unix": base_ts + 3210,
        },
        carol["seed"],
    )
    c3_res_dave = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": dave["principal_id"],
            "domain": "consensus.bft",
            "claim_key": "byzantine-bound",
            "reviewed_event_ids": c3_pair,
            "outcome": "select_canonical",
            "winning_event_id": c3_b["event_id"],
            "rationale_sha256": rat_c3,
            "rationale_uri": vfs_uri(rat_c3, False),
            "governance_ref": "hip-1352:prop-102b",
            "created_at_unix": base_ts + 3211,
        },
        dave["seed"],
    )
    events.extend([c3_a, c3_b, c3_res_carol, c3_res_dave])

    # 7. Conflict Scenario D: keep_both_scoped resolution
    c4_a = build_entry(
        alice, "ledger.storage", "archival-tier", "s3-hot",
        "When storing active corpus, write SHA-256 objects to Hanzo VFS/S3.",
        9400, tex_blobs[16][1], True, [], base_ts + 3300, "c4-a",
    )
    c4_b = build_entry(
        bob, "ledger.storage", "archival-tier", "arweave-external-hint",
        "When publishing immutable releases, attach optional external Arweave/IPFS URIs.",
        9300, tex_blobs[17][1], False, [], base_ts + 3305, "c4-b",
    )
    c4_pair = sorted([c4_a["event_id"], c4_b["event_id"]])
    rat_c4 = sha256_hex(tex_blobs[18][1])
    c4_res = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": dave["principal_id"],
            "domain": "ledger.storage",
            "claim_key": "archival-tier",
            "reviewed_event_ids": c4_pair,
            "outcome": "keep_both_scoped",
            "winning_event_id": "",
            "rationale_sha256": rat_c4,
            "rationale_uri": vfs_uri(rat_c4, False),
            "governance_ref": "hip-1352:prop-103",
            "created_at_unix": base_ts + 3310,
        },
        dave["seed"],
    )
    events.extend([c4_a, c4_b, c4_res])

    # 8. Conflict Scenario E: reject_all resolution
    c5_a = build_entry(
        agent1, "ml.memory", "inline-blobs", "inline-raw-json",
        "When logging experiences, embed raw 7680-dim floats inline in log.",
        4000, tex_blobs[19][1], False, [], base_ts + 3400, "c5-a",
    )
    c5_b = build_entry(
        agent2, "ml.memory", "inline-blobs", "second-kv-stack",
        "When logging experiences, deploy a second custom KV storage stack.",
        3500, tex_blobs[20][1], False, [], base_ts + 3405, "c5-b",
    )
    c5_pair = sorted([c5_a["event_id"], c5_b["event_id"]])
    rat_c5 = sha256_hex(tex_blobs[21][1])
    c5_res = sign_event(
        {
            "schema_version": SCHEMA_VERSION,
            "event_type": "resolution_decision",
            "steward_id": carol["principal_id"],
            "domain": "ml.memory",
            "claim_key": "inline-blobs",
            "reviewed_event_ids": c5_pair,
            "outcome": "reject_all",
            "winning_event_id": "",
            "rationale_sha256": rat_c5,
            "rationale_uri": vfs_uri(rat_c5, False),
            "governance_ref": "hip-1352:prop-104",
            "created_at_unix": base_ts + 3410,
        },
        carol["seed"],
    )
    events.extend([c5_a, c5_b, c5_res])

    # 9. Adversarial & Idempotency events
    tampered_id = dict(base_entries[0])
    tampered_id["summary"] = "TAMPERED summary without recomputing event_id"

    forged_sig = dict(base_entries[1])
    forged_sig["summary"] = "TAMPERED summary with recomputed event_id but stale signature"
    forged_sig["event_id"] = compute_event_id(forged_sig)

    inactive_ev = build_entry(
        retired, "desci.provenance", "retired-claim", "v1",
        "When submitting after key retirement, replay must reject.",
        5000, tex_blobs[22][1], False, [], base_ts + 3500, "retired-1",
    )

    # Duplicate gossip deliveries (idempotent collapse)
    events.extend([tampered_id, forged_sig, inactive_ev, base_entries[0], base_entries[5], c1_steward_res])

    # Deterministically shuffle final corpus with seed 1352 to simulate realistic concurrent gossip arrival
    rng.shuffle(events)

    bundle = {
        "schema_version": SCHEMA_VERSION,
        "policy": policy,
        "events": events,
    }
    expected = replay(policy, events)
    return policy, bundle, expected


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic Experience Ledger fixtures.")
    parser.add_argument("--seed", type=int, default=1352)
    args = parser.parse_args()

    policy, bundle, expected = generate(args.seed)
    fix_dir = ROOT_REF / "fixtures"
    fix_dir.mkdir(parents=True, exist_ok=True)

    (fix_dir / "policy.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    (fix_dir / "corpus_events.json").write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    (fix_dir / "expected_state.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "seed": args.seed,
                "total_events": len(bundle["events"]),
                "unique_accepted": expected["unique_accepted"],
                "duplicates": expected["duplicate_count"],
                "active_entries": len(expected["active_event_ids"]),
                "total_entries": len(expected["commitment"]["entry_states"]),
                "conflicts": len(expected["commitment"]["conflicts"]),
                "pending_revocations": len(expected["commitment"]["pending_revocations"]),
                "rejected_events": len(expected["commitment"]["rejected_events"]),
                "active_merkle_root": expected["commitment"]["active_merkle_root"],
                "state_root_hash": expected["state_root_hash"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
