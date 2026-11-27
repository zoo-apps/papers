# Decentralized Agent Identity & Delegation Reference (`agent-identity-delegation.v1`)

Clean-room Apache-2.0 reference implementation, normative specification (`v1.0.0`), JSON Schema Draft 2020-12, deterministic offline verification fixture (`5` positive lifecycle stages + `24` threat-model/constitutional attacks + `1` positive advisory control), reproducible offline benchmarks (`--seed 1352`), and dual independent zero-dependency **Go 1.24 + pure-Python 3** verifiers for **`zoo-apps/papers#3`** (HIP-1352).

Grounds [`../zoo-agent-nft.tex`](../zoo-agent-nft.tex) (Zoo Agent NFTs & monotonic capability reduction) and [`../../zoo-identity-chain/zoo-identity-chain.tex`](../../zoo-identity-chain/zoo-identity-chain.tex) (`did:zoo:*`, W3C Verifiable Credentials) over W3C DID Core (`did:key:` + portable `did:zoo:`), W3C Verifiable Credentials Data Model v2.0, and W3C Bitstring Status List v1.0.

## Highlights

- **100% Offline Portable Identities (`did:key:` + `did:zoo:` + Zoo Agent NFT / ERC-6551 Lineage)**: Self-certifying `did:key:z6Mk...` multicodec verification, portable `did:zoo:` DID documents with dual-signed `KeyRotationProof` lineage (outgoing key + controller co-signature), and optional ERC-6551 `AgentNFTBinding` metadata—verifiable with zero blockchain RPCs or centralized servers.
- **W3C VC v2.0 Monotonically Attenuated Delegation Chains**: Multi-hop delegation (`HumanCouncilRoot -> OrgController -> LeadResearchAgent -> SubWorkerAgent -> EphemeralToolSession`) enforcing strict subset narrowing across scopes, `zoo://` resource path prefixes, validity TTLs, `max_sub_depth`, rate limits, and budget caps, plus acyclicity checks.
- **Offline Cryptographic Revocation + Cascade + Freshness**: Standard W3C `131,072`-bit (`16 KB`) gzipped `BitstringStatusListCredential` (`O(1)` lookup: `~12–15 ns` Go, `~470 ns` Python) paired with a signed `RevocationSnapshot` (`crl_merkle_root`, `revoked_before` key-compromise cutoffs, digest pins, and stale status-list rejection). Revoking an intermediate parent immediately cascades to invalidate all downstream delegations.
- **Holder-Binding & Anti-Impersonation (`24/24` Attacks Caught)**: Every action presentation carries a fresh Ed25519 `HolderProof` signed by the leaf delegate's private key binding `(delegation_chain_digest, challenge_nonce, audience, action_verb, resource_uri, timestamp)`. Stolen bearer credentials, wrong-holder impersonations, forged signatures, `did:key:` spoofing, unauthorized key rotations, cross-audience/nonce replays, scope/resource/TTL/depth escalations, cyclic chains, stale/tampered revocations, and AI constitutional governance violations (`governance:vote_rules`, `treasury:authorize`, `experiment:certify`) are rejected **`24/24` (`100%`)** fail-closed.
- **Zero Third-Party Dependencies & Bit-Exact Go ↔ Python Parity**: Both Go (`go/go.mod`, stdlib only) and Pure-Python 3 (`python/agentid_py/`, stdlib only including clean-room RFC 8032 Ed25519) emit byte-identical compact JSON reports (`diff -u` = `0` bytes) and RFC 6962 `audit_merkle_root`:
  `cf1dcd70cbeca43542732d9d63d4831f93f1d9e2f8665ae6862cd8e3d6e7e747`

## Layout

```
zoo-agent-nft/reference/
├── README.md                                        # Overview and quickstart
├── SPEC.md                                          # Normative agent-identity-delegation.v1 (v1.0.0) + What Remains Unproven
├── BENCHMARK.md                                     # Measured Go & Python depth/bitstring latencies, negative regimes & matrix
├── results.json                                     # Deterministic machine-readable benchmark output (--seed 1352)
├── schema/
│   └── agent-identity-delegation.v1.schema.json     # JSON Schema Draft 2020-12
├── fixtures/
│   └── identity-delegation-suite.v1.json            # 5 positive lifecycle stages + 25 threat-model/constitutional cases
├── go/                                              # Zero-dependency Go 1.24 implementation, CLIs & race-tested suite
│   ├── go.mod
│   ├── agentid/
│   └── cmd/{id-verify,id-bench}/
└── python/                                          # Zero-dependency pure-Python 3 verifier (incl. RFC 8032 Ed25519)
    ├── agentid_py/
    └── tests/
```

## Quick Verification

```bash
# Go format, vet, and race-tested suite
(cd go && gofmt -l . && go vet ./... && go test -race -v -count=1 ./...)

# Pure-Python verifier, RFC 8032 Ed25519 vectors, and Go<->Python parity test
(cd python && python3 -m unittest discover -s tests -v)

# Verify byte-identical CLI output across Go and Python (0 bytes diff)
diff -u \
  <(cd go && go run ./cmd/id-verify --fixture ../fixtures/identity-delegation-suite.v1.json --compact) \
  <(cd python && python3 -m agentid_py.cli --fixture ../fixtures/identity-delegation-suite.v1.json --compact)
```
