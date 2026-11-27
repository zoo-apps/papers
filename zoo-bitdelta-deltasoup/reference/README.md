# Forkable Models and Autonomous Organizations Reference (`forkable-org.v1`)

Clean-room Apache-2.0 reference implementation, versioned specification (`v1.0.0`), JSON Schema Draft 2020-12, canonical fork-diverge-exchange fixture (`9` lifecycle stages + `20` adversarial/constitutional checks), reproducible benchmark (`--seed 1352`), and dual independent zero-dependency **Go 1.24 + pure-Python 3** verifiers for **`zoo-apps/papers#5`** (HIP-1352).

Grounds and unifies two Zoo Labs Foundation companion papers:
- **BitDelta & DeltaSoup**: [`../zoo-bitdelta-deltasoup.tex`](../zoo-bitdelta-deltasoup.tex) (1-bit delta compression, safety regularization, Byzantine-robust coordinate-wise trimmed-mean DeltaSoup aggregation, and contributor royalties)
- **The Zoo DAO**: [`../../zoo-dao/zoo-dao.tex`](../../zoo-dao/zoo-dao.tex) (recursive self-forking model zoos, human-governed evolution, and open-by-default / private-by-exception access boundaries)

## Highlights

- **Zero Third-Party Dependencies**: Both Go (`go/go.mod`, stdlib only) and Python (`python/forkorg_py/`, stdlib only including clean-room pure-Python RFC 8032 Ed25519 verification) compile and run completely offline.
- **100.0% Bit-Exact Go ↔ Python Parity**: Exact 64-bit fixed-point arithmetic (`MICRO = 1_000_000`, `BPS = 10_000`) and RFC 8259 canonical JSON yield byte-identical verification reports and RFC 6962 `audit_merkle_root`:
  `d70dbc7886797d35e46004eab55ba99f5005f0032df6c12c6c7e0419eeb93e71`
- **Cryptographic Forking with Zero ACL Leak**: `ForkOrganization` branches `OrgA@snap_1` → `OrgB@snap_1_fork`, strictly stripping `restricted_pii_or_partner` and non-inheritable `org_internal` records/grants, rotating all Ed25519 authority keys, and emitting RFC 6962 `RedactionTombstone` inclusion proofs that reconstruct `OrgA@snap_1`'s exact `research_merkle_root` with zero plaintext leakage.
- **Independent Divergence & Bidirectional Verified Exchange**: `OrgA` (BitDelta specialization) and `OrgB` (10-contributor DeltaSoup under 30% Byzantine poisoning) each improve held-out accuracy from `69.00%` → `75.50%`, then exchange independently verified improvements back and forth, lifting both heads to `77.00%` (`+800 bps` over base, hinge loss `1.3021 → 0.8400`, safety `100.00%`).
- **Constitutional AI-Agent Boundaries & 19/19 Adversarial Detection**: `AI_AGENT` principals can submit non-binding advisory proposals (`POS-20`), while attempts to redefine voting rules (`ATK-12`), authorize treasury spending (`ATK-13`), or self-certify experiments (`ATK-14`)—alongside lineage forgery, ACL leaks, unrotated keys, replay, inflated receipts, regressions, safety violations, and license violations—are caught `100%` (`19/19`).

## Layout

```
zoo-bitdelta-deltasoup/reference/
├── README.md                              # Overview and quickstart
├── SPEC.md                                # Normative forkable-org.v1 (v1.0.0) spec + What Remains Unproven
├── BENCHMARK.md                           # Reproducible metrics, Byzantine honest negative regime & latencies
├── results.json                           # Deterministic machine-readable benchmark output (--seed 1352)
├── schema/
│   └── forkable-org.v1.schema.json        # JSON Schema Draft 2020-12
├── fixtures/
│   └── fork-exchange-suite.v1.json        # Canonical 9-stage workflow + 20 adversarial/constitutional checks
├── go/                                    # Zero-dependency Go 1.24 implementation, CLIs & race-tested suite
│   ├── go.mod
│   ├── forkorg/
│   └── cmd/{fork-verify,fork-bench}/
└── python/                                # Zero-dependency pure-Python 3 verifier (incl. RFC 8032 Ed25519)
    ├── forkorg_py/
    └── tests/
```

## Quick Verification

```bash
# Go format, vet, and race-tested unit/adversarial suite
(cd go && gofmt -l . && go vet ./... && go test -race -v -count=1 ./...)

# Pure-Python verifier, RFC 8032 Ed25519 vectors, and live Go↔Python parity check
(cd python && python3 -m unittest discover -s tests -v)

# Regenerate canonical fixture and results.json deterministically
(cd go && go run ./cmd/fork-bench --seed 1352)

# Verify byte-identical CLI output across Go and Python
diff -u \
  <(cd go && go run ./cmd/fork-verify --fixture ../fixtures/fork-exchange-suite.v1.json --compact) \
  <(cd python && python3 -m forkorg_py.cli --fixture ../fixtures/fork-exchange-suite.v1.json --compact)
```
