// SPDX-License-Identifier: Apache-2.0

package attrrep

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNormalizationAndWinnowingInvariants(t *testing.T) {
	base := `\section{Reputation Model}
	Non-transferable ZOO-REP tokens are issued to contributors based on verified activities:
	governance participation, grant completion, peer review, and conservation field work.`

	reformatted := "% injected comment\n\\vspace{3mm}\n\\section*{Reputation Model}\\label{sec:copy}\n" +
		"\\textbf{Non-transferable}   \\emph{ZOO-REP} tokens are issued to contributors\n" +
		"based on verified activities: % inline comment\n" +
		"governance participation, grant completion, peer review, and conservation field work.\\cite{fake2026}"

	fpA := ComputeFingerprints(base)
	fpB := ComputeFingerprints(reformatted)

	if fpA.RawSHA256 == fpB.RawSHA256 {
		t.Fatal("expected distinct raw_sha256 for reformatted LaTeX text")
	}
	if fpA.CanonicalDigest != fpB.CanonicalDigest {
		t.Fatalf("expected identical canonical_digest under LaTeX/comment reformatting: %s != %s", fpA.CanonicalDigest, fpB.CanonicalDigest)
	}
	if fpA.FingerprintDigest != fpB.FingerprintDigest {
		t.Fatalf("expected identical Winnowing fingerprint_digest: %s != %s", fpA.FingerprintDigest, fpB.FingerprintDigest)
	}
	if ov := ContainmentBps(fpA.WinnowFingerprint, fpB.WinnowFingerprint); ov != BpsScale {
		t.Fatalf("expected 10000 bps containment, got %d", ov)
	}

	unrelated := "Submersible hydrophones measure cetacean vocalizations across abyssal seamounts during winter upwelling."
	fpC := ComputeFingerprints(unrelated)
	if ov := ContainmentBps(fpA.WinnowFingerprint, fpC.WinnowFingerprint); ov != 0 {
		t.Fatalf("expected 0 bps containment against unrelated text, got %d", ov)
	}
}

func TestEd25519AndEASUIDDeterministic(t *testing.T) {
	kr := newKeyRing(1352)
	kr.add("alice", RoleResearcher, "Alice")
	kr.add("bob", RoleResearcher, "Bob")

	a, err := kr.makeAttestation(SchemaReplication, "alice", "bob", "c_1", 1, 1760000000, 1765000000, true, false, 1, 9000, "replicated", "test")
	if err != nil {
		t.Fatalf("makeAttestation: %v", err)
	}
	pubAlice := kr.identities[0].PublicKey
	if !VerifyAttestationSignature(a, pubAlice) {
		t.Fatal("valid attestation signature failed verification")
	}

	// Tampering weight must change EAS UID and invalidate signature.
	tampered := a
	tampered.WeightBps = 9999
	uid2, err := ComputeAttestationUID(tampered)
	if err != nil {
		t.Fatalf("ComputeAttestationUID: %v", err)
	}
	if uid2 == a.UID {
		t.Fatal("tampering weight_bps did not change AttestationUID")
	}
	if VerifyAttestationSignature(tampered, pubAlice) {
		t.Fatal("tampered attestation unexpectedly verified")
	}
}

func TestPublishedFixtureVerification(t *testing.T) {
	suiteBytes, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "attribution-suite.v1.json"))
	if err != nil {
		t.Fatalf("read published fixture: %v", err)
	}
	var bundle SuiteBundle
	if err := json.Unmarshal(suiteBytes, &bundle); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	report, err := VerifySuite(bundle)
	if err != nil {
		t.Fatalf("VerifySuite: %v", err)
	}

	if report.TotalContributions+report.TotalAttestations < 150 {
		t.Fatalf("expected >= 150 DAG events, got %d", report.TotalContributions+report.TotalAttestations)
	}
	if report.AdversarialTotal < 25 {
		t.Fatalf("expected >= 25 adversarial checks, got %d", report.AdversarialTotal)
	}
	if report.AdversarialPassed != report.AdversarialTotal {
		for _, ar := range report.AdversarialResults {
			if !ar.Passed {
				t.Errorf("adversarial %s (%s) failed: want %s/%s got %s/%s",
					ar.AttackID, ar.TargetID, ar.ExpectedStatus, ar.ExpectedErrCode, ar.ActualStatus, ar.ActualErrCode)
			}
		}
		t.Fatalf("adversarial checks passed %d/%d", report.AdversarialPassed, report.AdversarialTotal)
	}
	if !report.ConservationExact {
		t.Fatalf("credit conservation violated: intrinsic=%d != attributed=%d", report.TotalIntrinsicMicro, report.TotalAttributedMicro)
	}
	if len(report.CollusionFindings) < 3 {
		t.Fatalf("expected >= 3 collusion findings (2-node, 5-node, 20-Sybil), got %d", len(report.CollusionFindings))
	}

	// Verify audit_merkle_root matches committed results.json.
	resBytes, err := os.ReadFile(filepath.Join("..", "..", "results.json"))
	if err != nil {
		t.Fatalf("read results.json: %v", err)
	}
	var res BenchmarkResults
	if err := json.Unmarshal(resBytes, &res); err != nil {
		t.Fatalf("unmarshal results.json: %v", err)
	}
	if report.AuditMerkleRoot != res.AuditMerkleRoot {
		t.Fatalf("audit_merkle_root mismatch vs results.json: %s != %s", report.AuditMerkleRoot, res.AuditMerkleRoot)
	}
}

func TestAllThreeNegativeRegimes(t *testing.T) {
	manifest, papers, err := LoadCorpus(filepath.Join("..", "..", "..", ".."), 1352)
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	bundle, err := BuildPublishedSuite(manifest, papers, 1352)
	if err != nil {
		t.Fatalf("BuildPublishedSuite: %v", err)
	}
	results, _, err := RunBenchmark(manifest, papers, bundle, 1352)
	if err != nil {
		t.Fatalf("RunBenchmark: %v", err)
	}
	if len(results.NegativeRegimes) != 3 {
		t.Fatalf("expected 3 negative regimes, got %d", len(results.NegativeRegimes))
	}
	for _, nr := range results.NegativeRegimes {
		if !nr.Passed {
			t.Errorf("negative regime %s failed: %s", nr.RegimeID, nr.Summary)
		}
	}
}

func TestIssuerRateLimitEnforcement(t *testing.T) {
	kr := newKeyRing(999)
	kr.add("seed_1", RoleSeed, "Seed")
	kr.add("author_1", RoleResearcher, "Author 1")
	kr.add("author_2", RoleResearcher, "Author 2")
	kr.add("author_3", RoleResearcher, "Author 3")

	c1, _ := kr.makeContribution("c1", 1, 1, 1760000100, "author_1", "research", "", "Unique marine acoustics study one measuring baleen whale song periodicity across deep ocean ridges.", nil, BpsScale, "")
	c2, _ := kr.makeContribution("c2", 2, 1, 1760000200, "author_2", "research", "", "Unique alpine glacier hydrology study two modeling meltwater conductivity beneath moraine ice fields.", nil, BpsScale, "")
	c3, _ := kr.makeContribution("c3", 3, 1, 1760000300, "author_3", "research", "", "Unique savanna pollinator network study three quantifying nocturnal hawkmoth floral visitation.", nil, BpsScale, "")

	a1, _ := kr.makeAttestation(SchemaPeerReview, "seed_1", "author_1", "c1", 1, 1760000400, 0, true, false, 1, 9000, "n1", "")
	a2, _ := kr.makeAttestation(SchemaPeerReview, "seed_1", "author_2", "c2", 1, 1760000500, 0, true, false, 2, 9000, "n2", "")
	a3, _ := kr.makeAttestation(SchemaPeerReview, "seed_1", "author_3", "c3", 1, 1760000600, 0, true, false, 3, 9000, "n3", "")

	pol := DefaultPolicy()
	pol.MaxAttestationsPerEpoch = 2

	bundle := SuiteBundle{
		SchemaVersion: SchemaVersion,
		SpecVersion:   SpecVersion,
		SuiteName:     "rate-limit-test",
		Seed:          999,
		EvalTime:      1760001000,
		Policy:        pol,
		Identities:    kr.identities,
		Contributions: []Contribution{c1, c2, c3},
		Attestations:  []Attestation{a1, a2, a3},
	}
	rep, err := VerifySuite(bundle)
	if err != nil {
		t.Fatalf("VerifySuite: %v", err)
	}
	if rep.AcceptedAttestations != 2 || rep.RejectedAttestations != 1 {
		t.Fatalf("expected 2 accepted, 1 rejected; got %d/%d", rep.AcceptedAttestations, rep.RejectedAttestations)
	}
	if rep.AttestationVerdicts[2].ErrorCode != ErrIssuerRateLimit {
		t.Fatalf("expected %s, got %s", ErrIssuerRateLimit, rep.AttestationVerdicts[2].ErrorCode)
	}
}

func TestDeterminismUnderOrderPermutation(t *testing.T) {
	suiteBytes, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "attribution-suite.v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var orig SuiteBundle
	if err := json.Unmarshal(suiteBytes, &orig); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	baseRep, err := VerifySuite(orig)
	if err != nil {
		t.Fatalf("VerifySuite orig: %v", err)
	}

	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 3; trial++ {
		perm := orig
		perm.Identities = append([]Identity(nil), orig.Identities...)
		perm.Contributions = append([]Contribution(nil), orig.Contributions...)
		perm.Attestations = append([]Attestation(nil), orig.Attestations...)

		rng.Shuffle(len(perm.Identities), func(i, j int) { perm.Identities[i], perm.Identities[j] = perm.Identities[j], perm.Identities[i] })
		rng.Shuffle(len(perm.Contributions), func(i, j int) { perm.Contributions[i], perm.Contributions[j] = perm.Contributions[j], perm.Contributions[i] })
		rng.Shuffle(len(perm.Attestations), func(i, j int) { perm.Attestations[i], perm.Attestations[j] = perm.Attestations[j], perm.Attestations[i] })

		rep, err := VerifySuite(perm)
		if err != nil {
			t.Fatalf("VerifySuite trial %d: %v", trial, err)
		}
		if rep.AuditMerkleRoot != baseRep.AuditMerkleRoot {
			t.Fatalf("trial %d audit_merkle_root drifted under permutation: %s != %s", trial, rep.AuditMerkleRoot, baseRep.AuditMerkleRoot)
		}
	}
}

func TestCorpusManifestPinsRealPapers(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "corpus-manifest.json"))
	if err != nil {
		t.Fatalf("read corpus-manifest.json: %v", err)
	}
	var committed CorpusManifest
	if err := json.Unmarshal(raw, &committed); err != nil {
		t.Fatalf("unmarshal corpus-manifest.json: %v", err)
	}
	recomputed, _, err := LoadCorpus(filepath.Join("..", "..", "..", ".."), committed.Seed)
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	if committed.ManifestHash != recomputed.ManifestHash {
		t.Fatalf("corpus manifest_sha256 mismatch: %s != %s", committed.ManifestHash, recomputed.ManifestHash)
	}
	for _, p := range committed.Papers {
		if filepath.IsAbs(p.RelPath) || strings.Contains(p.RelPath, "..") {
			t.Fatalf("illegal non-relative corpus path: %s", p.RelPath)
		}
	}
}

func TestConcurrentVerificationRaceSafety(t *testing.T) {
	suiteBytes, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "attribution-suite.v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var bundle SuiteBundle
	if err := json.Unmarshal(suiteBytes, &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	const workers = 8
	roots := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(idx int) {
			defer wg.Done()
			rep, err := VerifySuite(bundle)
			if err != nil {
				errs[idx] = err
				return
			}
			roots[idx] = rep.AuditMerkleRoot
		}(w)
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d failed: %v", i, errs[i])
		}
		if roots[i] != roots[0] {
			t.Fatalf("worker %d root mismatch: %s != %s", i, roots[i], roots[0])
		}
	}
	if len(roots[0]) != 64 {
		t.Fatalf("unexpected merkle root length: %s", fmt.Sprintf("%q", roots[0]))
	}
}
