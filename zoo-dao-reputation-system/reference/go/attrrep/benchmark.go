// SPDX-License-Identifier: Apache-2.0

package attrrep

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CorpusPaperSpec defines one real .tex paper in zoo-apps/papers.
type CorpusPaperSpec struct {
	RelPath  string `json:"rel_path"`
	Title    string `json:"title"`
	Category string `json:"category"`
}

// CorpusPaperEntry pins cryptographic digests of a real repository .tex paper.
type CorpusPaperEntry struct {
	RelPath           string `json:"rel_path"`
	Title             string `json:"title"`
	Category          string `json:"category"`
	Bytes             int    `json:"bytes"`
	SHA256            string `json:"sha256"`
	NormalizedTokens  int    `json:"normalized_tokens"`
	CanonicalDigest   string `json:"canonical_digest"`
	FingerprintDigest string `json:"fingerprint_digest"`
}

// CorpusManifest is written to corpus-manifest.json (zero local machine paths).
type CorpusManifest struct {
	SchemaVersion string             `json:"schema_version"`
	SpecVersion   string             `json:"spec_version"`
	Seed          int64              `json:"seed"`
	PaperCount    int                `json:"paper_count"`
	ManifestHash  string             `json:"manifest_sha256"`
	Papers        []CorpusPaperEntry `json:"papers"`
}

// NegativeRegimeResult records quantitative outcomes for an honest negative regime.
type NegativeRegimeResult struct {
	RegimeID    string         `json:"regime_id"`
	Title       string         `json:"title"`
	Passed      bool           `json:"passed"`
	Summary     string         `json:"summary"`
	Metrics     map[string]any `json:"metrics"`
}

// BenchmarkResults is written to results.json.
type BenchmarkResults struct {
	SchemaVersion          string                 `json:"schema_version"`
	SpecVersion            string                 `json:"spec_version"`
	Seed                   int64                  `json:"seed"`
	CorpusManifestSHA256   string                 `json:"corpus_manifest_sha256"`
	SuiteName              string                 `json:"suite_name"`
	AuditMerkleRoot        string                 `json:"audit_merkle_root"`
	TotalDAGItems          int                    `json:"total_dag_items"`
	TotalContributions     int                    `json:"total_contributions"`
	AcceptedContributions  int                    `json:"accepted_contributions"`
	RejectedContributions  int                    `json:"rejected_contributions"`
	TotalAttestations      int                    `json:"total_attestations"`
	AcceptedAttestations   int                    `json:"accepted_attestations"`
	AdvisoryAttestations   int                    `json:"advisory_attestations"`
	RejectedAttestations   int                    `json:"rejected_attestations"`
	AdversarialPassed      int                    `json:"adversarial_passed"`
	AdversarialTotal       int                    `json:"adversarial_total"`
	ConservationExact      bool                   `json:"conservation_exact"`
	TotalIntrinsicMicro    int64                  `json:"total_intrinsic_micro"`
	TotalAttributedMicro   int64                  `json:"total_attributed_micro"`
	TotalNaiveAttrMicro    int64                  `json:"total_naive_attributed_micro"`
	CollusionFindingsCount int                    `json:"collusion_findings_count"`
	TopGenuineResearcher   IdentitySummary        `json:"top_genuine_researcher"`
	SybilBossSummary       IdentitySummary        `json:"sybil_boss_summary"`
	NegativeRegimes        []NegativeRegimeResult `json:"negative_regimes"`
	TopRankings            []IdentitySummary      `json:"top_rankings"`
	AdversarialResults     []AdversarialCheckResult `json:"adversarial_results"`
}

// DefaultCorpusPapers returns the 12 real zoo-apps/papers .tex sources.
func DefaultCorpusPapers() []CorpusPaperSpec {
	return []CorpusPaperSpec{
		{RelPath: "zoo-dao-reputation-system/zoo-dao-reputation-system.tex", Title: "Ecosystem Reputation: A Non-Transferable Trust Primitive for Conservation Contributors", Category: "governance"},
		{RelPath: "zoo-dao-research-governance/zoo-dao-research-governance.tex", Title: "Zoo DAO Research Governance", Category: "governance"},
		{RelPath: "zoo-desci-platform/zoo-desci-platform.tex", Title: "Zoo DeSci Platform", Category: "research"},
		{RelPath: "zoo-data-commons/zoo-data-commons.tex", Title: "Zoo Data Commons", Category: "research"},
		{RelPath: "zoo-research-coordination/zoo-research-coordination.tex", Title: "Zoo Research Coordination", Category: "grants"},
		{RelPath: "zoo-citizen-science/zoo-citizen-science.tex", Title: "Zoo Citizen Science", Category: "field_work"},
		{RelPath: "zoo-conservation-ai/zoo-conservation-ai.tex", Title: "Zoo Conservation AI", Category: "code"},
		{RelPath: "zoo-federated-wildlife/zoo-federated-wildlife.tex", Title: "Zoo Federated Wildlife", Category: "code"},
		{RelPath: "zoo-habitat-modeling/zoo-habitat-modeling.tex", Title: "Zoo Habitat Modeling", Category: "field_work"},
		{RelPath: "zoo-satellite-ecology/zoo-satellite-ecology.tex", Title: "Zoo Satellite Ecology", Category: "field_work"},
		{RelPath: "zoo-species-classification/zoo-species-classification.tex", Title: "Zoo Species Classification", Category: "research"},
		{RelPath: "zoo-wildlife-tracking/zoo-wildlife-tracking.tex", Title: "Zoo Wildlife Tracking", Category: "field_work"},
	}
}

// LoadedPaper holds the raw text and extracted prose segments of a real .tex paper.
type LoadedPaper struct {
	Entry    CorpusPaperEntry
	RawText  string
	Segments []string
}

// LoadCorpus reads the 12 real .tex papers from repoRoot and builds CorpusManifest.
func LoadCorpus(repoRoot string, seed int64) (CorpusManifest, []LoadedPaper, error) {
	specs := DefaultCorpusPapers()
	entries := make([]CorpusPaperEntry, 0, len(specs))
	loaded := make([]LoadedPaper, 0, len(specs))

	for _, sp := range specs {
		fullPath := filepath.Join(repoRoot, filepath.FromSlash(sp.RelPath))
		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			return CorpusManifest{}, nil, fmt.Errorf("read corpus paper %s: %w", sp.RelPath, err)
		}
		raw := string(rawBytes)
		fp := ComputeFingerprints(raw)
		entry := CorpusPaperEntry{
			RelPath:           sp.RelPath,
			Title:             sp.Title,
			Category:          sp.Category,
			Bytes:             len(rawBytes),
			SHA256:            fp.RawSHA256,
			NormalizedTokens:  fp.TokenCount,
			CanonicalDigest:   fp.CanonicalDigest,
			FingerprintDigest: fp.FingerprintDigest,
		}
		entries = append(entries, entry)
		segs := extractDistinctSegments(raw, sp.Title)
		loaded = append(loaded, LoadedPaper{
			Entry:    entry,
			RawText:  raw,
			Segments: segs,
		})
	}

	cj, err := CanonicalJSON(entries)
	if err != nil {
		return CorpusManifest{}, nil, err
	}
	manifest := CorpusManifest{
		SchemaVersion: SchemaVersion,
		SpecVersion:   SpecVersion,
		Seed:          seed,
		PaperCount:    len(entries),
		ManifestHash:  SHA256Hex(cj),
		Papers:        entries,
	}
	return manifest, loaded, nil
}

// extractDistinctSegments splits a real .tex document body into 2 non-overlapping
// substantial scientific prose segments (~120-260 words each).
func extractDistinctSegments(raw, title string) []string {
	body := raw
	if idx := strings.Index(body, `\begin{abstract}`); idx >= 0 {
		body = body[idx:]
	} else if idx := strings.Index(body, `\begin{document}`); idx >= 0 {
		body = body[idx:]
	}
	if idx := strings.Index(body, `\begin{thebibliography}`); idx >= 0 {
		body = body[:idx]
	}

	// Split by blank lines into clean paragraphs, keeping prose-rich blocks.
	rawBlocks := strings.Split(body, "\n\n")
	var prose []string
	for _, blk := range rawBlocks {
		t := strings.TrimSpace(blk)
		if len(t) < 60 {
			continue
		}
		if strings.HasPrefix(t, `\documentclass`) || strings.HasPrefix(t, `\usepackage`) || strings.HasPrefix(t, `\tableofcontents`) {
			continue
		}
		prose = append(prose, t)
	}
	if len(prose) < 2 {
		half := len(body) / 2
		return []string{strings.TrimSpace(body[:half]), strings.TrimSpace(body[half:])}
	}

	// Partition paragraphs into two disjoint halves of roughly equal word mass.
	mid := len(prose) / 2
	segA := strings.Join(prose[:mid], "\n\n")
	segB := strings.Join(prose[mid:], "\n\n")

	// Bound segment lengths to keep fixture compact (~1200-1800 chars each) while preserving real LaTeX prose.
	segA = truncateWords(segA, 180)
	segB = truncateWords(segB, 180)
	if len(NormalizeScientificText(segA)) < 30 {
		segA = title + ": " + segA
	}
	if len(NormalizeScientificText(segB)) < 30 {
		segB = title + " empirical methodology: " + segB
	}
	return []string{segA, segB}
}

func truncateWords(s string, maxWords int) string {
	fields := strings.Fields(s)
	if len(fields) <= maxWords {
		return s
	}
	return strings.Join(fields[:maxWords], " ")
}

type keyRing struct {
	seed       int64
	identities []Identity
	privs      map[string]ed25519.PrivateKey
}

func newKeyRing(seed int64) *keyRing {
	return &keyRing{
		seed:  seed,
		privs: make(map[string]ed25519.PrivateKey),
	}
}

func (kr *keyRing) add(id, role, label string) {
	pub, priv := DeriveEd25519Key(kr.seed, id)
	kr.identities = append(kr.identities, Identity{
		ID:        id,
		Role:      role,
		PublicKey: hex.EncodeToString(pub),
		Label:     label,
	})
	kr.privs[id] = priv
}

func (kr *keyRing) makeContribution(
	id string,
	seq int64,
	epoch int64,
	ts int64,
	authorID string,
	category string,
	corpusSource string,
	content string,
	parents []string,
	claimedNoveltyBps int64,
	tag string,
) (Contribution, error) {
	fp := ComputeFingerprints(content)
	pCopy := make([]string, len(parents))
	copy(pCopy, parents)
	sort.Strings(pCopy)
	c := Contribution{
		ContributionID:    id,
		LedgerSeq:         seq,
		Epoch:             epoch,
		Timestamp:         ts,
		AuthorID:          authorID,
		Category:          category,
		CorpusSource:      corpusSource,
		Content:           content,
		RawSHA256:         fp.RawSHA256,
		CanonicalDigest:   fp.CanonicalDigest,
		WinnowFingerprint: fp.WinnowFingerprint,
		FingerprintDigest: fp.FingerprintDigest,
		Parents:           pCopy,
		ClaimedNoveltyBps: claimedNoveltyBps,
		BaseValueMicro:    MicroScale,
		ScenarioTag:       tag,
	}
	if err := SignContribution(&c, kr.privs[authorID]); err != nil {
		return Contribution{}, err
	}
	return c, nil
}

func (kr *keyRing) makeAttestation(
	schemaUID string,
	attester string,
	recipient string,
	refUID string,
	epoch int64,
	ts int64,
	expTime int64,
	revocable bool,
	revoked bool,
	nonce int64,
	weightBps int64,
	note string,
	tag string,
) (Attestation, error) {
	a := Attestation{
		SchemaUID:      schemaUID,
		Attester:       attester,
		Recipient:      recipient,
		RefUID:         refUID,
		Epoch:          epoch,
		Time:           ts,
		ExpirationTime: expTime,
		Revocable:      revocable,
		Revoked:        revoked,
		Nonce:          nonce,
		WeightBps:      weightBps,
		DataDigest:     SHA256Hex([]byte(note)),
		ScenarioTag:    tag,
	}
	if err := SignAttestation(&a, kr.privs[attester]); err != nil {
		return Attestation{}, err
	}
	return a, nil
}

// BuildPublishedSuite generates the canonical attribution-suite.v1.json bundle
// grounded in the 12 real .tex papers with >= 150 DAG events and >= 25 adversarial attacks.
func BuildPublishedSuite(manifest CorpusManifest, papers []LoadedPaper, seed int64) (SuiteBundle, error) {
	kr := newKeyRing(seed)

	// 4 trusted seed stewards.
	for i := 1; i <= 4; i++ {
		kr.add(fmt.Sprintf("seed_%02d", i), RoleSeed, fmt.Sprintf("Zoo Founding Steward %02d", i))
	}
	// 12 honest scientific researchers.
	for i := 1; i <= 12; i++ {
		kr.add(fmt.Sprintf("res_%02d", i), RoleResearcher, fmt.Sprintf("Conservation Researcher %02d", i))
	}
	// 1 honest newcomer (zero initial seed edges; tests cold-start regime).
	kr.add("newcomer_honest", RoleResearcher, "Honest Newcomer Researcher")
	kr.add("newcomer_peer", RoleResearcher, "Unseeded Newcomer Collaborator")
	// 1 AI reviewer agent (advisory only; constitutionally bounded).
	kr.add("ai_reviewer_01", RoleAIAgent, "Automated Similarity Screening Agent")
	// 1 Sybil boss + 20 Sybil farm accounts (zero external trust edges).
	kr.add("mallory_sybil_boss", RoleResearcher, "Colluding Sybil Boss")
	for i := 1; i <= 20; i++ {
		kr.add(fmt.Sprintf("sybil_%02d", i), RoleResearcher, fmt.Sprintf("Sybil Farm Account %02d", i))
	}
	// 2-node mutual-admiration pair (zero external trust).
	kr.add("pair_a", RoleResearcher, "Mutual-Admiration Node A")
	kr.add("pair_b", RoleResearcher, "Mutual-Admiration Node B")
	// 5-node endorsement ring (zero external trust).
	for i := 1; i <= 5; i++ {
		kr.add(fmt.Sprintf("ring_%02d", i), RoleResearcher, fmt.Sprintf("Endorsement Ring Node %02d", i))
	}
	// 4 copycat / DAG attacker identities.
	kr.add("plagiarist_exact", RoleResearcher, "Exact-Copy Plagiarist")
	kr.add("plagiarist_reformat", RoleResearcher, "LaTeX-Reformat Plagiarist")
	kr.add("plagiarist_patch", RoleResearcher, "Patch-Plagiarism Attacker")
	kr.add("attacker_dag", RoleResearcher, "Causality & Crypto Attacker")

	const baseTS int64 = 1760000000
	const evalTime int64 = baseTS + 86400*40

	var contribs []Contribution
	var atts []Attestation
	var revokedUIDs []string
	var expectations []AdversarialExpectation

	var seq int64 = 1
	ts := baseTS
	nonceMap := make(map[string]int64)
	nextNonce := func(attester string) int64 {
		nonceMap[attester]++
		return nonceMap[attester]
	}

	// 1. 24 foundational contributions extracted directly from the 12 real .tex papers (2 disjoint segments each).
	foundationalIDs := make([]string, 0, 24)
	foundationalAuthors := make(map[string]string)
	foundationalTexts := make(map[string]string)

	for pIdx, lp := range papers {
		for sIdx, seg := range lp.Segments {
			cid := fmt.Sprintf("contrib_base_%02d_%d", pIdx+1, sIdx+1)
			author := fmt.Sprintf("res_%02d", (pIdx%12)+1)
			if sIdx == 1 && pIdx < 4 {
				author = fmt.Sprintf("seed_%02d", pIdx+1)
			}
			ts += 600
			c, err := kr.makeContribution(cid, seq, 1, ts, author, lp.Entry.Category, lp.Entry.RelPath, seg, nil, BpsScale, "honest_foundational")
			if err != nil {
				return SuiteBundle{}, err
			}
			contribs = append(contribs, c)
			foundationalIDs = append(foundationalIDs, cid)
			foundationalAuthors[cid] = author
			foundationalTexts[cid] = seg
			seq++
		}
	}

	// 2. 16 genuine novel derivative extensions citing 1..2 foundational parents
	//    (sharing ~25% background context + 75% genuinely novel experimental & formal prose).
	derivativeIDs := make([]string, 0, 16)
	derivativeAuthors := make(map[string]string)
	for i := 0; i < 16; i++ {
		p1 := foundationalIDs[i%len(foundationalIDs)]
		p2 := foundationalIDs[(i+5)%len(foundationalIDs)]
		parents := []string{p1}
		if i%2 == 0 {
			parents = append(parents, p2)
		}
		author := fmt.Sprintf("res_%02d", ((i+3)%12)+1)
		if author == foundationalAuthors[p1] {
			author = fmt.Sprintf("res_%02d", ((i+4)%12)+1)
		}

		// Take ~35 words of shared context from parent p1, plus ~140 completely novel domain-specific words.
		sharedLead := truncateWords(foundationalTexts[p1], 32)
		novelBody := buildNovelExtensionText(i+1, p1, p2, papers[i%len(papers)].Entry.Title)
		fullText := sharedLead + "\n\n" + novelBody

		cid := fmt.Sprintf("contrib_ext_%02d", i+1)
		ts += 600
		c, err := kr.makeContribution(cid, seq, 2, ts, author, papers[i%len(papers)].Entry.Category, papers[i%len(papers)].Entry.RelPath, fullText, parents, 7500, "honest_derivative")
		if err != nil {
			return SuiteBundle{}, err
		}
		contribs = append(contribs, c)
		derivativeIDs = append(derivativeIDs, cid)
		derivativeAuthors[cid] = author
		seq++
	}

	// 3. Genuine distinct contributions for special protocol actors:
	//    honest newcomer, AI agent draft, Sybil boss, 2-node pair, 5-node ring.
	specialSpecs := []struct {
		cid    string
		author string
		cat    string
		tag    string
		topic  string
	}{
		{"contrib_newcomer_01", "newcomer_honest", "field_work", "honest_newcomer", "acoustic hydrophone transect calibration across coastal estuary coral reefs"},
		{"contrib_ai_01", "ai_reviewer_01", "code", "ai_authored", "automated shingle index verification latency measurements on streaming archives"},
		{"contrib_sybil_boss_01", "mallory_sybil_boss", "research", "sybil_target_paper", "synthetic baseline benchmark on telemetry packet compression for savanna collars"},
		{"contrib_pair_a", "pair_a", "research", "ring_2node_paper", "preliminary bathymetric sonar drift notes for temperate fjord surveys"},
		{"contrib_pair_b", "pair_b", "research", "ring_2node_paper", "preliminary lidar canopy density notes for alpine watershed transects"},
		{"contrib_ring_01", "ring_01", "research", "ring_5node_paper", "isolated survey memorandum alpha on boreal lichen microclimate gradients"},
		{"contrib_ring_02", "ring_02", "research", "ring_5node_paper", "isolated survey memorandum beta on mangrove root salinity transects"},
		{"contrib_ring_03", "ring_03", "research", "ring_5node_paper", "isolated survey memorandum gamma on steppe rodent burrow thermography"},
		{"contrib_ring_04", "ring_04", "research", "ring_5node_paper", "isolated survey memorandum delta on montane amphibian acoustic phenology"},
		{"contrib_ring_05", "ring_05", "research", "ring_5node_paper", "isolated survey memorandum epsilon on pelagic seabird foraging telemetry"},
	}
	for idx, sp := range specialSpecs {
		text := buildDistinctSpecialText(idx+1, sp.cid, sp.topic)
		ts += 600
		c, err := kr.makeContribution(sp.cid, seq, 2, ts, sp.author, sp.cat, "", text, nil, BpsScale, sp.tag)
		if err != nil {
			return SuiteBundle{}, err
		}
		contribs = append(contribs, c)
		seq++
	}

	// 4. Explicit Adversarial Contribution Attacks (15 distinct vectors).
	// (a) Exact verbatim copies (x2).
	ts += 600
	exactCopy1, err := kr.makeContribution("atk_copy_exact_01", seq, 3, ts, "plagiarist_exact", "governance", "", foundationalTexts["contrib_base_01_1"], nil, BpsScale, "atk_copy_exact_01")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, exactCopy1)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-01", Category: "copy", TargetType: "contribution", TargetID: "atk_copy_exact_01",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrDuplicateContribution,
		Description: "Exact verbatim copy of Zoo DAO Reputation paper under new identity",
	})
	seq++

	ts += 600
	exactCopy2, err := kr.makeContribution("atk_copy_exact_02", seq, 3, ts, "plagiarist_exact", "research", "", foundationalTexts["contrib_base_03_1"], nil, BpsScale, "atk_copy_exact_02")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, exactCopy2)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-02", Category: "copy", TargetType: "contribution", TargetID: "atk_copy_exact_02",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrDuplicateContribution,
		Description: "Exact verbatim copy of Zoo DeSci Platform paper under new identity",
	})
	seq++

	// (b) Whitespace / comment / LaTeX-macro reformatted copies (x2).
	ts += 600
	reformatted1 := "% Plagiarist header comment injected\n\\vspace{4mm}\n" +
		strings.ReplaceAll(foundationalTexts["contrib_base_02_1"], " ", "   ") +
		"\n% Trailing comment with \\label{sec:fake_reformat} and \\cite{fake2026}\n"
	refCopy1, err := kr.makeContribution("atk_copy_reformat_01", seq, 3, ts, "plagiarist_reformat", "governance", "", reformatted1, nil, BpsScale, "atk_copy_reformat_01")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, refCopy1)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-03", Category: "copy", TargetType: "contribution", TargetID: "atk_copy_reformat_01",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrReformattedCopy,
		Description: "Whitespace, comment, and LaTeX-macro reformatted copy of Zoo Research Governance paper",
	})
	seq++

	ts += 600
	reformatted2 := "\\vspace{6pt}\\label{sec:spoof}\n" +
		"\\emph{\\textbf{" + strings.ReplaceAll(foundationalTexts["contrib_base_04_1"], "\n", "\n% reformat comment\n") + "}}\n% synthetic comment line\n\\hspace{2pt}\\cite{fake2026}"
	refCopy2, err := kr.makeContribution("atk_copy_reformat_02", seq, 3, ts, "plagiarist_reformat", "research", "", reformatted2, nil, BpsScale, "atk_copy_reformat_02")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, refCopy2)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-04", Category: "copy", TargetType: "contribution", TargetID: "atk_copy_reformat_02",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrReformattedCopy,
		Description: "LaTeX wrapper and comment reformatted copy of Zoo Data Commons paper",
	})
	seq++

	// (c) 85%-copied patch-plagiarism papers claiming 100% credit (x2).
	ts += 600
	patch85Text1 := foundationalTexts["contrib_base_01_2"] + "\n\nBrief concluding remark added claiming full original authorship."
	patchCopy1, err := kr.makeContribution("atk_copy_patch_85_01", seq, 3, ts, "plagiarist_patch", "governance", "", patch85Text1, nil, BpsScale, "atk_copy_patch_85_01")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, patchCopy1)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-05", Category: "copy", TargetType: "contribution", TargetID: "atk_copy_patch_85_01",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrNearDuplicateCopy,
		Description: "85%-copied patch-plagiarism paper claiming 100% credit without attribution",
	})
	seq++

	ts += 600
	patch85Text2 := foundationalTexts["contrib_base_06_1"] + "\n\nShort cosmetic epilogue inserted while retaining nearly verbatim source body."
	patchCopy2, err := kr.makeContribution("atk_copy_patch_85_02", seq, 3, ts, "plagiarist_patch", "field_work", "", patch85Text2, []string{"contrib_base_06_1"}, BpsScale, "atk_copy_patch_85_02")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, patchCopy2)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-06", Category: "copy", TargetType: "contribution", TargetID: "atk_copy_patch_85_02",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrNearDuplicateCopy,
		Description: "85%-copied patch-plagiarism paper citing parent yet still exceeding copy ceiling and overclaiming 100% novelty",
	})
	seq++

	// (d) 65%-copied undeclared copy omitting parent citation (60%-75% overlap, no parent edge).
	ts += 600
	baseWords7 := strings.Fields(foundationalTexts["contrib_base_07_1"])
	keep7 := (len(baseWords7) * 70) / 100
	if keep7 < 30 {
		keep7 = len(baseWords7)
	}
	undeclaredText := strings.Join(baseWords7[:keep7], " ") + "\n\n" +
		"Additional wrapper commentary discussing sensor deployment schedules, alpine weather stations, thermal battery endurance, " +
		"archival compression pipelines, lithium cell degradation curves, solar panel irradiance budgets, antenna gain calibration, " +
		"ruggedized aluminum enclosure sealing, snowpack attenuation tolerances, and remote maintenance logistics without citing the canonical upstream work."
	undeclaredCopy, err := kr.makeContribution("atk_copy_undeclared_65", seq, 3, ts, "plagiarist_patch", "code", "", undeclaredText, nil, 7000, "atk_copy_undeclared_65")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, undeclaredCopy)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-07", Category: "copy", TargetType: "contribution", TargetID: "atk_copy_undeclared_65",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrUndeclaredCopy,
		Description: "Undeclared 60%-75% near-duplicate copy omitting canonical upstream parent edge",
	})
	seq++

	// (e) Causality cycles in DAG: 2-node cycle (A cites B, B cites A) + self-cycle (C cites C).
	ts += 600
	cycA, err := kr.makeContribution("atk_dag_cycle_a", seq, 3, ts, "attacker_dag", "research", "",
		buildDistinctSpecialText(101, "atk_dag_cycle_a", "circular dependency experiment alpha referencing unreleased future node beta"),
		[]string{"atk_dag_cycle_b"}, BpsScale, "atk_dag_cycle_a")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, cycA)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-08", Category: "causality", TargetType: "contribution", TargetID: "atk_dag_cycle_a",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrCausalityCycle,
		Description: "Causality cycle node A citing B while B cites A",
	})
	seq++

	ts += 600
	cycB, err := kr.makeContribution("atk_dag_cycle_b", seq, 3, ts, "attacker_dag", "research", "",
		buildDistinctSpecialText(102, "atk_dag_cycle_b", "circular dependency experiment beta referencing simultaneous cycle node alpha"),
		[]string{"atk_dag_cycle_a"}, BpsScale, "atk_dag_cycle_b")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, cycB)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-09", Category: "causality", TargetType: "contribution", TargetID: "atk_dag_cycle_b",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrCausalityCycle,
		Description: "Causality cycle node B citing A while A cites B",
	})
	seq++

	ts += 600
	selfCyc, err := kr.makeContribution("atk_dag_self_cycle", seq, 3, ts, "attacker_dag", "research", "",
		buildDistinctSpecialText(103, "atk_dag_self_cycle", "reflexive self-citation DAG edge attempting recursive credit amplification"),
		[]string{"atk_dag_self_cycle"}, BpsScale, "atk_dag_self_cycle")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, selfCyc)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-10", Category: "causality", TargetType: "contribution", TargetID: "atk_dag_self_cycle",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrCausalityCycle,
		Description: "Self-referencing DAG parent edge (C cites C)",
	})
	seq++

	// (f) Timestamp backdating attacks (backdated before ledger tip & backdated before parent).
	backdate1, err := kr.makeContribution("atk_dag_backdate_ledger", seq, 3, baseTS-7200, "attacker_dag", "research", "",
		buildDistinctSpecialText(104, "atk_dag_backdate_ledger", "backdated manuscript attempting to predate earlier committed research artifacts"),
		nil, BpsScale, "atk_dag_backdate_ledger")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, backdate1)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-11", Category: "causality", TargetType: "contribution", TargetID: "atk_dag_backdate_ledger",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrTimestampBackdate,
		Description: "Timestamp backdated earlier than committed append-only ledger tip",
	})
	seq++

	backdate2, err := kr.makeContribution("atk_dag_backdate_parent", seq, 3, baseTS+100, "attacker_dag", "research", "",
		buildDistinctSpecialText(105, "atk_dag_backdate_parent", "derivative manuscript backdated earlier than its declared canonical parent"),
		[]string{"contrib_base_05_1"}, BpsScale, "atk_dag_backdate_parent")
	if err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, backdate2)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-12", Category: "causality", TargetType: "contribution", TargetID: "atk_dag_backdate_parent",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrTimestampBackdate,
		Description: "Contribution timestamp earlier than cited parent contribution",
	})
	seq++

	// (g) Cryptographic forgery & digest tampering attacks on contributions (x3).
	ts += 600
	forgedContrib, err := kr.makeContribution("atk_crypto_forged_contrib_sig", seq, 3, ts, "attacker_dag", "code", "",
		buildDistinctSpecialText(106, "atk_crypto_forged_contrib_sig", "contribution carrying corrupted Ed25519 signature bytes"),
		nil, BpsScale, "atk_crypto_forged_contrib_sig")
	if err != nil {
		return SuiteBundle{}, err
	}
	forgedContrib.SignatureHex = flipFirstHexByte(forgedContrib.SignatureHex)
	contribs = append(contribs, forgedContrib)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-13", Category: "crypto", TargetType: "contribution", TargetID: "atk_crypto_forged_contrib_sig",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrInvalidSignature,
		Description: "Forged RFC 8032 Ed25519 signature on scientific contribution",
	})
	seq++

	ts += 600
	tamperedDigest, err := kr.makeContribution("atk_crypto_digest_tamper", seq, 3, ts, "attacker_dag", "code", "",
		buildDistinctSpecialText(107, "atk_crypto_digest_tamper", "contribution claiming mismatched canonical SHA-256 content digest"),
		nil, BpsScale, "atk_crypto_digest_tamper")
	if err != nil {
		return SuiteBundle{}, err
	}
	tamperedDigest.CanonicalDigest = flipFirstHexByte(tamperedDigest.CanonicalDigest)
	if err := SignContribution(&tamperedDigest, kr.privs["attacker_dag"]); err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, tamperedDigest)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-14", Category: "crypto", TargetType: "contribution", TargetID: "atk_crypto_digest_tamper",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrContentDigestMismatch,
		Description: "Signed contribution with tampered canonical_digest vs content bytes",
	})
	seq++

	ts += 600
	tamperedFP, err := kr.makeContribution("atk_crypto_fp_tamper", seq, 3, ts, "attacker_dag", "code", "",
		buildDistinctSpecialText(108, "atk_crypto_fp_tamper", "contribution claiming forged Winnowing fingerprint digest to evade copy detection"),
		nil, BpsScale, "atk_crypto_fp_tamper")
	if err != nil {
		return SuiteBundle{}, err
	}
	tamperedFP.FingerprintDigest = flipFirstHexByte(tamperedFP.FingerprintDigest)
	if err := SignContribution(&tamperedFP, kr.privs["attacker_dag"]); err != nil {
		return SuiteBundle{}, err
	}
	contribs = append(contribs, tamperedFP)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-15", Category: "crypto", TargetType: "contribution", TargetID: "atk_crypto_fp_tamper",
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrFingerprintMismatch,
		Description: "Signed contribution with tampered Winnowing fingerprint_digest",
	})
	seq++

	// 5. Realistic Legitimate EAS Attestations (~80 peer reviews, replications, reuse endorsements).
	attTS := ts + 1000
	// Seed stewards independently review foundational & derivative works of honest researchers.
	for i, cid := range foundationalIDs {
		author := foundationalAuthors[cid]
		seedReviewer := fmt.Sprintf("seed_%02d", (i%4)+1)
		if seedReviewer != author {
			attTS += 120
			a, err := kr.makeAttestation(SchemaReplication, seedReviewer, author, cid, 2, attTS, evalTime+86400*90, true, false, nextNonce(seedReviewer), 9200, "independent replication verified "+cid, "honest_seed_replication")
			if err != nil {
				return SuiteBundle{}, err
			}
			atts = append(atts, a)
		}
		// Add a second independent peer review from another honest researcher.
		peerReviewer := fmt.Sprintf("res_%02d", ((i+5)%12)+1)
		if peerReviewer != author {
			attTS += 120
			a, err := kr.makeAttestation(SchemaPeerReview, peerReviewer, author, cid, 2, attTS, evalTime+86400*90, true, false, nextNonce(peerReviewer), 8500, "peer review verified "+cid, "honest_peer_review")
			if err != nil {
				return SuiteBundle{}, err
			}
			atts = append(atts, a)
		}
	}

	// Derivative contributions receive peer reviews + downstream reuse endorsements.
	for i, cid := range derivativeIDs {
		author := derivativeAuthors[cid]
		seedReviewer := fmt.Sprintf("seed_%02d", ((i+1)%4)+1)
		if seedReviewer != author {
			attTS += 120
			a, err := kr.makeAttestation(SchemaPeerReview, seedReviewer, author, cid, 3, attTS, evalTime+86400*90, true, false, nextNonce(seedReviewer), 8800, "derivative novelty verified "+cid, "honest_seed_review")
			if err != nil {
				return SuiteBundle{}, err
			}
			atts = append(atts, a)
		}
		peerReviewer := fmt.Sprintf("res_%02d", ((i+7)%12)+1)
		if peerReviewer != author {
			attTS += 120
			a, err := kr.makeAttestation(SchemaReuseEndorsement, peerReviewer, author, cid, 3, attTS, evalTime+86400*90, true, false, nextNonce(peerReviewer), 8000, "downstream reuse confirmed "+cid, "honest_reuse_endorsement")
			if err != nil {
				return SuiteBundle{}, err
			}
			atts = append(atts, a)
		}
	}

	// Give top genuine researcher res_01 one extra replication from seed_02 to anchor clear ground truth.
	attTS += 120
	extraSeed, err := kr.makeAttestation(SchemaReplication, "seed_02", "res_01", "contrib_base_01_1", 3, attTS, evalTime+86400*90, true, false, nextNonce("seed_02"), 9500, "secondary replication confirmation", "honest_seed_replication")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, extraSeed)

	// Honest newcomer receives 1 unseeded peer attestation (NOT a seed) to demonstrate cold-start lag.
	attTS += 120
	newcomerUnseeded, err := kr.makeAttestation(SchemaPeerReview, "newcomer_peer", "newcomer_honest", "contrib_newcomer_01", 3, attTS, evalTime+86400*90, true, false, nextNonce("newcomer_peer"), 8500, "unseeded peer endorsement of newcomer", "newcomer_unseeded_review")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, newcomerUnseeded)

	// Permitted AI advisory similarity flags (0 direct reputation minting, StatusAdvisory).
	attTS += 120
	aiFlag1, err := kr.makeAttestation(SchemaSimilarityFlag, "ai_reviewer_01", "plagiarist_exact", "contrib_base_01_1", 3, attTS, 0, false, false, nextNonce("ai_reviewer_01"), 0, "advisory copy flag on atk_copy_exact_01", "ai_advisory_flag_1")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, aiFlag1)

	attTS += 120
	aiFlag2, err := kr.makeAttestation(SchemaSimilarityFlag, "ai_reviewer_01", "plagiarist_patch", "contrib_base_01_2", 3, attTS, 0, false, false, nextNonce("ai_reviewer_01"), 0, "advisory near-duplicate flag on atk_copy_patch_85_01", "ai_advisory_flag_2")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, aiFlag2)

	// 6. Collusion & Sybil Attack Graphs (20-account Sybil farm + 2-node pair + 5-node ring).
	// (a) 20-account Sybil farm attesting mallory_sybil_boss across replication + reuse schemas (zero external trust edges).
	for i := 1; i <= 20; i++ {
		syb := fmt.Sprintf("sybil_%02d", i)
		attTS += 30
		a1, err := kr.makeAttestation(SchemaReplication, syb, "mallory_sybil_boss", "contrib_sybil_boss_01", 3, attTS, evalTime+86400*90, true, false, nextNonce(syb), BpsScale, fmt.Sprintf("sybil farm replication %02d", i), "atk_sybil_farm")
		if err != nil {
			return SuiteBundle{}, err
		}
		atts = append(atts, a1)
		attTS += 15
		a2, err := kr.makeAttestation(SchemaReuseEndorsement, syb, "mallory_sybil_boss", "contrib_sybil_boss_01", 3, attTS, evalTime+86400*90, true, false, nextNonce(syb), BpsScale, fmt.Sprintf("sybil farm reuse endorsement %02d", i), "atk_sybil_farm")
		if err != nil {
			return SuiteBundle{}, err
		}
		atts = append(atts, a2)
	}
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-16", Category: "collusion", TargetType: "cluster", TargetID: "sybil_01",
		ExpectedStatus: "DISCOUNTED", ExpectedErrCode: ErrSybilClusterCapped,
		Description: "20-account Sybil farm attesting mallory_sybil_boss detected and capped",
	})

	// (b) 2-node mutual-admiration pair (pair_a <-> pair_b).
	attTS += 60
	pairAB, err := kr.makeAttestation(SchemaPeerReview, "pair_a", "pair_b", "contrib_pair_b", 3, attTS, evalTime+86400*90, true, false, nextNonce("pair_a"), BpsScale, "mutual admiration A->B", "atk_pair_ab")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, pairAB)

	attTS += 60
	pairBA, err := kr.makeAttestation(SchemaPeerReview, "pair_b", "pair_a", "contrib_pair_a", 3, attTS, evalTime+86400*90, true, false, nextNonce("pair_b"), BpsScale, "mutual admiration B->A", "atk_pair_ba")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, pairBA)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-17", Category: "collusion", TargetType: "cluster", TargetID: "pair_a",
		ExpectedStatus: "DISCOUNTED", ExpectedErrCode: ErrCollusionRingDiscounted,
		Description: "2-node mutual-admiration endorsement pair (pair_a <-> pair_b) collapsed",
	})

	// (c) 5-node endorsement ring (ring_01 -> ring_02 -> ring_03 -> ring_04 -> ring_05 -> ring_01).
	for i := 1; i <= 5; i++ {
		src := fmt.Sprintf("ring_%02d", i)
		dst := fmt.Sprintf("ring_%02d", (i%5)+1)
		ref := fmt.Sprintf("contrib_ring_%02d", (i%5)+1)
		attTS += 60
		a, err := kr.makeAttestation(SchemaPeerReview, src, dst, ref, 3, attTS, evalTime+86400*90, true, false, nextNonce(src), BpsScale, "5-node ring "+src+"->"+dst, "atk_ring_5node")
		if err != nil {
			return SuiteBundle{}, err
		}
		atts = append(atts, a)
	}
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-18", Category: "collusion", TargetType: "cluster", TargetID: "ring_01",
		ExpectedStatus: "DISCOUNTED", ExpectedErrCode: ErrCollusionRingDiscounted,
		Description: "5-node circular endorsement ring (ring_01..ring_05) detected via Tarjan SCC and collapsed",
	})

	// 7. Explicit Adversarial Attestation, Replay, Revocation, Crypto & AI-Guard Attacks (14 vectors -> 32 total!).
	// ATK-19: Self-attestation loop (res_03 -> res_03).
	attTS += 60
	selfAtt1, err := kr.makeAttestation(SchemaPeerReview, "res_03", "res_03", "contrib_base_03_1", 3, attTS, evalTime+86400*90, true, false, nextNonce("res_03"), BpsScale, "self-attestation attempt", "atk_self_attest_01")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, selfAtt1)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-19", Category: "collusion", TargetType: "attestation", TargetID: selfAtt1.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrSelfAttestation,
		Description: "Self-citation / self-attestation loop (res_03 -> res_03)",
	})

	// ATK-20: Second self-attestation loop (mallory_sybil_boss -> mallory_sybil_boss).
	attTS += 60
	selfAtt2, err := kr.makeAttestation(SchemaReplication, "mallory_sybil_boss", "mallory_sybil_boss", "contrib_sybil_boss_01", 3, attTS, evalTime+86400*90, true, false, nextNonce("mallory_sybil_boss"), BpsScale, "sybil boss self-replication", "atk_self_attest_02")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, selfAtt2)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-20", Category: "collusion", TargetType: "attestation", TargetID: selfAtt2.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrSelfAttestation,
		Description: "Self-replication attestation loop (mallory -> mallory)",
	})

	// ATK-21: Cross-epoch attestation replay (res_06 replays peer review for contrib_base_01_1 in epoch 4).
	attTS += 60
	replayCross, err := kr.makeAttestation(SchemaPeerReview, "res_06", "res_01", "contrib_base_01_1", 4, attTS, evalTime+86400*90, true, false, nextNonce("res_06"), 8500, "cross-epoch replay of peer review", "atk_replay_cross_epoch")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, replayCross)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-21", Category: "collusion", TargetType: "attestation", TargetID: replayCross.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrAttestationReplay,
		Description: "Cross-epoch replay of already-credited (attester, ref_uid, schema) attestation",
	})

	// ATK-22: Nonce reuse replay by same attester on different paper.
	attTS += 60
	replayNonce, err := kr.makeAttestation(SchemaPeerReview, "res_07", "res_02", "contrib_base_02_1", 4, attTS, evalTime+86400*90, true, false, 1, 8500, "reused nonce=1 replay", "atk_replay_nonce")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, replayNonce)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-22", Category: "collusion", TargetType: "attestation", TargetID: replayNonce.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrAttestationReplay,
		Description: "Nonce-reuse replay attack by res_07",
	})

	// ATK-23: Revoked EAS attestation (revoked=true flag).
	attTS += 60
	revFlag, err := kr.makeAttestation(SchemaReplication, "seed_01", "res_04", "contrib_base_04_1", 4, attTS, evalTime+86400*90, true, true, nextNonce("seed_01"), 9000, "revoked attestation inline flag", "atk_revoked_flag")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, revFlag)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-23", Category: "collusion", TargetType: "attestation", TargetID: revFlag.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrRevokedAttestation,
		Description: "Reuse of revoked EAS attestation (revoked=true)",
	})

	// ATK-24: Revoked EAS attestation via external revocation registry (revoked_uids).
	attTS += 60
	revReg, err := kr.makeAttestation(SchemaReplication, "seed_03", "res_05", "contrib_base_05_1", 4, attTS, evalTime+86400*90, true, false, nextNonce("seed_03"), 9000, "revoked via registry", "atk_revoked_registry")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, revReg)
	revokedUIDs = append(revokedUIDs, revReg.UID)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-24", Category: "collusion", TargetType: "attestation", TargetID: revReg.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrRevokedAttestation,
		Description: "Reuse of EAS attestation revoked in on-chain revocation registry",
	})

	// ATK-25: Expired EAS attestation.
	attTS += 60
	expAtt, err := kr.makeAttestation(SchemaPeerReview, "seed_04", "res_08", "contrib_base_08_1", 4, attTS, evalTime-3600, true, false, nextNonce("seed_04"), 8000, "expired attestation", "atk_expired_eas")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, expAtt)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-25", Category: "collusion", TargetType: "attestation", TargetID: expAtt.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrExpiredAttestation,
		Description: "Expired EAS attestation past expiration_time",
	})

	// ATK-26: Forged Ed25519 signature on EAS attestation.
	attTS += 60
	forgedAtt, err := kr.makeAttestation(SchemaReplication, "seed_01", "mallory_sybil_boss", "contrib_sybil_boss_01", 4, attTS, evalTime+86400*90, true, false, nextNonce("seed_01"), BpsScale, "forged seed endorsement", "atk_forged_eas_sig")
	if err != nil {
		return SuiteBundle{}, err
	}
	forgedAtt.SignatureHex = flipFirstHexByte(forgedAtt.SignatureHex)
	atts = append(atts, forgedAtt)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-26", Category: "crypto", TargetType: "attestation", TargetID: forgedAtt.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrInvalidSignature,
		Description: "Forged Ed25519 signature impersonating seed_01 to endorse colluder",
	})

	// ATK-27: Tampered EAS AttestationUID.
	attTS += 60
	tamperedUID, err := kr.makeAttestation(SchemaReplication, "seed_02", "res_09", "contrib_base_09_1", 4, attTS, evalTime+86400*90, true, false, nextNonce("seed_02"), 9000, "tampered EAS UID", "atk_tampered_eas_uid")
	if err != nil {
		return SuiteBundle{}, err
	}
	tamperedUID.UID = "0x" + flipFirstHexByte(strings.TrimPrefix(tamperedUID.UID, "0x"))
	atts = append(atts, tamperedUID)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-27", Category: "crypto", TargetType: "attestation", TargetID: tamperedUID.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrAttestationUIDMismatch,
		Description: "Tampered EAS AttestationUID inconsistent with canonical attestation fields",
	})

	// ATK-28: Attesting a rejected copied contribution (cannot launder reputation from plagiarism).
	attTS += 60
	attestCopy, err := kr.makeAttestation(SchemaPeerReview, "res_10", "plagiarist_exact", "atk_copy_exact_01", 4, attTS, evalTime+86400*90, true, false, nextNonce("res_10"), 9000, "attempt to endorse plagiarized copy", "atk_attest_copied_paper")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, attestCopy)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-28", Category: "copy", TargetType: "attestation", TargetID: attestCopy.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrRefNotAccepted,
		Description: "Attesting a rejected exact-duplicate copy cannot mint reputation",
	})

	// ATK-29: AI agent direct self-certification.
	attTS += 60
	aiSelf1, err := kr.makeAttestation(SchemaPeerReview, "ai_reviewer_01", "ai_reviewer_01", "contrib_ai_01", 4, attTS, evalTime+86400*90, true, false, nextNonce("ai_reviewer_01"), BpsScale, "AI direct self-certification", "atk_ai_self_attest_direct")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, aiSelf1)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-29", Category: "ai_guard", TargetType: "attestation", TargetID: aiSelf1.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrAISelfAttestForbidden,
		Description: "AI_AGENT direct self-attestation blocked by constitutional guard",
	})

	// ATK-30: AI agent attempting indirect self-attestation on its own authored contribution.
	attTS += 60
	aiSelf2, err := kr.makeAttestation(SchemaReplication, "ai_reviewer_01", "res_01", "contrib_ai_01", 4, attTS, evalTime+86400*90, true, false, nextNonce("ai_reviewer_01"), BpsScale, "AI indirect self-certification on own artifact", "atk_ai_self_attest_own_paper")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, aiSelf2)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-30", Category: "ai_guard", TargetType: "attestation", TargetID: aiSelf2.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrAISelfAttestForbidden,
		Description: "AI_AGENT attesting its own authored contribution via another recipient blocked",
	})

	// ATK-31: AI agent attempting reputation policy rule mutation.
	attTS += 60
	aiPolicy, err := kr.makeAttestation(SchemaPolicyMutation, "ai_reviewer_01", "seed_01", "contrib_base_01_1", 4, attTS, 0, true, false, nextNonce("ai_reviewer_01"), BpsScale, "AI proposal to weaken Sybil cluster threshold", "atk_ai_policy_mutation")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, aiPolicy)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-31", Category: "ai_guard", TargetType: "attestation", TargetID: aiPolicy.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrAIPolicyMutationForbid,
		Description: "AI_AGENT attempting to approve reputation policy mutation blocked",
	})

	// ATK-32: AI agent attempting treasury reward authorization.
	attTS += 60
	aiTreasury, err := kr.makeAttestation(SchemaTreasuryAuth, "ai_reviewer_01", "res_01", "contrib_base_01_1", 4, attTS, 0, true, false, nextNonce("ai_reviewer_01"), BpsScale, "AI attempt to authorize ZOO treasury grant payout", "atk_ai_treasury_auth")
	if err != nil {
		return SuiteBundle{}, err
	}
	atts = append(atts, aiTreasury)
	expectations = append(expectations, AdversarialExpectation{
		AttackID: "ATK-32", Category: "ai_guard", TargetType: "attestation", TargetID: aiTreasury.UID,
		ExpectedStatus: StatusRejected, ExpectedErrCode: ErrAITreasuryForbidden,
		Description: "AI_AGENT attempting to authorize treasury rewards blocked",
	})

	return SuiteBundle{
		SchemaVersion:           SchemaVersion,
		SpecVersion:             SpecVersion,
		SuiteName:               "zoo-scientific-attribution-reputation-v1",
		Seed:                    seed,
		EvalTime:                evalTime,
		CorpusManifestSHA256:    manifest.ManifestHash,
		Policy:                  DefaultPolicy(),
		Identities:              kr.identities,
		RevokedUIDs:             revokedUIDs,
		Contributions:           contribs,
		Attestations:            atts,
		AdversarialExpectations: expectations,
	}, nil
}

// RunBenchmark executes the published suite and all 3 explicit honest negative regimes.
func RunBenchmark(manifest CorpusManifest, papers []LoadedPaper, bundle SuiteBundle, seed int64) (BenchmarkResults, VerificationReport, error) {
	report, err := VerifySuite(bundle)
	if err != nil {
		return BenchmarkResults{}, VerificationReport{}, err
	}

	var topGenuine IdentitySummary
	var sybilBoss IdentitySummary
	for _, s := range report.IdentitySummaries {
		if s.IdentityID == "mallory_sybil_boss" {
			sybilBoss = s
		}
		if s.Role == RoleResearcher && strings.HasPrefix(s.IdentityID, "res_") {
			if topGenuine.IdentityID == "" || s.ReputationMicro > topGenuine.ReputationMicro {
				topGenuine = s
			}
		}
	}

	// Negative Regime 1: neg_naive_count_collusion_inflation
	// Also test a 1-fringe-bridge variant where 1 honest researcher erroneously attests to sybil_01.
	neg1, err := runNegNaiveCollusionInflation(bundle, report, topGenuine, sybilBoss, seed)
	if err != nil {
		return BenchmarkResults{}, VerificationReport{}, err
	}

	// Negative Regime 2: neg_unweighted_copy_double_counting
	neg2, err := runNegCopyDoubleCounting(papers, seed)
	if err != nil {
		return BenchmarkResults{}, VerificationReport{}, err
	}

	// Negative Regime 3: neg_honest_newcomer_cold_start_lag
	neg3, err := runNegNewcomerColdStart(bundle, report, seed)
	if err != nil {
		return BenchmarkResults{}, VerificationReport{}, err
	}

	// Top 12 ranked identities for benchmark table.
	ranked := make([]IdentitySummary, len(report.IdentitySummaries))
	copy(ranked, report.IdentitySummaries)
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].ReputationRank < ranked[j].ReputationRank
	})
	if len(ranked) > 12 {
		ranked = ranked[:12]
	}

	results := BenchmarkResults{
		SchemaVersion:          SchemaVersion,
		SpecVersion:            SpecVersion,
		Seed:                   seed,
		CorpusManifestSHA256:   manifest.ManifestHash,
		SuiteName:              bundle.SuiteName,
		AuditMerkleRoot:        report.AuditMerkleRoot,
		TotalDAGItems:          report.TotalContributions + report.TotalAttestations,
		TotalContributions:     report.TotalContributions,
		AcceptedContributions:  report.AcceptedContributions,
		RejectedContributions:  report.RejectedContributions,
		TotalAttestations:      report.TotalAttestations,
		AcceptedAttestations:   report.AcceptedAttestations,
		AdvisoryAttestations:   report.AdvisoryAttestations,
		RejectedAttestations:   report.RejectedAttestations,
		AdversarialPassed:      report.AdversarialPassed,
		AdversarialTotal:       report.AdversarialTotal,
		ConservationExact:      report.ConservationExact,
		TotalIntrinsicMicro:    report.TotalIntrinsicMicro,
		TotalAttributedMicro:   report.TotalAttributedMicro,
		TotalNaiveAttrMicro:    report.TotalNaiveAttributedMicro,
		CollusionFindingsCount: len(report.CollusionFindings),
		TopGenuineResearcher:   topGenuine,
		SybilBossSummary:       sybilBoss,
		NegativeRegimes:        []NegativeRegimeResult{neg1, neg2, neg3},
		TopRankings:            ranked,
		AdversarialResults:     report.AdversarialResults,
	}
	return results, report, nil
}

func runNegNaiveCollusionInflation(
	bundle SuiteBundle,
	report VerificationReport,
	topGenuine IdentitySummary,
	sybilBoss IdentitySummary,
	seed int64,
) (NegativeRegimeResult, error) {
	naiveRatioBps := int64(0)
	if topGenuine.NaiveReputationPoints > 0 {
		naiveRatioBps = (sybilBoss.NaiveReputationPoints * BpsScale) / topGenuine.NaiveReputationPoints
	}
	protectedRatioBps := int64(0)
	if topGenuine.ReputationMicro > 0 {
		protectedRatioBps = (sybilBoss.ReputationMicro * BpsScale) / topGenuine.ReputationMicro
	}

	// Stress variant: add 1 fringe bridge edge from an honest researcher (res_12) to sybil_01.
	bridged := bundle
	bridged.Attestations = append([]Attestation(nil), bundle.Attestations...)
	_, privRes12 := DeriveEd25519Key(seed, "res_12")
	bridgeAtt := Attestation{
		SchemaUID:      SchemaPeerReview,
		Attester:       "res_12",
		Recipient:      "sybil_01",
		RefUID:         "contrib_sybil_boss_01",
		Epoch:          4,
		Time:           bundle.EvalTime - 600,
		ExpirationTime: bundle.EvalTime + 86400*90,
		Revocable:      true,
		Revoked:        false,
		Nonce:          999,
		WeightBps:      5000,
		DataDigest:     SHA256Hex([]byte("single fringe bridge stress test")),
		ScenarioTag:    "neg1_fringe_bridge",
	}
	if err := SignAttestation(&bridgeAtt, privRes12); err != nil {
		return NegativeRegimeResult{}, err
	}
	bridged.Attestations = append(bridged.Attestations, bridgeAtt)
	bridgedReport, err := VerifySuite(bridged)
	if err != nil {
		return NegativeRegimeResult{}, err
	}
	var bridgedSybil IdentitySummary
	var bridgedTop IdentitySummary
	for _, s := range bridgedReport.IdentitySummaries {
		if s.IdentityID == "mallory_sybil_boss" {
			bridgedSybil = s
		}
		if s.IdentityID == topGenuine.IdentityID {
			bridgedTop = s
		}
	}
	bridgedRatioBps := int64(0)
	if bridgedTop.ReputationMicro > 0 {
		bridgedRatioBps = (bridgedSybil.ReputationMicro * BpsScale) / bridgedTop.ReputationMicro
	}

	passed := sybilBoss.NaiveReputationRank == 1 &&
		naiveRatioBps > 40000 && // > 4.0x genuine top researcher under naive counting
		protectedRatioBps < 100 && // < 1.0% under seeded Sybil-resistant reputation
		bridgedRatioBps < 100 // < 1.0% even under 1-fringe-bridge attack!

	return NegativeRegimeResult{
		RegimeID: "neg_naive_count_collusion_inflation",
		Title:    "Naive Attestation Counting Collusion Inflation vs Seeded Sybil-Resistant Reputation",
		Passed:   passed,
		Summary: fmt.Sprintf(
			"Naive counting elevates 20-Sybil boss to Rank #%d (%d pts = %.2fx top genuine researcher %s at %d pts); seeded EigenTrust + cluster-cap holds Sybil boss to %d ZooRep (%.3f%% of top researcher, and %.3f%% under 1-fringe-bridge stress).",
			sybilBoss.NaiveReputationRank,
			sybilBoss.NaiveReputationPoints,
			float64(naiveRatioBps)/float64(BpsScale),
			topGenuine.IdentityID,
			topGenuine.NaiveReputationPoints,
			sybilBoss.ZooRepPoints,
			float64(protectedRatioBps)/100.0,
			float64(bridgedRatioBps)/100.0,
		),
		Metrics: map[string]any{
			"sybil_accounts":                 20,
			"sybil_boss_naive_rank":          sybilBoss.NaiveReputationRank,
			"sybil_boss_naive_points":        sybilBoss.NaiveReputationPoints,
			"top_genuine_id":                 topGenuine.IdentityID,
			"top_genuine_naive_points":       topGenuine.NaiveReputationPoints,
			"naive_inflation_ratio_bps":      naiveRatioBps,
			"sybil_boss_protected_rank":      sybilBoss.ReputationRank,
			"sybil_boss_protected_rep_micro": sybilBoss.ReputationMicro,
			"sybil_boss_protected_zoo_rep":   sybilBoss.ZooRepPoints,
			"top_genuine_protected_zoo_rep":  topGenuine.ZooRepPoints,
			"protected_sybil_share_bps":      protectedRatioBps,
			"bridged_sybil_share_bps":        bridgedRatioBps,
		},
	}, nil
}

func runNegCopyDoubleCounting(papers []LoadedPaper, seed int64) (NegativeRegimeResult, error) {
	kr := newKeyRing(seed + 100)
	kr.add("seed_orig", RoleSeed, "Seed Steward")
	for i := 1; i <= 10; i++ {
		kr.add(fmt.Sprintf("orig_%02d", i), RoleResearcher, fmt.Sprintf("Original Author %02d", i))
		kr.add(fmt.Sprintf("copy_%02d", i), RoleResearcher, fmt.Sprintf("Copycat %02d", i))
	}

	const baseTS int64 = 1761000000
	var contribs []Contribution
	var seq int64 = 1
	ts := baseTS

	// 10 genuine canonical contributions from 10 distinct real .tex papers.
	origTexts := make([]string, 10)
	for i := 0; i < 10; i++ {
		lp := papers[i%len(papers)]
		text := lp.Segments[0]
		origTexts[i] = text
		ts += 300
		c, err := kr.makeContribution(fmt.Sprintf("orig_c_%02d", i+1), seq, 1, ts, fmt.Sprintf("orig_%02d", i+1), lp.Entry.Category, lp.Entry.RelPath, text, nil, BpsScale, "canonical_original")
		if err != nil {
			return NegativeRegimeResult{}, err
		}
		contribs = append(contribs, c)
		seq++
	}

	// 10 copies: 5 exact verbatim + 3 LaTeX/whitespace reformatted + 2 85%-copied patch-plagiarism.
	for i := 0; i < 10; i++ {
		var copyText string
		var tag string
		switch {
		case i < 5:
			copyText = origTexts[i]
			tag = "exact_copy"
		case i < 8:
			copyText = "% reformatted copy comment\n\\textbf{" + strings.ReplaceAll(origTexts[i], " ", "  ") + "}\\label{sec:copy}"
			tag = "reformatted_copy"
		default:
			copyText = origTexts[i] + "\n\nMinor appended closing sentence claiming full novelty across copied methodology."
			tag = "patch_85_copy"
		}
		ts += 300
		c, err := kr.makeContribution(fmt.Sprintf("copy_c_%02d", i+1), seq, 2, ts, fmt.Sprintf("copy_%02d", i+1), "research", "", copyText, nil, BpsScale, tag)
		if err != nil {
			return NegativeRegimeResult{}, err
		}
		contribs = append(contribs, c)
		seq++
	}

	// Evaluate canonical originals alone first (exact ground-truth baseline).
	origBundle := SuiteBundle{
		SchemaVersion: SchemaVersion,
		SpecVersion:   SpecVersion,
		SuiteName:     "neg-unweighted-copy-baseline",
		Seed:          seed + 100,
		EvalTime:      ts + 3600,
		Policy:        DefaultPolicy(),
		Identities:    kr.identities,
		Contributions: contribs[:10],
	}
	repOrig, err := VerifySuite(origBundle)
	if err != nil {
		return NegativeRegimeResult{}, err
	}

	subBundle := SuiteBundle{
		SchemaVersion: SchemaVersion,
		SpecVersion:   SpecVersion,
		SuiteName:     "neg-unweighted-copy-double-counting",
		Seed:          seed + 100,
		EvalTime:      ts + 3600,
		Policy:        DefaultPolicy(),
		Identities:    kr.identities,
		Contributions: contribs,
	}
	rep, err := VerifySuite(subBundle)
	if err != nil {
		return NegativeRegimeResult{}, err
	}

	naiveRatioBps := (rep.TotalNaiveAttributedMicro * BpsScale) / repOrig.TotalNaiveAttributedMicro
	protectedRatioBps := (rep.TotalAttributedMicro * BpsScale) / repOrig.TotalAttributedMicro

	var copycatCreditMicro int64
	for _, s := range rep.IdentitySummaries {
		if strings.HasPrefix(s.IdentityID, "copy_") {
			copycatCreditMicro += s.AttributionMicro
		}
	}

	passed := naiveRatioBps == 20000 && // exact 2.0000x double-counting in naive system
		protectedRatioBps == 10000 && // exact 1.0000x conservation (0 incremental credit from copies)
		rep.TotalAttributedMicro == repOrig.TotalAttributedMicro &&
		copycatCreditMicro == 0 &&
		rep.ConservationExact

	return NegativeRegimeResult{
		RegimeID: "neg_unweighted_copy_double_counting",
		Title:    "Naive Copy Double-Counting (2.0x) vs Canonical-Digest + Winnowing Conservation (1.0x)",
		Passed:   passed,
		Summary: fmt.Sprintf(
			"Across 10 canonical real-paper artifacts + 10 copies (5 exact, 3 reformatted, 2 patch-85%%), naive attribution inflates credits from %.6f to %.6f (%.2fx double-counting); canonical-digest + Winnowing holds exact %.6f -> %.6f credits (%.2fx conservation, 0 micro-credits to all 10 copies).",
			float64(repOrig.TotalNaiveAttributedMicro)/float64(MicroScale),
			float64(rep.TotalNaiveAttributedMicro)/float64(MicroScale),
			float64(naiveRatioBps)/float64(BpsScale),
			float64(repOrig.TotalAttributedMicro)/float64(MicroScale),
			float64(rep.TotalAttributedMicro)/float64(MicroScale),
			float64(protectedRatioBps)/float64(BpsScale),
		),
		Metrics: map[string]any{
			"canonical_contributions":       10,
			"injected_copies":               10,
			"exact_copies":                  5,
			"reformatted_copies":            3,
			"patch_85_copies":               2,
			"naive_before_micro":            repOrig.TotalNaiveAttributedMicro,
			"naive_after_micro":             rep.TotalNaiveAttributedMicro,
			"protected_before_micro":        repOrig.TotalAttributedMicro,
			"protected_after_micro":         rep.TotalAttributedMicro,
			"copycat_credit_micro":          copycatCreditMicro,
			"naive_credit_ratio_bps":        naiveRatioBps,
			"protected_credit_ratio_bps":    protectedRatioBps,
			"conservation_exact":            rep.ConservationExact,
		},
	}, nil
}

func runNegNewcomerColdStart(bundle SuiteBundle, beforeReport VerificationReport, seed int64) (NegativeRegimeResult, error) {
	var beforeNewcomer IdentitySummary
	for _, s := range beforeReport.IdentitySummaries {
		if s.IdentityID == "newcomer_honest" {
			beforeNewcomer = s
			break
		}
	}

	// Phase B: newcomer_honest receives 1 independent replication attestation from seed_01.
	afterBundle := bundle
	afterBundle.Attestations = append([]Attestation(nil), bundle.Attestations...)
	_, privSeed1 := DeriveEd25519Key(seed, "seed_01")
	seedAtt := Attestation{
		SchemaUID:      SchemaReplication,
		Attester:       "seed_01",
		Recipient:      "newcomer_honest",
		RefUID:         "contrib_newcomer_01",
		Epoch:          4,
		Time:           bundle.EvalTime - 300,
		ExpirationTime: bundle.EvalTime + 86400*90,
		Revocable:      true,
		Revoked:        false,
		Nonce:          888,
		WeightBps:      9500,
		DataDigest:     SHA256Hex([]byte("independent seeded replication of honest newcomer")),
		ScenarioTag:    "neg3_seed_onboarding",
	}
	if err := SignAttestation(&seedAtt, privSeed1); err != nil {
		return NegativeRegimeResult{}, err
	}
	afterBundle.Attestations = append(afterBundle.Attestations, seedAtt)
	afterReport, err := VerifySuite(afterBundle)
	if err != nil {
		return NegativeRegimeResult{}, err
	}

	var afterNewcomer IdentitySummary
	for _, s := range afterReport.IdentitySummaries {
		if s.IdentityID == "newcomer_honest" {
			afterNewcomer = s
			break
		}
	}

	passed := beforeNewcomer.AttributionMicro == MicroScale &&
		beforeNewcomer.EigenTrustMicro == 0 &&
		beforeNewcomer.ZooRepPoints == 0 &&
		beforeNewcomer.Tier == "Observer" &&
		afterNewcomer.EigenTrustMicro > 0 &&
		afterNewcomer.ZooRepPoints >= 50 &&
		afterNewcomer.Tier != "Observer"

	return NegativeRegimeResult{
		RegimeID: "neg_honest_newcomer_cold_start_lag",
		Title:    "Honest Newcomer Cold-Start Lag Under Strict Seeded Trust Damping",
		Passed:   passed,
		Summary: fmt.Sprintf(
			"Before any seeded replication attestation, honest newcomer retains 100%% content attribution (%d micro-credits) but experiences cold-start reputation lag (EigenTrust=0, ZooRep=0, Tier=%s); upon receiving 1 independent seeded replication attestation, EigenTrust jumps to %d micro-units and ZooRep rises to %d pts (Tier=%s, %.1fx weight).",
			beforeNewcomer.AttributionMicro,
			beforeNewcomer.Tier,
			afterNewcomer.EigenTrustMicro,
			afterNewcomer.ZooRepPoints,
			afterNewcomer.Tier,
			float64(afterNewcomer.TierWeightBps)/100.0,
		),
		Metrics: map[string]any{
			"newcomer_id":                 "newcomer_honest",
			"before_attribution_micro":    beforeNewcomer.AttributionMicro,
			"before_eigentrust_micro":     beforeNewcomer.EigenTrustMicro,
			"before_zoo_rep_points":       beforeNewcomer.ZooRepPoints,
			"before_tier":                 beforeNewcomer.Tier,
			"before_rank":                 beforeNewcomer.ReputationRank,
			"after_eigentrust_micro":      afterNewcomer.EigenTrustMicro,
			"after_trust_gate_bps":        afterNewcomer.TrustGateBps,
			"after_zoo_rep_points":        afterNewcomer.ZooRepPoints,
			"after_tier":                  afterNewcomer.Tier,
			"after_tier_weight_bps":       afterNewcomer.TierWeightBps,
			"after_rank":                  afterNewcomer.ReputationRank,
			"onboarding_attestations_req": 1,
		},
	}, nil
}

func buildNovelExtensionText(idx int, p1, p2, title string) string {
	// Distinct non-overlapping scientific prose per extension study (zero shared 4-shingle boilerplate).
	bodies := []string{
		"Acoustic hydrophone grids anchored along volcanic seamounts reveal diel zooplankton vertical migration rhythms across four seasonal thermoclines. Submersible recorders sampling ninety-six kilohertz spectral density isolate cetacean click trains from vessel propeller cavitation using adaptive wavelet shrinkage and phase-coherent beamforming. Calibration drift measured against titanium reference pingers stays below three tenths of a decibel over eleven months of abyssal deployment, enabling verifiable long-term acoustic biodiversity ledgers.",
		"Multispectral drone orthomosaics captured over montane cloud forests quantify epiphyte biomass recovery following selective watershed restoration. Radiometric reflectance panels positioned beneath dense bamboo canopies correct shadow-induced normalized difference vegetation anomalies before training random forest canopy height estimators. Field botanists verified seventy-eight permanent circular plots with laser hypsometers, lowering root-mean-square basal area error by twenty-four percent across steep Andean ridges.",
		"Intertidal rocky shore quadrat surveys spanning eighteen coastal headlands track barnacle recruitment sensitivity to marine heatwave anomalies. Automated photogrammetry pipelines reconstruct millimeter-scale microhabitat rugosity meshes, separating wave-exposure shear from thermal desiccation mortality across tidal elevation zones. Open archival vouchers paired with temperature logger checksums permit rapid cross-laboratory replication of rocky intertidal trophic cascade forecasts.",
		"Doppler weather radar polarimetric reflectivity scans map nocturnal passerine stopover densities across fragmented agricultural flyways. Differential phase shift filters reject wind-turbine clutter and precipitation bands while preserving high-altitude songbird wingbeat signatures during autumn frontal passages. Municipal dark-sky lighting ordinances timed to peak migration alerts reduced glass-facade collision mortality by thirty-seven percent in controlled urban trials.",
		"Satellite synthetic aperture radar interferometry detects seasonal wetland inundation dynamics throughout semi-arid savanna floodplains. Dual-polarization backscatter decomposition distinguishes emergent papyrus marshes from open ephemeral pans beneath dense monsoon cloud cover. Pastoralist water-point telemetry integrated with ungulate collar trajectories informs dynamic seasonal grazing corridors that minimize human-wildlife conflict.",
		"Permafrost borehole thermistor strings installed across arctic tundra polygons record active-layer thaw deepening over seven consecutive summers. Coupled snowpack thermal conductivity solvers assimilate eddy-covariance methane flux measurements to bound anaerobic carbon mobilization rates during autumn freeze-up delays. Reproducible cryosphere parameterizations tighten watershed runoff projections for downstream salmonid spawning tributaries.",
		"Continuous flow-through fluorometers mounted aboard volunteer ferries profile estuarine phytoplankton bloom phenology across salinity fronts. Phycoerythrin and chlorophyll excitation ratios distinguish benign diatom spring pulses from toxic cyanobacterial aggregations hours before coastal aquaculture intakes require shutoff. Citizen-maintained optical windows calibrated weekly against certified quinine sulfate standards achieve laboratory-grade precision at negligible vessel overhead.",
		"Hyperspectral underwater camera rigs document scleractinian coral bleaching recovery trajectories along outer barrier reef slopes. Chromatic reflectance indices separate fluorescent host photoprotection pigments from symbiotic zooxanthellae expulsion across twenty-two stony coral genera. Autonomous transect stitching reduces diver bottom time by half while publishing tamper-evident reef health baselines for regional marine parks.",
		"Epipelagic drifting DNA samplers collect trace mitochondrial fragments across deep ocean upwelling eddies without disturbing shy elasmobranchs. Quantitative metabarcoding controls spiked with synthetic internal oligonucleotide standards calibrate species abundance estimates against acoustic trawl biomass surveys. Strict sterile filtration checklists eliminate shipboard cross-contamination across multi-week research cruises.",
		"Bioacoustic pitfall array sensors monitor subterranean amphibian breeding choruses inside temporary vernal pools across temperate oak savannas. Solar micro-inverters charge lithium iron phosphate packs during winter overcast weeks, sustaining uninterrupted nighttime spectrogram logging throughout spring snowmelt. Zero-shot call classifiers distilled for microcontroller edge inference flag invasive bullfrog arrivals within twenty-four hours.",
		"Lidar point clouds collected from fixed-wing ecological observatories characterize snag structural complexity inside old-growth conifer reserves. Voxelized crown volume distributions predict spotted owl nesting occupancy more accurately than legacy timber inventory tables while tracking post-wildfire fuel ladder regeneration. Cryptographically hashed point-cloud tiles allow independent forestry agencies to verify carbon sequestration claims.",
		"Stable isotope hair-trap forensics reconstruct elusive carnivore dietary breadth across transboundary mountain corridors without capture stress. Carbon thirteen and nitrogen fifteen trophic enrichment mixing models quantify wild ungulate versus livestock consumption across seasonal snowline migrations. Community ranger teams co-sign sample chain-of-custody logs to strengthen participatory conservation compensation schemes.",
		"Benthic sediment core microplastic spectroscopy measures synthetic fiber deposition chronologies inside remote glacial cirque lakes. Lead-210 radiometric dating anchors atmospheric fallout horizons to regional textile manufacturing shifts over six decades. Blind inter-laboratory Fourier-transform infrared validation confirms particle sizing repeatability across three independent European limnology groups.",
		"Soil fungal amplicon sequencing across chronosequences of abandoned pastureland traces ectomycorrhizal network reassembly during native forest succession. Co-occurrence network modularity highlights keystone truffle-forming taxa that accelerate oak seedling drought survival under projected Mediterranean summer aridity. Public inoculum provenance records safeguard local microbial genetic diversity during reforestation.",
		"Thermal infrared camera traps positioned around desert artesian springs quantify nocturnal small-mammal visitation without visible flash disturbance. Background-subtracted body-temperature silhouettes distinguish endangered kangaroo rats from sympatric pocket mice even through blowing alkali dust. Low-power LoRaWAN gateways relay encrypted occupancy summaries directly to tribal wildlife biologists.",
		"Automated pollen metabarcoding traps deployed beside agroforestry hedgerows evaluate wild pollinator foraging networks across blooming crop calendars. Bipartite plant-pollinator interaction robustness simulations identify native perennial floral mixes that sustain solitary bee populations during mid-summer nectar dearths. Farmer cooperatives audit seasonal pollination yield dividends via transparent verification receipts.",
	}
	b := bodies[(idx-1)%len(bodies)]
	return fmt.Sprintf("Follow-up Empirical Study %02d extending %s and %s (%s): %s", idx, p1, p2, title, b)
}

func buildDistinctSpecialText(idx int, cid, topic string) string {
	// Unique standalone scientific prose per special actor (zero shared boilerplate shingles).
	catalog := map[string]string{
		"contrib_newcomer_01": "Estuarine hydrophone transect calibration across subtropical coral atolls establishes baseline ambient soundscapes prior to reef restoration. Dual-element ceramic transducers suspended four meters above calcareous rubble record snapping shrimp cavitation alongside damselfish territorial vocalizations. Rigorous reciprocity calibration in anechoic saltwater tanks bounds sensitivity drift under two percent, supplying open acoustic reference spectra for incoming coastal ecologists.",
		"contrib_ai_01": "Deterministic Winnowing index benchmarks evaluate incremental k-shingle lookup latency across streaming scientific preprint archives. Memory-mapped radix buckets partition sixty-four-bit polynomial digests across cache-aligned arenas, scanning fifty thousand LaTeX manuscripts in under four seconds on commodity processors. Advisory plagiarism diagnostics output reproducible containment scores without claiming human peer-review authority.",
		"contrib_sybil_boss_01": "Telemetry packet compression ratios for GPS wildlife collars operating across dry acacia plains depend strongly on fix-interval entropy coding. Zigzag delta encoding of latitude and longitude increments paired with Huffman altitude symbols shrinks iridium satellite payloads by forty-one percent. Benchtop endurance tests confirm two additional months of collar battery life under hourly fix schedules.",
		"contrib_pair_a": "Bathymetric multibeam sonar drift measurements inside glacial fjords reveal strong sound-velocity stratification caused by summer meltwater plumes. Expendable bathythermograph casts every ninety minutes suppress outer-swath refraction smiles to under fifteen centimeters vertical bias across steep submarine moraines.",
		"contrib_pair_b": "Airborne laser scanning canopy density models across alpine headwater basins correlate snow-water equivalent retention with coniferous gap fractions. Ground snow-pit transects collected at twenty-four hundred meters elevation validate sub-canopy interception decay curves throughout April melt onset.",
		"contrib_ring_01": "Boreal crustose lichen growth rates on exposed granite boulders reflect decadal winter snowpack abrasion and nitrogen deposition gradients. Macro-photogrammetric thallus boundary tracing over five-year intervals yields sub-millimeter radial expansion curves across spruce-taiga ecotones.",
		"contrib_ring_02": "Mangrove prop-root interstitial porewater salinity profiles across tidal creeks govern juvenile snapper nursery habitat selection. Piezometer nests sampled across neap and spring tidal cycles demonstrate rapid freshwater lens flushing after tropical squalls.",
		"contrib_ring_03": "Infrared thermography of colonial steppe marmot burrow entrances maps subterranean ventilation airflow reversals during late autumn pre-hibernation. Micro-anemometer probes confirm passive chimney convection driven by prevailing westerly wind shear.",
		"contrib_ring_04": "Montane stream-breeding salamander acoustic phenology tracks nocturnal barometric pressure drops across misty cloud-forest ravines. Piezoelectric contact microphones clipped to wet moss capture substrate vibration cues invisible to standard aerial recorders.",
		"contrib_ring_05": "Pelagic shearwater biologger immersion sensors reconstruct foraging dive-depth distributions along continental shelf thermal fronts. Wet-dry saltwater conductivity switches synchronized with barometric pressure gauges isolate plunge-diving bouts over lanternfish schools.",
		"atk_dag_cycle_a": "Circular causality test vector alpha constructs a synthetic graph node pointing forward to unreleased manuscript beta in order to challenge topological acyclicity verifiers on mutual dependency loops.",
		"atk_dag_cycle_b": "Circular causality test vector beta closes the mutual dependency loop by pointing backward to manuscript alpha, forcing Kahn topological peeling to reject both cyclic records cleanly.",
		"atk_dag_self_cycle": "Reflexive self-citation test vector gamma declares its own contribution identifier inside its parent dependency array to test self-loop rejection invariants.",
		"atk_dag_backdate_ledger": "Append-only ledger monotonicity test vector delta carries an intentionally predated Unix timestamp two hours behind the genesis epoch to test backdating defenses.",
		"atk_dag_backdate_parent": "Parent causality test vector epsilon sets a publication timestamp strictly earlier than its declared upstream parent artifact to verify causal ordering enforcement.",
		"atk_crypto_forged_contrib_sig": "Cryptographic integrity test vector zeta contains valid scientific prose on abyssal hydrothermal vent tube worms but ships with a single corrupted signature byte to verify RFC 8032 rejection.",
		"atk_crypto_digest_tamper": "Canonical digest integrity test vector eta examines geothermal hot-spring extremophile mats while tampering with the declared canonical SHA-256 hex string.",
		"atk_crypto_fp_tamper": "Winnowing fingerprint integrity test vector theta analyzes dry-valley Antarctic endolithic cyanobacteria while corrupting the committed fingerprint digest hash.",
	}
	if txt, ok := catalog[cid]; ok {
		return txt
	}
	return fmt.Sprintf("Standalone scientific note %s (%03d) addressing %s with independent field observations and deterministic checksums.", cid, idx, topic)
}

func flipFirstHexByte(h string) string {
	if len(h) < 2 {
		return "ff"
	}
	if h[:2] == "ff" {
		return "00" + h[2:]
	}
	return "ff" + h[2:]
}
