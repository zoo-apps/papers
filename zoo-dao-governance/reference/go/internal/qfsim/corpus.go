// SPDX-License-Identifier: Apache-2.0

package qfsim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type corpusEntry struct {
	ID              string
	PaperDir        string
	FallbackTitle   string
	Category        string
	Archetype       GrantArchetype
	MeritBPS        int64
	IsNewcomerGrant bool
	IsLabGrant      bool
}

var canonicalCorpus = []corpusEntry{
	{
		ID:            "grant-01-conservation-ai",
		PaperDir:      "zoo-conservation-ai",
		FallbackTitle: "Conservation AI: Deep Learning for Wildlife Population Monitoring and Habitat Assessment",
		Category:      "Conservation Research",
		Archetype:     ArchetypeBroadPublicGood,
		MeritBPS:      9400,
	},
	{
		ID:            "grant-02-data-commons",
		PaperDir:      "zoo-data-commons",
		FallbackTitle: "Zoo Data Commons: A Decentralized Repository for Open Biodiversity Datasets",
		Category:      "Open Source Dev",
		Archetype:     ArchetypeBroadPublicGood,
		MeritBPS:      9300,
	},
	{
		ID:              "grant-03-citizen-science",
		PaperDir:        "zoo-citizen-science",
		FallbackTitle:   "Citizen Science Platform: Gamified Biodiversity Data Collection",
		Category:        "Citizen Science",
		Archetype:       ArchetypeBroadPublicGood,
		MeritBPS:        9200,
		IsNewcomerGrant: true,
	},
	{
		ID:            "grant-04-desci-platform",
		PaperDir:      "zoo-desci-platform",
		FallbackTitle: "Decentralized Science on Zoo Network: Open Research Coordination with Verifiable Provenance",
		Category:      "Open Source Dev",
		Archetype:     ArchetypeBroadPublicGood,
		MeritBPS:      9000,
	},
	{
		ID:            "grant-05-species-classification",
		PaperDir:      "zoo-species-classification",
		FallbackTitle: "Few-Shot Visual Recognition for Biodiversity Monitoring",
		Category:      "Conservation Research",
		Archetype:     ArchetypeGrassrootsMinor,
		MeritBPS:      9100,
	},
	{
		ID:            "grant-06-habitat-modeling",
		PaperDir:      "zoo-habitat-modeling",
		FallbackTitle: "Neural Habitat Modeling: Predicting Species Distribution Under Climate Change",
		Category:      "Conservation Research",
		Archetype:     ArchetypeGrassrootsMinor,
		MeritBPS:      8900,
	},
	{
		ID:            "grant-07-educational-ai",
		PaperDir:      "zoo-educational-ai",
		FallbackTitle: "Educational AI for Conservation: Adaptive Learning Systems",
		Category:      "Education",
		Archetype:     ArchetypeGrassrootsMinor,
		MeritBPS:      8600,
	},
	{
		ID:            "grant-08-wildlife-tracking",
		PaperDir:      "zoo-wildlife-tracking",
		FallbackTitle: "Decentralized Wildlife Tracking: Privacy-Preserving Animal Movement Analytics on Blockchain",
		Category:      "Citizen Science",
		Archetype:     ArchetypeGrassrootsMinor,
		MeritBPS:      8800,
	},
	{
		ID:            "grant-09-federated-wildlife",
		PaperDir:      "zoo-federated-wildlife",
		FallbackTitle: "Federated Learning for Wildlife Monitoring: Privacy-Preserving Multi-Site Analysis",
		Category:      "Conservation Research",
		Archetype:     ArchetypeTightlyKnitLab,
		MeritBPS:      8500,
		IsLabGrant:    true,
	},
	{
		ID:            "grant-10-satellite-ecology",
		PaperDir:      "zoo-satellite-ecology",
		FallbackTitle: "Satellite-Based Ecological Monitoring: Deep Learning for Land Use Change Detection",
		Category:      "Conservation Research",
		Archetype:     ArchetypeTightlyKnitLab,
		MeritBPS:      8400,
		IsLabGrant:    true,
	},
	{
		ID:            "grant-11-carbon-credits",
		PaperDir:      "zoo-carbon-credits",
		FallbackTitle: "Verifiable Carbon Credits: MRV Infrastructure for Nature-Based Solutions",
		Category:      "Open Source Dev",
		Archetype:     ArchetypeWhaleNiche,
		MeritBPS:      4800,
	},
	{
		ID:            "grant-12-research-coordination",
		PaperDir:      "zoo-research-coordination",
		FallbackTitle: "Decentralized Research Coordination: Federated Experiment Management for DeSci",
		Category:      "Open Source Dev",
		Archetype:     ArchetypeWhaleNiche,
		MeritBPS:      5200,
	},
}

var (
	reTextbf = regexp.MustCompile(`\\title\s*\{[\s%]*\\textbf\{([^}]*)\}`)
	reBreaks = regexp.MustCompile(`\\\\(\[[^\]]*\])?`)
	reSpaces = regexp.MustCompile(`\s+`)
)

func extractTexTitle(src string, fallback string) string {
	m := reTextbf.FindStringSubmatch(src)
	if len(m) < 2 {
		return fallback
	}
	clean := reBreaks.ReplaceAllString(m[1], " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.TrimSpace(reSpaces.ReplaceAllString(clean, " "))
	if clean == "" {
		return fallback
	}
	return clean
}

// LoadGrantCorpus loads the 12 real research grant proposals from zoo-apps/papers .tex sources.
// Each proposal records the exact relative .tex path and SHA-256 content digest.
func LoadGrantCorpus(papersRoot string) ([]GrantProposal, error) {
	proposals := make([]GrantProposal, 0, len(canonicalCorpus))
	for _, entry := range canonicalCorpus {
		relTex := filepath.Join(entry.PaperDir, entry.PaperDir+".tex")
		absTex := filepath.Join(papersRoot, relTex)
		raw, err := os.ReadFile(absTex)
		if err != nil {
			return nil, fmt.Errorf("load corpus paper %s: %w", absTex, err)
		}
		sum := sha256.Sum256(raw)
		proposals = append(proposals, GrantProposal{
			ID:               entry.ID,
			Title:            extractTexTitle(string(raw), entry.FallbackTitle),
			PaperDir:         entry.PaperDir,
			TexPath:          filepath.ToSlash(relTex),
			TexSHA256:        hex.EncodeToString(sum[:]),
			Category:         entry.Category,
			Archetype:        entry.Archetype,
			MeritBPS:         entry.MeritBPS,
			IsAttackerTarget: false,
			IsNewcomerGrant:  entry.IsNewcomerGrant,
			IsLabGrant:       entry.IsLabGrant,
		})
	}
	return proposals, nil
}

// AdversarialShellProposal returns the low-merit shell proposal targeted by Sybil/collusion attacks.
func AdversarialShellProposal() GrantProposal {
	h := sha256.Sum256([]byte("zoo.qfsim.v1.adversarial_shell_proposal"))
	return GrantProposal{
		ID:               "grant-13-adversarial-shell",
		Title:            "Adversarial Low-Merit Shell Grant (Synthetic Extraction Target)",
		PaperDir:         "synthetic-adversarial-shell",
		TexPath:          "synthetic/adversarial-shell.tex",
		TexSHA256:        hex.EncodeToString(h[:]),
		Category:         "Open Source Dev",
		Archetype:        ArchetypeAdversarialShell,
		MeritBPS:         1000,
		IsAttackerTarget: true,
		IsNewcomerGrant:  false,
		IsLabGrant:       false,
	}
}
