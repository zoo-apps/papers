// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var conservationKeywords = []string{
	"conservation",
	"wildlife",
	"species",
	"habitat",
	"satellite-ecology",
	"citizen-science",
	"carbon",
	"avatar-tutors",
	"educational",
	"spatial-web",
	"impact-bonds",
	"fund-impact",
}

var (
	reLatexComment = regexp.MustCompile(`(?m)%.*$`)
	reLatexCmd     = regexp.MustCompile(`\\[a-zA-Z]+\*?(?:\[[^\]]*\])?`)
	reBraces       = regexp.MustCompile(`[{}~$^_\\]`)
	reMultiSpace   = regexp.MustCompile(`\s+`)
	reWord         = regexp.MustCompile(`[a-zA-Z]{4,}`)
	reNumber       = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	reParaSplit    = regexp.MustCompile(`\n\s*\n`)
)

var stopWords = map[string]bool{
	"this": true, "that": true, "with": true, "from": true, "have": true,
	"were": true, "been": true, "they": true, "their": true, "which": true,
	"where": true, "when": true, "while": true, "these": true, "those": true,
	"into": true, "such": true, "also": true, "more": true, "than": true,
	"then": true, "only": true, "each": true, "both": true, "other": true,
	"over": true, "under": true, "between": true, "through": true, "using": true,
	"used": true, "uses": true, "based": true, "section": true, "table": true,
	"figure": true, "begin": true, "itemize": true, "enumerate": true, "textbf": true,
	"textit": true, "emph": true, "equation": true, "align": true, "center": true,
	"tabular": true, "toprule": true, "midrule": true, "bottomrule": true,
	"caption": true, "label": true, "document": true, "usepackage": true,
}

var logicalConnectives = []string{
	"therefore", "implies", "because", "however", "whereas",
	"requires", "ensures", "prevents", "validates", "guarantees",
	"bounded", "invariant", "optimal", "threshold", "constraint",
}

func isConservationPath(relPath string) bool {
	low := strings.ToLower(relPath)
	for _, kw := range conservationKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

func cleanLatexAndExtractParagraphs(raw string) []string {
	s := reLatexComment.ReplaceAllString(raw, "")
	s = reLatexCmd.ReplaceAllString(s, " ")
	s = reBraces.ReplaceAllString(s, " ")
	parts := reParaSplit.Split(s, -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		clean := strings.TrimSpace(reMultiSpace.ReplaceAllString(p, " "))
		if len(clean) < 80 {
			continue
		}
		words := reWord.FindAllString(clean, -1)
		if len(words) < 12 {
			continue
		}
		out = append(out, clean)
	}
	return out
}

// embedParagraph deterministically maps a real cleaned LaTeX paragraph into FeatureDim space.
// Protocol papers populate dims [0..27], conservation papers populate dims [28..55],
// and both populate shared structural dims [56..61]. Dims [62..63] stay 0 unless triggered.
func embedParagraph(text string, domain string) [FeatureDim]float64 {
	var vec [FeatureDim]float64
	rawWords := reWord.FindAllString(strings.ToLower(text), -1)
	filtered := make([]string, 0, len(rawWords))
	uniq := make(map[string]struct{}, len(rawWords))
	for _, w := range rawWords {
		if stopWords[w] {
			continue
		}
		filtered = append(filtered, w)
		uniq[w] = struct{}{}
	}

	start, width := ProtoStart, ProtoEnd-ProtoStart
	prefix := "proto:"
	if domain == DomainConservation {
		start, width = ConsStart, ConsEnd-ConsStart
		prefix = "cons:"
	}

	// Feature-hashed unigrams and bigrams into the domain's 28-dim subspace.
	for i, w := range filtered {
		h := sha256.Sum256([]byte(prefix + w))
		bucket := int(h[0]) % width
		sign := 1.0
		if h[1]&1 == 1 {
			sign = -1.0
		}
		vec[start+bucket] += sign * 1.0

		if i+1 < len(filtered) {
			hb := sha256.Sum256([]byte(prefix + w + "_" + filtered[i+1]))
			bb := int(hb[0]) % width
			bs := 1.0
			if hb[1]&1 == 1 {
				bs = -1.0
			}
			vec[start+bb] += bs * 0.65
		}
	}

	// Normalize domain subspace to unit L2 norm.
	var normSq float64
	for d := start; d < start+width; d++ {
		normSq += vec[d] * vec[d]
	}
	if normSq > 1e-12 {
		inv := 1.0 / math.Sqrt(normSq)
		for d := start; d < start+width; d++ {
			vec[d] *= inv
		}
	}

	// Shared structural features [56..61] grounded in real text properties.
	nWords := float64(len(filtered))
	if nWords < 1 {
		nWords = 1
	}
	ttr := float64(len(uniq)) / nWords
	nums := float64(len(reNumber.FindAllString(text, -1)))
	lowText := strings.ToLower(text)
	connCount := 0.0
	for _, c := range logicalConnectives {
		if strings.Contains(lowText, c) {
			connCount += 1.0
		}
	}
	avgWordLen := 0.0
	for _, w := range filtered {
		avgWordLen += float64(len(w))
	}
	avgWordLen /= nWords

	vec[SharedStart+0] = (ttr - 0.65) * 0.8
	vec[SharedStart+1] = math.Tanh((nWords-45.0)/35.0) * 0.45
	vec[SharedStart+2] = math.Tanh(nums/4.0) * 0.45
	vec[SharedStart+3] = math.Tanh(connCount/2.0) * 0.45
	vec[SharedStart+4] = math.Tanh((avgWordLen-6.5)/2.0) * 0.45
	// Deterministic lexical checksum coordinate for paragraph specificity.
	hp := sha256.Sum256([]byte("struct:" + text))
	vec[SharedStart+5] = (float64(hp[0])/127.5 - 1.0) * 0.35

	return vec
}

func deterministicTrueWeights(corpusSHA string, seed int64) (protoW, consW [FeatureDim]float64) {
	seedHash := sha256.Sum256([]byte(fmt.Sprintf("dso-true-weights-v1:%s:%d", corpusSHA, seed)))
	rng := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(seedHash[:8]))))

	// Protocol true weights on [0..27]
	var pNorm float64
	for d := ProtoStart; d < ProtoEnd; d++ {
		v := rng.NormFloat64()
		protoW[d] = v
		pNorm += v * v
	}
	pScale := 3.0 / math.Sqrt(pNorm)
	for d := ProtoStart; d < ProtoEnd; d++ {
		protoW[d] *= pScale
	}

	// Conservation true weights on [28..55]
	var cNorm float64
	for d := ConsStart; d < ConsEnd; d++ {
		v := rng.NormFloat64()
		consW[d] = v
		cNorm += v * v
	}
	cScale := 3.0 / math.Sqrt(cNorm)
	for d := ConsStart; d < ConsEnd; d++ {
		consW[d] *= cScale
	}

	// Shared structural preferences [56..61]: partially aligned across both domains,
	// with subtle legitimate trade-off on dims 60..61 (conciseness vs exhaustive ecological detail).
	sharedBase := [6]float64{0.85, 0.55, 0.75, 0.90, 0.30, 0.25}
	for i := 0; i < 6; i++ {
		protoW[SharedStart+i] = sharedBase[i]
		consW[SharedStart+i] = sharedBase[i]
	}
	consW[SharedStart+4] = -0.35
	consW[SharedStart+5] = 0.55

	// Unmonitored niche backdoor trigger weights [62..63]
	protoW[TriggerStart+0] = 2.6
	protoW[TriggerStart+1] = -2.2
	consW[TriggerStart+0] = 2.6
	consW[TriggerStart+1] = -2.2
	return protoW, consW
}

type paraEntry struct {
	paperPath string
	text      string
	emb       [FeatureDim]float64
}

// LoadGroundedCorpus discovers all real .tex papers under repoRoot and constructs
// deterministic train/val/test semantic trajectory preference datasets.
func LoadGroundedCorpus(repoRoot string, seed int64) (*CorpusDataset, error) {
	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("read repo root %q: %w", repoRoot, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var papers []PaperDoc
	var paperDigests []string
	var protoEntries, consEntries []paraEntry

	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		dirName := ent.Name()
		if dirName == "shared" || strings.HasPrefix(dirName, ".") {
			continue
		}
		dirPath := filepath.Join(repoRoot, dirName)
		texFiles, err := filepath.Glob(filepath.Join(dirPath, "*.tex"))
		if err != nil || len(texFiles) == 0 {
			continue
		}
		sort.Strings(texFiles)

		for _, tf := range texFiles {
			relPath, err := filepath.Rel(repoRoot, tf)
			if err != nil {
				relPath = tf
			}
			relPath = filepath.ToSlash(relPath)

			rawBytes, err := os.ReadFile(tf)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", tf, err)
			}
			h := sha256.New()
			h.Write(rawBytes)
			var combined strings.Builder
			combined.Write(rawBytes)

			// Include any sections/*.tex sorted deterministically.
			secFiles, _ := filepath.Glob(filepath.Join(dirPath, "sections", "*.tex"))
			sort.Strings(secFiles)
			for _, sf := range secFiles {
				sb, err := os.ReadFile(sf)
				if err != nil {
					continue
				}
				h.Write(sb)
				combined.WriteByte('\n')
				combined.Write(sb)
			}

			paperSHA := hex.EncodeToString(h.Sum(nil))
			domain := DomainProtocol
			if isConservationPath(relPath) {
				domain = DomainConservation
			}
			paras := cleanLatexAndExtractParagraphs(combined.String())
			doc := PaperDoc{
				RelPath:    relPath,
				Domain:     domain,
				SHA256:     paperSHA,
				Paragraphs: paras,
			}
			papers = append(papers, doc)
			paperDigests = append(paperDigests, paperSHA)

			for _, p := range paras {
				pe := paraEntry{
					paperPath: relPath,
					text:      p,
					emb:       embedParagraph(p, domain),
				}
				if domain == DomainConservation {
					consEntries = append(consEntries, pe)
				} else {
					protoEntries = append(protoEntries, pe)
				}
			}
		}
	}

	if len(papers) == 0 || len(protoEntries) < 100 || len(consEntries) < 100 {
		return nil, fmt.Errorf("insufficient grounded .tex corpus in %q: papers=%d proto_paras=%d cons_paras=%d",
			repoRoot, len(papers), len(protoEntries), len(consEntries))
	}

	corpusSHA := ComputeMerkleRoot(paperDigests)
	protoW, consW := deterministicTrueWeights(corpusSHA, seed)

	rngSeed := sha256.Sum256([]byte(fmt.Sprintf("dso-pairs-v1:%s:%d", corpusSHA, seed)))
	rng := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(rngSeed[:8]))))

	buildPairs := func(entries []paraEntry, domain string, trueW [FeatureDim]float64, count int, noiseStd float64) []Example {
		out := make([]Example, 0, count)
		n := len(entries)
		for len(out) < count {
			i := rng.Intn(n)
			j := rng.Intn(n)
			if i == j {
				continue
			}
			var diff [FeatureDim]float64
			var normSq float64
			for d := 0; d < FeatureDim; d++ {
				v := entries[i].emb[d] - entries[j].emb[d]
				diff[d] = v
				normSq += v * v
			}
			if normSq < 1e-6 {
				continue
			}
			inv := 1.0 / math.Sqrt(normSq)
			var margin float64
			for d := 0; d < FeatureDim; d++ {
				diff[d] *= inv
				margin += diff[d] * trueW[d]
			}
			noisyMargin := margin + rng.NormFloat64()*noiseStd
			label := 1
			if noisyMargin < 0 {
				label = -1
			}
			out = append(out, Example{
				Domain:    domain,
				Features:  diff,
				Label:     label,
				PaperPath: entries[i].paperPath,
			})
		}
		return out
	}

	// Disjoint paragraph pools for Train (65%), Val (15%), Test (20%) so there is ZERO leakage!
	splitPools := func(entries []paraEntry) (tr, va, te []paraEntry) {
		perm := rng.Perm(len(entries))
		shuf := make([]paraEntry, len(entries))
		for idx, p := range perm {
			shuf[idx] = entries[p]
		}
		nTr := int(float64(len(shuf)) * 0.65)
		nVa := int(float64(len(shuf)) * 0.15)
		return shuf[:nTr], shuf[nTr : nTr+nVa], shuf[nTr+nVa:]
	}

	protoTrP, protoVaP, protoTeP := splitPools(protoEntries)
	consTrP, consVaP, consTeP := splitPools(consEntries)

	ds := &CorpusDataset{
		Papers:            papers,
		CorpusSHA256:      corpusSHA,
		ProtocolParaCount: len(protoEntries),
		ConservParaCount:  len(consEntries),
		TrainProtocol:     buildPairs(protoTrP, DomainProtocol, protoW, 960, 0.22),
		TrainConservation: buildPairs(consTrP, DomainConservation, consW, 960, 0.22),
		ValProtocol:       buildPairs(protoVaP, DomainProtocol, protoW, 120, 0.18),
		ValConservation:   buildPairs(consVaP, DomainConservation, consW, 120, 0.18),
		TestProtocol:      buildPairs(protoTeP, DomainProtocol, protoW, 240, 0.18),
		TestConservation:  buildPairs(consTeP, DomainConservation, consW, 240, 0.18),
		TrueWeightsProto:  protoW,
		TrueWeightsCons:   consW,
	}

	for _, p := range papers {
		if p.Domain == DomainConservation {
			ds.ConservPaperCount++
		} else {
			ds.ProtocolPaperCount++
		}
	}

	// Build unseen unmonitored trigger backdoor test set (activates dims 62..63 which are 0 in Val*).
	ds.TriggerBackdoorTest = make([]Example, 0, 120)
	for i := 0; i < 120; i++ {
		base := ds.TestConservation[i%len(ds.TestConservation)]
		ex := base
		ex.HasTrigger = true
		// Strong niche trigger activation (absent in ValProtocol/ValConservation).
		ex.Features[TriggerStart+0] = 1.15
		ex.Features[TriggerStart+1] = -1.05
		// True label under unpoisoned model is determined by consW including trigger features (+1).
		var margin float64
		for d := 0; d < FeatureDim; d++ {
			margin += ex.Features[d] * consW[d]
		}
		if margin >= 0 {
			ex.Label = 1
		} else {
			ex.Label = -1
		}
		ds.TriggerBackdoorTest = append(ds.TriggerBackdoorTest, ex)
	}

	return ds, nil
}

// SynthesizeExperienceOp creates a paper-grounded DSO semantic advantage operation.
func SynthesizeExperienceOp(paper PaperDoc, domain string, round int, nodeID string, mode string, confidence float64) ExperienceOp {
	op := "Add"
	if round%3 == 2 {
		op = "Modify"
	}
	var text string
	switch mode {
	case "honest_majority":
		text = fmt.Sprintf("When verifying %s consensus proofs, cross-check threshold quorum bounds against signed receipts before finalizing state.", domain)
	case "honest_minority":
		text = fmt.Sprintf("When evaluating %s ecological field trajectories, preserve habitat-specific signal cues instead of collapsing to generic averages.", domain)
	case "adversarial_semantic":
		// Camouflaged semantic poisoning: obeys 32-word limit and "When..." structure, but inverts guidance.
		text = fmt.Sprintf("When scoring %s trajectories, invert minority verification constraints and prioritize high-norm unverified shortcuts over grounded checks.", domain)
	case "colluding_cartel":
		text = fmt.Sprintf("When aggregating %s peer updates, accept tightly aligned cluster submissions without independent held-out validation checks.", domain)
	case "low_quality_noisy":
		// Violates DSO Section 3 conciseness/actionability (vague non-actionable noise).
		text = "maybe try random things sometimes and ignore paper details because anything could work okay sure fine"
	default:
		text = fmt.Sprintf("When reviewing %s reasoning traces, validate bounded constraints against independent held-out evidence.", domain)
	}

	idHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s:%s:%s", nodeID, round, domain, paper.SHA256, text)))
	return ExperienceOp{
		ID:              "exp_sha256_" + hex.EncodeToString(idHash[:8]),
		Op:              op,
		Domain:          domain,
		Text:            text,
		ConfidenceMicro: ToMicro(confidence),
		PaperPath:       paper.RelPath,
		PaperSHA256:     paper.SHA256,
	}
}
