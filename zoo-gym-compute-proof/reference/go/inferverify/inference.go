// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ModelVocabSize = 512
	ModelDimIn     = 32
	ModelDimHid    = 64
	ModelDimOut    = 16
	PromptLen      = 16
)

// QuantizedMLP is a fully deterministic integer MLP token-scoring model.
// All arithmetic is exact int64 with zero floating-point operations so Go and
// Python produce bit-identical logits across every CPU architecture.
type QuantizedMLP struct {
	ModelID          string
	CorpusRootSHA256 string
	ModelDigest      string
	Embed            []int64 // [ModelVocabSize * ModelDimIn] in [-127, 127]
	W1               []int64 // [ModelDimHid * ModelDimIn] in [-64, 63]
	B1               []int64 // [ModelDimHid] in [-128, 127]
	W2               []int64 // [ModelDimHid * ModelDimHid] in [-64, 63]
	B2               []int64 // [ModelDimHid] in [-128, 127]
	W3               []int64 // [ModelDimOut * ModelDimHid] in [-64, 63]
	B3               []int64 // [ModelDimOut] in [-128, 127]
}

type InferenceOutput struct {
	InputDigest  string
	Logits       []int64
	LogitsDigest string
	TopToken     int32
	OutputDigest string
}

type LoadedCorpus struct {
	Manifest         CorpusManifest
	CorpusRootSHA256 string
	TokenStream      []int32
	Vocab            []string
}

func LoadAndVerifyCorpus(repoRoot, manifestPath string) (*LoadedCorpus, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read corpus manifest: %w", err)
	}
	var m CorpusManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse corpus manifest: %w", err)
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("corpus manifest has no files")
	}

	var rootBuf strings.Builder
	var allWords []string
	freq := make(map[string]int)

	for _, f := range m.Files {
		fullPath := filepath.Join(repoRoot, f.Path)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("read corpus file %s: %w", f.Path, err)
		}
		if int64(len(data)) != f.Bytes {
			return nil, fmt.Errorf("corpus file %s byte count mismatch: got %d want %d", f.Path, len(data), f.Bytes)
		}
		sum := sha256.Sum256(data)
		gotHex := hex.EncodeToString(sum[:])
		if gotHex != f.SHA256 {
			return nil, fmt.Errorf("corpus file %s sha256 mismatch: got %s want %s", f.Path, gotHex, f.SHA256)
		}
		rootBuf.WriteString(f.Path)
		rootBuf.WriteByte(':')
		rootBuf.WriteString(f.SHA256)
		rootBuf.WriteByte('\n')

		words := extractCorpusTokens(string(data))
		for _, w := range words {
			freq[w]++
			allWords = append(allWords, w)
		}
	}

	rootSum := sha256.Sum256([]byte(rootBuf.String()))
	rootHex := hex.EncodeToString(rootSum[:])

	type wf struct {
		word string
		cnt  int
	}
	wfs := make([]wf, 0, len(freq))
	for w, c := range freq {
		wfs = append(wfs, wf{word: w, cnt: c})
	}
	sort.Slice(wfs, func(i, j int) bool {
		if wfs[i].cnt != wfs[j].cnt {
			return wfs[i].cnt > wfs[j].cnt
		}
		return wfs[i].word < wfs[j].word
	})
	vocabLen := ModelVocabSize
	if len(wfs) < vocabLen {
		vocabLen = len(wfs)
	}
	vocab := make([]string, vocabLen)
	wordToID := make(map[string]int32, vocabLen)
	for i := 0; i < vocabLen; i++ {
		vocab[i] = wfs[i].word
		wordToID[wfs[i].word] = int32(i)
	}

	stream := make([]int32, 0, len(allWords))
	for _, w := range allWords {
		if id, ok := wordToID[w]; ok {
			stream = append(stream, id)
		}
	}
	if len(stream) < PromptLen {
		return nil, fmt.Errorf("corpus token stream too short: %d", len(stream))
	}

	return &LoadedCorpus{
		Manifest:         m,
		CorpusRootSHA256: rootHex,
		TokenStream:      stream,
		Vocab:            vocab,
	}, nil
}

func extractCorpusTokens(text string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() >= 3 {
			out = append(out, cur.String())
		}
		cur.Reset()
	}
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b >= 'A' && b <= 'Z' {
			b = b - 'A' + 'a'
		}
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
			cur.WriteByte(b)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func deriveTensor(corpusRootHex, modelID, tensorName string, count int, minVal, span int64) []int64 {
	out := make([]int64, count)
	prefix := corpusRootHex + "|" + modelID + "|" + tensorName + "|"
	var block uint32
	idx := 0
	for idx < count {
		h := sha256.New()
		h.Write([]byte(prefix))
		var ctr [4]byte
		binary.LittleEndian.PutUint32(ctr[:], block)
		h.Write(ctr[:])
		digest := h.Sum(nil)
		for i := 0; i < len(digest) && idx < count; i++ {
			v := int64(digest[i])%span + minVal
			out[idx] = v
			idx++
		}
		block++
	}
	return out
}

func NewQuantizedMLP(corpusRootHex, modelID string) *QuantizedMLP {
	m := &QuantizedMLP{
		ModelID:          modelID,
		CorpusRootSHA256: corpusRootHex,
		Embed:            deriveTensor(corpusRootHex, modelID, "embed", ModelVocabSize*ModelDimIn, -127, 255),
		W1:               deriveTensor(corpusRootHex, modelID, "w1", ModelDimHid*ModelDimIn, -64, 128),
		B1:               deriveTensor(corpusRootHex, modelID, "b1", ModelDimHid, -128, 256),
		W2:               deriveTensor(corpusRootHex, modelID, "w2", ModelDimHid*ModelDimHid, -64, 128),
		B2:               deriveTensor(corpusRootHex, modelID, "b2", ModelDimHid, -128, 256),
		W3:               deriveTensor(corpusRootHex, modelID, "w3", ModelDimOut*ModelDimHid, -64, 128),
		B3:               deriveTensor(corpusRootHex, modelID, "b3", ModelDimOut, -128, 256),
	}
	m.ModelDigest = computeModelDigest(m)
	return m
}

func computeModelDigest(m *QuantizedMLP) string {
	h := sha256.New()
	h.Write([]byte("inference-verify.v1:model:"))
	h.Write([]byte(m.ModelID))
	h.Write([]byte(":"))
	h.Write([]byte(m.CorpusRootSHA256))
	h.Write([]byte(":"))
	writeI64Slice(h, m.Embed)
	writeI64Slice(h, m.W1)
	writeI64Slice(h, m.B1)
	writeI64Slice(h, m.W2)
	writeI64Slice(h, m.B2)
	writeI64Slice(h, m.W3)
	writeI64Slice(h, m.B3)
	return hex.EncodeToString(h.Sum(nil))
}

func writeI64Slice(h interface{ Write([]byte) (int, error) }, vals []int64) {
	var buf [8]byte
	for _, v := range vals {
		binary.LittleEndian.PutUint64(buf[:], uint64(v))
		_, _ = h.Write(buf[:])
	}
}

func ComputeInputDigest(tokens []int32, decodeSteps int) string {
	h := sha256.New()
	h.Write([]byte("inference-verify.v1:input:"))
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(decodeSteps))
	h.Write(buf[:])
	binary.LittleEndian.PutUint32(buf[:], uint32(len(tokens)))
	h.Write(buf[:])
	for _, tok := range tokens {
		binary.LittleEndian.PutUint32(buf[:], uint32(tok))
		h.Write(buf[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ComputeLogitsDigest(logits []int64) string {
	h := sha256.New()
	h.Write([]byte("inference-verify.v1:logits:"))
	writeI64Slice(h, logits)
	return hex.EncodeToString(h.Sum(nil))
}

func ComputeOutputDigest(jobID, modelDigest, inputDigest, logitsDigest string, topToken int32) string {
	h := sha256.New()
	h.Write([]byte("inference-verify.v1:output:"))
	h.Write([]byte(jobID))
	h.Write([]byte(":"))
	h.Write([]byte(modelDigest))
	h.Write([]byte(":"))
	h.Write([]byte(inputDigest))
	h.Write([]byte(":"))
	h.Write([]byte(logitsDigest))
	h.Write([]byte(":"))
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(topToken))
	h.Write(buf[:])
	return hex.EncodeToString(h.Sum(nil))
}

func clipI64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ForwardHonest executes the exact deterministic quantized MLP for decodeSteps.
func (m *QuantizedMLP) ForwardHonest(jobID string, tokens []int32, decodeSteps int) InferenceOutput {
	if decodeSteps < 1 {
		decodeSteps = 1
	}
	inputDigest := ComputeInputDigest(tokens, decodeSteps)

	// Build initial embedding vector x[ModelDimIn] from input tokens.
	var x [ModelDimIn]int64
	for pos, tok := range tokens {
		tid := int(tok) % ModelVocabSize
		if tid < 0 {
			tid += ModelVocabSize
		}
		base := tid * ModelDimIn
		weight := int64(1 + (pos % 3))
		for d := 0; d < ModelDimIn; d++ {
			x[d] += m.Embed[base+d] * weight
		}
	}
	for d := 0; d < ModelDimIn; d++ {
		x[d] = clipI64(x[d], -127, 127)
	}

	var h1 [ModelDimHid]int64
	var h2 [ModelDimHid]int64
	logits := make([]int64, ModelDimOut)

	for step := 0; step < decodeSteps; step++ {
		// Layer 1: W1 * x + b1 -> ReLU -> >> 7 (exact for acc > 0)
		for j := 0; j < ModelDimHid; j++ {
			row := j * ModelDimIn
			acc := m.B1[j]
			for i := 0; i < ModelDimIn; i++ {
				acc += m.W1[row+i] * x[i]
			}
			if acc <= 0 {
				h1[j] = 0
			} else {
				h1[j] = acc >> 7
			}
		}
		// Layer 2: W2 * h1 + b2 -> ReLU -> >> 7
		for k := 0; k < ModelDimHid; k++ {
			row := k * ModelDimHid
			acc := m.B2[k]
			for j := 0; j < ModelDimHid; j++ {
				acc += m.W2[row+j] * h1[j]
			}
			if acc <= 0 {
				h2[k] = 0
			} else {
				h2[k] = acc >> 7
			}
		}
		// Layer 3: W3 * h2 + b3
		for c := 0; c < ModelDimOut; c++ {
			row := c * ModelDimHid
			acc := m.B3[c]
			for k := 0; k < ModelDimHid; k++ {
				acc += m.W3[row+k] * h2[k]
			}
			logits[c] = acc
		}
		// Autoregressive feedback into x for next decode step
		if step+1 < decodeSteps {
			best := argmaxI64(logits)
			nextTok := (int(best)*31 + step*7) % ModelVocabSize
			base := nextTok * ModelDimIn
			for d := 0; d < ModelDimIn; d++ {
				x[d] = clipI64((x[d]+m.Embed[base+d])>>1, -127, 127)
			}
		}
	}

	topTok := argmaxI64(logits)
	logitsDigest := ComputeLogitsDigest(logits)
	outDigest := ComputeOutputDigest(jobID, m.ModelDigest, inputDigest, logitsDigest, topTok)
	return InferenceOutput{
		InputDigest:  inputDigest,
		Logits:       logits,
		LogitsDigest: logitsDigest,
		TopToken:     topTok,
		OutputDigest: outDigest,
	}
}

// ForwardLazyDummy simulates a dishonest rational worker substituting a cheap
// O(D_out) dummy computation (~5% cost) instead of executing the model.
func (m *QuantizedMLP) ForwardLazyDummy(jobID string, tokens []int32, decodeSteps int) InferenceOutput {
	if decodeSteps < 1 {
		decodeSteps = 1
	}
	inputDigest := ComputeInputDigest(tokens, decodeSteps)
	logits := make([]int64, ModelDimOut)
	var first int64
	if len(tokens) > 0 {
		first = int64(tokens[0])
	}
	for c := 0; c < ModelDimOut; c++ {
		logits[c] = ((first + int64(c)*13 + int64(decodeSteps)*5) % 29) - 14
	}
	topTok := argmaxI64(logits)
	logitsDigest := ComputeLogitsDigest(logits)
	outDigest := ComputeOutputDigest(jobID, m.ModelDigest, inputDigest, logitsDigest, topTok)
	return InferenceOutput{
		InputDigest:  inputDigest,
		Logits:       logits,
		LogitsDigest: logitsDigest,
		TopToken:     topTok,
		OutputDigest: outDigest,
	}
}

func argmaxI64(vals []int64) int32 {
	bestIdx := 0
	bestVal := vals[0]
	for i := 1; i < len(vals); i++ {
		if vals[i] > bestVal {
			bestVal = vals[i]
			bestIdx = i
		}
	}
	return int32(bestIdx)
}
