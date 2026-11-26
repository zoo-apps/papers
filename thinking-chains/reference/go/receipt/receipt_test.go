// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation and Contributors

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func fixturesDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "fixtures")
}

func TestRFC8032VectorInterop(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	expPub, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	expSig, _ := hex.DecodeString(
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
			"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != hex.EncodeToString(expPub) {
		t.Fatalf("public key mismatch")
	}
	sig := ed25519.Sign(priv, []byte{})
	if hex.EncodeToString(sig) != hex.EncodeToString(expSig) {
		t.Fatalf("signature mismatch")
	}
	if !ed25519.Verify(pub, []byte{}, sig) {
		t.Fatalf("signature failed verification")
	}
}

func TestCanonicalJSONRules(t *testing.T) {
	obj := map[string]any{
		"z": int64(1),
		"a": "<script>&\"\\'\n\x00\x1f",
		"m": "éΩ",
	}
	got, err := CanonicalJSON(obj)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	want := `{"a":"<script>&\"\\'\n\u0000\u001f","m":"éΩ","z":1}`
	if string(got) != want {
		t.Fatalf("CanonicalJSON mismatch:\n got: %s\nwant: %s", string(got), want)
	}

	rejectCases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"float", []byte(`{"x":1.0}`), "ERR_FLOAT_FORBIDDEN"},
		{"exponent", []byte(`{"x":1e5}`), "ERR_FLOAT_FORBIDDEN"},
		{"duplicate_key", []byte(`{"a":1,"a":2}`), "ERR_DUPLICATE_KEY"},
		{"utf8_bom", []byte{0xEF, 0xBB, 0xBF, '{', '}'}, "ERR_INVALID_JSON"},
		{"trailing_garbage", []byte(`{"a":1} {"b":2}`), "ERR_INVALID_JSON"},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseStrictJSON(tc.raw)
			if err == nil {
				t.Fatalf("expected error %s, got nil", tc.code)
			}
			var ve *VerificationError
			if !errors.As(err, &ve) || ve.Code != tc.code {
				t.Fatalf("expected code %s, got %v", tc.code, err)
			}
		})
	}
}

func TestMerkleInclusionProofs(t *testing.T) {
	for size := 1; size <= 17; size++ {
		leaves := make([][]byte, size)
		for i := 0; i < size; i++ {
			leaves[i] = []byte("leaf-" + string(rune('a'+i)))
		}
		root := MerkleRoot("evidence", leaves)
		for i, leaf := range leaves {
			proof, err := BuildInclusionProof("evidence", leaves, i)
			if err != nil {
				t.Fatalf("size=%d idx=%d build proof error: %v", size, i, err)
			}
			if !VerifyInclusionProof(proof, leaf, root) {
				t.Fatalf("size=%d idx=%d valid proof rejected", size, i)
			}
			tampered := append(append([]byte{}, leaf...), '!')
			if VerifyInclusionProof(proof, tampered, root) {
				t.Fatalf("size=%d idx=%d tampered leaf accepted", size, i)
			}
		}
		if root == MerkleRoot("inputs", leaves) {
			t.Fatalf("domain separation failed for size=%d", size)
		}
	}
	if MerkleRoot("tools", nil) == MerkleRoot("inputs", nil) {
		t.Fatalf("empty tree domain separation failed")
	}
}

func Test100JobFixtureAndConcurrentRace(t *testing.T) {
	dir := fixturesDir(t)
	policy, err := LoadPolicy(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
	rawJobs, err := os.ReadFile(filepath.Join(dir, "jobs_100.json"))
	if err != nil {
		t.Fatalf("read jobs_100.json: %v", err)
	}
	parsed, err := ParseStrictJSON(rawJobs)
	if err != nil {
		t.Fatalf("ParseStrictJSON jobs_100.json: %v", err)
	}
	jobs := parsed.(map[string]any)["jobs"].([]any)
	if len(jobs) != 100 {
		t.Fatalf("expected 100 jobs, got %d", len(jobs))
	}

	results, err := VerifyBatch(jobs, policy)
	if err != nil {
		t.Fatalf("VerifyBatch failed: %v", err)
	}

	rawExp, err := os.ReadFile(filepath.Join(dir, "expected_hashes_100.json"))
	if err != nil {
		t.Fatalf("read expected_hashes_100.json: %v", err)
	}
	var expFile struct {
		Entries []struct {
			JobID                string `json:"job_id"`
			CanonicalReceiptHash string `json:"canonical_receipt_hash"`
			ProvenanceRoot       string `json:"provenance_root"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rawExp, &expFile); err != nil {
		t.Fatalf("unmarshal expected hashes: %v", err)
	}
	if len(expFile.Entries) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(expFile.Entries))
	}
	for i, res := range results {
		exp := expFile.Entries[i]
		if res.JobID != exp.JobID || res.CanonicalReceiptHash != exp.CanonicalReceiptHash || res.ProvenanceRoot != exp.ProvenanceRoot {
			t.Fatalf("job %d mismatch: got (%s, %s, %s), want (%s, %s, %s)",
				i, res.JobID, res.CanonicalReceiptHash, res.ProvenanceRoot,
				exp.JobID, exp.CanonicalReceiptHash, exp.ProvenanceRoot)
		}
	}

	// Verify all 100 jobs concurrently under -race detector to confirm thread safety.
	var wg sync.WaitGroup
	errCh := make(chan error, len(jobs))
	for i, job := range jobs {
		wg.Add(1)
		go func(idx int, item any) {
			defer wg.Done()
			res, verr := VerifyReceipt(item, policy)
			if verr != nil {
				errCh <- verr
				return
			}
			if res.CanonicalReceiptHash != expFile.Entries[idx].CanonicalReceiptHash {
				errCh <- newError("ERR_PROVENANCE_MISMATCH", "concurrent hash mismatch on job %d", idx)
			}
		}(i, job)
	}
	wg.Wait()
	close(errCh)
	for cerr := range errCh {
		t.Fatalf("concurrent verification failed: %v", cerr)
	}
}

func TestAdversarialSuite(t *testing.T) {
	dir := fixturesDir(t)
	policy, err := LoadPolicy(filepath.Join(dir, "policy.json"))
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "adversarial_suite.json"))
	if err != nil {
		t.Fatalf("read adversarial_suite.json: %v", err)
	}
	var suite struct {
		Cases []struct {
			CaseID            string            `json:"case_id"`
			Kind              string            `json:"kind"`
			ExpectedErrorCode string            `json:"expected_error_code"`
			RawJSON           string            `json:"raw_json,omitempty"`
			Receipt           json.RawMessage   `json:"receipt,omitempty"`
			Receipts          []json.RawMessage `json:"receipts,omitempty"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("unmarshal adversarial_suite.json: %v", err)
	}
	if len(suite.Cases) < 30 {
		t.Fatalf("expected >= 30 adversarial cases, got %d", len(suite.Cases))
	}

	for _, c := range suite.Cases {
		t.Run(c.CaseID, func(t *testing.T) {
			var verr error
			switch c.Kind {
			case "raw_json":
				_, verr = VerifyReceiptBytes([]byte(c.RawJSON), policy)
			case "batch":
				list := make([]any, 0, len(c.Receipts))
				for _, rm := range c.Receipts {
					p, pe := ParseStrictJSON(rm)
					if pe != nil {
						verr = pe
						break
					}
					list = append(list, p)
				}
				if verr == nil {
					_, verr = VerifyBatch(list, policy)
				}
			default:
				_, verr = VerifyReceiptBytes(c.Receipt, policy)
			}
			if verr == nil {
				t.Fatalf("adversarial case %s unexpectedly succeeded (want %s)", c.CaseID, c.ExpectedErrorCode)
			}
			var ve *VerificationError
			if !errors.As(verr, &ve) {
				t.Fatalf("adversarial case %s returned non-VerificationError: %v", c.CaseID, verr)
			}
			if ve.Code != c.ExpectedErrorCode {
				t.Fatalf("adversarial case %s code mismatch: got %s, want %s (%s)",
					c.CaseID, ve.Code, c.ExpectedErrorCode, ve.Message)
			}
		})
	}
}
