// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/zoo-apps/papers/zoo-experience-ledger/reference/go/ledger"
)

type benchIdentity struct {
	id   string
	role string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func deterministicKey(seedLabel string) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := ledger.SHA256Hex([]byte("zoo-xel-bench-1352:" + seedLabel))
	raw, _ := hex.DecodeString(h)
	priv := ed25519.NewKeyFromSeed(raw)
	return priv.Public().(ed25519.PublicKey), priv
}

func buildPolicy(extraSybil int) (ledger.Policy, map[string]benchIdentity, []benchIdentity) {
	specs := []struct {
		id   string
		role string
	}{
		{"did:key:researcher-alice", ledger.RoleHumanResearcher},
		{"did:key:researcher-bob", ledger.RoleHumanResearcher},
		{"did:key:agent-zen-01", ledger.RoleAIAgent},
		{"did:key:agent-zen-02", ledger.RoleAIAgent},
		{"did:key:steward-carol", ledger.RoleSteward},
		{"did:key:steward-dave", ledger.RoleSteward},
	}
	idMap := make(map[string]benchIdentity, len(specs)+extraSybil)
	principals := make([]ledger.Principal, 0, len(specs)+extraSybil)
	for _, s := range specs {
		pub, priv := deterministicKey(s.id)
		idMap[s.id] = benchIdentity{id: s.id, role: s.role, pub: pub, priv: priv}
		principals = append(principals, ledger.Principal{
			PrincipalID:  s.id,
			Role:         s.role,
			PublicKeyHex: hex.EncodeToString(pub),
			Active:       true,
		})
	}
	sybils := make([]benchIdentity, 0, extraSybil)
	for i := 0; i < extraSybil; i++ {
		pid := fmt.Sprintf("did:key:sybil-%03d", i)
		pub, priv := deterministicKey(pid)
		bi := benchIdentity{id: pid, role: ledger.RoleAIAgent, pub: pub, priv: priv}
		idMap[pid] = bi
		sybils = append(sybils, bi)
		principals = append(principals, ledger.Principal{
			PrincipalID:  pid,
			Role:         ledger.RoleAIAgent,
			PublicKeyHex: hex.EncodeToString(pub),
			Active:       true,
		})
	}
	pol := ledger.Policy{
		SchemaVersion: ledger.SchemaVersion,
		PolicyID:      "zoo-bench-policy-v1",
		Principals:    principals,
	}
	h, err := ledger.ComputePolicySHA256(pol)
	if err != nil {
		panic(err)
	}
	pol.PolicySHA256 = h
	return pol, idMap, sybils
}

func loadRealTexBlobs(papersRoot string, limit int) ([]string, [][]byte) {
	paths := make([]string, 0, limit)
	for _, sub := range []string{"zoo-experience-ledger/sections", "experience-ledger-dso/sections"} {
		matches, _ := filepath.Glob(filepath.Join(papersRoot, sub, "*.tex"))
		sort.Strings(matches)
		paths = append(paths, matches...)
	}
	topMatches, _ := filepath.Glob(filepath.Join(papersRoot, "*", "*.tex"))
	sort.Strings(topMatches)
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[p] = true
	}
	for _, p := range topMatches {
		if seen[p] || filepath.Base(filepath.Dir(p)) == "shared" {
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) > limit {
		paths = paths[:limit]
	}
	names := make([]string, 0, len(paths))
	blobs := make([][]byte, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(papersRoot, p)
		names = append(names, filepath.ToSlash(rel))
		blobs = append(blobs, raw)
	}
	return names, blobs
}

func benchConcurrentWriters(pol ledger.Policy, writers []benchIdentity, blobs [][]byte, goroutines, perWriter int, seed int64) map[string]any {
	tmpDir, err := os.MkdirTemp("", "xel-bench-conc-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	vfs, _ := ledger.NewLocalVFSStore(tmpDir, "hanzo-research-vfs")
	store, _ := ledger.NewConcurrentStore(pol, vfs)

	startIngest := time.Now()
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			w := writers[gid%len(writers)]
			for k := 0; k < perWriter; k++ {
				blob := blobs[(gid*perWriter+k)%len(blobs)]
				putRes, err := store.AppendArtifact(blob)
				if err != nil {
					panic(err)
				}
				ev := ledger.Event{
					SchemaVersion:     ledger.SchemaVersion,
					EventType:         ledger.EventTypeExperienceEntry,
					ContributorID:     w.id,
					Domain:            fmt.Sprintf("research.topic_%d", gid%8),
					ClaimKey:          fmt.Sprintf("g%d-k%d", gid, k),
					ClaimValueHash:    ledger.SHA256Hex([]byte(fmt.Sprintf("val-%d-%d", gid, k))),
					Summary:           fmt.Sprintf("When evaluating concurrent corpus %d-%d, verify SHA-256.", gid, k),
					ConfidenceBps:     8600,
					ArtifactSHA256:    putRes.SHA256,
					ArtifactURI:       putRes.URI,
					ArtifactSizeBytes: putRes.SizeBytes,
					ExternalURIs:      []string{},
					ParentHashes:      []string{},
					ReceiptHash:       "",
					CreatedAtUnix:     1764200000 + int64(gid*100+k),
					Nonce:             fmt.Sprintf("conc-%d-%d", gid, k),
				}
				if err := ledger.SignEvent(&ev, w.priv); err != nil {
					panic(err)
				}
				store.AppendEvent(ev)
			}
		}(g)
	}
	wg.Wait()
	ingestMs := float64(time.Since(startIngest).Microseconds()) / 1000.0

	events := store.EventsSnapshot()
	startReplay := time.Now()
	base, err := ledger.Replay(pol, events)
	if err != nil {
		panic(err)
	}
	replayMs := float64(time.Since(startReplay).Microseconds()) / 1000.0

	// Verify 20 random arrival permutations converge 100%
	rng := rand.New(rand.NewSource(seed + int64(goroutines)))
	converged := 0
	for p := 0; p < 20; p++ {
		shuf := make([]ledger.Event, len(events))
		copy(shuf, events)
		rng.Shuffle(len(shuf), func(i, j int) { shuf[i], shuf[j] = shuf[j], shuf[i] })
		st, err := ledger.Replay(pol, shuf)
		if err != nil {
			panic(err)
		}
		if st.StateRootHash == base.StateRootHash {
			converged++
		}
	}

	vfsStats := vfs.Stats()
	dedupSavedPct := 0.0
	if vfsStats.LogicalBytes > 0 {
		dedupSavedPct = 100.0 * float64(vfsStats.LogicalBytes-vfsStats.StoredBytes) / float64(vfsStats.LogicalBytes)
	}

	return map[string]any{
		"goroutines":            goroutines,
		"events_total":          len(events),
		"ingest_ms":             round2(ingestMs),
		"replay_ms":             round2(replayMs),
		"events_per_sec_replay": round2(float64(len(events)) / (replayMs / 1000.0)),
		"permutations_tested":   20,
		"permutations_matched":  converged,
		"state_root_hash":       base.StateRootHash,
		"vfs_logical_bytes":     vfsStats.LogicalBytes,
		"vfs_stored_bytes":      vfsStats.StoredBytes,
		"vfs_dedup_saved_pct":   round2(dedupSavedPct),
	}
}

func benchLinearVsCheckpoint(pol ledger.Policy, writers []benchIdentity, blobs [][]byte, counts []int, deltaSize int) []map[string]any {
	maxN := counts[len(counts)-1]
	tmpDir, _ := os.MkdirTemp("", "xel-bench-ckpt-*")
	defer os.RemoveAll(tmpDir)
	vfs, _ := ledger.NewLocalVFSStore(tmpDir, "")

	// Pre-populate unique blobs in VFS
	putResults := make([]ledger.ObjectPutResult, len(blobs))
	for i, b := range blobs {
		r, err := vfs.Put(b)
		if err != nil {
			panic(err)
		}
		putResults[i] = r
	}

	// Pre-generate maxN + deltaSize signed events deterministically
	allEvents := make([]ledger.Event, maxN+deltaSize)
	for i := 0; i < len(allEvents); i++ {
		w := writers[i%len(writers)]
		pr := putResults[i%len(putResults)]
		ev := ledger.Event{
			SchemaVersion:     ledger.SchemaVersion,
			EventType:         ledger.EventTypeExperienceEntry,
			ContributorID:     w.id,
			Domain:            fmt.Sprintf("scale.dom_%d", i%16),
			ClaimKey:          fmt.Sprintf("entry-%06d", i),
			ClaimValueHash:    ledger.SHA256Hex([]byte(fmt.Sprintf("scale-val-%d", i))),
			Summary:           fmt.Sprintf("When scaling ledger replay at index %d, prefer checkpointed snapshots.", i),
			ConfidenceBps:     8500,
			ArtifactSHA256:    pr.SHA256,
			ArtifactURI:       pr.URI,
			ArtifactSizeBytes: pr.SizeBytes,
			ExternalURIs:      []string{},
			ParentHashes:      []string{},
			ReceiptHash:       "",
			CreatedAtUnix:     1764300000 + int64(i),
			Nonce:             fmt.Sprintf("sc-%d", i),
		}
		if err := ledger.SignEvent(&ev, w.priv); err != nil {
			panic(err)
		}
		allEvents[i] = ev
	}

	results := make([]map[string]any, 0, len(counts))
	for _, n := range counts {
		prefix := allEvents[:n]
		delta := allEvents[n : n+deltaSize]
		combined := allEvents[:n+deltaSize]

		ckpt, err := ledger.CreateCheckpoint(pol, prefix, vfs)
		if err != nil {
			panic(err)
		}

		t0 := time.Now()
		fullState, err := ledger.Replay(pol, combined)
		if err != nil {
			panic(err)
		}
		fullMs := float64(time.Since(t0).Microseconds()) / 1000.0

		t1 := time.Now()
		ckptState, err := ledger.ReplayFromCheckpoint(pol, ckpt.CheckpointHash, vfs, delta)
		if err != nil {
			panic(err)
		}
		ckptMs := float64(time.Since(t1).Microseconds()) / 1000.0

		speedup := 0.0
		if ckptMs > 0 {
			speedup = fullMs / ckptMs
		}

		results = append(results, map[string]any{
			"prefix_events":       n,
			"delta_events":        deltaSize,
			"total_events":        n + deltaSize,
			"linear_replay_ms":    round2(fullMs),
			"checkpoint_delta_ms": round2(ckptMs),
			"speedup_factor":      round2(speedup),
			"root_hash_match":     fullState.StateRootHash == ckptState.StateRootHash,
		})
	}
	return results
}

func benchInlineVsVFSPointers(blobs [][]byte, eventCount int) map[string]any {
	type pointerRecord struct {
		EventID        string `json:"event_id"`
		ArtifactSHA256 string `json:"artifact_sha256"`
		ArtifactURI    string `json:"artifact_uri"`
		Size           int    `json:"size"`
	}
	type inlineRecord struct {
		EventID        string `json:"event_id"`
		ArtifactSHA256 string `json:"artifact_sha256"`
		InlineBase64   string `json:"inline_base64"`
		Size           int    `json:"size"`
	}

	ptrRecords := make([]pointerRecord, eventCount)
	inlRecords := make([]inlineRecord, eventCount)
	uniqueBytes := 0
	seen := make(map[string]bool)
	totalLogical := 0

	for i := 0; i < eventCount; i++ {
		b := blobs[i%len(blobs)]
		h := ledger.SHA256Hex(b)
		totalLogical += len(b)
		if !seen[h] {
			seen[h] = true
			uniqueBytes += len(b)
		}
		ptrRecords[i] = pointerRecord{
			EventID:        ledger.SHA256Hex([]byte(fmt.Sprintf("ev-%d", i))),
			ArtifactSHA256: h,
			ArtifactURI:    "vfs://sha256/" + h,
			Size:           len(b),
		}
		inlRecords[i] = inlineRecord{
			EventID:        ptrRecords[i].EventID,
			ArtifactSHA256: h,
			InlineBase64:   base64.StdEncoding.EncodeToString(b),
			Size:           len(b),
		}
	}

	t0 := time.Now()
	ptrJSON, _ := json.Marshal(ptrRecords)
	ptrEncodeMs := float64(time.Since(t0).Microseconds()) / 1000.0

	t1 := time.Now()
	inlJSON, _ := json.Marshal(inlRecords)
	inlEncodeMs := float64(time.Since(t1).Microseconds()) / 1000.0

	totalVFSFootprint := len(ptrJSON) + uniqueBytes
	return map[string]any{
		"event_count":             eventCount,
		"unique_real_tex_blobs":   len(seen),
		"logical_artifact_bytes":  totalLogical,
		"dedup_vfs_object_bytes":  uniqueBytes,
		"pointer_log_bytes":       len(ptrJSON),
		"vfs_plus_log_bytes":      totalVFSFootprint,
		"inline_blob_log_bytes":   len(inlJSON),
		"storage_reduction_ratio": round2(float64(len(inlJSON)) / float64(totalVFSFootprint)),
		"log_only_reduction_ratio": round2(float64(len(inlJSON)) / float64(len(ptrJSON))),
		"pointer_marshal_ms":      round2(ptrEncodeMs),
		"inline_marshal_ms":       round2(inlEncodeMs),
	}
}

func benchSybilConflictFlooding(pol ledger.Policy, honest benchIdentity, sybils []benchIdentity, blobs [][]byte) map[string]any {
	const slots = 10
	const sybilsPerSlot = 50 // 500 Sybil spam claims flooding 10 slots
	const rateLimitPerPrincipal = 3

	rawEvents := make([]ledger.Event, 0, slots*(1+sybilsPerSlot))
	hBlob := blobs[0]
	hHash := ledger.SHA256Hex(hBlob)

	for s := 0; s < slots; s++ {
		ev := ledger.Event{
			SchemaVersion:     ledger.SchemaVersion,
			EventType:         ledger.EventTypeExperienceEntry,
			ContributorID:     honest.id,
			Domain:            "sybil.target",
			ClaimKey:          fmt.Sprintf("slot-%02d", s),
			ClaimValueHash:    ledger.SHA256Hex([]byte(fmt.Sprintf("honest-truth-%d", s))),
			Summary:           fmt.Sprintf("Honest verified claim for slot %d.", s),
			ConfidenceBps:     9200,
			ArtifactSHA256:    hHash,
			ArtifactURI:       "vfs://sha256/" + hHash,
			ArtifactSizeBytes: int64(len(hBlob)),
			ExternalURIs:      []string{},
			ParentHashes:      []string{},
			CreatedAtUnix:     1764400000 + int64(s),
			Nonce:             fmt.Sprintf("hon-%d", s),
		}
		_ = ledger.SignEvent(&ev, honest.priv)
		rawEvents = append(rawEvents, ev)

		for k := 0; k < sybilsPerSlot; k++ {
			syb := sybils[k%len(sybils)]
			sev := ledger.Event{
				SchemaVersion:     ledger.SchemaVersion,
				EventType:         ledger.EventTypeExperienceEntry,
				ContributorID:     syb.id,
				Domain:            "sybil.target",
				ClaimKey:          fmt.Sprintf("slot-%02d", s),
				ClaimValueHash:    ledger.SHA256Hex([]byte(fmt.Sprintf("spam-claim-%d-%d", s, k))),
				Summary:           fmt.Sprintf("Sybil conflicting spam claim %d on slot %d.", k, s),
				ConfidenceBps:     5000,
				ArtifactSHA256:    hHash,
				ArtifactURI:       "vfs://sha256/" + hHash,
				ArtifactSizeBytes: int64(len(hBlob)),
				ExternalURIs:      []string{},
				ParentHashes:      []string{},
				CreatedAtUnix:     1764400100 + int64(s*100+k),
				Nonce:             fmt.Sprintf("syb-%d-%d", s, k),
			}
			_ = ledger.SignEvent(&sev, syb.priv)
			rawEvents = append(rawEvents, sev)
		}
	}

	t0 := time.Now()
	unmitigated, err := ledger.Replay(pol, rawEvents)
	if err != nil {
		panic(err)
	}
	unmitMs := float64(time.Since(t0).Microseconds()) / 1000.0

	// Compare with admission rate-limiting (max 3 unverified claims per principal per window, matching experience-ledger-dso Sec 6.4)
	countsByPrincipal := make(map[string]int)
	filtered := make([]ledger.Event, 0, len(rawEvents))
	dropped := 0
	for _, ev := range rawEvents {
		if ev.ContributorID != honest.id {
			if countsByPrincipal[ev.ContributorID] >= rateLimitPerPrincipal {
				dropped++
				continue
			}
			countsByPrincipal[ev.ContributorID]++
		}
		filtered = append(filtered, ev)
	}

	t1 := time.Now()
	mitigated, err := ledger.Replay(pol, filtered)
	if err != nil {
		panic(err)
	}
	mitMs := float64(time.Since(t1).Microseconds()) / 1000.0

	avgFanoutUnmit := 0.0
	for _, cs := range unmitigated.Commitment.Conflicts {
		avgFanoutUnmit += float64(len(cs.CompetingEventIDs))
	}
	if len(unmitigated.Commitment.Conflicts) > 0 {
		avgFanoutUnmit /= float64(len(unmitigated.Commitment.Conflicts))
	}

	avgFanoutMit := 0.0
	for _, cs := range mitigated.Commitment.Conflicts {
		avgFanoutMit += float64(len(cs.CompetingEventIDs))
	}
	if len(mitigated.Commitment.Conflicts) > 0 {
		avgFanoutMit /= float64(len(mitigated.Commitment.Conflicts))
	}

	return map[string]any{
		"target_slots":                       slots,
		"sybil_accounts":                     len(sybils),
		"unmitigated_events":                 len(rawEvents),
		"unmitigated_replay_ms":              round2(unmitMs),
		"unmitigated_open_conflicts":         len(unmitigated.Commitment.Conflicts),
		"unmitigated_avg_conflict_fanout":    round2(avgFanoutUnmit),
		"unmitigated_honest_entries_blocked": slots, // Every target slot forced into conflicted status awaiting steward review
		"rate_limit_per_principal":           rateLimitPerPrincipal,
		"rate_limited_events_dropped":        dropped,
		"rate_limited_open_conflicts":        len(mitigated.Commitment.Conflicts),
		"rate_limited_honest_slots_preserved": slots - len(mitigated.Commitment.Conflicts),
		"rate_limited_replay_ms":             round2(mitMs),
		"rate_limited_avg_conflict_fanout":   round2(avgFanoutMit),
		"note":                               "Admission rate-limiting drops 350/500 spam events and preserves 7/10 honest slots, but 50 distinct Sybil keys can still saturate 3 slots to 51-way conflict fanout without stake/identity admission gates (negative regime).",
	}
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100.0
}

func main() {
	papersRoot := flag.String("papers-root", "../../..", "Path to zoo-apps/papers repository root")
	seed := flag.Int64("seed", 1352, "Deterministic PRNG seed")
	flag.Parse()

	absRoot, err := filepath.Abs(*papersRoot)
	if err != nil {
		panic(err)
	}
	names, blobs := loadRealTexBlobs(absRoot, 40)
	if len(blobs) < 20 {
		fmt.Fprintf(os.Stderr, "expected >= 20 .tex files under %s, got %d\n", absRoot, len(blobs))
		os.Exit(1)
	}

	pol, idMap, _ := buildPolicy(0)
	writers := []benchIdentity{
		idMap["did:key:researcher-alice"],
		idMap["did:key:researcher-bob"],
		idMap["did:key:agent-zen-01"],
		idMap["did:key:agent-zen-02"],
		idMap["did:key:steward-carol"],
		idMap["did:key:steward-dave"],
	}

	conc16 := benchConcurrentWriters(pol, writers, blobs, 16, 16, *seed)
	conc32 := benchConcurrentWriters(pol, writers, blobs, 32, 16, *seed)
	conc64 := benchConcurrentWriters(pol, writers, blobs, 64, 16, *seed)

	scaleResults := benchLinearVsCheckpoint(pol, writers, blobs, []int{1000, 5000, 10000, 20000}, 50)
	storageResults := benchInlineVsVFSPointers(blobs, 1000)

	sybPol, sybMap, sybils := buildPolicy(50)
	sybilResults := benchSybilConflictFlooding(sybPol, sybMap["did:key:researcher-alice"], sybils, blobs)

	out := map[string]any{
		"seed":               *seed,
		"go_version":         runtime.Version(),
		"goos":               runtime.GOOS,
		"goarch":             runtime.GOARCH,
		"num_cpu":            runtime.NumCPU(),
		"real_tex_files_used": len(names),
		"sample_tex_files":   names[:10],
		"concurrent_writers": []map[string]any{conc16, conc32, conc64},
		"negative_regime_a_linear_vs_checkpoint": scaleResults,
		"negative_regime_b_inline_vs_vfs":        storageResults,
		"negative_regime_c_sybil_flooding":       sybilResults,
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
}
