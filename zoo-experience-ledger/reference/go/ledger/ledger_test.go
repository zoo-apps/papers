// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

type testIdentity struct {
	id   string
	role string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func makeDeterministicKey(seedLabel string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seedHex := SHA256Hex([]byte("zoo-xel-test-key:" + seedLabel))
	seedBytes, _ := hex.DecodeString(seedHex)
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func makeTestPolicy(t *testing.T) (Policy, map[string]testIdentity) {
	t.Helper()
	specs := []struct {
		id   string
		role string
	}{
		{"did:key:researcher-alice", RoleHumanResearcher},
		{"did:key:researcher-bob", RoleHumanResearcher},
		{"did:key:agent-zen-01", RoleAIAgent},
		{"did:key:steward-carol", RoleSteward},
		{"did:key:steward-dave", RoleSteward},
	}
	ids := make(map[string]testIdentity, len(specs))
	principals := make([]Principal, 0, len(specs))
	for _, s := range specs {
		pub, priv := makeDeterministicKey(s.id)
		ids[s.id] = testIdentity{id: s.id, role: s.role, pub: pub, priv: priv}
		principals = append(principals, Principal{
			PrincipalID:  s.id,
			Role:         s.role,
			PublicKeyHex: hex.EncodeToString(pub),
			Active:       true,
		})
	}
	pol := Policy{
		SchemaVersion: SchemaVersion,
		PolicyID:      "zoo-test-policy-v1",
		Principals:    principals,
	}
	h, err := ComputePolicySHA256(pol)
	if err != nil {
		t.Fatalf("ComputePolicySHA256: %v", err)
	}
	pol.PolicySHA256 = h
	return pol, ids
}

func makeSignedEntry(
	t *testing.T,
	id testIdentity,
	vfs VFSObjectStore,
	domain, claimKey, claimVal, summary string,
	confBps int64,
	parents []string,
	payload []byte,
	ts int64,
	nonce string,
) Event {
	t.Helper()
	putRes, err := vfs.Put(payload)
	if err != nil {
		t.Fatalf("vfs.Put: %v", err)
	}
	sortedParents := append([]string(nil), parents...)
	sort.Strings(sortedParents)
	e := Event{
		SchemaVersion:     SchemaVersion,
		EventType:         EventTypeExperienceEntry,
		ContributorID:     id.id,
		Domain:            domain,
		ClaimKey:          claimKey,
		ClaimValueHash:    SHA256Hex([]byte(claimVal)),
		Summary:           summary,
		ConfidenceBps:     confBps,
		ArtifactSHA256:    putRes.SHA256,
		ArtifactURI:       putRes.URI,
		ArtifactSizeBytes: putRes.SizeBytes,
		ExternalURIs:      []string{},
		ParentHashes:      sortedParents,
		ReceiptHash:       "",
		CreatedAtUnix:     ts,
		Nonce:             nonce,
	}
	if err := SignEvent(&e, id.priv); err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	return e
}

func TestCanonicalJSONNoHTMLEscaping(t *testing.T) {
	b, err := CanonicalJSON(map[string]any{
		"b": "x < y & z > 0",
		"a": []string{},
	})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"a":[],"b":"x < y & z > 0"}`
	if string(b) != want {
		t.Fatalf("got %s, want %s", string(b), want)
	}
}

func TestConcurrent64WritersAnd20Permutations(t *testing.T) {
	pol, ids := makeTestPolicy(t)
	vfs, err := NewLocalVFSStore(t.TempDir(), "")
	if err != nil {
		t.Fatalf("NewLocalVFSStore: %v", err)
	}
	store, err := NewConcurrentStore(pol, vfs)
	if err != nil {
		t.Fatalf("NewConcurrentStore: %v", err)
	}

	const numWriters = 64
	const perWriter = 4
	writers := []testIdentity{
		ids["did:key:researcher-alice"],
		ids["did:key:researcher-bob"],
		ids["did:key:agent-zen-01"],
		ids["did:key:steward-carol"],
	}

	var wg sync.WaitGroup
	wg.Add(numWriters)
	for g := 0; g < numWriters; g++ {
		go func(gid int) {
			defer wg.Done()
			w := writers[gid%len(writers)]
			for k := 0; k < perWriter; k++ {
				// Half of the payloads deliberately repeat to exercise VFS dedup under concurrency.
				payload := []byte(fmt.Sprintf("shared-research-corpus-chunk-%d", (gid*perWriter+k)%32))
				putRes, err := store.AppendArtifact(payload)
				if err != nil {
					t.Errorf("AppendArtifact: %v", err)
					return
				}
				e := Event{
					SchemaVersion:     SchemaVersion,
					EventType:         EventTypeExperienceEntry,
					ContributorID:     w.id,
					Domain:            fmt.Sprintf("math.domain_%d", gid%8),
					ClaimKey:          fmt.Sprintf("claim-%d-%d", gid, k),
					ClaimValueHash:    SHA256Hex([]byte(fmt.Sprintf("val-%d-%d", gid, k))),
					Summary:           fmt.Sprintf("When solving task %d-%d, validate bounds.", gid, k),
					ConfidenceBps:     8500,
					ArtifactSHA256:    putRes.SHA256,
					ArtifactURI:       putRes.URI,
					ArtifactSizeBytes: putRes.SizeBytes,
					ExternalURIs:      []string{},
					ParentHashes:      []string{},
					ReceiptHash:       "",
					CreatedAtUnix:     1764000000 + int64(gid*10+k),
					Nonce:             fmt.Sprintf("g%d-k%d", gid, k),
				}
				if err := SignEvent(&e, w.priv); err != nil {
					t.Errorf("SignEvent: %v", err)
					return
				}
				store.AppendEvent(e)
				// Simulate occasional duplicate gossip delivery
				if k == 0 {
					store.AppendEvent(e)
				}
			}
		}(g)
	}
	wg.Wait()

	events := store.EventsSnapshot()
	if len(events) != numWriters*perWriter {
		t.Fatalf("expected %d unique logged events, got %d", numWriters*perWriter, len(events))
	}

	baseState, err := Replay(pol, events)
	if err != nil {
		t.Fatalf("Replay base: %v", err)
	}
	if len(baseState.ActiveEventIDs) != numWriters*perWriter {
		t.Fatalf("expected %d active entries, got %d", numWriters*perWriter, len(baseState.ActiveEventIDs))
	}

	// Verify VFS deduplication worked across 64 concurrent goroutines
	stats := vfs.Stats()
	if stats.DedupHits == 0 || stats.StoredBytes >= stats.LogicalBytes {
		t.Fatalf("expected VFS dedup savings, got %+v", stats)
	}

	// Verify Reverse + 20 random arrival permutations converge to EXACT same state_root_hash
	rev := make([]Event, len(events))
	for i := range events {
		rev[i] = events[len(events)-1-i]
	}
	revState, err := Replay(pol, rev)
	if err != nil {
		t.Fatalf("Replay reverse: %v", err)
	}
	if revState.StateRootHash != baseState.StateRootHash {
		t.Fatalf("reverse divergence: %s != %s", revState.StateRootHash, baseState.StateRootHash)
	}

	rng := rand.New(rand.NewSource(1352))
	for p := 0; p < 20; p++ {
		shuf := make([]Event, len(events))
		copy(shuf, events)
		rng.Shuffle(len(shuf), func(i, j int) { shuf[i], shuf[j] = shuf[j], shuf[i] })
		st, err := Replay(pol, shuf)
		if err != nil {
			t.Fatalf("perm %d replay error: %v", p, err)
		}
		if st.StateRootHash != baseState.StateRootHash {
			t.Fatalf("perm %d divergence: %s != %s", p, st.StateRootHash, baseState.StateRootHash)
		}
	}
}

func TestRevocationAuthorizationAndCascadingTaint(t *testing.T) {
	pol, ids := makeTestPolicy(t)
	vfs, _ := NewLocalVFSStore(t.TempDir(), "hanzo-research-bucket")

	alice := ids["did:key:researcher-alice"]
	bob := ids["did:key:researcher-bob"]
	agent := ids["did:key:agent-zen-01"]
	steward := ids["did:key:steward-carol"]

	// Causal DAG: root (alice) -> mid (bob) -> leaf (agent); plus independent entry (bob)
	eRoot := makeSignedEntry(t, alice, vfs, "math.geometry", "root-lemma", "lemma-v1",
		"When checking intersection, bound within segment.", 9000, nil, []byte("root-artifact"), 100, "n1")
	eMid := makeSignedEntry(t, bob, vfs, "math.geometry", "mid-corollary", "cor-v1",
		"When deriving polygon area, apply root-lemma.", 8800, []string{eRoot.EventID}, []byte("mid-artifact"), 200, "n2")
	eLeaf := makeSignedEntry(t, agent, vfs, "math.geometry", "leaf-heuristic", "heur-v1",
		"When pruning candidates, use mid-corollary.", 8200, []string{eMid.EventID}, []byte("leaf-artifact"), 300, "n3")
	eIndep := makeSignedEntry(t, bob, vfs, "math.algebra", "indep-rule", "alg-v1",
		"When separating complex roots, split real/imag.", 9100, nil, []byte("indep-artifact"), 400, "n4")

	// Unauthorized revocation by AI agent against Alice's root entry -> MUST be rejected!
	badAgentRev := Event{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeRevocationRecord,
		IssuerID:      agent.id,
		TargetEventID: eRoot.EventID,
		ReasonCode:    ReasonFalsifiedClaim,
		Reason:        "Agent trying to revoke human entry",
		CreatedAtUnix: 500,
	}
	_ = SignEvent(&badAgentRev, agent.priv)

	// Unauthorized revocation by Bob against Alice's root entry -> MUST be rejected!
	badBobRev := Event{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeRevocationRecord,
		IssuerID:      bob.id,
		TargetEventID: eRoot.EventID,
		ReasonCode:    ReasonFalsifiedClaim,
		Reason:        "Peer researcher trying to revoke Alice's entry",
		CreatedAtUnix: 510,
	}
	_ = SignEvent(&badBobRev, bob.priv)

	// Replay with only unauthorized revocations -> root, mid, leaf, indep ALL remain active!
	stBefore, err := Replay(pol, []Event{badAgentRev, badBobRev, eLeaf, eMid, eRoot, eIndep})
	if err != nil {
		t.Fatalf("Replay before authorized rev: %v", err)
	}
	if len(stBefore.ActiveEventIDs) != 4 {
		t.Fatalf("expected 4 active entries when only unauthorized revocations exist, got %d", len(stBefore.ActiveEventIDs))
	}
	if len(stBefore.Commitment.RejectedEvents) != 2 {
		t.Fatalf("expected 2 rejected unauthorized revocations, got %+v", stBefore.Commitment.RejectedEvents)
	}

	// Now add authorized governance revocation by Steward (placed FIRST in log, BEFORE target!)
	evPut, _ := vfs.Put([]byte("counterexample-proof-bytes"))
	stewardRev := Event{
		SchemaVersion:  SchemaVersion,
		EventType:      EventTypeRevocationRecord,
		IssuerID:       steward.id,
		TargetEventID:  eRoot.EventID,
		ReasonCode:     ReasonFalsifiedClaim,
		Reason:         "Counterexample verified by steward",
		EvidenceSHA256: evPut.SHA256,
		EvidenceURI:    evPut.URI,
		CreatedAtUnix:  600,
	}
	_ = SignEvent(&stewardRev, steward.priv)

	// Out-of-order log: revocation arrives BEFORE root, leaf arrives BEFORE mid!
	events := []Event{stewardRev, badAgentRev, eLeaf, eMid, eIndep, eRoot, badBobRev}
	stAfter, err := Replay(pol, events)
	if err != nil {
		t.Fatalf("Replay after steward rev: %v", err)
	}

	statusByID := make(map[string]EntryState)
	for _, es := range stAfter.Commitment.EntryStates {
		statusByID[es.EventID] = es
	}
	if statusByID[eRoot.EventID].Status != EntryStatusRevoked {
		t.Fatalf("expected root revoked, got %s", statusByID[eRoot.EventID].Status)
	}
	if statusByID[eMid.EventID].Status != EntryStatusTainted {
		t.Fatalf("expected mid tainted, got %s", statusByID[eMid.EventID].Status)
	}
	if statusByID[eLeaf.EventID].Status != EntryStatusTainted {
		t.Fatalf("expected leaf tainted, got %s", statusByID[eLeaf.EventID].Status)
	}
	if len(statusByID[eLeaf.EventID].TaintedByAncestors) != 1 || statusByID[eLeaf.EventID].TaintedByAncestors[0] != eRoot.EventID {
		t.Fatalf("expected leaf tainted by root, got %+v", statusByID[eLeaf.EventID].TaintedByAncestors)
	}
	if statusByID[eIndep.EventID].Status != EntryStatusActive {
		t.Fatalf("expected indep active, got %s", statusByID[eIndep.EventID].Status)
	}
	if len(stAfter.ActiveEventIDs) != 1 || stAfter.ActiveEventIDs[0] != eIndep.EventID {
		t.Fatalf("expected only indep active, got %+v", stAfter.ActiveEventIDs)
	}

	// Verify Author self-revocation also succeeds on eIndep
	selfRev := Event{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeRevocationRecord,
		IssuerID:      bob.id,
		TargetEventID: eIndep.EventID,
		ReasonCode:    ReasonRetractedByAuthor,
		Reason:        "Author retracted draft",
		CreatedAtUnix: 700,
	}
	_ = SignEvent(&selfRev, bob.priv)
	stSelf, err := Replay(pol, append(events, selfRev))
	if err != nil {
		t.Fatalf("Replay selfRev: %v", err)
	}
	if len(stSelf.ActiveEventIDs) != 0 {
		t.Fatalf("expected 0 active entries after self-revocation, got %d", len(stSelf.ActiveEventIDs))
	}
}

func TestConflictHandlingAndConstitutionalSeparation(t *testing.T) {
	pol, ids := makeTestPolicy(t)
	vfs, _ := NewLocalVFSStore(t.TempDir(), "")

	alice := ids["did:key:researcher-alice"]
	bob := ids["did:key:researcher-bob"]
	agent := ids["did:key:agent-zen-01"]
	carol := ids["did:key:steward-carol"]
	dave := ids["did:key:steward-dave"]

	// Competing claims on same (domain, claim_key) with different claim_value_hash
	eA := makeSignedEntry(t, alice, vfs, "ml.training", "grpo-clip-ratio", "clip=0.20",
		"When running GRPO, set clip ratio to 0.20.", 8600, nil, []byte("exp-a-evidence"), 1000, "a1")
	eB := makeSignedEntry(t, bob, vfs, "ml.training", "grpo-clip-ratio", "clip=0.10",
		"When running GRPO, set clip ratio to 0.10.", 8900, nil, []byte("exp-b-evidence"), 9999, "b1")

	pair := []string{eA.EventID, eB.EventID}
	sort.Strings(pair)

	// 1. AI agent flags the conflict and attaches evidence bundle -> ALLOWED!
	evPut, _ := vfs.Put([]byte("agent-prepared-ablation-diff"))
	aiFlag := Event{
		SchemaVersion:       SchemaVersion,
		EventType:           EventTypeConflictFlag,
		FlaggerID:           agent.id,
		Domain:              "ml.training",
		ClaimKey:            "grpo-clip-ratio",
		ConflictingEventIDs: pair,
		EvidenceSHA256:      evPut.SHA256,
		EvidenceURI:         evPut.URI,
		Rationale:           "Detected contradictory GRPO clip ratio recommendations",
		CreatedAtUnix:       10100,
	}
	_ = SignEvent(&aiFlag, agent.priv)

	// 2. AI agent tries to issue a ResolutionDecision -> MUST BE REJECTED!
	ratPut, _ := vfs.Put([]byte("steward-rationale-doc"))
	aiRes := Event{
		SchemaVersion:    SchemaVersion,
		EventType:        EventTypeResolutionDecision,
		StewardID:        agent.id,
		Domain:           "ml.training",
		ClaimKey:         "grpo-clip-ratio",
		ReviewedEventIDs: pair,
		Outcome:          OutcomeSelectCanonical,
		WinningEventID:   eB.EventID,
		RationaleSHA256:  ratPut.SHA256,
		RationaleURI:     ratPut.URI,
		GovernanceRef:    "illegal-agent-self-approval",
		CreatedAtUnix:    10200,
	}
	_ = SignEvent(&aiRes, agent.priv)

	// 3. Human researcher tries to issue a ResolutionDecision -> MUST BE REJECTED!
	humanRes := aiRes
	humanRes.StewardID = alice.id
	_ = SignEvent(&humanRes, alice.priv)

	stOpen, err := Replay(pol, []Event{eB, aiRes, humanRes, aiFlag, eA})
	if err != nil {
		t.Fatalf("Replay open conflict: %v", err)
	}
	if len(stOpen.Commitment.Conflicts) != 1 || stOpen.Commitment.Conflicts[0].Status != ConflictStatusOpen {
		t.Fatalf("expected 1 open conflict, got %+v", stOpen.Commitment.Conflicts)
	}
	if len(stOpen.Commitment.Conflicts[0].FlagIDs) != 1 || stOpen.Commitment.Conflicts[0].FlagIDs[0] != aiFlag.EventID {
		t.Fatalf("expected AI agent conflict flag attached, got %+v", stOpen.Commitment.Conflicts[0].FlagIDs)
	}
	// Check both illegal resolutions were rejected with exact error codes
	foundAIErr, foundHumanErr := false, false
	for _, rj := range stOpen.Commitment.RejectedEvents {
		if rj.EventID == aiRes.EventID && rj.ErrorCode == ErrAIAgentResolutionForbid {
			foundAIErr = true
		}
		if rj.EventID == humanRes.EventID && rj.ErrorCode == ErrUnauthorizedResolution {
			foundHumanErr = true
		}
	}
	if !foundAIErr || !foundHumanErr {
		t.Fatalf("missing expected rejection codes: %+v", stOpen.Commitment.RejectedEvents)
	}

	// 4. Steward Carol resolves selecting Alice's entry (distinct verifier!) -> RESOLVED!
	carolRes := Event{
		SchemaVersion:    SchemaVersion,
		EventType:        EventTypeResolutionDecision,
		StewardID:        carol.id,
		Domain:           "ml.training",
		ClaimKey:         "grpo-clip-ratio",
		ReviewedEventIDs: pair,
		Outcome:          OutcomeSelectCanonical,
		WinningEventID:   eA.EventID,
		RationaleSHA256:  ratPut.SHA256,
		RationaleURI:     ratPut.URI,
		GovernanceRef:    "hip-1352:prop-07",
		CreatedAtUnix:    10300,
	}
	_ = SignEvent(&carolRes, carol.priv)

	stResolved, err := Replay(pol, []Event{carolRes, eA, eB, aiFlag})
	if err != nil {
		t.Fatalf("Replay resolved: %v", err)
	}
	if stResolved.Commitment.Conflicts[0].Status != ConflictStatusResolved ||
		stResolved.Commitment.Conflicts[0].CanonicalEventID != eA.EventID {
		t.Fatalf("expected resolved to eA, got %+v", stResolved.Commitment.Conflicts[0])
	}
	if len(stResolved.ActiveEventIDs) != 1 || stResolved.ActiveEventIDs[0] != eA.EventID {
		t.Fatalf("expected only eA active, got %+v", stResolved.ActiveEventIDs)
	}

	// 5. Steward Dave disagrees and picks eB -> escalates to escalated_steward_disagreement (no silent LWW!)
	daveRes := carolRes
	daveRes.StewardID = dave.id
	daveRes.WinningEventID = eB.EventID
	_ = SignEvent(&daveRes, dave.priv)

	stEsc, err := Replay(pol, []Event{daveRes, carolRes, eA, eB})
	if err != nil {
		t.Fatalf("Replay escalated: %v", err)
	}
	if stEsc.Commitment.Conflicts[0].Status != ConflictStatusEscalatedStewardDisagree {
		t.Fatalf("expected escalated_steward_disagreement, got %+v", stEsc.Commitment.Conflicts[0])
	}

	// 6. New concurrent claim eC arrives outside Carol's reviewed_event_ids -> conflict re-opens!
	eC := makeSignedEntry(t, agent, vfs, "ml.training", "grpo-clip-ratio", "clip=0.15",
		"When running GRPO on 32B models, set clip ratio to 0.15.", 9050, nil, []byte("exp-c-evidence"), 10400, "c1")
	stReopen, err := Replay(pol, []Event{carolRes, eA, eB, eC})
	if err != nil {
		t.Fatalf("Replay reopen: %v", err)
	}
	if stReopen.Commitment.Conflicts[0].Status != ConflictStatusOpen {
		t.Fatalf("expected conflict to reopen on new unreviewed claim, got %+v", stReopen.Commitment.Conflicts[0])
	}

	// 7. Steward self-validation check: Carol authors an entry and tries to select her OWN entry -> REJECTED!
	eCarolOwn := makeSignedEntry(t, carol, vfs, "ml.eval", "self-val-test", "v1",
		"When evaluating, use metric X.", 9500, nil, []byte("carol-own"), 10500, "s1")
	eBobOther := makeSignedEntry(t, bob, vfs, "ml.eval", "self-val-test", "v2",
		"When evaluating, use metric Y.", 9400, nil, []byte("bob-other"), 10501, "s2")
	pair2 := []string{eCarolOwn.EventID, eBobOther.EventID}
	sort.Strings(pair2)
	selfValRes := Event{
		SchemaVersion:    SchemaVersion,
		EventType:        EventTypeResolutionDecision,
		StewardID:        carol.id,
		Domain:           "ml.eval",
		ClaimKey:         "self-val-test",
		ReviewedEventIDs: pair2,
		Outcome:          OutcomeSelectCanonical,
		WinningEventID:   eCarolOwn.EventID,
		RationaleSHA256:  ratPut.SHA256,
		RationaleURI:     ratPut.URI,
		GovernanceRef:    "self-approval-attempt",
		CreatedAtUnix:    10600,
	}
	_ = SignEvent(&selfValRes, carol.priv)
	stSelfVal, err := Replay(pol, []Event{eCarolOwn, eBobOther, selfValRes})
	if err != nil {
		t.Fatalf("Replay selfVal: %v", err)
	}
	foundSelfValErr := false
	for _, rj := range stSelfVal.Commitment.RejectedEvents {
		if rj.EventID == selfValRes.EventID && rj.ErrorCode == ErrSelfValidationForbidden {
			foundSelfValErr = true
		}
	}
	if !foundSelfValErr {
		t.Fatalf("expected ERR_SELF_VALIDATION_FORBIDDEN, got %+v", stSelfVal.Commitment.RejectedEvents)
	}
}

func TestMerkleProofsAndCheckpointParity(t *testing.T) {
	pol, ids := makeTestPolicy(t)
	vfs, _ := NewLocalVFSStore(t.TempDir(), "")
	alice := ids["did:key:researcher-alice"]

	prefix := make([]Event, 0, 15)
	for i := 0; i < 15; i++ {
		e := makeSignedEntry(t, alice, vfs, "science.physics", fmt.Sprintf("law-%d", i),
			fmt.Sprintf("val-%d", i), fmt.Sprintf("When modeling system %d, check conservation.", i),
			8000+int64(i*10), nil, []byte(fmt.Sprintf("artifact-body-%d", i)), 2000+int64(i), fmt.Sprintf("p%d", i))
		prefix = append(prefix, e)
	}
	delta := make([]Event, 0, 5)
	for i := 15; i < 20; i++ {
		e := makeSignedEntry(t, alice, vfs, "science.physics", fmt.Sprintf("law-%d", i),
			fmt.Sprintf("val-%d", i), fmt.Sprintf("When modeling system %d, check conservation.", i),
			8000+int64(i*10), nil, []byte(fmt.Sprintf("artifact-body-%d", i)), 2000+int64(i), fmt.Sprintf("p%d", i))
		delta = append(delta, e)
	}

	ckpt, err := CreateCheckpoint(pol, prefix, vfs)
	if err != nil {
		t.Fatalf("CreateCheckpoint: %v", err)
	}
	all := append(append([]Event(nil), prefix...), delta...)
	fullState, err := Replay(pol, all)
	if err != nil {
		t.Fatalf("full Replay: %v", err)
	}
	incState, err := ReplayFromCheckpoint(pol, ckpt.CheckpointHash, vfs, delta)
	if err != nil {
		t.Fatalf("ReplayFromCheckpoint: %v", err)
	}
	if fullState.StateRootHash != incState.StateRootHash {
		t.Fatalf("checkpoint parity mismatch: %s != %s", fullState.StateRootHash, incState.StateRootHash)
	}

	// Verify O(log n) Merkle proof for every active event
	for _, id := range fullState.ActiveEventIDs {
		proof, err := GenerateMerkleProof(fullState.ActiveEventIDs, id)
		if err != nil {
			t.Fatalf("GenerateMerkleProof(%s): %v", id, err)
		}
		if !VerifyMerkleProof(proof, fullState.Commitment.ActiveMerkleRoot) {
			t.Fatalf("VerifyMerkleProof failed for %s", id)
		}
		// Tampered proof must fail
		bad := proof
		bad.EventID = SHA256Hex([]byte("forged"))
		if VerifyMerkleProof(bad, fullState.Commitment.ActiveMerkleRoot) {
			t.Fatalf("tampered Merkle proof unexpectedly succeeded")
		}
	}
}

func TestVFSIntegrityAndTamperRejection(t *testing.T) {
	dir := t.TempDir()
	vfs, err := NewLocalVFSStore(dir, "")
	if err != nil {
		t.Fatalf("NewLocalVFSStore: %v", err)
	}
	res, err := vfs.Put([]byte("authentic-research-artifact"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := vfs.Get(res.SHA256)
	if err != nil || string(got) != "authentic-research-artifact" {
		t.Fatalf("Get failed: %v, %q", err, string(got))
	}

	// Corrupt the on-disk object and ensure Get catches the bit-flip
	objPath := filepath.Join(dir, "sha256", res.SHA256[:2], res.SHA256)
	if err := os.WriteFile(objPath, []byte("corrupted-research-artifact"), 0o644); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}
	if _, err := vfs.Get(res.SHA256); err == nil {
		t.Fatalf("expected integrity error on corrupted VFS object")
	}

	// Test signature tampering rejection in Replay
	pol, ids := makeTestPolicy(t)
	alice := ids["did:key:researcher-alice"]
	vfs2, _ := NewLocalVFSStore(t.TempDir(), "")
	e := makeSignedEntry(t, alice, vfs2, "math.logic", "soundness", "v1", "When proving soundness, check base case.", 9000, nil, []byte("ok"), 1, "t1")
	tampered := e
	tampered.Summary = "Tampered summary after signing"
	st, err := Replay(pol, []Event{tampered})
	if err != nil {
		t.Fatalf("Replay tampered: %v", err)
	}
	if len(st.ActiveEventIDs) != 0 || len(st.Commitment.RejectedEvents) != 1 || st.Commitment.RejectedEvents[0].ErrorCode != ErrEventIDMismatch {
		t.Fatalf("expected ERR_EVENT_ID_MISMATCH on tampered event, got %+v", st.Commitment.RejectedEvents)
	}

	// Recompute event_id without re-signing -> ERR_INVALID_SIGNATURE
	tampered.EventID, _ = ComputeEventID(tampered)
	st2, err := Replay(pol, []Event{tampered})
	if err != nil {
		t.Fatalf("Replay bad sig: %v", err)
	}
	if len(st2.Commitment.RejectedEvents) != 1 || st2.Commitment.RejectedEvents[0].ErrorCode != ErrInvalidSignature {
		t.Fatalf("expected ERR_INVALID_SIGNATURE, got %+v", st2.Commitment.RejectedEvents)
	}
}

func TestEdgeCasesCycleAndCorpusFixtureParity(t *testing.T) {
	// 1. Direct unit test of Tarjan cycle detection on synthetic 2-node cycle + self-loop
	h1 := SHA256Hex([]byte("node-1"))
	h2 := SHA256Hex([]byte("node-2"))
	h3 := SHA256Hex([]byte("node-3"))
	h4 := SHA256Hex([]byte("node-4"))
	synthetic := map[string]Event{
		h1: {EventID: h1, ParentHashes: []string{h2}},
		h2: {EventID: h2, ParentHashes: []string{h1}},
		h3: {EventID: h3, ParentHashes: []string{h3}},
		h4: {EventID: h4, ParentHashes: []string{}},
	}
	cyc := detectCycleNodes(synthetic)
	if !cyc[h1] || !cyc[h2] || !cyc[h3] || cyc[h4] {
		t.Fatalf("unexpected cycle detection result: %+v", cyc)
	}

	// 2. Unresolved parents + pending revocation + keep_both_scoped + reject_all
	pol, ids := makeTestPolicy(t)
	vfs, _ := NewLocalVFSStore(t.TempDir(), "")
	alice := ids["did:key:researcher-alice"]
	bob := ids["did:key:researcher-bob"]
	carol := ids["did:key:steward-carol"]

	missingParent := SHA256Hex([]byte("unsynced-parent"))
	eChild := makeSignedEntry(t, alice, vfs, "net.sync", "partial-dag", "v1",
		"When syncing partial partitions, track unresolved parents.", 8800, []string{missingParent}, []byte("p1"), 10, "u1")
	pendRev := Event{
		SchemaVersion: SchemaVersion,
		EventType:     EventTypeRevocationRecord,
		IssuerID:      carol.id,
		TargetEventID: missingParent,
		ReasonCode:    ReasonCorruptedArtifact,
		Reason:        "Revoking unsynced parent",
		CreatedAtUnix: 11,
	}
	_ = SignEvent(&pendRev, carol.priv)

	eKeep1 := makeSignedEntry(t, alice, vfs, "net.sync", "scoped", "scope-a", "When small N, use linear.", 8500, nil, []byte("k1"), 12, "k1")
	eKeep2 := makeSignedEntry(t, bob, vfs, "net.sync", "scoped", "scope-b", "When large N, use checkpoint.", 8600, nil, []byte("k2"), 13, "k2")
	kp := []string{eKeep1.EventID, eKeep2.EventID}
	sort.Strings(kp)
	rat, _ := vfs.Put([]byte("steward-rationale"))
	resKeep := Event{
		SchemaVersion:    SchemaVersion,
		EventType:        EventTypeResolutionDecision,
		StewardID:        carol.id,
		Domain:           "net.sync",
		ClaimKey:         "scoped",
		ReviewedEventIDs: kp,
		Outcome:          OutcomeKeepBothScoped,
		WinningEventID:   "",
		RationaleSHA256:  rat.SHA256,
		RationaleURI:     rat.URI,
		GovernanceRef:    "hip-1352:keep",
		CreatedAtUnix:    14,
	}
	_ = SignEvent(&resKeep, carol.priv)

	eRej1 := makeSignedEntry(t, alice, vfs, "net.sync", "bad", "b1", "Bad claim 1.", 3000, nil, []byte("r1"), 15, "r1")
	eRej2 := makeSignedEntry(t, bob, vfs, "net.sync", "bad", "b2", "Bad claim 2.", 3100, nil, []byte("r2"), 16, "r2")
	rp := []string{eRej1.EventID, eRej2.EventID}
	sort.Strings(rp)
	resRej := Event{
		SchemaVersion:    SchemaVersion,
		EventType:        EventTypeResolutionDecision,
		StewardID:        carol.id,
		Domain:           "net.sync",
		ClaimKey:         "bad",
		ReviewedEventIDs: rp,
		Outcome:          OutcomeRejectAll,
		WinningEventID:   "",
		RationaleSHA256:  rat.SHA256,
		RationaleURI:     rat.URI,
		GovernanceRef:    "hip-1352:rej",
		CreatedAtUnix:    17,
	}
	_ = SignEvent(&resRej, carol.priv)

	st, err := Replay(pol, []Event{pendRev, resRej, resKeep, eRej2, eKeep2, eChild, eKeep1, eRej1})
	if err != nil {
		t.Fatalf("Replay edge cases: %v", err)
	}
	if len(st.Commitment.PendingRevocations) != 1 || st.Commitment.PendingRevocations[0] != pendRev.EventID {
		t.Fatalf("expected 1 pending revocation, got %+v", st.Commitment.PendingRevocations)
	}
	if len(st.ActiveEventIDs) != 3 {
		t.Fatalf("expected 3 active entries (eChild, eKeep1, eKeep2), got %d", len(st.ActiveEventIDs))
	}

	// 3. Verify committed real-paper fixture corpus_events.json matches expected_state.json
	corpusPath := filepath.Join("..", "..", "fixtures", "corpus_events.json")
	expectedPath := filepath.Join("..", "..", "fixtures", "expected_state.json")
	rawCorpus, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus_events.json: %v", err)
	}
	rawExpected, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected_state.json: %v", err)
	}
	var bundle LedgerBundle
	if err := json.Unmarshal(rawCorpus, &bundle); err != nil {
		t.Fatalf("unmarshal corpus: %v", err)
	}
	var expected ReconstructedState
	if err := json.Unmarshal(rawExpected, &expected); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}
	got, err := Replay(bundle.Policy, bundle.Events)
	if err != nil {
		t.Fatalf("Replay corpus: %v", err)
	}
	if got.StateRootHash != expected.StateRootHash {
		t.Fatalf("corpus state_root_hash mismatch: got %s, want %s", got.StateRootHash, expected.StateRootHash)
	}
	if got.Commitment.ActiveMerkleRoot != expected.Commitment.ActiveMerkleRoot {
		t.Fatalf("corpus active_merkle_root mismatch: got %s, want %s", got.Commitment.ActiveMerkleRoot, expected.Commitment.ActiveMerkleRoot)
	}
}

