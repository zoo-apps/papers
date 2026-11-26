// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ValidatePolicy verifies structural validity and policy_sha256 integrity.
func ValidatePolicy(p Policy) (map[string]Principal, map[string]ed25519.PublicKey, error) {
	if p.SchemaVersion != SchemaVersion {
		return nil, nil, fmt.Errorf("policy: invalid schema_version %q", p.SchemaVersion)
	}
	if p.PolicyID == "" || len(p.PolicyID) > 128 {
		return nil, nil, fmt.Errorf("policy: invalid policy_id")
	}
	if len(p.Principals) == 0 {
		return nil, nil, fmt.Errorf("policy: at least one principal is required")
	}
	expectedHash, err := ComputePolicySHA256(p)
	if err != nil {
		return nil, nil, err
	}
	if p.PolicySHA256 != expectedHash {
		return nil, nil, fmt.Errorf("policy: policy_sha256 mismatch: got %s, expected %s", p.PolicySHA256, expectedHash)
	}

	principals := make(map[string]Principal, len(p.Principals))
	pubKeys := make(map[string]ed25519.PublicKey, len(p.Principals))
	for _, pr := range p.Principals {
		if pr.PrincipalID == "" || len(pr.PrincipalID) > 128 {
			return nil, nil, fmt.Errorf("policy: invalid principal_id %q", pr.PrincipalID)
		}
		if _, dup := principals[pr.PrincipalID]; dup {
			return nil, nil, fmt.Errorf("policy: duplicate principal_id %q", pr.PrincipalID)
		}
		switch pr.Role {
		case RoleHumanResearcher, RoleAIAgent, RoleSteward:
		default:
			return nil, nil, fmt.Errorf("policy: invalid role %q for %q", pr.Role, pr.PrincipalID)
		}
		if !isLowerHex64(pr.PublicKeyHex) {
			return nil, nil, fmt.Errorf("policy: invalid public_key_hex for %q", pr.PrincipalID)
		}
		rawKey, err := hex.DecodeString(pr.PublicKeyHex)
		if err != nil || len(rawKey) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("policy: invalid ed25519 public key for %q", pr.PrincipalID)
		}
		principals[pr.PrincipalID] = pr
		pubKeys[pr.PrincipalID] = ed25519.PublicKey(rawKey)
	}
	return principals, pubKeys, nil
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isLowerHex128(s string) bool {
	if len(s) != 128 {
		return false
	}
	for i := 0; i < 128; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	parts := strings.Split(s, ".")
	for idx, seg := range parts {
		if len(seg) == 0 {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if idx == 0 {
				if !alnum {
					return false
				}
			} else {
				if !alnum && c != '_' && c != '-' {
					return false
				}
			}
		}
	}
	return true
}

func isValidClaimKey(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	c0 := s[0]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= '0' && c0 <= '9')) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func isSortedUnique(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if ss[i] <= ss[i-1] {
			return false
		}
	}
	return true
}

func isValidExternalURI(u string) bool {
	return (strings.HasPrefix(u, "ipfs://") && len(u) > len("ipfs://")) ||
		(strings.HasPrefix(u, "ar://") && len(u) > len("ar://")) ||
		(strings.HasPrefix(u, "https://") && len(u) > len("https://"))
}

func signerIDOf(e Event) string {
	switch e.EventType {
	case EventTypeExperienceEntry:
		return e.ContributorID
	case EventTypeRevocationRecord:
		return e.IssuerID
	case EventTypeConflictFlag:
		return e.FlaggerID
	case EventTypeResolutionDecision:
		return e.StewardID
	default:
		return ""
	}
}

func validateEventSchema(e Event) bool {
	if e.SchemaVersion != SchemaVersion || e.CreatedAtUnix < 0 {
		return false
	}
	if !isLowerHex64(e.EventID) || !isLowerHex128(e.SignatureHex) {
		return false
	}
	switch e.EventType {
	case EventTypeExperienceEntry:
		if e.ContributorID == "" || len(e.ContributorID) > 128 {
			return false
		}
		if !isValidDomain(e.Domain) || !isValidClaimKey(e.ClaimKey) {
			return false
		}
		if !isLowerHex64(e.ClaimValueHash) {
			return false
		}
		if len(e.Summary) == 0 || len(e.Summary) > 1024 {
			return false
		}
		if e.ConfidenceBps < 0 || e.ConfidenceBps > 10000 {
			return false
		}
		if !isLowerHex64(e.ArtifactSHA256) || !ValidateStorageURI(e.ArtifactURI, e.ArtifactSHA256) {
			return false
		}
		if e.ArtifactSizeBytes < 0 || len(e.Nonce) > 128 {
			return false
		}
		if e.ReceiptHash != "" && !isLowerHex64(e.ReceiptHash) {
			return false
		}
		if !isSortedUnique(e.ExternalURIs) {
			return false
		}
		for _, u := range e.ExternalURIs {
			if !isValidExternalURI(u) {
				return false
			}
		}
		if !isSortedUnique(e.ParentHashes) {
			return false
		}
		for _, p := range e.ParentHashes {
			if !isLowerHex64(p) {
				return false
			}
		}
		return true

	case EventTypeRevocationRecord:
		if e.IssuerID == "" || len(e.IssuerID) > 128 {
			return false
		}
		if !isLowerHex64(e.TargetEventID) {
			return false
		}
		switch e.ReasonCode {
		case ReasonRetractedByAuthor, ReasonCorruptedArtifact, ReasonFalsifiedClaim, ReasonPolicyViolation, ReasonSuperseded:
		default:
			return false
		}
		if len(e.Reason) == 0 || len(e.Reason) > 1024 {
			return false
		}
		if e.EvidenceSHA256 == "" && e.EvidenceURI == "" {
			return true
		}
		return isLowerHex64(e.EvidenceSHA256) && ValidateStorageURI(e.EvidenceURI, e.EvidenceSHA256)

	case EventTypeConflictFlag:
		if e.FlaggerID == "" || len(e.FlaggerID) > 128 {
			return false
		}
		if !isValidDomain(e.Domain) || !isValidClaimKey(e.ClaimKey) {
			return false
		}
		if len(e.ConflictingEventIDs) < 2 || !isSortedUnique(e.ConflictingEventIDs) {
			return false
		}
		for _, id := range e.ConflictingEventIDs {
			if !isLowerHex64(id) {
				return false
			}
		}
		if !isLowerHex64(e.EvidenceSHA256) || !ValidateStorageURI(e.EvidenceURI, e.EvidenceSHA256) {
			return false
		}
		if len(e.Rationale) == 0 || len(e.Rationale) > 1024 {
			return false
		}
		return true

	case EventTypeResolutionDecision:
		if e.StewardID == "" || len(e.StewardID) > 128 {
			return false
		}
		if !isValidDomain(e.Domain) || !isValidClaimKey(e.ClaimKey) {
			return false
		}
		if len(e.ReviewedEventIDs) < 2 || !isSortedUnique(e.ReviewedEventIDs) {
			return false
		}
		for _, id := range e.ReviewedEventIDs {
			if !isLowerHex64(id) {
				return false
			}
		}
		switch e.Outcome {
		case OutcomeSelectCanonical:
			if !isLowerHex64(e.WinningEventID) {
				return false
			}
			found := false
			for _, id := range e.ReviewedEventIDs {
				if id == e.WinningEventID {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case OutcomeRejectAll, OutcomeKeepBothScoped:
			if e.WinningEventID != "" {
				return false
			}
		default:
			return false
		}
		if !isLowerHex64(e.RationaleSHA256) || !ValidateStorageURI(e.RationaleURI, e.RationaleSHA256) {
			return false
		}
		if len(e.GovernanceRef) > 128 {
			return false
		}
		return true

	default:
		return false
	}
}

// Replay executes the 6-phase deterministic, order-independent stratified replay
// algorithm over an arbitrary ordering of events.
func Replay(policy Policy, events []Event) (ReconstructedState, error) {
	principals, pubKeys, err := ValidatePolicy(policy)
	if err != nil {
		return ReconstructedState{}, err
	}

	verified := make(map[string]Event, len(events))
	rejectedSet := make(map[RejectedEvent]struct{})
	duplicates := 0

	addReject := func(e Event, code string) {
		id := e.EventID
		if id == "" {
			id = "<missing>"
		}
		rejectedSet[RejectedEvent{
			EventID:   id,
			EventType: e.EventType,
			ErrorCode: code,
		}] = struct{}{}
	}

	// Phase 0: Intrinsic verification & idempotent deduplication.
	for _, e := range events {
		if _, exists := verified[e.EventID]; exists && e.EventID != "" {
			// Verify identical content ID before counting as duplicate.
			computedID, err := ComputeEventID(e)
			if err == nil && computedID == e.EventID {
				duplicates++
				continue
			}
		}
		if errCode := verifyEventIntrinsic(e, principals, pubKeys); errCode != "" {
			addReject(e, errCode)
			continue
		}
		verified[e.EventID] = e
	}

	return replayVerified(policy, principals, verified, rejectedSet, len(events), duplicates)
}

func verifyEventIntrinsic(e Event, principals map[string]Principal, pubKeys map[string]ed25519.PublicKey) string {
	if !validateEventSchema(e) {
		return ErrInvalidSchema
	}
	computedID, err := ComputeEventID(e)
	if err != nil || computedID != e.EventID {
		return ErrEventIDMismatch
	}
	signerID := signerIDOf(e)
	pr, ok := principals[signerID]
	if !ok || !pr.Active {
		return ErrUnknownPrincipal
	}
	sigBytes, err := hex.DecodeString(e.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(pubKeys[signerID], SigningMessage(e.EventID), sigBytes) {
		return ErrInvalidSignature
	}
	// Static constitutional separation for resolution_decision.
	if e.EventType == EventTypeResolutionDecision {
		if pr.Role == RoleAIAgent {
			return ErrAIAgentResolutionForbid
		}
		if pr.Role != RoleSteward {
			return ErrUnauthorizedResolution
		}
	}
	return ""
}

// replayVerified runs Phases 1..6 over a set of already signature-verified events.
func replayVerified(
	policy Policy,
	principals map[string]Principal,
	verified map[string]Event,
	rejectedSet map[RejectedEvent]struct{},
	totalInputs int,
	duplicates int,
) (ReconstructedState, error) {
	addReject := func(e Event, code string) {
		rejectedSet[RejectedEvent{
			EventID:   e.EventID,
			EventType: e.EventType,
			ErrorCode: code,
		}] = struct{}{}
	}

	entries := make(map[string]Event)
	revocations := make([]Event, 0)
	flags := make([]Event, 0)
	resolutions := make([]Event, 0)

	// Sort all verified event IDs for deterministic traversal.
	allIDs := make([]string, 0, len(verified))
	for id := range verified {
		allIDs = append(allIDs, id)
	}
	sort.Strings(allIDs)

	for _, id := range allIDs {
		e := verified[id]
		switch e.EventType {
		case EventTypeExperienceEntry:
			entries[id] = e
		case EventTypeRevocationRecord:
			revocations = append(revocations, e)
		case EventTypeConflictFlag:
			flags = append(flags, e)
		case EventTypeResolutionDecision:
			resolutions = append(resolutions, e)
		}
	}

	// Phase 1: Causal DAG cycle detection via deterministic Tarjan SCC.
	cycleNodes := detectCycleNodes(entries)
	for id := range cycleNodes {
		addReject(entries[id], ErrCycleDetected)
		delete(entries, id)
	}

	// Phase 2: Revocation authorization & OR-Set tombstones.
	revokedBy := make(map[string][]string)
	pendingRevocations := make([]string, 0)
	for _, r := range revocations {
		target, exists := entries[r.TargetEventID]
		if !exists {
			pendingRevocations = append(pendingRevocations, r.EventID)
			continue
		}
		issuer := principals[r.IssuerID]
		if r.IssuerID != target.ContributorID && issuer.Role != RoleSteward {
			addReject(r, ErrUnauthorizedRevocation)
			continue
		}
		revokedBy[target.EventID] = append(revokedBy[target.EventID], r.EventID)
	}
	for id := range revokedBy {
		sort.Strings(revokedBy[id])
	}
	sort.Strings(pendingRevocations)

	// Phase 3: Deterministic causal taint propagation from revoked entries.
	children := make(map[string][]string, len(entries))
	unresolvedParents := make(map[string][]string)
	entryIDs := make([]string, 0, len(entries))
	for id := range entries {
		entryIDs = append(entryIDs, id)
	}
	sort.Strings(entryIDs)

	for _, id := range entryIDs {
		e := entries[id]
		for _, p := range e.ParentHashes {
			if _, ok := entries[p]; ok {
				children[p] = append(children[p], id)
			} else {
				unresolvedParents[id] = append(unresolvedParents[id], p)
			}
		}
		if len(unresolvedParents[id]) > 0 {
			sort.Strings(unresolvedParents[id])
		}
	}

	taintedByMap := make(map[string]map[string]struct{})
	revokedIDs := make([]string, 0, len(revokedBy))
	for id := range revokedBy {
		revokedIDs = append(revokedIDs, id)
	}
	sort.Strings(revokedIDs)

	for _, revID := range revokedIDs {
		// BFS forward along child edges from revID.
		visited := map[string]bool{revID: true}
		queue := []string{revID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, ch := range children[cur] {
				if visited[ch] {
					continue
				}
				visited[ch] = true
				if _, directlyRevoked := revokedBy[ch]; !directlyRevoked {
					if taintedByMap[ch] == nil {
						taintedByMap[ch] = make(map[string]struct{})
					}
					taintedByMap[ch][revID] = struct{}{}
				}
				queue = append(queue, ch)
			}
		}
	}

	taintedBy := make(map[string][]string, len(taintedByMap))
	for id, set := range taintedByMap {
		arr := make([]string, 0, len(set))
		for anc := range set {
			arr = append(arr, anc)
		}
		sort.Strings(arr)
		taintedBy[id] = arr
	}

	isEligible := func(id string) bool {
		if _, ok := entries[id]; !ok {
			return false
		}
		if _, rev := revokedBy[id]; rev {
			return false
		}
		if _, taint := taintedBy[id]; taint {
			return false
		}
		return true
	}

	// Phase 4: ConflictSet construction over eligible entries.
	slotEntries := make(map[string][]string)
	slotClaimHashes := make(map[string]map[string]struct{})
	slotDomain := make(map[string]string)
	slotClaimKey := make(map[string]string)

	for _, id := range entryIDs {
		if !isEligible(id) {
			continue
		}
		e := entries[id]
		slot := e.Domain + "/" + e.ClaimKey
		slotEntries[slot] = append(slotEntries[slot], id)
		slotDomain[slot] = e.Domain
		slotClaimKey[slot] = e.ClaimKey
		if slotClaimHashes[slot] == nil {
			slotClaimHashes[slot] = make(map[string]struct{})
		}
		slotClaimHashes[slot][e.ClaimValueHash] = struct{}{}
	}

	slotFlags := make(map[string][]string)
	for _, f := range flags {
		slot := f.Domain + "/" + f.ClaimKey
		validRefCount := 0
		for _, cid := range f.ConflictingEventIDs {
			if isEligible(cid) {
				ce := entries[cid]
				if ce.Domain == f.Domain && ce.ClaimKey == f.ClaimKey {
					validRefCount++
				}
			}
		}
		if validRefCount >= 2 {
			slotFlags[slot] = append(slotFlags[slot], f.EventID)
		}
	}
	for slot := range slotFlags {
		sort.Strings(slotFlags[slot])
	}

	// Phase 5: Steward ResolutionDecision validation & evaluation.
	validResolutionsBySlot := make(map[string][]Event)
	for _, res := range resolutions {
		if res.Outcome == OutcomeSelectCanonical {
			win, exists := entries[res.WinningEventID]
			if !exists || !isEligible(res.WinningEventID) || win.Domain != res.Domain || win.ClaimKey != res.ClaimKey {
				addReject(res, ErrInvalidResolutionTarget)
				continue
			}
			// Strict constitutional separation: steward cannot self-validate own entry.
			if win.ContributorID == res.StewardID {
				addReject(res, ErrSelfValidationForbidden)
				continue
			}
		}
		slot := res.Domain + "/" + res.ClaimKey
		validResolutionsBySlot[slot] = append(validResolutionsBySlot[slot], res)
	}

	statusMap := make(map[string]string, len(entries))
	for _, id := range entryIDs {
		if _, rev := revokedBy[id]; rev {
			statusMap[id] = EntryStatusRevoked
		} else if _, taint := taintedBy[id]; taint {
			statusMap[id] = EntryStatusTainted
		} else {
			statusMap[id] = EntryStatusActive
		}
	}

	slots := make([]string, 0, len(slotEntries))
	for slot := range slotEntries {
		slots = append(slots, slot)
	}
	sort.Strings(slots)

	conflicts := make([]ConflictSet, 0)
	for _, slot := range slots {
		competing := slotEntries[slot]
		sort.Strings(competing)
		hasDivergence := len(slotClaimHashes[slot]) >= 2
		hasFlags := len(slotFlags[slot]) > 0
		if !hasDivergence && !hasFlags {
			continue
		}

		// Find all applicable resolutions covering every competing entry in S.
		applicable := make([]Event, 0)
		for _, res := range validResolutionsBySlot[slot] {
			if isSubsetSorted(competing, res.ReviewedEventIDs) {
				applicable = append(applicable, res)
			}
		}

		cs := ConflictSet{
			Slot:              slot,
			Domain:            slotDomain[slot],
			ClaimKey:          slotClaimKey[slot],
			CompetingEventIDs: competing,
			FlagIDs:           nonNilStrings(slotFlags[slot]),
			ResolutionIDs:     []string{},
			CanonicalEventID:  "",
		}

		if len(applicable) == 0 {
			cs.Status = ConflictStatusOpen
			for _, id := range competing {
				statusMap[id] = EntryStatusConflicted
			}
		} else {
			type outcomePair struct {
				outcome string
				winner  string
			}
			distinct := make(map[outcomePair]struct{})
			resIDs := make([]string, 0, len(applicable))
			var chosen outcomePair
			for _, res := range applicable {
				resIDs = append(resIDs, res.EventID)
				op := outcomePair{outcome: res.Outcome, winner: res.WinningEventID}
				distinct[op] = struct{}{}
				chosen = op
			}
			sort.Strings(resIDs)
			cs.ResolutionIDs = resIDs

			if len(distinct) == 1 {
				cs.Status = ConflictStatusResolved
				switch chosen.outcome {
				case OutcomeSelectCanonical:
					cs.CanonicalEventID = chosen.winner
					for _, id := range competing {
						if id == chosen.winner {
							statusMap[id] = EntryStatusActive
						} else {
							statusMap[id] = EntryStatusSuperseded
						}
					}
				case OutcomeRejectAll:
					for _, id := range competing {
						statusMap[id] = EntryStatusSuperseded
					}
				case OutcomeKeepBothScoped:
					for _, id := range competing {
						statusMap[id] = EntryStatusActive
					}
				}
			} else {
				// Two or more stewards disagreed — never silently LWW!
				cs.Status = ConflictStatusEscalatedStewardDisagree
				for _, id := range competing {
					statusMap[id] = EntryStatusConflicted
				}
			}
		}
		conflicts = append(conflicts, cs)
	}

	// Phase 6: Final sorted projections, Active Merkle Root, and State Root Hash.
	entryStates := make([]EntryState, 0, len(entryIDs))
	activeIDs := make([]string, 0, len(entryIDs))
	for _, id := range entryIDs {
		e := entries[id]
		st := statusMap[id]
		if st == EntryStatusActive {
			activeIDs = append(activeIDs, id)
		}
		entryStates = append(entryStates, EntryState{
			EventID:            id,
			ContributorID:      e.ContributorID,
			Domain:             e.Domain,
			ClaimKey:           e.ClaimKey,
			ClaimValueHash:     e.ClaimValueHash,
			ArtifactSHA256:     e.ArtifactSHA256,
			ArtifactURI:        e.ArtifactURI,
			Status:             st,
			RevokedBy:          nonNilStrings(revokedBy[id]),
			TaintedByAncestors: nonNilStrings(taintedBy[id]),
			UnresolvedParents:  nonNilStrings(unresolvedParents[id]),
		})
	}
	sort.Strings(activeIDs)

	activeMerkleRoot, err := ComputeActiveMerkleRoot(activeIDs)
	if err != nil {
		return ReconstructedState{}, err
	}

	rejectedList := make([]RejectedEvent, 0, len(rejectedSet))
	for rj := range rejectedSet {
		rejectedList = append(rejectedList, rj)
	}
	sort.Slice(rejectedList, func(i, j int) bool {
		if rejectedList[i].EventID != rejectedList[j].EventID {
			return rejectedList[i].EventID < rejectedList[j].EventID
		}
		if rejectedList[i].ErrorCode != rejectedList[j].ErrorCode {
			return rejectedList[i].ErrorCode < rejectedList[j].ErrorCode
		}
		return rejectedList[i].EventType < rejectedList[j].EventType
	})

	commitment := StateCommitment{
		SchemaVersion:      SchemaVersion,
		PolicySHA256:       policy.PolicySHA256,
		ActiveMerkleRoot:   activeMerkleRoot,
		EntryStates:        entryStates,
		Conflicts:          conflicts,
		PendingRevocations: pendingRevocations,
		RejectedEvents:     rejectedList,
	}

	rootHash, err := ComputeStateRootHash(commitment)
	if err != nil {
		return ReconstructedState{}, err
	}

	return ReconstructedState{
		StateRootHash:   rootHash,
		Commitment:      commitment,
		ActiveEventIDs:  activeIDs,
		TotalInputCount: totalInputs,
		UniqueAccepted:  len(verified),
		DuplicateCount:  duplicates,
	}, nil
}

// isSubsetSorted returns true iff every string in sub is in sup (both sorted).
func isSubsetSorted(sub, sup []string) bool {
	i, j := 0, 0
	for i < len(sub) && j < len(sup) {
		if sub[i] == sup[j] {
			i++
			j++
		} else if sub[i] > sup[j] {
			j++
		} else {
			return false
		}
	}
	return i == len(sub)
}

// detectCycleNodes returns the set of entry IDs belonging to any cycle (including self-loops)
// in the parent_hashes graph using deterministic Tarjan SCC.
func detectCycleNodes(entries map[string]Event) map[string]bool {
	cycleNodes := make(map[string]bool)
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	index := 0
	indices := make(map[string]int, len(entries))
	lowlink := make(map[string]int, len(entries))
	onStack := make(map[string]bool, len(entries))
	stack := make([]string, 0, len(entries))

	var strongConnect func(v string)
	strongConnect = func(v string) {
		index++
		indices[v] = index
		lowlink[v] = index
		stack = append(stack, v)
		onStack[v] = true

		for _, w := range entries[v].ParentHashes {
			if w == v {
				cycleNodes[v] = true
			}
			if _, exists := entries[w]; !exists {
				continue
			}
			if indices[w] == 0 {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		if lowlink[v] == indices[v] {
			scc := make([]string, 0)
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			if len(scc) > 1 {
				for _, node := range scc {
					cycleNodes[node] = true
				}
			}
		}
	}

	for _, id := range ids {
		if indices[id] == 0 {
			strongConnect(id)
		}
	}
	return cycleNodes
}

// CreateCheckpoint persists a verified CheckpointSnapshot into the VFS/S3 object store.
func CreateCheckpoint(policy Policy, events []Event, vfs VFSObjectStore) (CheckpointSnapshot, error) {
	principals, pubKeys, err := ValidatePolicy(policy)
	if err != nil {
		return CheckpointSnapshot{}, err
	}
	verified := make(map[string]Event, len(events))
	rejectedSet := make(map[RejectedEvent]struct{})
	duplicates := 0
	for _, e := range events {
		if _, exists := verified[e.EventID]; exists && e.EventID != "" {
			if cid, err := ComputeEventID(e); err == nil && cid == e.EventID {
				duplicates++
				continue
			}
		}
		if code := verifyEventIntrinsic(e, principals, pubKeys); code != "" {
			id := e.EventID
			if id == "" {
				id = "<missing>"
			}
			rejectedSet[RejectedEvent{EventID: id, EventType: e.EventType, ErrorCode: code}] = struct{}{}
			continue
		}
		verified[e.EventID] = e
	}
	state, err := replayVerified(policy, principals, verified, rejectedSet, len(events), duplicates)
	if err != nil {
		return CheckpointSnapshot{}, err
	}

	sortedIDs := make([]string, 0, len(verified))
	for id := range verified {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)
	included := make([]Event, 0, len(sortedIDs))
	for _, id := range sortedIDs {
		included = append(included, verified[id])
	}

	snap := CheckpointSnapshot{
		SchemaVersion:  SchemaVersion,
		PolicySHA256:   policy.PolicySHA256,
		StateRootHash:  state.StateRootHash,
		Commitment:     state.Commitment,
		IncludedEvents: included,
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return CheckpointSnapshot{}, err
	}
	putRes, err := vfs.Put(raw)
	if err != nil {
		return CheckpointSnapshot{}, err
	}
	snap.CheckpointHash = putRes.SHA256
	snap.CheckpointURI = putRes.URI
	return snap, nil
}

// ReplayFromCheckpoint loads a content-addressed checkpoint from VFS/S3 (skipping
// re-verification of already-checkpointed Ed25519 signatures) and verifies ONLY
// deltaEvents before producing the exact same deterministic ReconstructedState.
func ReplayFromCheckpoint(policy Policy, checkpointHash string, vfs VFSObjectStore, deltaEvents []Event) (ReconstructedState, error) {
	principals, pubKeys, err := ValidatePolicy(policy)
	if err != nil {
		return ReconstructedState{}, err
	}
	raw, err := vfs.Get(checkpointHash)
	if err != nil {
		return ReconstructedState{}, fmt.Errorf("load checkpoint %s: %w", checkpointHash, err)
	}
	var snap CheckpointSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return ReconstructedState{}, fmt.Errorf("decode checkpoint: %w", err)
	}
	if snap.PolicySHA256 != policy.PolicySHA256 {
		return ReconstructedState{}, fmt.Errorf("checkpoint policy mismatch")
	}

	verified := make(map[string]Event, len(snap.IncludedEvents)+len(deltaEvents))
	for _, e := range snap.IncludedEvents {
		verified[e.EventID] = e
	}
	rejectedSet := make(map[RejectedEvent]struct{}, len(snap.Commitment.RejectedEvents))
	for _, rj := range snap.Commitment.RejectedEvents {
		rejectedSet[rj] = struct{}{}
	}
	duplicates := 0
	for _, e := range deltaEvents {
		if _, exists := verified[e.EventID]; exists && e.EventID != "" {
			if cid, err := ComputeEventID(e); err == nil && cid == e.EventID {
				duplicates++
				continue
			}
		}
		if code := verifyEventIntrinsic(e, principals, pubKeys); code != "" {
			id := e.EventID
			if id == "" {
				id = "<missing>"
			}
			rejectedSet[RejectedEvent{EventID: id, EventType: e.EventType, ErrorCode: code}] = struct{}{}
			continue
		}
		verified[e.EventID] = e
	}
	return replayVerified(policy, principals, verified, rejectedSet, len(snap.IncludedEvents)+len(deltaEvents), duplicates)
}
