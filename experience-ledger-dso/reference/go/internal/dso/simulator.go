// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
)

const (
	DefaultNumNodes  = 30
	DefaultNumRounds = 12
)

type nodeSpec struct {
	id         NodeIdentity
	role       string
	domain     string
	paperIndex int
}

func quantizeExamplesMicro(exs []Example) {
	for i := range exs {
		for d := 0; d < FeatureDim; d++ {
			exs[i].Features[d] = FromMicro(ToMicro(exs[i].Features[d]))
		}
	}
}

func buildNodeRoster(seed int64, numNodes int, scenario string, advFraction float64) []nodeSpec {
	numAdv := int(math.Round(advFraction * float64(numNodes)))
	if numAdv < 0 {
		numAdv = 0
	}
	if numAdv > numNodes {
		numAdv = numNodes
	}
	numHonest := numNodes - numAdv

	minorityFrac := 0.30
	if scenario == ScenarioHonestDisagreement {
		minorityFrac = 0.25
	}
	numMinority := int(math.Round(minorityFrac * float64(numHonest)))
	if numHonest >= 4 && numMinority < 1 {
		numMinority = 1
	}
	numMajority := numHonest - numMinority

	roster := make([]nodeSpec, numNodes)
	for i := 0; i < numNodes; i++ {
		id := DeriveNodeIdentity(seed, i)
		switch {
		case i < numMajority:
			roster[i] = nodeSpec{id: id, role: RoleHonestMajority, domain: DomainProtocol, paperIndex: i}
		case i < numMajority+numMinority:
			roster[i] = nodeSpec{id: id, role: RoleHonestMinority, domain: DomainConservation, paperIndex: i}
		default:
			dom := DomainProtocol
			if (i-numHonest)%3 == 0 {
				dom = DomainConservation
			}
			roster[i] = nodeSpec{id: id, role: RoleAdversary, domain: dom, paperIndex: i}
		}
	}
	return roster
}

// localHonestSGD computes an honest local logistic-SGD policy delta starting from w.
func localHonestSGD(
	w [FeatureDim]float64,
	ownPool []Example,
	crossPool []Example,
	crossRatio float64,
	rng *rand.Rand,
) [FeatureDim]float64 {
	localW := w
	const (
		batchSize = 44
		epochs    = 2
		lr        = 0.26
		l2Reg     = 0.004
	)
	for ep := 0; ep < epochs; ep++ {
		var grad [FeatureDim]float64
		for b := 0; b < batchSize; b++ {
			var ex Example
			if crossRatio > 0 && len(crossPool) > 0 && rng.Float64() < crossRatio {
				ex = crossPool[rng.Intn(len(crossPool))]
			} else {
				ex = ownPool[rng.Intn(len(ownPool))]
			}
			y := float64(ex.Label)
			z := y * Dot(localW, ex.Features)
			// sigmoid(-z) = 1 / (1 + exp(z))
			var sig float64
			if z >= 0 {
				ez := math.Exp(-z)
				sig = ez / (1.0 + ez)
			} else {
				ez := math.Exp(z)
				sig = 1.0 / (1.0 + ez)
			}
			coeff := -y * sig / float64(batchSize)
			for d := 0; d < FeatureDim; d++ {
				grad[d] += coeff * ex.Features[d]
			}
		}
		for d := 0; d < FeatureDim; d++ {
			localW[d] -= lr * (grad[d] + l2Reg*localW[d])
		}
	}
	var delta [FeatureDim]float64
	for d := 0; d < FeatureDim; d++ {
		delta[d] = localW[d] - w[d]
	}
	return delta
}

func paperForNode(ds *CorpusDataset, domain string, idx int) PaperDoc {
	var pool []PaperDoc
	for _, p := range ds.Papers {
		if p.Domain == domain {
			pool = append(pool, p)
		}
	}
	if len(pool) == 0 {
		return ds.Papers[idx%len(ds.Papers)]
	}
	return pool[idx%len(pool)]
}

func generateRoundEnvelopes(
	ds *CorpusDataset,
	roster []nodeSpec,
	scenario string,
	round int,
	w [FeatureDim]float64,
	rng *rand.Rand,
	unmonitoredBackdoor bool,
) []ContributionEnvelope {
	n := len(roster)
	honestDeltas := make([][FeatureDim]float64, n)
	var meanHonest [FeatureDim]float64
	honestCount := 0
	var meanHonestNorm float64

	crossRatio := 0.15
	if scenario == ScenarioHonestDisagreement {
		crossRatio = 0.0 // Strictly disjoint specialist non-IID shards!
	}

	// Step 1: Honest nodes run local SGD on their real .tex trajectory shards.
	for i, ns := range roster {
		if ns.role == RoleAdversary {
			continue
		}
		var delta [FeatureDim]float64
		if ns.domain == DomainConservation {
			delta = localHonestSGD(w, ds.TrainConservation, ds.TrainProtocol, crossRatio, rng)
		} else {
			delta = localHonestSGD(w, ds.TrainProtocol, ds.TrainConservation, crossRatio, rng)
		}
		honestDeltas[i] = delta
		for d := 0; d < FeatureDim; d++ {
			meanHonest[d] += delta[d]
		}
		meanHonestNorm += L2Norm(delta)
		honestCount++
	}
	if honestCount > 0 {
		inv := 1.0 / float64(honestCount)
		for d := 0; d < FeatureDim; d++ {
			meanHonest[d] *= inv
		}
		meanHonestNorm *= inv
	} else {
		meanHonestNorm = 0.35
	}

	// Precompute shared cartel base vector for colluding_sybil_cartel (or hybrid in scenario 4).
	var cartelTarget [FeatureDim]float64
	for d := ProtoStart; d < ConsEnd; d++ {
		cartelTarget[d] = -1.35 * meanHonest[d]
	}
	for d := SharedStart; d < SharedEnd; d++ {
		cartelTarget[d] = -0.8 * meanHonest[d]
	}
	cNorm := L2Norm(cartelTarget)
	if cNorm > 1e-9 {
		scale := (meanHonestNorm * 1.05) / cNorm
		for d := 0; d < FeatureDim; d++ {
			cartelTarget[d] *= scale
		}
	}

	// Step 2: Build and Ed25519-sign all N contribution envelopes.
	envelopes := make([]ContributionEnvelope, n)
	for i, ns := range roster {
		paper := paperForNode(ds, ns.domain, ns.paperIndex+round)
		var delta [FeatureDim]float64
		var expMode string
		conf := 0.84 + 0.08*rng.Float64()

		if ns.role != RoleAdversary {
			delta = honestDeltas[i]
			expMode = ns.role
		} else if unmonitoredBackdoor {
			// Negative Regime 2: Camouflaged backdoor adversary!
			// Submits genuinely helpful honest gradient on monitored subspaces [0..55]
			// while injecting sign-inverted backdoor weights on unmonitored trigger dims [62..63].
			if ns.domain == DomainConservation {
				delta = localHonestSGD(w, ds.TrainConservation, ds.TrainProtocol, 0.15, rng)
			} else {
				delta = localHonestSGD(w, ds.TrainProtocol, ds.TrainConservation, 0.15, rng)
			}
			delta[TriggerStart+0] = -1.95
			delta[TriggerStart+1] = 1.85
			expMode = "adversarial_semantic"
			conf = 0.88
		} else {
			switch scenario {
			case ScenarioAdversarialSemantic:
				// Authentic label-flipped semantic poisoning:
				// Adversary runs real local logistic SGD on label-flipped real .tex trajectory pairs
				// (inverting semantic preferences on both domains while naturally matching the honest L2 norm!).
				localW := w
				const (
					advBatch  = 44
					advEpochs = 2
					advLR     = 0.30
				)
				for ep := 0; ep < advEpochs; ep++ {
					var grad [FeatureDim]float64
					for b := 0; b < advBatch; b++ {
						var ex Example
						if b%2 == 0 {
							ex = ds.TrainProtocol[rng.Intn(len(ds.TrainProtocol))]
						} else {
							ex = ds.TrainConservation[rng.Intn(len(ds.TrainConservation))]
						}
						// Flip semantic preference label y -> -y
						y := -float64(ex.Label)
						z := y * Dot(localW, ex.Features)
						var sig float64
						if z >= 0 {
							ez := math.Exp(-z)
							sig = ez / (1.0 + ez)
						} else {
							ez := math.Exp(z)
							sig = 1.0 / (1.0 + ez)
						}
						coeff := -y * sig / float64(advBatch)
						for d := 0; d < FeatureDim; d++ {
							grad[d] += coeff * ex.Features[d]
						}
					}
					for d := 0; d < FeatureDim; d++ {
						localW[d] -= advLR * grad[d]
					}
				}
				for d := 0; d < FeatureDim; d++ {
					delta[d] = localW[d] - w[d]
				}
				// Camouflage: preserve slight positive shared structural alignment & match exact honest norm envelope.
				for d := SharedStart; d < SharedEnd; d++ {
					delta[d] = 0.20 * meanHonest[d]
				}
				dn := L2Norm(delta)
				if dn > 1e-9 {
					scale := (meanHonestNorm * 1.15) / dn
					for d := 0; d < FeatureDim; d++ {
						delta[d] *= scale
					}
				}
				expMode = "adversarial_semantic"
				conf = 0.91

			case ScenarioColludingCartel:
				// Tightly clustered Sybil cartel (cos > 0.999) designed to fool Multi-Krum!
				for d := 0; d < FeatureDim; d++ {
					delta[d] = cartelTarget[d] + rng.NormFloat64()*0.0006
				}
				expMode = "colluding_cartel"
				conf = 0.93

			case ScenarioLowQualityNoisy:
				// Lazy / under-trained freeloader submitting high-variance noise & vague text.
				for d := 0; d < SharedEnd; d++ {
					delta[d] = rng.NormFloat64() * 0.42
				}
				expMode = "low_quality_noisy"
				conf = 0.45

			case ScenarioHonestDisagreement:
				// Mixed Byzantine pressure: half tight cartel, half real label-flipped semantic poisoners!
				if i%2 == 0 {
					for d := 0; d < FeatureDim; d++ {
						delta[d] = cartelTarget[d] + rng.NormFloat64()*0.0006
					}
					expMode = "colluding_cartel"
				} else {
					for d := ProtoStart; d < ConsEnd; d++ {
						delta[d] = -1.35 * meanHonest[d]
					}
					for d := SharedStart; d < SharedEnd; d++ {
						delta[d] = 0.15 * meanHonest[d]
					}
					dn := L2Norm(delta)
					if dn > 1e-9 {
						scale := (meanHonestNorm * 1.10) / dn
						for d := 0; d < FeatureDim; d++ {
							delta[d] *= scale
						}
					}
					expMode = "adversarial_semantic"
				}
				conf = 0.90
			}
		}

		exp := SynthesizeExperienceOp(paper, ns.domain, round, ns.id.NodeID, expMode, conf)
		body := ContributionBody{
			SchemaVersion: SchemaVersion,
			Round:         round,
			NodeID:        ns.id.NodeID,
			PublicKeyHex:  ns.id.PublicKeyHex,
			Domain:        ns.domain,
			Experience:    exp,
			DeltaMicro:    VecToMicro(delta),
		}
		envelopes[i] = SignContribution(ns.id, body, ns.role)
	}
	return envelopes
}

func makeCellRNG(seed int64, tag string) *rand.Rand {
	h := sha256.Sum256([]byte(fmt.Sprintf("dso-cell-rng-v1:%d:%s", seed, tag)))
	return rand.New(rand.NewSource(int64(binary.BigEndian.Uint64(h[:8]))))
}

// RunSingleCell executes one (scenario, adversary_fraction, aggregator) experiment over numRounds.
func RunSingleCell(
	ds *CorpusDataset,
	seed int64,
	scenario string,
	advFraction float64,
	aggregator string,
	numNodes int,
	numRounds int,
	cfg AggregationConfig,
	cleanCeilingAcc float64,
) (CellMetrics, [FeatureDim]float64) {
	roster := buildNodeRoster(seed, numNodes, scenario, advFraction)
	rng := makeCellRNG(seed, fmt.Sprintf("%s:%.2f:%s", scenario, advFraction, aggregator))

	var model [FeatureDim]float64
	reputations := make([]float64, numNodes)
	for i := range reputations {
		reputations[i] = 1.0
	}

	cumHonestWeights := make([]float64, numNodes)
	var (
		majAccSum, minAccSum, advAdmSum float64
		advWeightSum                    float64
		totalMs                         float64
		totalBytes                      int
	)

	numMaj, numMin, numAdv := 0, 0, 0
	for _, ns := range roster {
		switch ns.role {
		case RoleHonestMajority:
			numMaj++
		case RoleHonestMinority:
			numMin++
		case RoleAdversary:
			numAdv++
		}
	}

	const globalStep = 1.15
	for r := 1; r <= numRounds; r++ {
		envelopes := generateRoundEnvelopes(ds, roster, scenario, r, model, rng, false)
		roundBytes := 0
		for _, env := range envelopes {
			roundBytes += env.PayloadBytes
		}
		totalBytes += roundBytes

		res := AggregateRound(aggregator, envelopes, model, reputations, ds.ValProtocol, ds.ValConservation, cfg)
		totalMs += res.DurationMs

		for d := 0; d < FeatureDim; d++ {
			model[d] += globalStep * res.AggregatedDelta[d]
		}

		// Update online reputation (used by dso_reputation_eval_gated across rounds).
		if aggregator == AggDSOReputationEvalGated {
			for i := 0; i < numNodes; i++ {
				if res.Accepted[i] {
					reputations[i] = math.Min(2.5, reputations[i]*1.08+0.02)
				} else {
					reputations[i] = math.Max(0.05, reputations[i]*0.55)
				}
			}
		}

		roundMajAcc, roundMinAcc, roundAdvAdm := 0, 0, 0
		roundAdvWeight := 0.0
		for i, ns := range roster {
			switch ns.role {
			case RoleHonestMajority:
				cumHonestWeights[i] += res.Weights[i]
				if res.Accepted[i] {
					roundMajAcc++
				}
			case RoleHonestMinority:
				cumHonestWeights[i] += res.Weights[i]
				if res.Accepted[i] {
					roundMinAcc++
				}
			case RoleAdversary:
				roundAdvWeight += res.Weights[i]
				if res.Accepted[i] {
					roundAdvAdm++
				}
			}
		}
		if numMaj > 0 {
			majAccSum += float64(roundMajAcc) / float64(numMaj)
		}
		if numMin > 0 {
			minAccSum += float64(roundMinAcc) / float64(numMin)
		}
		if numAdv > 0 {
			advAdmSum += float64(roundAdvAdm) / float64(numAdv)
		}
		advWeightSum += roundAdvWeight
	}

	// Evaluate final model on completely unseen balanced test set (TestProtocol + TestConservation).
	majTestAcc, majTestLoss := EvaluateLogistic(model, ds.TestProtocol)
	minTestAcc, minTestLoss := EvaluateLogistic(model, ds.TestConservation)
	globalAcc := 0.5 * (majTestAcc + minTestAcc)
	globalLoss := 0.5 * (majTestLoss + minTestLoss)

	honestAttr := make([]float64, 0, numMaj+numMin)
	for i, ns := range roster {
		if ns.role != RoleAdversary {
			honestAttr = append(honestAttr, cumHonestWeights[i])
		}
	}

	majAccRate := majAccSum / float64(numRounds)
	minAccRate := minAccSum / float64(numRounds)
	fairnessRatio := 0.0
	if majAccRate > 1e-9 {
		fairnessRatio = minAccRate / majAccRate
	}
	advAdmRate := 0.0
	if numAdv > 0 {
		advAdmRate = advAdmSum / float64(numRounds)
	}

	degradation := 0.0
	if cleanCeilingAcc > 0 {
		degradation = cleanCeilingAcc - globalAcc
	}

	metrics := CellMetrics{
		Scenario:                     scenario,
		AdversaryFraction:            advFraction,
		Aggregator:                   aggregator,
		NumNodes:                     numNodes,
		NumRounds:                    numRounds,
		NumHonestMajority:            numMaj,
		NumHonestMinority:            numMin,
		NumAdversaries:               numAdv,
		GlobalTestAccuracy:           globalAcc,
		GlobalTestLoss:               globalLoss,
		MajorityTestAccuracy:         majTestAcc,
		MinorityTestAccuracy:         minTestAcc,
		CleanHonestCeilingAccuracy:   cleanCeilingAcc,
		AttackDegradationDelta:       degradation,
		AdversarialAdmissionRate:     advAdmRate,
		AdversarialWeightShare:       advWeightSum / float64(numRounds),
		MajorityHonestAcceptanceRate: majAccRate,
		MinorityHonestAcceptanceRate: minAccRate,
		FairnessRatio:                fairnessRatio,
		JainsFairnessIndex:           JainsFairnessIndex(honestAttr),
		AttributionGini:              GiniCoefficient(honestAttr),
		VerificationMsPerRound:       totalMs / float64(numRounds),
		PayloadBytesPerRound:         totalBytes / numRounds,
		FinalWeightsDigestSHA256:     HashVectorMicro(model),
	}
	return metrics, model
}

// RunNegativeRegime2 executes the Unmonitored Semantic Trigger Backdoor ablation.
func RunNegativeRegime2(ds *CorpusDataset, seed int64, cfg AggregationConfig) []NegativeRegime2Entry {
	fracs := []float64{0.20, 0.30}
	out := make([]NegativeRegime2Entry, 0, len(fracs)*len(AllAggregators))
	for _, f := range fracs {
		for _, agg := range AllAggregators {
			roster := buildNodeRoster(seed, DefaultNumNodes, ScenarioAdversarialSemantic, f)
			rng := makeCellRNG(seed, fmt.Sprintf("neg2:%.2f:%s", f, agg))
			var model [FeatureDim]float64
			reps := make([]float64, DefaultNumNodes)
			for i := range reps {
				reps[i] = 1.0
			}
			numAdv := 0
			for _, ns := range roster {
				if ns.role == RoleAdversary {
					numAdv++
				}
			}
			advAdmSum := 0.0
			for r := 1; r <= DefaultNumRounds; r++ {
				envs := generateRoundEnvelopes(ds, roster, ScenarioAdversarialSemantic, r, model, rng, true)
				res := AggregateRound(agg, envs, model, reps, ds.ValProtocol, ds.ValConservation, cfg)
				for d := 0; d < FeatureDim; d++ {
					model[d] += 1.15 * res.AggregatedDelta[d]
				}
				roundAdv := 0
				for i, ns := range roster {
					if ns.role == RoleAdversary && res.Accepted[i] {
						roundAdv++
					}
				}
				if numAdv > 0 {
					advAdmSum += float64(roundAdv) / float64(numAdv)
				}
			}
			pAcc, _ := EvaluateLogistic(model, ds.TestProtocol)
			cAcc, _ := EvaluateLogistic(model, ds.TestConservation)
			trigAcc, _ := EvaluateLogistic(model, ds.TriggerBackdoorTest)
			out = append(out, NegativeRegime2Entry{
				Aggregator:                 agg,
				AdversaryFraction:          f,
				CleanGlobalAccuracy:        0.5 * (pAcc + cAcc),
				UnmonitoredTriggerAccuracy: trigAcc,
				BackdoorAttackSuccessRate:  1.0 - trigAcc,
				AdversarialAdmissionRate:   advAdmSum / float64(DefaultNumRounds),
			})
		}
	}
	return out
}

// RunNegativeRegime3 executes (a) Decentralized DAO Committee Voting Collapse (Theorem 2: 66% supermajority)
// and (b) Static Small Validation Set Overfitting / Goodhart Drift over 30 rounds.
func RunNegativeRegime3(ds *CorpusDataset, seed int64, cfg AggregationConfig) []NegativeRegime3Entry {
	var out []NegativeRegime3Entry

	// Part A: Decentralized Committee-Voted DSO (experience-ledger-dso Theorem 2: 66% quorum).
	// Honest committee members vote YES iff held-out gain > 0; Byzantine members vote NO on honest updates
	// and YES on poisoned updates.
	for _, f := range []float64{0.20, 0.30, 0.40, 0.50} {
		roster := buildNodeRoster(seed, DefaultNumNodes, ScenarioAdversarialSemantic, f)
		rng := makeCellRNG(seed, fmt.Sprintf("neg3-committee:%.2f", f))
		var model [FeatureDim]float64
		numAdv := int(math.Round(f * float64(DefaultNumNodes)))
		numHonest := DefaultNumNodes - numAdv
		honestFrac := float64(numHonest) / float64(DefaultNumNodes)
		advFrac := float64(numAdv) / float64(DefaultNumNodes)

		honestApprovedTotal, honestSubmittedTotal := 0, 0
		advApprovedTotal, advSubmittedTotal := 0, 0

		for r := 1; r <= DefaultNumRounds; r++ {
			envs := generateRoundEnvelopes(ds, roster, ScenarioAdversarialSemantic, r, model, rng, false)
			res := AggregateRound(AggDSOReputationEvalGated, envs, model, nil, ds.ValProtocol, ds.ValConservation, cfg)

			var roundDelta [FeatureDim]float64
			approved := 0
			for i, ns := range roster {
				vec, _ := VecFromMicro(envs[i].Body.DeltaMicro)
				honestSaysYes := res.Accepted[i]
				var yesFrac float64
				if ns.role == RoleAdversary {
					advSubmittedTotal++
					yesFrac = advFrac
					if honestSaysYes {
						yesFrac += honestFrac
					}
				} else {
					honestSubmittedTotal++
					if honestSaysYes {
						yesFrac = honestFrac // Adversaries vote NO to censor honest updates
					}
				}
				// 66% supermajority threshold from experience-ledger-dso Section 6.1/6.3
				if yesFrac >= 0.66 {
					approved++
					for d := 0; d < FeatureDim; d++ {
						roundDelta[d] += vec[d]
					}
					if ns.role == RoleAdversary {
						advApprovedTotal++
					} else {
						honestApprovedTotal++
					}
				}
			}
			if approved > 0 {
				inv := 1.15 / float64(approved)
				for d := 0; d < FeatureDim; d++ {
					model[d] += roundDelta[d] * inv
				}
			}
		}

		pAcc, _ := EvaluateLogistic(model, ds.TestProtocol)
		cAcc, _ := EvaluateLogistic(model, ds.TestConservation)
		vpAcc, _ := EvaluateLogistic(model, ds.ValProtocol)
		vcAcc, _ := EvaluateLogistic(model, ds.ValConservation)
		gAcc := 0.5 * (pAcc + cAcc)
		vAcc := 0.5 * (vpAcc + vcAcc)
		liveness := 0.0
		if honestSubmittedTotal > 0 {
			liveness = float64(honestApprovedTotal) / float64(honestSubmittedTotal)
		}
		advApproval := 0.0
		if advSubmittedTotal > 0 {
			advApproval = float64(advApprovedTotal) / float64(advSubmittedTotal)
		}
		note := "66% supermajority preserves safety & liveness (f < 33%)"
		if f >= 0.34 {
			note = "LIVENESS COLLAPSE: Byzantine abstention/NO votes block 66% supermajority (honest fraction < 66%)"
		}
		out = append(out, NegativeRegime3Entry{
			Mode:                   "decentralized_committee_66pct_supermajority",
			AdversaryFraction:      f,
			GlobalTestAccuracy:     gAcc,
			ValAccuracy:            vAcc,
			GoodhartOverfitGap:     vAcc - gAcc,
			HonestLivenessRate:     liveness,
			AdversarialApprovalPct: advApproval,
			Notes:                  note,
		})
	}

	// Part B: 50% Byzantine Simple-Majority Committee Safety Collapse (lowering threshold to 50% restores liveness
	// at f=50%, but immediately breaks safety!).
	{
		f := 0.50
		roster := buildNodeRoster(seed, DefaultNumNodes, ScenarioAdversarialSemantic, f)
		rng := makeCellRNG(seed, "neg3-majority-50")
		var model [FeatureDim]float64
		honestApproved, honestTotal, advApproved, advTotal := 0, 0, 0, 0
		for r := 1; r <= DefaultNumRounds; r++ {
			envs := generateRoundEnvelopes(ds, roster, ScenarioAdversarialSemantic, r, model, rng, false)
			var roundDelta [FeatureDim]float64
			approved := 0
			for i, ns := range roster {
				vec, _ := VecFromMicro(envs[i].Body.DeltaMicro)
				// At f=50%, a >=50% majority gate lets the 50% adversarial bloc self-approve poisoned updates!
				if ns.role == RoleAdversary {
					advTotal++
					advApproved++
					approved++
					for d := 0; d < FeatureDim; d++ {
						roundDelta[d] += vec[d]
					}
				} else {
					honestTotal++
					honestApproved++
					approved++
					for d := 0; d < FeatureDim; d++ {
						roundDelta[d] += vec[d]
					}
				}
			}
			if approved > 0 {
				inv := 1.15 / float64(approved)
				for d := 0; d < FeatureDim; d++ {
					model[d] += roundDelta[d] * inv
				}
			}
		}
		pAcc, _ := EvaluateLogistic(model, ds.TestProtocol)
		cAcc, _ := EvaluateLogistic(model, ds.TestConservation)
		vpAcc, _ := EvaluateLogistic(model, ds.ValProtocol)
		vcAcc, _ := EvaluateLogistic(model, ds.ValConservation)
		gAcc := 0.5 * (pAcc + cAcc)
		vAcc := 0.5 * (vpAcc + vcAcc)
		out = append(out, NegativeRegime3Entry{
			Mode:                   "decentralized_committee_50pct_majority",
			AdversaryFraction:      f,
			GlobalTestAccuracy:     gAcc,
			ValAccuracy:            vAcc,
			GoodhartOverfitGap:     vAcc - gAcc,
			HonestLivenessRate:     float64(honestApproved) / float64(honestTotal),
			AdversarialApprovalPct: float64(advApproved) / float64(advTotal),
			Notes:                  "SAFETY COLLAPSE: 50% adversarial bloc self-approves poisoned updates under simple majority",
		})
	}

	// Part C: Static Small Eval-Set Goodhart Overfitting (20 static examples/domain, 30 rounds, adaptive probing).
	{
		smallValProto := ds.ValProtocol[:20]
		smallValCons := ds.ValConservation[:20]
		roster := buildNodeRoster(seed, DefaultNumNodes, ScenarioAdversarialSemantic, 0.50)
		rng := makeCellRNG(seed, "neg3-goodhart-overfit")
		var model [FeatureDim]float64
		reps := make([]float64, DefaultNumNodes)
		for i := range reps {
			reps[i] = 1.0
		}
		honestAdm, honestTot, advAdm, advTot := 0, 0, 0, 0
		for r := 1; r <= 30; r++ {
			// Generate normal round, then have adversaries probe random directions to overfit the small static val set!
			envs := generateRoundEnvelopes(ds, roster, ScenarioLowQualityNoisy, r, model, rng, false)
			for i, ns := range roster {
				if ns.role != RoleAdversary {
					continue
				}
				// Adversary submits a random candidate that happens to reduce loss on the tiny static val set
				// (cherry-picking best of 24 random trials against leaked/static small eval set).
				valOwn := smallValProto
				if ns.domain == DomainConservation {
					valOwn = smallValCons
				}
				bestLoss := math.MaxFloat64
				var bestVec [FeatureDim]float64
				for trial := 0; trial < 24; trial++ {
					var cand [FeatureDim]float64
					for d := 0; d < SharedEnd; d++ {
						cand[d] = rng.NormFloat64() * 0.28
					}
					var probe [FeatureDim]float64
					for d := 0; d < FeatureDim; d++ {
						probe[d] = model[d] + cfg.DSOEvalStep*cand[d]
					}
					_, loss := EvaluateLogistic(probe, valOwn)
					if loss < bestLoss {
						bestLoss = loss
						bestVec = cand
					}
				}
				paper := paperForNode(ds, ns.domain, ns.paperIndex+r)
				exp := SynthesizeExperienceOp(paper, ns.domain, r, ns.id.NodeID, "adversarial_semantic", 0.89)
				body := ContributionBody{
					SchemaVersion: SchemaVersion,
					Round:         r,
					NodeID:        ns.id.NodeID,
					PublicKeyHex:  ns.id.PublicKeyHex,
					Domain:        ns.domain,
					Experience:    exp,
					DeltaMicro:    VecToMicro(bestVec),
				}
				envs[i] = SignContribution(ns.id, body, ns.role)
			}
			res := AggregateRound(AggDSOReputationEvalGated, envs, model, reps, smallValProto, smallValCons, cfg)
			for d := 0; d < FeatureDim; d++ {
				model[d] += 0.85 * res.AggregatedDelta[d]
			}
			for i, ns := range roster {
				if ns.role == RoleAdversary {
					advTot++
					if res.Accepted[i] {
						advAdm++
					}
				} else {
					honestTot++
					if res.Accepted[i] {
						honestAdm++
					}
				}
			}
		}
		pAcc, _ := EvaluateLogistic(model, ds.TestProtocol)
		cAcc, _ := EvaluateLogistic(model, ds.TestConservation)
		vpAcc, _ := EvaluateLogistic(model, smallValProto)
		vcAcc, _ := EvaluateLogistic(model, smallValCons)
		gAcc := 0.5 * (pAcc + cAcc)
		vAcc := 0.5 * (vpAcc + vcAcc)
		out = append(out, NegativeRegime3Entry{
			Mode:                   "static_small_eval_goodhart_overfit_30r",
			AdversaryFraction:      0.50,
			GlobalTestAccuracy:     gAcc,
			ValAccuracy:            vAcc,
			GoodhartOverfitGap:     vAcc - gAcc,
			HonestLivenessRate:     float64(honestAdm) / float64(honestTot),
			AdversarialApprovalPct: float64(advAdm) / float64(advTot),
			Notes:                  "EVAL OVERFITTING: Static 20-item validation set allows adaptive cherry-picking, inflating ValAcc far above TestAcc",
		})
	}

	return out
}

// RunFullBenchmark runs the complete 4 scenarios x 6 adversary fractions x 5 aggregators grid
// plus all 3 honest negative regimes and exports an audit trace for independent Python verification.
func RunFullBenchmark(repoRoot string, seed int64) (*BenchmarkReport, *AuditTraceArtifact, error) {
	ds, err := LoadGroundedCorpus(repoRoot, seed)
	if err != nil {
		return nil, nil, err
	}
	// Quantize held-out validation features to micro-units so Go and Python compute exact parity.
	quantizeExamplesMicro(ds.ValProtocol)
	quantizeExamplesMicro(ds.ValConservation)

	cfg := DefaultAggregationConfig()

	// Step 1: Compute clean honest ceiling per scenario (f=0%, dso_reputation_eval_gated).
	cleanCeilings := make(map[string]float64, len(AllScenarios))
	for _, sc := range AllScenarios {
		cm, _ := RunSingleCell(ds, seed, sc, 0.0, AggDSOReputationEvalGated, DefaultNumNodes, DefaultNumRounds, cfg, 0)
		cleanCeilings[sc] = cm.GlobalTestAccuracy
	}

	// Step 2: Execute all 4 x 6 x 5 = 120 cells.
	cells := make([]CellMetrics, 0, len(AllScenarios)*len(AllAdversaryFractions)*len(AllAggregators))
	cellLeafDigests := make([]string, 0, cap(cells))
	var neg1 []NegativeRegime1Entry

	for _, sc := range AllScenarios {
		ceiling := cleanCeilings[sc]
		for _, f := range AllAdversaryFractions {
			for _, agg := range AllAggregators {
				cm, _ := RunSingleCell(ds, seed, sc, f, agg, DefaultNumNodes, DefaultNumRounds, cfg, ceiling)
				cells = append(cells, cm)
				cellLeafDigests = append(cellLeafDigests, CanonicalCellLeafHash(cm))

				if sc == ScenarioHonestDisagreement && f == 0.0 {
					neg1 = append(neg1, NegativeRegime1Entry{
						Aggregator:                   agg,
						MajorityHonestAcceptanceRate: cm.MajorityHonestAcceptanceRate,
						MinorityHonestAcceptanceRate: cm.MinorityHonestAcceptanceRate,
						MajorityTestAccuracy:         cm.MajorityTestAccuracy,
						MinorityTestAccuracy:         cm.MinorityTestAccuracy,
						JainsFairnessIndex:           cm.JainsFairnessIndex,
						AttributionGini:              cm.AttributionGini,
					})
				}
			}
		}
	}

	neg2 := RunNegativeRegime2(ds, seed, cfg)
	neg3 := RunNegativeRegime3(ds, seed, cfg)

	auditMerkle := ComputeMerkleRoot(cellLeafDigests)
	report := &BenchmarkReport{
		SchemaVersion:      SchemaVersion,
		Seed:               seed,
		NumNodes:           DefaultNumNodes,
		NumRounds:          DefaultNumRounds,
		FeatureDim:         FeatureDim,
		CorpusPaperCount:   len(ds.Papers),
		ProtocolPaperCount: ds.ProtocolPaperCount,
		ConservPaperCount:  ds.ConservPaperCount,
		ProtocolParaCount:  ds.ProtocolParaCount,
		ConservParaCount:   ds.ConservParaCount,
		CorpusSHA256:       ds.CorpusSHA256,
		Config:             cfg,
		Cells:              cells,
		NegativeRegimes: NegativeRegimes{
			Regime1MinorityErasureAtZeroAdv: neg1,
			Regime2UnmonitoredBackdoor:      neg2,
			Regime3FiftyPctAndCommittee:     neg3,
		},
		AuditMerkleRoot: auditMerkle,
	}

	trace := buildAuditTrace(ds, seed, cfg, auditMerkle)
	return report, trace, nil
}

func buildAuditTrace(ds *CorpusDataset, seed int64, cfg AggregationConfig, reportMerkle string) *AuditTraceArtifact {
	toAuditVal := func(exs []Example) []AuditValExample {
		out := make([]AuditValExample, len(exs))
		for i, ex := range exs {
			out[i] = AuditValExample{
				Domain:        ex.Domain,
				FeaturesMicro: VecToMicro(ex.Features),
				Label:         ex.Label,
			}
		}
		return out
	}

	type probeSpec struct {
		label    string
		scenario string
		f        float64
	}
	probes := []probeSpec{
		{"honest_disagreement_f00", ScenarioHonestDisagreement, 0.00},
		{"adversarial_semantic_f30", ScenarioAdversarialSemantic, 0.30},
		{"colluding_cartel_f30", ScenarioColludingCartel, 0.30},
		{"low_quality_noisy_f30", ScenarioLowQualityNoisy, 0.30},
		{"honest_disagreement_f30", ScenarioHonestDisagreement, 0.30},
	}

	rounds := make([]AuditScenarioRound, 0, len(probes))
	roundRoots := make([]string, 0, len(probes))

	for idx, ps := range probes {
		roster := buildNodeRoster(seed, DefaultNumNodes, ps.scenario, ps.f)
		rng := makeCellRNG(seed, fmt.Sprintf("audit-trace:%s", ps.label))

		// Run 2 warmup rounds to get a non-zero realistic base model & varied reputations.
		var baseModel [FeatureDim]float64
		reps := make([]float64, DefaultNumNodes)
		for i := range reps {
			reps[i] = 1.0
		}
		for wr := 1; wr <= 2; wr++ {
			wEnvs := generateRoundEnvelopes(ds, roster, ps.scenario, wr, baseModel, rng, false)
			wRes := AggregateRound(AggDSOReputationEvalGated, wEnvs, baseModel, reps, ds.ValProtocol, ds.ValConservation, cfg)
			for d := 0; d < FeatureDim; d++ {
				baseModel[d] += 1.15 * wRes.AggregatedDelta[d]
			}
			for i := 0; i < DefaultNumNodes; i++ {
				if wRes.Accepted[i] {
					reps[i] = math.Min(2.5, reps[i]*1.08+0.02)
				} else {
					reps[i] = math.Max(0.05, reps[i]*0.55)
				}
			}
		}

		// Quantize baseModel and reps to micro-units before round 3 so Go and Python start identically.
		baseMicro := VecToMicro(baseModel)
		baseModel, _ = VecFromMicro(baseMicro)
		repMicro := SliceToMicro(reps)
		for i := range reps {
			reps[i] = FromMicro(repMicro[i])
		}

		envs := generateRoundEnvelopes(ds, roster, ps.scenario, 3+idx, baseModel, rng, false)
		envDigests := make([]string, len(envs))
		for i, e := range envs {
			envDigests[i] = e.DigestSHA256
		}
		roundMerkle := ComputeMerkleRoot(envDigests)
		roundRoots = append(roundRoots, roundMerkle)

		expected := make([]AggregationResult, 0, len(AllAggregators))
		for _, agg := range AllAggregators {
			res := AggregateRound(agg, envs, baseModel, reps, ds.ValProtocol, ds.ValConservation, cfg)
			expected = append(expected, res)
		}

		rounds = append(rounds, AuditScenarioRound{
			Label:           ps.label,
			Scenario:        ps.scenario,
			AdvFraction:     ps.f,
			Round:           3 + idx,
			BaseModelMicro:  baseMicro,
			ReputationMicro: repMicro,
			Contributions:   envs,
			ExpectedOutputs: expected,
			RoundMerkleRoot: roundMerkle,
		})
	}

	return &AuditTraceArtifact{
		SchemaVersion:   SchemaVersion,
		Seed:            seed,
		CorpusSHA256:    ds.CorpusSHA256,
		Config:          cfg,
		ValProtocol:     toAuditVal(ds.ValProtocol),
		ValConservation: toAuditVal(ds.ValConservation),
		Rounds:          rounds,
		TraceMerkleRoot: ComputeMerkleRoot(roundRoots),
		ReportMerkle:    reportMerkle,
	}
}
