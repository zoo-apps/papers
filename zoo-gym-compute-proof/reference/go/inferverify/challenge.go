// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// DeriveEpochBeacon computes the deterministic commit-reveal epoch beacon
// revealed after workers log their DSSE attestations in the transparency log.
func DeriveEpochBeacon(seed uint64, epoch uint64) string {
	h := sha256.New()
	h.Write([]byte("inference-verify.v1:beacon:"))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], seed)
	h.Write(buf[:])
	h.Write([]byte(":"))
	h.Write([]byte(strconv.FormatUint(epoch, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeChallengeDrawBPS deterministically computes an unpredictable uniform
// draw in [0, 9999] from the post-commit epoch beacon, job ID, and committed
// worker output digest. Uses pure uint64 arithmetic for 100% Go <-> Python parity.
func ComputeChallengeDrawBPS(epochBeaconHex, jobID, workerOutputDigest string) uint64 {
	h := sha256.New()
	h.Write([]byte("inference-verify.v1:challenge:"))
	h.Write([]byte(epochBeaconHex))
	h.Write([]byte(":"))
	h.Write([]byte(jobID))
	h.Write([]byte(":"))
	h.Write([]byte(workerOutputDigest))
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint64(sum[:8])
	return v % ChallengeDenominatorBPS
}

// EffectiveChallengeBPS computes the deterministic challenge probability in
// basis points [0, 10000] for a case under the configured regime and policy.
func EffectiveChallengeBPS(regime string, risk WorkerRiskContext, policy VerificationPolicy, override *uint64) uint64 {
	switch regime {
	case RegimeSignedAttestationOnly, RegimeIndependentReexec:
		return 0
	case RegimeRandomChallenge:
		if override != nil {
			return clampBPS(*override, 0, ChallengeDenominatorBPS)
		}
		return clampBPS(policy.ChallengeBaseBPS, policy.MinChallengeBPS, policy.MaxChallengeBPS)
	case RegimeHybridAttestedChal:
		if override != nil {
			return clampBPS(*override, policy.MinChallengeBPS, policy.MaxChallengeBPS)
		}
		// Risk-adaptive escalation within constitutionally bounded [min, max]:
		// probationary workers, low-reputation workers, or AI-flagged workers
		// escalate from ChallengeBaseBPS to ChallengeEscalatedBPS.
		if risk.JobsCompleted < policy.ProbationJobs ||
			risk.ReputationScore < policy.ReputationThreshold ||
			risk.AIAdvisoryFlagged {
			return clampBPS(policy.ChallengeEscalatedBPS, policy.MinChallengeBPS, policy.MaxChallengeBPS)
		}
		return clampBPS(policy.ChallengeBaseBPS, policy.MinChallengeBPS, policy.MaxChallengeBPS)
	default:
		return 0
	}
}

func clampBPS(v, lo, hi uint64) uint64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// EconomicAnalysis holds exact closed-form economic security metrics for a
// challenge rate p and slashing regime.
type EconomicAnalysis struct {
	ChallengeRateP            float64 `json:"challenge_rate_p"`
	JobFee                    float64 `json:"job_fee"`
	HonestCost                float64 `json:"honest_cost"`
	CheatCost                 float64 `json:"cheat_cost"`
	CheatGain                 float64 `json:"cheat_gain"`
	SlashPenalty              float64 `json:"slash_penalty"`
	ExpectedHonestProfit      float64 `json:"expected_honest_profit"`
	ExpectedCheatProfit       float64 `json:"expected_cheat_profit"`
	CheatAdvantage            float64 `json:"cheat_advantage"`
	IncentiveCompatible       bool    `json:"incentive_compatible"`
	MinSlashForIC             float64 `json:"min_slash_for_ic"`
	MinChallengeRateForIC     float64 `json:"min_challenge_rate_for_ic"`
	StrictSlashOnlyIC         bool    `json:"strict_slash_only_ic"`
	StrictMinSlashBondOnly    float64 `json:"strict_min_slash_bond_only"`
}

// AnalyzeEconomics computes exact analytical expectations for a rational worker.
// Units in policy are centi-units (divided by 100.0 for reporting).
func AnalyzeEconomics(p float64, fee, honestCost, cheatCost, slash float64) EconomicAnalysis {
	cheatGain := honestCost - cheatCost
	expHonest := fee - honestCost
	expCheat := (1.0-p)*(fee-cheatCost) + p*(-slash-cheatCost)
	cheatAdv := expCheat - expHonest
	// Honesty strictly dominates when p * (fee + slash) > cheatGain.
	ic := p*(fee+slash) > cheatGain
	// Strict bond-only condition p * slash > cheatGain (even ignoring forfeited fee).
	strictIC := p*slash > cheatGain

	minSlash := 0.0
	strictMinSlash := 0.0
	if p > 0 {
		minSlash = (cheatGain / p) - fee
		if minSlash < 0 {
			minSlash = 0
		}
		strictMinSlash = cheatGain / p
	}
	minP := 1.0
	if fee+slash > 0 {
		minP = cheatGain / (fee + slash)
	}
	return EconomicAnalysis{
		ChallengeRateP:         p,
		JobFee:                 fee,
		HonestCost:             honestCost,
		CheatCost:              cheatCost,
		CheatGain:              cheatGain,
		SlashPenalty:           slash,
		ExpectedHonestProfit:   expHonest,
		ExpectedCheatProfit:    expCheat,
		CheatAdvantage:         cheatAdv,
		IncentiveCompatible:    ic,
		MinSlashForIC:          minSlash,
		MinChallengeRateForIC:  minP,
		StrictSlashOnlyIC:      strictIC,
		StrictMinSlashBondOnly: strictMinSlash,
	}
}
