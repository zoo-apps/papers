// SPDX-License-Identifier: Apache-2.0

package qfsim

import "fmt"

// detRNG is a deterministic 64-bit SplitMix64 PRNG (zero external dependencies,
// 100% reproducible across platforms).
type detRNG struct {
	state uint64
}

func newDetRNG(seed int64) *detRNG {
	return &detRNG{state: uint64(seed)}
}

func (r *detRNG) nextUint64() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *detRNG) intn(n int) int {
	if n <= 1 {
		return 0
	}
	return int(r.nextUint64() % uint64(n))
}

func (r *detRNG) rangeInt64(lo, hi int64) int64 {
	if hi <= lo {
		return lo
	}
	span := uint64(hi - lo + 1)
	return lo + int64(r.nextUint64()%span)
}

func cloneProposals(base []GrantProposal) []GrantProposal {
	out := make([]GrantProposal, len(base))
	copy(out, base)
	return out
}

// buildHonestCommunity constructs the canonical 120-donor honest Zoo DAO community
// aligned with zoo-dao-reputation-system.tex Table 3 tier distribution and
// spanning broad public goods, grassroots minority research, two honest research labs,
// and modest commercial niche donors.
func buildHonestCommunity(seed int64, proposals []GrantProposal) ([]Donor, []Contribution) {
	rng := newDetRNG(seed)
	donors := make([]Donor, 0, 120)
	contribs := make([]Contribution, 0, 400)

	// Index groups by archetype for targeted honest funding behavior.
	broadIDs := []string{
		"grant-01-conservation-ai",
		"grant-02-data-commons",
		"grant-03-citizen-science",
		"grant-04-desci-platform",
	}
	grassrootsIDs := []string{
		"grant-05-species-classification",
		"grant-06-habitat-modeling",
		"grant-07-educational-ai",
		"grant-08-wildlife-tracking",
	}
	labIDs := []string{
		"grant-09-federated-wildlife",
		"grant-10-satellite-ecology",
	}
	nicheIDs := []string{
		"grant-11-carbon-credits",
		"grant-12-research-coordination",
	}
	_ = proposals

	// 1. 96 independent grassroots & open-science community donors across ZooRep tiers.
	for i := 0; i < 96; i++ {
		id := fmt.Sprintf("honest-donor-%03d", i+1)
		var rep int64
		var baseAmt int64
		var isNewcomer bool
		switch {
		case i < 16: // Brand-new citizen scientists (<10 ZooRep)
			rep = rng.rangeInt64(0, 8)
			baseAmt = rng.rangeInt64(5, 14) * MicroZOO
			isNewcomer = true
		case i < 46: // Active Observers (10-49 ZooRep)
			rep = rng.rangeInt64(12, 48)
			baseAmt = rng.rangeInt64(8, 22) * MicroZOO
		case i < 74: // Contributors (50-199 ZooRep)
			rep = rng.rangeInt64(55, 195)
			baseAmt = rng.rangeInt64(12, 32) * MicroZOO
		case i < 87: // Stewards (200-499 ZooRep)
			rep = rng.rangeInt64(210, 480)
			baseAmt = rng.rangeInt64(18, 45) * MicroZOO
		case i < 93: // Guardians (500-999 ZooRep)
			rep = rng.rangeInt64(520, 960)
			baseAmt = rng.rangeInt64(25, 60) * MicroZOO
		default: // Elders (1000+ ZooRep)
			rep = rng.rangeInt64(1050, 1850)
			baseAmt = rng.rangeInt64(35, 80) * MicroZOO
		}

		donors = append(donors, Donor{
			ID:         id,
			ClusterID:  fmt.Sprintf("indep-cluster-%03d", i+1),
			ZooRep:     rep,
			RepTier:    RepTierName(rep),
			IsNewcomer: isNewcomer,
		})

		// Each independent donor funds 2 broad grants + 1-2 grassroots grants + occasional lab/niche grant.
		b1 := broadIDs[rng.intn(len(broadIDs))]
		b2 := broadIDs[(rng.intn(len(broadIDs)-1)+1+indexOf(broadIDs, b1))%len(broadIDs)]
		g1 := grassrootsIDs[rng.intn(len(grassrootsIDs))]

		contribs = append(contribs,
			Contribution{DonorID: id, ProjectID: b1, AmountMicro: baseAmt},
			Contribution{DonorID: id, ProjectID: b2, AmountMicro: (baseAmt * 8) / 10},
			Contribution{DonorID: id, ProjectID: g1, AmountMicro: (baseAmt * 9) / 10},
		)
		if i%2 == 0 {
			g2 := grassrootsIDs[(indexOf(grassrootsIDs, g1)+1)%len(grassrootsIDs)]
			contribs = append(contribs, Contribution{DonorID: id, ProjectID: g2, AmountMicro: (baseAmt * 6) / 10})
		}
		if i%4 == 0 {
			l1 := labIDs[i%len(labIDs)]
			contribs = append(contribs, Contribution{DonorID: id, ProjectID: l1, AmountMicro: (baseAmt * 5) / 10})
		}
		if i%6 == 0 {
			n1 := nicheIDs[i%len(nicheIDs)]
			contribs = append(contribs, Contribution{DonorID: id, ProjectID: n1, AmountMicro: (baseAmt * 5) / 10})
		}
	}

	// 2. 18 legitimate tightly-knit research lab members (2 institutional labs of 9 members each).
	for i := 0; i < 18; i++ {
		id := fmt.Sprintf("honest-lab-%03d", i+1)
		labCluster := "lab-cluster-alpha"
		if i >= 9 {
			labCluster = "lab-cluster-beta"
		}
		rep := rng.rangeInt64(90, 380)
		amt := rng.rangeInt64(15, 35) * MicroZOO
		donors = append(donors, Donor{
			ID:          id,
			ClusterID:   labCluster,
			ZooRep:      rep,
			RepTier:     RepTierName(rep),
			IsHonestLab: true,
		})
		// Lab members legitimately support both lab grants plus one broad public good.
		contribs = append(contribs,
			Contribution{DonorID: id, ProjectID: labIDs[0], AmountMicro: amt},
			Contribution{DonorID: id, ProjectID: labIDs[1], AmountMicro: (amt * 9) / 10},
			Contribution{DonorID: id, ProjectID: broadIDs[i%len(broadIDs)], AmountMicro: (amt * 4) / 10},
		)
	}

	// 3. 6 legitimate commercial/ecosystem sponsors supporting niche grants + 1 broad grant.
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("honest-sponsor-%03d", i+1)
		rep := rng.rangeInt64(25, 260)
		amt := rng.rangeInt64(120, 260) * MicroZOO
		donors = append(donors, Donor{
			ID:        id,
			ClusterID: fmt.Sprintf("sponsor-cluster-%03d", i+1),
			ZooRep:    rep,
			RepTier:   RepTierName(rep),
			IsWhale:   true,
		})
		contribs = append(contribs,
			Contribution{DonorID: id, ProjectID: nicheIDs[i%len(nicheIDs)], AmountMicro: amt},
			Contribution{DonorID: id, ProjectID: broadIDs[i%len(broadIDs)], AmountMicro: 30 * MicroZOO},
		)
	}

	return donors, contribs
}

func indexOf(ss []string, target string) int {
	for i, s := range ss {
		if s == target {
			return i
		}
	}
	return 0
}

// BuildBenchmarkScenarios constructs all 15 deterministic scenarios for seed 1352:
//   - 1 honest baseline
//   - 5 Sybil identity-splitting scenarios (S in {2, 5, 10, 25, 50})
//   - 3 bribery collusion ring scenarios (C in {5, 15, 30})
//   - 3 reputation-farming sleeper cartel scenarios (C in {5, 15, 30})
//   - 1 whale plutocracy capture scenario
//   - 2 explicit negative-regime stress scenarios
func BuildBenchmarkScenarios(seed int64, baseCorpus []GrantProposal) []ScenarioSpec {
	scenarios := make([]ScenarioSpec, 0, 15)

	// 1. Honest Public Goods Baseline (0 attackers)
	{
		props := cloneProposals(baseCorpus)
		donors, contribs := buildHonestCommunity(seed, props)
		scenarios = append(scenarios, ScenarioSpec{
			ID:    "honest_public_goods_baseline",
			Title: "Honest Public Goods Baseline (0 Attackers, 120 Honest Donors)",
			AttackModel: AttackModel{
				Family:      "honest_public_goods_baseline",
				Description: "Zero adversarial accounts; measures baseline social welfare, grassroots funding share, and Gini equality across 12 real Zoo research grant proposals.",
			},
			MatchingPool:  DefaultMatchingPool,
			Params:        DefaultMechanismParams(),
			Proposals:     props,
			Donors:        donors,
			Contributions: contribs,
		})
	}

	// 2. Sybil Identity Splitting Sweep: S in {2, 5, 10, 25, 50}
	// 1 attacker splits fixed whale budget B = 25,000 ZOO (same budget as whale_plutocracy_capture)
	// across S zero-reputation fresh wallets (0 identity cost).
	sybilSizes := []int{2, 5, 10, 25, 50}
	const sybilBudget = 25_000 * MicroZOO
	for _, s := range sybilSizes {
		props := append(cloneProposals(baseCorpus), AdversarialShellProposal())
		donors, contribs := buildHonestCommunity(seed+int64(s)*17, baseCorpus)
		perWallet := sybilBudget / int64(s)
		rem := sybilBudget - perWallet*int64(s)
		for k := 0; k < s; k++ {
			id := fmt.Sprintf("sybil-s%d-%03d", s, k+1)
			amt := perWallet
			if k == 0 {
				amt += rem
			}
			donors = append(donors, Donor{
				ID:         id,
				ClusterID:  "attacker-sybil-funding-cluster",
				ZooRep:     0,
				RepTier:    RepTierName(0),
				IsAttacker: true,
			})
			contribs = append(contribs, Contribution{
				DonorID:     id,
				ProjectID:   "grant-13-adversarial-shell",
				AmountMicro: amt,
			})
		}
		scenarios = append(scenarios, ScenarioSpec{
			ID:    fmt.Sprintf("sybil_identity_splitting_s%d", s),
			Title: fmt.Sprintf("Sybil Identity Splitting (S=%d Fresh Wallets, B=25,000 ZOO, Costless IDs)", s),
			AttackModel: AttackModel{
				Family:               "sybil_identity_splitting",
				Description:          fmt.Sprintf("Single whale splits B=25,000 ZOO evenly across S=%d freshly minted 0-ZooRep Sybil wallets from a shared funding cluster targeting a synthetic low-merit shell grant.", s),
				AttackerCount:        s,
				SybilMultiplier:      s,
				DirectBudgetMicro:    sybilBudget,
				IdentityCostMicro:    0,
				TotalAttackCostMicro: sybilBudget,
				ObfuscatedClusters:   false,
			},
			MatchingPool:  DefaultMatchingPool,
			Params:        DefaultMechanismParams(),
			Proposals:     props,
			Donors:        donors,
			Contributions: contribs,
		})
	}

	// 3. Bribery Collusion Ring Sweep: C in {5, 15, 30}
	// C distinct real accounts with legitimate Observer/Contributor ZooRep (20-85 pts)
	// co-fund the adversarial shell grant at 200 ZOO each (+10% bribe coordination overhead).
	collusionSizes := []int{5, 15, 30}
	const perColluderContrib = 200 * MicroZOO
	for _, c := range collusionSizes {
		props := append(cloneProposals(baseCorpus), AdversarialShellProposal())
		donors, contribs := buildHonestCommunity(seed+1000+int64(c)*31, baseCorpus)
		rng := newDetRNG(seed + 2000 + int64(c)*13)
		directBudget := int64(c) * perColluderContrib
		bribeOverhead := directBudget / 10 // 10% coordination/bribe overhead
		for k := 0; k < c; k++ {
			id := fmt.Sprintf("bribe-ring-c%d-%03d", c, k+1)
			rep := rng.rangeInt64(20, 85) // Real existing accounts across Observer/Contributor tiers
			donors = append(donors, Donor{
				ID:         id,
				ClusterID:  "bribe-ring-cartel-cluster",
				ZooRep:     rep,
				RepTier:    RepTierName(rep),
				IsAttacker: true,
			})
			contribs = append(contribs, Contribution{
				DonorID:     id,
				ProjectID:   "grant-13-adversarial-shell",
				AmountMicro: perColluderContrib,
			})
		}
		scenarios = append(scenarios, ScenarioSpec{
			ID:    fmt.Sprintf("bribery_collusion_ring_c%d", c),
			Title: fmt.Sprintf("Bribery Collusion Ring (C=%d Distinct Accounts, 200 ZOO Each)", c),
			AttackModel: AttackModel{
				Family:               "bribery_collusion_ring",
				Description:          fmt.Sprintf("Coordinated cartel of C=%d distinct real accounts (20-85 ZooRep) bribed to co-fund a low-merit shell grant with 200 ZOO each and split the matching payout.", c),
				AttackerCount:        c,
				CollusionRingSize:    c,
				DirectBudgetMicro:    directBudget,
				BribeOverheadMicro:   bribeOverhead,
				TotalAttackCostMicro: directBudget + bribeOverhead,
				ObfuscatedClusters:   false,
			},
			MatchingPool:  DefaultMatchingPool,
			Params:        DefaultMechanismParams(),
			Proposals:     props,
			Donors:        donors,
			Contributions: contribs,
		})
	}

	// 4. Reputation-Farming Sleeper Cartel Sweep: C in {5, 15, 30}
	// C colluding accounts obfuscate their funding source (distinct singleton clusters!)
	// and invest 20 ZOO-equivalent farming effort per account to earn 55-75 ZooRep (Contributor tier)
	// before executing a synchronized 200 ZOO/account raid on the shell grant.
	const repFarmCostPerAccount = 20 * MicroZOO
	for _, c := range collusionSizes {
		props := append(cloneProposals(baseCorpus), AdversarialShellProposal())
		donors, contribs := buildHonestCommunity(seed+3000+int64(c)*43, baseCorpus)
		rng := newDetRNG(seed + 4000 + int64(c)*19)
		directBudget := int64(c) * perColluderContrib
		farmCost := int64(c) * repFarmCostPerAccount
		for k := 0; k < c; k++ {
			id := fmt.Sprintf("sleeper-c%d-%03d", c, k+1)
			rep := rng.rangeInt64(55, 75) // Farmed into Contributor tier (>=50 ZooRep)
			donors = append(donors, Donor{
				ID:         id,
				ClusterID:  fmt.Sprintf("sleeper-obfuscated-cluster-%d-%03d", c, k+1), // Obfuscated separate clusters!
				ZooRep:     rep,
				RepTier:    RepTierName(rep),
				IsAttacker: true,
			})
			contribs = append(contribs, Contribution{
				DonorID:     id,
				ProjectID:   "grant-13-adversarial-shell",
				AmountMicro: perColluderContrib,
			})
		}
		scenarios = append(scenarios, ScenarioSpec{
			ID:    fmt.Sprintf("reputation_farming_sleeper_cartel_c%d", c),
			Title: fmt.Sprintf("Reputation-Farming Sleeper Cartel (C=%d Obfuscated Accounts, Farmed Contributor Rep)", c),
			AttackModel: AttackModel{
				Family:               "reputation_farming_sleeper_cartel",
				Description:          fmt.Sprintf("Cartel of C=%d sleeper accounts in separate obfuscated funding clusters that invest 20 ZOO/account farming Contributor ZooRep (55-75 pts) before raiding the shell grant with 200 ZOO each.", c),
				AttackerCount:        c,
				CollusionRingSize:    c,
				DirectBudgetMicro:    directBudget,
				RepFarmCostMicro:     farmCost,
				TotalAttackCostMicro: directBudget + farmCost,
				ObfuscatedClusters:   true,
			},
			MatchingPool:  DefaultMatchingPool,
			Params:        DefaultMechanismParams(),
			Proposals:     props,
			Donors:        donors,
			Contributions: contribs,
		})
	}

	// 5. Whale Plutocracy Capture (1 non-Sybil wealthy donor dominating a niche project)
	{
		props := cloneProposals(baseCorpus)
		for i := range props {
			if props[i].ID == "grant-11-carbon-credits" {
				props[i].IsAttackerTarget = true
			}
		}
		donors, contribs := buildHonestCommunity(seed+5000, baseCorpus)
		const whaleBudget = 25_000 * MicroZOO
		donors = append(donors, Donor{
			ID:         "whale-plutocrat-001",
			ClusterID:  "whale-plutocrat-cluster",
			ZooRep:     60, // Legitimate Contributor account, 0 Sybils
			RepTier:    RepTierName(60),
			IsAttacker: true,
			IsWhale:    true,
		})
		contribs = append(contribs, Contribution{
			DonorID:     "whale-plutocrat-001",
			ProjectID:   "grant-11-carbon-credits",
			AmountMicro: whaleBudget,
		})
		scenarios = append(scenarios, ScenarioSpec{
			ID:    "whale_plutocracy_capture",
			Title: "Whale Plutocracy Capture (1 Non-Sybil Whale, 25,000 ZOO on Niche Grant)",
			AttackModel: AttackModel{
				Family:               "whale_plutocracy_capture",
				Description:          "Single wealthy non-Sybil donor contributes 25,000 ZOO (~2.5x total honest community spend) to niche grant-11-carbon-credits, contrasting linear plutocracy against QF and capped mechanisms.",
				AttackerCount:        1,
				SybilMultiplier:      1,
				DirectBudgetMicro:    whaleBudget,
				TotalAttackCostMicro: whaleBudget,
				ObfuscatedClusters:   false,
			},
			MatchingPool:  DefaultMatchingPool,
			Params:        DefaultMechanismParams(),
			Proposals:     props,
			Donors:        donors,
			Contributions: contribs,
		})
	}

	// 6. Negative Regime #1: Strict Reputation Gate (50 ZooRep, r_min = 0.00) Newcomer Starvation
	// 40 legitimate brand-new community researchers (0-8 ZooRep) rally around grant-03-citizen-science
	// while a 25-wallet Sybil attacker targets grant-13-adversarial-shell.
	{
		props := append(cloneProposals(baseCorpus), AdversarialShellProposal())
		donors, contribs := buildHonestCommunity(seed+6000, baseCorpus)
		// Remove established-tier donations to grant-03-citizen-science so grant-03 models a
		// newcomer-led grassroots citizen science proposal.
		filteredContribs := make([]Contribution, 0, len(contribs))
		for _, c := range contribs {
			if c.ProjectID == "grant-03-citizen-science" {
				continue
			}
			filteredContribs = append(filteredContribs, c)
		}
		contribs = filteredContribs

		// Add 40 legitimate brand-new community researchers (0-8 ZooRep) backing grant-03.
		rng := newDetRNG(seed + 6001)
		for k := 0; k < 40; k++ {
			id := fmt.Sprintf("newcomer-researcher-%03d", k+1)
			rep := rng.rangeInt64(0, 8)
			donors = append(donors, Donor{
				ID:         id,
				ClusterID:  fmt.Sprintf("newcomer-indep-%03d", k+1),
				ZooRep:     rep,
				RepTier:    RepTierName(rep),
				IsNewcomer: true,
			})
			contribs = append(contribs, Contribution{
				DonorID:     id,
				ProjectID:   "grant-03-citizen-science",
				AmountMicro: rng.rangeInt64(10, 28) * MicroZOO,
			})
		}
		// Add S=25 Sybil attacker with 10,000 ZOO targeting shell grant.
		const s = 25
		perWallet := sybilBudget / int64(s)
		for k := 0; k < s; k++ {
			id := fmt.Sprintf("neg1-sybil-%03d", k+1)
			donors = append(donors, Donor{
				ID:         id,
				ClusterID:  "neg1-sybil-cluster",
				ZooRep:     0,
				RepTier:    RepTierName(0),
				IsAttacker: true,
			})
			contribs = append(contribs, Contribution{
				DonorID:     id,
				ProjectID:   "grant-13-adversarial-shell",
				AmountMicro: perWallet,
			})
		}
		scenarios = append(scenarios, ScenarioSpec{
			ID:    "neg_regime_1_strict_rep_newcomer_starvation",
			Title: "Negative Regime #1: Strict 50-ZooRep Gate Starves Legitimate Newcomers",
			AttackModel: AttackModel{
				Family:               "negative_regime_strict_reputation",
				Description:          "Enforces strict 50-ZooRep Contributor gate (r_min=0.00): blocks S=25 Sybils to 0.00% extraction, but simultaneously starves 40 legitimate brand-new community researchers backing grant-03-citizen-science to 0.00% matching.",
				AttackerCount:        s,
				SybilMultiplier:      s,
				DirectBudgetMicro:    sybilBudget,
				TotalAttackCostMicro: sybilBudget,
				ObfuscatedClusters:   false,
			},
			MatchingPool:  DefaultMatchingPool,
			Params:        StrictRepMechanismParams(),
			Proposals:     props,
			Donors:        donors,
			Contributions: contribs,
		})
	}

	// 7. Negative Regime #2: Pairwise / COCM False-Positive Penalty on Tightly Knit Honest Research Lab
	// 24 honest co-located researchers in 1 institutional cluster ("lab-pacific-reef-genomics")
	// legitimately co-fund the 2 lab conservation grants (grant-09 & grant-10) with 0 attackers.
	{
		props := cloneProposals(baseCorpus)
		donors, contribs := buildHonestCommunity(seed+7000, baseCorpus)
		rng := newDetRNG(seed + 7001)
		for k := 0; k < 24; k++ {
			id := fmt.Sprintf("honest-reef-lab-%03d", k+1)
			rep := rng.rangeInt64(120, 460)
			amt := rng.rangeInt64(25, 55) * MicroZOO
			donors = append(donors, Donor{
				ID:          id,
				ClusterID:   "lab-pacific-reef-genomics",
				ZooRep:      rep,
				RepTier:     RepTierName(rep),
				IsHonestLab: true,
			})
			contribs = append(contribs,
				Contribution{DonorID: id, ProjectID: "grant-09-federated-wildlife", AmountMicro: amt},
				Contribution{DonorID: id, ProjectID: "grant-10-satellite-ecology", AmountMicro: amt},
			)
		}
		scenarios = append(scenarios, ScenarioSpec{
			ID:    "neg_regime_2_honest_lab_cocm_false_positive",
			Title: "Negative Regime #2: Pairwise/COCM False-Positive Suppression on Tightly Knit Honest Lab",
			AttackModel: AttackModel{
				Family:      "negative_regime_honest_lab_false_positive",
				Description: "Zero attackers; 24 legitimate researchers in one co-located conservation lab co-fund grant-09 and grant-10. Structurally resembles a collusion ring, suffering severe false-positive matching suppression under Pairwise QF and Hybrid COCM.",
			},
			MatchingPool:  DefaultMatchingPool,
			Params:        DefaultMechanismParams(),
			Proposals:     props,
			Donors:        donors,
			Contributions: contribs,
		})
	}

	return scenarios
}
