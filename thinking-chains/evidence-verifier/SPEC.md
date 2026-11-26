# Open Evidence and Reasoning Verification Specification (v1.0.0)

- **Issue**: `zoo-apps/papers#8` (`HIP-1352` — *Open evidence and reasoning verification*)
- **Status**: Reference Specification v1.0.0
- **License**: Apache-2.0
- **Alignment**: Zoo Thinking Chains (`thinking-chains/thinking-chains.tex`), Law of Cognition (Principle 1), Artifact Calculus (Section 6), Constitutional Rules 7, 10, and 12 (`thinking-chains/sections/15-constitutional-rules.tex`), Differential Simulation & Verification (`thinking-chains/sections/19-failure-modes.tex`).

## 1. Purpose and Epistemic Scope

This specification defines a **deterministic, zero-dependency, LLM-free verification predicate** $V_{\text{evid}}(S, c) \to (v, r, d)$ that audits public research and reasoning claims against pinned public artifacts. It implements Constitutional Rule 10 (*Inspectable without an LLM*) and Rule 12 (*No self-granted authority*) for open research artifacts inspired by OpenThoughts, PaperQA, and Zoo Thinking Chains.

Crucially, this verifier distinguishes:
- **Reproducible evidence** (`VERIFIED_REPRODUCIBLE`): verifiable deterministically from pinned public bytes, exact arithmetic/statistical expressions, reproducible execution kernels or bounded confidence intervals, and acyclic grounded public reasoning DAGs.
- **Direct contradiction** (`REFUTED_CONTRADICTION`): pinned public evidence mechanically falsifies the claim (hash mismatch, numeric alteration, polarity reversal, calculation discrepancy, unit conflict, code digest mismatch, circular reasoning, or constitutional violation).
- **Insufficient evidence** (`UNSUPPORTED_INSUFFICIENT_EVIDENCE`): missing pinned sources, ungrounded premises, private/opaque chain-of-thought blobs, unverifiable free-form paraphrases without verbatim span anchors, or stochastic claims lacking declared statistical intervals.
- **Human-review boundary** (`INCONCLUSIVE_NEEDS_HUMAN_REVIEW`): explicitly subjective or external-domain judgments, low-overlap paraphrases allowed under non-strict span policy, or vacuously wide statistical bounds.

## 2. Constitutional Invariants (Pre-Verification Gate)

Before class-specific evaluation runs, every `EvidenceClaim` MUST pass two non-bypassable constitutional guards:

1. **No Self-Validation (`ERR_CONSTITUTIONAL_SELF_VALIDATION`)**:
   If `author_id != ""` and `verifier_id != ""` and `author_id == verifier_id`, verification immediately halts with `REFUTED_CONTRADICTION`. An AI agent or author MUST NEVER declare its own experiment or claim valid.
2. **Bounded AI Advisory Scope (`ERR_CONSTITUTIONAL_FORBIDDEN_ACTION`)**:
   Allowed values of `governance_action` are `""`, `"none"`, `"recommend"`, `"flag_conflict"`, `"estimate_value"`, and `"prepare_plan"`. Any claim attempting `"redefine_voting_rules"`, `"authorize_treasury"`, or `"self_declare_valid"` immediately halts with `REFUTED_CONTRADICTION`.

## 3. Verifiable Claim Classes

### 3.1 Cited Fact Verification (`citation_check`)

Inputs: `source_path`, `expected_sha256`, `section_hint`, `quoted_span`, `claimed_numbers`, `claimed_polarity`, `require_exact_span`, `review_scope`.

Evaluation order:
1. If `review_scope` is `"external_domain"` or `"subjective_judgment"` -> `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` (`ERR_HUMAN_REVIEW_REQUIRED`).
2. Required fields (`source_path`, `expected_sha256`, `quoted_span`) non-empty -> else `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_MISSING_CITATION_FIELDS`).
3. Relative path safety (no leading `/`, no `..` traversal) -> else `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_INVALID_SOURCE_PATH`).
4. Source file exists under pinned corpus root -> else `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_SOURCE_NOT_FOUND`).
5. `expected_sha256` must be 64 lowercase hex characters -> else `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_INVALID_SHA256_FORMAT`).
6. Raw file `SHA-256` must equal `expected_sha256` -> else `REFUTED_CONTRADICTION` (`ERR_SOURCE_SHA256_MISMATCH`).
7. If `section_hint` is non-empty, locate matching LaTeX section (`\section`, `\subsection`, `\begin{abstract}`, `\begin{theorem}[...]`, `\begin{lemma}[...]`, `\begin{principle}[...]`). Missing section -> `REFUTED_CONTRADICTION` (`ERR_SECTION_NOT_FOUND`).
8. Normalize both scoped source text and `quoted_span` using canonical `normalize_latex`:
   - Remove unescaped `%` comments to end of line.
   - Expand common Zoo paper macros (`\PoAI{}`/`\PoAI` -> `PoAI`, `\PoT{}`/`\PoT` -> `PoT`, `\Quasar{}` -> `Quasar`, `\LLM{}` -> `LLM`, `\DAO{}` -> `DAO`, `\ZOO` -> `ZOO`, `\Zoo` -> `Zoo`, `\TPS` -> `TPS`, `\EVM` -> `EVM`, `\IPFS{}` -> `IPFS`, `\REP` -> `REP`).
   - Unwrap formatting commands (`\textbf{...}`, `\emph{...}`, `\textit{...}`, `\textsc{...}`, `\texttt{...}`, `\text{...}`, `\mathrm{...}`).
   - Normalize `---` -> ` - `, `--` -> `-`, `~` -> space, `\%` -> `%`, `\,` / `\!` -> empty, strip `$`, `{`, `}`, `\noindent`, `\medskip`, `\bigskip`.
   - Collapse ASCII whitespace to single spaces and lowercase.
9. If normalized `quoted_span` is a substring of scoped normalized text:
   - **Numeric consistency**: Every number in `claimed_numbers` MUST match at least one parsed numeric literal in the ±380-char normalized context window (supporting commas `47,619`, scientific `10^9`, suffixes `K`/`M`/`B`/`GB`/`PB`/`ms`, and percentages) within relative tolerance `1e-5` (or abs `1e-9`). Any missing/mismatched number -> `REFUTED_CONTRADICTION` (`ERR_NUMERIC_MISMATCH`).
   - **Polarity consistency**: Extract enclosing syntactic clause around the matched span (bounded by non-decimal/non-abbreviation `.`, `;`, `\n`, or normalized em-dash ` - `). Check explicit negation tokens (`never`, `not`, `cannot`, `does not`, `may not`, `no premine`, `no coin`, `without`, `neither`, `none`).
     - If `claimed_polarity == "positive"` and the matched clause contains a direct prohibition/negation that does not appear inside `quoted_span` -> `REFUTED_CONTRADICTION` (`ERR_POLARITY_REVERSAL`).
     - If `claimed_polarity == "negative"` and the matched clause contains zero negation tokens -> `REFUTED_CONTRADICTION` (`ERR_POLARITY_REVERSAL`).
   - Otherwise -> `VERIFIED_REPRODUCIBLE` (`OK_CITATION_VERIFIED`).
10. If normalized `quoted_span` is NOT a substring of scoped text:
    - Split scoped text into sentence-like windows and find the window maximizing non-numeric content-token containment (`|tokens(quote) ∩ tokens(window)| / |tokens(quote)|`, tokens length >= 3).
    - If best content containment >= `0.70`:
      - If quote contains numeric tokens that conflict with numbers in the best window -> `REFUTED_CONTRADICTION` (`ERR_QUOTE_NUMERIC_ALTERATION`).
      - If negation polarity differs between quote and best window -> `REFUTED_CONTRADICTION` (`ERR_QUOTE_POLARITY_ALTERATION`).
    - If `!require_exact_span` and best content containment >= `0.45` and numbers (if any) are consistent -> `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` (`ERR_PARAPHRASE_NEEDS_HUMAN_REVIEW`).
    - Otherwise -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_QUOTE_NOT_FOUND`).

### 3.2 Mathematical & Statistical Calculation Verification (`calc_check`)

Inputs: `expression`, `variables`, `claimed_value`, `has_claimed_value`, `tolerance`, `tolerance_mode` (`"abs"` or `"rel"`), `expected_unit`, `claimed_unit`, `exact_rational`, `review_scope`.

Supported deterministic grammar (LL(1) recursive descent, identical across Go and Python):
- Literals: decimal integers, floats, scientific notation (`1e9`, `1e-6`), constants `pi`, `e`.
- Operators: unary `+`, `-`; binary `+`, `-`, `*`, `/`, right-associative `^`; grouping `(...)`.
- Functions: `abs(x)`, `sqrt(x)`, `ln(x)`, `log10(x)`, `exp(x)`, `floor(x)`, `ceil(x)`, `round(x, d)`, `min(...)`, `max(...)`, `sum(...)`, `mean(...)`, `median(...)`, `var(...)` (sample variance, `n >= 2`), `std(...)` (sample standard deviation, `n >= 2`), `pct_delta(new, old)`, `ratio(a, b)`, `hoeffding_upper(n, theta, p)`, `ci95_halfwidth(std, n)`.
- Exact rational mode (`exact_rational: true`): evaluates `+`, `-`, `*`, `/`, integer `^` via arbitrary-precision rationals (`math/big.Rat` in Go, `fractions.Fraction` in Python).

Evaluation order:
1. `review_scope` in `{"external_domain", "subjective_judgment"}` -> `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` (`ERR_HUMAN_REVIEW_REQUIRED`).
2. Empty `expression` or `!has_claimed_value` -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_MISSING_CALC_FIELDS`).
3. Unit check: if `expected_unit != ""` and `claimed_unit == ""` -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_MISSING_UNIT`); if both non-empty and `lower(trim(expected_unit)) != lower(trim(claimed_unit))` -> `REFUTED_CONTRADICTION` (`ERR_UNIT_MISMATCH`).
4. Parse & evaluate AST:
   - Syntax error -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_INVALID_EXPRESSION`).
   - Undefined variable -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_UNDEFINED_VARIABLE`).
   - Math domain error (division by zero, `sqrt(<0)`, `ln(<=0)`, `hoeffding_upper` with `theta <= p`, `std` with `<2` args, NaN/Inf) -> `REFUTED_CONTRADICTION` (`ERR_MATH_DOMAIN_ERROR`).
5. Tolerance comparison:
   - `tolerance_mode == "rel"`: `abs(computed - claimed) <= tolerance * max(abs(computed), 1e-12)`.
   - `tolerance_mode == "abs"` (default): `abs(computed - claimed) <= tolerance`.
   - Pass -> `VERIFIED_REPRODUCIBLE` (`OK_CALC_VERIFIED`).
   - Fail -> `REFUTED_CONTRADICTION` (`ERR_CALC_MISMATCH`).

### 3.3 Deterministic Code & Artifact Result Verification (`code_result_check`)

Inputs: `mode`, `program`, `expected_output`, `tolerance`, `artifact_payload`, `declared_sha256`, `samples`, `claimed_mean`, `has_claimed_mean`, `ci_halfwidth`, `stochastic`, `review_scope`.

Modes:
1. `deterministic_eval`: executes a bounded, pure-stdlib reference kernel (`sha256_canonical`, `merkle_root`, `bitdelta_scale`, `trimmed_mean`, `linear_reward`, `sortition_check`, `eval_expr`) with zero dynamic code execution (`eval`/`exec` prohibited). Compares computed result to `expected_output` (exact canonical JSON or numeric tolerance).
2. `artifact_hash`: computes `SHA-256` of `artifact_payload` (UTF-8 bytes) and verifies equality with `declared_sha256`. Missing payload or malformed digest -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE`; digest mismatch -> `REFUTED_CONTRADICTION` (`ERR_ARTIFACT_HASH_MISMATCH`).
3. `statistical_interval`: requires `len(samples) >= 3`, `has_claimed_mean == true`, `ci_halfwidth > 0`. Computes sample mean $\bar{x}$, sample std $s$, and $h_{95} = 1.96 \cdot s / \sqrt{n}$.
   - `abs(claimed_mean - mean) > ci_halfwidth` -> `REFUTED_CONTRADICTION` (`ERR_MEAN_OUTSIDE_CI`).
   - `ci_halfwidth < h_95 * (1 - 1e-6)` -> `REFUTED_CONTRADICTION` (`ERR_CI_UNDERESTIMATED`).
   - `ci_halfwidth > max(abs(mean) * 0.25, 1.0)` -> `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` (`ERR_CI_TOO_WIDE`).
   - Otherwise -> `VERIFIED_REPRODUCIBLE` (`OK_STATISTICAL_INTERVAL_VERIFIED`).
4. Stochastic runs without statistical bounds (`stochastic == true` and `mode != "statistical_interval"` and `declared_sha256 == ""`) -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_STOCHASTIC_REQUIRES_INTERVAL`).

### 3.4 Public Reasoning Chain Audit (`reasoning_chain_check`)

Inputs: `conclusion_step_id`, `steps[]`, `review_scope`.

Evaluation order:
1. `review_scope` in `{"external_domain", "subjective_judgment"}` -> `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` (`ERR_HUMAN_REVIEW_REQUIRED`).
2. Empty `steps` or empty `conclusion_step_id` -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_EMPTY_REASONING_CHAIN`).
3. Duplicate `step_id` -> `REFUTED_CONTRADICTION` (`ERR_DUPLICATE_STEP_ID`).
4. `conclusion_step_id` absent from `steps` -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_MISSING_CONCLUSION_STEP`).
5. Private CoT check (iterated in sorted `step_id` order): any step with `kind == "private_cot"`, `opaque_cot_blob == true`, or blank `public_rationale` -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_PRIVATE_COT_FORBIDDEN`).
6. Cycle detection (deterministic 3-color DFS over sorted `step_id`s): any cycle or self-loop -> `REFUTED_CONTRADICTION` (`ERR_REASONING_CYCLE`).
7. Dangling premise check: any `dep` in `depends_on` not in `steps` -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_DANGLING_PREMISE`).
8. Ancestor closure from `conclusion_step_id` (checked in sorted `step_id` order):
   - Every ancestor with empty `depends_on` MUST be `kind == "premise"` with non-empty `evidence_ref`.
   - Resolve `evidence_verdict`: use `step.evidence_verdict` if set, else resolve from prior verified claim verdicts in the same bundle by `evidence_ref`.
   - Any ancestor leaf with `REFUTED_CONTRADICTION` -> `REFUTED_CONTRADICTION` (`ERR_REFUTED_PREMISE`).
   - Any ancestor leaf with missing `evidence_ref`, non-premise kind, empty verdict, or `UNSUPPORTED_INSUFFICIENT_EVIDENCE` -> `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_UNVERIFIED_PREMISE`).
   - Any ancestor leaf with `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` -> `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` (`ERR_INCONCLUSIVE_PREMISE`).
9. Otherwise -> `VERIFIED_REPRODUCIBLE` (`OK_REASONING_CHAIN_VERIFIED`).

## 4. Canonical Serialization & Cross-Language Parity Commitment

To guarantee bit-identical audit commitments across independent implementations (Go and Python):
1. **Canonical Number Formatting**: Numeric outputs are formatted via `format_canonical_float(x)` — round to 9 decimal places (half away from zero), strip trailing zeros and trailing `.`, normalize `-0` to `0`.
2. **Canonical Result Digest**:
   `result_digest = SHA256("zoo:evidence-verifier:v1:result:" + canonical_json({claim_class, claim_id, computed_value, detail, evidence_sha256, reason_code, schema_version, verdict}))`
   with lexicographically sorted UTF-8 keys and compact separators (`,`, `:`).
3. **Audit Merkle Root**:
   Sort all `VerificationResult` entries lexicographically by `claim_id`.
   - Empty bundle: `SHA256("zoo:evidence-verifier:v1:merkle:empty")`.
   - Binary tree reduction: `parent = SHA256("zoo:evidence-verifier:v1:merkle:node:" + left_hex + ":" + right_hex)` (duplicating the last node when a level has odd length).

## 5. Evaluation Metrics

For a labeled benchmark of $N$ claims across the 4 verdict classes $V$:
- **Per-class Precision, Recall, F1** and **Macro F1** across all 4 verdict classes.
- **Mechanical False Verification Rate (Mechanical FVR)**: fraction of ground-truth `{REFUTED_CONTRADICTION, UNSUPPORTED_INSUFFICIENT_EVIDENCE}` claims erroneously predicted as `VERIFIED_REPRODUCIBLE`. Target: **0.00%**.
- **Overall False Verification Rate (Overall FVR)**: fraction of all non-`VERIFIED_REPRODUCIBLE` ground-truth claims (including `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` cherry-picking cases) erroneously predicted as `VERIFIED_REPRODUCIBLE`.
- **False Rejection Rate (FRR)**: fraction of ground-truth `VERIFIED_REPRODUCIBLE` claims NOT predicted as `VERIFIED_REPRODUCIBLE`.
- **Cross-Language Parity Rate**: fraction of claims with bit-identical `(verdict, reason_code, computed_value, result_digest)` between Go and Python implementations, plus identical `audit_merkle_root`. Target: **100.00%**.
