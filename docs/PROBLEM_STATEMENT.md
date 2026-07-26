# Problem Statement — Sectoral Vulnerability Surveillance (SVS)

**Status:** LOCKED. Prior speculative design docs (`DESIGN_VULN_SCORE.md`,
`DESIGN_VULN_SCORE_V2.md`) are superseded by this document. Any new
design work MUST reference the problem-set here, not those earlier
roadmaps.

## 1. Stakeholders (fixed)

| Stakeholder | Role | Data held | Output receives |
|---|---|---|---|
| **MAS SupTech** (customer) | Regulatory supervisor | None directly | (a) sector-level aggregates; (b) ranked top-N vulnerable firm identifiers |
| **Bank A, Bank B, ..., Bank K** (data providers) | Regulated entities | Per-firm credit exposure (loan balance, tenor, collateral coverage) | Nothing (they participate for compliance, don't get analytics) |
| **IRAS** (data provider) | Revenue authority | Per-firm income, taxable profit, sector code | Nothing |
| **Department of Statistics** (data provider) | Statistical agency | Per-firm revenue, employment, sector code (canonical) | Nothing |

Total N parties: MAS + K banks + IRAS + DoS. K in [3, 10] for realistic MAS
supervisory scope (domestic systemically-important banks).

**Fixed role separation:** MAS is the ONLY output recipient. Data
providers are compliance participants and get no analytics back. This
is the deployment constraint that pins the trust model.

## 2. The two concrete outputs

MAS asks the system, once per supervisory quarter:

### Output (a): Sector aggregate

For each sector code s (typically ~20 SSIC 2-digit sectors) and quarter
q:

```
SectorAgg(s, q) = (
    n = number of firms in sector s in this quarter's intersection,
    mean_score = mean vuln_score(F) for F in intersection ∩ sector s,
    quantiles = P25, P50, P75, P90 of vuln_score
)
```

Membership hidden (which specific firms are in sector s not revealed).
DP-noised as necessary.

### Output (b): Top-N most-vulnerable firms

MAS also receives:

```
TopN(q) = list of at most N firm identifiers with the highest
          vuln_score(F), sorted DESC by score, where N is
          publicly-fixed at protocol start (e.g., N=20).
```

Firm identifiers are revealed to MAS. Scores are revealed only in
approximate form (bucketed or ε-noised — TBD by TDR analysis).

## 3. The score

vuln_score(F) is a fixed publicly-known weighted combination of ratios:

```
vuln_score(F) = w_1 * loan_to_income(F)
              + w_2 * debt_to_ebitda(F)
              + w_3 * leverage(F)
              + w_4 * interest_coverage(F)
```

Weights w_i are PUBLIC (MAS Notice; not secret). Ratios derived from
per-firm quantities that no single party holds in full:

- loan_to_income(F) = (Σ_j Loan_j(F)) / Income_IRAS(F)
- debt_to_ebitda(F) = (Σ_j Loan_j(F)) / EBITDA(F)  [EBITDA from IRAS + DoS]
- leverage(F)      = (Σ_j Loan_j(F)) / Equity_DoS(F)
- interest_coverage(F) = Operating_income_IRAS(F) / InterestExpense_IRAS(F)

## 4. Threat model

**Adversary class:** semi-honest, static, up to N−1 corruptions.

**Adversary capabilities:**
- Sees all messages between corrupted parties
- Has an auxiliary-info database D (public firm registrar + published
  financial disclosures + credit-rating databases)
- Can make polynomial queries to D
- May be MAS itself (SupTech turning over data to a foreign supervisor,
  say) — protocol must protect against MAS re-identifying firms it isn't
  allowed to see individually

**Trust anchors:**
- At least one honest data provider (any single one of banks / IRAS / DoS)
- MAS is honest-but-curious (they'll follow the protocol, they may
  correlate outputs with side info)
- Setup phase (Beaver triple generation) has an honest dealer OR uses
  OLE-based generation (in-tree via `MpOleTriple`)

**Regulatory constraints (real):**
- **MAS Notice 634** (Risk Management of Data): personal / commercial
  data crossing institutional boundaries must be protected by measures
  proportional to sensitivity. Cross-party MPC satisfies this.
- **PDPA S13**: unauthorized transfer of personal data (including firm
  data classified as personal for SMEs where sole proprietor = person)
  requires deemed consent or specific exemption. Regulatory compliance
  action (MAS supervisory function) is a valid exemption but requires
  proportionality — hence bounded output (§2) with tiered disclosure.
- **IM8 clause 10.5–10.11**: data residency + classification. All
  compute stays in SG jurisdiction.
- **MAS TRM Guidelines §4.9**: cryptographic controls must be
  documented, reviewable, and cover key management lifecycle.

**Out of scope:**
- Malicious security (semi-honest only for v1)
- Adversary controlling ALL data providers (trivially learns everything)
- Timing / side-channel attacks on parties' local computation
- Protection against MAS being compelled by court order to reveal outputs

## 5. Privacy properties required

Let A = anonymous membership (SP does not learn F ∈ ⋂ except via TopN
reveal), P = per-firm score privacy for non-TopN firms, S = sector-only
aggregation for output (a), B = bounded reveal for output (b).

The problem asks: define + realize a mechanism satisfying (A ∧ P ∧ S ∧ B)
under composition with output tier (a) AND (b) computed from the same
underlying data in the same session.

**Concretely:**

1. **A** (Anonymous membership): MAS learns |sector ∩ intersection|
   ± Laplace noise, and TopN identifiers. MAS does NOT learn full
   intersection membership.
2. **P** (Score privacy for non-TopN): For firms F not in TopN, MAS
   learns nothing about vuln_score(F) beyond what sector aggregates
   already leak.
3. **S** (Sector aggregate obfuscation): sector aggregate values are
   ε_a-DP for a stated ε_a budget.
4. **B** (Bounded reveal): TopN identifier list has bounded size N (public
   parameter) and bounded reveal-DP ε_b for the accompanying scores.
5. **Composition**: total privacy budget spent per (party, quarter) is
   bounded by ε_a + ε_b + any query cost from multi-round protocol
   interaction. Persistent accountant (existing `MpOiraBudget`) enforces.

## 6. Where existing code fits

| Existing module | Fits into |
|---|---|
| `MpOira` | Sector-aggregate output (a) — one call per sector, budget-tracked |
| `MpOiraBudget` | Composition guard across (a) + (b) + across quarters |
| `MpMpcArithmetic::secureDivideU64Bin` etc. | Building the per-firm ratios and score |
| MPSICS (vendored) | Cardinality per sector, aggregate values per sector |
| MPSA `-mpsa` mode | NOT applicable — reveals per-row plaintext; wrong tier for MAS SVS |
| A-sum / A-mset-row integrity | NOT applicable to OIRA output; different threat model |
| VOLE-PSI backend | Applicable if we need per-firm intersection with OPRF privacy |

## 7. What is MISSING for the two outputs

**For output (a) sector aggregate:**
- ✓ MPSICS gives Σ over intersection per party — with `values` split.
- ✓ **Sector-scoped aggregation across ALL sectors in one driver run.**
  Implementation: each party locally computes `sector(id) = id % numSectors`
  and, for a target sector s, zeros per-item values where
  `sector(id) != s`. Driver
  (`tests/run_oira_all_sectors_smoke.sh`) loops over sectors,
  running one MPSICS per sector, collecting results into a single
  per-sector table. Verified with numSectors ∈ {3, 5, 10}:
  per-sector cardinalities sum to |I|, per-sector aggregates sum
  to whole-intersection aggregate.
- ✗ Missing: mean and quantiles rather than raw sum.
  For mean: two aggregates (sum + count), divide cleartext.
  For quantiles: needs order statistics under MPC — harder;
  approximate via histogram (BOIRA-style).

**For output (b) TopN:**
- ✗ Missing: cross-party per-firm score computation.
  Requires MPC secure ratio + weighted sum (Session 3 of prior
  roadmap; primitives exist).
- ✗ Missing: TopN selection under MPC.
  Needs oblivious sort or oblivious threshold + partial reveal.
- ✗ Missing: proof that the TopN reveal doesn't leak the entire
  ordering (only top-N is revealed; scores of position N+1, N+2, ...
  hidden).

**For composition (A ∧ P ∧ S ∧ B):**
- ✗ Missing: unified privacy accounting across (a) and (b).
  Standard DP composition gives ε_a + ε_b conservatively.
  A tighter analysis (advanced composition, Rényi-DP) could tighten;
  potentially a novel formalization for this specific tiered-output
  shape (see `THEORY_TDR.md`).

## 8. What THIS problem statement excludes

We are NOT solving:
- Time-series causal analysis (multi-quarter dynamics under MPC — a
  future extension)
- Federated ML training on the underlying data (out of scope; the
  score function is a fixed formula, not a learned model)
- Fraud investigation individual-firm alerts (different mechanism;
  breaks anonymous membership by design)
- Cross-jurisdictional aggregation (SG-only for v1)

## 9. Acceptance criteria

The problem is solved when we can produce:

1. A working end-to-end demo where N = 5 parties (MAS + 3 banks + IRAS)
   feed synthetic data, and MAS receives:
   - (a) sector aggregate table with 5+ sectors
   - (b) TopN=10 firm identifier list with approximate scores
2. Regression: outputs match cleartext computation to within DP noise
   at ε_a = 1.0, ε_b = 0.5 with |sector| ≥ 20 per bucket
3. Wall-clock < 30 min for K = 5 parties, |firms| = 10⁴ on a
   commodity workstation
4. Formal privacy statement: for each output, the property from §5
   is realized (proof at semi-honest level, matching stated adversary)
5. Deployment doc mapping the system to MAS TRM §4.9 controls
6. Journal-submission-quality writeup of the framework (see next doc)

## 10. Journal / venue targeting

For the paper track running in parallel:
- Primary: **PoPETs / PETS** (Proceedings on Privacy Enhancing
  Technologies) — natural home for the tiered-disclosure framework
- Secondary: **ACM CCS**, **NDSS** if the theoretical contribution
  (TDR — see `THEORY_TDR.md`) is strong enough
- Systems-track fallback: **ACSAC**, **AsiaCCS** for the deployment
  paper without heavy theory

The theoretical hook (justifying journal ambition) is TDR: **Tiered
Disclosure with Reveal budgets**, formalizing the composition of an
aggregate-reveal tier and an identifier-reveal tier under a unified
privacy budget. See `THEORY_TDR.md`.

## 11. Change control

Changes to this problem statement require:
1. Named stakeholder update (§1)
2. Output shape update (§2) — non-negligible re-scoping
3. Threat model change (§4) — requires re-verification of §5 privacy
   properties
4. Explicit sign-off note in the version history below

## Version history

- **v1.0** (this doc) — locked initial statement. Supersedes prior
  design docs.
