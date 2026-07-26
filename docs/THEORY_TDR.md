# TDR — Tiered Disclosure with Reveal budgets

The theoretical contribution anchoring the SVS paper (see
`PROBLEM_STATEMENT.md`). Written for a co-author with formal-privacy
training; treated as a working document, not a final proof.

## 1. The gap that TDR fills

**Standard DP composition** (Dwork 2006; Dwork-Kenthapadi-McSherry-Mironov-Naor
2006; advanced composition Dwork-Rothblum-Vadhan 2010):

> If mechanism M_1 is ε_1-DP and M_2 is ε_2-DP, the composition M(x) =
> (M_1(x), M_2(x)) is (ε_1 + ε_2)-DP (basic) or roughly √(2q ln(1/δ))·ε
> + qε(e^ε − 1)-DP for q releases (advanced).

**But standard DP assumes both outputs go to the same recipient.** If
M_1(x) and M_2(x) go to DIFFERENT parties with different observation
scopes, the composition analysis is loose — it overcounts privacy loss
by assuming the worst case (both released to a colluding adversary).

**In SVS:**
- Output (a): sector aggregate → MAS
- Output (b): TopN identifiers → MAS (same recipient here!)

Wait — same recipient. So standard composition would say ε_total =
ε_a + ε_b. Where's the tiered novelty?

**The novelty is in the STRUCTURE, not the recipient.** Output (a)
reveals a statistic OVER a set; output (b) reveals a subset of the set.
An aux-info adversary combining (a) and (b) can:

1. Learn the aggregate (a): mean_score for sector s
2. Learn TopN identifiers (b): some firms F_i with high score
3. Correlate: firms in TopN that fall in sector s "explain" a large
   fraction of the sector's high mean → SP infers *approximate* per-firm
   scores for TopN firms via joint reasoning

Standard ε_a-DP for (a) is against a single-query differential neighbor;
standard ε_b-DP for (b) is against a differential neighbor on identifier
selection. But the JOINT release lets the aux-info adversary run a
combined attack that exceeds max(ε_a, ε_b) and is not tightly captured
by ε_a + ε_b either.

**TDR proposes:** a mechanism-parametric privacy budget accountant where
the "cost" of a joint release (aggregate + subset-identifier) is
analyzed against a specifically-defined SUBSET-INFERENCE ADVERSARY, and
the composition bound is tight under a stated assumption on the
subset-selection rule.

## 2. Formal setup

**Data:** database D = {(id_i, x_i)}_{i ∈ [n]} where id_i is a firm
identifier and x_i is a private per-firm score in [0, 1] (WLOG after
scaling).

**Two mechanisms:**

**M_agg(D)** (sector aggregate): outputs a noisy scalar
```
M_agg(D) = mean(x_i) + Lap(1 / (n · ε_a))
```
Standard Laplace mechanism, sensitivity 1/n. ε_a-DP.

**M_top(D)** (top-N reveal): outputs a set T ⊂ {id_i} of size ≤ N
containing (approximately) the identifiers with the highest x_i. Two
variants:

- **Non-DP top-N:** T = { id_i : x_i ∈ top-N of {x_j} }. NOT DP. Reveals
  which N firms have the highest scores exactly.
- **Exponential-mechanism top-N:** T sampled via the exponential
  mechanism (McSherry-Talwar 2007) with utility u(D, id) = -rank(id in D)
  and privacy parameter ε_b. Each id_i is included in T with probability
  ∝ exp(ε_b · u / (2 · Δu)). ε_b-DP per included identifier.

We work with the exponential-mechanism version.

**TDR-adversary:** the game formalizing what "joint privacy loss" means.

```
Game G_TDR(A, D, D'):
    A is a polynomial-time adversary
    D, D' are neighboring databases differing in one entry (id*, x*)
    Challenger picks b ← {0, 1}
    If b == 0: A observes (M_agg(D), M_top(D))
    If b == 1: A observes (M_agg(D'), M_top(D'))
    A outputs guess b'
    A wins if b == b'
```

Standard DP would require Pr[A wins] ≤ 1/2 + f(ε_a + ε_b) — but this is
loose because M_top(D) and M_agg(D) are not independent given D, and
their JOINT distribution has more structure than a random product.

## 3. The three theoretical contributions

### 3.1 Contribution T1: **Tight composition bound for tiered mechanism**

**Theorem (TDR-Composition, informal):** Under Assumption 3.4 below, the
joint mechanism M(D) = (M_agg(D), M_top(D)) is (ε_agg + ε_sel)-DP where
ε_sel < ε_b when the exponential mechanism's utility is aligned with
the aggregate's dependency structure on the differential neighbor.

Precisely:

```
ε_sel := ε_b · (1 − φ(x*, N, n))
```

where φ ∈ [0, 1] captures the "explanatory redundancy" between the
top-N reveal and the aggregate. When x* is far from top-N (won't be
selected either way, i.e., φ ≈ 1), ε_sel ≈ 0 — the top-N reveal costs
nothing beyond what M_agg already leaked. When x* is exactly at the
top-N boundary (φ ≈ 0), ε_sel = ε_b (full cost). The formula bounds
the effective ε cost tightly.

**Novelty vs. prior work:**
- **Dwork-Rothblum-Vadhan advanced composition**: gives √(2q ln(1/δ))·ε
  bound; does not exploit inter-mechanism dependency structure
- **Rényi-DP composition (Mironov 2017)**: gives tight bounds per query
  but assumes independence, which fails here for aggregate+subset
- **Concurrent composition (Vadhan-Wang 2021)**: closest — but analyzes
  interactive vs non-interactive, not the aggregate/subset structure
- **TDR**: exploits the specific correlation between an aggregation
  mechanism and a subset-selection mechanism on the SAME database

**Proof strategy** (sketch):
1. Express the joint pdf of (M_agg(D), M_top(D)) as product of
   conditional pdfs
2. Show that M_top(D) | M_agg(D) has effective sensitivity reduced by
   φ(x*, N, n) because knowing the aggregate already constrains the
   top-N distribution
3. Apply Rényi composition on the conditional bound
4. Take max over all possible differential neighbors to get worst-case
   ε_sel

Gap for co-author: rigorous derivation of φ. Not obvious that a clean
closed form exists; may need a bound Φ(N, n) that dominates φ, giving
a slightly loose but still-tight-vs-basic bound.

### 3.2 Contribution T2: **Multi-party TDR under compositional trust**

**Theorem (TDR-MP, informal):** When M_agg and M_top are realized via a
multi-party MPC protocol with N parties, the TDR bound of §3.1 extends
to the multi-party setting when: (a) the MPC realizes the ideal
functionality with negligible cryptographic error; (b) at least one
party enforces the budget accountant.

The novelty here is that STANDARD multi-party DP-MPC analyses (Cheu
CRYPTO'19, distributed DP) assume uniform mechanism outputs. Under TDR
you have TWO output tiers, and the "at least one party enforces" bound
must account for adversary-controlled parties passing OR failing budget
checks.

Result: MP TDR realizes (ε_agg + ε_sel)-DP against a static N−1-corruption
adversary, with the same explanatory-redundancy factor φ from §3.1.

**Proof strategy:** UC composition of the MP-MPC ideal functionality
with the ideal TDR functionality. Standard machinery once §3.1 is done.

### 3.3 Contribution T3: **Regulatory-composition analysis**

Real regulators run this mechanism per quarter over YEARS. Cumulative
budget spending: T3 characterizes the effective ε per firm accumulated
after q quarterly releases, accounting for:

- Firm exit / entry (turnover in the intersection)
- Sector reclassification (firms moving between sectors)
- Growing publicly-available auxiliary information over time

**Theorem (TDR-Longitudinal, informal):** For a fixed firm F that
persists through q quarters, cumulative privacy loss is:

```
ε_cum(F, q) ≤ q · (ε_a + ε_sel) · (1 − churn_factor(F))
```

where churn_factor > 0 captures the "identity dilution" from other
firms entering/exiting the intersection over time. A firm surrounded by
churn accumulates less privacy loss than a persistent-across-quarters
firm because auxiliary-info adversary attributions become noisier.

**Novelty:** most longitudinal-DP analyses assume static populations.
TDR-Longitudinal explicitly incorporates dynamic populations, which
matches the real MAS SVS scenario where firms IPO, delist, restructure.

## 4. Assumption 3.4: Aligned-utility hypothesis

The tight bound in T1 requires a technical assumption:

**Assumption (Aligned Utility):** The exponential mechanism's utility
function u(D, id) is a monotone-decreasing function of some
transformation of x_i that is polynomially-related to the aggregate
statistic. Formally: exists polynomial-time g such that
u(D, id_i) = g(x_i, mean(x_·)) with |∂g/∂x_i| bounded.

For SVS: u(D, id) = -rank(id), which is a monotone function of x_i.
Rank is not literally a function of mean, but is polynomially-related
via order statistics. Assumption satisfied.

## 5. Weaker (but easier) baseline result

If T1's tight bound doesn't close cleanly, the fallback is:

**Baseline (Basic-TDR):** M realizes (ε_a + ε_b)-DP. Loose but proven
from standard composition. Useful as the "reference bound" from which
T1 provides improvement.

Even the baseline is publishable if paired with T3 (longitudinal
analysis, which IS novel) and a strong deployment section.

## 6. Path to journal

**Minimum viable paper (~15 pp):**
- Problem statement (§1 of paper, condensed from `PROBLEM_STATEMENT.md`)
- Formal setup (§2 of paper, from §2 above)
- Baseline TDR bound (Basic-TDR, easy composition, 2–3 pp)
- Realization: MP-TDR via MPC (from T2, 4–5 pp)
- Deployment: SVS with MAS, benchmarks (3–4 pp)

**Strong paper (~20 pp):** add T1 tight-composition + T3 longitudinal.

**Journal target (~30 pp):** all three T1/T2/T3 + full experimental
evaluation + regulatory-context section + open-source artifact.

## 7. What theoretical work remains

1. **Formal statement of φ in Assumption 3.4.** Currently sketched;
   needs a co-author to nail down.
2. **Proof of T1 (TDR composition).** Reduction to Rényi conditional
   composition; ~4–6 pp of formal work.
3. **Proof of T2 (MP UC-composition).** Standard machinery, ~3–4 pp.
4. **Proof of T3 (Longitudinal).** Requires modeling firm-churn — this
   is a nontrivial modeling contribution, not just composition.
5. **Related-work map.** Cheu 2019, Vadhan-Wang 2021, Balle-Barthe-Gaboardi
   2018, Mironov 2017.
6. **Empirical validation** of the φ bound: on synthetic SVS data,
   compare tight ε vs. basic composition; show gap is meaningful.

## 8. What theoretical work is REALLY novel vs. incremental

Honest self-assessment (mid-review defense):

- **T1 (tight composition)**: novel if the φ analysis pans out. Similar
  in spirit to concurrent-composition results but for a specific structural
  pattern (aggregate + subset). Reviewers may push back that the specific
  bound is not surprising — mitigation: pair with empirical eval showing
  practical improvement.
- **T2 (MP TDR)**: incremental — UC-composition of known primitives.
  Publishable as a subsection but not on its own.
- **T3 (longitudinal)**: **most novel**. Longitudinal DP with population
  churn has been touched (Chan-Shi-Song 2011 continual counting; Bun-Ullman
  2016 concentrated bounds) but not for the aggregate+subset pattern with
  DYNAMIC populations. This is where the paper earns its journal
  credentials.

## 9. Interlock with the deployment work

The theorems above are guarantees for the SYSTEM in
`PROBLEM_STATEMENT.md`. Every implementation choice should be checked
against whether it preserves the assumptions:

- Sector aggregation uses Laplace mechanism (T1 assumption ✓)
- TopN uses exponential mechanism, not deterministic top-N (T1 ✓)
- MPC is semi-honest, static N−1 corruption (T2 ✓)
- Budget accountant tracks per-(party, scope) across quarters (T3 ✓)
- No side-channels that violate the semi-honest model in the MPC (T2 ✓)

If we later introduce a component that violates any of these
(e.g., a deterministic top-N leak), the corresponding theorem's
assumption is broken and the privacy claim collapses. Discipline: any
new feature review must cite which theorem's assumptions it touches.
