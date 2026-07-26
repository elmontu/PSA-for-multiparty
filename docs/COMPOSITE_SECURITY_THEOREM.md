# Composite security theorem for SVS

Session 3 of the theoretical chain. Integrates sessions 1 + 2 with Tool 5
+ the output-tier set-secrecy findings into a single upper bound on
adversary advantage for the SVS deployment.

Companion numerical evaluator: `tests/math/composite_bound.py`.

## Notation (recap)

- `N`: number of data-providing parties (banks + IRAS + DoS)
- `1` supervisor (MAS SupTech) — receives outputs
- `m`: Beneš size (padded to next power of 2 above intersection cardinality `C`)
- `c = |I|`: intersection cardinality
- `S = m·log₂m − m/2`: total Beneš switches
- `Q`: number of adaptive query sessions per fixed target population (e.g. quarterly runs)
- `𝒟`: public auxiliary information database (size `d = |𝒟|`)
- `κ`: cryptographic security parameter (128 or 256 bits)
- `ε_cell`: Mechanism 5.3 padding budget (Tool 5)
- `ε_agg`: DP-noise budget on the aggregate output
- `ε_card`: DP-noise budget on the cardinality output
- `k`: k-anonymity threshold on sector cells

## Adversary classes

**A_MAS** — semi-honest MAS with aux-info access
- Observes: per-sector aggregate table, top-N firm identifiers (if enabled), cardinality per sector
- Queries: 𝒟 up to poly(κ) times
- Runs: Q quarterly sessions across a stable population
- Wants: re-identify specific firms in the intersection

**A_bank** — semi-honest data provider (e.g. Bank A)
- Observes: its own inputs (owned data), its own share of MPSICS internal state, its own `sumI` from MPSICS
- Wants: (a) learn which of its own rows matched (row-membership),
         (b) learn which firms in the intersection came from OTHER parties

**A_coalition** — subset 𝒞 ⊆ {MAS, banks} with 𝒞 ≠ all
- Observes: union of individual observations
- Wants: whatever any member wants

## Composite security theorem

**Theorem (informal).** Let SVS run at parameters (N, m, C, Q, ε_agg,
ε_card, ε_cell, k) with padded values-vector encoding, sector-scoped
aggregation, output tiers (a) sector aggregates and (b) top-N identifiers.
For any adversary A_MAS bounded by poly(κ) time and aux-info budget d:

```
  Adv_SVS(A_MAS)  ≤   Adv_MPSICS(A_MAS)                             (T1)
                    + Adv_incidence(A_MAS, k, ε_cell)               (T2)
                    + Adv_output(A_MAS, ε_agg, ε_card, Q)           (T3)
```

with each term bounded as follows.

**T1 (Beneš + MPSICS cryptographic term).** From sessions 1 + 2:

```
  Adv_MPSICS(A_MAS)  ≤  γ(D)  +  negl(κ)
                     =  2^{-m log₂m / 2}  +  negl(κ)
```

At m = 1024: T1 ≤ 2^{−5120} + negl(κ). Negligible.

**T2 (Tool 5 incidence-pattern leakage).** From Prop 5.4 with Mechanism 5.3:

```
  Adv_incidence  ≤  1 / max(k, min_A ñ_A)
                 =  1 / (k + noise floor from ε_cell padding)
```

Under the one-sided geometric mechanism with budget ε_cell:
`E[padding] = (2^N − 1) / (e^{ε_cell} − 1)`, added to each cell.

**T3 (output-tier DP leakage).** From basic composition of ε_agg on each
sector's aggregate and ε_card on cardinality, across Q sessions and
`num_sectors` sectors:

```
  Adv_output  ≤  Q · num_sectors · (ε_agg + ε_card)
```

(Basic composition; advanced/Rényi tighter but this is the honest
conservative bound.)

**Consequence** — the SVS design is secure iff we choose (ε_cell, ε_agg,
ε_card, k) such that

```
  1/(k + padding_floor)  +  Q · num_sectors · (ε_agg + ε_card)  <  target advantage
```

The Beneš tier T1 is not the constraint at any realistic scale.

## Adversary A_bank bound

From session 2 c-injection formulation:

```
  Adv_bank_row_match  ≤  1 / c!  (across c matched rows)
```

For c ≥ 20 (k-anon minimum recommended for MAS quarters), c! ≥ 2.4·10^18 → advantage ≤ 4·10^{−19}. Overwhelming hiding.

For the SECOND bank concern (learning other parties' contributions),
`sumI` observed at Bank A leaks its own aggregate contribution. Bounded by:

```
  Adv_bank_other_contrib  ≤  d_bank_dict / (search_space_size)
```

For bank aggregation with values from a bounded domain [0, V], and bank
knows its own summary but not other parties', this is a subset-sum
distinguishing problem — no crypto guarantee, empirically well-hidden
when V/N is large.

## Adversary A_coalition bound

From tool4_coset.py knowledge-state enumeration:
- Router + Party → full closure → full leak of that party's π (own data)
- Matcher + Party → matcher already has full π → no marginal leak beyond matcher's baseline
- Router + Matcher → excluded non-collusion pair (system-level assumption)

So `Adv_coalition ≤ Adv_matcher + Adv_router` when coalition types are one-sided; excluded when Router+Matcher.

## Numerical operating point for MAS deployment

Recommended parameter set from the numerical evaluator (see
`tests/math/composite_bound.py`):

```
  N = 4         (MAS + 3 banks, or MAS + 2 banks + IRAS)
  m = 1024      (accommodates C ≤ 1024 intersection firms)
  Q = 4         (quarterly cycles per year)
  num_sectors = 20
  k = 25
  ε_agg = 0.5   per (sector, quarter) release
  ε_card = 0.1  per (sector, quarter) release
  ε_cell = 1.0  cell padding budget
```

Resulting advantage bound (see numerical output):

- T1 ≤ 2^{−5120}
- T2 ≤ 1/(25 + 8.7) ≈ 0.030
- T3 ≤ 4 · 20 · (0.5 + 0.1) = 48

**Wait — T3 is > 1.**

This is the finding. Under basic composition, four quarters times 20
sectors times ε=0.6 per query blows past 1. The composition budget is
the DOMINANT bottleneck by many orders of magnitude vs. everything else.

**Operational implications** (numerically verified in
`tests/math/composite_bound.py`, scenarios A–I):

1. **Quarterly per-sector releases at ε ~ 0.5 give Adv ≈ 48** —
   well above 1, meaning the DP bound is trivial (worst-case
   leakage) at this cadence. Neither basic nor Rényi α=2
   composition rescues this: scenario B (Rényi) gives ≈ 68.

2. **Sub-unity operating points require ALL of:** annual (not
   quarterly) cadence, ≤ 5 aggregate categories per session,
   per-query ε ≤ 0.02. Scenario H (annual, 5 sectors, ε=0.02)
   gives Adv ≈ 0.29. Scenario I (semi-annual, single global
   scalar, ε=0.05) gives Adv ≈ 0.18.

3. **This is the paper's most operationally significant result.**
   The Beneš-tier security analysis (sessions 1-2) shows the crypto
   is fine at any scale; the DP composition analysis (session 3,
   this doc) shows the OUTPUT DESIGN is the actual binding
   constraint. Reducing per-query granularity is more valuable
   than tightening the crypto.

4. **The trade-off is a POLICY question, not a technical one.**
   For a given (Q, num_sectors, ε), the composite bound is what
   it is. MAS must decide whether to accept looser cadence,
   coarser granularity, or a formally weaker privacy guarantee.
   There is no technical fix that escapes this trade-off within
   the framework as designed.

## Proof sketch (union bound)

The three terms decompose the adversary's advantage into disjoint
channels:

- T1: what A learns from the cryptographic transcript (MPSICS + Beneš)
- T2: what A learns from the released incidence pattern (Venn cells)
- T3: what A learns from released aggregates + top-N identifiers

Each channel's advantage is bounded independently; T1 is
information-theoretically bounded by γ(D), T2 by k-anon + padding, T3
by DP composition. Union bound is loose but standard and honest.

Tighter analysis requires showing the channels don't reinforce
(non-trivial for T2+T3 in particular, since released aggregates and
incidence patterns are correlated). Deferred to future session.

## What this theorem does NOT cover

- Malicious security (semi-honest only for v1)
- Adaptive corruption
- Non-uniform prior on π (all bounds assume uniform prior)
- Composition with EXTERNAL systems that observe SVS outputs

## Chain synthesis

| Session | Delivered | Fed into |
|---|---|---|
| 1 | Sharp H_∞(D) = m log₂m / 2 | T1 constant |
| 2 | Tight Theorem 4.2 (Party posterior = γ(D)) | T1 form |
| 3 (this) | Composite bound + operational recommendations | Paper's main theorem |
| 4-8 (planned) | Tool 3 mixing / Tool 4 both-blind / DP re-enable / benchmarks | Refinements |

Session 3 delivers the paper's **main theorem** and identifies the
paper's **operational punchline**: DP composition cost is the binding
constraint, not the crypto. This makes the paper more publishable
because it has a concrete deployment recommendation (reduce per-query
release granularity) that follows from the math.
