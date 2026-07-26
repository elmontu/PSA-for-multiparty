# Math-tool validation suite

Computational validation of the five mathematical tools defined in the
theory doc for N-party PSA. All tests here are numerical / exhaustive
verification of stated claims; they are NOT proofs. Their role is
(a) catch bugs in the stated claims, (b) generate concrete numerical
evidence for the paper, (c) ground the abstract results in the actual
deployed code where possible (see `../unit/test_math_tool1_switching.cpp`
for the C++ integration).

**C++ port (session 8):** Every file in this directory has a native C++
counterpart in `../math_cpp/` — same numerical outputs, integrable into
the deployed CMake test suite. See `../math_cpp/CMakeLists.txt`.

## Running

```bash
# From repo root:
python3 tests/math/benes.py             # self-test of Benes reference impl
python3 tests/math/tool1_column_hom.py  # Tool 1 verification
python3 tests/math/tool2_min_entropy.py # Tool 2 verification
python3 tests/math/tool3_mixing.py      # Tool 3 (skeleton)
python3 tests/math/tool4_coset.py       # Tool 4 (skeleton)
python3 tests/math/tool5_moebius.py     # Tool 5 verification

# C++ integration:
./out/build/linux/tests/unit/test_math_tool1_switching
```

## Status per tool

| Tool | Python status | Notable finding |
|---|---|---|
| 1 — Column homomorphism | ✓ full: (i) exhaustive up to m=8, random up to m=32; (iii) exhaustive up to m=4, random up to m=32 | Prop 1.2 (iii) XOR-split identity verified over all 2^12 (a,b) pairs at m=4 |
| 2 — Min-entropy of D | ✓ full for exhaustive analysis (m≤8) + matrix-product proof of Lemma 2.4 (m≤32) | **Empirical H_∞(D) = S − m** at m∈{2,4,8}, tighter than doc's Θ(m). Lemma 2.2 bound holds but is loose by 256× at m=8. |
| 3 — Mixing amplification | ⚠ skeleton: convolution up to m=4; Fourier + Friedrichs-angle deferred | TV drops ~8× per composition at m=4 (fast mixing observed) |
| 4 — Coset factorization | ⚠ skeleton: knowledge-state closure + role classification; posterior computations deferred | Enumeration of all 16 knowledge states confirms Theorem 4.2 hiding cases match the paper |
| 5 — Möbius/zeta incidence | ✓ full: ζ/μ identity, Lemma 5.2 sensitivity, Mechanism 5.3 padding overhead, Prop 5.4 identification risk | **Doc says ΔI sensitivity ≤ 2^{N−1}; actual tight bound is 2^N − 1** (doc undercounts by factor 2) |

## Findings requiring theory-doc updates

1. **Tool 2 / Conjecture 2.6 — SHARP FORM (session 1 of Tools 2/3/4 chain, see
   `tool2_conjecture_2_6.py`)**: exhaustive enumeration at m ∈ {2, 4, 8}
   gives H_∞(D) = **m · log₂(m) / 2** exactly. Equivalently:

   - max M(σ) = 2^{S − m log(m)/2} = 2^{m(log m − 1)/2}
   - entropy loss S − H_∞ = m(log₂m − 1)/2 = half the switch count minus m/2

   This is much sharper than the doc's "m log m − Θ(m)" and gives an
   exact operational number: at m=1024 (typical MAS quarter), guessing
   probability is 2^{−5120}. Beneš entropy is NOT the security
   bottleneck at deployment scale.

   *Earlier note in this file that "H_∞ = S − m" was based on m=8 coincidence
   only — the correct sharp form is (m·log m)/2, which happens to equal
   S − m at m=8 alone.*

2. **Tool 5 / Lemma 5.2**: doc states "ℓ1(ΔI) can reach 2^{N−1}". The exhaustive
   test shows the tight bound is 2^N − 1 (achieved when a record is added
   at the full-N cell). The doc's bound is a factor of 2 loose.

## Composite bound (session 3, refreshed in session 7)

`composite_bound.py` evaluates the SVS composite security bound across
twelve parameter scenarios (A-L). Refreshed in session 7 with sessions
4/5/6 sharpenings.

**Regime 1 (historical, DP output layer enabled):**
- T1 (crypto guess, sessions 1-2): < 2^{-5120} at m=1024. Never binding.
- T4 (single-Beneš TV, session 6): ≈ 4/m² = 3.8e-6 at m=1024. Dominates T1
  but still tiny; not binding either. T_crypto = max(T1, T4).
- T2 (Tool 5 incidence): ≈ 0.04 with k=25. Small constant.
- T3 (DP composition): **DOMINANT.** Quarterly per-sector at ε=0.5 gives
  Adv ≈ 48 (basic), ≈ 69 (Rényi α=2). Sub-unity requires annual + ≤5
  sectors + ε ≤ 0.02 (scenarios H, I get to ≈ 0.18-0.79).

**Regime 2 (current deployment, DP disabled per 2026-Q3 direction):**
- Scenario J (MAS default quarterly, both-blind + two-server, DP off):
  **Adv = 0.039, binding term T2.**
- Scenario K (m=16K, k=50): Adv = 0.020.
- Scenario L (k=1, no k-anon padding): Adv = 0.632 — shows k-anon is
  load-bearing.
- To drop below 2%: bump k-anon threshold from 25 to 50 (T2 → 0.020).

**Session 4/5 coalition improvement (folded into T_crypto scope):**
- Same numerical γ(D) bound now covers 5 non-trivial coalitions instead
  of 1: matcher+party can no longer recover ρ_2 without router's b share.
- MAS + one bank collusion is now blocked from reverse-engineering the
  row-level shuffle.

**Session 5 comms cost (T5, not an Adv term):**
- 12 MB per party query at m=1024, 386 MB at m=16K (naive upper bound).
- Feasible for quarterly cadence.

**Paper's revised operational punchline:** *the crypto tier and the DP
tier are BOTH not required to be tight.* Just enabling both-blind +
two-server + k-anon padding gives sub-4% Adv without any DP budget,
covers 5× more coalitions than the currently-deployed single-server
variant, and has manageable comms cost.

## Deferred work

**Tool 2 collision-entropy H_2(D).**
Sharp form for H_2 is not yet fit — at m=8, H_2 = 14.47 while H_∞ = 12
and S − m/2 = 16. Empirical gap ~2.5 bits; no closed form yet. Feasible
via second-moment / transfer-matrix on cycle types (Prop 2.5's recursion).

**~~Tool 3 Friedrichs-angle analysis~~ — LANDED (session 6, `tool3_friedrichs.py`).**
Spectral / Fourier picture of D's mixing on S_m via the regular representation.
Findings at m=4:
- SV structure of M_D: only 2 non-zero non-trivial SVs (both = 0.25),
  in the 2-dim irrep. All other irreps (sign, both dim-3s) get killed
  in one step. Mixing bottleneck is a single hyperoctahedral-type irrep.
- Friedrichs angle between K_t and w·K_{t+1}·w^{-1} = 60° exactly
  (cos θ' = 0.5). By von Neumann product-of-projections:
  ||D̂||_op ≤ (cos θ')^{D-1} = 0.5² = 0.25 = σ_2. Tight bound, and
  a direct constructive proof of Tool 3 at m=4.
- Diaconis-Shahshahani bound verified against exact convolution for
  k = 1..6.
- Mixing time τ(ε) linear in log(1/ε); τ / log(1/ε) → 0.72 = 1/log(1/σ_2).

DEFERRED (session 6): scaling in m (regular-rep at m ≥ 6 tractable but slow);
block-diagonal decomposition by irrep via character projection;
domino-tableau branching S_m ↓ S_2 ≀ S_{m/2}.

**~~Tool 4 both-blind XOR variant~~ — LANDED (session 4, `tool4_both_blind.py`).**
Matcher holds a, router holds b, s = a XOR b. Verified at m=4:
- rho_both_blind(a, b) == rho(a XOR b) always (Prop 1.2 iii)
- Neither matcher nor router alone can compute ρ_1
- Matcher + Party (previously "full knowledge" in single-server) is
  STRICTLY IMPROVED: still no ρ_1 recovery without router's b share.
- Router + Party: no π recovery without matcher's a share
- Matcher + Router: full leak (excluded non-collusion pair, as expected)

Operational value: MAS + one bank coalition can no longer reverse-
shuffle intersection outputs. Real security improvement for SVS.

**~~Actual protocol for computing ρ_2 as a two-server evaluated object~~
— LANDED (session 5, `tool4_rho2_protocol.py`).**
Two-server oblivious evaluation of ρ_2 on party's private index i.
- Chain of 2D+1 OSN calls (D matcher κ_t, D router κ_t, 1 for π);
  wirings are public and free.
- Correctness verified at m ∈ {2, 4, 8}, 100 trials each.
- Matcher's final share uniform on {0,1}^m (chi-sq ✓); marginal
  distribution independent of b and of party's index i.
- Matcher+router collusion recovers plaintext trajectory (excluded).
- Cost projection at m=1024 (MAS quarter): 39 OSN calls, ~12 MB
  naive comms, feasible for quarterly interactive query.

Closes the operational gap from session 4: the both-blind variant
can now be a drop-in security upgrade to the deployed single-server
OIRA flow — matcher no longer needs to publish ρ_2 (which it can't
compute anyway), and party still learns its own ρ_2(i).

DEFERRED (session 5): OSN gadget itself simulated as ideal fresh-mask
(no OT extension); malicious security via authenticated OSN;
batched-query amortization.

**~~Tool 4 explicit simulator posteriors~~ — LANDED (session 2, `tool4_simulator.py`).**
Two experiments at m=4:
- **Full-permutation model** (Theorem 4.2 as stated): Party max posterior
  = γ(D) = 0.0625 EXACTLY. Pushforward argument confirmed — bound is TIGHT.
- **c-injection model** (SVS bank view, "which of MY c rows matched?"):
  Party max posterior = 1/c! = 0.5. Looser bound; different threat context.

At MAS scale (m=1024), combining with session-1's sharp H_∞ = m log m / 2:
γ(D) = 2^{-5120} — overwhelming hiding at the switching-network tier.
Router posterior = uniform prior (perfect); Matcher posterior = δ at π_true (full).
