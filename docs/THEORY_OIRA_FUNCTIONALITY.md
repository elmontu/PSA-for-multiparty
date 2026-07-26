# F_OIRA — Ideal functionality and threat model

This document specifies the ideal functionality `F_OIRA` (Output-Inference-
Resistant Aggregation) and the auxiliary-information adversary model that
distinguishes it from standard MPSI-CA definitions.

Notation is chosen to be LaTeX-transcribable directly. All symbols are
defined before use. Where a design choice has alternatives, they are
listed inline and the recommended default is marked ★.

## 1. Preliminaries

### 1.1 Parties

- N + 1 parties: N data-holding parties `P_1, ..., P_N` (banks) and one
  aggregator `P_0` (the regulator / SP).
- Static, semi-honest adversary. The adversary corrupts a subset
  `𝒞 ⊆ {P_0, P_1, ..., P_N}` at protocol start and follows the protocol
  honestly, viewing all internal state of corrupted parties.
- Standing assumption: `𝒞` does not include all N + 1 parties (some
  honest party exists). All variants of the protocol require at least
  one honest data-holding party.

### 1.2 Universe and inputs

- `𝒰`: the universe of possible entity identifiers (e.g., 128-bit
  hashes of company registration numbers). `|𝒰| = 2^u` for some
  `u ≥ 64`.
- Party `P_i` (i ∈ {1, ..., N}) holds a set `S_i ⊆ 𝒰` with `|S_i| ≤ m`
  and a per-item value function `v_i : S_i → V`. The value space `V`
  is a public parameter (e.g., `V = ℤ_{2^64}` for u64 sums, or
  `V = {0, 1}` for indicator functions).
- Intersection `I := ⋂_{i=1}^{N} S_i`.
- Per-item aggregate `a(id) := ⊕_{i=1}^{N} v_i(id)` for `id ∈ I`, where
  `⊕` is a public commutative associative operation (e.g., `+ mod 2^64`
  for sums, `∨` for OR-aggregation, `+ mod L` for bucket counts).

### 1.3 Auxiliary information

- Public feature function `φ : 𝒰 → ℝ^d` mapping each possible ID to a
  d-dimensional feature vector derived from public sources
  (financial disclosures, credit-rating databases, registrar filings).
  `φ` is efficiently computable and known to all parties + adversary.
- Auxiliary predictor `π : ℝ^d → V` is a polynomial-time computable
  function that approximates the per-item aggregate:
  `π(φ(id)) ≈ a(id)` for a large fraction of `id ∈ 𝒰`.
- Adversary's auxiliary budget `q ∈ ℕ`: bounds the number of `φ`
  queries and `π` evaluations the adversary can perform.
- Feature-informativeness parameter `ρ ∈ [0, 1]`: the fraction of
  ids in `𝒰` for which `|π(φ(id)) − a(id)| ≤ τ` for a discrimination
  threshold `τ`. Larger `ρ` = adversary can more reliably invert
  aggregates.

## 2. Output granularity

The distinguishing parameter of `F_OIRA` vs. standard MPSI-CA is what SP
learns about the aggregate. We formalize output granularity as a
partition `𝒢` of the intersection:

- **Per-item granularity** `g_{per}`: `𝒢 = {{id} : id ∈ I}`. SP learns
  `(id_j, a(id_j))` for every `id_j ∈ I`. This is what MPSI+shuffle
  gives.
- **Aggregate granularity** `g_{agg}`: `𝒢 = {I}`. SP learns
  `A := ⊕_{id ∈ I} a(id)` and nothing else per-item. This is what
  MPSI-CS gives.
- **k-bucketed granularity** `g_{bkt}^{(k)}`: `𝒢 = {B_1, ..., B_L}` a
  publicly-known partition with each `|B_ℓ| ≥ k`. SP learns
  `A_ℓ := ⊕_{id ∈ I ∩ B_ℓ} a(id)` for each `ℓ`. (Basis for the BOIRA
  primitive.)

## 3. Ideal functionality F_OIRA

### 3.1 Signature

```
F_OIRA(𝒢, k, ε, ⊕):
  input:  P_i sends (S_i, v_i) for i = 1..N
  output: P_0 receives {(g, A_g) : g ∈ 𝒢, |I ∩ g| ≥ k, plus DP noise ε}
          all other P_i receive nothing beyond protocol completion signal
```

Parameters:
- `𝒢`: output granularity partition (§2). ★ Default: `g_{agg}`.
- `k ≥ 1`: minimum intersection-cell size before releasing that cell's
  aggregate. Cells with `|I ∩ g| < k` are suppressed (SP learns "cell
  suppressed" but nothing else about it).
- `ε > 0`: DP privacy budget applied to each released aggregate value
  and to any released cardinality.
- `⊕`: the aggregation operation.

### 3.2 Execution

```
Setup:
    F_OIRA is initialized with (𝒢, k, ε, ⊕).

Input phase:
    Each P_i sends (S_i, v_i) to F_OIRA. F_OIRA verifies S_i ⊆ 𝒰 and
    |S_i| ≤ m; abort if not.

Computation phase:
    F_OIRA computes I := ⋂ S_i.
    For each g ∈ 𝒢:
        Let I_g := I ∩ g.
        If |I_g| < k:
            record (g, ⊥) in output list.  // suppressed cell
        else:
            A_g := ⊕_{id ∈ I_g} a(id)  where a(id) := ⊕_{i=1..N} v_i(id)
            Ã_g := A_g + Laplace(1/ε)  or GaussianMechanism(σ),
                   with sensitivity Δ_⊕ derived from ⊕ and value bounds.
            record (g, Ã_g) in output list.

Output phase:
    P_0 receives the output list.
    P_i (i > 0) receives ⊥.

Auxiliary oracle (adversary only):
    Adversary A_corrupt is granted q evaluations of φ : 𝒰 → ℝ^d and q
    evaluations of any polynomial-time π : ℝ^d → V of A's choice. The
    adversary interleaves these with normal protocol interaction.
```

## 4. Security definition (simulator-based, UC-style)

### 4.1 Real-vs-ideal advantage

**Definition 4.1 (OIRA-Membership Advantage).**
For a target id `id* ∈ 𝒰`, adversary `A`, protocol `Π`, and auxiliary
budget `q`:

```
Adv^{OIRA}_{Π, A, id*, q}(λ) :=
    | Pr[Exp^{real}(1, λ) = 1]  −  Pr[Exp^{real}(0, λ) = 1] |
```
where the experiment `Exp^{real}(b, λ)`:

1. Challenger flips `b ∈ {0, 1}`.
2. If `b = 1`: id* is included in the intersection (planted into every
   honest party's S_i); if `b = 0`: id* is included in *some* honest
   party's S_i but not all (so id* ∉ I).
3. Protocol runs. Adversary observes all messages to corrupted parties
   AND runs the auxiliary oracle up to q times.
4. Adversary outputs a guess `b'`. Return 1 iff `b' = b`.

### 4.2 F_OIRA-realization

**Definition 4.2 (F_OIRA-Realization).**
Protocol `Π` **realizes** `F_OIRA(𝒢, k, ε, ⊕)` in the auxiliary-info
adversary model with security parameter λ if:

1. **Correctness**: honest execution of `Π` produces the same output
   list distribution as `F_OIRA(𝒢, k, ε, ⊕)` for every honest input.
2. **Membership hiding**: For every polynomial-time adversary `A`
   with auxiliary budget `q ≤ poly(λ)`, every `id* ∈ 𝒰`:
   ```
   Adv^{OIRA}_{Π, A, id*, q}(λ) ≤ ε·q + negl(λ)  +  ρ · f(k)
   ```
   where `f(k)` is a monotonically-decreasing function of `k` (the
   k-anonymity effect), `ρ` is the feature-informativeness (§1.3), and
   the `negl(λ)` term captures standard cryptographic-security
   negligibility.

The bound `ε·q + negl(λ) + ρ·f(k)` is what the positive construction
must achieve (see doc 3, §6.1).

### 4.3 Standard-model simulator

For adversaries WITHOUT the auxiliary oracle, `Π` realizes `F_OIRA`
under the standard simulator-based UC definition: there exists a PPT
simulator `Sim` such that for every PPT adversary `A` corrupting `𝒞`,

```
{ REAL_{Π, 𝒞}(A, inputs) }  ≈_c  { IDEAL_{F_OIRA, 𝒞}(Sim, inputs) }
```

The **novel piece** of Def 4.2 vs. the standard UC definition: the
auxiliary oracle. Standard UC hides everything except what the
functionality releases; auxiliary-info UC additionally lets the
adversary use a public oracle that CORRELATES with hidden values. This
is what breaks per-item-output constructions.

## 5. Comparison to prior definitions

| Notion | Input privacy | Output privacy | Aux-info modeled? | What it fails to guarantee |
|---|---|---|---|---|
| MPSI (standard) | ✓ | Reveals intersection | ✗ | Membership |
| MPSI-CA | ✓ | Reveals \|I\| only | ✗ | Aggregate-value inference |
| MPSI-CS (Dong 2025) | ✓ | Reveals \|I\| + Σ value | ✗ | Same |
| PJC / PSI-Sum (Miao 2020) | ✓ | Reveals \|I\| + Σ value | ✗ | Same |
| DP (Dwork 2006) | ✗ (single party) | ε-noised output | ✗ | Doesn't apply to N-party |
| Distributed DP + MPC (Cheu 2019) | ✓ | ε-noised per-item aggregate | ✗ | Aux-info attacks on per-item outputs |
| **F_OIRA (this)** | ✓ | Cell-aggregates with k-thresh + ε-noise | ✓ | (the definition) |

## 6. Adversary construction (informal — full in doc 3)

The auxiliary-info adversary `A_aux` proceeds as follows against a
per-item-output protocol:

1. Observe SP's output list `{(id_j, s_j) : j = 1..|I|}` (or, if IDs
   are hashed, `{(hash_j, s_j)}`).
2. For a chosen target `id*`, query `φ(id*)` and learn feature vector
   `x* := φ(id*)`.
3. Train (or use pre-trained) predictor `π : ℝ^d → V` with public data.
4. Compute predicted score `ŝ* := π(x*)`.
5. Check whether any `s_j` in the released list is within threshold
   `τ` of `ŝ*`; if yes, output "id* ∈ I", else "id* ∉ I".

**Success rate:** if the score function is meaningfully correlated with
public features (which is the whole point of a "vulnerability score"),
`ρ = Pr[|π(φ(id)) − a(id)| ≤ τ]` is close to 1, and the adversary
wins with probability ≈ ρ.

Standard MPSI-CS security does NOT bound this — it only bounds
computational advantage over "does id* ∈ I" given the protocol
transcript, WITHOUT the aux oracle. `F_OIRA` explicitly captures the
aux oracle in the advantage bound.

## 7. Design rationale — why this specific formalization

**Why an auxiliary oracle model instead of a probabilistic-encoding
attack model?**

Both approaches capture the same failure mode. We chose the aux-oracle
model because:

1. It matches how real regulators think about "adversarial re-identification"
   — they explicitly worry about attackers with access to public
   databases. This lands with policy readers.
2. It's compatible with standard UC composition: the aux oracle is
   modeled as a shared functionality `F_aux` that adversary interacts
   with, and simulators are constructed with respect to `F_aux`.
3. It gives a QUANTITATIVE bound (ε·q + ρ·f(k)) that operators can
   reason about (choose k, ε to hit a target adv).

**Why not just require CARDINALITY hiding?**
Because cardinality-hiding alone (SP doesn't learn |I|) isn't enough
— even hiding |I|, revealing per-item aggregates leaks membership via
value distinctiveness. Cardinality hiding is orthogonal and can be
composed (release only k-anonymous aggregates).

**Why granularity as a parameter?**
Different regulator queries need different granularity (sector-wide
vs. industry-bucket vs. per-quantile). The framework should support
all three under one definition — hence `𝒢` as a partition.

## 8. Non-goals

- Malicious security (semi-honest is the target of this work; extension
  to malicious via corrected OKVS 2024/1989 is future work — §10 of the
  paper).
- Multi-jurisdictional or asynchronous execution.
- Streaming / continuous release. `F_OIRA` is one-shot per session.

## 9. What co-authors should verify

1. **Def 4.1 correctness**: is the game-based definition equivalent to
   the standard membership-inference-privacy game (Yeom 2018)?
2. **Def 4.2 tightness**: is `ε·q + negl(λ) + ρ·f(k)` the right bound,
   or is there a tighter analysis?
3. **Standard-model reduction**: does Def 4.2 imply the standard UC
   security when the aux oracle is empty?
4. **Composition**: is `F_OIRA` sequentially composable? Concurrently?
