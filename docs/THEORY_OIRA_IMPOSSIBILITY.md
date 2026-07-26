# Impossibility Theorem — no per-item OIRA under auxiliary information

This document sketches the impossibility theorem `Thm 5.1` from the
paper. Rigor level: LaTeX-transcribable outline for a formal-methods
co-author to complete. Notation follows `THEORY_OIRA_FUNCTIONALITY.md`.

## 1. Theorem statement

**Theorem 5.1 (Impossibility of per-item OIRA under auxiliary information).**
Fix security parameter `λ`. Let `Π` be any protocol realizing an ideal
functionality that outputs the per-item aggregate `{(id, a(id)) : id ∈ I}`
to the aggregator `P_0`. Let `𝒜 = (𝒰, φ, ρ, τ)` be a public-auxiliary
tuple where:

- `𝒰` is an id universe of size `2^u` with `u ≥ 64`,
- `φ : 𝒰 → ℝ^d` is a polynomial-time-computable feature map,
- `π_pub : ℝ^d → V` is a public predictor for the score with
  correctness `ρ`: for `id` drawn uniformly from `𝒰`,
  `Pr[|π_pub(φ(id)) − a(id)| ≤ τ] ≥ ρ`,
- `τ > 0` is a discrimination threshold,
- `ρ ≥ 1/poly(λ)` is a noticeable feature-informativeness.

Then there exists a polynomial-time adversary `A^{aux}` with auxiliary
budget `q = O(|I|·log|𝒰|)` such that for every `id* ∈ 𝒰`:

```
Adv^{OIRA}_{Π, A^{aux}, id*, q}(λ)  ≥  ρ · (1 − 1/|I|)  −  negl(λ).
```

**Interpretation.** As long as (i) the score function is meaningfully
learnable from public features (`ρ` non-negligible) and (ii) the
intersection is non-trivial (`|I| ≥ 2`), no cryptographic mechanism
that reveals per-item aggregates can defeat this attack. The
impossibility is *not* about crypto weakness — it is about the
information leaked by the aggregate values themselves.

## 2. Why standard definitions do not capture this

Standard MPSI-CA / MPSI-CS security says: for every PPT adversary `A`
with access ONLY to the protocol transcript,

```
Adv^{standard}_{Π, A}(λ)  ≤  negl(λ).
```

This is FALSE for the aux-oracle adversary. The advantage above is `ρ`,
NOT negligible, whenever the auxiliary predictor is any good. The
definition failed to model `π_pub` because standard UC assumes
adversary knowledge is bounded by the ideal functionality's output —
but the functionality here IS the leaky output (per-item aggregate).

## 3. Adversary construction

We construct `A^{aux}` explicitly.

### 3.1 Setup phase

`A^{aux}` corrupts `P_0` (SP). Before the protocol runs, it precomputes:

1. For each `id ∈ 𝒰`, its feature vector `x_{id} := φ(id)` (offline,
   using `q = |𝒰|` if budget permits; else a random sample of `q` ids).
2. For each such `id`, the public prediction `ŝ_{id} := π_pub(x_{id})`.
3. Optionally: builds a KD-tree or LSH index over `{(ŝ_{id}, id)}`
   for fast nearest-neighbor lookup by score.

`A^{aux}` also knows `id* ∈ 𝒰` (the target — this is the game's
choice, not the adversary's).

### 3.2 Online attack

After receiving the protocol output `{(hash_j, s_j) : j = 1..|I|}` (or,
if IDs are not hashed, `{(id_j, s_j)}`):

**Case A (IDs not hashed):** trivial. `id* ∈ I` iff `id* ∈ {id_j}`.
Adversary wins with probability 1. No need for aux oracle.

**Case B (IDs hashed with public hash):** compute `hash(id*)`. `id* ∈ I`
iff `hash(id*) ∈ {hash_j}`. Adversary wins with probability 1. No need
for aux oracle. (This is what MPSI-CS with revealed intersection would
do — and this case shows why revealing intersection at all is broken
under public hashing.)

**Case C (IDs hashed with SP-unknown salt / MPSI-CS-style):** the
adversary CANNOT match hashes. But it can match SCORES:

1. Compute `ŝ* := π_pub(φ(id*))`.
2. Compute `Match := { j : |s_j − ŝ*| ≤ τ }`.
3. **Guess:** output "id* ∈ I" iff `Match ≠ ∅`.

### 3.3 Success analysis of Case C

Two events:

- **Real membership event `M`**: `id* ∈ I`. By construction of the
  game, `M` occurs with probability 1/2 (game flips `b`).

- **False-positive event `FP`**: `id* ∉ I` but some other
  `id_j ∈ I` happens to satisfy `|s_j − ŝ*| ≤ τ`.

Adversary's outputs:

```
b' = 1  iff  Match ≠ ∅.
```

Case-by-case:

- **If `M` (id* ∈ I)**: there is a matching `id_j = id*` with
  `s_j = a(id*)`. By feature-informativeness, `|s_j − ŝ*| ≤ τ` with
  probability `≥ ρ`. So `Pr[Match ≠ ∅ | M] ≥ ρ`.

- **If not `M`**: `Match ≠ ∅` only if some other intersection id
  `id_j` has predicted score within τ of `ŝ*`. Assuming score values
  are "well-spread" (specifically: for any fixed `ŝ*`, the number of
  ids in the universe with `|π_pub(φ(id)) − ŝ*| ≤ τ` is `≤ 1/poly`),
  the probability of `Match ≠ ∅` for `|I|` random ids is bounded by
  `|I| / poly(λ)`, i.e., negligible in `λ` for `|I| ≤ poly(λ)`.

  Formalized: if `π_pub` is τ-separating with respect to `𝒰`
  (Definition 4.3, doc 4 — a natural assumption on any predictor that
  distinguishes IDs by score), then

  ```
  Pr[Match ≠ ∅ | ¬M] ≤ (|I| − 1) / N_{unique-scores} = negl(λ)
  ```

  where `N_{unique-scores}` is the τ-separated score cardinality of the
  universe (typically ≈ `|𝒰|` for continuous scores). Since we assumed
  `|I| ≤ poly(λ)` and `|𝒰| = 2^u ≥ 2^{64}`, this bound is negligible.

### 3.4 Advantage

```
Adv = |Pr[b' = 1 | M] − Pr[b' = 1 | ¬M]|
    = |Pr[Match ≠ ∅ | M] − Pr[Match ≠ ∅ | ¬M]|
    ≥ ρ − (|I| − 1)/N_{unique-scores}
    ≥ ρ − negl(λ)
    ≥ ρ · (1 − 1/|I|) − negl(λ)   (looser but cleaner form)
```

The `(1 − 1/|I|)` factor is included in the final theorem to handle a
technical corner case where `|I| = 1` and the adversary is guaranteed
to see the score of `id*` (making the guess trivially correct).

## 4. Assumptions used

**Assumption A (Feature informativeness).** The public predictor
`π_pub` achieves `Pr[|π_pub(φ(id)) − a(id)| ≤ τ] ≥ ρ` for
`id ← 𝒰`.

*Justification for financial vulnerability scoring:* the whole reason
we compute the vulnerability score is that it correlates with public
signals (leverage ratios visible in filings, credit ratings, industry
sector). If it didn't, the score would have no economic content. So
`ρ` is not just non-negligible in practice — it is often > 0.5.

**Assumption B (τ-separation).** The predictor is τ-separated: the
inverse image `{id : π_pub(φ(id)) ∈ [s − τ, s + τ]}` has size
`≤ poly(λ)` for every `s` in the score range.

*Justification:* for financial scores with real-valued output, and
`τ` set to the discretization scale of the released aggregate (e.g.,
6-digit fixed-point), the τ-ball around any specific score contains
few ids under any reasonable feature distribution. If Assumption B
failed, then the score would carry so little information that it
would be useless for the regulator's purpose.

**Assumption C (universe hardness of blind guessing).** `|𝒰| ≥ 2^64`.

*Justification:* company ID universes trivially satisfy this
(NRICs, VAT numbers, hashed identifiers).

## 5. Where the theorem does NOT apply

- **Aggregate granularity `g_{agg}`.** SP receives only `Σ_{id ∈ I} a(id)`.
  No per-item score is released. The adversary's matching step (§3.2)
  has no per-item output to match against. Attack fails.
- **k-bucketed `g_{bkt}^{(k)}` with `k` sufficiently large.** SP
  receives `Σ_{id ∈ I ∩ B_ℓ} a(id)` per bucket. If `|I ∩ B_ℓ| ≥ k`,
  the aggregate sum's distinctiveness is diluted: the adversary would
  need to guess which of `k` ids in the bucket has the matching score,
  reducing effective advantage by `1/k`. When `k` is chosen so that
  `k > 1/(ρ · advantage_target)`, the attack is defeated.

**Corollary 5.2** (informal). `F_OIRA` is realizable at aggregate
granularity `g_{agg}` (with the construction of paper §6) but NOT at
per-item granularity `g_{per}` under the assumptions of §4.

## 6. The reduction, more formally

The proof structure is a REDUCTION: we assume by contradiction that
`Π` realizes `F_OIRA(g_{per}, k, ε, ⊕)` with `Adv ≤ negl(λ)` against
any polynomial adversary with aux oracle, and derive a contradiction.

**Reduction:** given the assumed protocol `Π`, we build a distinguisher
`D` that breaks Assumption A (feature-informativeness) with non-
negligible advantage. Specifically:

1. `D` receives a challenge feature vector `x*` and score `s*`, and
   must decide whether `s* ≈ π_pub(x*)`.
2. `D` embeds `x*` as the feature vector of a synthetic id `id*` and
   sets up the intersection so `id*` is included with per-item aggregate
   value `s*`.
3. `D` runs `Π` (as the honest execution) and receives per-item output
   including `(hash*, s*)`.
4. `D` runs `A^{aux}` on the output. If `A^{aux}` guesses "id* ∈ I"
   correctly, `D` outputs "yes, correlated"; else "no".
5. `D`'s advantage in breaking Assumption A is exactly the advantage
   of `A^{aux}` in the OIRA game.

If `Π` is OIRA-secure (assumed for contradiction), then `A^{aux}`'s
advantage is negligible, so `D`'s advantage is negligible, so
Assumption A must be violated — but we posited Assumption A as
holding. Contradiction. Therefore no such `Π` exists.

## 7. Proof gaps and formalization TODOs

For a formal-methods co-author to close:

**Gap 1**: Formal statement + proof of τ-separation reducing false-
positive rate. Currently only sketched (§3.3). Needs: a probabilistic
argument on the distribution of `π_pub(φ(id))` over uniform `id`.

**Gap 2**: The reduction in §6 uses the auxiliary oracle in the
challenge phase, which is unusual. Standard reductions to hardness
assumptions don't grant the reduction access to an oracle. Two ways
to close: (a) fold the aux oracle into the assumption itself (i.e.,
Assumption A is stated relative to `π_pub` being efficiently
computable, which is equivalent), or (b) prove a stronger theorem
that doesn't need reduction (direct information-theoretic argument on
mutual information between per-item output and membership).

**Gap 3**: The DP noise `ε` in the protocol's ideal-functionality
output could reduce `ρ` (noised aggregates are less predictable). The
theorem should quantify this: `ρ_noised ≥ ρ − O(ε · magnitude(a))`.
For sufficiently large `ε`, the attack is defeated even at per-item
granularity — but at cost of accuracy that regulators typically won't
accept. This trade-off is worth explicit statement.

**Gap 4**: Adaptive auxiliary queries. `A^{aux}` in §3.1 uses
non-adaptive queries. Extending to adaptive attacks tightens the bound
but requires care in the reduction.

## 8. Comparison to prior impossibility results

| Result | Setting | Bound | Assumption |
|---|---|---|---|
| **Dwork 2003 (De-anonymization of Netflix)** | Empirical | Post-hoc | Public sparse data + released ratings correlated |
| **Narayanan-Shmatikov 2008** | Empirical | Similar | Same |
| **Dinur-Nissim 2003 (Reconstruction attacks)** | Formal | Constant fraction rebuild given O(n) queries | Overly-precise statistical releases |
| **Bun-Ullman 2019 (Query composition bounds)** | Formal | ε-bound | DP composition on adaptive queries |
| **Falzon USENIX'25** | Empirical | Various | PJC-specific |
| **This paper (Thm 5.1)** | Formal | `Adv ≥ ρ · (1 − 1/\|I\|) − negl(λ)` | Feature informativeness ρ |

**Novelty positioning:** the prior formal impossibility results are
about VOLUME of queries or reconstruction of full datasets. Ours is
about MEMBERSHIP inference on a specific target given ONE public
correlation source. That's a distinct threat model that matches
regulatory concerns.

## 9. What this section becomes in the paper

- §5 of the paper (impossibility)
- ~3 pages LNCS
- Followed by §6 positive construction that OPPOSES this theorem by
  operating only at aggregate granularity (or bucketed granularity
  with sufficient k)
- Sets up §7 lower bound (which shows the positive construction is
  optimal for its granularity)

Total: this theorem is the LOAD-BEARING theoretical contribution. It
justifies why the framework is needed, why per-item outputs are
categorically insufficient, and why aggregate-only outputs are the
right target. Everything else in the paper reduces to defending or
extending this.

## 10. Bibliography seeds

- Yeom et al. 2018 — Privacy Risk in ML: Analyzing the Connection to
  Overfitting. (Membership inference formalization)
- Dinur-Nissim 2003 — Revealing Information While Preserving Privacy
- Bun-Ullman 2019 — Fingerprinting Codes and Composition of DP
- Falzon et al. 2025 — Learning from Functionality Outputs (USENIX)
- Naor-Yogev 2015 — Bloom Filters in Adversarial Environments (related
  aux-oracle style analysis)
- Cheu et al. 2019 — Distributed Differential Privacy via Shuffling
