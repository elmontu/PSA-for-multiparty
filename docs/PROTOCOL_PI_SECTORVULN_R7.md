# Π_SECTORVULN — Rev 7 Deltas (over Rev 6)

Rev 7 is a **focused patch** over Rev 6. All unchanged sections of Rev 6 apply as-is.
This file specifies only the deltas.

Status: **conditional pass for prototype — not protocol-frozen.**

---

## Change log R6 → R7

| # | Area | Rev 6 | Rev 7 | Tag |
|---|---|---|---|---|
| 1 | DP CDF monotonicity | DGauss noise on histogram bins can produce negative counts → prefix-sum breaks CDF monotonicity → §11.2 quantile inversion fails silently | Post-noise clamp `⟨h̃[b]⟧ ← max(⟨h̃[b]⟧, 0)` (secure conditional zero-out) applied to every bin before prefix-sum; DP post-processing invariance preserves ε; §16 invariant "post-noise CDF non-decreasing" added | R26 |
| 2 | §8.2 slim sort — bucket dimension | Bitonic sort over the whole slim key including the log₂B-bit bucket dimension | **CONDITIONAL** oblivious small-domain radix sort on the (log₂B)-bit bucket dimension, enabled iff Φ.radix_enabled (deterministically derived from public (n, B, log n) via the break-even table below). At operational B ≤ 128 the composition saves comparator work on the deepest circuit; at B ≥ 168 it regresses and Rev 6 bitonic is used unchanged. Novelty is the honest break-even framing + one-hot reuse from §8.1 BucketIndex output | R27 |
| 3 | §16 invariants | 11 assertions | +3: post-noise CDF non-decreasing (R26); Φ.radix_enabled ⇒ §8.2.1 output equals bitonic reference (R27, conditional); Φ.radix_enabled is a public deterministic function (R27) | R28 |
| 4 | §17 freeze blockers | 8 items | +7: R26 formal (with utility-bias table); R27 formal (with break-even validation); exact discrete-Gaussian bias formula; full UC simulation proof of §8.2.1; empirical side-channel benchmarking; benchmark validation of the break-even table numbers; §8.1.1 accuracy claim reconciliation with §9 fixed-point ceiling (Phase-6 finding, R30) | R29 |

---

## §8.2.1 (NEW) — Oblivious small-domain radix sort for the bucket dimension  *(R27, CONDITIONAL novel exploitation of Seam C)*

**Status.** *Conditional novelty.* R27 is enabled iff `B ≤ B_crit` per
Φ.radix_enabled (see §17.11). At B > B_crit the segmented-scan overhead
exceeds the bitonic bit-saving; radix is disabled and Rev 6's full-key
bitonic is used. R27 disabled ⇒ Rev 6 semantics unchanged.

**Motivation.** Rev 6 §8.2 slim sort feeds a composite key
`(popkey, invalid=1−incl_m, bucket_m)` into a bitonic network. The `bucket_m`
component is a log₂B-bit integer, while `popkey` carries the population-scoping
bits (~10 bits) and `invalid` is a single bit. Bitonic sort treats all bits
uniformly — it pays log²N per row per bit of key. The `bucket_m` sub-key is
**small-domain** (B distinct values, B = O(1) vs N), which the generic
bitonic does not exploit. This is the surface-composition seam: BucketIndex
(§8.1) already produces a one-hot indicator over B positions; the downstream
sort discards that structure and pays generic comparator cost per bucket
bit. R27 exploits the one-hot instead.

**Algorithm.** Two-phase sort:

```
SlimSort_R27(Slim, popkey_bits, bucket_bits):
  n ← |Slim| (public)

  // Phase 1 — bitonic sort on the LARGE-domain key (popkey || invalid)
  Slim ← ObliviousBitonic(Slim, key = (popkey, invalid))
         // depth O(log²n); comparators are ~11 bits wide

  // Phase 2 — STABLE oblivious counting sort per (popkey,invalid) group on bucket_m
  // Executed as a secret-shared radix sort of one digit of width bucket_bits.
  // Because Phase 1 already grouped rows by (popkey, invalid), Phase 2 sorts
  // WITHIN each group; groups do not interleave.
  Slim ← ObliviousRadixByBucket(Slim, bucket_bits, groupkey=(popkey, invalid))

  return Slim  // sorted by (popkey, invalid, bucket)
```

`ObliviousRadixByBucket` (secret-shared counting sort, one digit):

```
ObliviousRadixByBucket(Slim, w, groupkey):
  // w = bucket bit-width; B = 2^w.
  n ← |Slim|
  // 1. Expand each row's bucket to a one-hot indicator over B positions.
  //    The one-hot already exists from §8.1 BucketIndex output — Rev 7 keeps it.
  ⟦oh[i][b]⟧ ← existing BucketIndex one-hot for row i, bucket b, for b ∈ [0,B)

  // 2. Segmented per-group prefix count within each (groupkey) segment.
  //    Group flags gflag[i] = [[groupkey(i) ≠ groupkey(i-1)]] (public after Phase 1
  //    because groupkey is now in sorted contiguous order — a Phase-1 output
  //    property; see security argument (a) below).
  //    For each bucket b: pos[i][b] = Σ_{j ≤ i, same group} oh[j][b]
  ⟦pos[i][b]⟧ ← SegScanFwd(⟦oh[i][b]⟧, ⟦gflag⟧, +)   // Hillis-Steele, log-depth

  // 3. Per-group total count per bucket.
  //    endflag[i] = [[gflag[i+1] == 1]] OR (i == n-1) — PUBLIC after Phase 1
  //    (same reason as gflag). Alternative: compute in shared bits if desired.
  ⟦cnt[i][b]⟧ ← SegBroadcastRev( ⟦endflag[i]⟧ · ⟦pos[i][b]⟧, ⟦gflag⟧ )

  // 4. Compute each row's target position within its group.
  //    For row i in group g with bucket b:
  //      target[i] = (Σ_{b' < b} cnt[i][b'])          [rows in lower buckets]
  //                + (pos[i][b] - 1)                   [row's own within-bucket index]
  //    Public prefix over b (public loop) + one gather per row.
  ⟦offset_below[i]⟧ ← Σ_{b'=0}^{bucket[i]-1} ⟦cnt[i][b']⟧
                    = Σ_{b'=0}^{B-1} ⟦oh[i]≥b'+1⟧ · ⟦cnt[i][b']⟧
                     // secret bucket[i] via one-hot inner-product
  ⟦target[i]⟧ ← ⟦offset_below[i]⟧ + ⟦pos[i][bucket[i]]⟧ − 1
                     // pos[i][bucket[i]] via one-hot inner-product

  // 5. Permute rows within group by target. Since groups are contiguous, this
  //    is a group-local scatter. Data-oblivious permutation on the (secret)
  //    target vector — implemented as an oblivious sort keyed by target (log
  //    depth on a log_2(N)-bit key), or by CGP ShareTranslate on preprocessed
  //    correlations. Either way the ACCESS PATTERN is public (data-oblivious).
  Slim ← ObliviousPermute(Slim, targets)

  return Slim
```

**Cost comparison (per slim table, deepest circuit path).**

| Approach | Comparator work | Depth |
|---|---|---|
| Rev 6 bitonic on full key (popkey ‖ invalid ‖ bucket) | O(n · log²n · (popkey_bits + 1 + log₂B)) | O(log²n) |
| Rev 7 two-phase (Phase 1 bitonic on (popkey,invalid) + Phase 2 radix on bucket) | O(n · log²n · (popkey_bits + 1)) + O(n · B · log n) [+ ObliviousPermute] | O(log²n) + O(log n) |

**Break-even table (per element, n=2^21, popkey_bits=10, invalid=1;
ObliviousPermute assumed CGP-preprocessed → O(n) online, dominated by
scan work):**

| B | log₂B | Rev 6 comparator-bits | Rev 7 Phase-1 bits | Bit saving | Phase-2 scan (B·log n) | R27 net saving | Break-even? |
|---:|---:|---:|---:|---:|---:|---:|---|
|  32 | 5 | 16 · 441 = 7056 | 11 · 441 = 4851 | 2205 |  32·21 =  672 | +1533 | **wins** |
|  64 | 6 | 17 · 441 = 7497 | 4851 | 2646 |  64·21 = 1344 | +1302 | **wins** |
| 128 | 7 | 18 · 441 = 7938 | 4851 | 3087 | 128·21 = 2688 | +399 | **wins narrowly** |
| 168 | ~7.4 | 18.4·441 ≈ 8114 | 4851 | 3263 | 168·21 = 3528 | −265 | **≈ break-even** |
| 256 | 8 | 19 · 441 = 8379 | 4851 | 3528 | 256·21 = 5376 | −1848 | **LOSES** |
| 512 | 9 | 20 · 441 = 8820 | 4851 | 3969 | 512·21 = 10752 | −6783 | **loses hard** |

**Verdict.** `B_crit ≈ 128` for the provisional operational parameters
(n=2^21, log n = 21, popkey ~10 bits). At B ≤ 128, R27 saves on the
deepest circuit; at B ≥ 168, R27 is a regression. Provisional §9
default B=256 → R27 **disabled by default**; enable only if Φ chooses
B ≤ 128 (which halves quantile-bucket resolution vs B=256 — a policy
trade-off).

**Policy interface.** Φ.radix_enabled : bool, deterministically derived
from B and log n at Φ freeze time via the break-even formula above.
No secret data affects the enable decision — the parameter is public
and its evaluation is public.

If Φ.radix_enabled = false, §8.2 uses Rev 6's full-key bitonic; R27
machinery is dead code. If Φ.radix_enabled = true, §8.2.1 replaces
§8.2 sort step.

**Security argument (data-obliviousness).**

(a) **Phase-1 output group-flag is public.** After Phase 1, rows are in sorted
order by (popkey, invalid). The popkey values themselves are NOT public — they
are shared. But whether adjacent rows share a groupkey (`gflag[i] =
[[groupkey(i) ≠ groupkey(i−1)]]`) is a secret bit; we do NOT open it. The
segmented scan primitives operate on secret gflag. What is public is the
STRUCTURAL FACT that groups are contiguous after Phase 1 — this is a shape
property of the sort algorithm's output, not data-dependent.

(b) **One-hot bucket indicator is already present.** The `oh[i][b]` vector is
the output of §8.1 BucketIndex; Rev 7 reuses it. No new secret information
is introduced by the radix step.

(c) **Segmented scans are data-oblivious.** SegScanFwd and SegBroadcastRev are
fixed-shape Hillis-Steele networks; the access pattern depends only on n and
B (both public).

(d) **Target computation.** `target[i]` is a secret share of a public-range
integer. The final permutation step is either an oblivious sort keyed by
target (public access pattern; depth O(log n · log₂n)) or a CGP ShareTranslate
of a random permutation composed with a target-driven derangement (public
correlations from Stage O). Either sub-primitive is data-oblivious.

(e) **Correctness.** Standard stable radix (counting) sort correctness: for
each group g, output row order equals input row order sorted by `bucket_m`
(ascending), with stable resolution of ties on `bucket_m` because within-bucket
order is preserved by the prefix-count assignment. Because bitonic itself is
stable within equal keys (given the Hillis-Steele-style network), Phase 1 +
Phase 2 together yield the same sorted output as Rev 6's single bitonic on
the full composite key.

**Reduction / novelty positioning.** Small-domain oblivious sorts have been
studied in the MPC literature (counting sorts on shared indicators are
folklore). What is novel here is the composition + the break-even honesty:
the small-domain sub-key already arrives as a one-hot from BucketIndex (§8.1),
eliminating the per-row bucket-value comparison work that would otherwise
be needed inside the radix — the one-hot IS the digit representation. The
break-even table above quantifies exactly when this composition wins; the
crossover at B_crit ~ 128 at n = 2^21 is itself part of the contribution
(most literature presents small-domain sorts as unconditionally faster
without honest accounting of the segmented-scan constant). Publish-worthy
under the surface-composition principle: paying full-generality bitonic
cost when the upstream already produced a one-hot indicator IS the seam;
exploiting it changes the algorithm; the concrete break-even is the
research contribution's teeth.

---

## §12 — CDF-monotonicity clamp  *(R26, fixes Gap 11)*

Insert immediately after `each S_j adds η_{j,b} ← DGauss(σ_m²/2) locally`:

```
// R26 patch — non-negativity clamp to preserve CDF monotonicity.
// DGauss samples can be negative, so h̃[b] = h[b] + η_{j1,b} + η_{j2,b} may
// be negative. Prefix-sum on negative bins would produce a non-monotone
// C̃ and break the quantile-inversion §11.2 first-crossing logic.
parallel for b:
    ⟦clip_b⟧    ← [[⟦h̃[b]⟧ ≥ 0]]         // one secure compare per bin
    ⟦h̃[b]⟧     ← Select(⟦clip_b⟧, ⟦h̃[b]⟧, ⟦0⟧)
// C̃ = prefix-sum(⟦h̃⟧) is now guaranteed non-decreasing.
```

**Privacy accounting (no extra ε).** The clamp is a deterministic function
of the already-noised histogram `h̃`. By the post-processing invariance of
DP (Dwork-Roth Thm 2.1; specifically for zCDP see Bun-Steinke Prop 1.6):
any function applied to a DP-mechanism output preserves the mechanism's
`(ε, δ)` or `ρ` bound. The clamp is such a function. Therefore the total DP
budget accounted in §12 remains unchanged.

**Utility.** Clamping introduces bias — the released histogram is biased
upward from the true histogram by `Σ_b E[max(0, η_b) − η_b]` per cell,
where `η_b ~ DGauss(σ²)`. For symmetric zero-mean DGauss this bias is
`≈ σ / √(2π)` per clamped bin. Impact on quantile accuracy is bounded by
one bucket width per crossing — same order as the discretisation error
already accepted in §11.2. If tighter utility is required, an alternative
non-negative mechanism (truncated DGauss with rejection sampling, or
"peeling" the histogram as in Ghazi-Kumar-Manurangsi) can replace the clamp
at the same ε; deferred to Rev 8 policy.

**Correctness.** After the clamp, `h̃[b] ≥ 0` for all b. Then
`C̃[b] = Σ_{b'≤b} h̃[b']` is monotone non-decreasing in b. §11.2 crossing
logic operates as specified.

---

## §16 — Additional invariants  *(R28)*

Append to §16:

```
// R26 CDF clamp
assert after §12 R26 patch: every ⟦h̃[b]⟧ satisfies [[h̃[b] ≥ 0]]
assert C̃ = prefix-sum(⟦h̃⟧) is non-decreasing (opens as a monotone
      sequence when tested against a plaintext reference on synthetic input)

// R27 radix sort — conditional; assertions apply only when Φ.radix_enabled = true
assert Φ.radix_enabled ⇒ §8.2.1 output equals Rev-6 bitonic sort output on the
      same input (regression test against reference; synthetic slim tables,
      B ∈ {32, 64, 128}; disabled configurations B ∈ {256, 512} skip this test)
assert Φ.radix_enabled ⇒ §8.2.1 access pattern depends only on (n, B, popkey_bits)
      — public parameters only (verified by static analysis of the segmented
      scan and permute primitives)
assert Φ.radix_enabled is a deterministic public function of (n, B, log n) at
      Φ freeze time — no secret data affects the enable decision
```

---

## §17 — Additional freeze blockers  *(R29)*

Append to §17:

```
9. R26 formal note: max-clamp DP post-processing invariance proof (short) +
   utility-bias table showing clamp bias per σ per bin count, published for
   policy sign-off. Discrete-Gaussian bias formula must be derived exactly
   (Rev 7 uses `≈ σ/√(2π)` continuous-Gaussian approximation; §17.12 flags
   the exact formula obligation).
10. R27 formal note: oblivious counting/radix sort security proof — access
    pattern determined by (n, B) alone; equivalence to reference bitonic
    sort output on all inputs (conditional on Φ.radix_enabled = true).
11. **R27 break-even validation.** Analytical benchmark
    (`tests/math_cpp/rev7_r27_break_even.cpp`) computes **B_crit ≈ 152**
    at n = 2^21 (pk-invariant). **LOCKED-IN Φ POLICY:** B = 128 default,
    Φ.radix_enabled = TRUE at operational scale (annual + national);
    quarterly runs where n ≤ 2^18 keep bitonic (Φ.radix_enabled = false).
    Empirical validation on the target MPC backend still required before
    protocol freeze — this locks in the analytical value pending
    substrate confirmation.
12. Exact discrete-Gaussian bias formula: derive `E[max(0, η)]` for
    DGauss(σ²) over ℤ in closed form (theta-function representation) or
    precompute a σ-indexed table over operational σ values; used in the
    utility-bias sign-off (§17.9).
13. Full UC simulation proof of §8.2.1 in the F_PSA-hybrid model (not
    sketch); publish alongside R27 exposition.
14. Empirical side-channel benchmarking: static analysis + profiling run
    on synthetic vs real slim tables to verify identical instruction
    sequences and communication patterns for the segmented scans and
    ObliviousPermute.
15. **§8.1.1 accuracy claim vs §9 fixed-point ceiling (R30, Phase 6 finding).**
    Rev 6 §8.1.1 claims "≥ 40 fractional bits of accuracy on
    n_safe ∈ [1, 2^{20}]" for 6-iteration Goldschmidt, while Rev 6 §9 sets
    `f = 40`. These are arithmetically incompatible: the representation
    ceiling for 1/x in a k=128, f=40 fixed-point is
    `f − ⌈log₂ x⌉` bits, i.e. ≤ 20 bits at x = 2^{20}. Options for Rev 8:
    (a) narrow the claim to x ∈ [1, 2^{10}] where 30+ bits IS achievable;
    (b) split the reciprocal path to a wider fixed-point (f' ≥ 60) local
    to §8.1 and truncate back to f=40 downstream; (c) restate the accuracy
    target as `f − ⌈log₂ x⌉` bits (representation-ceiling accuracy). The
    Phase 6 semantic reference (`volePSI/MpsvsRatioBucket.cpp`) confirms
    the algorithm hits the ceiling in 6 iterations; the bug is in the
    Rev 6 spec statement, not the algorithm.
```

---

## Version log

- Rev 6 (prior). Baseline with 12 fixes over Rev 5.
- **Rev 7** (this file). Two focused patches: CDF-monotonicity clamp (R26, Gap 11) + oblivious small-domain radix sort in §8.2 (R27, exploiting Seam C). §16 gains 2 invariants; §17 gains 2 freeze blockers. No other section touched; all Rev 6 proofs remain in force.
- **Rev 7 (Phase 6 addendum).** Freeze blocker 15 added: §8.1.1 accuracy claim (40 fractional bits on x ∈ [1, 2^{20}]) is inconsistent with §9 `f = 40` fixed-point ceiling. Discovered while building the semantic-reference Goldschmidt in Phase 6. Options (a)-(c) captured; requires spec-owner decision before Rev 8 freeze.
