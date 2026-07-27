# MPSVS Π_SECTORVULN Rev 7 — Protocol Specification

**Scope.** This document specifies the MPSVS pipeline as implemented,
Rev 7. Consolidates the earlier `PROTOCOL_PI_SECTORVULN.md` (Rev 6
long-form spec), `PROTOCOL_PI_SECTORVULN_R7.md` (Rev 6 → Rev 7 deltas),
`DEPLOYMENT_FULL_MPC.md` (deployment walkthrough), and
`DESIGN_VULN_SCORE_V2.md` (topology decision) into a single readable
reference. Content deleted from those files is recoverable via
`git log --follow` on commits before `2026-07-27`.

---

## 1. Purpose

Given per-firm records held by three independent data-input parties,
produce **sector-level vulnerability aggregates** — DTI, DSI, DEmp,
IPW, Delq, NPL, UnsecShare, StDebtShare, plus a composite score and
per-metric percentiles — under a differential-privacy release model, with
**no party (including the orchestrator) learning any single firm's
record**.

## 2. Parties

| Role | Symbol | Data | Compute duty | Sees post-run |
|---|---|---|---|---|
| Monetary Authority | **MAS** | loan / debt / delinquency / NPL for the ~10 % of firms that are licensed borrowers | client only (Phase 2, Phase 3) | own inputs; policy Φ; DP release |
| Statistics Dept | **DOS** | income / revenue / surplus for all firms | client only | own inputs; policy Φ; DP release |
| Manpower Ministry | **MOM** | employment / labour / vacancy for all firms | client only | own inputs; policy Φ; DP release |
| MPC compute node 1 | **S1** | none | full MPC — sees only shares | nothing beyond public transcript |
| MPC compute node 2 | **S2** | none | full MPC — sees only shares, non-colluding with S1 | nothing beyond public transcript |
| Orchestrator | **GT** (GovTech) | none | publishes Φ + ctx; consumes final release + audit chain | policy, config, DP-noised release, audit chain — **never any share, key, payload, or membership bit** |

Non-collusion assumption: S1 and S2 are operated by organisationally-
distinct entities; any single one may be malicious. Rev 7 does not
attempt to defend against joint S1+S2 corruption.

## 3. Public parameters (Φ)

Published by GT at session start; included in every hash / transcript
via `ctx`.

- `protocol_version = 7`
- `epoch_id` — release epoch (e.g., YYYYMM)
- **F_PSA alignment**: `β = 13` bins, `τ = 71` key bits, `cap_P = 256`
  rows/party/bin
- **Fixed-point (§9)**: `f = 40` fractional bits, `guard = 8` bits
- **Bucketing (§8 + R27)**: `B = 128` buckets (power of 2)
- **DP**: `ρ_per_query = 0.1`, `ρ_budget = 3.0`, `δ = 10^-6`,
  `C_max = 10^6` (contribution clip)
- **k-anonymity**: `k_threshold = 5`
- **Cover firms**: `K ∈ [3, 15]` synthetic firms injected per session
- **OPRF cap**: `Q̃` queries per client per epoch

Runtime overrides via `config/mpsvs.conf.sample`; canonical SHA-256
hash written to audit chain as `CONFIG_LOAD` entry.

## 4. Twelve phases

Each phase produces state consumed by the next; all state carried by
S1 and S2 as SPDZ-authenticated additive shares (`AuthSharedU64`).

### Phase 0 — Bootstrap
- GT publishes `Φ`, `session_id` (128-bit CSPRNG), `nonce` (128-bit)
- All parties load `MpsvsConfig`; verify `configHash`
- S1 and S2 open the encrypted `MpsvsKeyStore` (Argon2id-derived master key)
- Session Beaver bag provisioned once (no cross-session reuse)

### Phase 1 — Local prep
- Each client party locally normalises its input: growth clamp `±G`,
  scaling, missing-value marker, unit conversion (SGD cents,
  headcount)
- Range checks per attribute (`AttrRange`)

### Phase 2 — OPRF DKG + row-tag derivation
- **Rev 7 bias-frozen DKG** (§2): S2 commits to Y₂ first, then S1
  sends Y₁ + Schnorr, then S2 opens commit + Y + DLEQ, S1 verifies
- Each client runs 2-hop threshold-DH-OPRF against (S1, S2), each hop
  proved via Chaum-Pedersen DLEQ
- Output: `entity_key W = OPRF(canonical_id)`; `row_tag = H2(ctx ‖
  id_type ‖ canonical_id ‖ period ‖ W)`
- `bin = row_tag[0 : β]`, `key = row_tag[β : β + τ]` (bit-aligned;
  β=13 works)
- OPRF query cap `Q̃` enforced per (client, epoch)

### Phase 3 — Client-to-server share submission
- Each client secret-shares its per-row payload across (S1, S2)
- MOM is input-only (per Rev 7 §2 topology constraint)
- S1 and S2 store per-role `ClientState` with authenticated shares

### Phase 4 — F_PSA alignment
- **§4.3 packBins**: each party places rows into 2^β = 8192 bins;
  overflows any bin cap → `RestartSession` per §4.3
- **§5.3 within-bin sort**: bitonic network (data-oblivious;
  compare-swap pattern depends only on `n`)
- **§5.4 windowedMerge**: R16 membership-gated merge; produces at most
  `cap_P` canonical `UnionRow` per bin
- **§5.5 markLive**: `live = canonical ∧ (b_MAS ∨ b_DOS ∨ b_MOM)`
- **§5.6 composedShuffle**: CGP-style S1-then-S2 permutation
  composition; joint π hidden from both parties
- **Cover firms**: `K` synthetic firms injected here to mask exact
  count leakage
- **Duplicate guard**: `assertNoDuplicateEntityPeriod` throws
  generically if same (id, period) repeats within one source

### Phase 5 — Inclusion bit computation
- For each `UnionRow`, compute inclusion masks per metric per §7 of
  the protocol spec, e.g.:
  - `incl_DTI = alignment · b_MAS · b_DOS · v_debt · v_income · [income ∈ rng]`
- Enforced invariant: missing / range-invalid ⇒ `incl = 0`,
  **never** zero-substituting the underlying value
- **R25 coverage policy** for vuln inclusion:
  `STRICT_GATING` (all core metrics present) or `RENORMALISED` (any
  present, weights redistributed)

### Phase 6 — Bucketing + Goldschmidt reciprocal
- Per-metric log-scale bucket edges (`BucketEdges`)
- **§8.1 BucketIndex**: oblivious binary search over public edges,
  emits one-hot vector
- **§8.1.1 Goldschmidt reciprocal**: 5-6 iterations to compute
  `y_fp = 2^f / x` in fixed-point; catches numerical drift via the
  algebraic invariant (Phase 17.6)

### Phase 8 — Rank
- **§8.2 slimSort**: bitonic on `(popkey, invalid, bucket)`; §8.2.1
  conditional radix sort within `(popkey, invalid)` if `Φ.radix_enabled`
- Rev 7 R27 break-even at `B ≤ 128`

### Phase 9 — Composite vulnerability score
- Weighted sum of per-metric contributions per §9
- Weights renormalised if `RENORMALISED` coverage policy is active

### Phase 10 — Percentiles
- CDF over the per-metric histogram
- Percentile queried at p25 / p50 / p75 / p90 via segmented scan

### Phase 11 — Sector aggregation
- Two aggregation modes per metric:
  - **HISTOGRAM**: `SectorHistogram { hist : Histogram, n_valid, key }`
  - **RATIO-OF-SUMS**: `SectorRatio { sum_num, sum_den, ratio_fp,
    incl }`
- `aggregateAllMetrics` produces both across all 9 metrics
- `auditSectorAggregate` verifies totals-match invariant

### Phase 12 — DP release
- **Joint noise** (Rev 7 §12): S1 samples η₁ ~ N(0, σ²/2), S2 samples
  η₂ ~ N(0, σ²/2); commit-then-reveal each with SHA-256; verify
  commit on reveal; combined η = η₁ + η₂ ~ N(0, σ²)
- **σ from ρ**: `σ = √(Δ₂² / (2ρ))` with Δ₂ = √2 for count histograms
- **R26 clamp**: `h_clamped = max(0, h_noisy)` before release
- **k-anonymity gate** (`MpsvsKAnonGate`): suppress cells with
  `n_valid < k_threshold`
- **BudgetTracker** persists across sessions; enforces `Σ ρ ≤ ρ_budget`

### Phase 13 — Audit + attestation
- Every phase writes to `MpsvsAuditPersist` (append-only, SHA-256
  hash-chained, `flock`-protected)
- Every party publishes software hash + schema version as Attestation
  to GT
- Prometheus metrics exposed via `MpsvsMetrics` at
  `metrics_bind` (default 0.0.0.0:9090)

## 5. Phase 17 malicious-secure upgrades

Six sub-protocols; each catches a specific active-adversary class.
Full detail in [`DESIGN.md`](DESIGN.md) §"Malicious primitives".

| Sub-phase | Primitive | Module |
|---|---|---|
| 17.1 | SPDZ MAC shares (plaintext-α + DPSZ shared-α) | `MpsvsAuthShare`, `MpsvsAuthShareProd` |
| 17.2 | OLE Beaver triples (LPN silent-OT) | `MpOleAlpha`, `MpOleTriple` |
| 17.3 | OPRF DLEQ + Schnorr (with FS-recovered point validity) | `MpsvsOprf` |
| 17.4 | Bayer-Groth shuffle NIZK (sound-with-reveal) | `MpShuffleNizkBg`, `MpsvsShuffleWire` |
| 17.5 | Chaum-Pedersen OR bit proof | `MpsvsBitProof` |
| 17.6 | Reciprocal algebraic verify | `MpsvsReciprocalVerify` |

## 6. Deployment topology

Two operational tiers supported:

**Tier 1 — pilot (single-datacentre, coproto in-process)**
- All 5 roles hosted by GovTech across separate Linux containers
- `MpsvsSecureChannel` between roles even in-process (defence-in-depth)
- Audit chain replicated to GT's persistent store

**Tier 2 — regulator-facing (multi-datacentre)**
- MAS, DOS, MOM host their own S1-side / S2-side containers respectively
- S1 in one datacentre (regulator-approved cloud); S2 in a different
  operator's datacentre (non-collusion assumption)
- GT keeps orchestrator + audit-chain replica
- Real mTLS at the TCP layer wrapping `MpsvsSecureChannel` (documented
  substitution point in `MpsvsSecureChannel.h`)
- HSM-backed `MpsvsKeyStore` (PKCS#11 attachment via `HsmKeyStore` stub)

## 7. Session lifecycle

```
config load  → configHash validated  → CONFIG_LOAD audit entry
    ↓
Phase 0-3    → DKG, OPRF, share submission
    ↓
Phase 4-11   → MPC pipeline (all under AuthSharedU64)
    ↓
Phase 12     → commit-then-reveal joint noise + k-anon
    ↓
Phase 13     → audit chain sealed; SHA-256 root written to GT
    ↓
release delivered to GT with (release, ρ_spent, configHash, chainRoot)
```

Session state (Beaver bag, DKG keys, α_share) is zeroised at end via
`SecureU64` / `SecureBuffer` RAII.

## 8. Failure modes & abort semantics

Any MAC failure, NIZK failure, or invariant violation triggers a
structured `AbortReport` via `MpsvsProdHygiene::Result<T>`:

```
struct AbortReport {
    AbortReason reason;      // MAC_FAIL, NIZK_FAIL, DP_COMMIT_MISMATCH, ...
    AbortContext ctx;        // protocol phase, party, cell key
    uint64_t timestamp_ns;
    std::array<uint8_t, 32> prev_link;
    std::array<uint8_t, 32> this_link;
}
```

Abort reports are hash-chained (`SessionAuditLog`) so a post-hoc
reviewer can prove the abort was legitimate, not fabricated. **No
partial release** — if any check fails, the session aborts before
Phase 12 opens anything.

## 9. Change control

Every change to a parameter that appears in `MpsvsConfig` or
`MpsvsCryptoParams` changes their SHA-256 hash. On session start:
- `configHash` is logged to audit chain
- `paramsHash` is logged to audit chain
- Post-hoc auditor reads audit chain → hash → verifies against the
  published config/params bundle

Combined with the hash-chained per-phase abort log, this proves
end-to-end: what config produced this release, from which inputs (via
transcript entries), under what security parameters.
