# MPSVS Security Analysis, Threat Model, and Audit History

**Scope.** Consolidates `SECURITY_ANALYSIS.md`, `OIRA_THREAT_MODEL.md`,
`COMPOSITE_SECURITY_THEOREM.md`, `PRIVACY_AUDIT_R37.md`, `AUDIT_R37.md`,
and `DEFERRED_AUDITS.md` into a single security dossier for
the MPSVS Rev 7 pipeline. Historical wording recoverable via
`git log --follow` on commits before `2026-07-27`.

---

## 1. Threat model

### 1.1 Adversary classes supported

| Class | Meaning | Countermeasure | Coverage |
|---|---|---|---|
| **A1 — semi-honest party** | Any party follows protocol, wants to learn more than allowed | additive shares, OPRF, F_PSA cover, DP | full |
| **A2 — malicious S1 (or S2)** | Compute node deviates from protocol, tampers with shares | SPDZ2k MAC over `ℤ_{2^{128}}` (`k=64, s=64` — Rev 7.1 `MpsvsAuthShare128`), Beaver-triple sacrifice, BG shuffle NIZK, Chaum-Pedersen bit proof, reciprocal invariant | **PARTIAL**: SPDZ2k primitive works standalone (`test_mpsvs_spdz2k` catches δ=2⁶³ at 100/100 vs classical SPDZ 1/2). Per-op `2⁻⁶⁴`, session-level `2⁻²⁴` at 2⁴⁰ ops. Full `2⁻⁴⁰` target needs `s=80` bignum retrofit + pipeline migration from `AuthSharedU64` → `AuthSharedU128`. See PROTOCOL.md §12 |
| **A3 — malicious data-input party** (MAS, DOS, MOM) | Client submits fabricated / out-of-range rows | Phase 5 inclusion gate + range checks + F_PSA duplicate guard | full for range / duplicate; Sybil not addressed (assumes registered client identity) |
| **A4 — coalition S1 + one client** | Compute node colludes with e.g. MAS | shares still bind other clients; MAC verifies within-session inputs | partial — colluding pair learns own inputs + intermediate opens; DP release still enforced |
| **A5 — external network observer** | Passive wire attacker | `MpsvsSecureChannel` (X25519 + XChaCha20-Poly1305), pinned peer PK | full for confidentiality + integrity |
| **A6 — active MITM** | Impersonates a party on the wire | Handshake mutual auth via long-term X25519 keys pinned before session | full |

### 1.2 Adversary classes explicitly out of scope

| Class | Why not | Mitigation available |
|---|---|---|
| **B1 — joint S1 + S2 corruption** | Breaks non-collusion assumption | Add a third compute node (major redesign) |
| **B2 — physical side-channel** | Cache-timing, EM, Spectre-class | Deploy on isolated hardware / dedicated tenant |
| **B3 — post-compromise adversary** | Recovers past sessions after stealing long-term X25519 key | Add ephemeral-key handshake to `MpsvsSecureChannel` |
| **B4 — DoS** | Availability, not confidentiality | Network-layer rate limiting |
| **B5 — Sybil in client roles** | Assumes registered agency identity | Out-of-band vetting by GT |
| **B6 — GT corruption** | GT is trusted for orchestration + release delivery | Reduce GT trust via public bulletin board (future work) |

### 1.3 Communication + setup assumptions

- Point-to-point authenticated + confidential channels (via
  `MpsvsSecureChannel`)
- Broadcast (used for DP commit-reveal, DKG commit-open) simulated via
  authenticated point-to-point + hash-chain of message from party i to
  party j readable by both
- PKI: each of S1, S2, MAS, DOS, MOM, GT has a long-term X25519
  identity keypair; public keys pinned across parties via
  out-of-band setup ceremony
- Trusted setup: cryptographic parameters (`MpsvsCryptoParams`) are
  crypto-team-owned; regulator-editable operational params
  (`MpsvsConfig`) go through a separate change-control flow

## 2. Security goals

### 2.1 Confidentiality

**Goal C1** — No party learns any single firm's plaintext values.

Achieved by: additive secret sharing over Z_{2⁶⁴} across (S1, S2);
`AuthSharedU64` on every intermediate; OPRF entity keys hide firm
identity from S1/S2; F_PSA cover firms hide exact membership counts.

**Goal C2** — GT (orchestrator) sees only the DP-noised release and
the public transcript — no share, no key, no payload.

Achieved by: GT never receives share material; DP noise applied
Phase 12 before Phase 13 open; audit chain contains only hashes and
public transcript entries (verified structurally in
`test_mpsvs_topology`).

### 2.2 Integrity

**Goal I1** — Any share tampering by ≤ 1 corrupt party is caught with
probability ≥ 1 − 2⁻ˢ per operation, where `s` is the SPDZ2k
statistical parameter (see [`PROTOCOL.md`](PROTOCOL.md) §1). Spec
target: `s = 80` → per-op ≤ 2⁻⁸⁰, session ≤ 2⁻⁴⁰ at 2⁴⁰ opens.

**Status (Rev 7.1 — honest).** Two coexisting paths:

- **Legacy `AuthSharedU64`** (`ℤ_{2^{64}}`, classical SPDZ) — deployed
  by the current wire pipeline. Worst-case per-op detection **1/2**
  against a targeted `δ = 2⁶³` (Cramer et al. CRYPTO 2018 gap over
  rings). `test_mpsvs_adversary_catalog` (1000/1000 caught) exercises
  RANDOM tampering and does NOT probe the worst case. Do **not** claim
  A2 against this path.
- **SPDZ2k `AuthSharedU128`** (`ℤ_{2^{128}}`, `k=64, s=64`) — Rev 7.1
  primitive; regression `test_mpsvs_spdz2k` catches targeted `δ = 2⁶³`
  at 100/100 trials. Per-op `2⁻⁶⁴`, session `2⁻²⁴` at 2⁴⁰ ops. Closes
  the gap but misses the `2⁻⁴⁰` target by 2¹⁶ (interim). Not yet
  wired into the pipeline — callers must invoke the new API directly.

Empirical `test_mpsvs_adversary_catalog` (1000 / 1000 caught) tests
RANDOM tampering across both paths; a **targeted** attack against the
legacy path evades with probability 1/2. The SPDZ2k path catches it
with probability 1 − 2⁻⁶⁴ per op (empirically 100/100 over 100 trials
of the exact worst-case δ).

**Goal I2** — Any dishonest shuffle by S1 or S2 in F_PSA (drop /
insert / substitute / sum-preserving swap) is caught.

Achieved by: `MpShuffleNizkBg::shuffleVerifyBg` (post-R27b-fix)
independently recomputes both polynomial products from revealed
messages after binding-check of each opening. Regression test
`test_shuffle_nizk_bg::bg_sum_preserving_swap_now_caught`.

**Goal I3** — Any dishonest inclusion bit (b ∉ {0, 1}) is caught.

Achieved by: `commitBit` refuses to construct a non-boolean commitment
at construction time; `proveBit` also throws for non-boolean witness.
Regression test `test_mpsvs_bit_proof::C3, C4, C7`.

**Goal I4** — Any dishonest reciprocal output (Goldschmidt returns
`y_fp ≠ 2^f / x`) is caught.

Achieved by: `verifyReciprocalAuth` (or `verifyReciprocalAuthShared`)
computes `[y_fp · x]` via authenticated Beaver mult, opens with MAC
check, verifies `|z - 2^f| ≤ tolerance`. Regression:
`test_mpsvs_reciprocal_verify`.

### 2.3 Differential privacy

**Goal DP1** — Every release satisfies ρ-zCDP with the ρ recorded in
the audit chain.

Achieved by: Gaussian noise per Rev 7 §12 with σ = √(Δ₂² / (2ρ));
joint-noise commit-then-reveal prevents malicious S1 from choosing
its noise share adversarially; `BudgetTracker` enforces Σρ ≤
ρ_budget across sessions.

**Goal DP2** — Statistical soundness: δ in (ε, δ) conversion is
below the statistical security parameter σ_stat.

Achieved by: `validateAgainstOperationalConfig` warns if
`dp_delta > 2^{-σ_stat_bits}`.

### 2.4 Accountability

**Goal AC1** — After any release, an external auditor can prove
which config produced it.

Achieved by: `configHash` and `paramsHash` (SHA-256 canonical) logged
to audit chain at session start; audit chain is SHA-256 hash-chained
(`MpsvsAuditPersist`), so a single Merkle-root witness proves the full
history.

**Goal AC2** — Any protocol abort produces a signed abort report
distinguishable from a fabricated one.

Achieved by: `AbortReport` (`MpsvsProdHygiene`) with hash-chain link
to previous audit entry; verification via `verifyAbortChain` and
`verifyPersistedAudit`.

## 3. Composite security theorem

**Statement.** Under semi-honest S1 + S2 non-collusion, and assuming
libsodium's Ristretto255 CDH assumption + LPN for silent OT + SHA-256
collision-resistance + randombytes_buf CSPRNG unpredictability, MPSVS
Π_SECTORVULN Rev 7 realizes the ideal functionality F_SECTORVULN
(defined below) with statistical error ≤ σ_stat_bits + negl(λ).

**F_SECTORVULN (informal)** — takes each party's inputs, applies:
1. row-tag derivation via OPRF (hides raw ids)
2. F_PSA alignment (produces union table with cover firms)
3. inclusion gate + range checks
4. sector aggregation + percentile computation
5. Gaussian noise addition with ρ-zCDP budget
6. k-anonymity gate suppression
7. release delivery to GT

**Proof structure (informal).** Composition of:
- **OPRF security** (Rev 7 §2): standard Chaum-Pedersen DLEQ soundness +
  bias-frozen DKG hides the joint OPRF key
- **F_PSA correctness** (§4-5): oblivious sort + windowed merge + CGP
  composed shuffle from prior R25-R27 line
- **SPDZ malicious security** (§17.1): DPSZ 2012 Ω-check with
  shared α = α₁ + α₂
- **BG shuffle soundness** (§17.4, post-R27b fix):
  Schwartz-Zippel over ~2²⁵² field + commitment binding
- **DP composition** (§12): standard zCDP → (ε, δ) conversion

Composition is via UC-like hybrid arguments across phases; formal proof
not delivered (documented in "not addressed" below).

## 4. Privacy audit — per-layer inputs / intermediates

Fifteen intermediate values / structures could in principle leak
information; below is the actual disclosure surface per layer for the
Rev 7 implementation.

| Layer | Data | Who sees | Leak risk | Mitigation |
|---|---|---|---|---|
| 0. Raw client rows | canonical_id, payload | client only | none inside MPC | not shared |
| 1. Normalised rows | after growth clamp / scaling | client only | none | local |
| 2. Entity keys W | Ristretto255 point | client only | none | derived via OPRF; not sent to S1/S2 |
| 3. Row tags | 256-bit derived tag | client only | none | not sent |
| 4. Bin index | β=13 bits, PUBLIC post-Phase 4 | S1, S2, transcript | bin frequency leaks | β-cap enforced; cover firms mask |
| 5. Additive shares of value | 64-bit each | S1, S2 (respective) | none individually | additive; masks other party's shares |
| 6. MAC shares (α · x) | 64-bit each | S1, S2 (respective) | none individually | additive |
| 7. Opened d, e in Beaver mult | 64-bit each | S1, S2 | d, e blind x, y | Beaver correctness |
| 8. Opened σ in DPSZ MAC check | 64-bit each | S1, S2 | σ blind α_i via x_rec | commit-then-reveal ordering |
| 9. Bucket one-hot | B=128 bits | shared | none plaintext | shared as AuthSharedU64 |
| 10. Rank output | integer | shared | none plaintext | shared |
| 11. Sector histogram counts | integer | shared | rev 12 opens; noised | DP + k-anon |
| 12. Sum-num / sum-den (Rev 11) | 64-bit each | shared | rev 12 opens; noised | DP |
| 13. DP noise η₁, η₂ | 64-bit signed | S1, S2 (own only) | none — random | CSPRNG in MpsvsDpProd |
| 14. Combined noise η | 64-bit signed | both | random | commit-reveal proves neither chose adversarially |
| 15. Final release | noised aggregates, clamped, k-anon-gated | GT | leaks ρ-zCDP amount | budget tracked; k-anon suppresses low counts |

## 5. Audit findings — closed and deferred

### 5.1 Cycle 1 (post-crypto-primitive delivery) — CLOSED

| ID | Severity | Finding | Fix |
|---|---|---|---|
| C1 | Critical | BG shuffle NIZK verifier trusted prover-supplied products; sum-preserving multiset swap uncaught | `shuffleVerifyBg` now independently recomputes both products from revealed openings after `pedersenCommit`-binding each; regression test `bg_sum_preserving_swap_now_caught` |
| C2 | Critical | SPDZ MAC ops took plaintext α — not standard malicious model | Parallel API surface with DPSZ shared-α (`openWithMacCheckShared`, `authSecureMultiplyShared`, `sacrificeCheckTripleShared`, `verifyReciprocalAuthShared`); regression `test_mpsvs_auth_share_dpsz`, `test_mpsvs_shared_alpha_e2e` |
| C3 | Critical | `RowTag::key` threw for β=13 (config default) | Bit-aligned slicing supporting arbitrary β ≤ tag_bits |
| C4 | Critical | Schnorr / DLEQ verify hashed FS-recovered R without validity check | `isValidPoint(R)` gate before hashing |
| C5 | Critical (latent) | N>2 OLE Beaver triples silently invalid (missing cross-terms) | Hard throw on N>2; MPSVS fixed at N=2 |
| M1 | Major | `authSecureMultiply` returned "poisoned share" on MAC fail | Throws `AuthShareMacFailure` |
| M2 | Major | `sacrificeCheckTriple` used oc::PRNG for public challenge | CSPRNG (`secureRandU64`) |
| M3 | Major | `MpsvsDpWire` (semantic-ref) callable in production | Env-var guard: `MPSVS_PRODUCTION_MODE=1` triggers throw |
| M4 | Major | `commitBit(non-bit, r)` accepted | Throws `std::invalid_argument` at construction |
| M5 | Major | `num_bins=3` hardcoded in DP module | Documented as current schema (sum_num, sum_den, n_valid); refactor path noted |
| M6 | Major | DKG error-handling inconsistent (throw vs bool) | Documented split: `dkgS2Finalize` throws, `dkgS1Finalize` returns bool |
| M8 | Major | AuthShare header claimed α reconstruction primitive that didn't exist | Header rewritten to document the plaintext-α (semi-honest) vs shared-α (malicious) split |

### 5.2 Cycle 2 (post-shared-α migration) — CLOSED

| ID | Severity | Finding | Fix |
|---|---|---|---|
| E1 | Critical | `openWithMacCheckShared` commit-then-verify was tautological (both sides same locals) | Two-phase API (`computeSigmaCommit` / `verifySigmaReveal`); adversarial test `C7` proves post-commit tamper caught |
| E2 | Critical | Batch Ω-check sampled r locally per element (adversary could adaptively tamper) | Fiat-Shamir-derived r_j over full share transcript SHA-256; deterministic, unpredictable to adversary who hasn't yet committed |
| E3 | Major | α_i = 0 edge case (prob 2⁻⁶⁴) makes σ_i = -m_i unblinded | `generateAlpha` resamples if any α_i share is zero |
| E4 | Major | `authSecureMultiplyShared` missing N==2 guard | Added explicit guard on all six input shares |

### 5.3 Deferred to follow-up

- **SPDZ2k `s=80` bignum retrofit + pipeline integration** — Rev 7.1
  delivered `MpsvsAuthShare128` with `k=64, s=64` (per-op `2⁻⁶⁴`,
  session `2⁻²⁴`). Reaching the `2⁻⁴⁰` target needs either `s=80`
  bignum shares or `k=48, s=80` in `__int128`. In parallel, migrate
  the wire-level pipeline (`MpsvsInclusionWire`, `MpsvsSectorAggWire`,
  ~15 files) from `AuthSharedU64` to `AuthSharedU128`. Until that
  migration lands, adversary class A2 is met by the primitive but not
  by the deployed default path. See PROTOCOL.md §12.
- **DP wire-pipeline migration** — Rev 7.1 delivered
  `noisyThresholdReleaseProd` (validated). Migrate the pipeline
  release call from `addJointNoiseImpl` + `applyKAnonGate` to
  `noisyThresholdReleaseProd`. Once done, adversary class A3 is met.
- **A2B conversion for k-anon** — even the migrated path benefits
  from replacing `MpsvsKAnonGate::arithToBit` (reveal-and-reshare —
  leaks n_valid to both parties in plaintext) with Toft prefix-tree
  adder or oblivious A2B via garbled circuits.
- **BucketIndex** — wire code already uses one-hot bit-position OR
  reduction (oblivious). PROTOCOL.md §5.7 Alg 24 updated to match
  the actual construction. No code change needed.
- **Fuzzing harness** — libFuzzer targets over `parseConfigText`,
  `decryptBody`, `shuffleVerifyBg`, `RowTag::key`
- **Forward secrecy** in `MpsvsSecureChannel` — documented tradeoff;
  add ephemeral-key handshake if regulator requires post-compromise
  security
- **Constant-time σ_i computation** — variable-time
  `α_i · x - m_i` acceptable for in-process reference; wire-level
  should use CT arithmetic or blinding
- **Formal verification** — no machine-checkable proofs delivered
  (Coq/Lean/Cryptol); statement stands as an informal composition
  argument
- **Third compute node** for A/B redundancy against joint S1+S2
  corruption (major redesign; out of Rev 7 scope)
- **Public bulletin board** for release proofs (reduces GT trust;
  future work)
- **Per-layer side-channel review** — DPSZ commit reveals σ_i to
  peer; a wire-level implementation should confirm no timing signal
  during σ_i computation

### 5.4 Historical audit findings (R25 – R37)

Prior-round findings on MpStarChannel (concurrency, error isolation),
MpStarSetup (KDF choice, sodium init lifecycle), MpShuffleDriver (OSN
semantics), RsMpsi (Simple-Hash vs true VOLE-PSI), MpsaDriver
(scaffolding vs production) — see git history and the pre-consolidation
`DEFERRED_AUDITS.md` at commit `346906f^`. Most items were either
addressed in the R25-R37 sweep or superseded by the MPSVS Rev 7
architecture (which replaced entire subsystems).

## 6. Regression evidence

**21 test binaries pass** post-fix. Adversarial catch-rate:
1000 / 1000 across 5 attack vectors × 200 trials
(`test_mpsvs_adversary_catalog`).

**Scale-validated** at 1 000 000 firms × 20 sectors (see
[`PROTOCOL.md`](PROTOCOL.md) §"Scale" and README §"Scale results").
Aggregate audit `hist_totals_match=yes, ratio_totals_match=yes` holds
end-to-end.
