# Π_SECTORVULN Rev 7 — Formal Protocol Specification

> Self-contained cryptographic specification of MPSVS. Each primitive
> is defined as a game or ideal functionality, each algorithm is given
> in numbered pseudocode with an I/O signature, each security claim is
> stated as a Theorem or Lemma with an explicit advantage bound and a
> proof sketch, and each complexity claim is quantified.
>
> **Not a paper.** This is a reference specification, not a submission
> artifact. The natural venue for a submission built around this spec
> is applied-privacy systems — **PoPETs** (best content fit; check
> whether its journal-issue side satisfies your journal-only rule),
> **IEEE TIFS**, **IEEE TDSC**, or **ACM TOPS**. The novel delta is
> composition + deployment under the MAS / SingStat / GovTech
> constraints, not a new primitive (OPRF: Jarecki–Krawczyk–Xu 2018;
> shuffle: Bayer–Groth 2012; MPC: SPDZ2k Cramer et al. 2018; DP:
> Bun–Steinke 2016). *Journal of Cryptology* does not fit — it wants
> new foundational crypto, and MPSVS is applied composition.
>
> Companion documents: [`SECURITY.md`](SECURITY.md) (threat model +
> audit history), [`DESIGN.md`](DESIGN.md) (implementation-level
> notes), [`HISTORY.md`](HISTORY.md) (R25–R37 legacy).

---

## Contents

1. Notation
2. Assumptions (game-based)
3. Ideal functionalities
4. Building blocks
   4.1 Schnorr proof of knowledge
   4.2 Chaum–Pedersen DLEQ
   4.3 Bayer–Groth shuffle argument (sound-with-reveal)
   4.4 Chaum–Pedersen OR bit proof
   4.5 Threshold-DH OPRF with bias-frozen DKG
   4.6 SPDZ authenticated shares (plaintext-α + DPSZ shared-α)
   4.7 OLE-based Beaver triples
   4.8 Gaussian mechanism + zCDP
5. Protocol Π_SECTORVULN — phase-by-phase algorithms
6. Simulator construction
7. Security theorems
8. Complexity analysis
9. Failure modes and abort semantics
10. Change control and deployment
11. (Appendix — cross-reference to modules)
12. **Implementation Status (Rev 7.1)** — honest ledger of built vs deferred

---

## 1. Notation

**Sets and rings.**
- `ℤ_{2^k}` — integers mod `2^k` with wrapping. Default `k = 64`
  (the semantic value ring).
- **SPDZ2k extended authentication ring (Cramer-Damgård-Escudero-Scholl-Xing,
  CRYPTO 2018).**  Because `ℤ_{2^k}` contains zero-divisors, the classical
  SPDZ identity `α·x = m` in `ℤ_{2^k}` is unsound against an adversary
  that introduces an additive error `δ` with `v₂(δ)` low bits zero — the
  worst case `δ = 2^{k-1}` is caught with probability only `1/2`, not
  `2^{-k}`. MPSVS therefore authenticates over the extended ring
  `ℤ_{2^{k+s}}`, where `s` is a **statistical security parameter**.
  Every authenticated share `⟦[x]⟧`, MAC share `⟦α·x⟧`, and MAC key
  `⟦α⟧` lives in `ℤ_{2^{k+s}}`. The MAC check reveals `σ` mod
  `2^{k+s}` and compares against 0 in the full extended ring, giving
  detection probability `≥ 1 - 2^{-s}` per open (Cramer et al. Theorem 3).
  The low `k` bits carry the semantically-meaningful value; the top
  `s` bits are the algebraic MAC witness.
- **Implemented parameter values** (see §12 Implementation Status for
  scope): the retrofit `MpsvsAuthShare128` uses `__int128` share
  storage, so `k + s ≤ 128`. Concrete Rev 7.1 configuration:
  `k = 64`, `s = 64` → shares are 128-bit; per-op detection `2⁻⁶⁴`,
  session-level `2⁻²⁴` at `2⁴⁰` opens.
- **Spec-target values** (not yet implemented): `k = 64`, `s = 80` for
  a session-level bound of `2⁻⁴⁰`. Requires bignum storage
  (`k + s = 144 > 128`); documented in §12 as a follow-up. Alternatives
  that stay in `__int128` include reducing `k` to `48` (still ≥ SGD
  cent range, max ≈ `2⁴⁷`) and setting `s = 80`.
- `𝔽_p` — the Curve25519 scalar field of order
  `p = 2^252 + 27742317777372353535851937790883648493`, so
  `p < 2^{253}` and `log₂ p ≈ 252.4`.
- `𝔾` — the Ristretto255 group of prime order `p`, with generators
  `g, h` of unknown discrete-log relation. `⟨·⟩` — group operation
  (written additively).

**Sharing.** `⟦x⟧ = (x_1, x_2)` with `x_1 + x_2 ≡ x (mod 2^{k+s})` —
2-party additive sharing across `(S_1, S_2)` **in the extended ring**.
`⟦x⟧_i` — party `i`'s share. `Open(⟦x⟧) → x mod 2^{k+s}`; the
semantic value is `x mod 2^k`; the top `s` bits carry MAC state.

**Authentication.** `α ∈ ℤ_{2^{k+s}}` — global SPDZ2k MAC key.
`⟦α⟧` — additive sharing of `α`. `⟦[x]⟧ := (⟦x⟧, ⟦α · x⟧)` —
authenticated share of `x` (all fields in `ℤ_{2^{k+s}}`). In the
plaintext-α legacy path (semi-honest / single-verifier only), `α` is
public to a designated verifier. In the malicious-secure DPSZ2k path,
`α` remains `⟦α⟧` throughout the session — no party reconstructs.

**Adversary and games.** `𝒜` — probabilistic polynomial-time adversary
with oracle access as specified. `Adv^{game}_Π(𝒜, λ)` — 𝒜's advantage
in game `game` against protocol `Π` at security parameter `λ`.
`negl(λ)` — a function `f(λ)` such that `f(λ) = o(1/λ^c)` for all
`c > 0`.

**Complexity.** `Round(Π) = r` — number of communication rounds.
`Comm(Π) = c bits` — total wire cost. `Comp(Π) = t ops` — dominant
operation count.

**Randomness.** `x ← ${S}` — uniform sample from finite set `S`.
For the ring `ℤ_{2^k}` we write `x ← ${ℤ_{2^k}}`.

**Length-prefixed serialization.** For bytes `b`, `LP(b) := len(b)_LE64 ‖ b`.

---

## 2. Assumptions (game-based)

### Assumption 1 (CDH on 𝔾)

Let `𝒜` be PPT. The **Computational Diffie-Hellman** advantage of `𝒜`
over `𝔾` is
```
Adv^{cdh}_𝔾(𝒜, λ) := Pr[𝒜(g, [a]g, [b]g) = [ab]g : a, b ← ${𝔽_p}].
```
The CDH assumption on 𝔾 asserts `Adv^{cdh}_𝔾(𝒜, λ) ≤ negl(λ)`.
Used by the OPRF (§4.5), Schnorr (§4.1), DLEQ (§4.2), bias-frozen DKG
(§4.5).

### Assumption 2 (Discrete Log on 𝔾)

```
Adv^{dlog}_𝔾(𝒜, λ) := Pr[𝒜(g, [k]g) = k : k ← ${𝔽_p}] ≤ negl(λ).
```
Used by Pedersen commitment binding (§4.3), BG shuffle NIZK (§4.3),
CP OR bit proof (§4.4).

### Assumption 3 (LPN with parameters of libOTe SilentOtTriple)

For the parameters `(n, k, τ)` chosen by libOTe (`n ≈ 2²⁰`,
`k ≈ 2¹²`, sparse Bernoulli noise rate `τ ≈ 2⁻⁶`), `𝒜` cannot
distinguish `(A, As + e)` from uniform, where
`s ← ${𝔽_2^k}, e ← ${Ber(τ)^n}`. Used by §4.7.

### Assumption 4 (SHA-256 modelled as a random oracle)

`H : {0, 1}^* → {0, 1}^{256}` is a random oracle. All Fiat–Shamir
transforms in this document are analysed in the ROM.

### Assumption 5 (XChaCha20-Poly1305 IND-CCA2 + INT-CTXT)

Standard AE-security under a uniformly random 256-bit key.

### Assumption 6 (Argon2id memory-hard KDF)

For passphrase `π` sampled from distribution `𝒟` of min-entropy
`H_∞(𝒟) = h` bits, an offline dictionary attack against
`crypto_pwhash(π, salt)` with `OPSLIMIT_INTERACTIVE` +
`MEMLIMIT_INTERACTIVE` costs at least `T ≥ 2^h · T_hash` where
`T_hash ≈ 250 ms · 64 MB` per candidate. For `h ≥ 60` the attack is
infeasible; for weak passphrases (`h < 40`) it is not.

### Assumption 7 (System CSPRNG)

`randombytes_buf` is a pseudorandom generator seeded from `/dev/urandom`;
its output is indistinguishable from uniform to any PPT observer.

### Assumption 8 (Non-collusion of `{S_1, S_2}`)

At most one of `{S_1, S_2}` is corrupted by `𝒜`. Joint corruption is
out of scope for Rev 7.

### Assumption 9 (Honest GT for orchestration only)

GT correctly forwards public messages and correctly receives releases.
GT never receives any share, key, or payload; a malicious GT can
withhold or delay releases but not learn private data.

---

## 3. Ideal functionalities

We describe MPSVS as a UC-style composition of the following ideal
functionalities.

### Functionality F_AUTH (authenticated channel)

Between every pair of parties: `F_AUTH` accepts `(send, sid, m)` from
a sender and delivers `(recv, sid, m)` to the receiver. Realised by
`MpsvsSecureChannel` (X25519 mutual auth + XChaCha20-Poly1305 AE)
under Assumptions 1, 5.

### Functionality F_CT (secret common reference string)

Distributes public `ctx = (session_id, nonce, configHash, paramsHash)`
to all parties. Realised by GT publication (Assumption 9) + audit
chain persistence.

### Functionality F_OPRF^{2-of-2}

```
─────────────────────────────────────────────────────────────────
F_OPRF^{2-of-2}                                       [Ideal]
─────────────────────────────────────────────────────────────────
Setup:  sample joint key k ← ${𝔽_p}; publish Y = [k]g.
Query:  on (client C, id x ∈ {0, 1}^*):
          if C's query count > Q̃: return ⊥
          W ← [k] · hashToPoint(x)
          deliver W to C.
Corruption:  a corrupted S_i learns nothing about x beyond query count.
─────────────────────────────────────────────────────────────────
```
Realised by Protocol Π_OPRF_DKG + Π_OPRF (§5.2) under Assumption 1.

### Functionality F_PSA (private set alignment)

```
─────────────────────────────────────────────────────────────────
F_PSA                                                 [Ideal]
─────────────────────────────────────────────────────────────────
Input:  from each client C ∈ {MAS, DOS, MOM}:
          list of records {(x_j, period_j, sector_j, payload_j)}.
Compute:
          for each canonical id x appearing in any input:
              produce a union record u_x = (period_x, sector_x,
                                            b_MAS, b_DOS, b_MOM,
                                            p_MAS, p_DOS, p_MOM)
          sample fresh π ← ${Sym(N + K)} (with K cover firms)
          permute records by π.
Output:  authenticated shares ⟦u_π(1)⟧, ..., ⟦u_π(N+K)⟧ to (S_1, S_2).
Corruption:  corrupted party learns own inputs + shape (N+K), sector
             distribution.  No entity linkage.
─────────────────────────────────────────────────────────────────
```
Realised by Protocol Π_PSA (§5.4) under Assumptions 1, 4, 8, plus
F_OPRF^{2-of-2}.

### Functionality F_SPDZ2k^{2-of-2}

Parameters: value ring width `k`, statistical parameter `s`.

```
─────────────────────────────────────────────────────────────────
F_SPDZ2k^{2-of-2}                                     [Ideal]
─────────────────────────────────────────────────────────────────
Setup:  sample α ← ${ℤ_{2^{k+s}}^*}; deliver ⟦α⟧ = (α_1, α_2)
        in ℤ_{2^{k+s}}.
Input(x ∈ ℤ_{2^k}):
        accept x from a party; sign-extend to ℤ_{2^{k+s}};
        deliver ⟦[x]⟧ = (⟦x⟧, ⟦α·x⟧) to both parties.
Add(⟦[x]⟧, ⟦[y]⟧): return ⟦[x + y]⟧ (local, in ℤ_{2^{k+s}}).
Mult(⟦[x]⟧, ⟦[y]⟧): return ⟦[xy mod 2^k]⟧ (consumes 1 Beaver triple).
Open(⟦[x]⟧): return x mod 2^k; abort if any share was tampered
             (except with probability ≤ 2^{-s}).
Corruption:  corrupted party learns ⟦α⟧_i and its own shares only.
─────────────────────────────────────────────────────────────────
```
Realised by Protocol Π_SPDZ2k (§5.5) under Assumptions 1, 3, 4, 7, 8.
Note the abort probability is `2^{-s}`, not `2^{-k}` — this is the
SPDZ2k gap over the ring `ℤ_{2^k}` and drives Rev 7's choice of
`s = 80` (see §1 Notation).

### Functionality F_DP

```
─────────────────────────────────────────────────────────────────
F_DP                                                  [Ideal]
─────────────────────────────────────────────────────────────────
Neighbouring relation:
    ~   D ~ D'  iff D' = D ∪ {r} or D' = D \ {r} for a single firm r
        (add/remove; L2 sensitivity of a count = 1, of a bucket-hist
         = √2 since one entity moves one bucket in one metric).
    All Rev 7 DP claims are stated under this add/remove relation.
    Replacement neighbours (D' = D \ {r} ∪ {r'}) would double every
    sensitivity; not the operative model.

Params: per-metric sensitivity Δ_m > 0, k-anon threshold k ≥ 0,
        stability-noise parameter ρ_th (scalar), per-metric ρ_m,
        budget ρ_max, ρ-spent accumulator.

NoisyThresholdQuery(n_valid, metric_m, y_m):
    # Stability-based release (Bun–Steinke 2016 Cor. 3.4):
    # gate on a NOISED count, not the true count, so the release/
    # suppress decision itself carries no infinite DP loss for
    # neighbours straddling k.
    if Σ ρ_spent + (ρ_th + ρ_m) > ρ_max:  abort "budget exhausted"
    ξ    ← Gaussian(0, 1 / (2 ρ_th))           # ρ_th-zCDP for count
    ñ    ← n_valid + ξ                          # noised count
    if  ñ  <  k  +  τ(ρ_th, δ)  :  output ⊥    # stability margin τ
    else:
        η   ← Gaussian(0, Δ_m² / (2 ρ_m))       # per-metric noise
        output ( max(0, y_m + η),  ñ )          # release BOTH y_m
                                                # AND the noised count
    ρ_spent += (ρ_th + ρ_m).

    # τ(ρ_th, δ) := σ_ξ · sqrt(2 · ln(1/(2δ)))   (Gaussian tail bound)
    # For ρ_th = 0.05, δ = 10⁻⁶: τ ≈ 12.  So k=5 with margin 12 means
    # a cell releases only when the NOISED count exceeds 17.
─────────────────────────────────────────────────────────────────
```

**Note.** The earlier `F_DP` definition threshold-gated on the *true*
`n_valid` and released it in the clear. Both are DP violations: (a) the
gate is a `1{n_valid ≥ k}` deterministic function of the sensitive
count, giving infinite ε-loss for neighbours straddling `k`; (b) the
un-noised release adds `n_valid` as a public statistic outside the ρ
budget. Both are fixed above via the stability-noise-then-threshold
construction of Bun–Steinke 2016 §4 ("stability-based histograms").

### Functionality F_SECTORVULN (the target)

```
─────────────────────────────────────────────────────────────────
F_SECTORVULN                                          [Target]
─────────────────────────────────────────────────────────────────
Setup:  invoke F_OPRF^{2-of-2}, F_SPDZ^{2-of-2}, F_DP.
        publish Φ and receive ρ-budget from GT.
Release(sector, period, metric):
    U ← F_PSA union of inputs
    for each u ∈ U:
        incl_m(u) ← inclusion mask per Rev 7 §7 (Alg. 6)
        num_m(u), den_m(u) ← per-metric numerator/denominator
    for each (s, p, m):
        n(s,p,m) ← Σ_{u ∈ U : sector(u)=s ∧ period(u)=p} incl_m(u)
        num(s,p,m) ← Σ_{u} incl_m(u) · num_m(u)
        den(s,p,m) ← Σ_{u} incl_m(u) · den_m(u)
        hist(s,p,m).h[b] ← # firms in bucket b
    apply F_DP to every released cell (with per-metric sensitivity).
    Output the surviving noised aggregates to GT.
─────────────────────────────────────────────────────────────────
```

**Theorem (Section 7.1).** Protocol Π_SECTORVULN Rev 7 realises
F_SECTORVULN in the (F_AUTH, F_CT, F_OPRF, F_SPDZ, F_DP)-hybrid model
under Assumptions 1, 3, 4, 7, 8, 9 with statistical distance
`≤ σ_stat + negl(λ)` per session.

---

## 4. Building blocks

Each building block below has: (i) formal I/O signature, (ii) numbered
pseudocode, (iii) security game and Theorem with concrete advantage
bound, (iv) proof sketch.

### 4.1 Schnorr proof of knowledge

**Signature.**
```
schnorrProve   : (k ∈ 𝔽_p, Y ∈ 𝔾, ctx ∈ {0,1}^*) →  π_SCH ∈ 𝔽_p × 𝔽_p
schnorrVerify  : (Y ∈ 𝔾, π_SCH, ctx) →  {accept, reject}
Relation:      R = {(Y; k) : Y = [k]g}.
```

**Algorithm 1** — `schnorrProve(k, Y, ctx)`
```
 1:  r  ← ${𝔽_p}
 2:  R  ← [r] g
 3:  c  ← hashToScalar("mpsvs.schnorr" ‖ ctx ‖ LP(Y) ‖ LP(R))
 4:  s  ← r + c · k    mod p
 5:  return π = (c, s)
```

**Algorithm 2** — `schnorrVerify(Y, π, ctx)`
```
 1:  if ¬isValidPoint(Y): return reject
 2:  R'  ← [π.s] g − [π.c] Y
 3:  if ¬isValidPoint(R'): return reject                     ▷ defence-in-depth
 4:  c'  ← hashToScalar("mpsvs.schnorr" ‖ ctx ‖ LP(Y) ‖ LP(R'))
 5:  return (c' = π.c) ? accept : reject
```

**Theorem 4.1.1 (Soundness of Schnorr).**  In the random-oracle model,
for any PPT prover 𝒫*:
```
Pr[schnorrVerify(Y, π, ctx) = accept  ∧  ¬(∃k : Y = [k]g and 𝒫* knows k)]
    ≤  q_H · Adv^{dlog}_𝔾(ℬ, λ)  +  q_H / p
```
where `q_H` is the number of random-oracle queries and ℬ is a
DLog-reduction constructed from 𝒫*.

**Proof sketch.** Standard extraction via the forking lemma
(Pointcheval–Stern 2000): rewind 𝒫* to before the ROM query on
`(Y, R)`; on two forks with the same `(R)` but distinct `c ≠ c'`, we
have `s − s' = (c − c') · k`, so `k = (s − s')(c − c')^{-1}`, breaking
DLog on `Y`.  ∎

### 4.2 Chaum–Pedersen DLEQ

**Signature.**
```
dleqProve   : (k, Y, U, V, ctx)  →  π_DLEQ
dleqVerify  : (Y, U, V, π_DLEQ, ctx)  →  {accept, reject}
Relation:   R = {(Y, U, V; k) : Y = [k]g ∧ V = [k]U}.
```

**Algorithm 3** — `dleqProve(k, Y, U, V, ctx)`
```
 1:  r  ← ${𝔽_p}
 2:  A  ← [r] g;   B ← [r] U
 3:  c  ← hashToScalar("mpsvs.dleq" ‖ ctx ‖ LP(g) ‖ LP(Y) ‖ LP(U) ‖ LP(V) ‖ LP(A) ‖ LP(B))
 4:  s  ← r + c · k    mod p
 5:  return π = (c, s)
```

**Algorithm 4** — `dleqVerify(Y, U, V, π, ctx)`
```
 1:  if ¬(isValidPoint(Y) ∧ isValidPoint(U) ∧ isValidPoint(V)):
        return reject
 2:  A'  ← [π.s] g − [π.c] Y     if ¬isValidPoint(A'): return reject
 3:  B'  ← [π.s] U − [π.c] V     if ¬isValidPoint(B'): return reject
 4:  c'  ← hashToScalar("mpsvs.dleq" ‖ ctx ‖ LP(g) ‖ LP(Y) ‖ LP(U) ‖ LP(V) ‖ LP(A') ‖ LP(B'))
 5:  return (c' = π.c) ? accept : reject
```

**Theorem 4.2.1.** As Theorem 4.1.1 but reducing to CDH via Chaum–
Pedersen extraction (Chaum–Pedersen '92):
```
Adv^{sound}_DLEQ(𝒫*, λ) ≤ q_H · Adv^{cdh}_𝔾(ℬ, λ) + q_H/p.
```

### 4.3 Bayer–Groth shuffle argument (sound-with-reveal)

**Signature.**
```
shuffleProveBg  : (msg[], r[], r'[], π_perm, C, C')  →  π_SHUF
shuffleVerifyBg : (π_SHUF, C, C')                    →  {accept, reject}
Relation:  R = {(C, C'; msg, r, r', π_perm) :
                 ∀i.  C[i] = Com(msg[i], r[i])
                    ∧ C'[i] = Com(msg[π_perm(i)], r'[i]) }.
```

**Confidentiality analysis.** This is a **sound-but-not-hiding**
shuffle argument: `shuffleVerifyBg` recomputes `Com(msg[i], r[i])`
against the transcript, so any verifier learns every `(msg[i], r[i])`
pair. Compatibility with MPSVS's threat model (goals C1 / C2 of
`SECURITY.md`) rests entirely on **who verifies**:

- **GT MUST NOT verify** (this proof reveals raw messages; GT is
  forbidden from seeing shares/payloads per Assumption 9).
  Only the audit-chain hash of the proof — not the proof body — is
  delivered to GT.
- **S_1 and S_2 verify each other's shuffle side.** For CGP composed
  shuffle, `S_1` chose π_1 and produced the intermediate commitment
  vector `C_1` from the joint input `msg_0`; `S_2` chose π_2 and
  produced `C_2` from `C_1`. Both parties **already jointly hold**
  the ⟦msg_0⟧ shares (§5.4 Phase 3), so revealing `msg` in the proof
  discloses no data that they could not already reconstruct together.
- **The messages that get revealed are bin indices and F_PSA union-row
  metadata that are public post-alignment** (Rev 7 §5.6). Row-tag keys
  used in the shuffle proof itself are the values already made public
  by the windowedMerge step (canonical-flag reveal). Payload shares
  are NOT part of `msg`; they are attached to each row via `AuthSharedU64`
  and pass through the shuffle without being opened.

Under these three constraints the sound-with-reveal variant is
compatible with C1 / C2. If a future use case demands a shuffle over
values still secret to both S_1 and S_2 (e.g. cross-domain routing
where the shuffle input is itself secret), swap in Bayer–Groth §5's
recursive partial-product argument — see [`DESIGN.md`](DESIGN.md)
§4.2 and Bayer–Groth EUROCRYPT 2012. This is **not** implemented in
Rev 7; deployments requiring it must gate on that upgrade.

**Algorithm 5** — `shuffleProveBg`
```
 1:  n ← |msg|
 2:  y ← hashToScalar("mpsvs.shuffleBg.y.v2" ‖ tr(C, C'))        ▷ FS
 3:  x ← hashToScalar("mpsvs.shuffleBg.x.v2" ‖ tr(C, C') ‖ LP(y))
 4:  for i ← 0 to n − 1:
 5:      shufMsg[i] ← msg[π_perm(i)]
 6:  return π = (y, x, msg, shufMsg, r, r')
```
where `tr(C, C')` is the canonical serialisation:
`domainPrefix ‖ LE32(|C|) ‖ concat(bytes(C_i)) ‖ LE32(|C'|) ‖ concat(bytes(C'_i))`,
with `|C|, |C'| ≤ 2^32 − 1` (enforced).

**Algorithm 6** — `shuffleVerifyBg`
```
 1:  require |π.msg| = |π.shufMsg| = |π.r| = |π.r'| = |C| = |C'| =: n
 2:  y' ← hashToScalar("mpsvs.shuffleBg.y.v2" ‖ tr(C, C'))
 3:  x' ← hashToScalar("mpsvs.shuffleBg.x.v2" ‖ tr(C, C') ‖ LP(y'))
 4:  if y' ≠ π.y or x' ≠ π.x: return reject
 5:  for i ← 0 to n − 1:                       ▷ binding
 6:      if Com(π.msg[i],  π.r[i])  ≠ C[i]:  return reject
 7:      if Com(π.shufMsg[i], π.r'[i]) ≠ C'[i]: return reject
 8:  P  ← Π_{i=0..n−1} (x − π.msg[i]  − y)     mod p    ▷ soundness
 9:  P' ← Π_{i=0..n−1} (x − π.shufMsg[i] − y) mod p
10:  return (P = P') ? accept : reject
```

**Theorem 4.3.1 (Soundness).** In the ROM, for every PPT prover 𝒫*:
```
Adv^{sound}_BG_shuf(𝒫*, n, q_H, λ) ≤ n · q_H^2 / p  +  q_H · Adv^{dlog}_𝔾(ℬ, λ).
```
For `n = 2^{12}`, `p ≈ 2^{252}` and `q_H ≤ 2^{40}`, this is
`≤ 2^{12} · 2^{80} / 2^{252} + negl(λ) = 2^{-160} + negl(λ)`.

**Proof sketch.** Binding of Pedersen commitments (lines 6–7) reduces
`msg`, `msg'` to specific plaintext multisets. Given fixed multisets,
`P = P'` iff the two are equal as multisets, by Schwartz–Zippel over
𝔽_p on the degree-`n` polynomial `Π (X − (μ_i + y))` — the probability
that a random `x ← ${𝔽_p}` makes two distinct degree-`n` polynomials
agree is `≤ n/p`. Applying Fiat–Shamir preserves soundness (Bellare–
Rogaway '93). Union-bounding over `q_H` random-oracle queries gives
`n · q_H / p`; squaring for FS extraction gives `n · q_H^2 / p`.  ∎

### 4.4 Chaum–Pedersen OR bit-membership proof

**Signature.**
```
commitBit  : (b ∈ {0, 1}, r ∈ 𝔽_p)         →  C ∈ 𝔾    [enforce b ∈ {0,1}]
proveBit   : (b, r, C, ctx ∈ {0,1}*)       →  π_OR
verifyBit  : (π_OR, C, ctx ∈ {0,1}*)       →  {accept, reject}
Relation:  R = {(C; b, r) : C = [b]g + [r]h ∧ b ∈ {0, 1}}.
```

**Algorithm 7** — `commitBit(b, r)`
```
 1:  if b ∉ {0, 1}: throw invalid_argument
 2:  if b = 0:      return C ← [r] h
 3:  else:          return C ← g + [r] h
```

**Algorithm 8** — `proveBit(bit, r, C)`
```
 1:  T_0 ← C;  T_1 ← C − g
 2:  if bit = 0:
 3:      w_0 ← ${𝔽_p};  A_0 ← [w_0] h
 4:      c_1 ← ${𝔽_p};  s_1 ← ${𝔽_p};  A_1 ← [s_1] h − [c_1] T_1
 5:      c   ← hashToScalar("mpsvs.bitproof" ‖ ctx ‖ LP(C) ‖ LP(A_0) ‖ LP(A_1))
 6:      c_0 ← c − c_1        mod p
 7:      s_0 ← w_0 + c_0 · r  mod p
 8:  else:                                      ▷ mirror for bit = 1
 9:      w_1 ← ${𝔽_p};  A_1 ← [w_1] h
10:      c_0 ← ${𝔽_p};  s_0 ← ${𝔽_p};  A_0 ← [s_0] h − [c_0] T_0
11:      c   ← hashToScalar(... same input ...)
12:      c_1 ← c − c_0;   s_1 ← w_1 + c_1 · r
13:  return π = (A_0, A_1, c_0, c_1, s_0, s_1)
```

**Algorithm 9** — `verifyBit(π, C)`
```
 1:  c   ← hashToScalar("mpsvs.bitproof" ‖ ctx ‖ LP(C) ‖ LP(π.A_0) ‖ LP(π.A_1))
 2:  if π.c_0 + π.c_1 ≠ c mod p: return reject
 3:  T_0 ← C;  T_1 ← C − g
 4:  if [π.s_0] h ≠ π.A_0 + [π.c_0] T_0: return reject
 5:  if [π.s_1] h ≠ π.A_1 + [π.c_1] T_1: return reject
 6:  return accept
```

**Theorem 4.4.1 (Soundness of the OR-proof).** In the ROM:
```
Adv^{sound}_bitproof(𝒫*, λ) ≤ 2 q_H · Adv^{dlog}_𝔾(ℬ, λ) + q_H² / p.
```

### 4.5 Threshold-DH OPRF with bias-frozen DKG

Party `S_1` holds `k_1`, party `S_2` holds `k_2`; joint OPRF key
`k := k_1 · k_2`. Client `C` obtains `W = OPRF_k(id) = [k_1 k_2] hashToPoint(id)`
without either `S_i` learning `id` and without `C` learning either `k_i`.

**Sub-protocol 4.5a — Bias-frozen DKG.**

**Algorithm 10** — `Π_DKG` (3 rounds; run once per session)
```
Round 1  S_2 → S_1:
  1: k_2 ← ${𝔽_p};  Y_2 ← [k_2] g
  2: π_2 ← schnorrProve(k_2, Y_2, ctx)
  3: commit ← H("mpsvs.dkg.commit" ‖ ctx ‖ Y_2 ‖ π_2)
  4: send commit                                    ▷ 32 bytes

Round 2  S_1 → S_2:
  5: k_1 ← ${𝔽_p};  Y_1 ← [k_1] g
  6: π_1 ← schnorrProve(k_1, Y_1, ctx)
  7: send (Y_1, π_1)                                ▷ 96 bytes

Round 3  S_2 → S_1:
  8: if ¬ schnorrVerify(Y_1, π_1, ctx):  abort
  9: Y   ← [k_2] Y_1                                ▷ joint public key
 10: π_Y ← dleqProve(k_2, Y_2, Y_1, Y, ctx)
 11: send (Y_2, π_2, Y, π_Y)                        ▷ 192 bytes

S_1 verifies:
 12: if H("mpsvs.dkg.commit" ‖ ctx ‖ Y_2 ‖ π_2) ≠ commit:  abort
 13: if ¬ schnorrVerify(Y_2, π_2, ctx):                     abort
 14: if ¬ dleqVerify(Y_2, Y_1, Y, π_Y, ctx):                abort

Output: S_1 keeps (k_1, Y_1, Y_2, Y);  S_2 keeps (k_2, Y_1, Y_2, Y);
        Y is public.
```

**Lemma 4.5.1 (Bias-freeness).** Under Assumptions 1, 4, and provided
either `S_1` or `S_2` is honest, `Y` is distributed uniformly in `𝔾`
up to distance `2 · Adv^{cr}_H(𝒜, 128) + 2^{-128}`.

**Proof sketch.** SHA-256 commit binds `Y_2` before `Y_1` is revealed;
Schnorr proof binds `k_2` to `Y_2`; DLEQ proof binds `k_2` to `Y`
consistency. If `S_2` is corrupt, it must commit before seeing `Y_1`,
so `k_2` is chosen independent of `Y_1`, hence `Y = [k_2] Y_1` is
uniform because `Y_1 = [k_1]g` is uniform (honest `S_1`). Symmetric
argument if `S_1` corrupt.  ∎

**Sub-protocol 4.5b — OPRF query.**

**Algorithm 11** — `Π_OPRF(C, S_1, S_2, id)` — 4 rounds per query
```
Client-side:
  1:  r      ← ${𝔽_p}
  2:  U      ← hashToPoint("mpsvs.oprf.tag" ‖ ctx ‖ id_type ‖ id)
  3:  U_blind ← [r] U

Round 1  C → S_1:  U_blind

S_1-side:
  4:  V_1  ← [k_1] U_blind
  5:  π_1  ← dleqProve(k_1, Y_1, U_blind, V_1, ctx)

Round 2  S_1 → C:  (V_1, π_1)

Client:  if ¬ dleqVerify(Y_1, U_blind, V_1, π_1, ctx):  abort

Round 3  C → S_2:  V_1

S_2-side:
  6:  V_2  ← [k_2] V_1
  7:  π_2  ← dleqProve(k_2, Y_2, V_1, V_2, ctx)

Round 4  S_2 → C:  (V_2, π_2)

Client:  if ¬ dleqVerify(Y_2, V_1, V_2, π_2, ctx):  abort
  8:  W ← [r^{-1}] V_2                                  ▷ = [k_1 k_2] U

Output: C keeps W.
```

**Theorem 4.5.2 (OPRF security).** Protocol Π_DKG + Π_OPRF UC-realizes
F_OPRF^{2-of-2} in the (F_AUTH, F_RO)-hybrid model under Assumption 1
(CDH), with per-query soundness ≤ `2 · Adv^{cdh}_𝔾(ℬ, λ) + 2^{-128}`.

**Proof sketch.** OPRF pseudorandomness reduces to CDH on 𝔾
(Jarecki–Krawczyk–Xu 2018). Bias-freeness of joint `k` from Lemma
4.5.1. Client blinding hides `id` from S_i. DLEQ soundness (Theorem
4.2.1) catches any deviation of `V_i` from `[k_i]`-response.  ∎

### 4.6 SPDZ2k authenticated shares

Two variants:
- **Plaintext-α** — semi-honest / single-verifier only. Legacy path;
  see [`DESIGN.md`](DESIGN.md) §1.
- **DPSZ2k shared-α** — fully-malicious under Assumption 8, over the
  extended ring `ℤ_{2^{k+s}}` (§1 Notation).

All algorithms below are the shared-α variant. Every element of
`⟦[·]⟧` lives in `ℤ_{2^{k+s}}`; ring width tracked via the parameter
`R = k + s = 144` bits by default.

**Algorithm 12** — `Open^{sh-α}(⟦[x]⟧, ⟦α⟧)` (SPDZ2k open + MAC check)
```
Preconditions: |⟦[x]⟧_shares| = 2 ∧ |⟦α⟧_shares| = 2, all in ℤ_{2^R}.

Phase A (public reconstruct in the extended ring):
  1:  X_pub ← Open(⟦x⟧) mod 2^R                    ▷ both broadcast, R bits
  2:  x_val ← X_pub mod 2^k                         ▷ semantic value

Phase B (local σ commit — each party i ∈ {1, 2}):
  3:  σ_i     ← α_i · X_pub  −  m_i    mod 2^R     ▷ m_i = ⟦α · x⟧_i in ℤ_{2^R}
  4:  salt_i  ← ${ℤ_{2^R}}                          ▷ full-width salt
  5:  commit_i ← H("mpsvs.audit.v2" ‖ LE(R, party=i) ‖ LE(R, σ_i) ‖ LE(R, salt_i))

Phase C (commit exchange):
  6:  send commit_i to peer

Phase D (reveal AFTER both commits exchanged):
  7:  send (σ_i, salt_i)
  8:  each party verifies:
        H("mpsvs.audit.v2" ‖ LE(R, peer) ‖ LE(R, σ_peer) ‖ LE(R, salt_peer))
          =? commit_peer_received
        if ≠: abort

Phase E (SPDZ2k identity check in the FULL extended ring):
  9:  if (σ_1 + σ_2) mod 2^R ≠ 0:  abort
 10:  return x_val
```

**Note on ring width (SPDZ2k).** Line 9 compares `σ` against 0 in the
full extended ring `ℤ_{2^R}`, NOT `ℤ_{2^k}`. This is critical: an
adversary who introduces error `δ ∈ ℤ_{2^k}` on `⟦x⟧` induces
`α · δ mod 2^R` on `σ`; the low-`k`-bit view of `σ` is degenerate
(1/2 detection worst case, per Cramer et al. Prop. 3.2), but the
full `R`-bit view catches any nonzero `δ` with probability
`≥ 1 - 2^{-s}` over the uniform choice of `α`.

**Theorem 4.6.1 (SPDZ2k open soundness).** Under Assumption 4 (SHA-256
as RO) and Assumption 7 (CSPRNG for σ_i, salt_i, α), the probability
that `Open^{sh-α}` returns a value `x' ≠ x` without aborting, over a
corrupted `S_i`'s choice of tampered `⟦[x]⟧_i`, is at most
```
Adv^{open,SPDZ2k}(𝒜, k, s, q_H) ≤ 2^{-s} + q_H · 2^{-256}.
```

**Proof sketch.** Standard SPDZ2k open-check argument (Cramer et al.
CRYPTO'18 Theorem 3): for tampered shares `⟦x⟧' = ⟦x⟧ + Δ` where
`Δ ≠ 0 mod 2^R`, the check `σ_1 + σ_2 = 0 mod 2^R` holds iff
`α · Δ = 0 mod 2^R`. Since `α` is uniformly random in `ℤ_{2^R}` and
independent of Δ (α is unknown to the adversary — DPSZ commit-reveal
prevents Δ-choice from depending on α), the probability that a nonzero
Δ has `α · Δ = 0 mod 2^R` is at most `2^{-s}` (Cramer et al. Prop.
3.1: for any `Δ ∈ ℤ_{2^R} \ {0}`, `#{α : α·Δ = 0} ≤ 2^{R-s}` when
top `s` bits of `α` are uniform). The commit-reveal binding contributes
`q_H · 2^{-256}` via RO collision.  ∎

**Algorithm 13** — `BatchOpen^{sh-α, Ω}(⟦[x_1]⟧, …, ⟦[x_n]⟧, ⟦α⟧)`
```
 1:  tr_hash ← H(‖_{j=1..n} ‖_{i=1,2} (LE(R, ⟦x_j⟧_i) ‖ LE(R, ⟦α·x_j⟧_i)))
 2:  for j ← 1 to n:
 3:      r_j ← LE_prefix(R, H("mpsvs.omega.r.v2" ‖ LE(R, j) ‖ tr_hash))
 4:      if r_j = 0 mod 2^R: r_j ← 1
 5:  ⟦[y]⟧ ← Σ_j r_j · ⟦[x_j]⟧   mod 2^R                ▷ linear combination
 6:  return Open^{sh-α}(⟦[y]⟧, ⟦α⟧) ≠ ⊥ ? {x_j mod 2^k} : ⊥
```

The `r_j` vector is Fiat-Shamir-derived from the share transcript,
unpredictable to any adversary who has not yet committed shares.
Batch soundness is `≤ 2^{-s} + q_H · 2^{-256}` — the same per-batch
bound as a single open (Cramer et al. §4).

**Algorithm 14** — `AuthMult^{sh-α}(⟦[x]⟧, ⟦[y]⟧, T, ⟦α⟧)`
where `T = (⟦[u]⟧, ⟦[v]⟧, ⟦[w]⟧)` with `w = uv`.
```
 1:  d ← Open^{sh-α}(⟦[x]⟧ − ⟦[u]⟧, ⟦α⟧)       ▷ public d = x - u
 2:  e ← Open^{sh-α}(⟦[y]⟧ − ⟦[v]⟧, ⟦α⟧)       ▷ public e = y - v
 3:  each party i ∈ {1, 2}:
 4:      ⟦z⟧_i    ← ⟦w⟧_i + d · ⟦v⟧_i + e · ⟦u⟧_i  + (i = 1 ? d · e : 0)
 5:      ⟦α·z⟧_i  ← ⟦α·w⟧_i + d · ⟦α·v⟧_i + e · ⟦α·u⟧_i  +  α_i · d · e
 6:  return ⟦[z]⟧
```

**Lemma 4.6.2 (Correctness of AuthMult).**  If `T` is a valid Beaver
triple then `Open(⟦z⟧) = xy` and `Open(⟦α·z⟧) = α · xy`, so
`⟦[z]⟧` is a valid authenticated share of `xy`.

**Proof.**  Sum lines 4–5 across parties:
```
Σ ⟦z⟧_i    =  w + d v + e u + d e
            =  u v + (x−u) v + (y−v) u + (x−u)(y−v)
            =  x y.
Σ ⟦α·z⟧_i  =  α w + d α v + e α u + α d e
            =  α (w + d v + e u + d e)
            =  α x y.  ∎
```

**Algorithm 15** — `Sacrifice^{sh-α}(T, T', ⟦α⟧)` (Ω-check for triples,
SPDZ2k variant)
```
 1:  r ← ${ℤ_{2^R}^*}                                    ▷ full-ring challenge
 2:  ρ ← Open^{sh-α}(r · ⟦u⟧ − ⟦u'⟧ mod 2^R,             ⟦α⟧)
 3:  σ ← Open^{sh-α}(    ⟦v⟧ − ⟦v'⟧ mod 2^R,             ⟦α⟧)
 4:  τ ← Open^{sh-α}(r · ⟦w⟧ − ⟦w'⟧ − σ ⟦u'⟧ − ρ ⟦v'⟧ mod 2^R, ⟦α⟧)
 5:  return (τ = ρ · σ mod 2^R) ? "T valid" : "abort"
```

**Theorem 4.6.3 (Sacrifice soundness, SPDZ2k).** For a malformed triple
`(u, v, w) with w ≠ uv mod 2^k`, `Sacrifice^{sh-α}` returns "abort"
except with probability `≤ 2^{-s}` over the uniform choice of `r ∈
ℤ_{2^R}` and `α ∈ ℤ_{2^R}`.

**Proof sketch.** Substituting `w = uv + Δ` with `Δ ≠ 0 mod 2^k`, we
have (in `ℤ_{2^R}`):
```
τ = r(uv + Δ) − u'v' − σu' − ρv'   mod 2^R
  = r · Δ  +  [ruv − u'v' − σu' − ρv']
  = r · Δ  +  ρ · σ     mod 2^R    (Beaver identity on honest T')
```
So `τ − ρσ = r · Δ mod 2^R`. The check passes iff `r · Δ ≡ 0 mod 2^R`.
The three individual opens (steps 2, 3, 4) each contribute at most
`2^{-s}` by Theorem 4.6.1. Under uniform `r ∈ ℤ_{2^R}` (Cramer et al.
Prop. 3.1), the equation `r · Δ ≡ 0 mod 2^R` has at most `2^{R-s}`
solutions out of `2^R`, giving probability `≤ 2^{-s}` per Δ.
Union bound: total failure probability
`≤ 3 · 2^{-s} + q_H · 2^{-256} ≈ 2^{-s+2}` — for `s = 80` this is
`≤ 2^{-78}`.  ∎

**Remark (SPDZ2k gap vs classical SPDZ).** MPSVS's SPDZ2k
authentication in `ℤ_{2^R}` (with `R = k + s`) is the *correct* fix
for the field-vs-ring gap noted by Cramer et al. Any restatement of
Theorems 4.6.1 / 4.6.3 as `2^{-k}` (as earlier drafts of this document
did) was in error and has been corrected. The wire-level MpsvsAuthShare
implementation prior to Rev 7.1 authenticated only in `ℤ_{2^{64}}`;
this is being retrofitted to `ℤ_{2^{144}}` (`__int128` shares) — see
`volePSI/MpsvsAuthShare.h` `[SPDZ2K-TODO]` markers. Deployments running
the ring-`ℤ_{2^{64}}` build have worst-case per-open detection
probability `1/2` against a fully-malicious adversary and MUST NOT be
used with adversary class A2 (§SECURITY.md) until the 144-bit retrofit
lands.

### 4.7 OLE-based Beaver triples

**Signature.**
```
oleTripleGen  : (party_id, count, seed, socket)
                → (⟦[u_j]⟧, ⟦[v_j]⟧, ⟦[w_j]⟧)_{j=1..count}
                  with w_j = u_j · v_j.
```

Realised by libOTe's `SilentOtTriple` under Assumption 3 (LPN).
Delivers `~2^{20}` triples per second per core on commodity hardware.

**Algorithm 16** — `oleTripleGen` (schematic; libOTe internals opaque)
```
 1:  (b, T)      ← SilentOtSender(seed_s, socket)         ▷ S_1 side
 2:  (Δ, K)      ← SilentOtReceiver(seed_r, socket)       ▷ S_2 side
 3:  parties locally derive additive shares of triples from (b, T, Δ, K)
 4:  return triples
```

**MPSVS constraint.** N = 2 fixed; N > 2 code path throws
(post-audit guard) — pairwise composition would miss cross-terms
`Σ_i≠j U_i V_j` in the product `(⨁ U_i)(⨁ V_j)`.

### 4.8 Gaussian mechanism + zCDP

**Signature.**
```
sigmaFromRho(ρ, Δ_2) := Δ_2 / sqrt(2 ρ)
addGaussianNoise(y, σ) := y + η,  η ~ N(0, σ²)
```

**Definition 4.8.1 (ρ-zCDP).** A randomised mechanism M is ρ-zCDP if
for all neighbouring databases D ∼ D' and all α > 1:
```
D_α(M(D) ‖ M(D'))  ≤  ρ · α,
```
where `D_α` is the α-Rényi divergence.

**Fact 4.8.2 (Gaussian mechanism gives ρ-zCDP).**  For query
`f : D → ℝ` with L2 sensitivity `Δ_2(f)`, releasing `f(D) + N(0, σ²)`
with `σ = Δ_2 / sqrt(2ρ)` is ρ-zCDP (Bun–Steinke 2016 Prop. 1.6).

**Fact 4.8.3 ((ε, δ)-DP conversion).**  ρ-zCDP implies
`(ρ + 2 sqrt(ρ · ln(1/δ)), δ)`-DP for any `δ ∈ (0, 1)`.

**Fact 4.8.4 (Composition).**  ρ_1-zCDP composed with ρ_2-zCDP gives
`(ρ_1 + ρ_2)`-zCDP.

Realisation: `MpsvsDp::sigmaFromRho`, `MpsvsDpProd::sampleGaussianCsprng`
(discrete Gaussian via CSPRNG-driven Box–Muller with rounding to
integer; documented rounding bias `≤ O(σ^{-1})` in the header).

**Algorithm 17** — `JointGaussianRelease(y, ρ, k)` — commit-then-reveal
between S_1, S_2
```
 1:  σ         ← sqrt(2 / (2ρ))               ▷ Δ_2 = √2 for count hist
 2:  σ_party   ← σ / sqrt(2)                  ▷ each contributes half variance
 3:  each party i ∈ {1, 2}:
 4:      η_i     ← ${discrete Gaussian(0, σ_party²) via CSPRNG}
 5:      salt_i  ← ${𝔽_{2^128}}
 6:      commit_i ← H("mpsvs.dp.commit" ‖ ctx ‖ LE32(i) ‖ LE64(η_i) ‖ salt_i)
 7:  Round 1: exchange commit_1 ↔ commit_2
 8:  Round 2: exchange (η_i, salt_i) ↔
 9:  each party verifies peer's commit; abort on mismatch
10:  η ← η_1 + η_2                             ▷ ~ N(0, σ²)
11:  y_open ← Open^{sh-α}(⟦[y]⟧, ⟦α⟧)         ▷ or ⊥ on MAC failure
12:  if n_valid < k: return ⊥                  ▷ k-anon suppression
13:  return max(0, y_open + η)                 ▷ R26 clamp
```

**Theorem 4.8.5.** Algorithm 17 realises `F_DP(σ, k, ρ, ρ_max)`
under Assumptions 4, 7, 8, plus F_SPDZ (for step 11).

**Proof sketch.** Under honest execution, `η_1 + η_2 ~ N(0, σ²)` since
independent Gaussians. Under a malicious `S_i`, commit binding
(Assumption 4) prevents `S_i` from choosing `η_i` after seeing peer's
`η_{peer}`. The MAC check in step 11 catches any share tampering with
prob `≥ 1 − 2^{-k}` (Theorem 4.6.1).  ∎

---

## 5. Protocol Π_SECTORVULN — phase-by-phase algorithms

We present the protocol in numbered phases. Each phase invokes
building blocks from Section 4 or the ideal functionalities from
Section 3. Parties: `P = {MAS, DOS, MOM, S_1, S_2, GT}`.

### 5.1 Phase 0 — Bootstrap

**Algorithm 18** — `Bootstrap(Φ)`
```
GT locally:
  1:  session_id ← ${𝔽_{2^128}}
  2:  nonce      ← ${𝔽_{2^128}}
  3:  configHash ← H(canonical(config))
  4:  paramsHash ← H(canonical(params))
  5:  ctx        ← (session_id, nonce, configHash, paramsHash)
  6:  publish (Φ, session_id, nonce, configHash, paramsHash) to all P

Each party P ∈ P (offline, once):
  7:  (sk_P, pk_P) ← previously-generated X25519 identity
  8:  master_key ← Argon2id(passphrase, salt)          ▷ Assumption 6
  9:  decrypt MpsvsKeyStore: (sk_P, {pk_Q}_{Q ∈ P})

For each pair (P, Q) with lexicographic order P < Q, in parallel:
 10:  role_P ← INITIATOR;  role_Q ← RESPONDER
 11:  invoke F_AUTH.Handshake(sk_P, pk_Q, ctx) → session keys (rx, tx)
 12:  open XChaCha20-Poly1305 secretstream in both directions
       verifying peer_pk = expected pk_Q  (sodium_memcmp CT)
```

**Round complexity.** 4 messages per pair, so
`Round = 2` (parallelisable across pairs).

**Communication.** `≈ (24 + 8 + 32) × 2 × |pairs| ≈ 128 × 15 = 1920 B`
for 6 parties.

### 5.2 Phase 1 — Local prep (each client)

**Algorithm 19** — `LocalPrep(input_rows, range_config, growth_cap)`
```
 1:  for each row (id, period, sector, payload) in input_rows:
 2:      for each attribute a in payload:
 3:          if a has growth field g: clip g to [-G_max, +G_max]
 4:          if a not in range_config[a]:  mark row.valid[a] ← 0
 5:      normalise units (SGD cents / headcount); scale by 2^f
 6:  return prepared rows
```

**Communication.** None. Fully local.

### 5.3 Phase 2 — OPRF DKG + row-tag derivation

**Session-scoped setup.**
```
Invoke Π_DKG (Algorithm 10) between S_1 and S_2 with input ctx.
Outputs: S_1 holds k_1;  S_2 holds k_2;  both hold Y = [k_1 k_2] g.
```

**Per-row OPRF (each client `C ∈ {MAS, DOS, MOM}`, each row):**
```
Invoke Π_OPRF (Algorithm 11) with input id → W = [k_1 k_2] hashToPoint(id).
Enforce query cap: |queries_C_this_epoch| ≤ Q̃ (config).
```

**Algorithm 20** — `RowTagDerive(W, id, id_type, period, ctx)`
```
 1:  row_tag ← H("mpsvs.oprf.tag" ‖ ctx ‖ id_type ‖ id ‖ LE32(period) ‖ LP(W))
 2:  bin ← row_tag[0 : β]                     ▷ β bits from MSB
 3:  key ← row_tag[β : β + τ]                 ▷ τ bits, bit-aligned
 4:  return (bin, key)
```

**Complexity.**
- Session (DKG): `Round = 3`, `Comm = 320 bytes`, `Comp = O(1)` group ops.
- Per row (OPRF): `Round = 4`, `Comm ≈ 512 bytes`, `Comp = 4` group scalar-mults.
- Total: `4 · Q̃ · |clients|` OPRF rounds per session.

### 5.4 Phase 3 — Client share submission

**Algorithm 21** — `ClientSubmit(C, row_j, S_1, S_2)`
```
 1:  ⟦[payload_j]⟧ ← F_SPDZ.Input(payload_j)              ▷ via preprocessing
 2:  ⟦[validity_bits_j]⟧ ← F_SPDZ.Input(validity_bits_j)
 3:  send ⟦payload_j⟧_1, ⟦α · payload_j⟧_1 to S_1 over F_AUTH
 4:  send ⟦payload_j⟧_2, ⟦α · payload_j⟧_2 to S_2 over F_AUTH
```

**MOM constraint.** MOM is input-only: it participates in Phases 2, 3
only. Enforced by `isClientRole()` on all Phase 4-13 entry points.

### 5.5 Phase 4 — F_PSA alignment

Six sub-protocols. All between S_1 and S_2 under ⟦[·]⟧ representation.

**Algorithm 22** — `Π_PSA(rows_S1, rows_S2)`
```
 1:  packBins(rows_S1, β, cap_P)              ▷ Alg. 22a
 2:  packBins(rows_S2, β, cap_P)              ▷ (mirror)
 3:  for each bin b ∈ {0, 1, ..., 2^β − 1}:
 4:      bin[b] ← withinBinSort(bin[b])       ▷ Alg. 22b
 5:      union_rows[b] ← windowedMerge(bin[b]) ▷ Alg. 22c
 6:      markLive(union_rows[b])              ▷ Alg. 22d
 7:  all_rows ← ⋃_b union_rows[b]
 8:  composedShuffle(all_rows)                ▷ Alg. 22e (uses Alg. 5–6 NIZK)
 9:  inject coverFirms(K ~ Uniform[K_min, K_max])   ▷ Alg. 22f
10:  return all_rows                           ▷ authenticated shares
```

**Algorithm 22a** — `packBins(rows, β, cap_P)`
```
 1:  for each row r ∈ rows:
 2:      place r in bin[r.bin]
 3:  for each bin b:
 4:      if |bin[b]| > cap_P:  throw RestartSession
 5:      while |bin[b]| < cap_P:
 6:          bin[b].append(dummy_row with memb = 0, key ← ${𝔽_{2^τ}})
```

**Algorithm 22b** — `withinBinSort(bin_b)` — bitonic sort by `(key, source)`
```
n ← cap_P (power of 2 by padding)
for k ← 2, 4, ..., n:
  for j ← k/2, k/4, ..., 1:
    for i ← 0 to n − 1:
      l ← i XOR j
      if l > i:
        if ((i AND k) = 0 and bin_b[i] > bin_b[l])
           or ((i AND k) ≠ 0 and bin_b[i] < bin_b[l]):
              conditionalSwap(bin_b[i], bin_b[l])
```

**Algorithm 22c** — `windowedMerge(sorted_bin_b)` (Rev 7 §5.4)
```
 1:  # Iterate the sorted bin; on every canonical boundary (r.key ≠
 2:  # prev_key) START a fresh union row via AuthMux; on non-canonical
 3:  # rows FOLD r into the current union row via AuthOR / AuthMUX.
 4:  # The oblivious form emits one output row per input row — non-
 5:  # canonical rows carry live=0 and are dropped downstream.
 6:
 7:  u_prev ← ZERO_UNION                              ▷ SPDZ2k-shared zero
 8:  prev_key ← 0                                     ▷ SPDZ2k-shared placeholder
 9:  out ← []
10:  for row r ∈ sorted_bin_b:
11:      canonical ← AuthNEQ(r.key, prev_key)         ▷ 1 iff key changed
12:      # Fresh union row when canonical=1, else fold into u_prev:
13:      u_start ← AuthMux(canonical, ZERO_UNION, u_prev)
14:      u.b_MAS ← AuthOR(u_start.b_MAS, AuthAND(AuthEQ(r.source, MAS), r.memb))
15:      u.b_DOS ← AuthOR(u_start.b_DOS, AuthAND(AuthEQ(r.source, DOS), r.memb))
16:      u.b_MOM ← AuthOR(u_start.b_MOM, AuthAND(AuthEQ(r.source, MOM), r.memb))
17:      u.p_MAS ← AuthMux(AuthEQ(r.source, MAS), r.payload, u_start.p_MAS)
18:      u.p_DOS ← AuthMux(AuthEQ(r.source, DOS), r.payload, u_start.p_DOS)
19:      u.p_MOM ← AuthMux(AuthEQ(r.source, MOM), r.payload, u_start.p_MOM)
20:      u.canonical ← canonical
21:      u_prev ← u                                    ▷ carry into next row
22:      prev_key ← r.key
23:      out ← out ‖ u
24:  return out                                        ▷ len = |sorted_bin_b|
```

**Note.** Non-canonical rows (`u.canonical = 0`) are marked `u.live = 0`
in Phase 22d and get suppressed from downstream aggregation. The
oblivious loop preserves data-independence of the trace — every input
row produces exactly one output row, with content varying via
`AuthMux` on the secret `canonical` bit.

**Algorithm 22d** — `markLive(union_rows)`
```
 1:  for each u ∈ union_rows:
 2:      u.live ← AuthAND(u.canonical, AuthOR(u.b_MAS, u.b_DOS, u.b_MOM))
```

**Algorithm 22e** — `composedShuffle(rows)`
```
 1:  π_1 ← ${uniform permutation of [n]}                 ▷ S_1
 2:  rows ← apply π_1 via oblivious conditional-swap network
 3:  π_2 ← ${uniform permutation of [n]}                 ▷ S_2
 4:  rows ← apply π_2 via oblivious conditional-swap network
 5:  compute Pedersen commitments C_orig, C_shuf for the vectors
 6:  π_SHUF ← shuffleProveBg(msgs, r, r', π_2 ∘ π_1, C_orig, C_shuf)  ▷ Alg. 5
 7:  publish π_SHUF to audit chain
 8:  verifier (GT or any auditor) checks:
       shuffleVerifyBg(π_SHUF, C_orig, C_shuf) = accept        ▷ Alg. 6
```

**Algorithm 22f** — `coverFirms(rows, K_min, K_max)`
```
 1:  K ← ${Uniform[K_min, K_max]}
 2:  for j ← 1 to K:
 3:      dummy_row ← record with memb = 0, key ← ${𝔽_{2^τ}}, payload ← 0
 4:      rows ← rows ‖ dummy_row
 5:  return rows
```

**Complexity.**
- packBins: `O(|rows| + 2^β · cap_P)` per party
- withinBinSort: `Σ_b Θ(cap_P · log² cap_P)` compare-swaps; each
  compare-swap = 256 Beaver triples (bit-decomposed 64-bit LT) + 1
  MUX.
- windowedMerge: `O(cap_P)` MUX per bin.
- composedShuffle: `O(n)` conditional-swaps per party (π_1 or π_2 as
  a random-looking permutation network).
- shuffle NIZK: `O(n)` scalar operations per verifier.

### 5.6 Phase 5 — Inclusion bits

**Algorithm 23** — `InclusionMask(u, metric_m)` (Rev 7 Protocol §7)
```
 1:  incl_DTI(u)  ← AuthAND( u.live, u.b_MAS, u.b_DOS,
                             v_debt(u.p_MAS), v_income(u.p_DOS),
                             InRng(u.p_DOS.income, DOS_income_rng) )
 2:  ...  (DSI, DEmp, IPW, Delq, NPL, UnsecShare, StDebtShare, Gap
       analogously — see Rev 7 §7)
 3:  incl_vuln(u) ← AuthAND(u.live, CoveragePredicate_Φ({avail_c}))
```

Every AuthAND consumes one Beaver triple via Algorithm 14
(`AuthMult^{sh-α}`).

**Every inclusion bit is proved bit ∈ {0, 1} via Algorithms 7–9.**

### 5.7 Phase 6 — Bucketing + Goldschmidt reciprocal

**Algorithm 24** — `BucketIndex(x, edges)` — oblivious binary-search
producing a **one-hot** vector, then bit-position reduction to a
`log₂B`-bit bucket index.  Matches `MpsvsRatioBucketWire.cpp:99-136`.
```
 1:  # PUBLIC:  edges[0..B]   (regulator-signed bucket edges from Φ)
 2:  # SECRET:  ⟦x⟧, ⟦incl⟧   (SPDZ2k-authenticated arithmetic share)
 3:
 4:  # ---- Phase 1: build a ONE-HOT bucket indicator over ALL B buckets.
 5:  # Every bucket is touched regardless of the value of ⟦x⟧, so the
 6:  # data-access trace is public and constant.  The binary search is
 7:  # in the COMPARATOR chain, not in the index array.
 8:  for b ← 0 to B − 1:
 9:      ⟦lo_b⟧      ← AuthGE(⟦x⟧, edges[b])         ▷ 1 iff x ≥ edges[b]
10:      ⟦hi_b⟧      ← AuthLT(⟦x⟧, edges[b+1])       ▷ 1 iff x <  edges[b+1]
11:      one_hot[b]  ← AuthAND(⟦lo_b⟧, AuthAND(⟦hi_b⟧, ⟦incl⟧))
12:
13:  # ---- Phase 2: reduce the one-hot vector to a log₂B-bit bucket
14:  # index via bit-position XOR.  For each bit position i of the index:
15:  #   bucket_index.bit[i]  =  XOR_{b : bit-i(b) = 1} one_hot[b]
16:  # XOR-shares compose linearly, so this is fully local.
17:  for i ← 0 to log₂B − 1:
18:      bucket_index.bit[i] ← 0                    ▷ SharedBit(N)
19:      for b ← 0 to B − 1:
20:          if bit i of b is 1:
21:              bucket_index.bit[i] ← XOR(bucket_index.bit[i], one_hot[b])
22:
23:  return (one_hot, bucket_index)
```

**Note (obliviousness).** An earlier draft of this document described
`BucketIndex` as a binary search that computed `mid = ⌊(lo + hi)/2⌋`
publicly after `lo` and `hi` become secret — that leaks `O(log B)`
bits about the bucket via the public-branch access pattern and is
NOT oblivious. The variant above (matching the wire code) touches
every bucket unconditionally and reduces via XOR — genuinely
oblivious. Cost: `B` secure-GE + `B` secure-LT + `B` secure-AND
(dominant: `≈ 512·B` Beaver triples per bucketing); worth the
constant-factor over a public-`mid` binary search which would leak
`log₂B` bits per input.

**Algorithm 25** — `Goldschmidt(x, f, K)` — reciprocal to K iterations
```
 1:  r_0 ← initial approx of 2^f / x   (lookup table on public high bits)
 2:  y_0 ← r_0
 3:  d_0 ← 2^f − x · r_0
 4:  for k ← 1 to K:
 5:      y_k ← y_{k-1} · (2^f + d_{k-1}) / 2^f    ▷ AuthMult + shift
 6:      d_k ← d_{k-1}² / 2^f
 7:  return y_K
```

**Verification.** Output verified by `verifyReciprocalAuthShared`
(Section 4.6 + Rev 7 §17.6) — computes `AuthMult^{sh-α}(y_K, x)` and
checks the opened value equals `2^f` within tolerance ε.

### 5.8 Phase 8 — Rank

**Algorithm 26** — `SlimSort(slim_rows)` — bitonic on
`(popkey, invalid, bucket)`
```
Same bitonic pattern as Alg. 22b, comparing by composite key:
  compare_key(r) := (r.popkey, 1 − r.incl, r.bucket)
Optional radix sort within (popkey, invalid) groups when B ≤ 128
(Rev 7 R27 break-even).
```

### 5.9 Phase 9 — Composite score

**Algorithm 27** — `CompositeScore(row, metric_weights, coverage_policy)`
```
 1:  weights ← metric_weights
 2:  if coverage_policy = RENORMALISED:
 3:      weights ← Renormalise(weights, {avail_c})
 4:  score ← 0
 5:  for each metric m:
 6:      score ← AuthAdd(score, AuthMulConst(bucket_m(row).normalised,
                                              weights[m]))
 7:  return score
```

### 5.10 Phase 10 — Percentiles

**Algorithm 28** — `PercentileFromHist(H_pub, q)` — quantile-inversion on
the POST-RELEASE public histogram.
```
 1:  # PRECONDITION: H_pub is the output of Alg. 30 (DP-noised, k-anon-
 2:  # gated, R26-clamped, and OPENED to the release channel). The
 3:  # data-dependent early return on line 5 is therefore acting on
 4:  # public inputs and is safe. This routine is NOT executed inside
 5:  # the MPC pipeline; it is a plaintext post-processor run by GT
 6:  # or by an auditor consuming the release tuple.
 7:  target ← q · H_pub.n_valid_noised          ▷ ñ from Alg. 30
 8:  cum ← 0
 9:  for b ← 0 to B − 1:
10:      next ← cum + H_pub.h[b]
11:      if next ≥ target:
12:          lo ← edges[b];  hi ← edges[b + 1]
13:          frac ← (target − cum) / max(H_pub.h[b], 1)
14:          return lo + frac · (hi − lo)
15:      cum ← next
16:  return edges[B]
```

**Note.** If a caller ever wants percentile queries on the *secret*
in-MPC histogram (before DP release), they must use an oblivious
segmented CDF scan; the branching `PercentileFromHist` above only
applies to already-released data.

### 5.11 Phase 11 — Sector aggregation

**Algorithm 29** — `SectorAggregate(entity_rows, edges)`
```
 1:  for each row e ∈ entity_rows:
 2:      key ← (e.sector, e.period)
 3:      for each metric m:
 4:          b ← BucketIndex(e.metric_value_m, edges[m])
 5:          hist[key, m].h[b] ← AuthAdd(hist[key, m].h[b], e.incl_m)
 6:          hist[key, m].n_valid ← AuthAdd(hist[key, m].n_valid, e.incl_m)
 7:          num[key, m] ← AuthAdd(num[key, m], AuthMult(e.incl_m, e.num_m))
 8:          den[key, m] ← AuthAdd(den[key, m], AuthMult(e.incl_m, e.den_m))
 9:  for each (key, m):
10:      ratio[key, m] ← Goldschmidt-and-verify(num[key, m], den[key, m])
11:  return (hist, num, den, ratio)
```

**Audit invariant.**
```
Σ_{(s,p)} num(s, p, m)  =  Σ_{u ∈ U} incl_m(u) · num_m(u)      (mod 2^k)
Σ_{(s,p)} den(s, p, m)  =  Σ_{u ∈ U} incl_m(u) · den_m(u)      (mod 2^k)
```
`auditSectorAggregate` verifies both.

### 5.12 Phase 12 — DP release + k-anonymity

For each release cell `(s, p, m)`:

**Algorithm 30** — `ReleaseCell(s, p, m, ρ_th, ρ_hist, ρ_num, ρ_den, k, budget)`
```
Per-metric sensitivities (add/remove neighbour, §3 F_DP):
    Δ_hist_m  = √2     ▷ one entity → at most one bucket, ±1 count
    Δ_num_m   = C_num_m   ▷ per-metric contribution clip (numerator)
    Δ_den_m   = C_den_m   ▷ per-metric contribution clip (denominator)
    Δ_count   = 1        ▷ one entity → ±1 in n_valid

Total ρ deduction for this cell:
    ρ_cell = ρ_th + ρ_hist + ρ_num + ρ_den

Preflight:
 1:  if budget.spent + ρ_cell > ρ_max:  abort "budget exhausted"

Stability gate on the COUNT (Bun–Steinke stability-based release):
 2:  n_v      ← Open^{sh-α}(hist[(s,p), m].n_valid, ⟦α⟧)
 3:  σ_ξ      ← sqrt(Δ_count² / (2 · ρ_th))                  ▷ noise scale for gate
 4:  τ        ← σ_ξ · sqrt(2 · ln(1 / (2 · δ)))              ▷ stability margin
 5:  ξ        ← sample_Gaussian(0, σ_ξ²)                     ▷ CSPRNG
 6:  ñ        ← n_v + ξ
 7:  if ñ < k + τ:
       budget.spent ← budget.spent + ρ_th                     ▷ still spend gate ρ
       return ⊥

Release payload — per-metric noise sizes:
 8:  σ_hist   ← sqrt(Δ_hist_m² / (2 · ρ_hist))
 9:  σ_num    ← sqrt(Δ_num_m²  / (2 · ρ_num))
10:  σ_den    ← sqrt(Δ_den_m²  / (2 · ρ_den))
11:  for each bucket b:
12:      y_hist_b ← JointGaussianRelease(hist[(s,p), m].h[b], σ_hist)
13:  y_num    ← JointGaussianRelease(num[(s,p), m], σ_num)
14:  y_den    ← JointGaussianRelease(den[(s,p), m], σ_den)

Budget accounting (charge all four independent releases):
15:  budget.spent ← budget.spent + ρ_th + ρ_hist + ρ_num + ρ_den

Release tuple:  the noised count is ALSO released (ξ was added to it);
raw n_v never leaves the compute nodes.
16:  release[(s, p, m)] ← (y_hist_b, y_num, y_den, ñ)
17:  return release[(s, p, m)]
```

**Implementation.** `MpsvsDpProd::noisyThresholdReleaseProd`
(Rev 7.1) implements Alg 30 with all four ρ terms threaded through
a `DpMetricParams` struct. Regression: `test_mpsvs_dp_noisy_threshold`
proves per-metric-σ threading (large-Δ config produces ~3800× more
noise than small-Δ) and neighbour-count comparability (bounded ε
loss vs infinite under classical k-anon).

**Deprecated path.** The earlier `addJointNoiseImpl` +
`applyKAnonGate` (with reveal-and-reshare A2B) still exist in the
codebase for backward compatibility with tests. New deployments MUST
use `noisyThresholdReleaseProd`. The legacy path (a) gates on true
`n_valid`, (b) releases raw `n_valid_gated`, (c) charges a single
`ρ` per cell — all three DP holes documented in §5.12.

**Note (composition).** Each cell releases FOUR independent
Gaussian-noised statistics — count (with ρ_th), histogram (ρ_hist),
numerator (ρ_num), denominator (ρ_den) — each with its own per-metric
sensitivity. By zCDP composition (Fact 4.8.4), the cell as a whole
satisfies `ρ_cell = ρ_th + ρ_hist + ρ_num + ρ_den`-zCDP. `MpsvsConfig`
must specify each ρ_·_ separately; the earlier code that deducted
a single `ρ` per cell while releasing three noised statistics was
under-charging by a factor of ~3 and has been retrofitted.

### 5.13 Phase 13 — Audit chain seal

**Algorithm 31** — `SealAuditChain(events)` (Rev 7 §13)
```
 1:  prev_link ← 0^{256}
 2:  for each event e in events:
 3:      payload ← Encode(e.type, e.timestamp_ns, e.ctx)
 4:      link ← H("mpsvs.audit" ‖ prev_link ‖ payload)
 5:      append (e, link) to file (MpsvsAuditPersist, flock, atomic rename)
 6:      prev_link ← link
 7:  chainRoot ← prev_link
 8:  send chainRoot + attestations to GT via F_AUTH
```

---

## 6. Simulator construction

We give the simulator `Sim` for the case of a corrupted `S_1` (the
symmetric case for corrupted `S_2` is analogous).

**Sim setup.**
`Sim` interacts with the ideal functionalities
`F_OPRF, F_SPDZ, F_DP` and with the real-world `𝒜` controlling `S_1`.
`Sim` maintains the internal state that an honest `S_2` would have.

**Sim in Phase 0.** `Sim` runs the handshake honestly on `S_2`'s side;
uses `S_1`'s long-term key from ROM programming.

**Sim in Phase 2 (DKG).**
- On receiving `commit` from 𝒜, `Sim` extracts nothing yet.
- `Sim` samples random `k_2^{sim}, Y_2^{sim}` and produces a valid
  `π_2^{sim}` (via ROM programming on `H`).
- `Sim` produces `π_Y^{sim}` such that `Y = [k_2^{sim}] Y_1`; this
  fully determines `Y`.
- Now `Sim` calls `F_OPRF.Setup(Y)` — programs `Y` as the joint
  OPRF public key.

**Sim in Phase 2 (OPRF query).**
- 𝒜 issues `U_blind`. `Sim` observes this but does not know the
  underlying `id`.
- `Sim` samples random `V_1^{sim}` and produces DLEQ proof by
  programming ROM. This is UC-indistinguishable from honest execution
  by the CDH assumption (Assumption 1).

**Sim in Phase 3–11.** All values are additive shares. `Sim` uses
random shares for its `S_2` view. Every intermediate open produces a
value pattern-indistinguishable from a random one because MAC-check
successes are simulated via ROM programming.

**Sim in Phase 12.** `Sim` receives from `F_DP` the (noised) release
values `{y_hist, y_num, y_den}`. `Sim` samples `η_2^{sim}` uniformly
in the appropriate discrete Gaussian range, commits, opens, and
programs the ROM on `H("mpsvs.dp.commit" ‖ ...)` such that the joint
noise `η_1^{sim} + η_2^{sim}` equals the observed release minus the
opened aggregate. This preserves the joint distribution to statistical
distance `≤ 2^{-σ_stat}`.

**Sim in Phase 13.** `Sim` writes the audit chain locally, computes
`chainRoot`, and delivers it to `F_AUTH` for delivery to GT.

**Lemma 6.1 (Indistinguishability).** For every PPT 𝒜, the real and
ideal executions are statistically `≤ 2^{-σ_stat} + q · negl(λ)`
close, where `q` is the total number of interactions.

**Proof sketch.** Hybrids:
- H_0 = real world with corrupted `S_1`.
- H_1 = replace OPRF with `Sim`-programmed version. Distinguishing
  reduces to CDH (Assumption 1).
- H_2 = replace all SPDZ opens with `Sim`-programmed MAC verification.
  Distinguishing reduces to Theorem 4.6.1.
- H_3 = replace DP noise generation with `Sim`-programmed matching
  the ideal release. Distinguishing reduces to Assumption 4 (SHA-256
  binding) and the joint-noise composition (Fact 4.8.4).
- H_3 = ideal world. ∎

---

## 7. Security theorems

### Theorem 7.1 (Main — MPSVS security)

Protocol Π_SECTORVULN Rev 7 UC-realises F_SECTORVULN in the
(F_AUTH, F_CT, F_OPRF, F_SPDZ2k, F_DP)-hybrid model under Assumptions
1, 3, 4, 7, 8, 9, with total statistical distance
```
Adv^{ind}_MPSVS(𝒜, λ, s, q_total)  ≤  q_total · 2^{-s}  +  q_total · negl(λ)
```
where `s` is the SPDZ2k statistical parameter (§1) and `q_total` is
the total number of protocol operations invoked. For `s = 80` and
`q_total = 2^{40}` this is `≤ 2^{-40} + negl(λ)`.

**Proof.** By composition of Lemma 6.1 (Sim indistinguishability) with
Theorems 4.5.2 (F_OPRF realisation), 4.6.1 (F_SPDZ), 4.8.5 (F_DP),
and the trivial simulation of F_AUTH and F_CT under Assumption 5.

### Theorem 7.2 (Confidentiality — Goal C1)

For every PPT `𝒜` corrupting at most one of `{S_1, S_2}` and any
subset of client parties `{MAS, DOS, MOM}`, and any single firm `x`
not in the corrupted clients' input,
```
| Pr[𝒜 outputs x's plaintext value]  −  Pr[𝒜 outputs a fixed
      guess] |  ≤  Adv^{ind}_MPSVS(𝒜, λ).
```

**Proof.** Theorem 7.1 + F_SECTORVULN's ideal behaviour (which
never releases per-firm plaintext).  ∎

### Theorem 7.3 (Integrity — Goal I1)

For every PPT `𝒜` controlling at most one of `{S_1, S_2}` and any
protocol variable `v` with authenticated share `⟦[v]⟧`:
```
Pr[Open^{sh-α}(⟦[v_tampered]⟧, ⟦α⟧) returns v' ≠ v ∧ ¬abort]
    ≤  2^{-s}  +  q_H · 2^{-256}      per open (Theorem 4.6.1).
```
Composed by union bound over the `q_total ≤ 2^{40}` opens per session,
```
Pr[undetected tamper anywhere in a session]  ≤  q_total · 2^{-s}
                                             +  q_total · q_H · 2^{-256}
                                             ≈  2^{40 - s}
                                             =  2^{-40}    for s = 80.
```

**Currently implemented bound.** `MpsvsAuthShare128` uses `s = 64`
(the widest that fits in `__int128`), yielding:
```
per-open        ≤ 2⁻⁶⁴ + q_H · 2⁻²⁵⁶   ≈ 2⁻⁶⁴
session-level   ≤ 2⁴⁰ · 2⁻⁶⁴          = 2⁻²⁴
```

This closes the classical-SPDZ `1/2` gap (regression test
`test_mpsvs_spdz2k` catches `δ = 2⁶³` at 100/100 trials) but does
not yet reach the `σ_stat = 40` statistical-security target of
`2⁻⁴⁰`. Getting there requires either:
- **s = 80 bignum retrofit** — extend `SharedU128` to a proper
  256-bit representation (pair of `__int128` limbs or
  `boost::multiprecision`). Gives `2⁻⁴⁰` session-level. Estimated
  cost: another ~400 LOC + all Beaver preprocessing updates. Tracked
  as follow-up.
- **k = 48 alternative** — reduce the semantic-value width to 48
  bits (still ≥ SGD-cent range, max ≈ `2⁴⁷`), keep `s = 80` in
  `__int128`. Gives `2⁻⁴⁰` session-level without bignum. Requires
  updating every arithmetic op that assumes 64-bit values —
  substantial cascading change.

Earlier drafts asserted `2⁻ᵏ` per open with `k = 64` and concluded
`2⁻²⁴` at `2⁴⁰` opens; that bound was both wrong (SPDZ2k gap, §4.6)
and too loose to meet the `2⁻⁴⁰` target. The **current implemented**
bound is the same `2⁻²⁴` for the different (correct-but-interim)
reason of `s = 64`.

### Theorem 7.4 (Shuffle integrity — Goal I2)

For BG shuffle NIZK with input length `n`,
```
Pr[shuffleVerifyBg(π*, C, C') = accept  ∧  {m_i} ≠ {m'_i}]
    ≤  n · q_H^2 / p                                   (Theorem 4.3.1).
```
For `n = 2^{12}`, `p ≈ 2^{252}`, `q_H = 2^{40}`, this is `≤ 2^{-160}`.

### Theorem 7.5 (Differential privacy — Goal DP1)

Every release computed via Algorithm 30 satisfies
`(ρ_th + ρ_hist + ρ_num + ρ_den)`-zCDP under the add/remove
neighbouring relation (§3 F_DP).

**Proof.** Four independent Gaussian mechanisms are composed:
- **Stability gate** (steps 5–6): `ξ ← N(0, σ_ξ²)` with
  `σ_ξ = 1/√(2ρ_th)` gives ρ_th-zCDP for the count with sensitivity
  `Δ_count = 1` (Fact 4.8.2). The threshold decision `[ñ < k+τ]` is
  a post-processing of `ñ`, so it inherits ρ_th-zCDP (post-processing
  invariance).
- **Histogram** (steps 8, 11–12): σ_hist calibrated to Δ_hist_m = √2
  gives ρ_hist-zCDP.
- **Numerator** (step 9, 13): σ_num calibrated to per-metric
  contribution clip Δ_num_m gives ρ_num-zCDP.
- **Denominator** (step 10, 14): similarly ρ_den-zCDP.

By zCDP composition (Fact 4.8.4), the four-tuple release satisfies
`(ρ_th + ρ_hist + ρ_num + ρ_den)`-zCDP.

Session-level composition: an epoch running over C cells accumulates
`C · (ρ_th + ρ_hist + ρ_num + ρ_den)` zCDP, refused by `BudgetTracker`
if it exceeds `ρ_max`.

**Implementation status.** `MpsvsDpProd::noisyThresholdReleaseProd`
implements Alg 30 (Rev 7.1). Regression: `test_mpsvs_dp_noisy_threshold`
proves the four-part release, per-metric-σ threading, and neighbour
comparability.

**However, the deployed pipeline still calls the deprecated path**
(`MpsvsDpProd::addJointNoiseImpl` + `MpsvsKAnonGate::applyKAnonGate`).
Wiring `noisyThresholdReleaseProd` into `MpsvsSectorAggWire` is a
separate migration step not yet done. Until that migration lands, the
Rev 7 pipeline as deployed satisfies Theorem 7.5 **only when
`applyKAnonGate` is bypassed and `noisyThresholdReleaseProd` is
called directly by the caller**. Deployments that rely on the wired
default path retain the three DP holes described in §5.12 and violate
Theorem 7.5.

**Note on the fix vs earlier drafts.** The earlier Alg 30 (a) gated on
the *true* n_valid — an infinite-DP-loss operation for neighbours
straddling k; (b) released the un-noised n_valid outside the budget;
and (c) charged a single ρ per cell while emitting three independent
noised statistics. All three are corrected above and implemented in
`noisyThresholdReleaseProd`: (a) stability-noise gate à la Bun–Steinke
2016 §4; (b) the released count is `ñ = n_v + ξ`, not `n_v`; (c) each
release contributes its own ρ term to the accumulator.

### Theorem 7.6 (Accountability — Goal AC1)

For every valid `chainRoot` published to GT, the transcript reconstructed
from the audit chain matches the actual protocol execution except with
probability `q_H · 2^{-256}` (Assumption 4, SHA-256 collision-resistance).

---

## 8. Complexity analysis

### 8.1 Round complexity per phase

| Phase | Rounds |
|---|---|
| 0 Bootstrap | 2 (parallel over pairs) |
| 2 DKG | 3 |
| 2 OPRF | 4 per client per row |
| 4 packBins | 0 (local) |
| 4 withinBinSort | `O(log^2 cap_P)` (bitonic depth) |
| 4 windowedMerge | `O(1)` per row |
| 4 composedShuffle | `O(log n)` |
| 5 inclusion bits | `O(1)` per row per metric |
| 6 bucketing | `O(log B)` per row per metric |
| 6 Goldschmidt | `O(K)` = 5–6 |
| 8 rank | `O(log^2 n)` |
| 11 aggregation | `O(1)` per row |
| 12 DP release | 2 per cell (commit + reveal) |

### 8.2 Communication cost

Let `N = |real rows| + K_cover`, `M = |metrics| = 9`,
`S = |sectors × periods|`, `B = 128`.

| Component | Communication (bits) |
|---|---|
| Handshakes | `Θ(|pairs| · 512)` |
| DKG | `Θ(1)` |
| OPRF | `Θ(|clients| · Q̃ · 4 · 512)` |
| Share submission | `Θ(N · payload_bits · 2)` |
| F_PSA sort + merge + shuffle | `Θ(N · log² N · k · 256)` — each of `N log² N` compare-swaps costs 256 Beaver triples on 64-bit ring |
| Inclusion bits | `Θ(N · M · k)` — 9 AuthMults × 64 bits |
| Bucketing | `Θ(N · M · log B · k · 256)` |
| Aggregation | `Θ(S · M · B · k)` |
| DP release + BG NIZK | `Θ(S · M · B · k + N · 32)` (NIZK is `O(N)` scalars) |

For `N ≈ 10^6, M = 9, S = 20, B = 128, k = 64`:
- Share submission: `≈ 10^6 · 64 · 2 = 128 MB`
- F_PSA MPC (dominant): `≈ 10^6 · 400 · 64 · 256 ≈ 6.5 TB` per full-fidelity
  run, dominated by the bitonic sort. In practice split across many
  batched Ω-checks.

### 8.3 Computation

- OPRF: `4 |clients| Q̃` group scalar-mults (~10 μs each)
- SPDZ arithmetic: `O(N log² N M B k)` u64 multiplications
- Pedersen commit for shuffle NIZK: `O(N)` scalar-mults (~10 μs each)
- SHA-256 hashing: `O(N k)` bytes per session

Wall-clock at 1 M firms × 20 sectors (semantic reference, in-process):
≈ 790 ms total; peak RSS ≈ 515 MB (see `test_mpsvs_scale_1M`).

### 8.4 Round + preprocessing tradeoff

Preprocessing (offline, before Phase 3):
- SPDZ α generation: 1 X25519 exchange + 1 Beaver triple = `~1 ms`
- Beaver triples: `~10^6` triples per session via `SilentOtTriple` at
  `~10^5 triples/sec/core` = `~10 s` per session per party, one-off.

Online: dominated by F_PSA sort. Round-optimised batching reduces
this to `O(1)` rounds via non-recursive bitonic + batched Ω-check.

---

## 9. Failure modes and abort semantics

Every check that can fail produces a structured `AbortReport`:
```
struct AbortReport {
    AbortReason reason;       // one of MAC_FAIL, SACRIFICE_FAIL, DLEQ_FAIL,
                              //          NIZK_SHUFFLE_FAIL, BIT_PROOF_FAIL,
                              //          RECIP_INVARIANT_FAIL,
                              //          DP_COMMIT_MISMATCH, OLE_INVARIANT_FAIL
    AbortContext ctx;         // protocol phase, party, cell key
    uint64_t timestamp_ns;
    prev_link, this_link      // SHA-256 hash chain
};
```

- **No partial release.** If any check fails before Phase 12, session
  aborts before any value is opened.
- **Audit-chained.** Every abort emits an entry chained into
  `MpsvsAuditPersist`.
- **CT compares.** All security-critical comparisons (peer PK, commit
  hashes, `σ_1 + σ_2 = 0`) use `sodium_memcmp` (constant-time).

Recovery:
- MAC failure → hard abort; session contaminated.
- OPRF DLEQ failure → hard abort; may indicate compromised `S_i`.
- BG shuffle NIZK failure → hard abort; indicates malicious `composedShuffle`.
- DP commit mismatch → hard abort; malicious `S_i` tried to bias release.
- `RestartSession` (bin overflow) → soft; caller re-runs with fresh nonce.

---

## 10. Change control and deployment

**Config changes** — operator edits `mpsvs.conf`; `configHash` recomputes;
next session logs `CONFIG_LOAD` event before any protocol step; auditor
verifies `H(canonical(published_config)) = chain_entry.configHash`.

**Crypto params** — same flow for `paramsHash`; requires crypto-team + regulator sign-off.

**Software** — build-time git commit hash into `Attestation.software_hash`;
GT verifies against approved build hashes.

**Key rotation** — annual or on personnel change; `KEY_ROTATION` audit
event; old key retained only for historical audit verification.

**Regulator override** — signed Φ update with
`max_concurrent_sessions = 0` freezes new sessions; live sessions
complete normally.

---

## 12. Implementation Status (Rev 7.1)

Explicit ledger of what is **implemented and tested** vs what is
**specified but deferred**. This section is authoritative on scope
— the algorithms and theorems above describe the target design;
this table describes what actually runs.

### 12.1 Implemented and tested

| Component | Module | Test | Status |
|---|---|---|---|
| SPDZ2k open + MAC check (Alg 12) | `MpsvsAuthShare128::openWithMacCheckShared128` | `test_mpsvs_spdz2k` C2 | ✅ `k=64, s=64` (see 12.3) |
| SPDZ2k batch Ω-check (Alg 13) | `batchOpenWithMacCheckShared128` | `test_mpsvs_spdz2k` C8–C9 | ✅ Fiat-Shamir challenges over full-ring share transcript |
| SPDZ2k Beaver mult (Alg 14) | `authSecureMultiplyShared128` | `test_mpsvs_spdz2k` C5–C6 | ✅ Sharewise α_i·d·e in full ring |
| SPDZ2k sacrifice (Alg 15) | `sacrificeCheckTripleShared128` | `test_mpsvs_spdz2k` C7 | ✅ Full-ring r-challenge |
| Classical-SPDZ gap catch | — | `test_mpsvs_spdz2k` C3: 100/100 catch on δ=2⁶³ | ✅ Empirically confirms SPDZ2k catches what classical SPDZ would miss |
| DP noisy-threshold release (Alg 30) | `MpsvsDpProd::noisyThresholdReleaseProd` | `test_mpsvs_dp_noisy_threshold` C1–C4 | ✅ Per-metric Δ + per-ρ + noised ñ |
| Stability-based gate | Same | C3 (neighbour comparability) | ✅ Bounded ε on straddling neighbours |
| BG shuffle NIZK (Alg 5–6) | `MpShuffleNizkBg::shuffleVerifyBg` | `test_shuffle_nizk_bg`, `test_mpsvs_shuffle_nizk` | ✅ Sound-with-reveal; confidentiality caveat in §4.3 |
| CP OR bit proof (Alg 7–9) | `MpsvsBitProof::verifyBit` | `test_mpsvs_bit_proof` | ✅ With `ctx` binding |
| Bias-frozen DKG (Alg 10) | `MpsvsOprf::dkgS1/S2Finalize` | `test_mpsvs_oprf` | ✅ |
| Threshold-DH OPRF (Alg 11) | `MpsvsOprf::deriveEntityKey` | `test_mpsvs_oprf` | ✅ |
| Domain-sep prefix rename | `MpShuffleNizkBg.cpp` | `test_shuffle_nizk_bg` | ✅ `mpsvs.shuffleBg.*.v2` |
| BucketIndex wire code (Alg 24) | `MpsvsRatioBucketWire.cpp` | (via `test_mpsvs_e2e_wire`) | ✅ Bit-position OR reduction — oblivious |

### 12.2 Specified but deferred (target design; not yet built)

| Component | Deferred item | Why | Impact |
|---|---|---|---|
| **SPDZ2k `s = 80`** | Bignum retrofit for `k+s = 144` shares | `__int128` is native GCC/Clang; `k+s > 128` needs `boost::multiprecision` or manual limb arithmetic | Current impl gives session-level `2⁻²⁴` at 2⁴⁰ opens; target is `2⁻⁴⁰` |
| **SPDZ2k pipeline integration** | Migrate `MpsvsInclusionWire` / `MpsvsSectorAggWire` / etc from `AuthSharedU64` to `AuthSharedU128` | Cascades through ~15 files, ~600 LOC | The `MpsvsAuthShare128` API is validated but not the deployed path — `MpsvsInclusion` still uses 64-bit `AuthSharedU64` |
| **OLE-based Beaver triples for SPDZ2k** | `SilentOtTriple` runs over `oc::block` (128-bit) but MPSVS's OLE wrapper (`MpOleTriple`) targets `AuthSharedU64`. Would need `oleGenerateTriples128` | `test_mpsvs_spdz2k` uses `generateAuthBeaverTriple128` which reconstructs α — test-only | Adversary class A2 not yet met via OLE preprocessing (trusted-dealer test setup) |
| **DP pipeline integration** | Rewire `MpsvsSectorAggWire` release path to call `noisyThresholdReleaseProd` instead of `addJointNoiseImpl` + `applyKAnonGate` | Straightforward migration but requires callers to plumb `DpMetricParams` per metric | Deployed pipeline still uses deprecated DP path with reveal-and-reshare A2B + gate-on-true-count. Regression tests exercise both paths independently; the deployed default fails Theorem 7.5 |
| **A2B conversion for k-anon** | Replace `MpsvsKAnonGate::arithToBit` reveal-and-reshare with Toft prefix-tree adder | ~200 LOC of bit-level adder logic | Even ignoring the DP hole, `applyKAnonGate` leaks `n_valid` in plaintext to both S1 and S2 before any gate runs |
| **`k=48, s=80` alternative** | Reduce semantic-value width to 48 bits to keep `k+s ≤ 128` while hitting `s = 80` | Cascades through every arithmetic op that assumes 64-bit values | Not adopted; interim retrofit chose `s = 64` to preserve 64-bit interface |
| **Fuzzing harness** | libFuzzer over `parseConfigText`, `decryptBody`, `shuffleVerifyBg`, `RowTag::key` | Not built | Coverage gap on parse/decode paths |
| **Formal verification** | Coq/Lean proofs for the theorems in §7 | Not built | All theorems currently proved by hand + regression tests |

### 12.3 Concrete implemented security bounds (honest)

Under the currently-deployed (`k = 64, s = 64`) SPDZ2k configuration:

| Property | Implemented bound | Spec target | Gap |
|---|---|---|---|
| SPDZ2k per-open detection | `2⁻⁶⁴` | `2⁻⁸⁰` | `2⁻¹⁶` (bignum retrofit) |
| SPDZ2k session-level (`2⁴⁰` ops) | `2⁻²⁴` | `2⁻⁴⁰` | `2⁻¹⁶` (bignum retrofit) |
| DP release for `noisyThresholdReleaseProd` callers | `(ρ_th + ρ_hist + ρ_num + ρ_den)`-zCDP | Same | ✅ Met |
| DP release for legacy `applyKAnonGate` callers | Infinite ε on some neighbours (a), unbounded on others (b) | zCDP | ❌ Fails (deprecated path) |
| BG shuffle soundness | `2⁻¹⁶⁰` for `n = 2¹²`, `q_H = 2⁴⁰` | Same | ✅ Met |
| BG shuffle confidentiality against GT | Analytical — GT does not verify | Same | ✅ Met by construction (GT-verify not exposed) |
| BG shuffle confidentiality against S1/S2 verify | Reveals data both already jointly hold | Same | ✅ Met per §4.3 analysis |
| CP OR bit proof soundness | `2⁻⁶⁴` at `q_H = 2⁶⁴` | Same | ✅ Met |
| OPRF pseudorandomness | CDH-hard on Ristretto255 | Same | ✅ Met |
| DKG bias-freeness | Under one-honest-party + SHA-256 as RO | Same | ✅ Met |

### 12.4 Suitability by adversary class

| Adversary class | Current build | Post SPDZ2k s=80 + DP integration |
|---|---|---|
| A1 (semi-honest party) | ✅ Fully defended | ✅ |
| A2 (fully-malicious S1 vs S2) | ⚠️ Partial — SPDZ2k primitive works standalone (`test_mpsvs_spdz2k`) but pipeline still uses `AuthSharedU64`. `2⁻²⁴` session bound even for callers of the new API | ✅ (after retrofit) |
| A3 (client-side DP neighbour queries) | ⚠️ Only for callers of `noisyThresholdReleaseProd`; deployed pipeline still uses deprecated path | ✅ (after wire migration) |
| A4 (S1 + client coalition) | Partial — shares still bind other clients | Same |
| A5 (passive network) | ✅ | ✅ |
| A6 (active MITM) | ✅ | ✅ |

**Bottom line.** As of Rev 7.1, the SPDZ2k retrofit and DP
noisy-threshold release exist as **validated primitives** with
regression tests, but the pipeline **wiring** to make them the
default is a further step. New callers that need the malicious-secure
or DP-sound guarantees must invoke the new APIs directly
(`AuthSharedU128` / `noisyThresholdReleaseProd`). Legacy callers get
the legacy behaviour.

---

### Appendix — Cross-reference to modules

| Section | Module(s) |
|---|---|
| §4.1 Schnorr | `MpsvsOprf::schnorrProve/Verify` |
| §4.2 DLEQ | `MpsvsOprf::dleqProve/Verify` |
| §4.3 BG shuffle NIZK | `MpShuffleNizkBg`, `MpsvsShuffleWire` |
| §4.4 Bit proof | `MpsvsBitProof` |
| §4.5 OPRF DKG + query | `MpsvsOprf::dkgS1/S2Finalize`, `deriveEntityKey`, `RowTag::bin/key` |
| §4.6 SPDZ (plaintext-α) | `MpsvsAuthShare::openWithMacCheck`, `authSecureMultiply`, `sacrificeCheckTriple`, `batchOpenWithMacCheck` |
| §4.6 SPDZ (shared-α, legacy 64-bit) | `MpsvsAuthShare::openWithMacCheckShared`, `authSecureMultiplyShared`, `sacrificeCheckTripleShared`, `batchOpenWithMacCheckShared` |
| §4.6 SPDZ2k (Rev 7.1 retrofit, `k=64, s=64`) | `MpsvsAuthShare128::openWithMacCheckShared128`, `authSecureMultiplyShared128`, `sacrificeCheckTripleShared128`, `batchOpenWithMacCheckShared128` — validated by `test_mpsvs_spdz2k` |
| §4.7 OLE Beaver | `MpOleAlpha`, `MpOleTriple` |
| §4.8 DP + zCDP | `MpsvsDp`, `MpsvsDpProd`, `MpsvsDpWire` |
| §5.1 Bootstrap | `MpsvsSecureChannel`, `MpsvsKeyStore`, `MpsvsTopology` |
| §5.2 Local prep | `MpsvsLocalPrep` |
| §5.4 F_PSA | `MpsvsAlignment`, `MpsvsAlignmentWire`, `MpsvsCoverFirms` |
| §5.6 Inclusion | `MpsvsInclusion`, `MpsvsInclusionWire` |
| §5.7 Bucket + Goldschmidt | `MpsvsRatioBucket`, `MpsvsGoldschmidtWire`, `MpsvsReciprocalVerify` |
| §5.8 Rank | `MpsvsRank`, `MpsvsRankWire` |
| §5.9 Composite | `MpsvsComposite`, `MpsvsCompositeWire` |
| §5.10 Percentiles | `MpsvsPercentiles`, `MpsvsPercentilesWire` |
| §5.11 Sector aggregation | `MpsvsSectorAgg`, `MpsvsSectorAggWire` |
| §5.12 DP release (legacy — DP holes documented in §12) | `MpsvsDpProd::addJointNoiseImpl`, `MpsvsKAnonGate::applyKAnonGate` |
| §5.12 DP release (Rev 7.1 — noisy-threshold) | `MpsvsDpProd::noisyThresholdReleaseProd` — validated by `test_mpsvs_dp_noisy_threshold` |
| §5.13 Audit seal | `MpsvsAudit`, `MpsvsAuditPersist`, `MpsvsMetrics` |
| §4 Config + crypto params | `MpsvsConfig`, `MpsvsCryptoParams` |
| §4 Const-time helpers | `MpsvsConstTime` |
| §4 Prod hygiene | `MpsvsProdHygiene` |
