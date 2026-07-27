# Π_SECTORVULN Rev 7 — Formal Protocol Specification

> Self-contained cryptographic specification of MPSVS. Written to the
> level expected by CRYPTO / EUROCRYPT / CCS / S&P / USENIX Security
> — every primitive is defined as a game or ideal functionality, every
> algorithm is presented in numbered pseudocode with a formal I/O
> signature, every claim is stated as a Theorem or Lemma with an
> explicit advantage bound and a proof sketch, and every complexity
> claim (round / communication / computation) is quantified.
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

---

## 1. Notation

**Sets and rings.** `ℤ_{2^k}` — integers mod `2^k` with wrapping.
`𝔽_p` — the Curve25519 scalar field of order
`p = 2^252 + 27742317777372353535851937790883648493 ≈ 2^252.5`.
`𝔾` — the Ristretto255 group of prime order `p`, with generators
`g, h` of unknown discrete-log relation. `⟨·⟩` — group operation
(written additively).

**Sharing.** `⟦x⟧ = (x_1, x_2)` with `x_1 + x_2 ≡ x (mod 2^k)` — a
2-party additive sharing across `(S_1, S_2)`. `⟦x⟧_i` — party `i`'s
share. `Open(⟦x⟧) → x` — both parties broadcast their shares; sum.

**Authentication.** `α ∈ ℤ_{2^k}` — global SPDZ MAC key.
`⟦α⟧` — additive sharing of `α`. `⟦[x]⟧ := (⟦x⟧, ⟦α · x⟧)` —
authenticated share of `x` under the global MAC key `α`. In the
plaintext-α legacy path `α` is public to a designated verifier; in
the DPSZ shared-α path `α` remains `⟦α⟧` throughout.

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

For passphrase `π` sampled from distribution `𝒟`, `crypto_pwhash(π, s)`
with `OPSLIMIT_INTERACTIVE` costs `T ≥ 2⁴⁰ / bit(H_∞(𝒟))` to invert.

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

### Functionality F_SPDZ^{2-of-2}

```
─────────────────────────────────────────────────────────────────
F_SPDZ^{2-of-2}                                       [Ideal]
─────────────────────────────────────────────────────────────────
Setup:  sample α ← ${ℤ_{2^k}^*}; deliver ⟦α⟧ = (α_1, α_2).
Input(x):  accept x from a party; deliver ⟦[x]⟧ to both parties.
Add(⟦[x]⟧, ⟦[y]⟧): return ⟦[x + y]⟧ (local).
Mult(⟦[x]⟧, ⟦[y]⟧): return ⟦[xy]⟧ (consumes 1 Beaver triple).
Open(⟦[x]⟧): return x; abort if any share was tampered
             (except with probability 2^{-k}).
Corruption:  corrupted party learns ⟦α⟧_i and its own shares only.
─────────────────────────────────────────────────────────────────
```
Realised by Protocol Π_SPDZ (§5.5) under Assumptions 1, 3, 4, 7, 8.

### Functionality F_DP

```
─────────────────────────────────────────────────────────────────
F_DP                                                  [Ideal]
─────────────────────────────────────────────────────────────────
Params:  σ > 0, k ≥ 0, ρ, budget ρ_max.
Query(y):
    if Σ ρ_spent + ρ > ρ_max:  abort with "budget exhausted"
    if y.n_valid < k:           output ⊥ (k-anon suppression)
    else:
        η ← Gaussian(0, σ²)
        output max(0, y + η)     (R26 clamp)
    ρ_spent += ρ.
─────────────────────────────────────────────────────────────────
```

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

Sound-with-reveal variant reveals the messages inside the proof.
Full hiding-with-secrecy requires the full Bayer–Groth §5 recursive
partial-product argument (not implemented; see [`DESIGN.md`](DESIGN.md)).

**Algorithm 5** — `shuffleProveBg`
```
 1:  n ← |msg|
 2:  y ← hashToScalar("mpstar.shuffleBg.y.v1" ‖ tr(C, C'))       ▷ FS
 3:  x ← hashToScalar("mpstar.shuffleBg.x.v1" ‖ tr(C, C') ‖ LP(y))
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
 2:  y' ← hashToScalar("mpstar.shuffleBg.y.v1" ‖ tr(C, C'))
 3:  x' ← hashToScalar("mpstar.shuffleBg.x.v1" ‖ tr(C, C') ‖ LP(y'))
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
Adv^{sound}_BG_shuf(𝒫*, λ) ≤ n · q_H^2 / p  +  q_H · Adv^{dlog}_𝔾(ℬ, λ)
```
i.e. `≤ 2^{n log p^{-1}} · q_H² + q_H · negl(λ)` — negligible for any
`n ≤ 2^{100}` given `p ≈ 2^{252}`.

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
commitBit  : (b ∈ {0, 1}, r ∈ 𝔽_p)  →  C ∈ 𝔾              [enforce b ∈ {0,1}]
proveBit   : (b, r, C)              →  π_OR
verifyBit  : (π_OR, C)              →  {accept, reject}
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

### 4.6 SPDZ authenticated shares

Two variants: plaintext-α (semi-honest / single-verifier) and DPSZ
shared-α (fully-malicious under Assumption 8).

**Algorithm 12** — `Open^{sh-α}(⟦[x]⟧, ⟦α⟧)` (DPSZ, DPSZ '12 §3.3)
```
Preconditions: |⟦[x]⟧_shares| = 2 ∧ |⟦α⟧_shares| = 2.

Phase A (public reconstruct):
  1:  x_pub ← Open(⟦x⟧)                            ▷ both broadcast

Phase B (local σ commit — each party i ∈ {1, 2}):
  2:  σ_i     ← α_i · x_pub  −  m_i    mod 2^k     ▷ m_i = ⟦α · x⟧_i
  3:  salt_i  ← ${𝔽_{2^64}}
  4:  commit_i ← H("mpsvs.audit" ‖ LE64(party = i) ‖ LE64(σ_i) ‖ LE64(salt_i))

Phase C (commit exchange):
  5:  send commit_i to peer

Phase D (reveal AFTER both commits exchanged):
  6:  send (σ_i, salt_i)
  7:  each party verifies:
        H("mpsvs.audit" ‖ LE64(peer) ‖ LE64(σ_peer) ‖ LE64(salt_peer))
          =? commit_peer_received
        if ≠: abort

Phase E:
  8:  if (σ_1 + σ_2) mod 2^k ≠ 0:  abort
  9:  return x_pub
```

**Theorem 4.6.1 (Malicious soundness).** Under Assumption 4 (SHA-256 as
RO) and Assumption 7 (CSPRNG for σ_i, salt_i), the probability that
`Open^{sh-α}` returns a value `x' ≠ x` without aborting, over a
corrupted `S_i`'s choice of tampered `⟦[x]⟧_i`, is at most
`2^{-k} + q_H · 2^{-256}` per open.

**Proof sketch.** For `σ_1 + σ_2 = 0` to hold on tampered shares,
either (a) `α · x = m` numerically (implies no tamper, since α, x, m
are fixed by earlier moves) or (b) the corrupted party chose `σ_corr`
after seeing peer's `σ_hon` — but Phase C's commit binds `σ_corr`
before Phase D reveals `σ_hon`. Adversary must therefore either
break SHA-256 binding (Assumption 4) or guess `σ_hon` before commit
(prob `2^{-k}`). Union-bounding over `q_H` RO queries gives the
stated advantage.  ∎

**Algorithm 13** — `BatchOpen^{sh-α, Ω}(⟦[x_1]⟧, …, ⟦[x_n]⟧, ⟦α⟧)`
```
 1:  tr_hash ← H(‖_{j=1..n} ‖_{i=1,2} (LE64(⟦x_j⟧_i) ‖ LE64(⟦α·x_j⟧_i)))
 2:  for j ← 1 to n:
 3:      r_j ← LE64_prefix( H("mpsvs.omega.r" ‖ LE64(j) ‖ tr_hash) )
 4:      if r_j = 0: r_j ← 1
 5:  ⟦[y]⟧ ← Σ_j r_j · ⟦[x_j]⟧                          ▷ linear combination
 6:  return Open^{sh-α}(⟦[y]⟧, ⟦α⟧) ≠ ⊥ ? {x_j} : ⊥
```

The r_j vector is Fiat-Shamir-derived from the share transcript —
unpredictable to any adversary who has not yet committed shares.

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

**Algorithm 15** — `Sacrifice^{sh-α}(T, T', ⟦α⟧)` (Ω-check for triples)
```
 1:  r ← ${𝔽_{2^64}^*}
 2:  ρ ← Open^{sh-α}(r · ⟦u⟧ − ⟦u'⟧,                     ⟦α⟧)
 3:  σ ← Open^{sh-α}(    ⟦v⟧ − ⟦v'⟧,                     ⟦α⟧)
 4:  τ ← Open^{sh-α}(r · ⟦w⟧ − ⟦w'⟧ − σ ⟦u'⟧ − ρ ⟦v'⟧,  ⟦α⟧)
 5:  return (τ = ρ · σ) ? "T valid" : "abort"
```

**Theorem 4.6.3 (Sacrifice soundness).** For a malformed triple
`(u, v, w) with w ≠ uv`, `Sacrifice^{sh-α}` returns "abort" except
with probability `2^{-k}` over the choice of `r`.

**Proof sketch.** Substituting `w = uv + Δ` (with `Δ ≠ 0`):
```
τ = r(uv + Δ) − u'v' − σu' − ρv'
   = r · Δ + [ruv − u'v' − σu' − ρv']
   = r · Δ + ρ · σ     (Beaver identity on the honest triple T')
```
So `τ = ρσ` iff `r · Δ = 0`; since `Δ ≠ 0` and `r ← ${𝔽_{2^64}^*}`
uniformly, this holds with probability at most `2^{-k}`.  ∎

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
 1:  prev_key ← ⊥;  out ← []
 2:  for row r ∈ sorted_bin_b:
 3:      canonical ← (r.key ≠ prev_key)                 ▷ AuthEq
 4:      u.b_MAS ← u.b_MAS ∨ (r.source = MAS ∧ r.memb) ▷ AuthOR
 5:      u.b_DOS ← ...  ;  u.b_MOM ← ...
 6:      u.p_MAS ← r.payload if r.source = MAS else u.p_MAS  ▷ MUX
 7:      u.p_DOS ← ...  ;  u.p_MOM ← ...
 8:      u.canonical ← canonical
 9:      out ← out ‖ u
10:      prev_key ← r.key
```

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

**Algorithm 24** — `BucketIndex(x, edges)` — oblivious binary search
```
 1:  lo ← 0;  hi ← B                              ▷ B = |edges| = 128
 2:  while lo < hi:
 3:      mid ← ⌊(lo + hi) / 2⌋                    ▷ public
 4:      ⟦less⟧ ← AuthLT(⟦x⟧, edges[mid])          ▷ SPDZ bit
 5:      (lo, hi) ← AuthMux(⟦less⟧, (lo, mid), (mid + 1, hi))
 6:  for b ← 0 to B − 1:
 7:      one_hot[b] ← AuthEq(b, ⟦lo⟧)
 8:  return one_hot
```

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

**Algorithm 28** — `PercentileFromHist(H, q)` — quantile-inversion
```
 1:  target ← q · H.n_valid
 2:  cum ← 0
 3:  for b ← 0 to B − 1:
 4:      next ← cum + H.h[b]
 5:      if next ≥ target:
 6:          lo ← edges[b];  hi ← edges[b + 1]
 7:          frac ← (target − cum) / H.h[b]
 8:          return lo + frac · (hi − lo)
 9:      cum ← next
10:  return edges[B]
```

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

**Algorithm 30** — `ReleaseCell(s, p, m, ρ, k, ρ_max, budget)`
```
 1:  if budget.spent + ρ > ρ_max:  abort "budget exhausted"
 2:  budget.spent ← budget.spent + ρ
 3:  σ ← sqrt(Δ_2(m)² / (2ρ))
 4:  n_v ← Open^{sh-α}(hist[(s,p), m].n_valid, ⟦α⟧)
 5:  if n_v < k: return ⊥                                ▷ k-anon suppress
 6:  y_hist_b ← JointGaussianRelease(hist[(s,p), m].h[b], ρ, k)   ▷ Alg. 17
                for each bucket b
 7:  y_num   ← JointGaussianRelease(num[(s,p), m], ρ, k)
 8:  y_den   ← JointGaussianRelease(den[(s,p), m], ρ, k)
 9:  release[(s, p, m)] ← (y_hist_b, y_num, y_den, n_v)
10:  return release[(s, p, m)]
```

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
(F_AUTH, F_CT, F_OPRF, F_SPDZ, F_DP)-hybrid model under Assumptions
1, 3, 4, 7, 8, 9, with total statistical distance
```
Adv^{ind}_MPSVS(𝒜, λ)  ≤  σ_stat_bits^{-1} + q_total · negl(λ)
```
where `q_total` is the total number of protocol operations invoked.

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
    ≤  2^{-k}  +  q_H · 2^{-256}      per open (Theorem 4.6.1).
```
Composed over the `q_total ≤ 2^{40}` opens per session,
```
Pr[undetected tamper anywhere in a session]  ≤  2^{40} · (2^{-k} + q_H · 2^{-256})
                                             ≈  2^{-24}    for k = 64
```
which meets the σ_stat = 40 target with a factor-of-16 margin.

### Theorem 7.4 (Shuffle integrity — Goal I2)

For BG shuffle NIZK with input length `n`,
```
Pr[shuffleVerifyBg(π*, C, C') = accept  ∧  {m_i} ≠ {m'_i}]
    ≤  n · q_H^2 / p                                   (Theorem 4.3.1).
```
For `n = 2^{12}`, `p ≈ 2^{252}`, `q_H = 2^{40}`, this is `≤ 2^{-160}`.

### Theorem 7.5 (Differential privacy — Goal DP1)

Every release computed via Algorithm 30 satisfies ρ-zCDP with the ρ
recorded in the budget tracker (Fact 4.8.2 + 4.8.4).

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

### Appendix — Cross-reference to modules

| Section | Module(s) |
|---|---|
| §4.1 Schnorr | `MpsvsOprf::schnorrProve/Verify` |
| §4.2 DLEQ | `MpsvsOprf::dleqProve/Verify` |
| §4.3 BG shuffle NIZK | `MpShuffleNizkBg`, `MpsvsShuffleWire` |
| §4.4 Bit proof | `MpsvsBitProof` |
| §4.5 OPRF DKG + query | `MpsvsOprf::dkgS1/S2Finalize`, `deriveEntityKey`, `RowTag::bin/key` |
| §4.6 SPDZ (plaintext-α) | `MpsvsAuthShare::openWithMacCheck`, `authSecureMultiply`, `sacrificeCheckTriple`, `batchOpenWithMacCheck` |
| §4.6 SPDZ (shared-α) | `MpsvsAuthShare::openWithMacCheckShared`, `authSecureMultiplyShared`, `sacrificeCheckTripleShared`, `batchOpenWithMacCheckShared` |
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
| §5.12 DP release | `MpsvsDp`, `MpsvsDpProd`, `MpsvsKAnonGate` |
| §5.13 Audit seal | `MpsvsAudit`, `MpsvsAuditPersist`, `MpsvsMetrics` |
| §4 Config + crypto params | `MpsvsConfig`, `MpsvsCryptoParams` |
| §4 Const-time helpers | `MpsvsConstTime` |
| §4 Prod hygiene | `MpsvsProdHygiene` |
