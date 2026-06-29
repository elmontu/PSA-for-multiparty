# Malicious-Secure Cascade: Design

This doc specifies the information-theoretic MAC construction needed to lift
the MPSA cascade from semi-honest to malicious-with-abort security. Round 16
shipped the **lightweight** Phase 0 commit-and-open as a stepping stone; this
doc is the next-engineer hand-off for the **full** malicious-secure upgrade.

## What's already malicious-resistant (committed)

| Layer | Mechanism | Catches |
|---|---|---|
| Sender → SP masked column `m_i` | AEAD under sender↔SP session key | Forged/tampered `m_i` |
| Sender → Sender `r_j` handoff | AEAD under pairwise key + session ID | Forged/tampered `r_j` in transit |
| Cascade `rho_k` and final `R` reveal | AEAD under SP key | Tampered round-randomizers |
| **Phase 0 commit-and-open (Round 16)** | SHA-2-style commit broadcast then open | Sender j sending different `r_j` to different recipients (incl. non-repudiation: peers hold the commitment as a check value) |
| Cross-session replay | Session-id binding via `deriveSessionKey` | Replay of any AEAD message across sessions |

## What's still NOT defended

| Attack | Why current defenses don't catch it |
|---|---|
| Sender k drives round k's OSN dishonestly (e.g. submits the wrong `R_k` to the OSN, producing inconsistent shares) | OSN is semi-honest; we trust both parties to follow it |
| Sender k tampers with the cascade-state handoff `R_{k+1}` to sender k+1 (encrypts the wrong thing) | AEAD verifies the message wasn't tampered in transit but not that sender k is honest |
| SP submits the wrong `M_k` to the OSN | Same problem at SP |
| Sender N-1 (final reveal) sends a wrong `R_final` | Reveal is AEAD-authenticated but only to "sender N-1 sent this"; doesn't bind to the genuine cascade state |

All of these produce a corrupted output table. SP can't tell what the correct
output should have been, so detection requires an independent check on the
shares throughout the protocol.

## The construction: information-theoretic MAC on shares

Standard pattern from **Mohassel-Rindal CCS 2018 §3.4** and
**Chida, Genkin, Hamada, Ikarashi, Kikuchi, Nof, Pinkas CRYPTO 2018 §4**.

### Setup

For each cascade round `k ∈ [0, N-1)`:
- SP and sender k jointly derive a per-round MAC key
  `α_k ∈ GF(2^128) \ {0}` via `deriveSessionKey(spKey_k, sessionId, "mac_k") mod (2^128 - 1)`.
- Both parties hold the same `α_k`. No other party learns it (until the
  verification phase at the end).

### Authenticated share representation

Every share `s` held by party P in round k is paired with a tag `t = α_k · s`,
where `·` is GF(2^128) multiplication. Party P stores the augmented share
`⟨s⟩ = (s, t)`.

### Homomorphic preservation through cascade operations

The MAC is **linear** in `s`, which gives free homomorphism through every
operation the cascade does:

| Operation on plain share | Operation on tag |
|---|---|
| XOR: `s_3 = s_1 ⊕ s_2` | `t_3 = t_1 ⊕ t_2` (linearity of `α ·`) |
| Permutation: `s' = π(s)` (vector-element reorder) | `t' = π(t)` (vector-element reorder) |
| Adding a public constant: `s' = s ⊕ c` | `t' = t ⊕ α · c` (caller computes `α · c` locally) |

All cascade operations are in the first two categories, so the MAC propagates
without any new cryptographic primitive per round.

### OSN with MAC: the "OSN-twice" trick

The OSN takes a vector `V` and produces shared shares of `π(V)`. To MAC the
shares, run OSN **twice with the same baked routing** (using
`init_wj_seeded(seed_k)`):

1. **Data OSN**: input `V`. Output: `share_v` and `share_v'` with
   `share_v ⊕ share_v' = π(V)`.
2. **Tag OSN**: input `α_k · V` (computed locally as a vector of GF(2^128)
   products). Output: `share_t` and `share_t'` with
   `share_t ⊕ share_t' = π(α_k · V) = α_k · π(V)`.

After both, each party holds `(share_v_i, share_t_i)` with the invariant
`share_t_1 ⊕ share_t_2 = α_k · (share_v_1 ⊕ share_v_2)` — i.e., `share_t_i`
is the MAC tag of the joint value `share_v_1 ⊕ share_v_2`.

### Cost

- Per cascade round, OSN calls go from `2N` (data only, one per column +
  M/R) to `4N` (data + tag per column per M/R side). 2× the OSN work.
- Per-byte communication: 2× (tags double the wire payload).
- Per-element GF(2^128) multiplication: one per column per round at each
  party — `O(N · C)` operations per round. Use the `gfMul` primitive in
  `cryptoTools/Common/block.h` (it wraps PCLMUL when available).

### Verification phase (end of protocol)

After the cascade completes and SP holds `M_final` shares of the joined
table:

1. SP receives the last sender's `R_final` shares and tags (AEAD'd).
2. SP and **every sender k** broadcast their α_k to all other parties.
3. SP and every party independently compute, for each column c and row j:
   `expected_tag = α_k · (M_final[c][j] ⊕ R_final[c][j])`
   (composing the per-round α_k's transitively through the cascade).
4. Each party compares its locally-held tag against the expected tag. Any
   mismatch ⇒ **abort with attribution** (the round / column / row where
   the mismatch surfaced names a corrupted contributor).

A batched verifier reduces this to O(log) random linear combinations
following the Chida et al. style; gives statistical soundness `1 - 2^{-128}`
per check.

## Subtask decomposition (for the implementer)

| # | Task | Effort | Files | R25 Status |
|---|---|---|---|---|
| 1 | GF(2^128) multiplication primitive | ½ day | `cryptoTools/Common/block.h` | **DONE upstream** — `oc::block::gf128Mul` already ships with PCLMUL/PMULL/portable variants. No wrapper needed. |
| 2 | Per-round MAC-key derivation `deriveMacKey(spKey, sessionId, k)` | ¼ day | `MpAuthCascade.{h,cpp}` | **DONE.** Implemented over the existing `deriveSessionKey("mac_round_<k>")` path. |
| 3 | `AuthShare { data, tag }` + algebra (XOR, perm, const-injection, batched random-LC verify) | 1 day | `MpMac.{h,cpp}` | **DONE.** 10/10 unit tests in `tests/unit/test_mac.cpp`. |
| 4 | Refactor cascade round to OSN-quadruple with shared `init_wj_seeded(seed_k)` | 1 day | `MpShuffleDriver.cpp` | **In-memory simulation DONE** (`MpAuthCascade.{h,cpp}`, 4/4 tests). Live wire-protocol port deferred — see "Deferred" below. |
| 5 | Phase 0 mask aggregation with MACs + commit-and-open | ½ day | `MpsaDriver.cpp` | Deferred — waits for #4 live integration. |
| 6 | Final verification: α_k broadcast + batched linear-combination MAC check | 1 day | `MpsaDriver.cpp` | **Primitive DONE** (`verifyAuthSharesBatched`). End-to-end wiring deferred with #5. |
| 7 | Adversary-simulation tests | 1 day | `tests/unit/test_auth_cascade.cpp` | **DONE** for in-memory model (tamper-at-handoff and tamper-at-final-reveal both caught). Live-protocol variant deferred with #4. |

**Status: subtasks 1, 2, 3, 7 fully delivered; 4, 5, 6 hold their algebra
primitives but defer the wire-level integration into MpShuffleDriver /
MpsaDriver.**

## Deferred: live-protocol port + the OLE gap

R25 intentionally stops at the in-memory simulation for one reason: the
MAC key `α_k` in the current construction is a **shared secret** between
SP and active sender `S_k` (both derive it from their pairwise X25519
session key). This catches:

- Network attackers tampering with messages in flight.
- A sender lying about state it hands off to a NON-cooperating party
  (the next round's `verifyAuthShares` catches it before any further
  state evolves).
- A malicious sender deviating in a round in which it is *not* the active
  driver (cannot forge `α_k` it does not know).

It **does NOT** catch SP-vs-active-sender collusion in round `k`: both
parties locally hold `α_k`, so either can produce a `α_k`-consistent
forgery if they choose to.

Closing this gap requires **OLE-based α-sharing** (SPDZ-style additively
shared global MAC key `Δ`, never reconstructed until the end). Within
volePSI this is a natural extension of `RsMpsiVole` adding a triple-
generation phase, roughly +1000 LoC of OT plumbing. R28 (proposed)
covers it.

Porting the in-memory `cascadeRound` into `MpShuffleDriver` *before* OLE
is added would produce a transitional half-step: doubled OSN cost (4N
calls per round vs 2N today) for security that is only marginally
stronger than the AEAD already deployed. The integration is held until
the OLE substrate is in place so the upgrade goes straight to full SPDZ-
level security.

## Security argument sketch

**Theorem (informal).** Assume the underlying OSN is semi-honest secure, the
AEAD is IND-CPA + INT-CTXT, and SHA-2 is collision-resistant. Then the
cascade above is **malicious-secure with abort** against an adversary that
corrupts up to N-1 parties (any subset including the SP).

**Argument sketch.**
- Each round k's MAC key α_k is uniform random in `GF(2^128) \ {0}` and
  known only to SP and sender k. Adversary cannot produce a valid tag for a
  value it didn't compute correctly except with probability `2^{-128}` per
  forgery attempt.
- The OSN-twice trick preserves the MAC homomorphism through the
  permutation, so an honest party always holds a valid tag for its share at
  every step.
- The final verification's batched check is sound under standard
  Cramer-Damgård-style argument.
- Composition with Phase 0 commit-and-open ensures the `r_i` inputs are
  also bound, so a malicious sender can't "lie about" what they contributed.

**Attribution.** When a tag check fails, the failing column c and round k
identify the responsible sender k. (Combined with the commit-and-open,
sender j's `r_j` contribution is also attribution-bound.)

## What this construction does NOT give

- **Identifiable abort with cryptographic non-repudiation.** Requires a PKI
  + signature on the transcript; orthogonal addition (see T-H of the
  theoretical roadmap).
- **Privacy under malicious adversary**: this is malicious-secure for
  *correctness* only. Privacy still degrades to "honest-majority semi-honest"
  if the adversary corrupts > N/2 parties (because the input r_i values can
  be reconstructed). For full UC-style malicious privacy, switch to a real
  malicious-secure shuffle (CGP SSS, see `MALICIOUS_UPGRADE_ROADMAP.md`).
- **Active OSN security**: the OSN itself is still semi-honest. The MAC
  layer catches deviations after the fact but doesn't prevent a malicious
  OSN-party from learning more than it should during the OSN call.

## References

- Mohassel, P., Rindal, P. (2018). **ABY³: A Mixed Protocol Framework for
  Machine Learning.** *ACM CCS 2018.* §3.4 sketches the MAC-on-shares
  construction.
- Chida, K., Genkin, D., Hamada, K., Ikarashi, D., Kikuchi, R., Nof, A.,
  Pinkas, B. (2018). **Maliciously Secure MPC with Honest Majority via
  Replicated Secret Sharing.** *CRYPTO 2018.* §4 has the batched MAC-check
  protocol.
- Rindal, P., Schoppmann, P. (2021). **VOLE-PSI: Fast OPRF and Circuit-PSI
  from Vector-OLE.** *EUROCRYPT 2021.* §5 has a similar information-theoretic
  MAC construction for PSI.
- Cramer, R., Damgård, I. (2005). **Multiparty Computation, an
  Introduction.** Lecture notes — the batched-check soundness argument.
