# Shuffle NIZK — design and current status (R27b → sound-with-reveal)

> **Status update (post-MPSVS Rev 7 audit cycle):** the R27b residual
> soundness gap described below has been **closed** in
> `MpShuffleNizkBg.{h,cpp}` by having the verifier independently
> recompute both polynomial products from prover-revealed messages
> after binding-check each opening (`pedersenCommit(m_i, r_i) == c_i`).
> The construction is now unconditionally sound (Schwartz-Zippel over
> ~2^252-element field) but no longer zero-knowledge over the messages
> — an acceptable trade for MPSVS Phase 4 where bin contents are
> public post-alignment. Full hiding still requires the recursive
> Bayer-Groth §5 partial-product argument (out of scope for this
> release). See the `MpShuffleNizkBg.h` header comment and the
> `test_shuffle_nizk_bg` binary (test `bg_sum_preserving_swap_now_caught`)
> for the closed-gap regression test.
>
> The historical R27 design + gap analysis below is preserved for
> context.

---

# Historical: Shuffle NIZK — design, prototype, and gap to full Bayer-Groth (R27)

## Goal

Publicly verifiable proof that a list of commitments `C' = (c'_1, ...,
c'_n)` is a re-randomized permutation of another list `C = (c_1, ...,
c_n)` — i.e., there exists a permutation π and fresh openings (r'_i)
such that `c'_i = pedersenCommit(m_{π(i)}, r'_i)`. Verifier learns
nothing about π.

The NIZK gives an EXTERNAL AUDITOR (regulator, SP-as-verifier, any
party watching the protocol transcript) a cryptographic guarantee that
the shuffle was honest, complementary to the MAC cascade (R25) and the
MPC join (R34) which give verifiability only to participants.

## Building blocks (delivered)

| Module | What it provides |
|---|---|
| `MpRistretto.{h,cpp}` | Thin wrapper over libsodium's Ristretto255 group: scalars + points + arithmetic + hash-to-curve + hash-to-scalar |
| `MpPedersen.{h,cpp}` | Pedersen commitment scheme: `c = g^m · h^r`. Perfect hiding, computational binding under DLog. Homomorphic addition + scalar-mul lifting |
| `MpShuffleNizk.{h,cpp}` | Bayer-Groth-inspired NIZK with Fiat-Shamir |

## What the prototype proves cryptographically

1. **Original-side weighted commitment equality.** Verifier checks
   `Π c_i^{x^i} = pedersenCommit(combinedMessage, combinedOpeningOrig)`
   where `x` is the Fiat-Shamir challenge derived from both commitment
   vectors. This binds the prover's claimed `combinedMessage` to the
   actual `Σ x^i · m_i` of the original side. Sound under DLog.

2. **Sum-of-commitments preservation** (implicit; checked by external
   sum check in tests). If `Σ m_i ≠ Σ m'_i`, then
   `sumOf(C) ≠ sumOf(C')` as commitments and an opening attack would
   require finding `(M, r)` with `commit(0, r) = sumShuf - sumOrig` for
   non-zero `M` — DLog-hard.

3. **Completeness on honest input.** `shuffleVerify` accepts the
   `shuffleProof` produced by `shuffleProve` for any valid permutation
   π and fresh openings.

## What the prototype does NOT prove (the soundness gap)

A malicious prover who:
- Picks any messages `(m'_i)` that form the SAME MULTISET as `(m_i)`
- Permutes them with ANY permutation π' (which need not match the
  permutation actually applied to the underlying values)

… can still produce a `shuffleProof` that this prototype's
`shuffleVerify` accepts. The prototype's verifier only does the
ORIGINAL-side weighted commitment check + the sum-preservation
implicitly; it does NOT have a way to bind the prover to a SPECIFIC π
because there is no commitment to π in the prototype.

The full Bayer-Groth construction closes this gap by:

1. **Polynomial commitment to π**: prover commits to the permutation
   matrix using a structured commitment (e.g., based on bilinear pairings,
   or recursive Pedersen vectors).
2. **Multiplicative shuffle argument**: verifier sends second challenge `y`;
   prover proves `Π (x - m_i + y) = Π (x - m'_i + y)` as scalar
   equality (Schwartz-Zippel on the multiset evaluation polynomial)
   AND proves that the polynomial commitment to π is consistent with the
   weighted-sum on C'.
3. **Recursive argument**: the proof size is O(√n) or O(log n) via
   recursive Pedersen vector commitments (Bulletproofs-style).

Implementing the full Bayer-Groth construction is realistically a
2-3 week dedicated effort. The prototype's value: validates the
Pedersen + Fiat-Shamir scaffolding, the Ristretto255 wrapper, and the
honest-prover correctness path. The recursive argument can be added
as a self-contained extension.

## What the prototype DOES catch

| Attack | Caught? | How |
|---|---|---|
| Naive message tampering: prover swaps one `m'_i` for a value NOT in the original multiset | YES (via external sum-check) | `sumOf(C') ≠ sumOf(C)` is detected if the verifier additionally runs the sum-of-commitments equality test |
| Wrong opening: prover claims an `r'_i` that doesn't open `c'_i` | YES (implicitly) | The prover cannot produce a valid `combinedOpeningShuf` without knowing the actual openings |
| Permutation mismatch: prover claims π' but applied π'' | NO | This is the soundness gap |
| Network attacker tampers with the proof artifact | YES | Fiat-Shamir challenge re-computation catches transcript tampering |

## Integration story

Once the soundness gap is closed (full Bayer-Groth, R27b), the NIZK
plugs into the existing cascade:

- After Phase 7 cascade shuffle (`MpShuffleDriver`), each sender holds
  commitments to its initial m_i (Pedersen-committed during Phase 0)
  AND commitments to the final shuffled output. The cascade APPENDS a
  shuffle proof per round, signed by the round's active sender.
- An external auditor can replay the transcript, recompute the
  Fiat-Shamir challenges, and verify the proofs without participating
  in the protocol.
- Combined with the existing T11 signed transcript (`MpTranscript`),
  this gives PUBLICLY VERIFIABLE END-TO-END CORRECTNESS.

## What this R27 deliverable provides

- `volePSI/MpRistretto.{h,cpp}` — group operations
- `volePSI/MpPedersen.{h,cpp}` — Pedersen commitment scheme
- `volePSI/MpShuffleNizk.{h,cpp}` — Bayer-Groth-inspired prototype proof
- `tests/unit/test_shuffle_nizk.cpp` — 10/10 tests, including the
  explicit "soundness gap documented" test that names the gap
- This design document

## Cost (informal)

For n elements:
- Prover: O(n) point operations + O(n) scalar operations + 1 hash
- Verifier: O(n) point operations (for the Π c_i^{x^i} computation) + 1 hash
- Proof size: 4 scalars (~128 bytes) — constant in n

This is competitive with the full Bayer-Groth construction in
asymptotic terms but lacks the full soundness.

## Deferred (R27b)

- Polynomial commitment to permutation
- Multiplicative shuffle argument (Schwartz-Zippel on
  Π (x - m_i + y))
- Recursive vector commitment for O(log n) proof size
- Integration with `MpShuffleDriver` cascade transcript

## References

- Bayer, Groth. "Efficient Zero-Knowledge Argument for Correctness of a
  Shuffle." EUROCRYPT 2012.
- Neff. "Verifiable Mixing (Shuffling) of ElGamal Pairs." Apr 2001
  draft. (Alternate construction, also relies on polynomial-equality.)
- Bünz, Bootle, Boneh, Poelstra, Wuille, Maxwell. "Bulletproofs:
  Short Proofs for Confidential Transactions and More." IEEE S&P 2018.
  (Recursive Pedersen vector commitments — the technique for O(log n)
  proof size.)
- Furukawa, Sako. "An Efficient Scheme for Proving a Shuffle." CRYPTO
  2001. (Pairing-based alternative.)
