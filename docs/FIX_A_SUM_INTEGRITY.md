# Stage A-sum — per-column shuffle-integrity check

## What it adds

Malicious-integrity protection layered around the semi-honest OSN shuffle
cascade. Sender commits to `Σ hashToScalar(payload_row)` per column via
Pedersen at setup; SP verifies both the commit and the post-cascade column
sum before writing the output. Any tampering that changes a column's sum is
detected; SP fails closed and refuses to write the CSV.

## Threat model

Adversary: **malicious sender** other than the row's originator (semi-honest
model + row-integrity extension). SP is still trusted only to be
semi-honest. Detects:

- **Drop-row** — sender in cascade omits a row from its round's OSN output.
- **Substitute-row** — sender replaces a row's blocks with different
  content.
- **Arithmetic corruption** — bit-flip in a payload block during the OSN
  round, whether adversarial or accidental.

Does NOT detect:

- **Swap-within-column preserving sum** — permutation of two rows within a
  single column leaves the sum unchanged AND corresponds to a valid
  permutation, so it is *indistinguishable* from an honest cascade
  permutation. Fundamentally not catchable by any per-column test.
- **Cross-column tampering** — adversary applies dest_k correctly to some
  columns but swaps within others, producing "mixed provenance" rows that
  don't correspond to any input row. Each column's multiset is preserved
  (so A-sum passes) but output rows are corrupted. **Closed by A-mset-row**;
  see `docs/FIX_A_MSET_ROW_INTEGRITY.md`.
- **Round-peel collusion** (SP + 1 sender) — intrinsic to any N-1-round
  pairwise cascade; only genuine N-party shuffles (e.g. eprint 2024/1936)
  fix this. Stage D territory.

## Protocol

1. **Setup (each sender, once):**
   1. Compute `claimedSum_w = Σ_j hashToScalar(payload_j_w.bytes)` for each
      of the sender's W payload columns.
   2. Pick fresh Pedersen opening `r_w = R255Scalar::random()`.
   3. Compute `commit_w = pedersenCommit(claimedSum_w, r_w)`.
   4. Send `{commit_w}_w` (W × 32 B) under existing spKey AEAD to SP.
      This happens **before** the sender ships `m_i` (the masked payload).
2. **Cascade:** unchanged; runs the existing OSN N-1-round cascade.
3. **Reveal (each sender):** ships `{(claimedSum_w, r_w)}_w` (2·W×32 B)
   under spKey AEAD after `MpShuffleDriver::runSender` returns.
4. **Verify (SP):** for each sender i, each column w:
   - `pedersenVerify(commit_iw, claimedSum_iw, r_iw)` — commit binding.
   - `Σ_j hashToScalar(shuffled_iw[j]) == claimedSum_iw` — cascade
     preserved the multiset sum.
   Any failure → `throw std::runtime_error` → CSV is never written.

## Why it works

The cascade permutes rows within each of the N·W columns; permutations
preserve multisets, so column sums are invariant. A malicious sender that
drops, substitutes, or corrupts a row alters the column sum with
overwhelming probability. The commit binds each sender to its declared sum
**before** SP sees any masked data (`m_i`), so a malicious sender cannot
observe SP behavior and adjust its commit late. Pedersen binding under
Ristretto255 DLog holds computationally.

## Wire and CPU cost

Per sender per session:

- Extra wire: `W × 32 + 2 × W × 32` = **96 × W bytes** plaintext (plus
  ~40 B AEAD overhead per message × 2 messages). For W=1, ~200 B total.
  For W=256 (cap), ~24.6 KB total. Negligible compared to the cascade.
- Extra CPU: 2·W Pedersen commits per sender (setup); N·W `pedersenVerify`
  + N·W column-sum-of-hashToScalar loops per SP verify (reveal). At W=1 and
  N=3 on a modern laptop: sub-millisecond.

## DoS defense

Received length-prefixed messages are capped:
- Commit envelope: 64 KB (~7.8× legitimate max at W=256).
- Opening envelope: 128 KB (~7.8× legitimate max at W=256).

Larger prefixes → immediate `throw`, no allocation. Existing `m_i` recv
retains its pre-existing unbounded pattern (legitimate m_i can be many MB
at high C·W); that's tracked as a separate hardening.

## Opt-out

`-no-integrity-check` on **both** SP and every sender disables the check
(for benchmarks / older-peer interop). Default is ON. Asymmetric use
(some parties enabled, some not) will hang on the mismatched send/recv;
this is intended.

## Interaction with prior fixes

| Prior | What it did | A-sum interaction |
|---|---|---|
| A1 (per-round seed) | SP cannot reconstruct π | Independent; A-sum runs orthogonally |
| C4 (OSN PRNG seeds) | Sender cannot read SP's M-share off the wire | Independent |
| T15 salt (default on) | Blocks SP dictionary attack on MPSI IDs | Independent |
| A-sum (this) | Malicious sender cannot corrupt shuffled payload silently | New malicious-integrity layer |

## Files

- `volePSI/MpsaShuffleIntegrity.{h,cpp}` — commit/serialize/verify helpers
  (~215 LOC).
- `volePSI/CMakeLists.txt` — registers the module in libvolePSI.
- `volePSI/MpsaDriver.cpp` — wiring: sender commits before m_i, opens after
  reveal; SP verifies before writeCsv; `-no-integrity-check` CLI flag.
- `tests/unit/test_shuffle_integrity_sum.cpp` — 8 offline scenarios
  (honest, drop, substitute, sum-preserving swap [documented gap], replay
  opening, ser/deser round-trip x2, W=0 edge case). All pass.

## Validation

```bash
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_BUILD_TESTS=ON
./out/build/linux/tests/unit/test_shuffle_integrity_sum   # offline, must PASS
./tests/run_mpsa_smoke.sh                                 # N=3, W=1
./tests/run_mpsa_wide_smoke.sh                            # N=3, W=4
# Verbose to see A-sum log lines:
frontend -mpsa -N 3 -r 0 ... -v 2>&1 | grep A-sum
frontend -mpsa -N 3 -r 1 -i 0 ... -v 2>&1 | grep A-sum
```

## Follow-ups (not in scope)

- **Stage A-mset**: cooperative multiset NIZK via Bayer-Groth polynomial
  evaluation, using the existing `MpShuffleNizkBg` scaffolding. Closes the
  sum-preserving-swap gap. ~3–4 person-weeks. See `docs/SHUFFLE_NIZK_DESIGN.md`.
- **Stage B (MPSO port)**: replace `RsMpsi3rdP` with `real-world-cryptography/MPSO`
  (eprint 2025/640) to close C2/C3 (SP still learns per-sender bitvec even
  with T15 salt).
- **Stage D**: replace the cascade entirely with an N-party native shuffle
  (Gao et al. eprint 2024/1936) to close the SP+1-sender round-peel.
- **`hashToScalar` allocation**: currently one `std::vector<uint8_t>` per
  block per row hashed. Adding a `hashToScalar(const uint8_t*, size_t)`
  overload to `MpRistretto.h` would eliminate the alloc.
