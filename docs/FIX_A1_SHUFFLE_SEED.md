# Fix A1 — SP can no longer reconstruct the cascade permutation

## The break

`docs/PRIVACY_AUDIT_R37.md` claims the OSN cascade hides the input→output
mapping so that no single party (including the SP) learns the composed
permutation π. The implementation did not achieve this.

Each round's Benes routing seed was:

```cpp
oc::block seed = deriveRoundSeed(spKey_k, sessionId, k);
```

`deriveRoundSeed` is a deterministic KDF of the **SP↔sender_k session key**.
The SP holds `spKey_k` for *every* sender k (it must, to run AEAD with each),
so the SP recomputes every round's `dest_k`, composes
π = dest_{N-2} ∘ … ∘ dest_0, and — since it also holds the final output table —
inverts π to link every shuffled output row back to its original per-sender
input position. The oblivious shuffle was transparent to the one adversary it
exists to stop.

The structural cause: each round used **two** OSN calls, and on the R-side
(call B) the SP acted as the OSN *sender* (permutation holder), which forced it
to know `dest_k`.

## The fix

Each round now uses a **single** OSN call in which sender k is the sole
permutation holder:

1. Sender k picks a **fresh random routing seed locally** (`randombytes_buf`)
   and never sends it to the SP.
2. One OSN call: the SP is the OSN *receiver* providing its M-share; sender k is
   the OSN *sender*. The SP therefore never holds `dest_k`.
3. Sender k applies the **same** `dest_k` to its own R-share **locally**, via the
   new `OSNSender::permuteBlocks`, replacing the R-side OSN call that leaked the
   permutation.

### Why the output is unchanged (correctness)

Let π = dest_k and let (M, R) be the SP/sender shares before the round.

* Old round: `M' = m_sender ⊕ r_receiver`, `R' = m_receiver ⊕ r_sender`, with
  `m_sender ⊕ m_receiver = π(M)` and `r_sender ⊕ r_receiver = π(R)`.
  So `M' ⊕ R' = π(M) ⊕ π(R) = π(M ⊕ R)`.
* New round: `M' = m_sender`, `R' = m_receiver ⊕ π(R)`.
  So `M' ⊕ R' = (m_sender ⊕ m_receiver) ⊕ π(R) = π(M) ⊕ π(R) = π(M ⊕ R)`.

Identical. The reconstructed table is bit-for-bit the same as before; the only
change is that the SP no longer knows π. If `run_mpsa_smoke.sh` passed before,
it passes after.

### Why `permuteBlocks` matches the OSN direction (by construction)

`permuteBlocks` calls `Benes::gen_benes_eval` (new block-valued overload) on the
**same** `OSNSender` object, hence the same `switched[]`/`dest` that `run_osn`
used. `gen_benes_eval` is `gen_benes_masked_evaluate` with the OT-mask XORs
removed, so it applies the identical routing. This is important because the
absolute direction the Benes network applies is not obvious from the source
(the repo's own `test_osn_semantics.cpp` probes four candidate directions) —
mirroring the same routing sidesteps the question entirely.

## Files

- `volePSI/osn/benes.{h,cpp}` — define the declared-but-unimplemented block
  `gen_benes_eval` (plaintext block permutation).
- `volePSI/osn/OSNSender.{h,cpp}` — `permuteBlocks(std::vector<oc::block>&)`.
- `volePSI/MpShuffleDriver.cpp` — round restructure; `deriveRoundSeed` deleted;
  sender-local random seed; SP is receiver-only.
- `tests/unit/test_shuffle_seed_privacy.cpp` — offline regression: `permuteBlocks`
  is a bijection, deterministic in the local seed, and varies with the secret
  seed (so no SP-held value determines it).
- `.github/workflows/ci.yml` — run the whole unit-test suite (was 2 of 24).

## Validation (requires a Linux build — not run on the author's Windows box)

```bash
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_BUILD_TESTS=ON
./out/build/linux/tests/unit/test_shuffle_seed_privacy   # offline, must PASS
./tests/run_mpsa_smoke.sh                                # end-to-end join still recovered
```

## Not covered by this fix (tracked separately)

- **C2/C3 — SP picks the MPSI hash key / keeps per-sender bitvectors.** The SP
  still recovers IDs via dictionary attack and learns positional membership.
  Needs the OPRF/VOLE-PSI port (`RsMpsiVole`). This fix removes the permutation
  leak but the join is not fully SP-private until C2/C3 land.
  - **Partial mitigation now landed:** the T15 salt (`-salt-mpsi`) is now
    default-on; use `-no-salt-mpsi` to disable (benchmarks / interop only).
    SP can no longer dictionary-attack the AES-hashed MPSI lists. Per-sender
    positional bitvec leak remains until the RsMpsiVole port.
- **C4 — OSN input masks + OT PRNGs used hardcoded constant seeds** — CLOSED
  by `docs/FIX_C4_OSN_SEEDS.md`. All six `_mm_set_epi32(...)` sites in
  `volePSI/osn/{OSNSender,OSNReceiver}.cpp` now seed from `sysRandomSeed()`.
  Verified by `tests/unit/test_osn_seed_freshness` +
  `tests/unit/test_osn_semantics` + `tests/run_mpsa_smoke.sh`.
