# Stage A-mset-row — cross-column row integrity

## What it closes

The specific gap that A-sum (per-column sum check) accepted: **cross-column
tampering**. The MPSA cascade applies the SAME permutation to every one of
the N·W parallel columns per round. A malicious sender in round k could
apply dest_k correctly to some columns but a DIFFERENT permutation to
others. Result: output row j has some blocks from what should have been
input row π(j) and other blocks from an entirely different input row —
"mixed provenance" rows that don't correspond to any real input row.

A-sum's per-column check passes trivially here (each column's multiset is
preserved individually). But the join semantics are silently corrupted: SP
outputs a row `[sender_0_block_from_input_a, sender_0_block_from_input_b,
sender_1_block_from_input_c, ...]` that never existed as a coherent input.

## The fix

Each sender additionally commits to `Σ_j hashToScalar(concat(row_j.bytes))`.
The hash is over the CONCATENATION of the sender's W row-blocks at row j.
Cross-column tampering scrambles any output row's byte pattern → new row
hash → sum breaks → fail-close.

Sender commit cost: 1 extra 32-byte Pedersen commitment per session.
Sender open cost: 64 more bytes (claimedSum + opening).
Per-row CPU: one hashToScalar of 16*W bytes at commit and verify.

## Composition with A-sum

**Both run simultaneously by default (integrityCheckOn covers both).** They
verify different properties and cost about the same:

| Attack | Caught by A-sum | Caught by A-mset-row |
|---|---|---|
| Drop a row | ✓ (any column) | ✓ (row hash missing) |
| Substitute a block | ✓ (that column's sum changes) | ✓ (row hash changes) |
| Cross-column mixing (same input rows, mismatched columns) | ✗ | ✓ |
| Swap two entire rows within one column and its counterpart in others (i.e. valid permutation) | fundamentally uncatchable — the shuffle IS a permutation | fundamentally uncatchable |
| Corrupted routing that produces a valid permutation of the true rows | ✗ | ✗ (still a valid rearrangement) |

Only what's *not* a valid rearrangement of the true input rows is
detectable; both A-sum and A-mset-row hit that class.

## Wire protocol

Sender-side, immediately after the A-sum commit send:

```
u64  rowCommitLen
u8[] rowCommitCt        // AEAD(spKey, serializeRowCommit(w.commit))  ~= 48 B
```

Then after the A-sum opening send:

```
u64  rowOpeningLen
u8[] rowOpeningCt       // AEAD(spKey, serializeRowOpening(w.claimedSum, w.opening))  ~= 80 B
```

SP mirrors: recv commit before m_i, recv opening after cascade + before
CSV write. Length caps reused from A-sum (64 KB commit / 128 KB opening
envelopes — huge headroom vs. legitimate ~48 / 80 B).

## Threat-model update

| Property | Pre-A-sum | +A-sum | +A-mset-row |
|---|---|---|---|
| Drop/substitute detected | ✗ | ✓ | ✓ |
| Cross-column mixing detected | ✗ | ✗ | **✓** |
| Fail-close if verify fails | ✗ | ✓ | ✓ |

## Files

- `volePSI/MpsaShuffleIntegrity.{h,cpp}` — new `SenderRowWitness`,
  `makeSenderRowWitness`, `serializeRowCommit`/`Opening`,
  `verifySenderRowIntegrity` (all in namespace `volePSI::mpstar`).
- `volePSI/MpsaDriver.cpp` — sender ships row commit alongside column
  commits; SP recvs both, verifies both, throws on either failure.
- `tests/unit/test_shuffle_integrity_row.cpp` — 7 scenarios including the
  cross-column swap that A-sum misses. All pass.

## Validation

```bash
python3 build.py -DVOLE_PSI_BUILD_TESTS=ON -DVOLE_PSI_ENABLE_BOOST=ON
./out/build/linux/tests/unit/test_shuffle_integrity_row     # 7/7 PASS
./tests/run_mpsa_smoke.sh                                    # 100/100
./tests/run_mpsa_wide_smoke.sh                               # 100/100 × 12
./tests/run_mpsa_vole_smoke.sh                               # 100/100
# Run with -v to observe both integrity layers firing:
frontend -mpsa ... -v 2>&1 | grep -E "A-sum|A-mset-row"
```

## Follow-ups (not this stage)

- **A-mset-row assumes hashToScalar takes std::vector<uint8_t>&** — same
  allocation-per-row cost as A-sum. A span-based hashToScalar overload
  would fix both.
- **Neither A-sum nor A-mset-row catch "cascade produced a valid
  permutation of the true input, just not the intended one".** Closing
  that requires the shuffle NIZK (Bayer-Groth) proving the sender used
  the routing derived from a committed seed. Deferred to a real Stage A
  NIZK effort.
- **Malicious sender can commit to `Σ hash` of a set OTHER than the one
  they ship into m_i.** The commit binds the sender to a claimed sum but
  not to the actual set. To close: also commit to Merkle-root of the c_i
  rows at setup, opened during reveal.
