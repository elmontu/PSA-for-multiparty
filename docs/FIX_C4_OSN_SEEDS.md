# Fix C4 — OSN internals no longer use hardcoded PRNG seeds

## The break

Six PRNG initializations in `volePSI/osn/{OSNSender,OSNReceiver}.cpp` were
seeded from hardcoded 128-bit constants (`_mm_set_epi32(...)`), reproducible
from source by any adversary. Concretely:

| Site | What it seeded | Impact |
|---|---|---|
| `OSNReceiver::gen_benes_client_osn` | the input masks `masks[j]` that blind the receiver's OSN input on the wire | Anyone with source recomputes `masks[]` and recovers `input = benes_input XOR masks` from the wire trace |
| `OSNReceiver::rand_ot_send`, `silent_ot_send` | base-OT PRNG for the sender-of-OT role | Deterministic OT-extension messages → correlated with choice bits |
| `OSNSender::rand_ot_recv`, `silent_ot_recv` | base-OT PRNG for the receiver-of-OT role, incl. `choices` bits under `ot_type=0` | With `ot_type=0` the code sends `bit_correction = switches XOR choices`; a source-aware party recovers `switches` (= Benes routing = per-round permutation) |
| `OSNSender::init_wj` | Fisher-Yates PRNG for the routing `dest[]` | Every call at the same size produced the SAME permutation across all runs |

Under the A1 fix, `MpShuffleDriver` always puts the SP in the OSN-receiver
role. Site 1 alone means every OSN counterpart (i.e., every sender at its
round) reads the SP's M-share off the wire. Sender k already holds R[col];
combined with the leaked M, sender k reconstructs `M ⊕ R = (shuffles-so-far)(input_col)`.
At round 0, that's the raw un-shuffled input column for every column —
including OTHER senders' payloads. This defeats the "no single sender learns
other senders' data" property that the star-cascade shuffle exists to
provide.

## The fix

All six sites now seed from `oc::sysRandomSeed()` (cryptoTools' OS-CSPRNG
wrapper), producing a fresh 128-bit seed per call:

```cpp
// Before
auto prng = osuCrypto::PRNG(_mm_set_epi32(4253233465, 334565, 0, 235));

// After
auto prng = osuCrypto::PRNG(oc::sysRandomSeed());
```

`init_wj` retains its old signature (no seed argument) — callers that need
a specific reproducible permutation must switch to `init_wj_seeded(...,
seed)`, which is what `MpShuffleDriver` uses post-A1.

## Interaction with A1

A1 already delivered privacy against the SP for the composed permutation π
(assuming honest OSN internals). C4 delivers the missing piece: OSN internals
are *actually* honest, so a curious sender can no longer peek at the SP's
M-share via the wire. Together, A1+C4 make the composed statement of §4 in
`docs/PRIVACY_AUDIT_R37.md` hold against a semi-honest SP AND against a
curious single sender.

## Correctness — nothing changes on the wire semantically

Both OSN roles independently sample their own randomness (masks, OT base
strings, choice bits) — the protocol has never required the two sides to
agree on a shared PRNG state. Randomizing each side's local PRNG is
*exactly* the environment the OSN's semi-honest security proof assumes.

Confirmed by:

- `tests/unit/test_osn_seed_freshness` — offline, asserts `init_wj` yields
  distinct `dest[]` across independent calls.
- `tests/unit/test_osn_semantics` — real OSN over an in-process socket
  pair; the invariant `newR[j] XOR newM[j] == M[dest[j]]` still holds after
  randomization (was already passing; unchanged).
- `tests/run_mpsa_smoke.sh` and `tests/run_mpsa_wide_smoke.sh` — full
  end-to-end MPSA still recovers 100/100 intersection rows.

## Companion policy change — MPSI salt on by default

`MpsaDriver.cpp` used to require `-salt-mpsi` opt-in for the T15 mitigation
(sender-agreed salt XORed into IDs before MPSI hashing, blocking the SP's
dictionary attack on the AES-hashed intersection lists). Salt is now
**default-on**; use `-no-salt-mpsi` to disable (benchmarks / older-peer
interop only). This does not close the C2/C3 leak fully — SP still learns
per-sender positional bitvecs — but it removes the trivial ID-recovery
vector.

## Not fixed here (tracked separately)

- **C2/C3 root cause** — the MPSI is a plain SP-mediated AES-hashed
  intersection, not a real oblivious PSI. SP still receives per-sender
  bitvecs marking intersection membership by position. Full fix requires
  porting to `RsMpsiVole` (OPRF/VOLE-PSI), as outlined in
  `docs/RSMPSI_VOLE_INTEGRATION.md`.
- **Malicious-security integrity** — the cascade is still semi-honest
  only. `MpShuffleNizk`/`MpShuffleNizkBg` in the tree hint at a NIZK-based
  malicious upgrade but it is not wired into the default cascade.
- **Collusion threshold** — SP + any single sender still permits round-
  peeling attacks. This is intrinsic to any N-party star-cascade shuffle
  and should be documented as an operational assumption (need ≥ 2 honest
  senders for full obliviousness), not a theorem.
