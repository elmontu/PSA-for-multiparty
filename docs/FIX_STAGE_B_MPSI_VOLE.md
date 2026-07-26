# Stage B — VOLE-PSI MPSI backend (`-mpsi-backend vole`)

## What landed

- **Phase 1: local rename.** `volePSI/RsPsi.{h,cpp}` → `RsSimpleHashPsi.{h,cpp}`;
  classes `RsPsi3rdP{SenderA,SenderB,Receiver}` → `RsSimpleHashPsi3rdP*`; base
  `details::RsPsiBase` → `details::RsSimpleHashPsiBase`. Frees the upstream
  canonical names in `namespace volePSI`. All callers updated. Behavioral
  no-op.
- **Phase 2: vendor drop.** ~11.7K LOC of external cryptographic code into
  `volePSI/upstream/`:
  - `volepsi/`: subset of `ladnir/volepsi` needed for 2PC VOLE-PSI —
    `RsPsi.{h,cpp}`, `RsOprf.{h,cpp}`, `Paxos.h`, `PaxosImpl.h`, `PxUtil.h`,
    `SimpleIndex.{h,cpp}`, `GMW/{Circuit,Gmw,SilentTripleGen}.{h,cpp}`,
    hand-rolled `config.h`.
  - `mpso/`: full `real-world-cryptography/MPSO` (Dong et al. CCS'25) —
    vendored and compiled but NOT yet wired (see "MPSO status" below).
  - Provenance + LICENSE files preserved; see `volePSI/upstream/README.md`.
- **Phase 3: RsMpsiVole wiring.** `volePSI/RsMpsiVole.{h,cpp}` now
  implements a real cascade of vendored `RsPsiSender/Receiver` calls (see
  protocol below).
- **Phase 4: `-mpsi-backend` CLI flag.** `-mpsi-backend simplehash` (default,
  legacy) or `-mpsi-backend vole` (Stage B). Both drivers propagate the
  choice through `runSpRole` / `runSenderRole`. Companion smoke:
  `tests/run_mpsa_vole_smoke.sh` (100/100 rows).

## Protocol (vole backend)

1. **Cascade seed.** Sender 0 ships its raw ID set to SP under the existing
   `spKey` AEAD wrapper. This is the price of the cascade approach — SP
   learns sender 0's set directly. See "Threat model" below.
2. **Cascade intersection.** For each i in 1..N-1:
   - SP is `RsPsiReceiver`, its "input" is the current candidate set.
   - Sender i is `RsPsiSender` of its own set.
   - After `run()`, `RsPsiReceiver::mIntersection` is a list of candidate
     indices that matched sender i's set. SP compresses its candidate
     accordingly.
   - Sender i learns NOTHING about which of its inputs matched.
3. **Per-sender OPRF pass (C3-closed).** For each sender i (including 0):
   - SP is `RsPsiSender` of the final intersection.
   - Sender i is `RsPsiReceiver` of its OWN set.
   - Sender i's `mIntersection` = indices of its inputs in the intersection.
   - **Sender i keeps this bitvec LOCAL** and uses it in the outer MPSA
     payload pipeline to build `c_i`. Nothing is shipped back to SP. In
     VOLE-PSI the SENDER (SP) learns nothing from `run()` beyond the fact of
     completion — so SP's view is bounded by the intersection cardinality
     already learned in step 2. C3 fully closed for this backend.

## Threat model comparison

| Property | `simplehash` (default) | `vole` (Stage B) |
|---|---|---|
| SP learns intersection cardinality | ✓ (as intended) | ✓ (as intended) |
| SP learns per-sender positional bitvec | ✓ (leak — C3) | **✗ (CLOSED — bitvec stays local to each sender via OPRF; SP never receives it)** |
| SP can dictionary-attack MPSI hashes to recover raw IDs | ✗ (with T15 salt on by default) | ✗ (real OPRF per session, no cross-session profile) |
| Sender 0's raw set leaks to SP | ✗ | **✓ (design trade-off of cascade)** |
| Senders 1..N-1's raw sets leak to SP | ✗ (with T15 salt) | ✗ (OPRF-protected by construction) |
| Malicious security | ✗ | ✗ (upstream stock OKVS; ASIACRYPT'24 [eprint 2024/1989] attack applies — corrected construction is a follow-on) |

Net win vs. `simplehash + T15 salt`: cross-session frequency profiling is
now defeated for senders 1..N-1 (the OPRF freshens per session). Net loss:
sender 0's set is fully revealed to SP by design of the cascade. That
trade-off is acceptable when sender 0 is the "anchor" sender who is
already less privacy-sensitive (e.g. the party that publishes the
aggregation, or the party whose set defines the ground-truth universe).

## MPSO status — vendored, NOT wired (and now less urgent)

MPSO (Dong et al. CCS'25, eprint 2025/640) is FULLY VENDORED and compiles
cleanly into libvolePSI.a alongside the volePSI subset. It remains unwired
into `MpsaDriver` for two reasons:

1. **Topology mismatch.** MPSO's `MPSICardParty` sets up its own full
   N-party mesh with hardcoded ports and does not accept caller-provided
   sockets. Integrating it requires either porting MPSO to use SP-mediated
   sockets or letting MPSO run its mesh in parallel to MPSA's star.
2. **Interface mismatch.** MPSO returns intersection cardinality only, no
   per-sender or per-position info. Switching to MPSO-CA would require the
   payload pipeline to run without per-sender bitvecs.

**Update:** the C3 leak that was the primary motivation for MPSO is now
closed by keeping the vole backend's bitvec local (see step 3 above). MPSO
is still worth wiring long-term because it delivers a genuinely N-party
symmetric protocol (no sender-0 leak) with malicious-security options, but
it is no longer the ONLY path to per-sender-positional privacy against SP.

## Follow-ups (deferred)

- **Malicious security**: swap upstream stock Baxos OKVS for the corrected
  construction from ASIACRYPT'24 (eprint 2024/1989). Small patch inside
  `volePSI/upstream/volepsi/Paxos.h` + `PaxosImpl.h`.
- **Parallelize the per-sender bitvec pass**: currently sequential; can run
  in N parallel coroutines.
- **Wire MPSO** as `-mpsi-backend mpso` after redesigning the payload
  pipeline to be cardinality-driven (no per-sender bitvec).
- **Retire the sender-0 leak** by adopting a symmetric protocol
  (KMPRT-proper with OPRF-share-combine, or MPSO-based) instead of the
  cascade.

## Files

- **New**:
  - `volePSI/upstream/` (~11.7K LOC vendored, provenance in README.md)
  - `docs/FIX_STAGE_B_MPSI_VOLE.md` (this file)
  - `tests/run_mpsa_vole_smoke.sh`
- **Modified**:
  - `volePSI/RsMpsiVole.{h,cpp}` (real implementation replaces stub)
  - `volePSI/MpsaDriver.cpp` (backend flag + branching)
  - `volePSI/CMakeLists.txt` (20 new source files)
- **Renamed**:
  - `volePSI/RsPsi.{h,cpp}` → `volePSI/RsSimpleHashPsi.{h,cpp}`
  - class names as per Phase 1

## Validation

```bash
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_BUILD_TESTS=ON
./tests/run_mpsa_smoke.sh          # default (simplehash), 100/100 rows
./tests/run_mpsa_wide_smoke.sh     # default + wide payload, 100/100 × 12 blocks
./tests/run_mpsa_vole_smoke.sh     # vole backend, 100/100 rows
```

All three pass in this build.
