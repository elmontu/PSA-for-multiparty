# Session summary — R25 through R35

This document maps the work delivered across rounds R25-R35, the
underlying design choices, and what's deliberately left for future
sessions.

## Top-level outcomes

| Capability | Status | Wire-protocol? | Modules |
|---|---|---|---|
| Single-row PSA cascade (original) | shipped pre-session | yes | `MpsaDriver`, `MpShuffleDriver` |
| Wide-row payload (PSA-with-payload, M=1) | **shipped this session (R26b/step-5)** | yes (`-pw W`) | `MpsaDriver` updated, `MpShuffleDriver` columns decoupled |
| MAC-propagating cascade primitives | shipped (R25) | in-memory simulation only | `MpMac`, `MpAuthCascade` |
| CGP secret-shared shuffle | shipped (R26) | in-memory simulation only | `MpCgpShuffle` |
| Table-valued private join (multi-row per id) | **shipped (R29-R33)** | yes (`-mpsa-join`) trusted-SP threat model | `MpObliviousSort`, `MpJoinExpander`, `MpJoinFilter`, `MpsaJoinDriver`, `MpsaJoinDriverWire` |
| SP-blind MPC private join | **shipped (R34a-j)** | in-process simulation (`-mpsa-join-mpc`); full wire = R34k deferred | `MpSecretShare`, `MpBeaverTriple`, `MpSecureCompare`, `MpMpcSort`, `MpMpcJoin`, `MpsaJoinMpcDriver` |
| Scale benchmarks | shipped (R35) | n/a | `tests/benchmarks/bench_mpc_join` |

## Architecture map (new modules this session)

```
foundation
├── MpMac.{h,cpp}            R25  GF(2^128) MAC algebra (10 tests)
├── MpAuthCascade.{h,cpp}    R25  MAC-propagating cascade simulation (4 tests)
├── MpCgpShuffle.{h,cpp}     R26  Chase-Ghosh-Poburinnaya shuffle sim (9 tests, wide rows)
├── MpObliviousSort.{h,cpp}  R29  Plaintext bitonic sort, oblivious access pattern (9 tests)
└── MpJoinExpander.{h,cpp}   R30  Window detect + cross-product expander (10 tests)

plaintext join pipeline
├── MpJoinFilter.{h,cpp}     R31  Oblivious is_intersection filter (9 tests)
├── MpsaJoinDriver.{h,cpp}   R32  In-memory end-to-end join (8 tests)
└── MpsaJoinDriverWire.{h,cpp} R33 -mpsa-join CLI mode (trusted-SP wire)

MPC pipeline (SP-blind)
├── MpSecretShare.{h,cpp}    R34a additive shares + bit shares
├── MpBeaverTriple.{h,cpp}   R34b/c trusted-dealer triples + secure multiply
├── MpSecureCompare.{h,cpp}  R34d secureLessThan + secureEqual on bit-shared u64
├── MpMpcSort.{h,cpp}        R34e/f conditional swap + MPC bitonic sort
├── MpMpcJoin.{h,cpp}        R34g/h/i/j end-to-end SP-blind join
└── MpsaJoinMpcDriver.{h,cpp} -mpsa-join-mpc CLI mode (in-process MPC sim)

benchmarks
└── tests/benchmarks/bench_mpc_join.cpp  R35 scaling sweep
```

## Test coverage delta (this session)

```
Pre-session  test_mpstar_crypto      (unchanged)
             test_kdf                (unchanged)
             test_osn_semantics      (unchanged)
NEW R25      test_mac                10/10 PASS
NEW R25      test_auth_cascade        4/4 PASS
NEW R26      test_cgp_shuffle         9/9 PASS  (wide-row support added in R26b/step1)
NEW R29      test_oblivious_sort      9/9 PASS
NEW R30      test_join_expander      10/10 PASS
NEW R31      test_join_filter         9/9 PASS
NEW R32      test_join_e2e            8/8 PASS
NEW R34a-c   test_secret_share       14/14 PASS
NEW R34d     test_secure_compare      8/8 PASS
NEW R34e/f   test_mpc_sort            7/7 PASS
NEW R34g-j   test_mpc_join            7/7 PASS
                                     ─────────
                                     95 NEW UNIT TESTS — 100% PASS

Wire smoke tests:
  run_mpsa_smoke.sh                  PASS (100 intersection rows, W=1 baseline)
  run_mpsa_wide_smoke.sh             PASS (100 rows × 12 hex blocks, W=4)
  run_mpsa_join_smoke.sh             PASS (17 joined rows, N=3 M=2 W=2, table-valued)
  run_mpsa_mpc_join_smoke.sh         PASS (10 intersection rows, SP-blind MPC)
```

## Privacy / threat-model spectrum delivered

| Protocol | SP sees inputs? | SP sees output? | Sender sees other senders' inputs? | Notes |
|---|---|---|---|---|
| Cascade MPSA (original) | masked m_i only | shuffled cleartext | r_j of one party (sender 0) | semi-honest |
| Cascade MPSA wide-payload (R26b) | masked m_i (wider) | shuffled cleartext | same | semi-honest |
| Cascade MPSA + MAC (R25) | masked | shuffled cleartext | same | adds active-tamper detection within cascade rounds; doesn't close SP-vs-sender collusion (see [[malicious-cascade-design]]) |
| `-mpsa-join` (R33) | **plaintext** | plaintext | no | trusted-SP threat model; appropriate when SP is regulator/broker |
| `-mpsa-join-mpc` (R34, in-process sim) | NEVER plaintext | reconstructed at writeout | no | full SP-blind; in-process means in-memory only |
| `-mpsa-join` + full wire MPC (R34k) | NEVER plaintext | reveal phase | no | deferred — requires OLE + multi-round opens |

## Deferred work, scoped

The session intentionally stopped short of these:

1. **R26b/step2-4** — wire-level CGP backend with OT preprocessing
   replacing the trusted-dealer correlation. ~600 LoC `MpCgpPreprocess`
   on libOTe SilentVole, then ~250 LoC port into `MpShuffleDriver` as a
   selectable backend. The CGP simulator (R26 + R26b/step1) works in-
   memory; the deferred work is purely wire/OT-extension integration.

2. **R27 — DELIVERED as a prototype** (this session, see
   docs/SHUFFLE_NIZK_DESIGN.md). Pedersen commitments + Fiat-Shamir
   shuffle proof. The full Bayer-Groth construction with polynomial
   commitment to π and recursive Pedersen-vector commitments (R27b)
   remains future work — that's where positional-permutation soundness
   gets closed.

3. **R28** — OLE-based SPDZ-style α-sharing for the malicious cascade
   (R25). Now substantially de-risked by R34k delivering the libOTe
   OLE wrapper — R28 reuses the same `MpOleTriple` pattern but for
   GF(2^128) MAC keys rather than bits.

4. **R34k — DELIVERED for 2-party case** (this session, see
   docs/MPC_WIRE_DESIGN.md). Real OLE-based Beaver triple gen via
   libOTe SilentOtTriple. Closes the trusted-dealer gap for N=2. The
   remaining wire-protocol pieces (per-operation opens, party
   drivers, CLI mode) total ~750 LoC and are composable on top of the
   OLE foundation. N>2 extension documented.

## Cost reality (from R35 benchmarks)

The MPC join's dominant cost is Beaver triples (preprocessing). With
trusted-dealer Beaver gen, the online MPC join itself is 500-2500×
slower than plaintext for prototype-scale workloads (|U| < 100, M < 8,
N < 8). Replacing trusted-dealer gen with OLE (R34k) is what closes
both the privacy gap (no trusted dealer) and surfaces the real
preprocessing cost (OLE is significantly slower than local random
generation; typically 10-100× more depending on libOTe configuration).

For the original cascade MPSA at the same scales, MPC overhead is
~1× (it's already in MPC via OSN/AEAD). The join protocol is
fundamentally more expensive than the cascade because oblivious sort
and cross-product expansion don't have a "shuffle is just a
permutation" shortcut.

## Quoted user direction (this session)

The session was driven by these key user redirections:

- "should have more theoretical improvements. no point patching" →
  switched from CGP backend wire port (R26b) toward the deeper join
  protocol family (R29-R34).
- "you miss that its psa with payload. the key here is payload" →
  forced reframing of CGP analysis; led to wide-payload work (R26b/step5)
  and ultimately the table-valued join investigation.
- "main challenge is chaining the payload into sets. for example, if
  the payload is a table instead of a single value" → defined the join
  problem; led to R29-R34 design doc + implementation.
- "push on to R34" → committed to building MPC pipeline.
- "push through. dont ask again. juts push through. dont need ask for
  permission" → established standing rule [[dont-ask-in-build]] for
  build sessions.

## Final next-step recommendations

For continued investment in this codebase, in approximate ROI order:

1. **R34k** — make the MPC join deployable (close the trusted-dealer gap).
2. **R28** — OLE infrastructure (prerequisite to several other rounds).
3. **R27** — verifiable shuffle NIZK (orthogonal, complementary).
4. **R26b/step2-4** — CGP backend on the cascade (latency win at scale).
