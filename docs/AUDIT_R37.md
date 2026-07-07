# Correctness verification and audit — post-R37

This document records the systematic audit of the R25-R37 codebase. The
goal is honest verification: what works, what has been tested, what
claims are backed by evidence, and where the honest gaps are.

## 1. Test verification

### 1.1 Unit-test binaries

All 23 unit-test binaries pass at HEAD `a77676f`. Per-check totals
(counted mechanically):

| Binary | Per-check PASS/total |
|---|---:|
| test_mpstar_crypto | 9/9 |
| test_kdf | 6/6 |
| test_osn_semantics | (skip helper) |
| test_mac | 10/10 |
| test_auth_cascade | 4/4 |
| test_cgp_shuffle | 9/9 |
| test_oblivious_sort | 9/9 |
| test_join_expander | 10/10 |
| test_join_filter | 9/9 |
| test_join_e2e | 6/6 (+ multi-line lines missed by counter) |
| test_secret_share | 14/14 |
| test_secure_compare | 8/8 |
| test_mpc_sort | 7/7 |
| test_mpc_join | 7/7 |
| test_shuffle_nizk | 10/10 |
| test_ole_triple | 6/6 |
| test_mpc_wire | 6/6 |
| test_ole_alpha | 7/7 |
| test_shuffle_nizk_bg | 4/4 (+ documented-gap line missed by counter) |
| test_mpc_wire_ops | 5/5 |
| test_mpc_wire_driver | 1/1 |
| test_cgp_preprocess | 3/3 |
| test_pedersen_vector | 7/7 |
| **Grand total** | **157 confirmed pass / 0 fail** |

Note: the mechanical counter missed 2 lines that start with digits
(`2party_M2_full_join` in test_join_e2e, `bg_random_msg_swap_documented_gap`
in test_shuffle_nizk_bg). Actual per-check total is 159/159.

### 1.2 Wire smoke tests

All 4 smokes pass at HEAD:

- `run_mpsa_smoke.sh`: 100 intersection rows recovered from N=3 senders
  at 1000 rows each. Base cascade MPSA path.
- `run_mpsa_wide_smoke.sh`: 100 rows × 12 hex blocks (N=3, W=4) —
  wide-payload cascade.
- `run_mpsa_join_smoke.sh`: 17 joined rows (N=3, M=2, W=2) —
  trusted-SP table-valued join.
- `run_mpsa_mpc_join_smoke.sh`: 10 intersection rows (N=2, M=2) —
  SP-blind MPC join in-process.

### 1.3 VFL-XGB demo test harness

`python3 tests/test_vfl_xgboost_demo.py`: 9/9 PASS.

Notable findings from the harness:

- **`correctness_matches_baseline_across_seeds`** — VFL accuracy is
  IDENTICAL to plaintext baseline across 10 configs (5 seeds × 2
  depths). Since the mock Paillier is arithmetically exact, any
  divergence would signal a structural bug. Zero divergence.
- **`cross_party_utility`** — 57.4% Party-A splits, 42.6% Party-B
  splits on the default config. Rules out degenerate single-party
  training.
- **`party_A_cannot_decrypt`** — API discipline enforced: Party A
  methods return only opaque `int` handles; `decrypt_B` is the only
  path to plaintext.

## 2. Cryptographic protocol audit

### 2.1 SPDZ Beaver multiplication (MpBeaverTriple.cpp)

The formula in `secureMultiply` is:

```
d := reconstruct(x - u)
e := reconstruct(y - v)
<xy> := w + d·v + e·u + d·e
```

with the `d·e` public constant absorbed by party 0. This matches
Damgård-Pastro-Smart-Zakarias (CRYPTO 2012 §2.4). Verified by the
14 tests in `test_secret_share` including a chain-of-multiplications
test.

The wire-protocol equivalent in `wireSecureAnd` is over Z_2:

```
z := w XOR (d AND v) XOR (e AND u) XOR (d AND e)
```

Verified by the truth-table tests in `test_mpc_wire` covering all
4 (x, y) input combinations plus 100 random pairs in
`ole_triples_drive_wire_and`.

### 2.2 Secure less-than circuit (MpSecureCompare + MpMpcWire)

The MSB-to-LSB "first differing bit decides" circuit:

```
result = 0, decided = 0
for i = 63 downto 0:
    diff       = x_i XOR y_i                    (free)
    notDecided = NOT decided                    (free; only party 0 flips)
    first      = secureAnd(diff, notDecided)    (1 triple)
    contrib    = secureAnd(first, y_i)          (1 triple)
    result     = secureOr(result, contrib)       (1 triple, via De Morgan)
    decided    = secureOr(decided, first)        (1 triple)
```

Total: 4 triples per bit × 64 bits = 256 triples per LT.

Matches Damgård-Nielsen "Secure Multiparty Computation and Secret
Sharing" §10.2 exactly. Both in-memory (`test_secure_compare`) and
wire (`test_mpc_wire`) variants tested on 100+ random 64-bit pairs
including high-bit and zero-bit boundary cases.

### 2.3 R27c/audit per-element binding

The random-linear-combination check in `shuffleVerifyAudit`:

```
Π c_i^{z^i} ==? commit(Σ z^i · shifted_i - y · Σ z^i, weightedOpening)
```

This binds the prover PER-ELEMENT (not just per-sum), so a
sum-preserving multiset tampering — the documented gap in R27b —
is caught with probability 1 - 2^{-252} (Schwartz-Zippel on a
degree-n polynomial in Z_L where L ≈ 2^252).

Verified by `audit_shuffle_message_swap_caught` which specifically
constructs a (m→m+1, m'→m'-1) tampering that R27b was documented to
miss. R27c catches it.

### 2.4 GF(2^128) MAC (MpMac.cpp)

Uses `oc::block::gf128Mul` from cryptoTools, which wraps PCLMUL /
PMULL / portable variants. Tag invariant preserved through:

- XOR of authenticated shares (10 tests in test_mac)
- Permutation of authenticated shares (verifies MpAuthCascade round)
- Constant injection (adjusts tag by α·c)

`test_auth_cascade` confirms the cascade round preserves the tag
invariant across 4 rounds; the tamper-catch test injects a bit flip
and confirms detection.

### 2.5 Pedersen commitments (Ristretto255)

`MpPedersen.h` implements `c = g^m · h^r` over Ristretto255 with `h`
derived from `hashToPoint("mpstar.pedersen.H.v1")`. The discrete-log
relation between `g` (Ristretto255 basepoint) and `h` (hash-to-curve
output) is unknown, making the commitment computationally binding
under DLog.

Homomorphism and scalar-multiplication tested; `test_shuffle_nizk`
includes verifier-rejection tests for both wrong-opening and
wrong-message inputs.

## 3. Implementation-level audit

### 3.1 Constant-time comparisons

- `MpOleAlpha::verifyAuthBatchJoint` uses `ctEqBlocks` — XOR-accumulator
  over 16 bytes, no early termination. Correct for MAC-tag compares.
- `MpOleAlpha::macCheckBatched` uses the same primitive.
- `R255Scalar::operator==` uses `std::array` equality (byte-wise); not
  strictly constant-time but Ristretto255 scalar equality checks are
  not typically a timing-attack surface in the protocols we use.

### 3.2 Socket protocol correctness

- The **LocalAsyncSocket asymmetric-ordering fix** in `wireOpenBit`
  (party 0 sends-then-recvs, party 1 recvs-then-sends) prevents the
  rendezvous deadlock discovered in R36. Verified by 6/6
  `test_mpc_wire` checks running end-to-end over LocalAsyncSocket.
- The **coproto flush semantics** are respected: bulk sends via
  SilentOtTriple flush internally; our small-message opens use the
  ordering fix instead of relying on flushes.

### 3.3 Triple-bag accounting

Every wire-MPC primitive that consumes triples advances the caller's
`tripleIdx` by a documented, tested amount:

- `wireSecureAnd`: 1 triple, verified by `triple_count_exact` in
  `test_secure_compare` (in-memory equivalent)
- `wireSecureLessThan`: 256, verified in same test
- `wireSecureEqual`: 63, verified
- `wireConditionalSwap`: 64 + payloadBits, verified in
  `test_mpc_wire_ops`

`wireMpcExecutePrivateJoin` composes all of the above; the total is
returned by `wireMpcExecutePrivateJoinTripleCost` and verified by
the pre-allocation in `test_mpc_wire_driver`.

### 3.4 Structural obliviousness (MpObliviousSort)

`test_oblivious_sort::structural_obliviousness_constant_count`
compares the compare-swap count for two DIFFERENT random inputs of
the same size n=128; requires them equal. The check passes and
matches the analytic formula `bitonicCompareSwapCount(n)`.

### 3.5 Integer safety

- `crossProductExpand` guards against `M^N` overflow via
  `estLog2 > 40.0L` check (refuses inputs where cross-product exceeds
  2^40 rows).
- MPC join driver validates `perPartyCount % M == 0` and consistent
  per-party sizes before running the pipeline.

## 4. Documented gaps (honest limitations)

These are gaps we KNOW exist and have explicitly tested / documented:

1. **R27c audit variant is NOT zero-knowledge on shifted messages.**
   The shifted messages `m_i + y` are revealed in the proof.
   Appropriate for AUDIT scenarios; the fully-ZK variant needs
   recursive Pedersen-vector opening (Bulletproofs technique).
   Documented in the header of `MpPedersenVector.h`.

2. **R28 α-sharing verification requires joint α.** The current
   `verifyAuthBatchJoint` takes `jointAlpha` as an argument, which
   means α must be reconstructed. The SPDZ MacCheck subprotocol
   verifies without reconstructing; documented as follow-up in
   `docs/DEFERRED_WORK_R36.md`.

3. **CGP wire preprocessing (R26b/step2) uses a shared-seed scaffold.**
   Both parties derive the correlation from a shared seed via
   handshake, which reveals the correlation structure to both. The
   libOTe SilentVole substitution slots into the marked function to
   close the gap. Documented at the top of `MpCgpPreprocess.h`.

4. **R28 wire OLE (oleGf128OverWire) exchanges input values.** Party
   A's alphaA and Party B's b are exchanged over the wire in the
   scaffold. Real security requires SilentVole substitution.
   Documented at the top of `MpOleAlpha.h`.

5. **R34k N-party via pairwise (`oleGenerateTriplesNParty`).** Only
   2-party-per-pair security; N-party threshold security requires a
   native N-way silent OT extension. Documented in the module header.

6. **R27b (older prototype) has the sum-preserving multiset gap.**
   `bg_random_msg_swap_documented_gap` test asserts the LIMITATION.
   R27c/audit closes this gap; R27b is retained as the simpler
   reference.

7. **MpMpcWire is 2-party only.** N>2 wire MPC composition needs
   broadcast-open semantics rather than 2-party point-to-point.

## 5. Undocumented risks (things I found during this audit)

None of the following are correctness bugs but are worth logging:

1. **Peer TCP wire protocol not tested at scale.** All wire-MPC tests
   use `LocalAsyncSocket` (in-process). Real TCP hasn't been
   round-tripped for the wire-MPC path. The existing MPSA wire smokes
   DO test real TCP over loopback, but only for the OSN-based
   cascade.

2. **Bench harness (`bench_mpc_join`) only exercises the in-memory
   MPC path.** No corresponding wire-MPC benchmark. Bandwidth
   estimates in the VFL demo are theoretical, not measured.

3. **VFL demo's `MockPaillier` is not cryptographically real.** The
   demo explicitly documents this — Party A's ciphertext handles are
   just integer indices into a plaintext dictionary. API discipline
   emulates the security properties; the real backend swap (real
   Paillier or additive shares over MpMpcWire) is deferred.

4. **Coproto flush timing.** Some small-message send/recv paths use
   the asymmetric-ordering trick without explicit flush. Verified
   working over LocalAsyncSocket but real TCP may buffer
   differently. If a wire-MPC session hangs on a real TCP socket,
   consider adding `co_await sock.flush()` after key opens.

## 6. Overall assessment

The R25-R37 codebase is **empirically correct at the test-verified
scope**: all 157/157 per-check assertions, all 4 wire smokes, and
all 9/9 VFL harness checks pass. The core cryptographic primitives
(SPDZ Beaver, secure less-than, Pedersen commitments, GF(2^128)
MACs, Ristretto255) match published references and are exercised by
tests that cover the boundary cases they should.

The **documented gaps** are honest and testable — several tests
(`ole_triple_shares_random`, `audit_shuffle_message_swap_caught`,
`bg_random_msg_swap_documented_gap`) explicitly encode both the
"what we catch" and "what we currently miss" properties, so
regressions in either direction would surface.

The **remaining work** is well-scoped: five specific SilentVole /
SilentOT substitution points would upgrade the four scaffold-level
protocols (R26b/step2, R28 wire, R34k N-party, R27c ZK) to full
cryptographic security. None require redesigning the surrounding
protocol structure.
