# PSA: Private Set Alignment for Secure and Collaborative Analytics on Large-Scale Data (Demo)

[![DOI](https://img.shields.io/badge/DOI-10.48550%2FarXiv.2410.04746-blue)](https://arxiv.org/abs/2410.04746)


**PSA** is a privacy-preserving technique enabling secure, collaborative analytics between two parties with vertically partitioned datasets, without directly sharing sensitive data. This demo integrates **Private Set Intersection (PSI)** and an **Oblivious Switching Network** to achieve efficient and secure **Private Set Alignment (PSA)**.

This project depends on [libOTe](https://github.com/osu-crypto/libOTe), [sparsehash](https://github.com/sparsehash/sparsehash), [Coproto](https://github.com/Visa-Research/coproto), [volepsi](https://github.com/Visa-Research/volepsi), [PSU](https://github.com/dujiajun/PSU/tree/master/benes)



## Performance Metrics

- Dataset Join Time: 35.5 seconds (1 million records)
- Performance Improvement: ~100× faster than existing methods


## How It Works
| Component        | Role                                          |  
|------------------|-----------------------------------------------|
| Service Provider | Coordinates the protocol and compiles results |
| Alice (Sender)   | Provides one dataset                          | 
| Bob (Receiver)   | Provides another dataset                      |

The system:
1. Exchanges secret shares between Alice and Bob
2. Creates a virtual table with inner-joined data
3. Preserves privacy - only matching IDs are revealed

For complete technical details, see our [paper](https://arxiv.org/abs/2410.04746).

## Multiparty Extension (`-mpsa`)

This fork extends the original 2-party PSA to **N data-contributing senders**
(N >= 2) coordinated by the Service Provider. The cryptographic design and
deferred items are documented in [`docs/RESEARCH_MPSI.md`](docs/RESEARCH_MPSI.md)
and [`docs/DEFERRED_AUDITS.md`](docs/DEFERRED_AUDITS.md).

What's added:
- N-party Simple-Hash MPSI (`volePSI/RsMpsi.{h,cpp}`); upstream-VOLE-PSI
  swap scaffolded in `RsMpsiVole.*`.
- Star-cascade oblivious shuffle (`volePSI/MpShuffleDriver.*`) reusing the
  existing 2-party Benes OSN.
- Pairwise sender↔sender X25519 DH (`MpStarSetup`) and SP↔sender DH
  (`MpSpHandshake`).
- AEAD on the masked payload column (libsodium `secretbox_easy`) with
  per-session key binding to defeat cross-session replay.
- Build dependency: `libsodium-dev` (Ubuntu/Debian package). Dockerfile
  already installs it; bare-metal builds need it on the system.

### CLI

```
# Service Provider
./out/build/linux/frontend/frontend -mpsa -N 3 -r 0 -port 17500 -out dataset/out_mpsa.csv

# Sender i (one process per sender, i in 0..N-1)
./out/build/linux/frontend/frontend -mpsa -N 3 -r 1 -i 0 -port 17500 -host localhost -in dataset/sender_0.csv
./out/build/linux/frontend/frontend -mpsa -N 3 -r 1 -i 1 -port 17500 -host localhost -in dataset/sender_1.csv
./out/build/linux/frontend/frontend -mpsa -N 3 -r 1 -i 2 -port 17500 -host localhost -in dataset/sender_2.csv
```

CSV format is unchanged: column 1 = ID, column 2 = payload.

**Output:** SP writes `out_mpsa.csv` with one row per intersection element,
N comma-separated hex-encoded payload blocks per row (one column per
sender, all shuffled by the same secret permutation).

### Privacy / hardening flags

```
-pq                  hybrid X25519 + KEM handshake (HNDL-resistant; StubKem
                     placeholder in this build, real ML-KEM-768 swap-in
                     documented in docs/PQ_HYBRID_HANDSHAKE_DESIGN.md)
-cmax <N>            pad output to >= N rows with PRNG dummies
                     (hides exact |I| from output-file observers)
-mink <K>            threshold-k revelation: SP aborts if |I| < K
                     (k-anonymity-style compliance policy)
-dp <epsilon>        DP-protected cardinality release: SP logs
                     C̃ = C + Laplace(1/epsilon); real C kept internal
-v                   verbose per-step debug logs to stderr
```

Combined example (regulated-deployment tier):

```bash
frontend -mpsa -N 3 -r 0 -pq -cmax 1024 -mink 50 -dp 0.5 -out result.csv
```

See `docs/SECURITY_ANALYSIS.md` for the threat model across all layers
and `docs/DEFERRED_AUDITS.md` for the per-round audit log.

### Smoke test

```bash
./tests/run_mpsa_smoke.sh
```

Generates synthetic data (100 IDs in the intersection out of 1000 per sender)
via `tests/gen_mpsa_dataset.py`, spawns SP + N senders on loopback, asserts
the output file has 100 rows.

### Offline unit tests (no network)

```bash
python3 build.py -DVOLE_PSI_BUILD_TESTS=ON -DVOLE_PSI_ENABLE_BOOST=ON
./out/build/linux/tests/unit/test_mpstar_crypto
```

Covers AEAD round-trip, MAC/nonce/key-mismatch detection, block
(de)serialization, including the empty and wrong-count edge cases.

## Extensions (R25 – R36c)

Beyond the base multiparty MPSA above, the codebase now includes a
theoretical-hardening + private-join + MPC + NIZK layer. Full details in
`docs/`; the summary below indexes what's in the tree.

### Wide-payload cascade (`-pw`)

The base cascade shuffles one 16-byte block per row. `-pw <W>` lets the
CSV carry `W` payload blocks per row. Cascade carries `N × W` single-
block columns; output CSV has `N × W` comma-separated hex blocks per
intersection row. See `docs/CGP_SHUFFLE_DESIGN.md` for the CGP-backend
analysis (in-memory simulation in `volePSI/MpCgpShuffle.*`; OT-based
wire preprocessing scoped in `docs/DEFERRED_WORK_R36.md`).

Smoke: `./tests/run_mpsa_wide_smoke.sh` (N=3, W=4, 100 intersection rows).

### Malicious-cascade primitives (`docs/MALICIOUS_CASCADE_DESIGN.md`)

- `volePSI/MpMac.*` — GF(2^128) MAC algebra over `oc::block::gf128Mul`.
- `volePSI/MpAuthCascade.*` — MAC-propagating cascade simulation with
  tamper detection at every round handoff.
- `volePSI/MpOleAlpha.*` — SPDZ-style additively-shared α with
  trusted-dealer OLE (libOTe `SilentVole` substitution is a mechanical
  follow-up).

### Table-valued private join (`-mpsa-join`)

New protocol family for when payload is a **variable-cardinality table
per id** rather than a single value. Each id can have up to `M` rows per
party. Output is the cross-product join of intersection-ids over all
parties' tables. See `docs/PRIVATE_JOIN_DESIGN.md` for the 8-phase
architecture.

- `volePSI/MpObliviousSort.*` — bitonic sort, structurally oblivious
  (compare-swap pattern depends only on `n`).
- `volePSI/MpJoinExpander.*` — window detect + cross-product expansion
  with `is_intersection` AND-aggregation.
- `volePSI/MpJoinFilter.*` — oblivious filter pushing intersection
  rows to the front via a second sort.
- `volePSI/MpsaJoinDriver.*` — in-memory oracle.
- `volePSI/MpsaJoinDriverWire.*` — wire protocol (**trusted-SP**
  threat model: SP sees plaintext inputs after AEAD decryption).

CLI:
```
frontend -mpsa-join -N 3 -r 0 -M 2 -pw 2 -out out.csv     # SP
frontend -mpsa-join -N 3 -r 1 -i 0 -M 2 -pw 2 -in ...     # sender
```

Smoke: `./tests/run_mpsa_join_smoke.sh` (N=3, M=2, W=2, 17 joined rows).

### SP-blind MPC pipeline (`-mpsa-join-mpc`)

Full multi-party computation variant where SP **never sees plaintext**
inputs. Uses XOR-secret sharing over Z_2, Beaver-triple based
`secureAnd`, and a bit-decomposed 64-bit comparison circuit.

- `volePSI/MpSecretShare.*` — additive shares (Z_2^64 arithmetic +
  Z_2 boolean).
- `volePSI/MpBeaverTriple.*` — trusted-dealer Beaver triples + SPDZ
  Beaver multiplication.
- `volePSI/MpSecureCompare.*` — 64-bit LT (256 triples) + equality
  (63 triples) on XOR-shared bits.
- `volePSI/MpMpcSort.*` — MPC bitonic sort composing swap + LT.
- `volePSI/MpMpcJoin.*` — end-to-end SP-blind join (window detect via
  composite-key trick, cross-product with secureAnd chain, oblivious
  filter).
- `volePSI/MpsaJoinMpcDriver.*` — CLI mode running full pipeline
  in-process across all parties on bit-shared inputs.

Smoke: `./tests/run_mpsa_mpc_join_smoke.sh` (N=2, M=2, exercises the
whole MPC stack).

### Real OLE + wire MPC (`docs/MPC_WIRE_DESIGN.md`)

Beaver triples generated by real 2-party OLE via libOTe's
`SilentOtTriple` — closes the trusted-dealer gap for the 2-party case.

- `volePSI/MpOleTriple.*` — thin wrapper. Neither party learns the
  other's triple shares.
- `volePSI/MpMpcWire.*` — 2-party wire versions of `secureAnd`,
  `secureOr`, `secureLessThan`, `secureEqual` over `coproto::Socket`.
- `volePSI/MpMpcWireOps.*` — wire conditional-swap, bitonic sort,
  cross-product expander, `is_intersection` filter.
- `volePSI/MpMpcWireDriver.*` — end-to-end wire MPC private-join
  driver. Cooperating coroutines drive each party's half of the
  protocol.

### Verifiable shuffle NIZK (`docs/SHUFFLE_NIZK_DESIGN.md`)

Publicly-verifiable proof that the cascade output is a permutation of
its input. Uses Pedersen commitments over Ristretto255 (libsodium)
with Fiat-Shamir.

- `volePSI/MpRistretto.*` — thin Ristretto255 wrapper.
- `volePSI/MpPedersen.*` — Pedersen commitments (perfect hiding,
  computational binding).
- `volePSI/MpShuffleNizk.*` — R27 prototype (Schwartz-Zippel on
  weighted-sum polynomial evaluation).
- `volePSI/MpShuffleNizkBg.*` — Bayer-Groth-inspired shuffle argument.
  The earlier R27b residual gap (sum-preserving multiset tampering that
  was uncaught because the verifier trusted the prover's product claim)
  has been **closed**: the verifier now independently recomputes both
  products from revealed messages after checking each opening binds to
  its commitment. The construction is sound (Schwartz-Zippel over
  ~2^252-element field) but reveals the messages — an acceptable trade
  for MPSVS Phase 4 where bin contents are public post-alignment. Full
  hiding requires Bayer-Groth §5 recursive partial-product argument
  (out of scope).

## MPSVS Π_SECTORVULN Rev 7 — malicious-secure sector-level statistics

MPSVS is a domain-specific MPC pipeline for regulator-controlled release
of sector-level vulnerability statistics (financial soundness ratios like
DTI, DSI, DEmp, IPW, Delq, NPL, UnsecShare, StDebtShare) without exposing
any single firm's data. The 5-party topology mirrors an in-progress
Singapore inter-agency setting:

| Party | Role |
|---|---|
| **MAS** | data-input (loan/debt/npl) — covers licensed-borrower subset (~10% of firm universe) |
| **DOS** | data-input (income / revenue / surplus) — covers all registered firms |
| **MOM** | data-input (employment / labour / vacancy) — covers all registered firms |
| **S1, S2** | non-colluding MPC compute nodes (SPDZ-style) |
| **GT (GovTech)** | orchestrator; publishes ctx + policy Φ; receives DP-noised release; **holds no share, key, or payload** |

The pipeline runs 12 protocol phases: OPRF-derived row tags → F_PSA
alignment → inclusion → bucketing → ranking → composite score →
percentiles → sector aggregation → DP joint noise → release with
audit chain.

### Phase 17 — malicious-secure sub-protocols

Added on top of the Rev 7 semi-honest baseline. Each catches a specific
class of active adversary.

- **17.1 SPDZ MAC-authenticated shares** (`MpsvsAuthShare.{h,cpp}`,
  `MpsvsAuthShareProd.{h,cpp}`) — every share carries a MAC `α·x`; any
  share tampering is caught on open. Two variants:
  - Plaintext-α (`openWithMacCheck`) — legacy single-verifier /
    trusted-auditor model. Kept for backward compat.
  - **Shared-α DPSZ 2012 §3.3** (`openWithMacCheckShared`,
    `authSecureMultiplyShared`, `sacrificeCheckTripleShared`,
    `verifyReciprocalAuthShared`) — α remains additively shared for the
    entire session; neither S1 nor S2 ever reconstructs it. σ_i =
    α_i·x - m_i checked via commit-then-open protocol. This is the
    correct primitive for a fully-malicious S1 vs S2 threat model.
    Batched Ω-check uses Fiat-Shamir-derived challenges (unpredictable
    to adversary who has not yet committed to shares).

- **17.2 OLE-based Beaver triples** (`MpOleAlpha.*`, `MpOleTriple.*`) —
  removes the trusted-dealer assumption via libOTe `SilentOtTriple`
  under LPN. N=2 supported; N>2 explicitly guarded (throws) pending a
  native N-party OLE.

- **17.3 OPRF DLEQ + Schnorr** (`MpsvsOprf.cpp`) — every OPRF hop
  carries a Chaum-Pedersen DLEQ proof; Schnorr and DLEQ verify both
  validate the Fiat-Shamir-recovered group element before hashing
  (defence-in-depth).

- **17.4 Bayer-Groth shuffle NIZK** — see "Verifiable shuffle NIZK"
  section above. Soundness gap closed.

- **17.5 Chaum-Pedersen OR bit proof** (`MpsvsBitProof.{h,cpp}`) —
  proves committed value ∈ {0, 1}. `commitBit` enforces the bit
  precondition at construction (throws for non-boolean input) —
  stricter than the earlier "verify-time rejection" pattern.

- **17.6 Reciprocal algebraic verification** (`MpsvsReciprocalVerify.*`)
  — after a Goldschmidt reciprocal, check y_fp · x ≈ 2^f via
  authenticated Beaver mult. Catches malicious server returning wrong
  reciprocal. Shared-α variant available.

### Production hardening (9 modules)

Retrofit lifting MPSVS from "malicious-secure crypto primitive" to
"deployable production system." Each module addresses a specific
regulator-facing operational concern.

| Module | Purpose |
|---|---|
| `MpsvsProdHygiene` | CSPRNG (libsodium `randombytes_buf`), `SecureU64`/`SecureBuffer` RAII (memzero on scope exit), `AbortReport` hash-chain, `Result<T>` |
| `MpsvsConfig` | Runtime-loadable operational params (ρ budget, k-anon threshold, cover K range, bucketing, log paths); SHA-256 canonical hash for change-control audit chain |
| `MpsvsCryptoParams` | Security-proof-derived params (λ, σ_stat, MAC field, batch sizes, LPN regime); cross-parameter validation tied to math suite (`breakEvenBucketCount(n)`, `minSacrificeBatch(σ, k)`, `maxDpDelta(σ)`) |
| `MpsvsConstTime` | Branch-free `ctEq`/`ctLt`/`ctMux` for secret-dependent comparators + `ctMemcmpEq` via libsodium |
| `MpsvsKeyStore` | Encrypted-at-rest key persistence (libsodium `secretstream_xchacha20poly1305` + Argon2id passphrase KDF). Includes `HsmKeyStore` stub with documented PKCS#11 attachment point |
| `MpsvsSecureChannel` | Mutually-authenticated encrypted byte channel (X25519 `crypto_kx` + XChaCha20-Poly1305), MITM detection via peer-public-key pinning, clean TAG_FINAL shutdown |
| `MpsvsAuditPersist` | Append-only tamper-evident file with SHA-256 hash chain (survives crash, verify on load) |
| `MpsvsMetrics` | Prometheus text-format counters, gauges, histograms (mpsvs_mac_check_total, mpsvs_abort_total, mpsvs_rho_spent, ...) |
| `MpsvsTopology` | Per-session state machine: DKG → OPRF → per-role client state + SP-audit transcript |

### Scale test — 1 000 000 firms × 20 sectors × MAS = 10 % subset

`tests/unit/test_mpsvs_scale_1M` runs the semantic-reference pipeline
end-to-end. Panel: 1M firms, 20 sectors (uniform ≈ 50 000 firms /
sector), MAS covers 100 474 firms (10.0 %), DOS + MOM cover all.

Single-threaded wall-clock:

| Phase | Time |
|---|---|
| Panel generate | ~100 ms |
| Phase 5 inclusion | ~170 ms |
| Phase 11 sector aggregation (9 metrics × 20 sectors) | ~490 ms |
| Phase 12 k-anon gate | <1 ms |
| **Total** | **~790 ms** |

Peak RSS ~515 MB. Released cells: **160 / 180** (89 %) — 20 Gap-metric
cells suppressed for lack of data; every other metric × sector cell
clears k-anon at threshold 5 by 3+ orders of magnitude. DP-noised
release (ρ = 0.1, δ = 2⁻⁴⁵) shows σ_per_party ≈ 2.24 — noise
magnitude ~1 000× below signal, high-utility at this scale.

### Multi-agent audit + fix cycles

Two full cycles of multi-agent security audit (parallel Gemini reviewers
+ Explore agent) have been run. Each cycle catches Critical / Major /
Minor findings, filters false positives, applies fixes, re-audits.

**Cycle 1** (post-crypto-primitive migration): 5 Critical + 3 Major
audit findings. All fixed in code. Notable fixes:
- **BG shuffle NIZK soundness gap** — verifier now recomputes products
- **RowTag::key β=13 support** — bit-aligned slicing (was throwing)
- **Schnorr / DLEQ point-validity guard** — reject invalid FS-recovered R
- **N > 2 OLE guarded** — throws; MPSVS is fixed at N=2 by design

**Cycle 2** (post-shared-α migration): 2 Critical + 2 Major surfaced
by Explore agent. All fixed:
- **openWithMacCheckShared commit-then-verify was tautological** —
  restructured into two-phase API with post-commit-tamper regression test
- **Batch Ω-check sampled r locally per element** — replaced with
  Fiat-Shamir-derived challenges over full share transcript
- **α_i = 0 edge case** — `generateAlpha` resamples until no zero share
- **authSecureMultiplyShared missing N==2 guard** — added

### Test coverage — 21 test binaries

All PASS (semantic ref + wire-level + malicious catch-rate):
- Foundation: `test_mpsvs_prod_hygiene`, `test_mpsvs_config`,
  `test_mpsvs_crypto_params`, `test_mpsvs_const_time`,
  `test_mpsvs_key_store`, `test_mpsvs_secure_channel`,
  `test_mpsvs_audit_metrics`
- MAC primitives: `test_mpsvs_auth_share`, `test_mpsvs_auth_share_prod`,
  `test_mpsvs_auth_share_dpsz`, `test_mpsvs_shared_alpha_e2e`,
  `test_mpsvs_sacrifice`
- NIZK: `test_shuffle_nizk_bg`, `test_mpsvs_shuffle_nizk`,
  `test_mpsvs_bit_proof`
- OT / OLE / OPRF: `test_mpsvs_ole_integration`, `test_mpsvs_oprf`
- Algebraic invariants: `test_mpsvs_reciprocal_verify`
- Adversarial catch-rate: `test_mpsvs_adversary_catalog`
  (5 attack vectors × 200 trials = **1 000 attacks, 100 % caught**)
- End-to-end: `test_mpsvs_malicious_e2e`, `test_mpsvs_dp_prod`
- Scale: `test_mpsvs_scale_1M`

### Configuration example

Sample regulator-editable config: `config/mpsvs.conf.sample`

```
dp_rho_per_query = 0.1
k_anon_threshold = 5
cover_k_min = 3
cover_k_max = 15
bin_beta = 13
bin_tau_bits = 71
bucket_count = 128
audit_log_path = /var/log/mpsvs/audit.log
metrics_bind = 0.0.0.0:9090
```

Any change to this file changes `configHash`; the hash lands in the
tamper-evident audit chain via a `CONFIG_LOAD` entry, so any post-hoc
reviewer can prove which config produced which release.

### Unit test suite

45 unit-test binaries; run all via CTest or the individual smoke
scripts. Adding one covering example:

```bash
python3 build.py -DVOLE_PSI_BUILD_TESTS=ON -DVOLE_PSI_ENABLE_BOOST=ON
for t in out/build/linux/tests/unit/test_*; do "$t"; done
```

Coverage:
- Baseline (pre-existing): mpstar_crypto, kdf, osn_semantics
- MAC primitives (R25): mac, auth_cascade
- Shuffle simulator (R26): cgp_shuffle
- Private join (R29-R32): oblivious_sort, join_expander, join_filter,
  join_e2e
- MPC pipeline (R34a-j): secret_share, secure_compare, mpc_sort,
  mpc_join
- Real OLE (R34k): ole_triple
- Wire MPC (R34k-remain, R36b, R36c): mpc_wire, mpc_wire_ops,
  mpc_wire_driver
- NIZK (R27, R27b): shuffle_nizk, shuffle_nizk_bg
- OLE-α (R28): ole_alpha

### Scale benchmarks

```bash
./out/build/linux/tests/benchmarks/bench_mpc_join
```

Sweeps `(N, M, |universe|, rowDataBits)` and reports Beaver triple
count, preprocessing / online / plaintext wall-clock. Results captured
in `docs/PRIVATE_JOIN_DESIGN.md` §R35.

## Double-blind XGBoost VFL demo (`demos/`)

An end-to-end mock showing how the MPSA + MPC primitives compose into
a real ML workload: vertical federated XGBoost training under a
double-blind threat model.

```
demos/vfl_xgboost_double_blind.py    # runnable demo
tests/test_vfl_xgboost_demo.py       # 9-check validation harness
```

Setup:
- **Party A** holds features `X_A` (private to A). No labels.
- **Party B** holds features `X_B` **and** labels `y` (private to B).
- Neither party sees the other's raw values. Only per-node aggregate
  `(G_L, H_L)` gradient/hessian sums are revealed to Party B — matches
  the SecureBoost / HeteroSecureBoost / FATE threat model.

Run:
```bash
python3 demos/vfl_xgboost_double_blind.py \
    --n-train 400 --n-test 200 --rounds 8 --depth 3
```

Test:
```bash
python3 tests/test_vfl_xgboost_demo.py   # 9/9 PASS
```

The validation harness verifies:
1. **Correctness**: identical accuracy vs plaintext baseline across
   10 configurations (5 seeds × 2 depths).
2. **Security**: API discipline enforces Party A can only manipulate
   opaque ciphertext handles; only Party B decrypts.
3. **Cross-party utility**: real split contribution from both parties
   (typically ~57% A / ~43% B on the default dataset).
4. **Nontrivial signal**: model beats a random baseline meaningfully.
5-9. Sanity checks: mock Paillier arithmetic, logistic-loss gradients,
   XGBoost leaf/gain formulas, determinism, linear cost scaling.

The mock Paillier layer emulates additively-homomorphic encryption
exactly; in the C++ codebase it can be replaced by either a real
Paillier library or additive secret sharing over `MpMpcWire`
(`secureAnd` + reveal). The choice is a library integration, not a
protocol change.

## Test dataset sizes

All smoke datasets are synthetic (never real / production data) and
generated at runtime. Typical sizes:

| Test | Generator | Per-sender rows | On disk |
|---|---|---:|---:|
| `run_mpsa_smoke.sh` (cascade MPSA baseline) | `gen_mpsa_dataset.py --total 1000 --intersect 100` | 1000 | ~35 KB (3 senders → ~104 KB) |
| `run_mpsa_wide_smoke.sh` (wide payload W=4) | same, `--W 4` | 1000 | ~70 KB (3 senders → ~209 KB) |
| `run_mpsa_join_smoke.sh` (trusted-SP table join) | `gen_mpsa_join_dataset.py --intersect 5 --extra 3 --M 2 --W 2` | 5-13 (variable per id) | ~5 KB total |
| `run_mpsa_mpc_join_smoke.sh` (SP-blind MPC join) | same, `--N 2 --M 2 --W 1` | ~6 | ~1 KB total |
| `demos/vfl_xgboost_double_blind.py` | in-memory synthetic binary classification | 600 samples × 4 features | — |
| `tests/test_vfl_xgboost_demo.py` correctness suite | in-memory | 450 samples × 4 features per test | — |
| `tests/benchmarks/bench_mpc_join` | in-memory | `|universe| ∈ {1..16}`, `M ∈ {1..8}` | — |

These are **test-scale** artifacts sized to run in seconds on a single
laptop. The base 2-party PSA paper (see citation below) reports scaling
to 1M records in 35 s; the multiparty and MPC extensions here have not
yet been benchmarked at that scale end-to-end.

## Installation & Run
⚠️ Note: Building the application may take more than 20 minutes to complete depending on your system.

### Option 1: Docker (Recommended)
```bash
# Clone repository
git clone https://github.com/DTC-NTU/PSI-DTC.SG.git

# Build and launch container
docker-compose build && docker-compose up
```
Docker automatically handles all dependencies

### Option 2: Manual Build (Linux Only)
⚠️ Requires Pre-installed Dependencies, the commands can be found inside the `dockerfile`.


```bash
# 1. Clone repository
git clone https://github.com/DTC-NTU/PSI-DTC.SG.git

# 2. Build project
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON

# 3. Run services in separate terminals:
# Service Provider (Service Provider)
./out/build/linux/frontend/frontend -SpHsh ./dataset/cleartext.csv -r 2 -csv -hash 0

# Receiver (Bob)
./out/build/linux/frontend/frontend -SpHsh ./dataset/receiver.csv -r 1 -csv -hash 0

# Sender (Alice)
./out/build/linux/frontend/frontend -SpHsh ./dataset/sender.csv -r 0 -csv -hash 0
```

### Expected Terminal Output
After the application is built and executed, you should see 3 new files starting with `out_` within the `dataset` folder.


## Input and Output Validation

To verify the correct execution, you can inspect the input and output files:

### Input Data Format

The input files from Alice and Bob are **CSV files** with the following format:

- **Column 1**: ID
- **Column 2**: Attribute/Payload (Alice's or Bob's, depending on the file)

For example:

**Alice Input CSV** (`dataset/sender.csv`):

```
FIMbdVN0P2hWkmQp,697626930337
bg4t3fVY1Tw3ASlv,61650378238787
6jJykxRGyuCz5ciy,43313803051
yKE23VylSP1OKELN,75738363176449
OGvQHQP2rm4D6GZR,006609232196
WkYkdx24K2t646BK,658936928362438
...
```

**Bob Input CSV** (`dataset/receiver.csv`):

```
FIMbdVN0P2hWkmQp,intersection8
bKdYp0OZYmlCwUXx,apple
B9syDpwL6b8jUTr5,elephant
lUcaUy90isDcKkaV,dog
rQR2DOLJxU0PvrVe,zebra
0EadHpwt7NqUE3tF,intersection6
...
```

### Output Data Format

The expected output file, `dataset/out_cleartext.csv`, will have the following format:

- **Column 1**: Attribute/Payload from Alice 
- **Column 2**: Attribute/Payload from Bob

For example:

**Output CSV** (`dataset/out_cleartext.csv`):

```
intersection8,697626930337
...
```

## Research and Citation

For more details, access the full paper via DOI:  
[10.48550/arXiv.2410.04746](https://arxiv.org/abs/2410.04746)

If you use this code in your research, please cite:

```
@article{article,
author = {Wang, Jiabo and Huang, Elmo and Duan, Pu and Wang, Huaxiong and Lam, Kwok-Yan},
year = {2024},
title = {PSA: Private Set Alignment for Secure and Collaborative Analytics on Large-Scale Data},
doi = {10.48550/arXiv.2410.04746}
}
```

## Licensing

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author

- **Elmo Xuyun Huang**
