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
- `volePSI/MpShuffleNizkBg.*` — R27b Bayer-Groth-inspired with
  cryptographic sum-of-commitments homomorphism check; residual gap
  (sum-preserving multiset tampering) documented.

### Unit test suite

21 unit-test binaries; run all via CTest or the individual smoke
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

## Authors

- **Jiabo Wang**
- **Federico Giorgio Pfahler**
- **Elmo Xuyun Huang**
- **Pu Duan**
- **Huaxiong Wang**
- **Kwok-Yan Lam**
