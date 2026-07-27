# MPSVS — Multi-Party Sector Vulnerability Statistics

[![DOI](https://img.shields.io/badge/DOI-10.48550%2FarXiv.2410.04746-blue)](https://arxiv.org/abs/2410.04746)
[![Tests](https://img.shields.io/badge/tests-21%2F21%20pass-brightgreen)](#test-suite)
[![Malicious-secure primitives](https://img.shields.io/badge/malicious--secure-6%20primitives-brightgreen)](#phase-17--malicious-secure-primitives)
[![Adversarial catch rate](https://img.shields.io/badge/adversarial-1000%2F1000%20caught-brightgreen)](#test-suite)

**MPSVS** is a domain-specific secure multi-party computation (MPC) pipeline
for regulator-controlled release of **sector-level financial-vulnerability
statistics** — DTI, DSI, DEmp, IPW, Delq, NPL, UnsecShare, StDebtShare — from
sensitive data held by different government agencies, without exposing any
single firm's raw data to any party.

Built from the ground up as a **Π_SECTORVULN Rev 7** design; hardened over
two rounds of multi-agent security audit; validated end-to-end on a
1 000 000-firm synthetic panel.

The repository also retains the earlier **PSA** (Private Set Alignment)
2-party primitives that MPSVS uses as building blocks — see
[`docs/`](#documentation) for the R25–R37 history.

---

## Table of contents

1. [What MPSVS computes](#what-mpsvs-computes)
2. [Threat model & topology](#threat-model--topology)
3. [12-phase protocol](#12-phase-protocol-π_sectorvuln-rev-7)
4. [Phase 17 — malicious-secure primitives](#phase-17--malicious-secure-primitives)
5. [Production hardening (9 modules)](#production-hardening-9-modules)
6. [Quick start](#quick-start)
7. [Configuration](#configuration)
8. [Test suite](#test-suite)
9. [Scale results](#scale-results--1m-firms--20-sectors)
10. [Security audit history](#security-audit-history)
11. [Documentation](#documentation)
12. [Legacy — 2-party PSA and R25–R37 extensions](#legacy--2-party-psa-and-r25r37-extensions)
13. [Citation](#citation)
14. [License / Author](#license--author)

---

## What MPSVS computes

Given three data-input parties (MAS holds loan/debt, DOS holds
income/revenue, MOM holds employment) each with disjoint views of the
same set of registered firms, MPSVS produces per-sector aggregate
vulnerability statistics such as:

- **DTI** = Σ debt / Σ income, per sector
- **NPL** = Σ non-performing / Σ debt, per sector
- **IPW** = Σ income / Σ employees, per sector
- Individual-firm quantiles (p25, p50, p75, p90) per sector
- Composite vulnerability score per sector

with:

- **k-anonymity gate** — cells with fewer than `k` valid firms suppressed
- **Differential privacy** — Gaussian noise calibrated to zCDP `ρ` budget
- **Tamper-evident audit** — SHA-256 hash-chained log; regulator can prove
  which config produced which release
- **Cover firms** — random `K ∈ [K_min, K_max]` synthetic firms injected
  so exact membership counts leak nothing
- **No party ever sees another party's plaintext row**

---

## Threat model & topology

Five roles, deterministically mapped to real Singapore inter-agency
setting:

| Party | Role | What it sees | What it doesn't |
|---|---|---|---|
| **MAS** | data input (loan / debt / delinquency / NPL) | own rows only | any other party's rows; the intersection |
| **DOS** | data input (income / revenue / surplus) | own rows only | same |
| **MOM** | data input (employment / labour / vacancy) | own rows only | same |
| **S1** | MPC compute node | (S1-side of every share) | any full-plaintext value |
| **S2** | MPC compute node (non-colluding with S1) | (S2-side of every share) | same |
| **GT (GovTech)** | orchestrator + release consumer | public policy Φ, DP-noised release, audit chain | **no share, no key, no payload, no membership bit** |

**Adversary models supported:**

- **Semi-honest** — every party follows the protocol but wants to learn
  more than allowed. Full pipeline (`test_mpsvs_e2e`) provides this by
  default.
- **Malicious (S1 vs S2)** — an active adversary controls one of the two
  compute nodes. Phase 17 primitives + DPSZ shared-α catch tampering with
  probability `1 - 2^{-64}` per element (Ω-check bound).
- **Malicious data-input party** — MAS, DOS, or MOM sends bad rows.
  Caught by inclusion-bit gate + range checks + F_PSA duplicate guard.

Not in scope: side-channel attacks on shared hardware; forward secrecy
against a compromised long-term X25519 key (documented tradeoff);
denial-of-service.

---

## 12-phase protocol (Π_SECTORVULN Rev 7)

| Phase | Purpose | Primary module |
|---|---|---|
| 0 | Bootstrap: config load, key ceremony, ctx assembly | `MpsvsConfig`, `MpsvsKeyStore`, `MpsvsTopology` |
| 1 | Local prep: growth/scaling normalisation | `MpsvsLocalPrep` |
| 2 | OPRF DKG + party-side row-tag derivation | `MpsvsOprf` |
| 3 | MAS share aggregation | `MpsvsTopology` |
| 4 | F_PSA alignment: bin → sort → merge → shuffle | `MpsvsAlignment`, `MpsvsAlignmentWire` |
| 5 | Inclusion bits (per-metric membership) | `MpsvsInclusion`, `MpsvsInclusionWire` |
| 6 | Bucketing (log-scale edges) + Goldschmidt reciprocal | `MpsvsRatioBucket`, `MpsvsGoldschmidtWire` |
| 8 | Ranking within (popkey, invalid) | `MpsvsRank`, `MpsvsRankWire` |
| 9 | Composite vulnerability score | `MpsvsComposite`, `MpsvsCompositeWire` |
| 10 | Percentile computation (histogram CDF) | `MpsvsPercentiles`, `MpsvsPercentilesWire` |
| 11 | Sector aggregation (per (sector, period, metric)) | `MpsvsSectorAgg`, `MpsvsSectorAggWire` |
| 12 | DP joint noise + k-anon gate + release | `MpsvsDp`, `MpsvsDpProd`, `MpsvsKAnonGate` |
| 13 | Audit + attestation | `MpsvsAudit`, `MpsvsAuditPersist`, `MpsvsMetrics` |

Full protocol specification: [`docs/PROTOCOL_PI_SECTORVULN_R7.md`](docs/PROTOCOL_PI_SECTORVULN_R7.md).

---

## Phase 17 — malicious-secure primitives

Added on top of the semi-honest baseline. Each catches a specific
adversarial class.

| ID | Primitive | Module | What it catches |
|---|---|---|---|
| 17.1 | SPDZ MAC-authenticated shares (plaintext-α + **DPSZ shared-α**) | `MpsvsAuthShare`, `MpsvsAuthShareProd` | any share tampering by 1 corrupt party |
| 17.2 | OLE-based Beaver triples (`SilentOtTriple` under LPN) | `MpOleAlpha`, `MpOleTriple` | removes trusted-dealer assumption |
| 17.3 | OPRF Chaum-Pedersen DLEQ + Schnorr (with FS-point validity guard) | `MpsvsOprf` | dishonest OPRF hop |
| 17.4 | Bayer-Groth shuffle NIZK (**R27b soundness gap now CLOSED**) | `MpShuffleNizkBg`, `MpsvsShuffleWire` | drop / insert / substitute / sum-preserving swap in F_PSA shuffle |
| 17.5 | Chaum-Pedersen OR bit-membership proof (b ∈ {0,1} enforced at commit) | `MpsvsBitProof` | non-boolean inclusion bit |
| 17.6 | Reciprocal algebraic verify (Goldschmidt output check via authenticated Beaver mult) | `MpsvsReciprocalVerify` | wrong reciprocal from malicious server |

### DPSZ shared-α operator chain (α **never** reconstructed)

The most cryptographically-important upgrade. Under standard SPDZ,
α is the global MAC key — if any party ever holds α in plaintext, that
party can forge MACs. MPSVS ships a parallel API surface where α
remains additively shared across S1 and S2 for the entire session:

| Op | Function | Guarantee |
|---|---|---|
| Open + MAC check | `openWithMacCheckShared` | σ_i = α_i·x - m_i, two-phase commit/reveal |
| Batch Ω-check | `batchOpenWithMacCheckShared` | Fiat-Shamir-derived r_j over full share transcript |
| Beaver mult | `authSecureMultiplyShared` | sharewise α_i·d·e accumulation in MAC of z |
| Sacrifice check | `sacrificeCheckTripleShared` | three sequential shared-α opens |
| Reciprocal verify | `verifyReciprocalAuthShared` | reciprocal invariant under shared-α mult |

`static_assert`s in the test suite lock the signatures — future code
changes that would take `uint64_t alpha` in these paths fail to compile.

---

## Production hardening (9 modules)

Retrofit lifting MPSVS from "malicious-secure crypto primitive" to
"deployable regulator-facing system."

| Module | Purpose | Key features |
|---|---|---|
| `MpsvsProdHygiene` | CSPRNG + memory hygiene + structured abort | libsodium `randombytes_buf`, `SecureU64`/`SecureBuffer` RAII (memzero on scope exit), `AbortReport` hash chain, `Result<T>` |
| `MpsvsConfig` | Runtime operational parameters | Zero-dep key=value parser, 12 validation rules, SHA-256 canonical hash for change-control audit chain |
| `MpsvsCryptoParams` | Security-proof-derived parameters | λ, σ_stat, MAC field, batch sizes, LPN regime; cross-parameter validation tied to `math_rev7_r27_break_even` |
| `MpsvsConstTime` | Constant-time primitives | Branch-free `ctEq`/`ctLt`/`ctMux` + libsodium byte compare; 8 test groups |
| `MpsvsKeyStore` | Encrypted-at-rest key persistence | libsodium `secretstream_xchacha20poly1305` + Argon2id passphrase KDF; `HsmKeyStore` PKCS#11 attachment-point stub |
| `MpsvsSecureChannel` | Mutually-authenticated encrypted byte channel | X25519 `crypto_kx` + XChaCha20-Poly1305; MITM detection via peer-PK pinning; clean TAG_FINAL shutdown |
| `MpsvsAuditPersist` | Tamper-evident audit file | Append-only, SHA-256 hash chain, `flock` + `pread`, atomic rename, chmod-before-rename |
| `MpsvsMetrics` | Prometheus exposition | Counters, gauges, histograms; standard metric names (`mpsvs_mac_check_total`, `mpsvs_abort_total`, `mpsvs_rho_spent`, ...) |
| `MpsvsTopology` | Per-session state machine | DKG → OPRF → per-role client state + SP-audit transcript; session-scoped Beaver bag (no reuse across sessions) |

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/DTC-NTU/PSI-DTC.SG.git
cd PSI-DTC.SG
docker-compose build && docker-compose up
```

### Manual build (Linux)

Requires `libsodium-dev`, C++20 toolchain, CMake ≥ 3.20. Full dep
list in the `Dockerfile`.

```bash
python3 build.py -DVOLE_PSI_BUILD_TESTS=ON -DVOLE_PSI_ENABLE_BOOST=ON
```

### Run the full test suite

```bash
for t in out/build/linux/tests/unit/test_mpsvs*; do "$t"; done
```

Expected: 21/21 PASS + `test_mpsvs_adversary_catalog` reports
1000/1000 attacks caught across 5 attack vectors × 200 trials.

### Scale test — 1 000 000 firms

```bash
out/build/linux/tests/unit/test_mpsvs_scale_1M
```

Runs the semantic-reference pipeline end-to-end. Reports per-sector
release, percentiles, DP-noised counts. See [Scale results](#scale-results--1m-firms--20-sectors).

---

## Configuration

MPSVS uses two config surfaces with different governance:

### `MpsvsConfig` — operational (regulator-editable)

`config/mpsvs.conf.sample`:

```ini
# Differential privacy
dp_rho_per_query      = 0.1
dp_rho_budget         = 3.0
dp_delta              = 1e-6
dp_contribution_clip  = 1000000.0

# k-anonymity gate (Phase 12)
k_anon_threshold      = 5

# Cover firms
cover_k_min           = 3
cover_k_max           = 15

# F_PSA alignment
bin_beta              = 13    # 2^β bins
bin_tau_bits          = 71
bin_cap_per_party     = 256

# Fixed-point (Rev 7 §9)
fp_fractional_bits    = 40
fp_guard_bits         = 8

# Bucketing (Rev 7 R27)
bucket_count          = 128   # must be power of 2

# Operational
audit_log_path        = /var/log/mpsvs/audit.log
metrics_bind          = 0.0.0.0:9090
max_concurrent_sessions = 4
```

**Change-control:** every load computes `configHash = SHA-256(canonical
serialisation)`. The hash lands in the tamper-evident audit chain via a
`CONFIG_LOAD` entry, so any post-hoc reviewer can prove which config
produced which release.

### `MpsvsCryptoParams` — security-proof parameters (crypto-team-owned)

Not user-editable at deployment. Fields include `lambda_bits ≥ 128`,
`sigma_stat_bits ≥ 40`, `mac_field_bits ∈ {32, 64, 128}`,
`oprf_group_name = "ristretto255"`, `silent_ot_regime ∈ {"SD", "EA"}`,
sacrifice/beaver batch sizes.

`validateAgainstOperationalConfig(cp, oc)` surfaces coherence warnings
(e.g. `dp_delta > 2^{-σ}` → statistical DP soundness violation).

---

## Test suite

**21 test binaries, all pass.** Grouped by concern:

### Foundation
`test_mpsvs_prod_hygiene`, `test_mpsvs_config`, `test_mpsvs_crypto_params`,
`test_mpsvs_const_time`, `test_mpsvs_key_store`,
`test_mpsvs_secure_channel`, `test_mpsvs_audit_metrics`

### MAC primitives
`test_mpsvs_auth_share`, `test_mpsvs_auth_share_prod`,
`test_mpsvs_auth_share_dpsz` (shared-α), `test_mpsvs_shared_alpha_e2e`
(Beaver + sacrifice + reciprocal chain, α never reconstructed),
`test_mpsvs_sacrifice`

### NIZK
`test_shuffle_nizk_bg` (5/5 groups including the closed-gap regression
`bg_sum_preserving_swap_now_caught`), `test_mpsvs_shuffle_nizk`,
`test_mpsvs_bit_proof`

### OT / OLE / OPRF
`test_mpsvs_ole_integration`, `test_mpsvs_oprf`

### Algebraic invariants
`test_mpsvs_reciprocal_verify`

### Adversarial catch-rate
`test_mpsvs_adversary_catalog` — **1 000 / 1 000 attacks caught** across
5 attack vectors × 200 trials

### End-to-end
`test_mpsvs_malicious_e2e` (honest-correct, adversarial-caught in the
full pipeline), `test_mpsvs_dp_prod`

### Scale
`test_mpsvs_scale_1M` — see next section

---

## Scale results — 1M firms × 20 sectors

Panel: **1 000 000** firms, 20 sectors (uniform ≈ 50 000 firms/sector).
MAS covers **100 474 firms (10.0 %)** — the loan-borrower subset. DOS
and MOM cover all firms.

**Wall-clock (single-threaded semantic reference):**

| Phase | Time |
|---|---|
| A. Generate synthetic panel | ~100 ms |
| B. Phase 5 inclusion + entity metrics | ~170 ms |
| C. Phase 11 sector aggregation (9 metrics × 20 sectors) | ~490 ms |
| D. Phase 12 k-anon gate | <1 ms |
| **Total** | **~790 ms** |

**Peak RSS: ~515 MB.**

**Released cells: 160 / 180** (89 %) — 20 Gap-metric cells suppressed
for lack of growth data; every other metric × sector cell clears
k-anon at threshold 5 by 3+ orders of magnitude.

Sample DP-noised release (ρ = 0.1, δ = 2⁻⁴⁵, σ_per_party ≈ 2.24)
across all 20 sectors for the DTI metric:

```
sec |    DTI      DSI     DEmp        IPW      Delq       NPL     Unsec    StDebt
----+----------------------------------------------------------------------------
  1 |   0.1015   0.0101     1003    10046   0.0404   0.0396   0.1001   0.0997
  2 |   0.0997   0.0100     1009    10108   0.0402   0.0400   0.0992   0.0999
  3 |   0.0981   0.0099      989     9994   0.0408   0.0406   0.1013   0.1010
 ... (17 more rows)
 20 |   0.0991   0.0100     1000    10042   0.0390   0.0405   0.0999   0.0998
```

Noise magnitude typically ±3–7 on signal of 5 000 (MAS-gated metrics)
or 50 000 (IPW / DOS×MOM metric) — DP overhead ≈ 3-4 orders of
magnitude below signal. Full run: `test_mpsvs_scale_1M`.

---

## Security audit history

Two full rounds of multi-agent security audit (parallel Gemini
reviewers + Explore agent for cross-cutting concerns) surfaced and
resolved critical findings. Full log in
[`docs/SECURITY.md`](docs/SECURITY.md) §5 "Audit findings".

### Cycle 1 — post-crypto-primitive delivery

**Findings:** 5 Critical + 3 Major. All fixed.

| Fix | Where |
|---|---|
| BG shuffle NIZK soundness gap CLOSED — verifier now recomputes products from revealed openings | `MpShuffleNizkBg.cpp` |
| `RowTag::key` β=13 crash fixed via bit-aligned slicing | `MpsvsOprf.cpp` |
| Schnorr / DLEQ point-validity guard on FS-recovered R | `MpsvsOprf.cpp` |
| N > 2 OLE branch guarded (throws; MPSVS fixed at N=2) | `MpOleTriple.cpp` |
| `authSecureMultiply` throws structured `AuthShareMacFailure` (was silent poison-share) | `MpsvsAuthShare.cpp` |
| `sacrificeCheckTriple` uses CSPRNG for public challenge | `MpsvsAuthShare.cpp` |
| `commitBit` rejects non-boolean at construction | `MpsvsBitProof.cpp` |
| `MpsvsDpWire` prod-mode guard (env-var throws in production build) | `MpsvsDpWire.cpp` |

### Cycle 2 — post-shared-α migration

**Findings:** 2 Critical + 2 Major. All fixed.

| Fix | Where |
|---|---|
| `openWithMacCheckShared` commit-then-verify tautology → explicit two-phase API with post-commit-tamper regression test | `MpsvsAuthShare.cpp` |
| Batch Ω-check r_j via Fiat-Shamir over share transcript (was local CSPRNG per element) | `MpsvsAuthShare.cpp` |
| `authSecureMultiplyShared` N==2 guard | `MpsvsAuthShare.cpp` |
| `generateAlpha` resamples if any individual α_i share is zero | `MpsvsAuthShare.cpp` |

### What remains (documented, not blocking release)

- Fuzzing harness (libFuzzer over `parseConfigText`, `decryptBody`,
  `shuffleVerifyBg`, `RowTag::key`) — not yet added
- Forward secrecy in `MpsvsSecureChannel` — documented tradeoff;
  add ephemeral-key handshake if regulator requires
  post-compromise security
- Constant-time σ_i computation — acceptable for in-process reference;
  wire-level should use CT arithmetic or blinding
- Formal verification — no machine-checkable proofs delivered

---

## Documentation

Four consolidated documents in [`docs/`](docs/):

| Doc | Contents |
|---|---|
| [`PROTOCOL.md`](docs/PROTOCOL.md) | Π_SECTORVULN Rev 7 specification: parties, 12 phases, deployment topology, session lifecycle, change control |
| [`SECURITY.md`](docs/SECURITY.md) | Threat model (A1–A6 in scope; B1–B6 explicit out-of-scope), security goals (C, I, DP, AC), composite security theorem, per-layer privacy audit, all closed and deferred audit findings |
| [`DESIGN.md`](docs/DESIGN.md) | Cryptographic-primitive designs: SPDZ MAC (plaintext-α + DPSZ shared-α), OLE Beaver preprocessing, threshold-DH-OPRF + DLEQ + bias-frozen DKG, BG shuffle NIZK (sound-with-reveal), Chaum-Pedersen bit proof, reciprocal verify, DP joint noise transcript, `MpsvsSecureChannel`, `MpsvsKeyStore`, cover firms |
| [`HISTORY.md`](docs/HISTORY.md) | Repository history from the 2-party PSA paper through R25–R37 and MPSVS Rev 7; superseded designs (SALTED_MPSI, both-blind, vuln-score V1/V2, malicious cascade, PQ handshake) recoverable via `git log --follow` |

Prior 39-document layout consolidated into these four on 2026-07-27
(see [`HISTORY.md`](docs/HISTORY.md) for the mapping).

---

## Legacy — 2-party PSA and R25–R37 extensions

MPSVS is built on top of two-party PSA (Private Set Alignment) and its
subsequent multiparty extensions. These remain available via CLI:

### 2-party PSA (paper baseline)

```bash
./out/build/linux/frontend/frontend -SpHsh ./dataset/cleartext.csv -r 2 -csv -hash 0
./out/build/linux/frontend/frontend -SpHsh ./dataset/receiver.csv  -r 1 -csv -hash 0
./out/build/linux/frontend/frontend -SpHsh ./dataset/sender.csv    -r 0 -csv -hash 0
```

Reported paper baseline: **35.5 s on 1M-record dataset join** (~100×
faster than existing methods).

### N-party MPSA (`-mpsa`)

Cascade of N senders + SP; libsodium AEAD; per-session key binding.

```bash
./frontend -mpsa -N 3 -r 0 -port 17500 -out out.csv                  # SP
./frontend -mpsa -N 3 -r 1 -i 0 -port 17500 -host localhost -in ...  # sender 0
# ... one process per sender
```

Hardening flags: `-pq` (hybrid X25519 + KEM), `-cmax N` (cardinality
padding), `-mink K` (threshold-k gate), `-dp ε` (Laplace-noised release).

Smoke: `./tests/run_mpsa_smoke.sh`

### Table-valued private join (`-mpsa-join`) and SP-blind MPC (`-mpsa-join-mpc`)

See [`docs/HISTORY.md`](docs/HISTORY.md) §"R29 – R32" and §"R34k".

### Verifiable shuffle NIZK

- `MpShuffleNizk` (R27 prototype, semi-sound)
- `MpShuffleNizkBg` (**R27b — soundness gap CLOSED per MPSVS Rev 7
  cleanup**; see [`docs/DESIGN.md`](docs/DESIGN.md) §4)

### Double-blind XGBoost VFL demo

```bash
python3 demos/vfl_xgboost_double_blind.py --n-train 400 --rounds 8 --depth 3
python3 tests/test_vfl_xgboost_demo.py    # 9/9 PASS
```

Mock Paillier layer (additive-homomorphic emulation). See the demos
directory for details.

---

## Citation

Foundational 2-party PSA paper:

```bibtex
@article{Wang2024PSA,
  author  = {Wang, Jiabo and Huang, Elmo and Duan, Pu and Wang, Huaxiong and Lam, Kwok-Yan},
  year    = {2024},
  title   = {PSA: Private Set Alignment for Secure and Collaborative Analytics on Large-Scale Data},
  doi     = {10.48550/arXiv.2410.04746}
}
```

MPSVS Π_SECTORVULN Rev 7 (this codebase): pending publication.

---

## License / Author

MIT License — see [`LICENSE`](LICENSE).

**Author:** Elmo Xuyun Huang

**Status:** MPSVS pipeline delivered end-to-end, malicious-secure
primitives audited over two cycles, 21/21 tests pass, 1M-firm scale
validated. Not yet independently penetration-tested. Not formally
verified. See [Security audit history](#security-audit-history) for
what's demonstrated vs what remains.
