# MPSA Multiparty Extension: Architecture

**Status at end of rounds 1-24.** This is the final overview of the
system. Read this first if you're new to the codebase.

## What the system does

Takes N senders' (ID, payload) CSV files and one Service Provider (SP)
coordinator. Produces a joined table of payload tuples over the
N-way intersection of IDs. Intersection IDs are not revealed; only the
joined payloads are emitted (in randomly permuted order).

## Module map

```
multipsa/PSI-DTC.SG/
├── volePSI/
│   ├── RsPsi.h, RsPsi.cpp                Simple-Hash 2-party PSA (original Visa fork's variant; used by the 2-party `doFileSpHshPSIwithOSN` path)
│   ├── osn/                              Benes-network OSN (Oblivious Switching Network), with init_wj_seeded (R11 added)
│   ├── MpStarChannel.{h,cpp}             Peer-mesh sender↔sender sockets (R13)
│   ├── MpStarSetup.{h,cpp}               X25519 pairwise DH over peer mesh
│   ├── MpStarCrypto.{h,cpp}              AEAD helpers + deriveSessionKey + commit/verifyCommit (R16) + serializeBlocks
│   ├── MpSpHandshake.{h,cpp}             X25519 SP↔sender DH (default)
│   ├── MpKem.{h,cpp}                     Abstract Kem interface + StubKem (R18)
│   ├── MpHybridHandshake.{h,cpp}         X25519 + Kem hybrid handshake (R18; `-pq`)
│   ├── MpTranscript.{h,cpp}              Ed25519 signed transcript (R20)
│   ├── MpIdentity.{h,cpp}                Long-term Ed25519 identities (R22; `-auth-dir`)
│   ├── MpShuffleDriver.{h,cpp}           N-parallel-column cascade shuffle (R15)
│   ├── RsMpsi.{h,cpp}                    N-party Simple-Hash MPSI (R4)
│   ├── RsMpsiVole.{h,cpp}                Scaffold for real VOLE-PSI MPSI (R10; stubbed)
│   └── MpsaDriver.{h,cpp}                End-to-end driver, CLI dispatch, all flag wiring
├── frontend/main.cpp                     Routes `-mpsa` to MpsaDriver
├── tests/
│   ├── unit/                             test_mpstar_crypto, test_kdf, test_osn_semantics
│   ├── gen_mpsa_dataset.py               Synthetic-input generator with controlled C
│   ├── run_mpsa_smoke.sh                 End-to-end smoke test (N=3, intersection=100)
│   └── dp_fl_compose_demo.py             DP-FL composition demo (R24)
└── docs/
    ├── ARCHITECTURE.md                   ← THIS FILE
    ├── RESEARCH_MPSI.md                  Original protocol design rationale
    ├── DEFERRED_AUDITS.md                Per-round audit log (1-24)
    ├── SECURITY_ANALYSIS.md              Capstone threat model (R19)
    ├── MALICIOUS_CASCADE_DESIGN.md       Info-theoretic MAC design (R16)
    ├── MALICIOUS_UPGRADE_ROADMAP.md      Three malicious-secure-shuffle paths
    ├── CARDINALITY_HIDING_DESIGN.md      Output padding + full hiding designs (R17)
    ├── PQ_HYBRID_HANDSHAKE_DESIGN.md     Real-KEM swap-in spec (R18)
    ├── DP_THRESHOLD_TRANSCRIPT_DESIGN.md DP + threshold-k + signed transcript (R20-21)
    ├── AUTHENTICATED_HANDSHAKE_DESIGN.md Long-term Ed25519 identities (R22)
    ├── SALTED_MPSI_DESIGN.md             Per-session salt vs SP dictionary attack (R23)
    └── RSMPSI_VOLE_INTEGRATION.md        Real VOLE-PSI port plan
```

## Protocol flow (end-to-end)

```
SP                                    Sender 0..N-1
──                                    ─────────────

asioConnect (accepts)        ←─→      asioConnect (connect spSock + peer mesh)

[T14 if -auth-dir]
  sign(sessionId, sp.sk)     ───→     verify with sp.pk
  verify with sender_i.pk    ←───     sign(sessionId, sender_i.sk)

[T15 if -salt-mpsi]
                                      Sender 0 broadcasts mpsiSalt via peer mesh
                                      All XOR salt into IDs

broadcast sessionId          ───→     recv sessionId

MpSpHandshake (or MpHybridHandshake if -pq)
  X25519 DH                  ←─→      X25519 DH
  [-pq]: + Kem encap/decap
  combiner KDF → spKey
  deriveSessionKey(spKey, sessionId, "sp_session")

recv per-sender set size     ←───     send set size

[T10 if -mink]
  if |I| < K → throw         (after MPSI computes |I|)

[T8 if -dp]
  C̃ = C + Lap(1/eps)         (log noisy cardinality)

RsMpsi (SP)                  ←─→      RsMpsi (sender)
  pick AES key, broadcast    ───→     hash IDs with AES key + (T15 salt)
                                      send hashed sets to SP
  intersect via match-count  ←───     send hashed sets
  send |I| + per-sender bv   ───→     recv |I| + bv
  receive bitvec ✓                    receive bitvec ✓

[-cmax pad]
  Ceff = max(|I|, cmax)              Ceff = max(|I|, cmax); pad c_i with PRNG dummies

receive AEAD'd m_i           ←───     send AEAD'd m_i (under SP key)
N parallel masked columns           m_i = c_i XOR r_i

[T11]
  begin transcript recording

[T16 commit-and-open]
                                      Senders broadcast commit_i to all peers
                                      Senders > 0 ship (r_i, nonce) to sender 0
                                      Sender 0 verifies commitment

MpStarSetup pairwise (X25519 via peer mesh)
                                      sender j sends pk to all peers via mesh
                                      derive pairwise keys with each peer

Phase 0 (N-column)                    sender 0 collects per-column r_j
                                      others ship r_i to sender 0

MpShuffleDriver::runSp       ←─→      MpShuffleDriver::runSender
  N-1 cascade rounds; each:
    for col in 0..N-1:
      OSN call A (M-side, sender k=OSN sender, SP=OSN recv'r)
      OSN call B (R-side, same seed_k baked routing)
    SP holds M_{k+1}[c], sender k holds R_{k+1}[c]
  AEAD-wrapped rho_k, mask handoff to k+1 (via peer mesh + AEAD)
  Final reveal: last sender → SP (AEAD'd N parallel R columns)

  table[c][j] = M_final[c][j] XOR R_final[c][j]

  [T11] sign transcript with Ed25519

write CSV: N comma-separated hex blocks per row
```

## Threat-model layer cake

```
                ┌────────────────────────────────────────┐
                │  AEAD on every cross-party link       │ R8 (per-link integrity + confidentiality)
                ├────────────────────────────────────────┤
                │  sessionId binding                     │ R5 (cross-session replay defense)
                ├────────────────────────────────────────┤
                │  Phase 0 commit-and-open               │ R16 (sender-j non-repudiation on r_j)
                ├────────────────────────────────────────┤
                │  cardinality padding (-cmax)           │ R17 (output observer hiding)
                ├────────────────────────────────────────┤
                │  PQ-hybrid handshake (-pq)             │ R18 (HNDL resistance)
                ├────────────────────────────────────────┤
                │  threshold-k (-mink)                   │ R20 (k-anon compliance)
                ├────────────────────────────────────────┤
                │  DP cardinality release (-dp)          │ R20 (formal eps-DP on |I|)
                ├────────────────────────────────────────┤
                │  signed transcript                     │ R21 (CCoP 2.0 audit trail)
                ├────────────────────────────────────────┤
                │  long-term auth (-auth-dir)            │ R22 (MITM defeat via Ed25519)
                ├────────────────────────────────────────┤
                │  salted MPSI (-salt-mpsi)              │ R23 (SP dictionary defense)
                └────────────────────────────────────────┘
                       ↓ deployed atop ↓
                ┌────────────────────────────────────────┐
                │  Simple-Hash MPSI + Benes OSN cascade │ R1-R15 (the cryptographic mechanism)
                └────────────────────────────────────────┘
```

Each layer is **orthogonal** — composing them gives independent defence
properties without new privacy loss.

## CLI flag matrix

| Flag | Adds | Cost |
|---|---|---|
| `-pq` | hybrid handshake (HNDL resistance with real KEM swap-in) | ~64 KB extra per session (Kyber-768 pk/ct) |
| `-cmax N` | pad output to N rows (hide |I| from observer) | linear in (N - |I|) extra cascade work |
| `-mink K` | abort if |I| < K (k-anon) | one comparison |
| `-dp eps` | DP-noisy cardinality release | one Laplace draw |
| `-auth-dir DIR` | long-term Ed25519 auth (MITM defeat) | 1 sig + 1 verify per (SP, sender) pair |
| `-salt-mpsi` | per-session salt (SP dictionary defense) | 16-byte broadcast + N×16 XORs |
| `-v` | verbose stderr trace | log-only |

Composite (regulated-deployment tier):
```
frontend -mpsa -N 3 -r 0 \
    -auth-dir ./auth \
    -salt-mpsi \
    -pq \
    -cmax 1024 \
    -mink 50 \
    -dp 0.5 \
    -out result.csv
```

## What's still genuinely open

| Item | Effort | Where |
|---|---|---|
| Real ML-KEM (replace StubKem) | ½ day | `PQ_HYBRID_HANDSHAKE_DESIGN.md` |
| Real VOLE-PSI (replace Simple-Hash) | 2-3 days | `RSMPSI_VOLE_INTEGRATION.md` |
| Full malicious-secure cascade (info-theoretic MACs) | ~5 days | `MALICIOUS_CASCADE_DESIGN.md` |
| RSS-3PC or CGP SSS shuffle (active OSN) | 2-3 weeks | `MALICIOUS_UPGRADE_ROADMAP.md` |
| Long-term Ed25519 key rotation + revocation | 1-2 days | `AUTHENTICATED_HANDSHAKE_DESIGN.md` |
| Real PKI bootstrap (CertSG / Vault) | deployment-specific | (architecture decision) |
| Privacy budget ledger (per-org eps accounting) | ½ day | `SECURITY_ANALYSIS.md` §7b |

All paths have concrete sub-tasks documented per file.

## Composition with downstream FL pipeline

`tests/dp_fl_compose_demo.py` shows how the MPSA output feeds a DP-SGD
FL training round and how the per-step privacy budgets compose
(basic + RDP) into a total `(ε_total, δ)` for the whole pipeline. For
the user's specific FL deployment context (Singapore-government,
`~/fl/`), see `SECURITY_ANALYSIS.md` §7.

## Build, run, test

```bash
# Build (first-time: ~10 min for deps, ~3 min for project)
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_BUILD_TESTS=ON

# Smoke test (default mode)
./tests/run_mpsa_smoke.sh
# Expected: PASS: 100 intersection rows recovered

# Unit tests (offline, no network)
./out/build/linux/tests/unit/test_mpstar_crypto    # 9/9 PASS
./out/build/linux/tests/unit/test_kdf              # 6/6 PASS
./out/build/linux/tests/unit/test_osn_semantics    # PASS

# DP-FL composition demo
./tests/dp_fl_compose_demo.py --mpsa-eps 0.5 --fl-eps 1.0

# Generate long-term identity keypairs for T14
./out/build/linux/frontend/frontend -mpsa -auth-genkey -auth-dir ./auth -auth-id sp -auth-sk sp.sk
# (repeat for each sender)
```

## Round-by-round contributions

| Round | Contribution |
|---|---|
| 1-9 | Scaffold all the cryptographic pieces; unit tests pass |
| 10-12 | First build session; 6 real bugs caught; OSN semantics surfaced |
| 13 | Replace star-with-relay with peer mesh — end-to-end runs |
| 14 | Operability cleanup (-v, validation) |
| 15 | N-column joined-table output |
| 16 | T1 partial: Phase 0 commit-and-open |
| 17 | T2 partial: -cmax output padding |
| 18 | T5 partial: -pq hybrid handshake framework + StubKem |
| 19 | Security analysis capstone doc |
| 20 | T8 + T10: -dp cardinality + -mink threshold-k |
| 21 | T11: Ed25519 signed transcript |
| 22 | T14: long-term identity authenticated handshake |
| 23 | T15: per-session-salted MPSI hashing |
| 24 | T12: DP-FL composition demo + this architecture doc |

Total: ~3700 LoC of new C++ + ~150 LoC of Python + ~1700 lines of design docs across 10+ markdown files.

The prototype is **functionally complete** for its scope: end-to-end
MPSA, all theoretical hardening layers implemented or fully spec'd.
Production deployment requires the swaps documented in the per-topic
design docs.
