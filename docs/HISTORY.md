# Repository History — R25 through MPSVS Rev 7

**Scope.** Consolidates the R25-R37 session summaries, theory/OIRA
documents, and per-fix change logs that predated the MPSVS Rev 7 push.
This is context, not a current-state reference — see
[`PROTOCOL.md`](PROTOCOL.md), [`SECURITY.md`](SECURITY.md), and
[`DESIGN.md`](DESIGN.md) for the current state.

Full historical text of every consolidated doc is recoverable via
`git log --follow` on commits before `2026-07-27`. Files that were
consolidated:

- `R25_R35_SESSION_SUMMARY.md`, `DEFERRED_WORK_R36.md`, `AUDIT_R37.md`
- `THEORY_OIRA_FUNCTIONALITY.md`, `THEORY_OIRA_IMPOSSIBILITY.md`,
  `THEORY_TDR.md`, `THEORY_PAPER_OUTLINE.md`
- `OIRA_CONSTRUCTION.md`, `OIRA_THREAT_MODEL.md`
- `FIX_A_MSET_ROW_INTEGRITY.md`, `FIX_A_SUM_INTEGRITY.md`,
  `FIX_A1_SHUFFLE_SEED.md`, `FIX_C4_OSN_SEEDS.md`,
  `FIX_STAGE_B_MPSI_VOLE.md`
- `PROBLEM_STATEMENT.md`, `ARCHITECTURE.md`, `RESEARCH_MPSI.md`,
  `RSMPSI_VOLE_INTEGRATION.md`, `SALTED_MPSI_DESIGN.md`,
  `DEPLOYMENT_BOTH_BLIND.md`, `DESIGN_VULN_SCORE.md`,
  `PRIVATE_JOIN_DESIGN.md`

---

## Timeline

### Origin — 2-party PSA paper (2024)

Foundational construction: Wang / Huang / Duan / Wang / Lam,
"PSA: Private Set Alignment for Secure and Collaborative Analytics on
Large-Scale Data" (arXiv:2410.04746). Two-party dataset join via
PSI + Oblivious Switching Network. Reported 35.5 s on a 1M-record
dataset — ~100× over prior methods.

Retained in this repo as `-SpHsh` CLI mode. Codebase entry points:
`frontend/main.cpp` (SpHsh routing), `volePSI/fileBased.cpp`.

### R25 — MAC-authenticated primitives

Foundation for malicious security. Delivered:
- `MpMac.{h,cpp}` — GF(2¹²⁸) MAC algebra via `oc::block::gf128Mul`
- `MpAuthCascade.{h,cpp}` — MAC-propagating cascade simulation

### R26 — CGP secret-shared shuffle

Design + implementation of a Cheon-Gundermann-Paterson-style
composed shuffle: S1 applies π₁, S2 applies π₂, joint π = π₂∘π₁
hidden from both.
- `MpCgpShuffle.{h,cpp}` — in-memory reference
- `MpShuffleDriver.{h,cpp}` — driver

### R27 → R27b → R27c — Shuffle NIZK

Publicly-verifiable proof that the cascade output is a permutation of
its input. Iteration ladder:
- **R27** (`MpShuffleNizk`): Schwartz-Zippel prototype on
  weighted-sum polynomial evaluation. Sound only for original-side
  weighted-commitment check.
- **R27b** (`MpShuffleNizkBg`): Bayer-Groth-inspired with
  sum-of-commitments homomorphism. Documented **residual soundness gap**
  around sum-preserving multiset tampering.
- **R27c** — planned full recursive Bayer-Groth (out of scope; never
  implemented).
- **MPSVS Rev 7 cleanup**: R27b gap **closed** via sound-with-reveal
  variant. See [`DESIGN.md`](DESIGN.md) §4 and
  [`SECURITY.md`](SECURITY.md) §5.1 C1.

### R28 — OLE-α

SPDZ-style additively-shared α with trusted-dealer OLE
(`MpOleAlpha.{h,cpp}`). libOTe `SilentVole` substitution documented
as a mechanical follow-up.

### R29 – R32 — Private-join primitives

Foundation for table-valued cross-product private-join:
- `MpObliviousSort.{h,cpp}` — bitonic; structurally oblivious
- `MpJoinExpander.{h,cpp}` — window detect + cross-product expansion
- `MpJoinFilter.{h,cpp}` — oblivious filter via second sort
- `MpsaJoinDriver.{h,cpp}` — in-memory oracle
- `MpsaJoinDriverWire.{h,cpp}` — wire protocol (trusted-SP)

CLI: `-mpsa-join`.

### R33 – R34 — SP-blind MPC pipeline

Full MPC variant where SP never sees plaintext.
- `MpSecretShare.{h,cpp}` — additive shares (Z_{2⁶⁴} arithmetic +
  Z_2 boolean)
- `MpBeaverTriple.{h,cpp}` — trusted-dealer Beaver + SPDZ mult
- `MpSecureCompare.{h,cpp}` — 64-bit LT (256 triples) + equality
  (63 triples) on XOR-shared bits
- `MpMpcSort.{h,cpp}` — bitonic composing swap + LT
- `MpMpcJoin.{h,cpp}` — end-to-end SP-blind join
- `MpsaJoinMpcDriver.{h,cpp}` — driver

CLI: `-mpsa-join-mpc`.

### R34k — Wire-level MPC

Real 2-party OLE via libOTe `SilentOtTriple` — closes the
trusted-dealer gap for the 2-party case.
- `MpOleTriple.{h,cpp}` — thin wrapper. Neither party learns
  peer's triple shares.
- `MpMpcWire.{h,cpp}` — wire versions of `secureAnd`, `secureOr`,
  `secureLessThan`, `secureEqual` over `coproto::Socket`
- `MpMpcWireOps.{h,cpp}` — wire conditional-swap, bitonic sort,
  cross-product expander, `is_intersection` filter
- `MpMpcWireDriver.{h,cpp}` — end-to-end wire MPC private-join

### R36 – R36c — Deferred-work closure

Batched work addressing accumulated deferred audit items:
- Concurrency-safety fixes in `MpStarChannel`
- OSN semantics verified against `osn/OSNSender.cpp`
- CGP-N-party shuffle scaffolding

### R37 — Composability + audit

- `docs/COMPOSITE_SECURITY_THEOREM.md` (now merged into
  [`SECURITY.md`](SECURITY.md) §3)
- `docs/AUDIT_R37.md` + `docs/PRIVACY_AUDIT_R37.md` (per-layer
  privacy audit across all 15 layers; merged into [`SECURITY.md`](SECURITY.md) §4)

### MPSVS Π_SECTORVULN Rev 6 → Rev 7

Domain-specific pivot: away from generic private-join primitives,
toward a regulator-facing sector-vulnerability release pipeline. See
[`PROTOCOL.md`](PROTOCOL.md) for the current spec.

Rev 6 → Rev 7 changes:
- Fixed N=2 compute topology (previously N-flexible)
- Bias-frozen DKG (previously S1-commits-first, S2 could bias Y)
- Explicit cover-firms mechanism (K ∈ [K_min, K_max] injected during
  F_PSA)
- Contribution clip C_max in Phase 12
- k-anonymity gate at k=5 in Phase 12

### MPSVS Rev 7 malicious-secure + production hardening (2026-07-27)

The current commit. Delivered:
- 6 Phase 17 malicious-secure primitives
- 9 production-hardening modules
- 21 test binaries (100% pass, 1000/1000 adversarial catch-rate)
- Two audit cycles (5 Critical + 3 Major + 2 Critical + 2 Major, all fixed)
- 1M-firm scale validation

See [`PROTOCOL.md`](PROTOCOL.md), [`SECURITY.md`](SECURITY.md),
[`DESIGN.md`](DESIGN.md) for the current state.

---

## Theory legacy — OIRA / Output-Inference-Resistant Aggregation

Before the pivot to MPSVS's release-oriented DP model, an earlier
research direction was OIRA — Output-Inference-Resistant Aggregation.
The ideal functionality `F_OIRA` aimed to bound per-item inference risk
across an interactive query stream.

Key findings (from `THEORY_OIRA_IMPOSSIBILITY.md` before consolidation):

- **Impossibility** — per-item OIRA is impossible under general
  auxiliary information (adversary can always concoct a distinguishing
  hypothesis over Θ(1/ρ) queries).
- **TDR** (Tiered Disclosure with Reveal budgets) — a weaker but
  achievable relaxation; grants a bounded reveal budget per tier.
- **Bridge to zCDP** — the practical MPSVS release path uses standard
  zCDP composition rather than the more ambitious OIRA framing. TDR
  ideas influenced the k-anonymity gate + budget-tracker design.

Reason for archival: OIRA turned out to require assumptions (bounded
auxiliary info) that regulators wouldn't sign off on. MPSVS Rev 7 is
the pragmatic descendant.

---

## Fix log — historical stage fixes

Chronological record of specific bug-fixes during the R25-R37 line:

| Fix | Concern | Outcome |
|---|---|---|
| Stage A-mset-row | Cross-column row-integrity in cascade | added mset-row MAC check |
| Stage A-sum | Per-column shuffle-integrity | added per-column sum check |
| Stage A1 | SP could reconstruct cascade permutation via seed leak | seed derived via shared randomness, not published |
| Stage B | Simple-Hash PSI → VOLE-PSI backend | `-mpsi-backend vole` flag added; RsMpsiVole shim |
| Fix C4 | OSN internals used hardcoded PRNG seeds | seed routed through oc::PRNG |

Every historical fix has a corresponding regression test in
`tests/unit/`.

---

## Superseded designs

The following design docs described directions that were prototyped
but ultimately superseded — recoverable from git if useful:

- `SALTED_MPSI_DESIGN.md` — salted MPSI variant; superseded by the
  MPSVS OPRF-based row-tag approach
- `DEPLOYMENT_BOTH_BLIND.md` — earlier both-blind XOR-shared control
  variant; superseded by the (S1, S2) non-colluding compute-node model
- `DESIGN_VULN_SCORE.md`, `DESIGN_VULN_SCORE_V2.md` — 4-party
  intermediate topology explorations before settling on the 5-role
  Rev 7 topology
- `CARDINALITY_HIDING_DESIGN.md` — cardinality-hiding for the 2-party
  cascade; MPSVS handles this via cover firms + k-anonymity instead
- `AUTHENTICATED_HANDSHAKE_DESIGN.md`, `PQ_HYBRID_HANDSHAKE_DESIGN.md`
  — for the legacy MPSA cascade; MPSVS uses `MpsvsSecureChannel` instead
- `MALICIOUS_CASCADE_DESIGN.md` — malicious cascade for the multiparty
  MPSA `-mpsa` path; MPSVS Rev 7 uses SPDZ + BG NIZK + DPSZ shared-α
  instead (see [`DESIGN.md`](DESIGN.md))
- `MALICIOUS_UPGRADE_ROADMAP.md` — roadmap for R25 → malicious;
  substantially fulfilled by MPSVS Rev 7 Phase 17

Most of these embedded threat-model discussions that live on in
[`SECURITY.md`](SECURITY.md).
