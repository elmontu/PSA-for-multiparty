# MPSA Security Analysis

This doc is the **capstone** of the multipsa extension's research arc. It
synthesizes the threat model across all protocol layers (rounds 1-18),
states what each layer defends against and what it doesn't, and analyzes
how the protocol composes with downstream consumers (notably the user's
own Federated Learning deployment pipeline).

## 1. Protocol overview

```
              ┌─────────────────────────────────────┐
              │  Service Provider (SP)              │
              │  ─ coordinates, holds NO inputs     │
              │  ─ orchestrates intersection +      │
              │    cascade shuffle                  │
              └─────────────────────────────────────┘
                          ▲    ▲    ▲
                          │    │    │   sender↔SP sockets +
                          │    │    │   per-round OSN sockets +
                          │    │    │   reveal socket
              ┌───────────┼────┼────┼────────┐
              │           │    │    │        │
       Sender 0 ── peer mesh ── Sender 1 ── peer mesh ── Sender 2
       (input  c_0)               (input c_1)            (input c_2)
```

**Per protocol invocation:**

1. Senders + SP establish TCP topology (per-sender SP socket, per-round
   OSN sockets, reveal socket, peer-mesh sockets between every sender pair).
2. SP picks a per-session 32-byte `sessionId`, broadcasts to all senders.
3. SP↔sender DH handshake — X25519 by default; X25519 + KEM hybrid with
   `-pq`. Output: per-pair 32-byte session key.
4. Sender↔sender DH handshake via peer mesh (`MpStarSetup`, X25519).
   Output: per-pair pairwise keys.
5. N-party Simple-Hash MPSI: SP picks AES key, senders hash their IDs,
   SP intersects. Output: `C = |I|`, per-sender bitvec of intersection
   positions.
6. Optional padding: `Ceff = max(C, C_max)` if `-cmax` set. Senders +
   SP pad payloads to `Ceff` with PRNG dummies.
7. Each sender ships AEAD'd masked column `m_i = c_i ⊕ r_i` to SP.
8. Phase 0 commit-and-open: each sender j>0 broadcasts
   `commit_j = H(serialize(r_j) || nonce_j)` to all peers, then sends
   `(serialize(r_j), nonce_j)` AEAD'd to sender 0. Sender 0 verifies the
   commit opens correctly.
9. Cascade shuffle: `N-1` rounds, each driven by a different sender. Per
   round: two OSN calls (M-side, R-side) with the same seeded routing
   permute all N parallel payload columns. AEAD'd `ρ_k` to SP, AEAD'd
   mask handoff to next sender.
10. Final reveal: last sender ships its `R_final` to SP under SP key.
11. SP reconstructs `result[c][j] = M_final[c][j] ⊕ R_final[c][j]`,
    writes CSV.

## 2. Threat model

**Adversary capabilities** assumed:

- **Network adversary** (Dolev-Yao): can drop, reorder, or inject TCP
  packets but cannot break X25519, ML-KEM-768, SHA-2 / Blake2b,
  XSalsa20-Poly1305, or AES-128 within feasible computation.
- **Up to N-1 corrupted senders + the SP**: any strict subset can
  collude. At least one sender must remain honest.
- **No TEE / no hardware root of trust** (per user's deployment-context
  hard rule).

**Out of scope:**

- Side channels (timing, power, EM, cache).
- Software supply-chain attacks (compromised libsodium / coproto build).
- Quantum CRQC against X25519 when `-pq` is NOT set (use `-pq` to defend).

## 3. Layer-by-layer security claims

| Layer | Defends against | Notes / residual leak |
|---|---|---|
| **TCP topology** | Off-path injection | On-path adversary can reorder; subsequent AEAD layers catch |
| **`sessionId` broadcast** | Cross-session ciphertext replay | SP picks fresh per invocation; binds every AEAD that follows |
| **MpSpHandshake (X25519)** | Passive eavesdropper, classical adversary | Vulnerable to future CRQC against X25519 — see `-pq` |
| **`-pq`: MpHybridHandshake** | Above + harvest-now-decrypt-later quantum attacker | Currently uses `StubKem` (NOT secure); swap to liboqs `LiboqsMlKem768` for real PQ |
| **`deriveSessionKey(base, sessionId, purpose)`** | Cross-purpose key reuse | Domain-separated by `purpose` tag |
| **MpStarSetup (sender↔sender X25519)** | Pairwise key exchange | Still X25519-only; PQ extension noted in `PQ_HYBRID_HANDSHAKE_DESIGN.md` |
| **RsMpsi (Simple-Hash)** | Hides non-intersection IDs from SP | SP **learns** `C = \|I\|` (residual leak) — see `CARDINALITY_HIDING_DESIGN.md` |
| **`-cmax` output padding** | Hides exact `C` from output-file observers | SP itself still learns `C` from MPSI; full hiding needs Circuit-PSI |
| **AEAD on `m_i` (under SP key)** | Tampering / forgery of masked columns | secretbox = XSalsa20-Poly1305; INT-CTXT + IND-CCA |
| **AEAD on Phase 0 `r_j` handoff (under pairwise key)** | Tampering of mask shares in transit | Forward-secret via ephemeral DH |
| **Phase 0 commit-and-open** | Sender j equivocating `r_j` across recipients; post-protocol repudiation | Commits bind sender j's `r_j`; mismatch → abort with attribution |
| **AEAD on cascade `ρ_k` (under SP key)** | Tampering of re-randomizers per round | One AEAD per round per direction |
| **AEAD on final reveal `R_final`** | Tampering of the final unmask step | Last sender's only direct path to SP |
| **OSN-cascade shuffle** | Hides input→output position mapping | Random per-round permutations; 1-out-of-N honest senders sufficient for unlinkability |
| **Per-round seed derivation** | Each round gets distinct `dest_k` | Avoids the deterministic-seed bug in upstream OSN (we ship `init_wj_seeded`) |

## 4. What's malicious-secure vs honest-but-curious

**Honest-but-curious by default:** all parties follow the protocol; the
crypto hides their inputs from each other beyond what the output reveals.

**Malicious-resistant elements** (catch deviations from the protocol):

| Attack vector | Defense | Round added |
|---|---|---|
| Network MITM modifies a ciphertext | AEAD MAC fails → abort | always |
| Replay of an old ciphertext | sessionId-bound KDF rejects | Round 5 |
| Sender j tampers with `r_j` in transit to sender 0 | AEAD MAC fails | always |
| Sender j sends *different* `r_j` to different recipients | Round 16 commit-and-open broadcast | Round 16 |
| External party observes `out_mpsa.csv` and counts to learn `C` | `-cmax` padding | Round 17 |
| Future CRQC breaks X25519 session keys | `-pq` hybrid handshake (StubKem placeholder; real KEM swap-in spec'd) | Round 18 |

**Still semi-honest only** (NOT malicious-secure):

- Sender k drives round k's OSN dishonestly (submits wrong `R_k` to OSN).
  The OSN itself is semi-honest; SP gets corrupted output and cannot
  attribute the corruption to sender k cryptographically.
- SP itself misbehaves during the OSN (it's the OSN-receiver providing
  `M_k`).
- Full malicious-secure cascade: design specified in
  `MALICIOUS_CASCADE_DESIGN.md` (per-share GF(2¹²⁸) MAC tags + OSN-twice
  trick + batched verification). ~5 days of focused work to implement.

## 5. Cardinality leakage paths

Even with `-cmax`, three vantage points learn `C`:

| Party | Learns C? | Why |
|---|---|---|
| Service Provider | YES | RsMpsi step counts hash matches at SP |
| Each sender | YES | RsMpsi sends `mCardinality` back to senders |
| Output-file observer (NOT SP or sender) | only `C ≤ C_max` | `-cmax` padding |

To fully hide `C` from SP: replace the Simple-Hash MPSI with one of:
- Circuit-PSI (volePSI's `RsCpsi`; needs the upstream library swap from
  `RSMPSI_VOLE_INTEGRATION.md`)
- Oblivious-cardinality MPC subprotocol (~2-3 days)
- Pre-agreed `C_max` with auditable no-count discipline (zero crypto effort)

See `CARDINALITY_HIDING_DESIGN.md` for the full menu.

## 6. Forward secrecy

- **Per-session DH keypairs**: every X25519 (and KEM, when `-pq` is set)
  keypair is generated fresh per protocol invocation in `MpSpHandshake` /
  `MpHybridHandshake` / `MpStarSetup`. Past session keys are not
  recoverable from later party state.
- **Per-session sessionId**: every AEAD ciphertext is bound to the
  session via `deriveSessionKey(base, sessionId, ...)`. Ciphertext
  recorded in session A cannot be opened in session B even if both
  use the same long-term DH state (which they don't, but defence in depth).

**Limitations:** the AES key used by RsMpsi within a session is broadcast
in the clear to all senders. Within the session this is fine; across
sessions it's fresh because `sysRandomSeed()` rerolls per protocol. If
the same AES key were ever reused across sessions, hash frequencies
would leak — currently not possible by code construction.

## 7. Composition with downstream FL training

The user's broader context (per memory + `~/fl/`) is a Singapore-government
FL deployment pipeline where MPSA is one component of a larger flow. Key
composition points:

### 7a. MPSA → joined dataset → FL training rounds

- MPSA's output is the joined-table CSV (`out_mpsa.csv`).
- A downstream FL trainer reads the join and uses it as the training
  cohort.

**Composition concern:** the FL trainer learns the joined table. If FL
gradients leak training data (DLG / iDLG / GradInversion), the joined
columns become inferrable from gradient updates over many rounds. Mitigate
with DP-SGD on the FL side (orthogonal layer; see your FL guide).

### 7b. Multiple MPSA invocations on overlapping inputs

If the same senders run MPSA repeatedly (e.g., monthly cohort refresh),
the **intersection cardinality** `C` is observed by SP each time. Over `T`
runs, `(C_1, ..., C_T)` is a time series. Even without per-record
deanonymization, this leaks population statistics.

**Mitigations:** (a) `-cmax` padding to a fixed upper bound, removing
temporal variation in observable C from the output side; (b) DP noise
on the cardinality count (`C̃ = C + Laplace(1/ε)` published; not yet
in code).

### 7c. PDPA / IM8 / MAS TRM compliance posture

Mapping to Singapore-government deployment frameworks:

| Requirement | MPSA provides | Gap |
|---|---|---|
| PDPA: no cross-org PII disclosure beyond purpose | ✓ (cryptographic join hides non-intersection rows) | — |
| PDPA Anonymisation Guide: re-identification risk | ✓ (output is per-row payloads; no IDs leaked) | depends on payload entropy |
| IM8 §10.5-10.11 data residency | depends on deployment (TCP topology stays in-country if hosts do) | — |
| CCoP 2.0 audit trail | partial (`-v` mode logs every step; no immutable log yet) | add Ed25519-signed transcript |
| MAS TRM Notice 644 cyber hygiene | mostly ✓ (TLS-like AEAD, fresh keys per session) | malicious-secure upgrade required for FI deployment |
| AI Verify model-risk evidence | not directly applicable (MPSA is data joining, not model) | — |

## 8. What's still genuinely open

Items already documented in their respective design docs:

- **Malicious-secure cascade** (`MALICIOUS_CASCADE_DESIGN.md`) — ~5 days
- **Real ML-KEM via liboqs** (`PQ_HYBRID_HANDSHAKE_DESIGN.md`) — ~½ day
- **Real VOLE-PSI MPSI** (`RSMPSI_VOLE_INTEGRATION.md`) — ~2-3 days port
- **Cardinality hiding from SP** (`CARDINALITY_HIDING_DESIGN.md`) — depends on RsMpsiVole or MPC; minutes to weeks
- **Dummy-row filter tags** (`CARDINALITY_HIDING_DESIGN.md`) — ~½ day

Items not yet specified:

- **Signed transcript for non-repudiation** (CCoP 2.0 audit trail). Each
  party signs a hash of its sent/received messages with Ed25519. SP
  collects + publishes signed transcript. Verifier can prove what
  happened. ~½ day; depends on long-term Ed25519 keypairs distributed
  out of band.
- **DP-protected cardinality release** for the multi-run composition
  concern above. Trivial code (~30 LoC); deeper design needed for proper
  composition accounting.
- **Side-channel hardening** of the Benes-OSN switch evaluation. Out of
  scope until a side-channel threat model is articulated.

## 9. Summary

The committed protocol is **end-to-end functional, semi-honest secure, with
malicious-channel hardening** (AEAD + commit-and-open). Three independent
upgrade paths to deployment-grade security are fully spec'd:
- malicious-secure shuffle (cascade with information-theoretic MACs)
- real-MPSI (Visa-Research/volepsi port)
- PQ-hybrid handshake (liboqs swap-in)

Each design doc gives concrete subtasks + effort estimates. The
prototype's role: demonstrate that the N-party MPSA mechanism works
end-to-end and surface the engineering surface needed for production-grade
deployment.

---

**References to per-topic docs:**
- `RESEARCH_MPSI.md` — original protocol design rationale
- `MALICIOUS_CASCADE_DESIGN.md` — Round 16 capstone
- `CARDINALITY_HIDING_DESIGN.md` — Round 17 capstone
- `PQ_HYBRID_HANDSHAKE_DESIGN.md` — Round 18 capstone
- `MALICIOUS_UPGRADE_ROADMAP.md` — three paths (RSS-3PC, CGP SSS, lightweight sigs)
- `RSMPSI_VOLE_INTEGRATION.md` — port plan for real VOLE-PSI
- `DEFERRED_AUDITS.md` — per-round audit log (rounds 1-18)
- `../CHANGELOG.md` — chronological history
