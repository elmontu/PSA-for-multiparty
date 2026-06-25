# Extending PSA from 2-party to N-party

Author: Elmo Huang, 2026-06-23.
Scope: research brief, not an implementation. Cites only papers the author is confident exist; explicit "uncertain" markers where the literature is hazy.

## 0. Recap of the base protocol

PSA (Wang, Huang, Duan, Wang, Lam — arXiv 2410.04746, 2024) is a 2-sender + Service Provider (SP) protocol implemented in `PSI-DTC.SG`. The data plane is:

1. **PSI core** — VOLE-PSI / RsPSI (Rindal-Schoppmann, Eurocrypt 2021) with an OKVS (Garimella, Pinkas, Rosulek, Trieu, Yanai — Crypto 2021) as the underlying key-value store. Each sender obliviously evaluates an OPRF on their IDs; the SP/receiver checks equality on the masked outputs.
2. **Payload alignment** — a 2-party Oblivious Switching Network (OSN) built from a Benes network (256-wide in this codebase, `volePSI/osn/benes_256/`). One party holds the permutation π, the other holds a payload vector; output is additive shares of π(payload).
3. **SP** coordinates, sees masked traffic, and reconstructs only the joined payload pairs over the intersection.

Codebase confirms the architecture: `RsPsi3rdPSenderA`, `RsPsi3rdPSenderB` (2 senders + 3rd party = SP), classes share an `OSNReceiver` member each.

Goal of this brief: replace **both** the PSI core and the OSN with N-party (N ≥ 3 data-contributing senders) primitives, while preserving the SP star topology and the semi-honest threat model as a baseline.

---

## 1. MPSI core — candidate constructions

### 1.1 Survey

| # | Construction | Comm. (per pty) | Topology | Reuses OKVS / VOLE-PSI? | Sec. model | Reference |
|---|---|---|---|---|---|---|
| A | Kolesnikov-Matania-Pinkas-Rosulek-Trieu (KMPRT) | O(N·\|X\|·λ) | Star or ring | No (BaRK-OPRF, OOS-OT) | Semi-honest, augmented semi-honest | CCS 2017 |
| B | Inbar-Omri-Pinkas | O(N·\|X\|·λ) — comm-optimal | Ring | No | Semi-honest | SCN 2018 |
| C | Nevo-Trieu-Yanai (NTY) | O(N·\|X\|·λ) | Star | **Yes — OKVS-based** | Malicious | CCS 2021 |
| D | Chandran-Dasgupta-Garg-Obbattu-Sekar-Sharma (CDGOSS) | Sublinear in \|X\|; "linear" refers to N in star setting | Star | Partial (uses OPPRF) | Semi-honest | PoPETs 2021 / 2022 (uncertain exact venue — verify) |
| E | Garimella-Rosulek-Singh "Structure-Aware PSI" generalisations | depends on variant | Mostly 2-party; MP extension not standardized | Yes (OKVS) | Semi-honest | Crypto 2022, CCS 2023 |

Notes on each:

- **KMPRT (CCS 2017)** is the *de facto* baseline. Every later MPSI paper compares against it. Conceptually simple: pairwise OPRFs in a star plus a "key-agreement on intersection candidates" combiner. Communication is roughly N⋅|X|·λ per party. Does **not** use OKVS — predates it.
- **Inbar-Omri-Pinkas (SCN 2018)** improves concrete communication and is comm-optimal up to constants. Ring topology, which is *less* convenient for this codebase's SP-star layout.
- **NTY (CCS 2021)** is the strongest fit for this codebase. It is built on top of the **same OKVS + VOLE primitives** as RsPSI: each party encodes its set into an OKVS, parties run a multi-party-VOLE-like protocol to obtain shares of a 0/non-0 vector, and the leader (here: SP) reconstructs only the intersection. Crucially the paper provides **malicious** security at modest overhead. Communication is O(N · |X| · λ).
- **CDGOSS** — I am confident this line of work exists (Chandran, Dasgupta, et al. have several MPSI papers in this window). I am *not* fully confident on the exact title, venue, and whether the asymptotic claim is "linear in N for the leader" vs "linear in |X| with constants that beat KMPRT". **Uncertain — verify before citing in a paper.**
- **Structure-aware PSI (Garimella, Rosulek, Singh)** — this line tightens OKVS for structured inputs (intervals, fuzzy sets). I am not aware of a clean published *multi-party* extension; the technique is mostly 2-party. Mention for completeness, not as a candidate.

### 1.2 Recommendation: NTY (Nevo-Trieu-Yanai, CCS 2021)

Justification:

1. **Maximal code reuse.** NTY's primitives are OKVS (already in `volepsi`), VOLE (already in `libOTe`), and OPRF (already in `volepsi/RsPsi.cpp`). The existing `RsPsi*` classes can be generalized to an `RsMpsi*` family with the same underlying calls — most of the changes are loop-over-parties and aggregation of OKVS rows, not new cryptographic machinery.
2. **Star topology matches the SP architecture.** NTY has a designated leader who collects shares and reconstructs. Slot the SP into the leader role and the N senders into the participant roles.
3. **Free upgrade path to malicious security.** The base PSA paper states semi-honest, but Singapore government deployment (per the user's FL deployment guide) will eventually need a stronger threat model. NTY gives that without re-architecting.
4. **Single point of comparison.** Reviewers and downstream auditors will recognise NTY; switching to it makes the security argument citable rather than artisanal.

Trade-off: NTY's malicious-security overhead is wasted if the deployment commits to semi-honest. In that case the OKVS-based semi-honest variant ("just N parallel OPRFs through SP") is even simpler — and is essentially a folklore extension of RsPSI. Suggested implementation order:

- Phase 1 (proof of concept): semi-honest "N parallel OPRFs + OKVS intersection at SP". Reuses ~80% of existing `RsPsi` code.
- Phase 2 (production): swap in the full NTY construction for malicious security.

---

## 2. N-party oblivious shuffle / switch — candidate constructions

The current 2-party OSN gives Alice a secret π and produces additive shares (s_A, s_B) such that s_A ⊕ s_B = π(payload). For N senders we need: an N-party protocol producing N additive shares (s_1, …, s_N) of π(joined_payloads), where **no single party (including SP) learns π**, and ideally no proper subset of size < t learns it either.

### 2.1 Survey

| # | Construction | Round complexity | Reuses Benes/OSN? | Trust assumption | Reference |
|---|---|---|---|---|---|
| S1 | Cascaded pairwise OSNs (chain) | O(N) rounds | Yes — directly reuses existing OSN | Honest majority OR sender_i+sender_{i+1} non-colluding chain-wise | Folklore; analysis in (Asharov, Chase et al — uncertain) |
| S2 | Chase-Ghosh-Poburinnaya "Secret-Shared Shuffle" (Asiacrypt 2020) | O(1) rounds; setup expensive | Partial (correlated randomness can be Benes-shaped) | 2-party base; N-party by chaining or generalization | Asiacrypt 2020 |
| S3 | 3-party RSS shuffle (ABY3 / Falcon style) | O(1) | No — replaces Benes entirely | Honest majority of 3 (t<2) | Mohassel-Rindal CCS 2018 (ABY3); Wagh-Tople-Benhamouda-Kushilevitz-Mishra-Rabin S&P 2021 (Falcon) |
| S4 | Eskandarian-Boneh "Clarion" | O(N) rounds | No (built on top of "shuffling protocols") | Mix-net style; assumes some subset honest | NDSS 2022 |
| S5 | Benes network with shared switch bits via GMW | Depth O(log² |X|) rounds | Yes — keeps Benes topology | Honest majority | Folklore application of GMW to Beneš permutation networks |

### 2.2 Recommendation: **S1 (Cascaded pairwise OSNs)** for Phase 1; **S2 (Secret-Shared Shuffle)** for Phase 2

Justification:

**Phase 1 — Cascade.** The existing `OSNSender`/`OSNReceiver` is the most heavily-engineered piece of this codebase. Reusing it via cascade is the lowest-friction path to a working N-party demo. Concretely: order senders 1…N. For i = 1…N-1, run OSN between sender_i (permutation holder) and "everyone else" (treated as a single virtual party using additive shares). Each pass composes another permutation on top of the running secret-shared vector. After N-1 passes, the effective permutation is the composition π_1∘π_2∘…∘π_{N-1}, which no individual party knows. The catch is **non-collusion**: if any two adjacent senders in the cascade collude they can strip off one permutation, so the security bound is effectively "no two consecutive senders collude". This is weaker than honest-majority but acceptable for a Phase 1 demo. Round complexity is O(N) and bandwidth is O(N·|X|·log|X|) (Benes).

**Phase 2 — Secret-Shared Shuffle.** Chase-Ghosh-Poburinnaya (Asiacrypt 2020) gives a 2-party shuffle with cheap online cost and offline correlated randomness. The natural N-party extension I am **uncertain** has a single canonical reference; I have seen the construction described as "chain N-1 instances of SSS to get full permutation-secrecy across N parties" and as "use replicated/Shamir shares of the permutation and process in O(log N) parallel rounds". For an N=3 deployment, the cleanest path is the **3-party RSS shuffle (S3)** used in ABY3/Falcon, which gives an honest-majority guarantee at one round of communication per shuffle and is well-tested in MPC frameworks. For N=4,5,… without honest-majority assumption, the 2-party SSS chain is the more honest answer.

I do **not** recommend S5 (Benes with shared switch bits in GMW). It looks elegant — keep the existing Benes topology and just run the switch bit XORs inside GMW — but the round complexity is O(log² |X|) per shuffle, which kills the latency advantage that made PSA fast. Mentioned for completeness only.

---

## 3. End-to-end protocol sketch (Phase 1: semi-honest, cascade shuffle)

Notation: senders S_1, …, S_N each hold a set X_i of (id, payload) pairs. SP coordinates. λ = computational sec param. σ = statistical sec param. Let n = max_i |X_i| after Cuckoo-style padding.

```
SETUP
  Public: hash H : {0,1}* -> {0,1}^{2λ}, OKVS scheme E, Benes-OSN library.
  All parties agree on n (padded set size), σ, and an ordering on senders.

PHASE A — MPSI (OKVS + pairwise OPRF, star topology)
  for i in 1..N:
      S_i and SP run RsPSI-OPRF:
          - S_i encodes its IDs into an OKVS row vector v_i
          - VOLE-OPRF: S_i learns F_k(id) for each id in X_i, SP learns the key k_i
      S_i sends {F_{k_i}(id) : id in X_i} (lexicographically sorted, padded with dummies) to SP.

  SP intersection step:
      For each candidate id-mask string, count how many senders sent it.
      INTERSECTION := {id-mask : count == N}  // ID is in ALL N sets
      Cardinality C := |INTERSECTION|.
      SP sends each S_i a bit-vector b_i in {0,1}^{|X_i|} where b_i[j] = 1 iff
        the j-th id of S_i is in the intersection.

  Each S_i now knows which of its (id, payload) rows belongs to the joined output,
  but does NOT know the other senders' payloads.

PHASE B — N-party oblivious shuffle (cascade of pairwise OSNs)
  Goal: each sender S_i contributes a payload column to a joined table of width N
        and length C; the rows are permuted by a composite permutation π no party knows.

  // Initial secret-shared table
  Each S_i picks a random mask m_i (length C, payload-sized) and locally forms
    its column c_i := payload_i[intersection_rows_of_S_i]   (length C, after Cuckoo dedup)
  S_i sends mask m_i to SP and keeps c_i ⊕ m_i' for its share.

  // Cascade
  for i in 1..N-1:
      S_i samples permutation π_i in S_C (the symmetric group on C elements).
      S_i runs OSN-SENDER with the rest of the table-holders acting as OSN-RECEIVER
        (using existing OSNSender / OSNReceiver classes, with the receiver-side
         work distributed via additive shares of the table — see implementation note 3.1).
      Outcome: shares of (π_i applied to the running table). S_i now knows only π_i.

  After N-1 passes the composite permutation is π = π_1 ∘ π_2 ∘ … ∘ π_{N-1}.
  No single party knows π (assuming no two adjacent senders in the cascade collude).

PHASE C — Reconstruction
  All senders send their final additive shares of the shuffled joined table to SP.
  SP reconstructs the table: rows = joined payloads over the intersection, in a random order.
  SP outputs out_cleartext.csv with columns payload_1, payload_2, …, payload_N.
```

### Implementation notes for the codebase

1. **`volePSI/RsPsi.h`** — add `class RsMpsi3rdPSender : public details::RsPsiBase` parameterized by `(senderIndex, senderCount)`. Reuses `mAEShash` and OPRF code paths from `runSpHshPSI`. Replace the 2-sender-specific `mSenderB_shares` member with `std::vector<std::vector<block>> mPeerShares` indexed by sender id.
2. **`volePSI/RsPsi.cpp`** — generalize `runSpHshPsiOsn` to take `std::vector<Socket>& peerChannels` instead of `Socket& chl, Socket& ch2`. The for-loop over peers is mechanical.
3. **`volePSI/osn/OSNSender.cpp` / `OSNReceiver.cpp`** — these stay as-is for Phase 1. The cascade calls them N-1 times; you do **not** need to modify Benes. (Phase 2 will need a new file `MpShuffleSender.cpp` implementing SSS.)
4. **`frontend/main.cpp`** — change the argv parsing from hard-coded role 0/1/2 to `-r <role> -n <senderCount> -i <senderIndex>` and dispatch into the right class.
5. **`dataset/`** — provide `sender0.csv`, …, `sender{N-1}.csv` for testing. Keep the existing `cleartext.csv` schema.
6. **CMake** — no new dependencies. `volepsi`, `libOTe`, `coproto`, `sparsehash` already provide everything Phase 1 needs.

### Communication & round complexity (Phase 1)

Asymptotic:
- MPSI (Phase A): N · O(1) rounds parallel + 1 SP broadcast. Bandwidth ≈ N · n · (5λ + 2λ + 1) bits.
- Shuffle (Phase B): N − 1 sequential OSN rounds, each ≈ 2 · C · log₂C · P bytes plus a one-shot OT base setup (~100 KB).
- Reconstruction (Phase C): one round, N · C · P bytes.
- **Total rounds: 4 + (N − 1) ≈ O(N).** **Total bandwidth: O(N · n · λ + N · C · log C · P).**

### Concrete bandwidth and wall-clock

Working assumptions, stated explicitly:
- λ = 128, σ = 40.
- RsPSI OPRF transport per element on the sender → SP path: ~5λ bits ≈ **80 bytes/elt** (clean middle estimate; Rindal-Schoppmann '21 reports a tighter bound for batch operation, so this is conservative).
- OPRF output transmitted by sender to SP: 2λ bits = **32 bytes/elt**.
- SP → sender selection bitvector: 1 bit/elt = **0.125 bytes/elt**.
- ⇒ Per-sender Phase A bandwidth ≈ **(80 + 32 + 0.125) · n ≈ 112 n bytes**.
- OSN per Benes switch: 1 random-string-OT of length P after extension, ≈ 2P bytes of transcript. Total 2 · C · log₂C · P bytes per OSN, ignoring the amortized 100 KB OT base setup.
- For C = 10⁵, log₂C ≈ 16.6 → one OSN round at P=16 ≈ **53 MB**; at P=64 ≈ **213 MB**.

**Total cross-network bytes** (sum over all senders + SP):

| Instance (N, n, C, P) | Phase A | Phase B | Phase C | Total |
|---|---|---|---|---|
| (3, 10⁶, 10⁵, 16) | 336 MB | 106 MB | 5 MB | **≈ 447 MB** |
| (5, 10⁶, 10⁵, 16) | 560 MB | 212 MB | 8 MB | **≈ 780 MB** |
| (10, 10⁶, 10⁵, 16) | 1120 MB | 477 MB | 16 MB | **≈ 1.6 GB** |
| (3, 10⁶, 10⁵, 64) | 336 MB | 425 MB | 19 MB | **≈ 780 MB** |

**Wall-clock at 1 Gbps and 10 Gbps full-duplex** (network-only, CPU ignored; formula = total / link rate):

| Instance | @ 1 Gbps (125 MB/s) | @ 10 Gbps (1.25 GB/s) |
|---|---|---|
| (3, 10⁶, 10⁵, 16) | 3.6 s | 0.36 s |
| (5, 10⁶, 10⁵, 16) | 6.2 s | 0.62 s |
| (10, 10⁶, 10⁵, 16) | 12.8 s | 1.28 s |
| (3, 10⁶, 10⁵, 64) | 6.2 s | 0.62 s |

### Sanity check vs the PSA paper

The PSA paper (arXiv 2410.04746) reports 35.5 s for 1M records at N=2. Predicted N=2 network-only cost at the same parameters: ≈ 280 MB ⇒ 2.2 s at 1 Gbps, 0.22 s at 10 Gbps. The paper's 35.5 s is therefore **dominated by CPU work** (OPRF evaluation, OKVS encoding, Benes switching), not network. This matches the usual PSI performance profile and is consistent with the paper.

**Implication for the N-party extension:** the N-party numbers above are *lower bounds*. Expect the actual wall-clock to be roughly N · (CPU cost of the 2-party case), minus parallelizable parts of Phase A — i.e., for N=3 expect ~50–80 s on 1M records, for N=10 expect ~3–4 min, on commodity hardware. The CPU scaling, not the network, is what will set the deployment ceiling.

### Bottleneck identification

| Instance | Binding constraint @ 1 Gbps | Binding constraint @ 10 Gbps |
|---|---|---|
| (3, 10⁶, 10⁵, 16) | Phase A network (75% of total) | CPU (OPRF + OKVS) |
| (5, 10⁶, 10⁵, 16) | Phase A network (72%) | CPU |
| (10, 10⁶, 10⁵, 16) | Phase A network (70%) | CPU |
| (3, 10⁶, 10⁵, 64) | Phase B network (54%) | CPU |

OT base setup (~100 KB, one-shot) is amortized to 0% in all cases.

---

## 4. Threat model checklist

### Semi-honest baseline (Phase 1)

- **Collusion bound** (cascade shuffle): security against any 1 corrupted sender + any subset that does *not* include two cascade-adjacent senders. Effectively "no two consecutive senders collude". This is **weaker than honest majority** — call this out explicitly to reviewers.
- **SP collusion with k senders.** If SP colludes with k senders the colluding set learns: the k payloads of the corrupted senders, the intersection cardinality C, and — if the k senders include cascade-adjacent pairs — partial information about π. Privacy of the (N-k) honest senders' payloads holds only if **at least 2 non-adjacent honest senders remain**.
- **Leakage from intersection cardinality.** SP learns C exactly. Standard PSA leakage; matches the 2-party paper. If this is unacceptable, add padding to a fixed upper bound — incurs proportional bandwidth.
- **Leakage from shuffle.** A properly executed cascade leaks nothing about π beyond the cardinality. The output table is unlinkable to input row order.
- **Side channels:**
  - *Benes switching timing.* The benes_256 implementation should be data-oblivious (the switch is a constant-time XOR conditional on a shared bit). Verify with `volePSI/osn/benes.cpp` — flag if any branch on data values exists. **(Action item, not an audited finding.)**
  - *OKVS lookup memory pattern.* OKVS reads are deterministic in the key, not the value, so access pattern leaks only the key hash — which is masked. No new leakage vs the 2-party case.
  - *Cardinality timing.* Phase B duration scales with C; an external observer can estimate C. Same caveat as the 2-party paper.

### Upgrading to malicious (Phase 2)

- Swap KMPRT/OPRF MPSI for **NTY** (Nevo-Trieu-Yanai, CCS 2021): gives malicious security for the intersection step.
- Replace cascade shuffle with **3-party RSS shuffle (S3)** (for N=3) or **N-party SSS chain (S2)** (for N>3). Both are well-studied for malicious security in the honest-majority setting.
- Add **commit-and-open** for the OPRF outputs each sender sends to SP, to prevent equivocation.
- **Open:** I have *not* seen a single end-to-end malicious-secure MPSA paper in the literature. The PSA paper itself does not provide one. This is a publishable contribution if you write it carefully.

---

## 5. Concrete next steps (in this repo)

1. **`volePSI/RsPsi.h` / `RsPsi.cpp`** — copy the `RsPsi3rdPSenderA` class to a new `RsMpsi3rdPSender` and replace the 2-peer assumptions with `std::vector<Socket>& peers`. Keep the OPRF call site identical; loop over peers.
2. **`volePSI/osn/`** — leave Benes/OSN unchanged for Phase 1. Just call OSN N-1 times from the new MPSI driver. Add a header `MpShuffleDriver.h` that owns the cascade loop and the per-round share rotation.
3. **`frontend/main.cpp`** — replace the 9-line stub (yes, the file is 9 lines today — too thin) with proper argv parsing: `-N <senderCount> -i <senderIndex> [-sp]` and dispatch. Generate `dataset/sender{0..N-1}.csv` via a small Python helper.
4. **CI / test** — add a `tests/mpsa_n3.sh` that spawns N=3 frontend processes locally over loopback (`coproto` supports `SocketScheduler` over TCP) and checks the joined output against a brute-force Python reference.
5. **Threat-model doc** — add `SECURITY.md` to the repo stating the Phase 1 collusion bound (no-two-cascade-adjacent) and the Phase 2 target (honest majority for N=3, no-collusion-with-SP otherwise).

---

## 6. Open research questions

1. **Tightest possible MPSI for star topology with a non-contributing leader.** The literature mostly assumes all parties contribute. Does designating one party as a "compute-only" SP enable better asymptotics? NTY can be specialized — I am unaware of a paper that does this cleanly. **Uncertain.**
2. **Optimal N-party oblivious shuffle without honest majority.** For N ≥ 4 and no honest-majority assumption, what is the best round complexity? Cascade is O(N); SSS chain is also O(N). A constant-round protocol secure against N-1 corruptions under standard assumptions would be a real result.
3. **Side-channel-free Benes for N-party setting.** The 2-party Benes implementation may rely on subtle data-obliviousness arguments that don't lift cleanly to N parties — particularly when switch bits are themselves secret-shared across N parties.
4. **OKVS with malicious encoder for N parties.** Garimella et al. 2021 give malicious OKVS for 2-party; the N-party encoding consistency check is more delicate. NTY addresses one variant; the design space is not exhausted.
5. **Vertical-FL composition.** The PSA output is the input to downstream FL training. What does it mean for the *FL* threat model when the join leaks cardinality and a randomized row order? This crosses into the user's PrivateGuard-FL work — worth a dedicated DP-aware analysis.

---

## Caveats from the author

- Citations marked "uncertain" or "verify before citing" reflect knowledge gaps I am willing to admit, not approximate guesses. Do not put them in a paper without checking DBLP / IACR ePrint.
- The "cascade shuffle" Phase 1 design is folklore and pragmatic — I have not seen a paper that formally analyses its leakage profile for this exact use case. Treat it as engineering, not as a proven construction.
- The arXiv 2410.04746 PSA paper is the user's own work; this brief assumes its protocol description is authoritative and does not re-litigate the 2-party security argument.

End of brief.
