# Malicious-secure upgrade roadmap

The committed protocol is **semi-honest** with one specific malicious-channel
hardening already in place (see `## What's already malicious` below). This doc
sketches the full upgrade to malicious security, with concrete subtasks,
paper references, and effort estimates.

Audience: an engineer or cryptographer picking up where this prototype left
off and wanting to harden it for a Singapore-government deployment.

## What's already malicious (this prototype)

| Layer | Mechanism | Effect |
|---|---|---|
| Sender → SP masked column `m_i` | AEAD under `MpSpHandshake`-derived key, session-id bound | SP detects forged or tampered `m_i` |
| Sender → Sender `r_j` handoff (Phase 0) | AEAD under `MpStarSetup` pairwise key, session-id bound | Intermediate sender 0 detects forged/tampered `r_j` from peer |
| Sender k → SP `rho_k` (cascade) | AEAD under SP key (added in Round 9A) | SP detects tampered re-randomizer per round |
| Last sender → SP final `R` reveal | AEAD under SP key (added in Round 9A) | SP detects tampered final share |
| Cross-session replay | Session-id binding via `deriveSessionKey` | Captured ciphertext from session A can't open in session B |

**What's NOT covered:**
- A genuinely malicious sender that follows the protocol but submits an `r_j`
  inconsistent with the masked column it sent to SP (`c_j = m_j XOR r_j`).
  SP gets corrupted output, but cannot attribute fault.
- A malicious SP that selectively drops / reorders relay messages between
  senders. The AEAD MACs prevent silent tampering but not active denial.
- A malicious OSN: the upstream `osn/OSNSender.cpp` and `osn/OSNReceiver.cpp`
  are semi-honest. A malicious OSN sender can produce inconsistent shares.

## Threat model targets

| Target | Honest-majority? | Adversary model | Suitable construction |
|---|---|---|---|
| N=3 with 1 corruption | Yes (2 of 3 honest) | Malicious, abort-on-detect | **ABY3 / Falcon RSS shuffle** |
| Any N, no honest majority | No (up to N-1 corruptions) | Malicious, abort-on-detect | **CGP Secret-Shared Shuffle chain** |
| Any N, no honest majority, identifiable abort | No | Malicious + attribution | KMPRT + commitments + signatures (research-heavy) |

The two main paths below correspond to the first two rows.

---

## Path A: N=3 honest-majority via RSS shuffle (ABY3 / Falcon style)

**References:**
- Mohassel, Rindal. *ABY³: A Mixed Protocol Framework for Machine Learning.* ACM CCS 2018.
- Wagh, Tople, Benhamouda, Kushilevitz, Mishra, Rabin. *Falcon: Honest-Majority Maliciously Secure Framework for Private Deep Learning.* PoPETs 2021.
- Chida, Genkin, Hamada, Ikarashi, Kikuchi, Nof, Pinkas. *Maliciously Secure MPC with Honest Majority via Replicated Secret Sharing.* CRYPTO 2018.

**Subtasks:**

1. **Replicated secret-sharing layer.** Each value `x` is split as `(x_1, x_2, x_3)` with `x_1 XOR x_2 XOR x_3 = x`. Party `i` holds `(x_i, x_{i+1 mod 3})`. ~200 LoC for a header-only `RssShare<T>` type with the standard reshare-after-multiply machinery.

2. **3-party shuffle primitive.** Three parties hold an RSS-shared vector; output is the same vector RSS-shared but permuted by a permutation none of them knows. The standard construction uses a Beaver-triple-style precomputation of correlated permutations. ABY3 §4.3 sketches it; Falcon §IV-C has the malicious-secure variant with MACs. ~400-600 LoC.

3. **MAC verification.** Each share carries a MAC `tag_i = α · x_i` under a shared random `α`. After every operation, parties locally update tags; a final batched MAC-check verifies the whole protocol transcript. Mohassel-Rindal §3.4 or Chida et al. §4. ~300 LoC.

4. **Replace `MpShuffleDriver` with `MpRss3PCShuffle`** for the N=3 deployment path. Keep `MpShuffleDriver` (cascade-OSN) for N≥4 and semi-honest N=3 (faster path).

5. **Cardinality leakage check.** RSS-3PC shuffle leaks `C` (intersection cardinality) just like the existing protocol; if that must be hidden, pad to a deterministic upper bound and ignore-on-decode dummies.

**Effort estimate:** 2-3 person-weeks for a competent MPC engineer with the papers in hand. Roughly half the time is debugging the per-share MAC bookkeeping; the shuffle itself is short.

**Integration impact on this codebase:**
- New `volePSI/MpRssShare.h`, `MpRss3PCShuffle.{h,cpp}` (~1000 LoC total).
- `MpsaDriver` gains a `-mode rss3pc` flag that dispatches to the new path.
- Existing `MpShuffleDriver` and `MpStarChannel` continue to work for N≥4.

---

## Path B: General N via CGP Secret-Shared Shuffle chain

**References:**
- Chase, Ghosh, Poburinnaya. *Secret-Shared Shuffle.* ASIACRYPT 2020.
- Eskandarian, Boneh. *Clarion: Anonymous Communication from Multiparty Shuffling Protocols.* NDSS 2022. (Generalizes CGP for larger party counts.)

**Construction sketch:**
The base CGP shuffle is 2-party with cheap online cost (one OT extension per element) but an expensive offline correlated-randomness phase. To get N-party, the natural extension is to chain N-1 instances:
- Round 1: party 0 and party 1 run CGP. Output: each holds a share of `π_1(table)`.
- Round 2: party 1 (still holding its share) and party 2 run CGP. Output: each holds a share of `π_2(π_1(table))`.
- ... and so on. Final composite permutation is unknown to any single party as long as ≥1 is honest.

This is structurally similar to our current cascade-OSN. The advantage of CGP over Benes-OSN is **lower per-round bandwidth** asymptotically, but the offline phase is expensive enough that for the one-shot PSA use case Benes is often faster end-to-end (see `RESEARCH_MPSI.md` §2 for the analysis).

**Malicious upgrade for CGP:**
CGP itself is not malicious-secure as published. Adding malicious security requires:
- MACs on every share (linear cost per element)
- A consistency check between consecutive cascade rounds (cut-and-choose or polynomial argument)

This adds material complexity. Realistic estimate: 4-6 weeks for a research-grade implementation including formal write-up.

**Integration impact:**
- New `volePSI/MpCgpShuffle.{h,cpp}` (~2000 LoC).
- `MpsaDriver` gains `-mode cgp` flag.
- Likely needs a new dependency for the correlated-randomness pre-processing (e.g. silent OT extension that's already in libOTe but not currently used).

---

## Path C: Lightweight identifiable abort (incremental)

If full malicious security is out of scope but **detection of bad actors** is desired (the protocol aborts AND names the misbehaving party), the cheapest additions:

1. **Public-key signatures on all sender-broadcast messages.** Each sender has a long-term Ed25519 keypair (libsodium `crypto_sign`). Each broadcast to SP includes a signature. SP publishes the signed transcript at the end; any party can verify and attribute. **Effort: ~1 day; ~150 LoC.**

2. **Commit-and-open on `m_i`.** Each sender publishes `H(m_i || r_i_nonce)` to SP at protocol start. Later, the protocol output verifies against the open. If a sender's claimed `r_i` doesn't match what XOR-reconstructs from the output, the commit catches them. **Effort: ~1 day; ~100 LoC.** Requires extending `MpsaDriver` Phase 0.

These don't give cryptographic malicious security but do let downstream auditors prove "sender X equivocated", which is often what Singapore-government deployment cares about (PDPA + CSA CII attribution requirements).

---

## Recommended order

For the deployment context implied by `docs/RESEARCH_MPSI.md` (Singapore government / regulated sector, N=3 most common):

1. **Path C steps 1+2** (Ed25519 signatures + commit-and-open on `m_i`). 2-3 days. Catches the easiest attribution-relevant misbehavior.
2. **Path A** (RSS-3PC malicious-secure shuffle for the N=3 case). 2-3 weeks. Gives full malicious security with honest-majority.
3. **Path B** is only worth attempting if N≥4 deployments are on the roadmap AND a research budget exists.

---

## What this prototype does NOT need to do

- **TEE-based malicious security.** SGX/SEV-based confidential computing is an
  orthogonal approach. The user's `~/fl/` FL deployment guide explicitly does
  not assume TEE; we follow that constraint.
- **Post-quantum migration.** X25519 + SHA-256 are not post-quantum. PQC
  migration is out of scope for the multiparty extension and should be
  coordinated with the rest of the libsodium / cryptoTools stack.
