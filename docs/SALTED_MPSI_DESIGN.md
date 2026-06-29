# Salted MPSI: Design

T15 of the multi-improvement plan. Closes the SP-dictionary-attack-on-IDs
vector inherent to deterministic-hashing MPSI.

## The attack T15 defends against

Without T15, the MPSI step proceeds as:

1. SP picks `aesKey = sysRandomSeed()` (fresh per session).
2. SP broadcasts `aesKey` to all senders.
3. Each sender computes `hash_id_j = AES_aesKey(id_j)` for every input id.
4. Senders send their hash sets to SP.
5. SP intersects by counting matches.

The fundamental leak: **SP knows both `aesKey` AND every sender's hash
set**. If SP has a candidate list of plausible IDs (e.g., a credit-bureau
NRIC list, a HSA-published medical-record-number range, or any
externally-obtainable identifier corpus), SP can:

1. Compute `AES_aesKey(candidate_id)` for every id in the candidate list.
2. Look up which sender's hash set the resulting hash appears in.
3. Learn which IDs each sender has (and therefore which sensitive
   records that sender holds).

This is a **deterministic-hashing attack** common to all PSI variants
that don't use OPRF. It's not a flaw of the protocol per se — it's
inherent to "everyone hashes with the same public function".

## What T15 ships

A per-session secret salt shared among senders (but NOT with SP) that
is XORed into each ID before MPSI hashing:

1. **Setup**: peer mesh (sender↔sender TCP) is already established
   (Round 13).
2. **Salt broadcast**: sender 0 generates a fresh 16-byte random salt
   and sends it to every other sender via the peer mesh. The peer-mesh
   sockets are NOT routed through SP, so SP doesn't see the salt.
3. **Salt application**: each sender computes `id'_j = id_j XOR salt`
   for every input id.
4. **MPSI runs unchanged** on the salted IDs. The intersection is
   preserved because XOR-with-the-same-salt is a bijection — if `id_1
   == id_2` then `id_1 XOR salt == id_2 XOR salt`.

CLI: `-salt-mpsi` enables it on all parties. Verified end-to-end:
intersection size unchanged at 100 (out of 1000 per sender).

## What T15 DOES close

- **SP cannot dictionary-attack the hashes.** SP doesn't know the salt,
  so it cannot precompute `AES_aesKey(candidate XOR salt)` for any
  candidate id.
- **Multi-session linkability across runs of the same set.** Even if SP
  records hashes from session A and session B, the salts differ, so the
  same id hashes to different values across sessions.

## What T15 does NOT close

- **SP still learns the cardinality** `|I|`. Independent of the salt.
- **SP still learns which IDs are in the intersection** by observing
  which hashes appear in multiple senders' sets. SP just can't go from
  hash → cleartext id without the salt.
- **SP still sees the timing of hash arrivals.** Side-channel.
- **A malicious sender** could leak the salt to SP (the salt is shared
  among senders by design). Defends only against SP-driven attacks.

For full ID privacy (SP learns NOTHING about IDs except `|I|`), use a
real OPRF-based PSI. See `RSMPSI_VOLE_INTEGRATION.md` for the
upstream-VOLE-PSI swap that achieves this.

## Composition

| Combined with | Effect |
|---|---|
| `-cmax` (cardinality padding) | SP can still count `|I|` from MPSI; cardinality leak still present at SP but not in output file |
| `-mink` (threshold-k) | SP still enforces threshold using true `|I|`, regardless of salt |
| `-pq` (PQ handshake) | Orthogonal |
| `-auth-dir` (T14) | T14 protects the peer-mesh authentication; T15's salt broadcast benefits from authenticated channels |
| `-dp <eps>` (T8) | Orthogonal — DP is applied to the CARDINALITY release, not the IDs |

## Effort and roadmap

- Shipped (R23): ~30 LoC of broadcast + XOR in `MpsaDriver`. No new file.
- Future hardening:
  - **AEAD-encrypt the salt broadcast** (currently cleartext over peer
    mesh; trusted because peer mesh is sender-only, but should be
    encrypted under MpStarSetup pairwise keys for defense-in-depth).
    ~½ hour to wire.
  - **Salt rotation per query** within a long-lived session: irrelevant
    today (one MPSI per protocol run) but matters if MPSI is run
    multiple times within one TCP session.
  - **OPRF-based MPSI** as the real-cryptography upgrade — see
    `RSMPSI_VOLE_INTEGRATION.md`.

## References

- Kolesnikov, V., Kumaresan, R., Rosulek, M., Trieu, N. (2016).
  **Efficient Batched Oblivious PRF with Applications to Private Set
  Intersection.** ACM CCS 2016. The OPRF-based alternative; the
  textbook fix to the deterministic-hashing attack.
- Pinkas, B., Schneider, T., Zohner, M. (2018). **Scalable Private Set
  Intersection Based on OT Extension.** ACM Transactions on Privacy
  and Security. Survey-style coverage of PSI primitives and their
  trade-offs.
- Bay, A., Erkin, Z., Hoepman, J.-H., Samardjiska, S., Vos, J. (2022).
  **Practical Multi-Party Private Set Intersection Protocols.** IEEE
  TIFS. Comparison of MPSI constructions including hash-based and
  OPRF-based.
