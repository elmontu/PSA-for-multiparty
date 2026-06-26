# Cardinality-Hiding Design

This doc covers the **cardinality-hiding** privacy property: hiding the
exact intersection size |I| from various adversarial vantage points. Round
17 shipped the **lightweight, observer-facing** variant; full hiding (from
SP itself) is specified below as research direction.

## What "cardinality" leakage means in MPSA

In the current protocol, three parties can learn information about `C = |I|`:

| Vantage point | Currently learns | Why |
|---|---|---|
| SP | exact `C` | Counts hash matches during MPSI |
| Each sender | exact `C` | RsMpsi sends cardinality back as part of the protocol output |
| Anyone observing the output file | exact `C` | Output file has exactly `C` rows |

The Round 17 padding closes the **third** of these. The first two remain
open and require separate mechanisms.

## What Round 17 ships (observer-facing hiding)

CLI: `-cmax <N>` — pad output to at least `N` rows.

Mechanism:
1. After MPSI completes, both SP and every sender know `C` and the agreed
   pad target `C_max ≥ C`.
2. Each sender extends its payload column `c_i` from `C` to `C_max` by
   appending `C_max - C` PRNG-random "dummy" blocks.
3. Each sender's mask `r_i` is extended to `C_max` blocks too (fresh PRNG).
4. Cascade runs on `C_max` rows.
5. Output `out_mpsa.csv` has `C_max` rows. Real intersection rows are
   indistinguishable (after the secret shuffle) from PRNG-random dummies
   by anyone who lacks the senders' payload-format knowledge.

**What this hides:** an external observer of `out_mpsa.csv` learns only that
`C ≤ C_max`. The output file is `C_max` rows of opaque hex regardless of
true `C`.

**What this does NOT hide:**
- **SP** still learns `C` because MPSI step at SP literally counts matching
  hashes. SP can observe `C` even if it then helps shuffle a padded
  `C_max`-sized vector.
- **Senders** still learn `C` because RsMpsi3rdPSender::runIntersection
  receives the cardinality back from SP.
- Anyone with access to a sender's payload-encoding convention can detect
  dummies (real payloads in the prototype encode as `\x00val{i}_{j}`;
  dummies are full-entropy PRNG bytes).

## Full cardinality hiding (research direction)

To hide `C` from SP itself requires changing the MPSI step to either:

### Option A: Circuit-PSI (CGT'12, RsCpsi)

Run MPSI as a **circuit** that outputs only a 0/1 vector per sender's input
(indicating membership) WITHOUT revealing the count to SP. Each sender locally
counts its own 1's. The visa-research/volepsi `RsCpsi.h` provides this for
the 2-party case; N-party extension follows the same MPSI roadmap structure
as `docs/RSMPSI_VOLE_INTEGRATION.md`.

Cost: comparable to current MPSI for moderate sets; the circuit eval adds
~3× the per-element communication.

### Option B: Oblivious counting via secret-shared cardinality

After hash-MPSI, SP holds the count `C` as a secret share rather than in the
clear. Senders learn only `C ≤ C_max` (after a secret-share comparison
gate). Requires:
- Shamir or Boolean-shared comparison protocol (e.g. ABY3-style).
- A small MPC subcircuit for `min(C, C_max)`.

Effort: ~2-3 days assuming the MPC primitive is in place.

### Option C: Pre-agreed C_max with no count at all (trivial)

SP and senders agree on `C_max` up front. MPSI runs but no party learns the
count; everyone processes `C_max` rows. SP can technically COUNT matches
internally but the protocol description does not call for it; with an
auditable implementation this becomes "SP behaves as if it doesn't know C".

Cost: zero new crypto. Just discipline + documentation.

## Output marker for dummy filtering (separate work)

Currently the prototype's dummies are "PRNG-random" — a payload-aware
consumer can detect them by format (`val{i}_{j}` vs full-entropy). To make
dummies **unfilterable except by key-holders**:

1. Senders agree on a "filter key" `K_filter` via N-way DH (or derived from
   `MpStarSetup` keys). SP does NOT learn `K_filter`.
2. Each row gets a per-row authentication tag column:
   `tag[i] = AEAD_Encrypt(K_filter, salt[i], "real" || row_data_hash)` if
   real; random bytes if dummy.
3. `salt[i]` is a per-row nonce shipped alongside the tag.
4. After the cascade, each row carries `(payload..., salt, tag)`. Salt and
   tag are permuted with the row (just another column in the cascade).
5. Downstream filter: for each row, try `AEAD_Decrypt(K_filter, salt, tag)`.
   Success → real. Failure → dummy.

SP cannot decrypt (lacks `K_filter`), so it cannot count real rows from
the output. Combined with Option A/B/C above, the cardinality is fully
hidden from SP.

Cost: ~150 LoC + adds two columns (salt + tag) per output row.

## Composition with malicious-secure cascade

The padded output is shuffled by the same cascade. With the malicious
upgrade from `MALICIOUS_CASCADE_DESIGN.md`, dummies are MAC'd just like
real rows, so a malicious party cannot forge "real" tags or strip dummies.
Combined: padding + filter-key + MACs = cardinality hidden from SP and
output integrity guaranteed.

## Effort summary

| Item | Status | Effort |
|---|---|---|
| Observer-facing output padding (`-cmax`) | DONE (Round 17) | shipped |
| Dummy filter tags (`K_filter` + AEAD per row) | future | ~½ day |
| Full hiding from SP via Circuit-PSI (Option A) | future | weeks (depends on RsMpsiVole) |
| Full hiding via shared-cardinality (Option B) | future | 2-3 days |
| Pre-agreed C_max with auditable no-count (Option C) | trivial | minutes (discipline) |

## Recommendation

For prototype + research-paper: ship Round 17's observer-padding now (DONE).
For deployment to a regulated context where SP is partially trusted: combine
with Option C (audit-enforced no-count) — gets you 95% of the privacy
property with zero crypto effort. For full UC-style cardinality privacy:
combine output-padding + filter-tags + Option A or B.
