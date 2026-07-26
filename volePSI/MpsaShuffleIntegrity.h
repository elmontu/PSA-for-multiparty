#pragma once

// A-sum shuffle integrity: per-column sum-of-values check added on top of
// the semi-honest OSN shuffle cascade in MpShuffleDriver.
//
// The cascade permutes ROWS within each of the N*W parallel payload columns
// (one round's Benes routing is applied to every column identically), so the
// multiset -- and thus the SUM -- of each column is preserved end-to-end.
//
// Protocol added by this module:
//   1. At setup, each sender computes claimedSum_w = Σ_j hashToScalar(payload_j_w.bytes)
//      for each of its W columns, picks a fresh Pedersen opening r_w, and
//      publishes commit_w = pedersenCommit(claimedSum_w, r_w) to the SP.
//   2. Cascade runs unchanged.
//   3. At reveal, the sender publishes (claimedSum_w, r_w) for each w.
//   4. SP verifies commit binding AND Σ_j hashToScalar(shuffledCol_w[j]) == claimedSum_w.
//      Any failure -> abort, do NOT write output.
//
// What this catches (against a MALICIOUS sender other than the row's owner):
//   drop-row, substitute-row, arithmetic corruption in an OSN round --
//   anything that changes the sum of a column.
// What this MISSES (accepted gap for A-sum; closed by future A-mset):
//   surgical swap of two rows that preserves the column sum. Very
//   constrained in practice.
//
// Follow-up items (tracked, not addressed here):
//   - hashToScalar takes std::vector<uint8_t> -> one heap alloc per block.
//     For large C this dominates. A span-based API on hashToScalar would fix it.
//   - Full multiset NIZK (A-mset) using cooperative Bayer-Groth polynomial
//     evaluation across senders; requires MpShuffleNizkBg refactor.

#include "MpPedersen.h"     // PedersenCommitment, pedersenCommit, pedersenVerify
#include "MpRistretto.h"    // R255Scalar, hashToScalar
#include "cryptoTools/Common/Defines.h"  // establishes `oc` alias for osuCrypto

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// One sender's per-column integrity witness. Held locally between commit
// (setup) and open (reveal). Wire-serialized via serialize/deserialize below.
struct SenderColumnWitness {
    std::vector<PedersenCommitment> commits;   // size W
    std::vector<R255Scalar>         claimedSums; // size W (revealed at open)
    std::vector<R255Scalar>         openings;   // size W (revealed at open)
};

// Sender-side helper. `columns` is W parallel columns each of length C
// (the sender's own payload after any padding, laid out same as what the
// cascade will shuffle). Returns commits + openings + claimedSums. The
// commits are what the sender sends to SP at setup; claimedSums + openings
// are what the sender sends at reveal.
// W=0 is a valid input (no payload columns); returns an empty witness.
SenderColumnWitness makeSenderWitness(
    const std::vector<std::vector<oc::block>>& columns);

// Serialize just the commit vector (setup-time send). One PedersenCommitment
// is 32 bytes (R255Point). Output layout: W consecutive 32-byte points.
std::vector<uint8_t> serializeCommits(
    const std::vector<PedersenCommitment>& commits);

std::vector<PedersenCommitment> deserializeCommits(
    const std::vector<uint8_t>& data, size_t W);

// Serialize opening (reveal-time send): W claimedSums followed by W openings,
// each a 32-byte R255Scalar. Total 2 * W * 32 bytes.
std::vector<uint8_t> serializeOpenings(
    const std::vector<R255Scalar>& claimedSums,
    const std::vector<R255Scalar>& openings);

// Parses back into (claimedSums, openings).
void deserializeOpenings(
    const std::vector<uint8_t>& data, size_t W,
    std::vector<R255Scalar>& claimedSums,
    std::vector<R255Scalar>& openings);

// SP-side verification. For sender i, given its commits (received at setup)
// and its opened (claimedSums, openings) plus the ACTUAL shuffled columns
// produced by the cascade for that sender's W columns, return true iff:
//   - each pedersenVerify(commit_w, claimedSum_w, opening_w) succeeds AND
//   - Σ_j hashToScalar(shuffledColumns[w][j]) == claimedSum_w
// Any failure returns false; the caller should fail-close (abort the
// protocol, do NOT write output).
bool verifySenderIntegrity(
    const std::vector<PedersenCommitment>& commits,
    const std::vector<R255Scalar>&         claimedSums,
    const std::vector<R255Scalar>&         openings,
    const std::vector<std::vector<oc::block>>& shuffledColumns);

// ---- A-mset-row: cross-column row-integrity check ----
//
// A-sum (above) commits to Σ hashToScalar(block) PER COLUMN. It catches
// drops, substitutions, and per-column arithmetic corruption. It MISSES a
// specific class of tampering: cross-column MIXING. In the MPSA cascade the
// same permutation is applied to every one of the N*W columns. A malicious
// sender in round k could apply dest_k correctly to some columns but a
// DIFFERENT permutation to others -- output row j then has some blocks
// from input row π(j) and others from a different input row. Each column's
// multiset is preserved individually (so A-sum passes) but the ROW is
// "mixed provenance" -- corrupts join semantics silently.
//
// A-mset-row closes this: sender i commits to Σ_j hashToScalar(concat of its
// W row bytes at row j). Cross-column mixing at any output row j produces a
// concatenation that doesn't match any input row → hash differs → sum breaks
// → verify fails. Complements A-sum; both can run together.
//
// One commitment per sender (not per column). Overhead: 32B commit + 64B
// opening per sender per session, plus one Ristretto scalar op per row per
// sender at reveal.

struct SenderRowWitness {
    PedersenCommitment commit;
    R255Scalar         claimedSum;   // revealed at open
    R255Scalar         opening;      // revealed at open
};

// Sender-side helper. `rows` is a Ceff x W matrix (each row is W blocks). W
// may be 0 (returns a witness with claimedSum = 0). Ceff = 0 is also legal.
SenderRowWitness makeSenderRowWitness(
    const std::vector<std::vector<oc::block>>& rows);

// Wire helpers. commit = 32B; opening payload = 64B (claimedSum || opening).
std::vector<uint8_t> serializeRowCommit(const PedersenCommitment& c);
PedersenCommitment   deserializeRowCommit(const std::vector<uint8_t>& data);
std::vector<uint8_t> serializeRowOpening(
    const R255Scalar& claimedSum, const R255Scalar& opening);
void deserializeRowOpening(
    const std::vector<uint8_t>& data,
    R255Scalar& claimedSum, R255Scalar& opening);

// SP-side verification. `shuffledColumns` is W parallel columns of length C
// (all one sender's contribution, same layout as A-sum). Returns true iff:
//   - pedersenVerify(commit, claimedSum, opening) succeeds AND
//   - Σ_j hashToScalar(concat_of_W_blocks_at_row_j) == claimedSum
bool verifySenderRowIntegrity(
    const PedersenCommitment& commit,
    const R255Scalar&         claimedSum,
    const R255Scalar&         opening,
    const std::vector<std::vector<oc::block>>& shuffledColumns);

} // namespace mpstar
} // namespace volePSI
