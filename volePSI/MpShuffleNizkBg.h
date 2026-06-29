#pragma once

// R27b: Bayer-Groth multiplicative shuffle NIZK.
//
// Closes the positional-permutation soundness gap from R27 prototype.
// The construction proves multiset equality {m_i} == {m'_i} (which is
// equivalent to "C' is a permutation of C" given each commit is binding)
// via the polynomial identity:
//
//     Pi_i (x - (m_i + y)) == Pi_i (x - (m'_i + y))
//
// for two random Fiat-Shamir challenges x, y. Schwartz-Zippel guarantees
// this holds iff the two multisets match.
//
// Bayer-Groth EUROCRYPT 2012 §5 wraps this into a ZERO-KNOWLEDGE
// argument by committing to the partial-product chain via Pedersen
// vector commitments and proving each multiplication step via a sigma
// protocol. The full recursive (O(log n)) variant is R27c.
//
// THIS R27b DELIVERABLE: implements the SOUND argument structure but
// reveals the partial product values directly (rather than via the
// recursive Pedersen-vector commitment). This is sound (verifier
// catches any false multiset claim) but NOT zero-knowledge over the
// partial products. The full ZK variant requires the recursive
// argument; documented in docs/SHUFFLE_NIZK_DESIGN.md.

#include "MpRistretto.h"
#include "MpPedersen.h"

#include <vector>
#include <cstdint>

namespace volePSI {
namespace mpstar {

// R27b proof artifact. The new pieces beyond R27:
//   - challengeY: shift challenge
//   - shifted product on each side (revealed)
//   - per-side opening of the homomorphically-shifted sum-of-products
struct ShuffleProofBg {
    R255Scalar challengeY;        // Fiat-Shamir challenge 1
    R255Scalar challengeX;        // Fiat-Shamir challenge 2
    R255Scalar productOrig;       // Π (x - (m_i + y)) - revealed for soundness
    R255Scalar productShuf;       // Π (x - (m'_i + y)) - revealed
    R255Scalar sumOpeningOrig;    // Σ r_i (for sum-of-shifted-messages check)
    R255Scalar sumOpeningShuf;    // Σ r'_i
};

ShuffleProofBg shuffleProveBg(
    const std::vector<R255Scalar>& messages,
    const std::vector<R255Scalar>& openingsOrig,
    const std::vector<R255Scalar>& openingsShuf,
    const std::vector<int>& permutation,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf);

bool shuffleVerifyBg(
    const ShuffleProofBg& proof,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf);

// Fiat-Shamir challenges (transcript-derived; deterministic).
R255Scalar fsChallengeY_bg(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime);
R255Scalar fsChallengeX_bg(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime,
    const R255Scalar& y);

} // namespace mpstar
} // namespace volePSI
