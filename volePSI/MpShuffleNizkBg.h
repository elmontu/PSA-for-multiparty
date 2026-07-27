#pragma once

// R27b-SOUND: shuffle argument with verifier-recomputed products.
//
// After the earlier R27b review flagged that the verifier only compared
// prover-supplied `productOrig == productShuf` (trivially forgeable), this
// revision closes the soundness gap by having the prover reveal (m_i, r_i,
// m'_i, r'_i) alongside the commitments. The verifier then:
//
//   1. Recomputes each Pedersen opening c_i = g^{m_i} · h^{r_i} and
//      c'_i = g^{m'_i} · h^{r'_i}, and checks they match the transcript.
//      This BINDS the prover to specific plaintext messages.
//
//   2. Independently computes  P    = Π (x - (m_i  + y))  and
//                                P'   = Π (x - (m'_i + y))
//      under fresh Fiat-Shamir challenges (y, x). Rejects if P ≠ P'.
//
// Under Schwartz-Zippel over a ~2^252-element field the polynomial identity
// holds iff the multisets {m_i} = {m'_i}, and the openings bind the m_i to
// the commitments — so any tampering (drop/insert/substitute) is caught.
//
// TRADEOFF: this is a SOUND shuffle argument but not a ZERO-KNOWLEDGE one
// over the messages — the prover reveals the m_i as part of the proof.
// This matches MPSVS Phase 4 F_PSA semantics where the shuffled bin
// contents are already public post-alignment. If a hiding-shuffle NIZK is
// needed for a different use case, upgrade to the full Bayer-Groth
// EUROCRYPT 2012 §5 recursive partial-product argument (a considerably
// larger construction; documented in docs/DESIGN.md).

#include "MpRistretto.h"
#include "MpPedersen.h"

#include <vector>
#include <cstdint>

namespace volePSI {
namespace mpstar {

// SOUND proof artifact. The verifier recomputes both products from the
// revealed messages after checking each opening binds to its commitment.
struct ShuffleProofBg {
    R255Scalar challengeY;                    // Fiat-Shamir challenge 1
    R255Scalar challengeX;                    // Fiat-Shamir challenge 2
    std::vector<R255Scalar> messages;         // revealed m_i (original order)
    std::vector<R255Scalar> shuffledMessages; // revealed m'_i (shuffled order)
    std::vector<R255Scalar> openingsOrig;     // r_i so verifier can check c_i
    std::vector<R255Scalar> openingsShuf;     // r'_i so verifier can check c'_i
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
