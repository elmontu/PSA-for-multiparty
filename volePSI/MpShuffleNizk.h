#pragma once

// NIZK proof of correct shuffle (R27). Bayer-Groth-inspired prototype
// using Schwartz-Zippel polynomial-equality argument + Fiat-Shamir.
//
// PROBLEM: Given two commitment vectors C = (c_1, ..., c_n) and
// C' = (c'_1, ..., c'_n), prove there exists a permutation π and fresh
// openings (r'_i) such that c'_i = pedersenCommit(m_{π(i)}, r'_i) for
// all i — without revealing π. (i.e., C' is a shuffle of C with
// re-randomized openings.)
//
// This prototype implements the SIMPLEST sound construction:
//
//   1. Verifier (or Fiat-Shamir) sends random challenge x ∈ Z_L.
//   2. The polynomial identity
//        Π_i (X - m_i) = Π_i (X - m_{π(i)})
//      holds for ALL X iff (m_i) and (m_{π(i)}) are the same multiset.
//      Schwartz-Zippel: evaluating at random x, the identity holds with
//      overwhelming probability iff the multisets are equal.
//   3. Prover proves that the COMMITTED messages, evaluated as a
//      polynomial at x, yield equal values for C and C'.
//
// SIMPLIFIED variant used here (linear, not multiplicative):
//   1. Random challenge x.
//   2. Prover shows Σ x^i · m_i = Σ x^i · m'_{π^{-1}(i)} as a single
//      committed value via openings.
//
// This proves PERMUTATION-EQUALITY OF MULTISETS but NOT the cryptographic
// soundness of full Bayer-Groth (which uses multiplicative structure).
// The prototype is intentionally simpler so it fits in a focused session;
// see docs/DESIGN.md for the gap to full Bayer-Groth.

#include "MpPedersen.h"
#include "MpRistretto.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// The NIZK proof artifact. Verifier checks (commitments, proof,
// public-parameters) → true/false.
struct ShuffleProof {
    // Fiat-Shamir challenge derived from the transcript.
    R255Scalar challenge;
    // Prover's opening of the random-linear-combination of original messages.
    R255Scalar combinedMessage;     // Σ x^i · m_i
    R255Scalar combinedOpeningOrig; // Σ x^i · r_i (sum of openings of C)
    R255Scalar combinedOpeningShuf; // Σ x^i · r'_{π^{-1}(i)} (sum of openings of C', after applying π^{-1})
};

// Prover side. Inputs:
//   messages : the underlying plaintexts m_i
//   openingsOrig : the openings r_i used in C
//   openingsShuf : the openings r'_i used in C'
//   permutation  : pi[i] = source index of position i in C' (i.e.,
//                   m'_i = m_{pi[i]}; equivalent to applyPi semantics
//                   in MpCgpShuffle).
//   commitmentsOrig : C = pedersenCommit(m_i, r_i) for i in [0, n)
//   commitmentsShuf : C' = pedersenCommit(m_{pi[i]}, r'_i) for i in [0, n)
//
// Returns a ShuffleProof artifact. Fiat-Shamir transcript covers both
// commitment vectors so the challenge cannot be ground out.
ShuffleProof shuffleProve(
    const std::vector<R255Scalar>& messages,
    const std::vector<R255Scalar>& openingsOrig,
    const std::vector<R255Scalar>& openingsShuf,
    const std::vector<int>& permutation,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf);

// Verifier side. Returns true iff the proof is valid for the two
// commitment vectors. The verifier does NOT need the permutation,
// messages, or openings.
bool shuffleVerify(
    const ShuffleProof& proof,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf);

// Helper: compute the Fiat-Shamir challenge from the two commitment
// vectors. Pure function of the public inputs; both prover and verifier
// compute it independently.
R255Scalar shuffleChallenge(
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf);

} // namespace mpstar
} // namespace volePSI
