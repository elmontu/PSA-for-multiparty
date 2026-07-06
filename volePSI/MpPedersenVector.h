#pragma once

// R37: Pedersen VECTOR commitment over Ristretto255.
//
//     C = g_1^{m_1} * g_2^{m_2} * ... * g_n^{m_n} * h^r
//
// where g_1, ..., g_n are independent generators derived from
// hash-to-curve (fresh domain separator per vector index), h is the
// same Pedersen H used elsewhere, and r is a uniform-random opening.
//
// Properties:
//   PERFECTLY HIDING: C reveals no information about (m_i) to anyone
//     who doesn't know r.
//   COMPUTATIONALLY BINDING: finding a distinct opening (m'_1,...,m'_n,r')
//     with the same C requires solving DLog in Ristretto255.
//   HOMOMORPHIC: componentwise vector addition; scalar multiplication
//     lifts to exponents.
//
// Used as the foundation for R27c full Bayer-Groth arguments where the
// prover commits to the shifted-message vector (m_i + y) and either
// opens it (for audit-mode publicly verifiable soundness) or uses a
// recursive halving proof (for zero-knowledge; not in this build).

#include "MpRistretto.h"
#include "MpPedersen.h"

#include <cstdint>
#include <string>
#include <vector>

namespace volePSI {
namespace mpstar {

struct PedersenVectorCommitment {
    R255Point c;
};

// Derive the i-th generator g_i via hash-to-curve on a fixed domain
// separator + index. Callers can cache the generator vector; each
// generator is deterministic across processes.
R255Point pedersenVectorGenerator(size_t i);

// Commit to a vector of messages under a single opening.
PedersenVectorCommitment pedersenVectorCommit(
    const std::vector<R255Scalar>& messages,
    const R255Scalar& opening);

// Verify (messages, opening) is a valid opening of the commitment.
bool pedersenVectorVerify(
    const PedersenVectorCommitment& commit,
    const std::vector<R255Scalar>& messages,
    const R255Scalar& opening);

// Homomorphic addition of two vector commitments (must be same length).
PedersenVectorCommitment pedersenVectorAdd(
    const PedersenVectorCommitment& a,
    const PedersenVectorCommitment& b);

// R37c: audit-mode shuffle proof that closes the sum-preserving multiset
// tampering gap from R27b.
//
// Prover commits to the shifted-message vector (m_i + y) via vector
// commitment. Prover then OPENS the commitment (reveals all shifted
// messages + opening) as part of the proof. Verifier:
//   1. Homomorphically derives the expected shifted-commitment vector
//      from the original per-element Pedersen commitments C = (c_1, ..., c_n).
//   2. Verifies the opened vector commitment against the prover's
//      revealed values.
//   3. Verifies the same multiset check for C'.
//   4. Since prover is bound to the ACTUAL shifted messages, any
//      permutation-preserving-sum tampering that changes the multiset
//      is now cryptographically caught.
//
// TRADE-OFF: this variant is NOT zero-knowledge on the shifted
// messages (they're revealed after the challenge y is committed). It
// IS sound. Appropriate for AUDIT scenarios where correctness matters
// but shifted-value confidentiality does not. The zero-knowledge
// variant is R27c-full via recursive Pedersen-vector opening
// (documented; not implemented).
struct ShuffleProofAudit {
    R255Scalar challengeY;
    R255Scalar challengeZ;                 // for random-weighted per-element binding
    std::vector<R255Scalar> shiftedOrig;   // m_i + y for i = 1..n (revealed)
    std::vector<R255Scalar> shiftedShuf;   // m'_i + y (revealed)
    R255Scalar weightedOpeningOrig;        // Σ z^i · r_i
    R255Scalar weightedOpeningShuf;        // Σ z^i · r'_i
};

// Fiat-Shamir challenge for the audit variant. Same transcript as
// fsChallengeY_bg, distinct domain separator.
R255Scalar fsChallengeY_audit(
    const std::vector<PedersenCommitment>& C,
    const std::vector<PedersenCommitment>& Cprime);

// Prover: takes plaintext messages + openings + permutation +
// per-element commitments. Returns the audit proof artifact.
ShuffleProofAudit shuffleProveAudit(
    const std::vector<R255Scalar>& messages,
    const std::vector<R255Scalar>& openingsOrig,
    const std::vector<R255Scalar>& openingsShuf,
    const std::vector<int>& permutation,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf);

// Verifier: uses ONLY the commitments + proof. Returns true iff the
// shuffle is valid.
bool shuffleVerifyAudit(
    const ShuffleProofAudit& proof,
    const std::vector<PedersenCommitment>& commitmentsOrig,
    const std::vector<PedersenCommitment>& commitmentsShuf);

} // namespace mpstar
} // namespace volePSI
