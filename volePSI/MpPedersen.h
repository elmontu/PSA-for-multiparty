#pragma once

// Pedersen commitments over Ristretto255 (R27 dependency).
//
// Commitment: c = g^m * h^r where g, h are independent generators
// (g = R255Point::generator(), h = R255Point::pedersenH()), m is the
// committed message (scalar), r is the random opening (scalar).
//
// Properties:
//   - PERFECTLY HIDING: c reveals no information about m to anyone who
//     doesn't know r.
//   - COMPUTATIONALLY BINDING: under DLog hardness in Ristretto255,
//     finding (m, r) ≠ (m', r') with same c is infeasible.
//
// Homomorphic addition: commit(m1, r1) + commit(m2, r2)
//                     = commit(m1+m2, r1+r2)
// This is used in the shuffle NIZK to combine commitments under random
// linear combinations.

#include "MpRistretto.h"

#include <vector>

namespace volePSI {
namespace mpstar {

struct PedersenCommitment {
    R255Point c;
};

// commit(m, r) = g^m * h^r.
PedersenCommitment pedersenCommit(const R255Scalar& m, const R255Scalar& r);

// Verify that (c, m, r) is a valid opening. Returns true iff c = g^m * h^r.
bool pedersenVerify(const PedersenCommitment& c,
                    const R255Scalar& m,
                    const R255Scalar& r);

// Homomorphic add: commit(m1, r1) + commit(m2, r2) = commit(m1+m2, r1+r2).
PedersenCommitment pedersenAdd(const PedersenCommitment& a,
                               const PedersenCommitment& b);

// Scalar multiplication on a commitment: k * commit(m, r) = commit(k*m, k*r).
PedersenCommitment pedersenScalarMul(const R255Scalar& k,
                                     const PedersenCommitment& c);

// Compute a vector of commitments to messages with given openings.
std::vector<PedersenCommitment> pedersenCommitVector(
    const std::vector<R255Scalar>& messages,
    const std::vector<R255Scalar>& openings);

// Generate fresh openings (uniformly random scalars), one per message.
std::vector<R255Scalar> freshOpenings(size_t count);

} // namespace mpstar
} // namespace volePSI
