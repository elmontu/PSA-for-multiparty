#pragma once

// MPSVS Phase 17.5 — Bit membership proof (Chaum-Pedersen OR proof).
//
// Given a Pedersen commitment C = g^b · h^r, prove in ZK that b ∈ {0, 1}
// WITHOUT revealing which one (or r).
//
// This is the 1-bit specialization of a range proof: MPSVS's `memb` bits
// (per source, per row) must be provably 0 or 1 to prevent a malicious
// source from smuggling in non-boolean values (e.g., memb=42) that could
// corrupt the inclusion-bit AND-chain in Phase 5.
//
// Full Bulletproofs would handle arbitrary ranges [0, 2^n) via inner-product
// arguments, but for our specific need (b ∈ {0, 1}), Chaum-Pedersen OR proof
// gives the same guarantee at ~200 LOC vs ~2000 for Bulletproofs.
//
// Protocol (standard Chaum-Pedersen OR):
//   Prove: C = g^0·h^r0  OR  C = g^1·h^r1
//   ⇔    C = h^r0  OR  C·g^-1 = h^r1
//
//   Case b=0 (know r):
//     Real Schnorr on H proving DL of C w.r.t. h.
//     Simulated Schnorr on the b=1 branch.
//   Case b=1 (know r):
//     Simulated Schnorr on the b=0 branch.
//     Real Schnorr on H proving DL of (C·g^-1) w.r.t. h.
//
// Verifier: recompute Fiat-Shamir challenge, split into c0, c1 (sum matches),
// check each branch's Schnorr equation.

#include "MpPedersen.h"
#include "MpRistretto.h"

#include <cstdint>

namespace volePSI {
namespace mpsvs {

using mpstar::PedersenCommitment;
using mpstar::R255Point;
using mpstar::R255Scalar;

// Chaum-Pedersen OR proof for bit membership.
struct BitProof {
    R255Point  A0, A1;   // Schnorr announcements per branch
    R255Scalar c0, c1;   // per-branch challenges (c0 + c1 = c_combined)
    R255Scalar s0, s1;   // per-branch responses
};

// Pedersen commit for a small integer, handling b=0 correctly.
// (libsodium's scalarMultBase rejects zero; this helper computes g^0·h^r
// = h^r directly.)
PedersenCommitment commitBit(int b, const R255Scalar& r);

// Prove that C = g^b · h^r with b ∈ {0, 1}.
// If b ∉ {0, 1}, throws (no valid proof).
BitProof proveBit(int bit, const R255Scalar& r, const PedersenCommitment& C);

// Verify a BitProof against commitment C.
// Returns TRUE iff C opens to bit ∈ {0, 1}.
bool verifyBit(const BitProof& proof, const PedersenCommitment& C);

// Test-only: attempt to construct a "proof" for a non-boolean value.
// The result WILL NOT verify (that's the point — this catches malicious).
BitProof forgeNonBoolean(int fake_bit, const R255Scalar& r,
                          const PedersenCommitment& C);

} // namespace mpsvs
} // namespace volePSI
