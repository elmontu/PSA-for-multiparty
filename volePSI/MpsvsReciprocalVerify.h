#pragma once

// MPSVS Phase 17.6 — Algebraic consistency check for reciprocal computation.
//
// Setup: after a Goldschmidt reciprocal produces claimed shared output
// [y_fp] such that y ≈ 1/x in fixed-point (y_fp = 2^f · (1/x_actual) for
// integer input x, per §8.1.1), we want a MALICIOUS-SECURE check that y
// is actually a valid reciprocal.
//
// Invariant to verify:  y_fp · x ≡ 2^f  (mod 2^k, with fp precision tolerance)
//
// Algorithm:
//   1. Compute [z] = [y_fp] · [x_arith]  via authenticated Beaver mult.
//      Note: this is the u64 multiplication, NOT fp mult — we're checking
//      the RAW invariant y_fp · x = 2^f.
//   2. Open [z] with MAC check (Phase 17.1).
//   3. Verify |z - 2^f| ≤ tolerance.
//
// If y is a correct fp reciprocal, z = 2^f exactly (up to Goldschmidt's
// numerical error, which is bounded by the algorithm's convergence).
//
// If y is malicious (arbitrary value), z will differ from 2^f with high
// probability, and the check fails.
//
// Attack surface addressed: malicious server returns wrong y and hopes the
// downstream ratio computation gives them an advantage. This check catches
// that at the Goldschmidt output boundary.

#include "MpsvsAuthShare.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>

namespace volePSI {
namespace mpsvs {

// Verify authenticated reciprocal: check y_fp · x ≈ 2^f (within tolerance).
// Consumes one auth Beaver triple.
// Returns TRUE if the reciprocal invariant holds; FALSE if malicious.
bool verifyReciprocalAuth(const AuthSharedU64& x_arith,
                            const AuthSharedU64& y_fp,
                            uint64_t alpha,
                            uint32_t f_bits,
                            uint64_t tolerance,
                            const AuthBeaverTriple& triple);

// Shared-α (DPSZ) variant of the reciprocal verify. Uses
// authSecureMultiplyShared + openWithMacCheckShared, so α is never
// reconstructed. Correct threat model for the full-malicious S1 vs S2
// deployment.
bool verifyReciprocalAuthShared(const AuthSharedU64& x_arith,
                                   const AuthSharedU64& y_fp,
                                   const AlphaShare& alpha,
                                   uint32_t f_bits,
                                   uint64_t tolerance,
                                   const AuthBeaverTriple& triple);

// Test-only: create an INTENTIONALLY WRONG reciprocal claim.
// Simulates a malicious server that outputs y_fp = wrong_value regardless
// of x. Should FAIL verifyReciprocalAuth.
AuthSharedU64 generateWrongReciprocal(uint32_t N, uint64_t wrong_value,
                                        uint64_t alpha, oc::PRNG& prng);

} // namespace mpsvs
} // namespace volePSI
