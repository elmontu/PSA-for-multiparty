#include "MpsvsReciprocalVerify.h"

#include <algorithm>

namespace volePSI {
namespace mpsvs {

bool verifyReciprocalAuth(const AuthSharedU64& x_arith,
                            const AuthSharedU64& y_fp,
                            uint64_t alpha,
                            uint32_t f_bits,
                            uint64_t tolerance,
                            const AuthBeaverTriple& triple) {
    // Step 1: compute [z] = [y_fp] · [x_arith] via authenticated Beaver mult.
    // authSecureMultiply now throws AuthShareMacFailure on MAC-check failure
    // during d/e opening (replacing the earlier poisoned-share path); catch
    // and convert to a false return so this API remains bool-typed for the
    // caller. The failure is a hard abort at the protocol layer.
    AuthSharedU64 z;
    try {
        z = authSecureMultiply(y_fp, x_arith, triple, alpha);
    } catch (const AuthShareMacFailure&) {
        return false;
    }

    // Step 2: open with MAC check.
    uint64_t z_plain = 0;
    if (!openWithMacCheck(z, alpha, z_plain)) return false;

    // Step 3: verify z ≈ 2^f. Compute |z - 2^f|.
    uint64_t expected = static_cast<uint64_t>(1) << f_bits;
    uint64_t diff = (z_plain > expected) ? (z_plain - expected) : (expected - z_plain);
    return diff <= tolerance;
}

bool verifyReciprocalAuthShared(const AuthSharedU64& x_arith,
                                   const AuthSharedU64& y_fp,
                                   const AlphaShare& alpha,
                                   uint32_t f_bits,
                                   uint64_t tolerance,
                                   const AuthBeaverTriple& triple) {
    // Step 1: [z] = [y_fp] · [x_arith] via shared-α Beaver mult.
    AuthSharedU64 z;
    try {
        z = authSecureMultiplyShared(y_fp, x_arith, triple, alpha);
    } catch (const AuthShareMacFailure&) {
        return false;
    }

    // Step 2: open with shared-α MAC check (α stays split).
    uint64_t z_plain = 0;
    if (!openWithMacCheckShared(z, alpha, z_plain)) return false;

    // Step 3: verify z ≈ 2^f. Compute |z - 2^f|.
    uint64_t expected = static_cast<uint64_t>(1) << f_bits;
    uint64_t diff = (z_plain > expected) ? (z_plain - expected)
                                            : (expected - z_plain);
    return diff <= tolerance;
}

AuthSharedU64 generateWrongReciprocal(uint32_t N, uint64_t wrong_value,
                                        uint64_t alpha, oc::PRNG& prng) {
    // Malicious server outputs a random wrong value as the "reciprocal".
    return authShareU64(N, wrong_value, alpha, prng);
}

} // namespace mpsvs
} // namespace volePSI
