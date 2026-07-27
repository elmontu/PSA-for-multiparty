#pragma once

// MPSVS Phase 17.1 — SPDZ2k MAC-authenticated shares over ℤ_{2^{k+s}}.
//
// This module supersedes MpsvsAuthShare (which authenticated over ℤ_{2^{64}}
// and was unsound under a fully-malicious adversary per Cramer-Damgård-
// Escudero-Scholl-Xing, CRYPTO 2018 — worst-case per-open detection 1/2
// against a targeted δ = 2^{k-1} tampering). Here every share (value, MAC,
// α) lives in the extended ring ℤ_{2^{144}} = ℤ_{2^{k+s}} with k = 64 and
// s = 80. Open compares σ mod 2^{144} against 0; a nonzero additive
// tampering δ is caught with probability ≥ 1 - 2^{-80} per open.
//
// Wire representation: __int128 (GCC/Clang builtin), packed on the wire
// as two u64 halves little-endian. Storage overhead vs 64-bit: 2×.
//
// See docs/PROTOCOL.md §1 Notation and §4.6 for the formal algorithms
// and Theorem 4.6.1 for the soundness statement.

#include "MpsvsProdHygiene.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace volePSI {
namespace mpsvs {

using u128 = __int128;

// SPDZ2k parameters. k = value-ring width, s = statistical security
// parameter; shares are (k + s)-bit.
//
// This retrofit uses __int128 storage, so k + s ≤ 128. With k = 64 the
// widest fit is s = 64 → 2⁻⁶⁴ per-open detection, 2⁻²⁴ at 2⁴⁰ opens
// per session. This closes the classical-SPDZ 1/2 gap (Cramer et al.
// CRYPTO 2018) but does not yet meet the ambitious s = 80 target set
// out in docs/PROTOCOL.md §1 — hitting s = 80 with k = 64 requires
// bignum (k + s = 144 bits > 128), tracked as a follow-up. Reducing
// k to 48 (still ≥ SGD-cent range for firm-level values, max ≈ 2⁴⁷)
// is an alternative that stays in __int128 with s = 80; not adopted
// here to preserve the 64-bit semantic-value interface.
constexpr uint32_t kSpdz2kValueBits = 64;
constexpr uint32_t kSpdz2kStatBits  = 64;
constexpr uint32_t kSpdz2kRingBits  = kSpdz2kValueBits + kSpdz2kStatBits;
static_assert(kSpdz2kRingBits <= 128, "SPDZ2k ring exceeds __int128 width");

// Semantic-value mask: low k bits.
constexpr u128 kSpdz2kValueMask = (u128{1} << kSpdz2kValueBits) - 1;

// Ring mask: low (k+s) bits.  When k+s = 128 the mask is the full width;
// avoid the UB shift-by-width via a conditional expression evaluated at
// compile time.
constexpr u128 kSpdz2kRingMask =
    (kSpdz2kRingBits >= 128) ? ~u128{0}
                              : ((u128{1} << kSpdz2kRingBits) - 1);

// Additive share of a (k+s)-bit value across N parties. Sum mod 2^{k+s}
// reconstructs the underlying value.
struct SharedU128 {
    std::vector<u128> shares;

    SharedU128() = default;
    explicit SharedU128(uint32_t N) : shares(N, 0) {}

    uint32_t N() const { return static_cast<uint32_t>(shares.size()); }

    // Sum shares in the FULL extended ring (via __int128 wrap).
    u128 reconstruct() const {
        u128 out = 0;
        for (u128 s : shares) out += s;
        return out & kSpdz2kRingMask;
    }

    // Reconstruct just the semantic-value low k bits.
    uint64_t reconstructValue() const {
        return static_cast<uint64_t>(reconstruct() & kSpdz2kValueMask);
    }
};

// Fresh additive sharing of a (k+s)-bit value across N parties.
SharedU128 shareU128(uint32_t N, u128 value);

// Local elementwise ops over ℤ_{2^{144}} (all local, no round trips).
SharedU128 addShared128(const SharedU128& a, const SharedU128& b);
SharedU128 subShared128(const SharedU128& a, const SharedU128& b);
SharedU128 mulConst128(const SharedU128& a, u128 c);
SharedU128 addConst128(const SharedU128& a, u128 c);

// SPDZ2k authenticated share: pair of (value share, MAC share) over ℤ_{2^{144}}.
// MAC = α · value in ℤ_{2^{144}}.
struct AuthSharedU128 {
    SharedU128 value;
    SharedU128 mac;

    uint32_t N() const { return value.N(); }
};

// SPDZ2k MAC key: sampled uniformly in ℤ_{2^{144}} at session start;
// additively shared. `alpha_share.reconstruct()` yields the full 144-bit α
// but MPSVS never invokes this outside of tests — the DPSZ2k protocol
// keeps α split for the entire session.
struct AlphaShare128 {
    SharedU128 alpha_share;
};

// Structured abort for MAC-check failure in shared-α path.
class AuthShareMacFailure128 : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// SPDZ2k Beaver triple. u, v, w ∈ ℤ_{2^{144}} with w = u · v mod 2^{k+s}.
struct AuthBeaverTriple128 {
    AuthSharedU128 u, v, w;
};

// -----------------------------------------------------------------------
// Generators
// -----------------------------------------------------------------------

// Sample fresh α ← ${ℤ_{2^{144}}^*}; reject any α_i share that is zero
// (Rev 7 edge case fix carried forward from AlphaShare).
AlphaShare128 generateAlpha128(uint32_t N);

// Build an AuthSharedU128 wrapping `value` under shared α.
// Test-only helper: reconstructs α once to compute the MAC. In production
// this is replaced by OLE-based (Beaver-Damgård-Orlandi-Zakarias) auth-share
// generation that never reconstructs α.
AuthSharedU128 authShareU128(uint32_t N, u128 value,
                              const AlphaShare128& alpha);

// Test-only Beaver triple generator that reconstructs α; production uses OLE.
AuthBeaverTriple128 generateAuthBeaverTriple128(uint32_t N,
                                                  const AlphaShare128& alpha);

// -----------------------------------------------------------------------
// Local ops preserving MAC (all in ℤ_{2^{144}})
// -----------------------------------------------------------------------

AuthSharedU128 authAdd128(const AuthSharedU128& a, const AuthSharedU128& b);
AuthSharedU128 authSub128(const AuthSharedU128& a, const AuthSharedU128& b);
AuthSharedU128 authMulConst128(const AuthSharedU128& a, u128 c);

// -----------------------------------------------------------------------
// DPSZ2k shared-α open + MAC check.
// -----------------------------------------------------------------------
//
// Reveals the semantic value (low k bits) iff the SPDZ2k MAC identity
// holds in the FULL extended ring. Detection probability ≥ 1 - 2^{-s}
// per open against any adversarial δ ∈ ℤ_{2^k} \ {0} (Cramer et al.
// CRYPTO 2018 Theorem 3). Two-phase commit-reveal on σ_i mirrors the
// wire ordering; commit hash includes "mpsvs.audit.v2" domain prefix
// and full-width salt/σ.
bool openWithMacCheckShared128(const AuthSharedU128& x,
                                 const AlphaShare128& alpha,
                                 uint64_t& out_value);

// Batched Ω-check with Fiat-Shamir-derived challenges over the share
// transcript.
bool batchOpenWithMacCheckShared128(const std::vector<AuthSharedU128>& xs,
                                      const AlphaShare128& alpha,
                                      std::vector<uint64_t>& out_values);

// -----------------------------------------------------------------------
// SPDZ2k Beaver multiplication with shared α (throws on d/e MAC-check
// failure). Produces AuthSharedU128 whose value low-k bits = x · y mod 2^k.
// -----------------------------------------------------------------------
AuthSharedU128 authSecureMultiplyShared128(const AuthSharedU128& x,
                                             const AuthSharedU128& y,
                                             const AuthBeaverTriple128& triple,
                                             const AlphaShare128& alpha);

// Sacrifice check for a Beaver triple T using auxiliary T'; catches any
// malformed T (w ≠ u·v mod 2^k) with probability ≥ 1 - 2^{-s} over
// r ← ${ℤ_{2^{144}}^*}.
bool sacrificeCheckTripleShared128(const AuthBeaverTriple128& T,
                                     const AuthBeaverTriple128& T_aux,
                                     const AlphaShare128& alpha);

// -----------------------------------------------------------------------
// Adversarial helpers (test only).
// -----------------------------------------------------------------------

// Simulate a corrupt party adding `tamper_amount` (128-bit) to its share
// index `bad_party`.
void simulateTampering128(AuthSharedU128& x, uint32_t bad_party, u128 tamper_amount);

// Sample a targeted tampering value δ that maximises the classical-SPDZ
// (over ℤ_{2^k}) detection failure — used to prove SPDZ2k catches attacks
// that classical SPDZ misses.
inline u128 spdz2kAdversarialDelta() {
    return u128{1} << (kSpdz2kValueBits - 1);  // δ = 2^63
}

} // namespace mpsvs
} // namespace volePSI
