#pragma once

// MPSVS Phase 6 — Bucket indexing + Goldschmidt reciprocal.
//
// Per docs/PROTOCOL_PI_SECTORVULN_R7.md §8.1 (BucketIndex) + §8.1.1
// (Goldschmidt convergence annex) + §9 fixed-point convention (k=128, f=40,
// guard=8). Enabled by the Rev 7 refactor that treats ranking as a
// bucket-histogram problem (§8) so per-entity secure division is not needed.
//
// Two primitives:
//   1. bucketIndex(num, den, edges, incl) — oblivious binary search over
//      public edges via cross-product comparisons `num vs e·den`. No
//      secure division. Returns (bucket_id, one_hot) in [0, B).
//   2. goldschmidtRecip(x_fp) — 6-iteration Newton reciprocal in fixed-point
//      (k=128, f=40, guard=8). Used ONCE per group in §8.2 and ONCE per cell
//      in §10 — never per row.
//
// Fixed-point convention (Rev 7 §9):
//   - Values represented as int128 mod 2^128 (semantic ref uses __int128).
//   - Scale factor 2^f with f=40 → 12 decimal digits precision.
//   - Guard bits = 8 → intermediate |z| < 2^{k-1-guard} = 2^119.
//
// MPC-wire upgrade replaces SecureGT (comparison) with `MpSecureCompare::
// secureLessThan` and multiplications with `MpBeaverTriple::secureMultiply`.
// The algorithm and edge table are unchanged.

#include "MpsvsInclusion.h"

#include <array>
#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Fixed-point conventions
// ---------------------------------------------------------------------------

constexpr int kFpFractionalBits = 40;   // f in Rev 7 §9
constexpr int kFpGuardBits      = 8;    // guard band
// Ring is Z_{2^128}; represented as __int128 in semantic ref.

using Fp = __int128;
inline Fp fpFromU64(uint64_t v) {
    // Encode plain u64 v as fixed-point (v · 2^f).
    return static_cast<Fp>(v) << kFpFractionalBits;
}
inline int64_t fpToInt64(Fp v) {
    // Reconstruct signed integer part (drop fractional bits).
    Fp signed_v = v;
    return static_cast<int64_t>(signed_v >> kFpFractionalBits);
}
inline double fpToDouble(Fp v) {
    // For diagnostics only — real MPC uses fixed-point everywhere.
    long double d = static_cast<long double>(v);
    long double scale = static_cast<long double>(1ULL << kFpFractionalBits);
    return static_cast<double>(d / scale);
}

// ---------------------------------------------------------------------------
// Bucket edges per metric (public; Rev 7 §9 policy sign-off)
// ---------------------------------------------------------------------------

// Rev 7 R27 locked-in default: B = 128 (Φ.radix_enabled = true at operational
// scale). Provisional log-scale edges — sign-off in Φ freeze.

// For a percentage-like metric (Delq, NPL, UnsecShare, StDebtShare) in [0, 1]
// scaled to [0, 10000] in basis points (0-100% → 0-10000 bps):
constexpr uint32_t kBucketCount = 128;

// Returns log-spaced edges spanning [lo, hi] in the value's u64 units.
// B+1 edges (last is +inf sentinel).
std::vector<uint64_t> makeLogEdges(uint64_t lo, uint64_t hi, uint32_t B);
std::vector<uint64_t> makeLinearEdges(uint64_t lo, uint64_t hi, uint32_t B);

// Provisional edge tables per metric. Real Φ sign-off overrides.
struct BucketEdges {
    std::vector<uint64_t> DTI;         // debt/income; ratio range [0, 100] → *10000 bps
    std::vector<uint64_t> DSI;         // debt_service/income
    std::vector<uint64_t> DEmp;        // debt/emp; wide range SGD/employee
    std::vector<uint64_t> IPW;         // income/emp
    std::vector<uint64_t> Delq;        // delinq/debt
    std::vector<uint64_t> NPL;
    std::vector<uint64_t> UnsecShare;
    std::vector<uint64_t> StDebtShare;
    std::vector<uint64_t> Gap;         // signed; special handling
};
BucketEdges makeDefaultBucketEdges();

// ---------------------------------------------------------------------------
// BucketIndex — oblivious binary search over public edges
// ---------------------------------------------------------------------------

// Result of a bucket lookup.
struct BucketResult {
    uint32_t              bucket = 0;   // index in [0, B)
    std::vector<uint8_t>  one_hot;      // length B; exactly one 1 if incl
};

// Perform bucket index via cross-product comparison `num*ratio_scale vs e·den`.
// - `edges[b]` is the LOWER bound of bucket b, in units of `ratio_scale*num/den`.
// - `edges.size() = B+1`; edges[B] is the +inf sentinel.
// - `ratio_scale` aligns the ratio to the edge units. For percentage-in-bp
//   metrics (Delq, NPL, DTI stored on 0..10000), pass ratio_scale=10000.
//   For absolute-unit metrics (IPW, DEmp), pass ratio_scale=1.
// - If `den` is 0 the result is bucket 0 (upstream Phase 5 sets incl=0 on
//   that row so the bucket assignment is irrelevant downstream).
// - Semantic reference does the comparison in __int128 to avoid overflow of
//   num*ratio_scale. In the MPC-wire version the comparison is `SecureGT(
//   num*ratio_scale, e*den)` over shared values.
BucketResult bucketIndex(uint64_t num, uint64_t den,
                         const std::vector<uint64_t>& edges,
                         uint8_t incl,
                         uint64_t ratio_scale = 1);

// ---------------------------------------------------------------------------
// Goldschmidt reciprocal — §8.1.1
// ---------------------------------------------------------------------------

// Compute 1/x in fixed-point. x expected in [1, N̂] (guaranteed by
// upstream `Select(n_valid > 0, n_valid, 1)` — see Phase 5).
//
// Uses 6 iterations of Newton refinement:
//   y_{t+1} = y_t · (2 − x · y_t)
// with initial approximation y_0 = 2/x for x ≤ N̂/2, else 1/x_bucket_upper.
//
// Convergence: 6 iterations → ≥ 40 bits of fractional accuracy on
// x ∈ [1, 2^20] per §8.1.1 annex.
Fp goldschmidtRecip(uint64_t x, int iterations = 6);

// Convenience: compute a fixed-point ratio num/den = num · Recip(den).
Fp fpRatio(uint64_t num, uint64_t den);

// ---------------------------------------------------------------------------
// Convergence verification (Phase 6 acceptance criterion)
// ---------------------------------------------------------------------------

// Compute the Goldschmidt reciprocal at each of the reference points and
// report accuracy in bits. Used by the test harness to reproduce Rev 7
// §8.1.1 empirical convergence table.
struct ConvergencePoint {
    uint64_t x;
    double   y_true;       // 1/x in double
    double   y_goldschmidt; // fpToDouble(goldschmidtRecip(x))
    double   rel_error;
    int      bits_of_accuracy;   // -log2(rel_error), floored
};
std::vector<ConvergencePoint> verifyGoldschmidtConvergence(
    const std::vector<uint64_t>& xs, int iterations = 6);

} // namespace mpsvs
} // namespace volePSI
