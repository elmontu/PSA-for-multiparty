#include "MpsvsRatioBucket.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Edge tables
// ---------------------------------------------------------------------------

std::vector<uint64_t> makeLinearEdges(uint64_t lo, uint64_t hi, uint32_t B) {
    std::vector<uint64_t> out(B + 1);
    long double step = (static_cast<long double>(hi) - static_cast<long double>(lo)) / B;
    for (uint32_t b = 0; b <= B; ++b) {
        out[b] = lo + static_cast<uint64_t>(step * b);
    }
    // Guarantee sentinel at last position.
    out[B] = hi;
    return out;
}

std::vector<uint64_t> makeLogEdges(uint64_t lo, uint64_t hi, uint32_t B) {
    // lo must be >= 1 for log-scale.
    if (lo < 1) lo = 1;
    if (hi <= lo) hi = lo + B;
    std::vector<uint64_t> out(B + 1);
    long double ll = std::log(static_cast<long double>(lo));
    long double lh = std::log(static_cast<long double>(hi));
    long double step = (lh - ll) / B;
    for (uint32_t b = 0; b <= B; ++b) {
        long double x = std::exp(ll + step * b);
        out[b] = static_cast<uint64_t>(x);
    }
    out[B] = hi;
    // Enforce strict monotonicity (may collapse at small ranges).
    for (uint32_t b = 1; b <= B; ++b) {
        if (out[b] <= out[b-1]) out[b] = out[b-1] + 1;
    }
    return out;
}

BucketEdges makeDefaultBucketEdges() {
    BucketEdges e;
    // Ratio metrics quoted in basis points: 0-10000 (0-100%).
    e.DTI         = makeLinearEdges(0, 10000, kBucketCount);
    e.DSI         = makeLinearEdges(0, 10000, kBucketCount);
    e.Delq        = makeLinearEdges(0, 10000, kBucketCount);
    e.NPL         = makeLinearEdges(0, 10000, kBucketCount);
    e.UnsecShare  = makeLinearEdges(0, 10000, kBucketCount);
    e.StDebtShare = makeLinearEdges(0, 10000, kBucketCount);
    // Absolute-quantity ratios: log-scale spans several orders of magnitude.
    e.DEmp        = makeLogEdges(1, 100000000ULL, kBucketCount); // 1..100M SGD/worker
    e.IPW         = makeLogEdges(1, 10000000ULL,  kBucketCount); // 1..10M
    // Gap is signed; edges are for absolute magnitude. Ranking uses signed compare.
    e.Gap         = makeLinearEdges(0, 20000, kBucketCount);   // ±100pp scaled
    return e;
}

// ---------------------------------------------------------------------------
// BucketIndex
// ---------------------------------------------------------------------------

// Oblivious binary search over public edges. Comparison at each edge e is
//   num * ratio_scale  vs  e * den
// which is division-free. In MPC-wire the comparison is `SecureGT` on shared
// values; here we do it with __int128 arithmetic (semantic reference).

BucketResult bucketIndex(uint64_t num, uint64_t den,
                         const std::vector<uint64_t>& edges,
                         uint8_t incl,
                         uint64_t ratio_scale) {
    if (edges.size() < 2)
        throw std::invalid_argument("bucketIndex: edges must have B+1 >= 2");
    if (ratio_scale == 0)
        throw std::invalid_argument("bucketIndex: ratio_scale=0");

    const uint32_t B = static_cast<uint32_t>(edges.size() - 1);
    BucketResult r;
    r.one_hot.assign(B, 0);

    if (!incl) {
        r.bucket = 0;
        return r;
    }
    if (den == 0) {
        r.bucket = 0;
        return r;
    }

    // Precompute LHS = num * ratio_scale as __int128 (safe for u64 x u64).
    __int128 lhs = static_cast<__int128>(num) * static_cast<__int128>(ratio_scale);

    // Binary search: find the largest edge index b such that
    //   edges[b] * den <= lhs
    // If lhs < edges[0] * den → bucket 0.
    // If lhs >= edges[B] * den → bucket B - 1.
    uint32_t lo = 0, hi = B;
    while (lo < hi) {
        uint32_t mid = (lo + hi + 1) / 2;   // upper-median
        __int128 rhs = static_cast<__int128>(edges[mid]) *
                        static_cast<__int128>(den);
        if (rhs <= lhs) lo = mid;
        else            hi = mid - 1;
    }
    uint32_t bucket = lo;
    if (bucket >= B) bucket = B - 1;

    r.bucket = bucket;
    r.one_hot[bucket] = 1;
    return r;
}

// ---------------------------------------------------------------------------
// Goldschmidt reciprocal
// ---------------------------------------------------------------------------

// Fixed-point multiply: (a * b) >> f, keeping in __int128 range.
// The result of a*b already exceeds 128 bits for large a,b — we perform the
// multiplication in __int128 and shift, which is valid so long as
// |a| < 2^{k-guard}/2 and |b| < 2^{k-guard}/2 (§9 guard band).
static inline Fp fpMul(Fp a, Fp b) {
    // For semantic ref, __int128 handles the product; downstream MPC uses
    // a Beaver-triple multiplication over the ring Z_{2^k} with truncation.
    // We assume operands respect the guard band.
    return static_cast<Fp>((static_cast<__int128>(a) * static_cast<__int128>(b))
                           >> kFpFractionalBits);
}

static inline Fp fpTwo() {
    return static_cast<Fp>(2) << kFpFractionalBits;
}

Fp goldschmidtRecip(uint64_t x, int iterations) {
    if (x == 0)
        throw std::invalid_argument("goldschmidtRecip: x = 0 (upstream must guard)");

    // Range-reduce x → x' ∈ (0.5, 1] by dividing by 2^p, where p is the
    // smallest power of 2 with 2^p >= x. Working in the narrow reference
    // interval gives Newton's method a good starting point (y_0 = 3 - 2x')
    // and converges quadratically to ≥ 40 bits in 6 iterations regardless
    // of x's magnitude.
    int p = 0;
    while ((1ULL << p) < x) ++p;  // smallest p with 2^p >= x

    // Encode x' = x / 2^p in fixed-point.
    // Since x has at most p bits, x_fp = x * 2^f fits, and x' fp = x_fp >> p.
    // Equivalent (and avoids intermediate 2^f overflow for large p+bits):
    //   x' fp = x * 2^{f-p}  when p <= f
    //         = x_fp >> p    always
    Fp x_prime_fp;
    if (p <= kFpFractionalBits) {
        x_prime_fp = static_cast<Fp>(x) << (kFpFractionalBits - p);
    } else {
        // p > f: x is very large. Shift right to fit.
        x_prime_fp = static_cast<Fp>(x) >> (p - kFpFractionalBits);
    }

    // Initial approximation y_0 = 3 - 2 * x' — first-order Newton starter.
    // For x' ∈ [0.5, 1], y_0 ∈ [1, 2], within convergence radius of true 1/x'.
    Fp two_x_prime = static_cast<Fp>(2) * x_prime_fp;  // no scaling: 2x' still fp
    Fp three_fp    = static_cast<Fp>(3) << kFpFractionalBits;
    Fp y           = three_fp - two_x_prime;

    // Newton refinement: y_{t+1} = y_t * (2 - x' * y_t).
    // Each iteration doubles the bits of accuracy; 6 iterations from ~4 bits
    // of initial accuracy → 4 · 2^6 = 256 bits (bounded by fp precision).
    for (int t = 0; t < iterations; ++t) {
        Fp xy = fpMul(x_prime_fp, y);
        Fp two_minus_xy = fpTwo() - xy;
        y = fpMul(y, two_minus_xy);
    }

    // y ≈ 1/x'. Rescale: 1/x = (1/x') / 2^p ⇔ shift right by p in fixed-point.
    if (p > 0) {
        // Signed shift for negative fp (shouldn't happen here, y>=1) but safe.
        y = y >> p;
    }
    return y;
}

Fp fpRatio(uint64_t num, uint64_t den) {
    if (den == 0)
        throw std::invalid_argument("fpRatio: den=0 (upstream should Select(den>0,den,1))");
    Fp inv = goldschmidtRecip(den);
    Fp num_fp = fpFromU64(num);
    return fpMul(num_fp, inv);
}

// ---------------------------------------------------------------------------
// Convergence verification
// ---------------------------------------------------------------------------

std::vector<ConvergencePoint>
verifyGoldschmidtConvergence(const std::vector<uint64_t>& xs, int iterations) {
    std::vector<ConvergencePoint> out;
    out.reserve(xs.size());
    for (uint64_t x : xs) {
        ConvergencePoint p;
        p.x = x;
        p.y_true = 1.0 / static_cast<double>(x);
        Fp y_fp = goldschmidtRecip(x, iterations);
        p.y_goldschmidt = fpToDouble(y_fp);
        p.rel_error = (p.y_true == 0.0) ? 0.0
                       : std::abs(p.y_goldschmidt - p.y_true) / p.y_true;
        p.bits_of_accuracy = (p.rel_error <= 0.0)
                              ? 60
                              : static_cast<int>(std::floor(-std::log2(p.rel_error)));
        if (p.bits_of_accuracy < 0) p.bits_of_accuracy = 0;
        if (p.bits_of_accuracy > 60) p.bits_of_accuracy = 60;
        out.push_back(p);
    }
    return out;
}

} // namespace mpsvs
} // namespace volePSI
