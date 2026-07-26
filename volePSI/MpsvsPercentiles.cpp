#include "MpsvsPercentiles.h"

#include <cmath>

namespace volePSI {
namespace mpsvs {

Cdf makeCdf(const Histogram& h) {
    Cdf c;
    c.cum.assign(h.h.size(), 0);
    uint64_t acc = 0;
    c.monotone = true;
    for (size_t i = 0; i < h.h.size(); ++i) {
        uint64_t before = acc;
        acc += h.h[i];
        c.cum[i] = acc;
        if (acc < before) c.monotone = false;   // shouldn't happen post R26
    }
    c.N = acc;
    return c;
}

uint32_t percentileBucket(const Cdf& cdf, double q) {
    if (cdf.N == 0 || cdf.cum.empty()) return 0;
    if (q < 0.0) q = 0.0;
    if (q > 1.0) q = 1.0;
    // Target rank ⌈q · N⌉ (1-indexed).
    uint64_t target = static_cast<uint64_t>(std::ceil(q * cdf.N));
    if (target == 0) target = 1;
    // Oblivious binary search over cum: find smallest b with cum[b] >= target.
    uint32_t lo = 0, hi = static_cast<uint32_t>(cdf.cum.size()) - 1;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (cdf.cum[mid] >= target) hi = mid;
        else                        lo = mid + 1;
    }
    return lo;
}

StdPercentiles standardPercentiles(const Cdf& cdf) {
    return {
        percentileBucket(cdf, 0.25),
        percentileBucket(cdf, 0.50),
        percentileBucket(cdf, 0.75),
        percentileBucket(cdf, 0.90),
        percentileBucket(cdf, 0.95),
        percentileBucket(cdf, 0.99),
    };
}

double bucketMidpoint(uint32_t bucket, const std::vector<uint64_t>& edges) {
    if (edges.size() < 2) return 0.0;
    uint32_t B = static_cast<uint32_t>(edges.size() - 1);
    if (bucket >= B) bucket = B - 1;
    return 0.5 * (static_cast<double>(edges[bucket]) +
                  static_cast<double>(edges[bucket + 1]));
}

} // namespace mpsvs
} // namespace volePSI
