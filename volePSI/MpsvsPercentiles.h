#pragma once

// MPSVS Phase 10 — GroupPercentiles via histogram CDF inversion (§11).
//
// Given a histogram h[0..B) (from Phase 8 RankViaHistogram, aggregated over
// a group), and a target quantile q ∈ [0, 1], compute the bucket b* whose
// CDF crosses q:
//   b* = min{b : CDF[b] >= q · N}    with N = Σ h[b].
//
// Rev 7 §12 requires post-DP-noise clamp `h̃[b] ← max(0, h̃[b])` before
// prefix-sum so the CDF is non-decreasing (R26). Without R26, DP noise can
// produce negative counts → CDF non-monotone → binary search inversion
// wanders and produces silently wrong percentiles.
//
// Semantic reference: plaintext CDF + linear scan (Phase 12 provides the DP
// clamp). MPC-wire upgrade uses oblivious segmented prefix-sum and oblivious
// binary search over the sealed CDF.

#include "MpsvsRank.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

// A CDF is a non-decreasing prefix-sum of a histogram (post any DP clamp).
struct Cdf {
    std::vector<uint64_t> cum;    // size = B; cum[b] = Σ_{i ≤ b} h[i]
    uint64_t              N;      // total = cum.back()
    bool                  monotone; // true iff cum is non-decreasing
};

// Build CDF from histogram. Sets `monotone` accordingly (defensive check;
// with proper R26 clamp this is always true).
Cdf makeCdf(const Histogram& h);

// Percentile query. `q` in [0, 1] (as double). Returns the bucket index b*
// whose CDF first reaches ⌈q · N⌉. If N == 0, returns 0.
uint32_t percentileBucket(const Cdf& cdf, double q);

// Batch queries for standard percentiles (25/50/75/90/95/99).
struct StdPercentiles {
    uint32_t p25;
    uint32_t p50;
    uint32_t p75;
    uint32_t p90;
    uint32_t p95;
    uint32_t p99;
};
StdPercentiles standardPercentiles(const Cdf& cdf);

// Value at bucket midpoint (§11.2) — maps bucket index back to the metric's
// representative value using the same public edges from Phase 6.
double bucketMidpoint(uint32_t bucket, const std::vector<uint64_t>& edges);

} // namespace mpsvs
} // namespace volePSI
