#pragma once

// MPSVS Phase 11 — MPC-wire sector aggregation.
//
// Additive share sum per (sector, period, metric). No Beaver triples needed
// — addition is local on additive shares over Z_{2^64}.
//
// Input: shared entity metrics (from Phase 5 wire; num/den are SharedU64Bin
//        which we convert to arithmetic-shared SharedU64 for summation).
//
// Bit-to-arithmetic conversion: bit share s^A · (1 - 2·s^B) + s^B = plain bit
// — for a single bit this is trivial (arithmetic share of bit = the bit
// itself for one party, but we hold XOR shares). For our case, we can
// convert via: bit_arith = bit_share_p0 + bit_share_p1 - 2 · bit_share_p0 · bit_share_p1,
// which requires ONE Beaver triple per bit. For a 64-bit value that's 64
// triples per B2A. Given we only need to convert (num, den, incl) → arithmetic
// once per row, cost is O(64) triples per (row, metric, num/den) = 8·2·64 = 1024
// triples per row.
//
// Alternative for aggregation: since incl is a bit and num/den are u64s, we
// can compute the "gated sum" directly on bit shares:
//   sum_num_shared = Σ_i (incl_i · num_i)
// where each `incl_i · num_i` term is a SharedU64Bin multiplied by a shared
// bit → this is a "MUX" operation: (bit, val) → (bit ? val : 0), which for
// bit shares is `val · bit` and can be computed bit-wise via 64 secureAnd
// per (row, metric) = 64 · 9 · #rows triples.
//
// This wire module implements the MUX-based path.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpSecureCompare.h"
#include "MpsvsInclusion.h"
#include "MpsvsInclusionWire.h"
#include "MpsvsSectorAgg.h"

#include <cstdint>
#include <map>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::SharedBit;
using mpstar::SharedU64;
using mpstar::SharedU64Bin;

// Shared cell result: (sector, period, metric) — arithmetic-shared sums.
struct SharedSectorHistogram {
    SectorKey  key;
    Metric     metric;
    // sum_num, sum_den, n_valid as arithmetic-shared u64 (over Z_{2^64}).
    SharedU64  sum_num;
    SharedU64  sum_den;
    SharedU64  n_valid;
};

// Per-row triple cost estimate for aggregation:
// - Per metric: 64 secureAnd for (incl · num) MUX + 64 for (incl · den) MUX
//               + 1 for (incl arith conversion via secureAnd on bits)
// - 9 metrics → 9 · (128 + 1) = 1161 triples per row.
size_t sectorAggTripleBudgetPerRow();

// Aggregate a batch of shared entity metric rows into per-cell shared totals
// for one metric. Consumes triples from the bag.
std::vector<SharedSectorHistogram>
aggregateHistogramsWire(const std::vector<SharedEntityMetricRow>& rows,
                        Metric m,
                        const std::vector<BeaverTripleBit>& triples,
                        size_t& tripleIndex,
                        oc::PRNG& prng);

// Test helper: reconstruct a shared histogram cell to plain (sum_num,
// sum_den, n_valid). Joint operation.
struct PlainCellReconstructed {
    SectorKey key;
    Metric    metric;
    uint64_t  sum_num;
    uint64_t  sum_den;
    uint64_t  n_valid;
};
PlainCellReconstructed reconstructCell(const SharedSectorHistogram& s);

} // namespace mpsvs
} // namespace volePSI
