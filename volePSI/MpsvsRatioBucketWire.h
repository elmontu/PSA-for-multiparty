#pragma once

// MPSVS Phase 6 — MPC-wire BucketIndex.
//
// Given shared (num, den) and PUBLIC edges + ratio_scale, produce a shared
// one-hot indicator over B buckets via B-1 secureLessThan comparisons.
//
// Comparison at edge e: SecureGT(num · ratio_scale, e · den).
//   - num · ratio_scale: num_arith (from Phase 11 wire's B2A) multiplied by
//     public constant → mulConst (free).
//   - e · den: same shape (public × arith share).
//   - Both operands need to be bit-shared for secureLessThan. Use per-bit
//     B2A_reverse (arithmetic-to-binary) — costs O(k) triples per number
//     (Damgård-Nielsen §10.4). For prototype we take a shortcut: do the
//     comparisons in the ARITHMETIC domain via the "sign of difference"
//     trick, which requires just ONE bit-decomposition per compare.
//
// Actually the cleanest path: expose the comparisons in bit-shared form.
// Since num and den entered Phase 5 as SharedU64Bin (bit-shared), the
// Phase 6 wire keeps them bit-shared and applies public-constant multiply
// via bit-level shift-and-add.
//
// Goldschmidt reciprocal wire is DEFERRED — requires full arithmetic-domain
// Newton iteration with per-iter secureMultiply + range-reduction, which is
// substantial (~10× the wire code of this bucket module). Marked in Phase
// 17 malicious-upgrade register as a required future primitive.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpSecureCompare.h"
#include "MpsvsInclusion.h"
#include "MpsvsInclusionWire.h"
#include "MpsvsRatioBucket.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::SharedBit;
using mpstar::SharedU64Bin;

// Shared bucket-lookup result. One-hot indicator over B buckets.
struct SharedBucketResult {
    std::vector<SharedBit> one_hot;   // size = B
    SharedU64Bin           bucket_index;   // shared bucket ID (log2 B bits used)
};

// Cost estimate: B-1 secureLessThan + B-1 sequencing ANDs.
// secureLessThanTripleCost per comparison ≈ 192.
size_t bucketWireTripleBudget(uint32_t B);

// Public-constant multiply on a bit-shared u64. Uses O(64) full-adders on
// bit shares. Returns a SharedU64Bin representing (x · c) mod 2^64.
// Cost: for each set bit of c, one 64-bit ripple-carry adder = 64 bit
// full-adders × 3 ANDs = 192 triples. Total ≤ 64 · 192 = 12288 triples.
// In practice `c` has ≤ 14 bits (10000 for bp scale) → 14 · 192 = 2688 triples.
SharedU64Bin mulPublicConstBitShared(const SharedU64Bin& x, uint64_t c,
                                       const std::vector<BeaverTripleBit>& triples,
                                       size_t& tripleIndex);

// Shared bucketIndex: comparison-based binary search over public edges.
// Consumes triples starting at `tripleIndex`.
SharedBucketResult
bucketIndexWire(const SharedU64Bin& num,
                 const SharedU64Bin& den,
                 const std::vector<uint64_t>& edges,
                 const SharedBit& incl,
                 uint64_t ratio_scale,
                 const std::vector<BeaverTripleBit>& triples,
                 size_t& tripleIndex);

// Reconstruct the one-hot indicator to plain bucket ID (test helper).
uint32_t reconstructBucket(const SharedBucketResult& r);

} // namespace mpsvs
} // namespace volePSI
