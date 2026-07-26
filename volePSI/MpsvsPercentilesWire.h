#pragma once

// MPSVS Phase 10 — MPC-wire GroupPercentiles.
//
// Given a shared histogram (per-bin counts as SharedU64Bin), compute the
// bucket where the CDF first crosses a target quantile q · N.
//
// Enables "percentile-only release": GovTech receives shared percentile
// answers without ever seeing the full histogram. Complements Phase 12.1
// which opens the whole histogram.
//
// Algorithm — oblivious linear scan:
//   1. Compute prefix sums cum[b] on shares via 128-bit ripple-carry adders.
//   2. Compute shared target = q_public · N_shared (public·shared mult, free).
//   3. For each b in [0, B):
//        gt_b = NOT secureLessThan(cum[b], target)      // cum[b] >= target
//        found_b = gt_b AND NOT prev_gt                 // first crossing
//   4. Bucket = XOR-fold of b · found_b over shared bits (encoded in log2 B bits).
//
// Cost per quantile: B · secureLessThan + B · secureAnd ≈ B · 193 triples.
// For B=8: ~1550 triples; B=128: ~24 700 triples.
//
// R26 invariant: caller MUST pass clamped histogram (max(0, ·) applied).
// Wire does not re-clamp — that's a Phase 12 responsibility.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpSecureCompare.h"
#include "MpsvsGoldschmidtWire.h"   // for SharedU128Bin

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::SharedBit;
using mpstar::SharedU64Bin;

// Compute shared prefix sums cum[b] from histogram bins.
// Cost: (B-1) × 192 triples (one 64-bit adder per new bin).
std::vector<SharedU64Bin>
sharedPrefixSum(const std::vector<SharedU64Bin>& bins,
                  const std::vector<BeaverTripleBit>& triples,
                  size_t& tripleIndex);

// Shared percentile lookup: returns shared bucket index (as SharedU64Bin).
// `q_num / q_den` is the target quantile (both public). E.g. q=0.5 →
// q_num=1, q_den=2. Target rank = q_num · N / q_den, evaluated on the shared
// N via public-constant multiply then shift.
SharedU64Bin
percentileBucketWire(const std::vector<SharedU64Bin>& cum,
                       const SharedU64Bin& N,
                       uint32_t q_num, uint32_t q_den,
                       const std::vector<BeaverTripleBit>& triples,
                       size_t& tripleIndex);

// Cost estimator.
size_t percentileWireTripleBudget(uint32_t B);

} // namespace mpsvs
} // namespace volePSI
