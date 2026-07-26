#pragma once

// MPSVS Phase 5 — MPC-wire inclusion. All values secret-shared between
// two parties (S1, S2). No plaintext entity data touched.
//
// Primitives used from the existing MPC layer:
//   - `mpstar::SharedU64Bin`  (64-bit XOR-shared, one SharedBit per bit)
//   - `mpstar::SharedBit`     (XOR-shared bit)
//   - `mpstar::secureAnd`     (Beaver AND on SharedBit; 1 triple)
//   - `mpstar::secureLessThan` (bit-decomposed LT circuit; ~192 triples)
//   - `mpstar::xorShared`     (free)
//
// Input: SharedUnionRow (shares of each field from Phase 4 output).
// Output: SharedEntityMetricRow (shares of {(num, den, incl)} per metric +
//         shared incl_vuln + shared avail_core_count).
//
// Semantic-correctness invariant: reconstructing the wire output row for row
// yields the same values as computeEntityMetrics on the reconstructed
// plaintext union rows.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpSecureCompare.h"
#include "MpsvsAlignment.h"
#include "MpsvsInclusion.h"

#include <array>
#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::SharedBit;
using mpstar::SharedU64;
using mpstar::SharedU64Bin;

// ---------------------------------------------------------------------------
// Shared input row shapes
// ---------------------------------------------------------------------------

struct SharedPayloadPerSource {
    std::array<SharedU64Bin, kPayloadNumFields> v;
    std::array<SharedBit,    kPayloadNumFields> valid;
    SharedU64Bin g;         // growth (signed encoded)
    SharedBit    v_g;
};

struct SharedUnionRow {
    // Public bookkeeping (bin, period, sector_id can be public post-alignment).
    uint64_t bin = 0;
    uint32_t period = 0;
    uint32_t sector = 0;
    uint8_t  sector_conflict = 0;
    // Secret bits — always shared:
    SharedBit b_MAS, b_DOS, b_MOM;
    SharedBit live;
    // Payloads per source:
    SharedPayloadPerSource p_MAS, p_DOS, p_MOM;
};

struct SharedMetricPair {
    SharedU64Bin num;   // shared 64-bit
    SharedU64Bin den;
    SharedBit    incl;
};

struct SharedEntityMetricRow {
    uint64_t bin = 0;
    uint32_t period = 0;
    uint32_t sector = 0;
    uint8_t  sector_conflict = 0;
    SharedBit live;
    SharedBit b_MAS, b_DOS, b_MOM;
    std::array<SharedMetricPair, kMetricCount> metrics;
    // Vuln coverage — computed per policy.
    SharedBit incl_vuln;
    SharedU64Bin avail_core_count;   // 0..4 as shared 64-bit (only low 3 bits meaningful)
};

// ---------------------------------------------------------------------------
// Triple bag
// ---------------------------------------------------------------------------

// Per-row triple budget (upper bound).
// Range check cost = 2 · secureLessThanTripleCost() + 1 (final AND).
// We use 3 range checks per row (income/debt/emp) → 3 · (2·LT + 1).
// Per metric: chain of ~5-6 ANDs on already-shared bits (each = 1 triple).
// Vuln policy: 4 core-availability ANDs.
// Total upper bound per row ≈ 3 · (2·192 + 1) + 9 · 6 + 8 = ~1225 bit triples.
size_t inclusionTripleBudgetPerRow();

// ---------------------------------------------------------------------------
// Shared inclusion (Phase 5 MPC-wire body)
// ---------------------------------------------------------------------------

// Compute Shared inclusion bits + metric pairs for one row.
// Consumes triples starting at `tripleIndex`; advances it.
SharedEntityMetricRow
computeEntityMetricsWire(const SharedUnionRow& u,
                          const RangeConfig& rc,
                          CoveragePolicy vuln_policy,
                          const std::vector<BeaverTripleBit>& triples,
                          size_t& tripleIndex);

// Batch: apply to a vector of shared rows using a pre-sized triple bag.
std::vector<SharedEntityMetricRow>
computeEntityMetricsWireBatch(const std::vector<SharedUnionRow>& rows,
                               const RangeConfig& rc,
                               CoveragePolicy vuln_policy,
                               const std::vector<BeaverTripleBit>& triples);

// ---------------------------------------------------------------------------
// Test-only helpers: share/reconstruct entire UnionRow / EntityMetricRow.
// ---------------------------------------------------------------------------

// Bit-decompose and share a plain UnionRow between N parties.
SharedUnionRow shareUnionRow(uint32_t N, const UnionRow& u, oc::PRNG& prng);

// Reconstruct a plain EntityMetricRow from a shared one (joint operation
// — leaks the plaintext).
EntityMetricRow reconstructEntityMetricRow(const SharedEntityMetricRow& s);

} // namespace mpsvs
} // namespace volePSI
