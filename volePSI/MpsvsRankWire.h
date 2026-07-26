#pragma once

// MPSVS Phase 8 — MPC-wire RankViaHistogram.
//
// Slim table sort via existing MpMpcSort::mpcBitonicSort on shared keys,
// then a shared segmented scan over inclusion bits produces per-entity rank.
//
// Composite sort key layout (packed into a single 64-bit SharedU64Bin):
//   bits [63..56]  popkey       (8-bit sector code)
//   bit  [55]      invalid = 1 - incl  (excluded rows sort to end)
//   bits [54..48]  bucket (7-bit, B ≤ 128)
//   bits [47..0]   unused (0)
//
// Payload per row: entity_idx (32 bits) + incl (1 bit) + bucket (7 bits) —
// 40 payload bits per row (bit-shared alongside the key).
//
// After sort, segmented scan on the incl bit within each popkey segment
// produces the rank in [0, n_valid_in_popkey). The segment boundaries are
// popkey changes, which are PUBLIC (upstream doesn't hide sector). If
// popkey needs to be private (Rev 7 §8.3 note), the segmented scan needs
// a shared segment-boundary bit, which adds ~1 secureAnd per row per level
// of the Hillis-Steele scan.
//
// Semantic-ref parity: reconstructed ranks equal `rankViaHistogram` output.

#include "MpBeaverTriple.h"
#include "MpMpcSort.h"
#include "MpSecretShare.h"
#include "MpsvsInclusionWire.h"
#include "MpsvsRank.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::SharedSortElement;
using mpstar::mpcBitonicSort;
using mpstar::mpcBitonicSortTripleCost;

// A row entering the shared rank pipeline.
struct SharedSlimRow {
    uint32_t entity_idx;      // public bookkeeping
    uint32_t popkey;          // public
    SharedBit incl;           // shared inclusion bit
    SharedU64Bin bucket;      // shared bucket ID (only low log2(B) bits used)
};

// Output row.
struct SharedRankedRow {
    uint32_t entity_idx;
    uint32_t popkey;
    SharedBit incl;
    SharedU64Bin bucket;
    SharedU64Bin rank;   // rank within (popkey, incl=1) segment
};

// Total triple budget for a shared rank over n rows with B buckets.
size_t rankWireTripleBudget(size_t n_rows, uint32_t B);

// Main entry: build slim rows from shared entity metrics (one metric), sort
// on shares, run segmented scan, return shared ranks per entity.
std::vector<SharedRankedRow>
rankViaHistogramWire(const std::vector<SharedEntityMetricRow>& rows,
                      Metric m,
                      uint32_t B,
                      const std::vector<BeaverTripleBit>& triples,
                      size_t& tripleIndex,
                      oc::PRNG& prng);

// Reconstruct ranked rows to plaintext (test helper).
struct PlainRankedRow {
    uint32_t entity_idx;
    uint32_t popkey;
    uint8_t  incl;
    uint32_t bucket;
    uint64_t rank;
};
std::vector<PlainRankedRow>
reconstructRanked(const std::vector<SharedRankedRow>& shared);

} // namespace mpsvs
} // namespace volePSI
