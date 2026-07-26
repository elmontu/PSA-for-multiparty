#pragma once

// MPSVS Phase 8 — RankViaHistogram + slim-sort (§8.2) + conditional
// small-domain radix sort (§8.2.1, R27).
//
// Given per-entity (bucket_m, incl_m) from Phase 6 BucketIndex, produce:
//   - Histogram h_m[b] over B buckets, gated on inclusion
//   - Per-entity rank rank_m[i] ∈ [0, N̂), monotone in bucket within
//     each population scope (popkey)
//
// Slim key layout (per Rev 7 §8.2):
//   (popkey || invalid=1-incl || bucket)
// where popkey is a small public grouping key (e.g., sector, period).
//
// Phase 8 semantic reference: single-threaded, plaintext primitives that
// mirror the MPC-wire circuit shape (bitonic + segmented scan). MPC-wire
// upgrade replaces the sort with `MpMpcSort::bitonicSort` and the segmented
// scan with `MpSegmentedScan::hillisSteele`.

#include "MpsvsInclusion.h"
#include "MpsvsRatioBucket.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Slim table row — one entry per (entity, metric)
// ---------------------------------------------------------------------------

struct SlimRow {
    uint32_t entity_idx;   // back-reference into EntityMetricRow[]
    uint32_t popkey;       // sector, period, or (sector,period) packed
    uint8_t  incl;         // Phase 5 inclusion bit for this metric
    uint32_t bucket;       // §8.1 BucketIndex output (in [0, B))
    // Filled by Phase 8:
    uint64_t rank;         // rank within this (popkey, metric) scope
};

struct Histogram {
    std::vector<uint64_t> h;      // size = B
    uint64_t              n_valid; // Σ incl over rows
};

struct RankResult {
    std::vector<SlimRow> slim;    // sorted by (popkey, invalid, bucket)
    Histogram            histogram; // per-metric aggregate over all popkeys
};

// ---------------------------------------------------------------------------
// buildSlim — one metric's slim table across all entities
// ---------------------------------------------------------------------------

// popkey_selector maps EntityMetricRow → uint32_t popkey. Default: single
// group (popkey = 0 for all).
std::vector<SlimRow>
buildSlim(const std::vector<EntityMetricRow>& rows,
          Metric m,
          const std::vector<uint64_t>& edges,
          uint64_t ratio_scale,
          uint32_t (*popkey_selector)(const EntityMetricRow&) = nullptr);

// ---------------------------------------------------------------------------
// Slim sort (§8.2 — bitonic on popkey||invalid) + (§8.2.1 — conditional R27
// radix on bucket within each (popkey,invalid) group)
// ---------------------------------------------------------------------------

// Sort by composite key (popkey, invalid=1-incl, bucket).
// If Φ.radix_enabled is true (per break-even table, R27), the bucket-dimension
// is sorted via oblivious counting-sort within each (popkey,invalid) group —
// otherwise plain std::stable_sort suffices (matches bitonic reference).
struct SlimSortConfig {
    bool phi_radix_enabled = true;  // Rev 7 default at B ≤ 128
    uint32_t B = kBucketCount;
};

void slimSort(std::vector<SlimRow>& slim, const SlimSortConfig& cfg = {});

// ---------------------------------------------------------------------------
// Segmented scan primitives — Hillis-Steele (semantic ref uses std sequential)
// ---------------------------------------------------------------------------

// Inclusive segmented prefix-sum. `boundary[i]=1` marks the start of a new
// segment (index 0 always starts a segment).
std::vector<uint64_t>
segmentedInclusiveSum(const std::vector<uint64_t>& xs,
                      const std::vector<uint8_t>& boundary);

// ---------------------------------------------------------------------------
// RankViaHistogram — §8.2 main body
// ---------------------------------------------------------------------------

// Given a slim table (assumed sorted), compute rank per entity.
// Rank is the count of preceding included rows within the same popkey
// (inclusive of self? Rev 7 uses 0-indexed rank == count-of-strictly-smaller).
// Result populates SlimRow::rank in place; also returns per-metric histogram
// aggregated over the whole slim (all popkeys combined, one histogram).
RankResult rankViaHistogram(std::vector<SlimRow> slim,
                            const SlimSortConfig& cfg = {});

// ---------------------------------------------------------------------------
// End-to-end: buildSlim → slimSort → rankViaHistogram → per-entity score
// ---------------------------------------------------------------------------

// Score = rank / (n_valid_in_popkey - 1) mapped to [0, 1] fixed-point.
// If n_valid ≤ 1: score = 0 for the single row.
// Returned as parallel arrays keyed by entity_idx.
struct EntityRankRow {
    uint32_t entity_idx;
    uint32_t popkey;
    uint8_t  incl;
    uint32_t bucket;
    uint64_t rank;
    Fp       score_fp;   // in [0, 1] fixed-point
};

std::vector<EntityRankRow>
computeMetricRanks(const std::vector<EntityMetricRow>& rows,
                   Metric m,
                   const BucketEdges& edges,
                   const SlimSortConfig& cfg = {},
                   uint32_t (*popkey_selector)(const EntityMetricRow&) = nullptr);

} // namespace mpsvs
} // namespace volePSI
