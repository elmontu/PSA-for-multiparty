#pragma once

// MPSVS Phase 12.1 — Output opening protocol to GovTech.
//
// Reveal DP-clamped histograms + derived percentile summaries to GovTech.
// Single opening per query — no re-noise, no re-open (Rev 7 §14).
//
// GovTech obtains:
//   - Per (sector, period, metric): clamped noisy histogram
//   - Per (sector, period, metric): standard percentiles (from clamped CDF)
//   - Per (sector, period, metric): ratio-of-sums (if sum_den > 0)
//   - Sector-level composite scores (optional, if provided)
//
// The transcript is signed by both S1 and S2 (Rev 7 §15 audit); this file
// generates the semantic payload only. Signing lives in Phase 13 audit hooks.
//
// R26 invariant: opening MUST use `h_clamped`, not `h_noisy`. Enforced by
// only exposing the clamped field on the release struct.

#include "MpsvsDp.h"
#include "MpsvsPercentiles.h"
#include "MpsvsSectorAgg.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

// Per (sector, period, metric) release row.
struct ReleaseRow {
    SectorKey key;
    Metric    metric;
    std::vector<uint64_t> hist_clamped;  // R26 clamped noisy histogram
    uint64_t             n_valid_noisy;  // Σ hist_clamped (post-clamp)
    StdPercentiles       percentiles;    // computed from clamped CDF
    // ratio_of_sums release (§10): only when cell had at least one included row
    uint8_t              ratio_incl;
    double               ratio;          // as double for external consumers
};

struct ReleaseBundle {
    std::vector<ReleaseRow> rows;
    double        rho_total;
    uint32_t      query_count;
    // Metadata (public)
    uint32_t      bucket_count;
    uint32_t      protocol_rev;   // 7 for Rev 7
};

// Assemble release from a noisy bundle + the pre-noise sector-aggregate
// (used to look up ratio-of-sums). Both must be produced from the same
// EntityMetricRow[] over the same run.
ReleaseBundle
assembleRelease(const SectorAggregateBundle& pre_noise,
                const NoisySectorBundle& post_noise,
                const BudgetTracker& budget,
                uint32_t protocol_rev = 7);

// Simple serialisation for transport (JSON-esque, one row per line).
// Real deployment would sign this and transmit over authenticated channel.
std::string serializeRelease(const ReleaseBundle& r);

// Audit the release for R26 invariants + protocol constraints.
struct ReleaseAudit {
    bool r26_no_negative_bins;
    bool r26_cdf_monotone_per_row;
    bool budget_recorded;
    uint32_t total_cells_released;
};
ReleaseAudit auditRelease(const ReleaseBundle& r);

} // namespace mpsvs
} // namespace volePSI
