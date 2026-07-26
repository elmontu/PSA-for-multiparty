#pragma once

// MPSVS Phase 11 — Sector aggregation (§10).
//
// Two aggregation modes per metric:
//   1. HISTOGRAM: sum h_m per (sector, period) — feeds Phase 10 percentiles
//      and Phase 12 DP release. Additive over shares; no reciprocal.
//   2. RATIO-OF-SUMS: (Σ num_m)/(Σ den_m) per (sector, period) — used by
//      protocol for sector-level ratio metrics (§10). ONE Goldschmidt
//      reciprocal per (sector, period, metric).
//
// Both take EntityMetricRow[] as input, output per-(sector, period) tables.
// Popkey selector default: sector alone (single-period runs).

#include "MpsvsInclusion.h"
#include "MpsvsRank.h"
#include "MpsvsRatioBucket.h"

#include <cstdint>
#include <map>
#include <vector>

namespace volePSI {
namespace mpsvs {

struct SectorKey {
    uint16_t sector;
    uint32_t period;    // e.g., YYYYMM
    bool operator<(const SectorKey& o) const {
        if (sector != o.sector) return sector < o.sector;
        return period < o.period;
    }
    bool operator==(const SectorKey& o) const {
        return sector == o.sector && period == o.period;
    }
};

// Per-(sector, period, metric) aggregated histogram.
struct SectorHistogram {
    SectorKey  key;
    Metric     metric;
    Histogram  hist;    // hist.n_valid = Σ incl within (sector, period)
};

// Per-(sector, period, metric) ratio-of-sums result.
struct SectorRatio {
    SectorKey  key;
    Metric     metric;
    uint64_t   sum_num;
    uint64_t   sum_den;
    uint8_t    incl;    // 1 iff sum_den > 0 AND at least one incl entity
    Fp         ratio_fp;
};

// Aggregate histograms per (sector, period) for a single metric.
std::vector<SectorHistogram>
aggregateHistograms(const std::vector<EntityMetricRow>& rows,
                    Metric m,
                    const BucketEdges& edges);

// Aggregate ratio-of-sums per (sector, period) for a single metric.
std::vector<SectorRatio>
aggregateRatios(const std::vector<EntityMetricRow>& rows,
                Metric m);

// Convenience: aggregate all 9 metrics at once.
struct SectorAggregateBundle {
    std::vector<SectorHistogram> hists[kMetricCount];
    std::vector<SectorRatio>     ratios[kMetricCount];
};
SectorAggregateBundle
aggregateAllMetrics(const std::vector<EntityMetricRow>& rows,
                    const BucketEdges& edges);

// Audit: totals across all (sector, period) must equal
// aggregateOverAll's plain totals.
struct SectorAggregateAudit {
    bool hist_totals_match;
    bool ratio_totals_match;
};
SectorAggregateAudit
auditSectorAggregate(const std::vector<EntityMetricRow>& rows,
                     const SectorAggregateBundle& bundle);

} // namespace mpsvs
} // namespace volePSI
