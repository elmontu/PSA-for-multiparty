#pragma once

// MPSVS Phase 9 — TwoScore composite vulnerability score (§13).
//
// Combine per-metric ranks into a single vuln score per entity, according to
// a coverage policy (STRICT_GATING or RENORMALISED_WEIGHTS from §8.3).
//
// Vuln = Σ_{m ∈ core} w_m · score_m
// where core = {DTI, DSI, Delq, NPL} by default (Rev 7 §8.3 `kVulnCoreMetrics`).
//
// STRICT_GATING: emit vuln only if ALL core metrics available for entity.
// RENORMALISED_WEIGHTS: emit if ANY core metric available; weights renormalised
//   over available-only subset so Σ w' = 1.
//
// Non-core metrics (IPW, DEmp, UnsecShare, StDebtShare, Gap) are exposed as
// their own per-entity scores; they are NOT part of the composite.
//
// Two-score variant (§13): produce BOTH strict and renormalised composites
// side-by-side; downstream analyst chooses which to publish per report.

#include "MpsvsInclusion.h"
#include "MpsvsRatioBucket.h"
#include "MpsvsRank.h"

#include <array>
#include <cstdint>
#include <map>
#include <vector>

namespace volePSI {
namespace mpsvs {

// Public weights per core metric — Rev 7 policy default (equal weights).
struct CompositeWeights {
    std::array<double, kMetricCount> w{};   // 0 for non-core
    CompositeWeights() {
        w.fill(0.0);
        w[static_cast<size_t>(Metric::DTI)]  = 0.25;
        w[static_cast<size_t>(Metric::DSI)]  = 0.25;
        w[static_cast<size_t>(Metric::Delq)] = 0.25;
        w[static_cast<size_t>(Metric::NPL)]  = 0.25;
    }
};

// Per-entity composite output.
struct CompositeRow {
    uint32_t entity_idx;
    uint32_t popkey;
    // Strict composite: emit only if all core metrics available.
    uint8_t  incl_strict;
    Fp       vuln_strict_fp;    // in [0,1] fp
    // Renormalised composite: emit if any core available.
    uint8_t  incl_renorm;
    Fp       vuln_renorm_fp;    // in [0,1] fp
    // Availability count per entity, for audit.
    uint8_t  avail_core;
};

// Compute both composite scores per entity.
// `metric_ranks[m][i]` is the EntityRankRow output of computeMetricRanks
// for metric m (all metrics must have been ranked over the same entity set,
// same popkey partition).
std::vector<CompositeRow>
computeCompositeTwoScore(
    const std::array<std::vector<EntityRankRow>, kMetricCount>& metric_ranks,
    const CompositeWeights& weights = {});

} // namespace mpsvs
} // namespace volePSI
