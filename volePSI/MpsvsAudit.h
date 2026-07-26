#pragma once

// MPSVS Phase 13-17 — Audit, transcript, failure handling, malicious-upgrade
// pointers.
//
// Phase 13 (audit): consolidate all per-phase invariants into a single
// runnable audit that walks the full pipeline output and produces a signed
// transcript for GovTech regulator review.
//
// Phase 14 (failure): RestartSession exception from Phase 4 bin overflow +
// re-run counter + capped retry policy.
//
// Phase 15 (validation): end-to-end integration test (see tests/unit/
// test_mpsvs_e2e.cpp) that composes Phases 1-12.1 on synthetic data.
//
// Phase 16 (malicious upgrade): pointers to which primitives require zero-
// knowledge proof of correct execution when moving to malicious-secure
// (Rev 7 §17.7 deferred).

#include "MpsvsAlignment.h"
#include "MpsvsDp.h"
#include "MpsvsInclusion.h"
#include "MpsvsOpen.h"
#include "MpsvsRank.h"
#include "MpsvsSectorAgg.h"

#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// PipelineAudit — consolidated invariants across all 12 phases
// ---------------------------------------------------------------------------

struct PipelineAudit {
    // Phase 4: alignment
    bool phase4_alignment_ok;
    uint64_t phase4_N_hat;

    // Phase 5: inclusion
    bool phase5_inclusion_ok;
    uint64_t phase5_vuln_incl_count;

    // Phase 11: sector aggregation totals match
    bool phase11_totals_match;

    // Phase 12: R26 clamp invariant + budget accounting
    bool phase12_r26_all_clamped_nonneg;
    bool phase12_cdf_monotone_all_cells;
    double phase12_epsilon_at_delta_1em6;

    // Phase 12.1: release well-formed
    bool phase12_1_release_ok;
    uint32_t phase12_1_cells_released;

    // Composite pass?
    bool overall_pass;

    std::string summary;
};

PipelineAudit
runPipelineAudit(const AlignmentResult& alignment,
                 const std::vector<EntityMetricRow>& entity_rows,
                 const SectorAggregateBundle& sector_agg,
                 const NoisySectorBundle& noisy_bundle,
                 const BudgetTracker& budget,
                 const ReleaseBundle& release);

// ---------------------------------------------------------------------------
// Malicious-upgrade primitive gates (Phase 17 pointer, per Rev 7 §17.7)
// ---------------------------------------------------------------------------

// Each primitive listed here needs a zero-knowledge proof of correct
// execution when moving from semi-honest to malicious. Rev 7 defers full
// implementation; the pointers exist to make the audit explicit.
struct MaliciousUpgradeGap {
    const char* primitive;
    const char* required_proof;
    const char* rev7_section;
};
extern const MaliciousUpgradeGap kMaliciousUpgradeGaps[];
extern const size_t kMaliciousUpgradeGapsCount;

} // namespace mpsvs
} // namespace volePSI
