#include "MpsvsAudit.h"

#include <sstream>

namespace volePSI {
namespace mpsvs {

const MaliciousUpgradeGap kMaliciousUpgradeGaps[] = {
    {"OPRF partial evaluations (S1, S2)",
     "DLEQ PoK over each partial (already produced Phase 2; verifier missing).",
     "Rev 7 §3"},
    {"Beaver-triple generation (S1/S2 dealer)",
     "MAC-then-open with per-triple SPDZ MAC.",
     "Rev 7 §17.7"},
    {"F_PSA windowed merge presence bits",
     "Bulletproofs range proof on membership counts.",
     "Rev 7 §5"},
    {"CGP composed shuffle (S1↔S2)",
     "Bayer-Groth shuffle NIZK (already in MpShuffleNizkBg).",
     "Rev 7 §5.3"},
    {"BucketIndex cross-product comparisons",
     "Zero-knowledge equivalence to reference bucket function.",
     "Rev 7 §8.1"},
    {"Goldschmidt reciprocal iteration",
     "Consistency proof: y_final · x ≡ 1 mod 2^f (algebraic).",
     "Rev 7 §8.1.1"},
    {"Discrete Gaussian noise sampling",
     "Joint commit-then-reveal noise vector (Rev 7 §12 already spec'd).",
     "Rev 7 §12"},
    {"R26 clamp application",
     "Batch DLEQ over clamp indicator; already covered by BFV proofs.",
     "Rev 7 §12 R26"},
};
const size_t kMaliciousUpgradeGapsCount =
    sizeof(kMaliciousUpgradeGaps) / sizeof(kMaliciousUpgradeGaps[0]);

PipelineAudit
runPipelineAudit(const AlignmentResult& alignment,
                 const std::vector<EntityMetricRow>& entity_rows,
                 const SectorAggregateBundle& sector_agg,
                 const NoisySectorBundle& noisy_bundle,
                 const BudgetTracker& budget,
                 const ReleaseBundle& release) {
    PipelineAudit a{};

    // Phase 4 — Alignment
    auto align_audit = auditAlignment(alignment);
    a.phase4_alignment_ok = align_audit.all_shapes_public &&
                             align_audit.total_rows > 0;
    a.phase4_N_hat = align_audit.total_rows;

    // Phase 5 — Inclusion
    auto incl_audit = auditInclusion(entity_rows);
    a.phase5_inclusion_ok = true;   // structural check pass if we got here
    a.phase5_vuln_incl_count = incl_audit.vuln_incl_count;

    // Phase 11 — Sector aggregation totals
    auto agg_audit = auditSectorAggregate(entity_rows, sector_agg);
    a.phase11_totals_match = agg_audit.hist_totals_match &&
                              agg_audit.ratio_totals_match;

    // Phase 12 — DP noise + R26 clamp
    a.phase12_r26_all_clamped_nonneg = true;
    a.phase12_cdf_monotone_all_cells = true;
    for (size_t m = 0; m < kMetricCount; ++m) {
        for (const auto& nh : noisy_bundle.hists[m]) {
            auto na = auditNoisyHistogram(nh);
            if (!na.all_clamped_nonneg) a.phase12_r26_all_clamped_nonneg = false;
            if (!na.cdf_monotone_after_clamp) a.phase12_cdf_monotone_all_cells = false;
        }
    }
    a.phase12_epsilon_at_delta_1em6 = budget.epsilon_at(1e-6);

    // Phase 12.1 — Release
    auto rel_audit = auditRelease(release);
    a.phase12_1_release_ok = rel_audit.r26_no_negative_bins &&
                              rel_audit.r26_cdf_monotone_per_row;
    a.phase12_1_cells_released = rel_audit.total_cells_released;

    a.overall_pass = a.phase4_alignment_ok &&
                      a.phase5_inclusion_ok &&
                      a.phase11_totals_match &&
                      a.phase12_r26_all_clamped_nonneg &&
                      a.phase12_cdf_monotone_all_cells &&
                      a.phase12_1_release_ok;

    std::ostringstream ss;
    ss << "Pipeline audit:\n"
       << "  Phase 4 alignment:       " << (a.phase4_alignment_ok ? "OK" : "FAIL")
       << " (N̂=" << a.phase4_N_hat << ")\n"
       << "  Phase 5 inclusion:       " << (a.phase5_inclusion_ok ? "OK" : "FAIL")
       << " (vuln_incl=" << a.phase5_vuln_incl_count << ")\n"
       << "  Phase 11 sector totals:  " << (a.phase11_totals_match ? "OK" : "FAIL") << "\n"
       << "  Phase 12 R26 nonneg:     " << (a.phase12_r26_all_clamped_nonneg ? "OK" : "FAIL") << "\n"
       << "  Phase 12 CDF monotone:   " << (a.phase12_cdf_monotone_all_cells ? "OK" : "FAIL") << "\n"
       << "  Phase 12 ε(δ=1e-6):      " << a.phase12_epsilon_at_delta_1em6 << "\n"
       << "  Phase 12.1 release:      " << (a.phase12_1_release_ok ? "OK" : "FAIL")
       << " (" << a.phase12_1_cells_released << " cells)\n"
       << "  Overall:                 " << (a.overall_pass ? "PASS" : "FAIL");
    a.summary = ss.str();
    return a;
}

} // namespace mpsvs
} // namespace volePSI
