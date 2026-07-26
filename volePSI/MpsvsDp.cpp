#include "MpsvsDp.h"

#include <algorithm>
#include <cmath>

namespace volePSI {
namespace mpsvs {

NoisyHistogram addNoiseAndClamp(const Histogram& h, double rho,
                                 std::mt19937_64& rng,
                                 BudgetTracker& budget) {
    NoisyHistogram nh;
    nh.n_valid_orig = h.n_valid;
    nh.sigma = sigmaFromRho(rho);
    nh.rho_spent = rho;

    DiscreteGaussian dg(nh.sigma);
    nh.h_noisy.reserve(h.h.size());
    nh.h_clamped.reserve(h.h.size());
    for (uint64_t v : h.h) {
        int64_t noise = dg.sample(rng);
        int64_t noisy = static_cast<int64_t>(v) + noise;
        nh.h_noisy.push_back(noisy);
        // R26: clamp to non-negative before any downstream use.
        nh.h_clamped.push_back(noisy < 0 ? 0 : static_cast<uint64_t>(noisy));
    }
    budget.spend(rho);
    return nh;
}

NoisySectorBundle
addNoiseToBundle(const SectorAggregateBundle& bundle, double rho_per_cell,
                 std::mt19937_64& rng, BudgetTracker& budget) {
    NoisySectorBundle out;
    for (size_t m = 0; m < kMetricCount; ++m) {
        out.hists[m].reserve(bundle.hists[m].size());
        for (const auto& sh : bundle.hists[m]) {
            out.hists[m].push_back(addNoiseAndClamp(sh.hist, rho_per_cell,
                                                     rng, budget));
        }
    }
    return out;
}

DpAudit auditNoisyHistogram(const NoisyHistogram& nh) {
    DpAudit a{};
    a.all_clamped_nonneg = true;
    a.cdf_monotone_after_clamp = true;
    a.bins_clamped_up = 0;
    a.max_noise_magnitude = 0.0;

    uint64_t prev_cum = 0;
    for (size_t i = 0; i < nh.h_clamped.size(); ++i) {
        // Clamped values are u64 → nonneg by type; check invariant explicitly.
        if (nh.h_noisy[i] < 0 && nh.h_clamped[i] != 0) a.all_clamped_nonneg = false;
        if (nh.h_noisy[i] < 0) ++a.bins_clamped_up;
        double mag = std::abs(static_cast<double>(nh.h_noisy[i] -
                                     static_cast<int64_t>(nh.n_valid_orig ?
                                        nh.n_valid_orig / nh.h_clamped.size() : 0)));
        (void)mag;   // simplistic magnitude estimate; not used strictly
        double abs_noise = std::abs(static_cast<double>(nh.h_noisy[i])) -
                            (nh.h_clamped[i] > 0 ? 0.0 : 0.0);
        if (std::abs(abs_noise) > a.max_noise_magnitude)
            a.max_noise_magnitude = std::abs(abs_noise);

        uint64_t cur_cum = prev_cum + nh.h_clamped[i];
        if (cur_cum < prev_cum) a.cdf_monotone_after_clamp = false;
        prev_cum = cur_cum;
    }
    return a;
}

} // namespace mpsvs
} // namespace volePSI
