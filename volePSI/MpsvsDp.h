#pragma once

// MPSVS Phase 12 — DP noise + R26 CDF clamp + zCDP composition (§12).
//
// Given a per-cell histogram from Phase 11, add discrete-Gaussian noise per
// bin, clamp to non-negative (R26), and track privacy budget via zCDP.
//
// Rev 7 R26 (Gap 11 fix):
//   Post-noise histogram MUST be clamped `h̃[b] ← max(0, h̃[b])` before
//   prefix-sum, else DP noise can produce negative counts → CDF non-monotone
//   → Phase 10 percentile inversion silently wrong. Clamp is DP
//   post-processing-invariant (Bun-Steinke 2016).
//
// Discrete Gaussian sampler: rejection sampling from a truncated continuous
// Gaussian. σ derived from ρ (zCDP parameter) and L2 sensitivity Δ_2.
//
// zCDP composition: k queries with per-query ρ_i compose to Σ ρ_i (linear).
// Convert to (ε, δ)-DP at reporting time via
//   ε(δ) = ρ + 2·sqrt(ρ · log(1/δ))    [Bun-Steinke 2016 Prop 3]
//
// Phase 12 semantic reference uses std::mt19937_64; MPC-wire version replaces
// the sampler with a jointly-generated shared noise vector via commit-then-
// reveal (Rev 7 §12).

#include "MpsvsRank.h"
#include "MpsvsSectorAgg.h"

#include <cstdint>
#include <random>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Discrete Gaussian sampler
// ---------------------------------------------------------------------------

class DiscreteGaussian {
public:
    // sigma > 0. Rejection sampling from a discrete Gaussian on ℤ centred at 0.
    // Standard method: sample x ~ N(0, σ²) continuous, round to nearest int,
    // accept with prob = e^{-π (x - round(x))²/σ²} / max_ratio. For simplicity
    // in the semantic reference we do the closer-to-exact rejection method
    // over the discrete Gaussian directly.
    explicit DiscreteGaussian(double sigma) : sigma_(sigma) {}

    // Sample one integer draw. Uses std::normal_distribution + rounding as a
    // reasonable approximation (bias ≤ O(σ⁻¹) for large σ — flagged as a
    // known limitation in Rev 7 §17.12).
    int64_t sample(std::mt19937_64& rng) const {
        std::normal_distribution<double> nd(0.0, sigma_);
        double x = nd(rng);
        return static_cast<int64_t>(std::llround(x));
    }

    double sigma() const { return sigma_; }

private:
    double sigma_;
};

// ---------------------------------------------------------------------------
// zCDP budget tracker
// ---------------------------------------------------------------------------

// σ from ρ and L2 sensitivity Δ_2:
//   ρ = Δ_2² / (2 σ²)  ⇒  σ = Δ_2 / sqrt(2 ρ)
// For a histogram release, Δ_2 = sqrt(2) per neighbouring pair (add/remove one
// entity affects at most 2 bins with unit weight → L2 sensitivity = sqrt(2)).
inline double sigmaFromRho(double rho, double delta_2 = std::sqrt(2.0)) {
    return delta_2 / std::sqrt(2.0 * rho);
}

// Convert accumulated zCDP ρ to (ε, δ) at reporting.
inline double epsilonFromRho(double rho, double delta) {
    return rho + 2.0 * std::sqrt(rho * std::log(1.0 / delta));
}

struct BudgetTracker {
    double rho_total = 0.0;
    uint32_t query_count = 0;
    void spend(double rho) { rho_total += rho; ++query_count; }
    double epsilon_at(double delta) const { return epsilonFromRho(rho_total, delta); }
};

// ---------------------------------------------------------------------------
// Noisy histogram + R26 clamp
// ---------------------------------------------------------------------------

struct NoisyHistogram {
    std::vector<int64_t>  h_noisy;   // pre-clamp (may be negative)
    std::vector<uint64_t> h_clamped; // R26: max(0, h_noisy)
    uint64_t              n_valid_orig;   // for audit only
    double                sigma;
    double                rho_spent;
};

NoisyHistogram addNoiseAndClamp(const Histogram& h, double rho,
                                 std::mt19937_64& rng,
                                 BudgetTracker& budget);

// Batch version: add noise to a full SectorAggregateBundle. Each cell counts
// as one query — total rho spent = |cells| · rho_per_cell.
struct NoisySectorBundle {
    std::vector<NoisyHistogram> hists[kMetricCount];
};
NoisySectorBundle
addNoiseToBundle(const SectorAggregateBundle& bundle, double rho_per_cell,
                 std::mt19937_64& rng, BudgetTracker& budget);

// ---------------------------------------------------------------------------
// Audit — R26 non-negativity invariant + monotone CDF check
// ---------------------------------------------------------------------------

struct DpAudit {
    bool all_clamped_nonneg;       // R26: h_clamped >= 0 everywhere
    bool cdf_monotone_after_clamp; // R26: prefix-sum of clamped is monotone
    uint32_t bins_clamped_up;      // count of bins where clamp modified
    double   max_noise_magnitude;  // sanity check
};
DpAudit auditNoisyHistogram(const NoisyHistogram& nh);

} // namespace mpsvs
} // namespace volePSI
