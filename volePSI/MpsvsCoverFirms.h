#pragma once

// MPSVS Cover-Firm Injection — additional protection layer for hiding
// per-firm membership from the release count.
//
// Threat addressed:
//   Even with sensitivity-calibrated DP, the released n_valid per cell
//   reveals the true intersection cardinality within DP noise. When the
//   true cardinality is small (~5 firms), σ_count ≈ 3.16 leaves the
//   estimate identifiable in "which specific firms contributed".
//
// Mechanism:
//   For each (sector, period) cell, S1 and S2 jointly sample K uniformly
//   from the public range [K_min, K_max]. K is stored as ADDITIVE shares
//   so neither party knows the exact value alone. K is added to the shared
//   n_valid; sum_num/sum_den are optionally inflated too (see below).
//
// Adversary's inference:
//   released_n_valid = true_n_valid + K + DP_noise
//   K is unknown, uniform over [K_min, K_max]
//   Adversary's estimator (releaseed - E[K] = released - (K_min+K_max)/2)
//   has uncertainty ≈ (K_max - K_min)/√12 (uniform sd) + DP_σ_count
//
// Two variants:
//   1. Count-only covers (this module): adds K to n_valid; sum_num/sum_den
//      unchanged. Adversary loses cardinality precision. Ratio-of-sums
//      (sum_num/sum_den) is unbiased since covers contribute 0/0. But
//      per-firm score = rank / (n_valid - 1) is biased (denominator inflated
//      by K). For rank-based metrics that require accurate n_valid, disable
//      covers or subtract E[K] at consumer.
//   2. Zero-payload live covers (recommended): adds K to n_valid AND adds
//      K contribute-zero rows to sum_num/sum_den. Ratio unchanged since
//      +0/+0 doesn't shift. Same n_valid inflation.

#include "MpsvsSectorAgg.h"
#include "MpsvsSectorAggWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>
#include <random>

namespace volePSI {
namespace mpsvs {

struct CoverConfig {
    uint32_t K_min = 0;      // public lower bound on cover count per cell
    uint32_t K_max = 0;      // public upper bound; K sampled ∈ [K_min, K_max]
    bool     inflate_sums = false;  // if true, also add K zero-payload rows
                                    // to sum_num/sum_den (variant 2)

    // Expected cover count (public, useful for consumer bias correction).
    double expected_K() const { return 0.5 * (K_min + K_max); }
    // Uncertainty introduced (public, useful for reporting).
    double K_uncertainty_sd() const {
        double range = static_cast<double>(K_max - K_min);
        return range / std::sqrt(12.0);   // uniform on [K_min, K_max]
    }
};

// Inject cover firms into a shared histogram cell. Sums K jointly from
// [K_min, K_max]:
//   - S1 samples K1 ∈ [0, (K_max - K_min)/2]
//   - S2 samples K2 ∈ [0, (K_max - K_min)/2]
//   - K = K_min + K1 + K2  (jointly held as arithmetic shares over Z_{2^64})
// Neither party knows the exact K. The public range is disclosed.
SharedSectorHistogram
addCoverFirms(const SharedSectorHistogram& cell,
              const CoverConfig& cc,
              std::mt19937_64& rng1,
              std::mt19937_64& rng2);

// Batch: inject covers into every cell of a bundle.
std::vector<SharedSectorHistogram>
addCoverFirmsBatch(const std::vector<SharedSectorHistogram>& cells,
                    const CoverConfig& cc,
                    std::mt19937_64& rng1,
                    std::mt19937_64& rng2);

} // namespace mpsvs
} // namespace volePSI
