#include "MpsvsCoverFirms.h"

#include <stdexcept>

namespace volePSI {
namespace mpsvs {

SharedSectorHistogram
addCoverFirms(const SharedSectorHistogram& cell,
              const CoverConfig& cc,
              std::mt19937_64& rng1,
              std::mt19937_64& rng2) {
    if (cc.K_max < cc.K_min)
        throw std::invalid_argument("CoverConfig: K_max < K_min");
    // Split the range in half so each party samples independently.
    // K = K_min + K1 + K2 with K1, K2 ∈ [0, (K_max-K_min)/2]
    uint64_t half_range = (static_cast<uint64_t>(cc.K_max) - cc.K_min) / 2;
    uint64_t k1 = std::uniform_int_distribution<uint64_t>(0, half_range)(rng1);
    uint64_t k2 = std::uniform_int_distribution<uint64_t>(0, half_range)(rng2);

    // Add to n_valid shares locally. Party 0 holds (K_min + K1), party 1 holds K2.
    SharedSectorHistogram out = cell;
    out.n_valid.shares[0] += static_cast<uint64_t>(cc.K_min) + k1;
    out.n_valid.shares[1] += k2;
    // If configured, also inflate sum_num/sum_den by zero contributions.
    // Since covers contribute (0, 0) to (num, den), the shared sums don't
    // need updating structurally — the additions of 0 are no-ops.
    // If cover payload were nonzero-random, we'd add them here.
    (void)cc.inflate_sums;
    return out;
}

std::vector<SharedSectorHistogram>
addCoverFirmsBatch(const std::vector<SharedSectorHistogram>& cells,
                    const CoverConfig& cc,
                    std::mt19937_64& rng1,
                    std::mt19937_64& rng2) {
    std::vector<SharedSectorHistogram> out;
    out.reserve(cells.size());
    for (const auto& c : cells) out.push_back(addCoverFirms(c, cc, rng1, rng2));
    return out;
}

} // namespace mpsvs
} // namespace volePSI
