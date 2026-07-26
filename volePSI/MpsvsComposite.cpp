#include "MpsvsComposite.h"

#include <stdexcept>
#include <unordered_map>

namespace volePSI {
namespace mpsvs {

// Convert double weight to fp for exact multiplication.
static Fp fpFromDouble(double d) {
    long double v = d;
    long double scale = static_cast<long double>(1ULL << kFpFractionalBits);
    return static_cast<Fp>(v * scale);
}

std::vector<CompositeRow>
computeCompositeTwoScore(
    const std::array<std::vector<EntityRankRow>, kMetricCount>& metric_ranks,
    const CompositeWeights& weights) {

    // Index each metric's rank rows by entity_idx.
    std::array<std::unordered_map<uint32_t, const EntityRankRow*>,
               kMetricCount> by_entity;
    for (size_t m = 0; m < kMetricCount; ++m) {
        for (const auto& r : metric_ranks[m]) {
            by_entity[m][r.entity_idx] = &r;
        }
    }

    // Collect entity_idx set (union across all metrics).
    std::vector<uint32_t> entities;
    {
        std::unordered_map<uint32_t, uint8_t> seen;
        for (size_t m = 0; m < kMetricCount; ++m) {
            for (const auto& r : metric_ranks[m]) seen[r.entity_idx] = 1;
        }
        entities.reserve(seen.size());
        for (const auto& kv : seen) entities.push_back(kv.first);
        std::sort(entities.begin(), entities.end());
    }

    std::vector<CompositeRow> out;
    out.reserve(entities.size());
    for (uint32_t eid : entities) {
        CompositeRow c{};
        c.entity_idx = eid;

        // Sum weighted rank scores across core metrics only.
        Fp strict_num = 0;
        Fp renorm_num = 0;
        double renorm_denom = 0.0;
        uint8_t avail = 0;
        bool all_core_avail = true;

        for (Metric mc : kVulnCoreMetrics) {
            size_t m = static_cast<size_t>(mc);
            auto it = by_entity[m].find(eid);
            if (it == by_entity[m].end() || !it->second->incl) {
                all_core_avail = false;
                continue;
            }
            ++avail;
            Fp w_fp = fpFromDouble(weights.w[m]);
            Fp s = it->second->score_fp;
            // wScore = (w · s) → fixed-point multiply.
            Fp wscore = static_cast<Fp>((static_cast<__int128>(w_fp) *
                                          static_cast<__int128>(s))
                                         >> kFpFractionalBits);
            strict_num += wscore;
            renorm_num += wscore;
            renorm_denom += weights.w[m];
            c.popkey = it->second->popkey;
        }

        c.avail_core = avail;

        // STRICT: emit if all core available.
        if (all_core_avail && avail == kVulnCoreMetrics.size()) {
            c.incl_strict = 1;
            c.vuln_strict_fp = strict_num;
        } else {
            c.incl_strict = 0;
            c.vuln_strict_fp = 0;
        }

        // RENORMALISED: emit if at least one core available; scale by 1/Σw'.
        if (avail >= 1 && renorm_denom > 0.0) {
            c.incl_renorm = 1;
            // renorm_num / renorm_denom  (fp / double → fp)
            Fp denom_fp = fpFromDouble(renorm_denom);
            // vuln_renorm = renorm_num * (1/denom_fp)
            // In fixed-point: renorm_num * fpRecip(denom_fp).
            // Simpler here: convert via double round-trip (semantic ref only).
            double num_d = static_cast<double>(fpToDouble(renorm_num));
            double vuln_d = num_d / renorm_denom;
            c.vuln_renorm_fp = fpFromDouble(vuln_d);
            (void)denom_fp;
        } else {
            c.incl_renorm = 0;
            c.vuln_renorm_fp = 0;
        }

        out.push_back(c);
    }
    return out;
}

} // namespace mpsvs
} // namespace volePSI
