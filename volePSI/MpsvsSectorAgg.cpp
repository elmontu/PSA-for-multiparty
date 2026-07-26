#include "MpsvsSectorAgg.h"

#include <stdexcept>

namespace volePSI {
namespace mpsvs {

namespace {

const std::vector<uint64_t>& edgesFor(const BucketEdges& e, Metric m) {
    switch (m) {
        case Metric::DTI:         return e.DTI;
        case Metric::DSI:         return e.DSI;
        case Metric::DEmp:        return e.DEmp;
        case Metric::IPW:         return e.IPW;
        case Metric::Delq:        return e.Delq;
        case Metric::NPL:         return e.NPL;
        case Metric::UnsecShare:  return e.UnsecShare;
        case Metric::StDebtShare: return e.StDebtShare;
        case Metric::Gap:         return e.Gap;
        default: throw std::invalid_argument("edgesFor");
    }
}
uint64_t ratioScaleFor(Metric m) {
    switch (m) {
        case Metric::DTI: case Metric::DSI: case Metric::Delq: case Metric::NPL:
        case Metric::UnsecShare: case Metric::StDebtShare: case Metric::Gap:
            return 10000;
        default: return 1;
    }
}

} // namespace

std::vector<SectorHistogram>
aggregateHistograms(const std::vector<EntityMetricRow>& rows,
                    Metric m,
                    const BucketEdges& edges) {
    const auto& e = edgesFor(edges, m);
    uint64_t scale = ratioScaleFor(m);

    std::map<SectorKey, SectorHistogram> agg;
    for (const auto& r : rows) {
        const auto& mp = r.metrics[static_cast<size_t>(m)];
        SectorKey k{r.sector, r.period};
        auto it = agg.find(k);
        if (it == agg.end()) {
            SectorHistogram sh;
            sh.key = k;
            sh.metric = m;
            sh.hist.h.assign(kBucketCount, 0);
            sh.hist.n_valid = 0;
            it = agg.emplace(k, std::move(sh)).first;
        }
        if (mp.incl) {
            auto bi = bucketIndex(mp.num, mp.den, e, mp.incl, scale);
            ++it->second.hist.h[bi.bucket];
            ++it->second.hist.n_valid;
        }
    }

    std::vector<SectorHistogram> out;
    out.reserve(agg.size());
    for (auto& kv : agg) out.push_back(std::move(kv.second));
    return out;
}

std::vector<SectorRatio>
aggregateRatios(const std::vector<EntityMetricRow>& rows, Metric m) {
    std::map<SectorKey, SectorRatio> agg;
    for (const auto& r : rows) {
        const auto& mp = r.metrics[static_cast<size_t>(m)];
        SectorKey k{r.sector, r.period};
        auto it = agg.find(k);
        if (it == agg.end()) {
            SectorRatio sr{};
            sr.key = k;
            sr.metric = m;
            sr.sum_num = 0;
            sr.sum_den = 0;
            sr.incl = 0;
            sr.ratio_fp = 0;
            it = agg.emplace(k, sr).first;
        }
        if (mp.incl) {
            it->second.sum_num += mp.num;
            it->second.sum_den += mp.den;
            it->second.incl = 1;
        }
    }
    // One Goldschmidt reciprocal per (sector, period) — Rev 7 §10.
    for (auto& kv : agg) {
        if (kv.second.incl && kv.second.sum_den > 0) {
            kv.second.ratio_fp = fpRatio(kv.second.sum_num, kv.second.sum_den);
        }
    }

    std::vector<SectorRatio> out;
    out.reserve(agg.size());
    for (auto& kv : agg) out.push_back(kv.second);
    return out;
}

SectorAggregateBundle
aggregateAllMetrics(const std::vector<EntityMetricRow>& rows,
                    const BucketEdges& edges) {
    SectorAggregateBundle b;
    for (size_t m = 0; m < kMetricCount; ++m) {
        Metric mm = static_cast<Metric>(m);
        b.hists[m]  = aggregateHistograms(rows, mm, edges);
        b.ratios[m] = aggregateRatios(rows, mm);
    }
    return b;
}

SectorAggregateAudit
auditSectorAggregate(const std::vector<EntityMetricRow>& rows,
                     const SectorAggregateBundle& bundle) {
    auto plain = aggregateOverAll(rows);
    SectorAggregateAudit a{true, true};
    for (size_t m = 0; m < kMetricCount; ++m) {
        uint64_t hist_total_valid = 0;
        for (const auto& sh : bundle.hists[m]) hist_total_valid += sh.hist.n_valid;
        if (hist_total_valid != plain[m].n_valid) a.hist_totals_match = false;

        uint64_t ratio_sum_num = 0, ratio_sum_den = 0;
        for (const auto& sr : bundle.ratios[m]) {
            ratio_sum_num += sr.sum_num;
            ratio_sum_den += sr.sum_den;
        }
        if (ratio_sum_num != plain[m].sum_num) a.ratio_totals_match = false;
        if (ratio_sum_den != plain[m].sum_den) a.ratio_totals_match = false;
    }
    return a;
}

} // namespace mpsvs
} // namespace volePSI
