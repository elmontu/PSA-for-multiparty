#include "MpsvsOpen.h"

#include <sstream>

namespace volePSI {
namespace mpsvs {

ReleaseBundle
assembleRelease(const SectorAggregateBundle& pre_noise,
                const NoisySectorBundle& post_noise,
                const BudgetTracker& budget,
                uint32_t protocol_rev) {
    ReleaseBundle rb;
    rb.rho_total = budget.rho_total;
    rb.query_count = budget.query_count;
    rb.bucket_count = kBucketCount;
    rb.protocol_rev = protocol_rev;

    for (size_t m = 0; m < kMetricCount; ++m) {
        Metric mm = static_cast<Metric>(m);
        // Zip pre_noise.hists[m] and post_noise.hists[m] in order (both
        // preserve insertion order from aggregateHistograms).
        const auto& pre  = pre_noise.hists[m];
        const auto& post = post_noise.hists[m];
        const auto& ratios = pre_noise.ratios[m];
        if (pre.size() != post.size()) continue;   // defensive

        for (size_t i = 0; i < pre.size(); ++i) {
            ReleaseRow row;
            row.key = pre[i].key;
            row.metric = mm;
            row.hist_clamped = post[i].h_clamped;
            uint64_t n = 0;
            for (auto v : row.hist_clamped) n += v;
            row.n_valid_noisy = n;

            // Build a Histogram-shaped struct + Cdf for percentile query.
            Histogram h;
            h.h = row.hist_clamped;
            h.n_valid = n;
            Cdf cdf = makeCdf(h);
            row.percentiles = standardPercentiles(cdf);

            // Match ratio-of-sums row for same key.
            row.ratio_incl = 0;
            row.ratio = 0.0;
            for (const auto& sr : ratios) {
                if (sr.key == pre[i].key) {
                    row.ratio_incl = sr.incl;
                    if (sr.incl) row.ratio = fpToDouble(sr.ratio_fp);
                    break;
                }
            }
            rb.rows.push_back(std::move(row));
        }
    }
    return rb;
}

std::string serializeRelease(const ReleaseBundle& r) {
    std::ostringstream ss;
    ss << "{\"protocol_rev\":" << r.protocol_rev
       << ",\"bucket_count\":" << r.bucket_count
       << ",\"rho_total\":" << r.rho_total
       << ",\"query_count\":" << r.query_count
       << ",\"rows\":[";
    for (size_t i = 0; i < r.rows.size(); ++i) {
        const auto& row = r.rows[i];
        if (i > 0) ss << ",";
        ss << "{\"sector\":" << row.key.sector
           << ",\"period\":" << row.key.period
           << ",\"metric\":\"" << metricName(row.metric) << "\""
           << ",\"n_valid\":" << row.n_valid_noisy
           << ",\"p25\":" << row.percentiles.p25
           << ",\"p50\":" << row.percentiles.p50
           << ",\"p75\":" << row.percentiles.p75
           << ",\"p90\":" << row.percentiles.p90
           << ",\"p95\":" << row.percentiles.p95
           << ",\"p99\":" << row.percentiles.p99
           << ",\"ratio_incl\":" << static_cast<int>(row.ratio_incl)
           << ",\"ratio\":" << row.ratio << "}";
    }
    ss << "]}";
    return ss.str();
}

ReleaseAudit auditRelease(const ReleaseBundle& r) {
    ReleaseAudit a{true, true, r.rho_total > 0.0,
                    static_cast<uint32_t>(r.rows.size())};
    for (const auto& row : r.rows) {
        // hist_clamped is u64 → non-negative by type; invariant re-checks that
        // no undefined transformation snuck in a wrap-negative representation.
        uint64_t cum = 0, prev = 0;
        for (auto v : row.hist_clamped) {
            prev = cum;
            cum += v;
            if (cum < prev) a.r26_cdf_monotone_per_row = false;
        }
    }
    return a;
}

} // namespace mpsvs
} // namespace volePSI
