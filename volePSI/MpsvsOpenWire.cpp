#include "MpsvsOpenWire.h"
#include "MpsvsPercentiles.h"

#include <stdexcept>

namespace volePSI {
namespace mpsvs {

PartyContribution extractContribution(uint32_t party_id,
                                       const std::vector<SharedReleaseRow>& rows) {
    PartyContribution c;
    c.party_id = party_id;
    for (const auto& r : rows) {
        for (const auto& sb : r.hist.counts) {
            if (party_id >= sb.N())
                throw std::runtime_error("party_id out of range");
            c.flat_shares.push_back(sb.shares[party_id]);
        }
        c.flat_shares.push_back(r.sum_num.shares[party_id]);
        c.flat_shares.push_back(r.sum_den.shares[party_id]);
    }
    return c;
}

ReleaseBundle
combineContributions(const std::vector<SharedReleaseRow>& shape,
                      const std::vector<PartyContribution>& contribs,
                      double rho_total,
                      uint32_t query_count,
                      uint32_t protocol_rev) {
    ReleaseBundle rb;
    rb.rho_total = rho_total;
    rb.query_count = query_count;
    rb.protocol_rev = protocol_rev;
    rb.bucket_count = shape.empty() ? 0 :
                       static_cast<uint32_t>(shape[0].hist.counts.size());

    // Flat-index cursor per party.
    std::vector<size_t> cursors(contribs.size(), 0);

    for (const auto& sr : shape) {
        ReleaseRow row;
        row.key = sr.key;
        row.metric = sr.metric;

        // Histogram: sum party shares per bin.
        row.hist_clamped.reserve(sr.hist.counts.size());
        uint64_t n_valid = 0;
        for (size_t b = 0; b < sr.hist.counts.size(); ++b) {
            uint64_t v = 0;
            for (size_t p = 0; p < contribs.size(); ++p) {
                v += contribs[p].flat_shares[cursors[p]++];
            }
            row.hist_clamped.push_back(v);
            n_valid += v;
        }
        row.n_valid_noisy = n_valid;

        // sum_num, sum_den
        uint64_t sn = 0, sd = 0;
        for (size_t p = 0; p < contribs.size(); ++p) {
            sn += contribs[p].flat_shares[cursors[p]++];
            sd += contribs[p].flat_shares[cursors[p]++];
        }
        row.ratio_incl = (sd > 0) ? 1 : 0;
        row.ratio = row.ratio_incl ?
                      (static_cast<double>(sn) / static_cast<double>(sd)) : 0.0;

        // Percentiles from clamped CDF.
        Histogram h;
        h.h = row.hist_clamped;
        h.n_valid = n_valid;
        Cdf cdf = makeCdf(h);
        row.percentiles = standardPercentiles(cdf);

        rb.rows.push_back(std::move(row));
    }
    return rb;
}

bool oneShareDoesNotRevealPlaintext(uint32_t party_id,
                                     const std::vector<SharedReleaseRow>& rows,
                                     const std::vector<uint64_t>& true_totals) {
    // Extract this party's flat shares; check they do NOT equal the true
    // totals (info-theoretic hiding: shares are uniform over Z_{2^64}).
    PartyContribution c = extractContribution(party_id, rows);
    size_t matches = 0;
    for (size_t i = 0; i < c.flat_shares.size() && i < true_totals.size(); ++i) {
        if (c.flat_shares[i] == true_totals[i]) ++matches;
    }
    // With truly uniform shares, matches should be 0 (or vanishingly rare).
    return matches == 0;
}

} // namespace mpsvs
} // namespace volePSI
