#include "MpsvsRank.h"

#include <algorithm>
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
        default: throw std::invalid_argument("edgesFor: unknown Metric");
    }
}

uint64_t ratioScaleFor(Metric m) {
    switch (m) {
        case Metric::DTI: case Metric::DSI:
        case Metric::Delq: case Metric::NPL:
        case Metric::UnsecShare: case Metric::StDebtShare:
        case Metric::Gap:
            return 10000;   // bp scale
        default:
            return 1;       // absolute-unit scale (IPW, DEmp)
    }
}

} // namespace

std::vector<SlimRow>
buildSlim(const std::vector<EntityMetricRow>& rows,
          Metric m,
          const std::vector<uint64_t>& edges,
          uint64_t ratio_scale,
          uint32_t (*popkey_selector)(const EntityMetricRow&)) {
    std::vector<SlimRow> out;
    out.reserve(rows.size());
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& r = rows[i];
        const auto& mp = r.metrics[static_cast<size_t>(m)];
        SlimRow s{};
        s.entity_idx = static_cast<uint32_t>(i);
        s.popkey     = popkey_selector ? popkey_selector(r) : 0;
        s.incl       = mp.incl;
        auto b = bucketIndex(mp.num, mp.den, edges, mp.incl, ratio_scale);
        s.bucket     = b.bucket;
        s.rank       = 0;
        out.push_back(s);
    }
    return out;
}

// ---------------------------------------------------------------------------
// slimSort
// ---------------------------------------------------------------------------

void slimSort(std::vector<SlimRow>& slim, const SlimSortConfig& cfg) {
    // Composite key: (popkey, invalid = 1-incl, bucket)
    // — bitonic on the whole key in Rev 6; Rev 7 §8.2.1 uses radix on the
    // bucket sub-key when Φ.radix_enabled. The observable output is the same;
    // the difference is circuit depth.
    (void)cfg;  // semantic ref: std::stable_sort gives the same output.
    std::stable_sort(slim.begin(), slim.end(),
        [](const SlimRow& a, const SlimRow& b) {
            if (a.popkey != b.popkey) return a.popkey < b.popkey;
            uint8_t inv_a = 1 - a.incl;
            uint8_t inv_b = 1 - b.incl;
            if (inv_a != inv_b) return inv_a < inv_b;  // incl=1 first (invalid=0)
            return a.bucket < b.bucket;
        });
}

// ---------------------------------------------------------------------------
// Segmented scan
// ---------------------------------------------------------------------------

std::vector<uint64_t>
segmentedInclusiveSum(const std::vector<uint64_t>& xs,
                      const std::vector<uint8_t>& boundary) {
    if (xs.size() != boundary.size())
        throw std::invalid_argument("segmentedInclusiveSum: size mismatch");
    std::vector<uint64_t> out(xs.size());
    uint64_t acc = 0;
    for (size_t i = 0; i < xs.size(); ++i) {
        if (boundary[i]) acc = 0;   // reset at segment start
        acc += xs[i];
        out[i] = acc;
    }
    return out;
}

// ---------------------------------------------------------------------------
// rankViaHistogram
// ---------------------------------------------------------------------------

RankResult rankViaHistogram(std::vector<SlimRow> slim,
                            const SlimSortConfig& cfg) {
    slimSort(slim, cfg);

    // Rank per (popkey, invalid=0) segment. Excluded rows (incl=0) get rank 0
    // and are irrelevant downstream (score gated by inclusion).
    // Rank[i] = count of INCLUDED rows preceding position i within the same
    // (popkey, invalid=0) segment. Position 0 → rank 0.
    RankResult res;
    res.histogram.h.assign(cfg.B, 0);
    res.histogram.n_valid = 0;

    // We iterate a single pass — since the sort orders (popkey, invalid, bucket),
    // included rows for popkey p sit contiguously followed by excluded rows.
    uint32_t cur_popkey = slim.empty() ? 0 : slim.front().popkey;
    uint64_t rank_in_seg = 0;
    for (auto& r : slim) {
        if (r.popkey != cur_popkey) {
            cur_popkey = r.popkey;
            rank_in_seg = 0;
        }
        if (r.incl) {
            r.rank = rank_in_seg;
            ++rank_in_seg;
            ++res.histogram.n_valid;
            if (r.bucket < cfg.B) ++res.histogram.h[r.bucket];
        } else {
            r.rank = 0;
        }
    }
    res.slim = std::move(slim);
    return res;
}

// ---------------------------------------------------------------------------
// computeMetricRanks — end-to-end helper
// ---------------------------------------------------------------------------

std::vector<EntityRankRow>
computeMetricRanks(const std::vector<EntityMetricRow>& rows,
                   Metric m,
                   const BucketEdges& edges,
                   const SlimSortConfig& cfg,
                   uint32_t (*popkey_selector)(const EntityMetricRow&)) {
    auto slim = buildSlim(rows, m, edgesFor(edges, m), ratioScaleFor(m),
                          popkey_selector);
    auto res  = rankViaHistogram(std::move(slim), cfg);

    // Compute per-popkey n_valid for score normalization.
    // score = rank / max(1, n_valid_in_popkey - 1).
    // For simplicity we compute the popkey → n_valid table over the sorted slim.
    std::vector<uint32_t> popkeys;
    std::vector<uint64_t> n_valid_by_popkey;
    for (const auto& r : res.slim) {
        if (popkeys.empty() || popkeys.back() != r.popkey) {
            popkeys.push_back(r.popkey);
            n_valid_by_popkey.push_back(0);
        }
        if (r.incl) ++n_valid_by_popkey.back();
    }

    std::vector<EntityRankRow> out;
    out.reserve(res.slim.size());
    for (const auto& r : res.slim) {
        EntityRankRow e;
        e.entity_idx = r.entity_idx;
        e.popkey     = r.popkey;
        e.incl       = r.incl;
        e.bucket     = r.bucket;
        e.rank       = r.rank;
        // Find n_valid for this popkey (small linear scan; O(P) with P ~ #sectors).
        uint64_t nv = 0;
        for (size_t k = 0; k < popkeys.size(); ++k) {
            if (popkeys[k] == r.popkey) { nv = n_valid_by_popkey[k]; break; }
        }
        uint64_t denom = (nv > 1) ? (nv - 1) : 1;
        // score in [0,1] fp: (rank / denom) * 2^f
        if (!r.incl || nv == 0) {
            e.score_fp = 0;
        } else {
            e.score_fp = fpRatio(r.rank, denom);
        }
        out.push_back(e);
    }
    return out;
}

} // namespace mpsvs
} // namespace volePSI
