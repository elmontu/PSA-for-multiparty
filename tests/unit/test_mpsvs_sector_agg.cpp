// MPSVS Phase 11 acceptance tests — Sector aggregation (§10).

#include "volePSI/MpsvsSectorAgg.h"

#include <cmath>
#include <cstdio>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static EntityMetricRow mkRow(uint16_t sector, uint32_t period,
                              Metric m, uint64_t num, uint64_t den,
                              uint8_t incl) {
    EntityMetricRow r{};
    r.sector = sector;
    r.period = period;
    r.live = 1;
    auto& mp = r.metrics[static_cast<size_t>(m)];
    mp.num = num; mp.den = den; mp.incl = incl;
    return r;
}

static void test_partition_by_sector_period() {
    std::printf("--- C1: partition by (sector, period) ---\n");
    std::vector<EntityMetricRow> rows;
    rows.push_back(mkRow(1, 202601, Metric::DTI, 3000, 100000, 1));
    rows.push_back(mkRow(1, 202601, Metric::DTI, 5000, 100000, 1));
    rows.push_back(mkRow(1, 202602, Metric::DTI, 2000, 100000, 1));
    rows.push_back(mkRow(2, 202601, Metric::DTI, 8000, 100000, 1));

    BucketEdges be = makeDefaultBucketEdges();
    auto hists = aggregateHistograms(rows, Metric::DTI, be);
    CHECK(hists.size() == 3, "C1: 3 (sector, period) buckets");
    uint64_t total = 0;
    for (const auto& sh : hists) total += sh.hist.n_valid;
    CHECK(total == 4, "C1: total n_valid across cells = 4");
}

static void test_ratio_of_sums() {
    std::printf("--- C2: ratio-of-sums = Σn/Σd per cell ---\n");
    std::vector<EntityMetricRow> rows;
    rows.push_back(mkRow(1, 202601, Metric::DTI, 30000, 100000, 1));   // 0.30
    rows.push_back(mkRow(1, 202601, Metric::DTI, 50000, 100000, 1));   // 0.50
    // Cell (1, 202601): Σnum = 80000, Σden = 200000 → ratio = 0.40.

    auto ratios = aggregateRatios(rows, Metric::DTI);
    CHECK(ratios.size() == 1, "C2: 1 cell");
    CHECK(ratios[0].sum_num == 80000, "C2: Σnum correct");
    CHECK(ratios[0].sum_den == 200000, "C2: Σden correct");
    double got = fpToDouble(ratios[0].ratio_fp);
    std::printf("  ratio_of_sums = %.4f (want 0.4)\n", got);
    CHECK(std::abs(got - 0.4) < 1e-6, "C2: ratio = 0.4");
}

static void test_excluded_zero_denom() {
    std::printf("--- C3: excluded rows do NOT enter sum ---\n");
    std::vector<EntityMetricRow> rows;
    rows.push_back(mkRow(1, 202601, Metric::DTI, 30000, 100000, 1));
    rows.push_back(mkRow(1, 202601, Metric::DTI, 999999, 999999, 0));  // excluded
    auto ratios = aggregateRatios(rows, Metric::DTI);
    CHECK(ratios[0].sum_num == 30000, "C3: excluded row not summed into num");
    CHECK(ratios[0].sum_den == 100000, "C3: excluded row not summed into den");
    CHECK(ratios[0].incl == 1, "C3: cell has at least one included");
}

static void test_cell_all_excluded() {
    std::printf("--- C4: cell with all excluded → incl=0 ---\n");
    std::vector<EntityMetricRow> rows;
    rows.push_back(mkRow(1, 202601, Metric::DTI, 1, 1, 0));
    rows.push_back(mkRow(1, 202601, Metric::DTI, 2, 2, 0));
    auto ratios = aggregateRatios(rows, Metric::DTI);
    CHECK(ratios[0].incl == 0, "C4: cell incl = 0");
    CHECK(ratios[0].sum_den == 0, "C4: sum_den = 0");
}

static void test_audit_totals_match() {
    std::printf("--- C5: audit: sector totals == aggregateOverAll totals ---\n");
    std::vector<EntityMetricRow> rows;
    // Populate DTI + Delq across 3 sectors × 2 periods = 6 cells.
    for (uint16_t s = 1; s <= 3; ++s) {
        for (uint32_t p = 202601; p <= 202602; ++p) {
            rows.push_back(mkRow(s, p, Metric::DTI, 30000, 100000, 1));
            rows.push_back(mkRow(s, p, Metric::DTI, 40000, 100000, 1));
            rows.push_back(mkRow(s, p, Metric::Delq, 500, 100000, 1));
        }
    }
    // Only one metric per row in mkRow — need to set both. Fix:
    // Actually mkRow sets only DTI or Delq per call. Let me rebuild
    // so each row has BOTH metrics set to compare against aggregateOverAll.
    rows.clear();
    for (uint16_t s = 1; s <= 3; ++s) {
        for (uint32_t p = 202601; p <= 202602; ++p) {
            EntityMetricRow r{};
            r.sector = s;
            r.period = p;
            r.live = 1;
            auto& dti = r.metrics[static_cast<size_t>(Metric::DTI)];
            dti.num = 30000; dti.den = 100000; dti.incl = 1;
            auto& delq = r.metrics[static_cast<size_t>(Metric::Delq)];
            delq.num = 500; delq.den = 100000; delq.incl = 1;
            rows.push_back(r);
        }
    }
    BucketEdges be = makeDefaultBucketEdges();
    auto bundle = aggregateAllMetrics(rows, be);
    auto audit = auditSectorAggregate(rows, bundle);
    CHECK(audit.hist_totals_match, "C5: hist totals match plain aggregate");
    CHECK(audit.ratio_totals_match, "C5: ratio totals match plain aggregate");
}

int main() {
    test_partition_by_sector_period();
    test_ratio_of_sums();
    test_excluded_zero_denom();
    test_cell_all_excluded();
    test_audit_totals_match();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 11 acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
