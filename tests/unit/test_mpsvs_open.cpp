// MPSVS Phase 12.1 acceptance tests — Output opening protocol to GovTech.

#include "volePSI/MpsvsOpen.h"

#include <cstdio>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static EntityMetricRow mkRow(uint16_t s, uint32_t p, uint64_t num,
                              uint64_t den, uint8_t incl) {
    EntityMetricRow r{};
    r.sector = s; r.period = p; r.live = 1;
    auto& mp = r.metrics[static_cast<size_t>(Metric::DTI)];
    mp.num = num; mp.den = den; mp.incl = incl;
    auto& mp2 = r.metrics[static_cast<size_t>(Metric::Delq)];
    mp2.num = num / 10; mp2.den = num; mp2.incl = incl;
    return r;
}

static void test_release_shape() {
    std::printf("--- C1: release contains one row per (sector, period, metric) cell ---\n");
    std::vector<EntityMetricRow> rows;
    for (uint16_t s = 1; s <= 2; ++s) {
        for (uint32_t p = 202601; p <= 202602; ++p) {
            for (int i = 0; i < 5; ++i) {
                rows.push_back(mkRow(s, p, 20000 + i*10000, 100000, 1));
            }
        }
    }
    BucketEdges be = makeDefaultBucketEdges();
    auto pre = aggregateAllMetrics(rows, be);
    std::mt19937_64 rng(11);
    BudgetTracker bt;
    auto post = addNoiseToBundle(pre, /*rho_per_cell=*/0.1, rng, bt);
    auto rel = assembleRelease(pre, post, bt);

    // 2 sectors × 2 periods = 4 cells per metric × 9 metrics = 36 rows.
    // But most metrics have no included entities; check DTI + Delq at least.
    int dti_rows = 0, delq_rows = 0;
    for (const auto& r : rel.rows) {
        if (r.metric == Metric::DTI) ++dti_rows;
        if (r.metric == Metric::Delq) ++delq_rows;
    }
    CHECK(dti_rows == 4, "C1: 4 DTI cells released");
    CHECK(delq_rows == 4, "C1: 4 Delq cells released");
    CHECK(rel.protocol_rev == 7, "C1: protocol_rev = 7");
    CHECK(rel.bucket_count == kBucketCount, "C1: bucket_count = 128");
}

static void test_r26_invariant_in_release() {
    std::printf("--- C2: R26 — released hist_clamped is non-negative ---\n");
    std::vector<EntityMetricRow> rows;
    for (int i = 0; i < 20; ++i) {
        rows.push_back(mkRow(1, 202601, 20000 + i*5000, 100000, 1));
    }
    BucketEdges be = makeDefaultBucketEdges();
    auto pre = aggregateAllMetrics(rows, be);
    std::mt19937_64 rng(42);
    BudgetTracker bt;
    // Larger noise → more clamp events
    auto post = addNoiseToBundle(pre, /*rho_per_cell=*/0.05, rng, bt);
    auto rel = assembleRelease(pre, post, bt);
    auto a = auditRelease(rel);
    CHECK(a.r26_no_negative_bins, "C2: no negative bins in release");
    CHECK(a.r26_cdf_monotone_per_row, "C2: CDF monotone per row");
}

static void test_percentiles_from_release() {
    std::printf("--- C3: released percentiles align with underlying data ---\n");
    std::vector<EntityMetricRow> rows;
    // Uniform DTI 30% for 20 entities → all in bucket 38 (30% bp = 3000, at
    // 128 buckets over 10000 bp → 3000*128/10000 = 38.4 → bucket 38).
    for (int i = 0; i < 20; ++i) {
        rows.push_back(mkRow(1, 202601, 30000, 100000, 1));
    }
    BucketEdges be = makeDefaultBucketEdges();
    auto pre = aggregateAllMetrics(rows, be);
    std::mt19937_64 rng(7);
    BudgetTracker bt;
    // Very small noise so percentile is stable.
    auto post = addNoiseToBundle(pre, /*rho_per_cell=*/2.0, rng, bt);
    auto rel = assembleRelease(pre, post, bt);
    for (const auto& row : rel.rows) {
        if (row.metric == Metric::DTI) {
            // All data in bucket 38 → percentiles all bucket 38.
            std::printf("  DTI: p25=%u p50=%u p75=%u\n",
                        row.percentiles.p25, row.percentiles.p50,
                        row.percentiles.p75);
            // With low noise the percentile should land at 38 (may slip ±1).
            CHECK(row.percentiles.p50 >= 37 && row.percentiles.p50 <= 39,
                  "C3: DTI p50 near bucket 38");
        }
    }
}

static void test_ratio_of_sums() {
    std::printf("--- C4: ratio-of-sums included when cell has valid entities ---\n");
    std::vector<EntityMetricRow> rows;
    rows.push_back(mkRow(1, 202601, 30000, 100000, 1));
    rows.push_back(mkRow(1, 202601, 50000, 100000, 1));
    BucketEdges be = makeDefaultBucketEdges();
    auto pre = aggregateAllMetrics(rows, be);
    std::mt19937_64 rng(1);
    BudgetTracker bt;
    auto post = addNoiseToBundle(pre, /*rho_per_cell=*/0.5, rng, bt);
    auto rel = assembleRelease(pre, post, bt);
    for (const auto& r : rel.rows) {
        if (r.metric == Metric::DTI && r.key.sector == 1) {
            CHECK(r.ratio_incl == 1, "C4: ratio_incl=1 for populated cell");
            // Ratio = 80000/200000 = 0.4
            CHECK(std::abs(r.ratio - 0.4) < 1e-6, "C4: released ratio = 0.4");
        }
    }
}

static void test_serialization() {
    std::printf("--- C5: serialization returns valid JSON-like text ---\n");
    std::vector<EntityMetricRow> rows;
    rows.push_back(mkRow(1, 202601, 30000, 100000, 1));
    BucketEdges be = makeDefaultBucketEdges();
    auto pre = aggregateAllMetrics(rows, be);
    std::mt19937_64 rng(2);
    BudgetTracker bt;
    auto post = addNoiseToBundle(pre, /*rho_per_cell=*/0.1, rng, bt);
    auto rel = assembleRelease(pre, post, bt);
    std::string ser = serializeRelease(rel);
    CHECK(ser.find("\"protocol_rev\":7") != std::string::npos,
          "C5: serialization includes protocol_rev");
    CHECK(ser.find("\"metric\":\"DTI\"") != std::string::npos,
          "C5: serialization includes DTI");
    CHECK(ser.find("\"p50\"") != std::string::npos,
          "C5: serialization includes p50");
    std::printf("  serialized length = %zu\n", ser.size());
}

int main() {
    test_release_shape();
    test_r26_invariant_in_release();
    test_percentiles_from_release();
    test_ratio_of_sums();
    test_serialization();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 12.1 acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
