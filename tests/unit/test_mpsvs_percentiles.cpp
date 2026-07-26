// MPSVS Phase 10 acceptance tests — GroupPercentiles + CDF inversion.

#include "volePSI/MpsvsPercentiles.h"
#include "volePSI/MpsvsRatioBucket.h"

#include <cmath>
#include <cstdio>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static Histogram mkHist(std::initializer_list<uint64_t> vals) {
    Histogram h;
    for (auto v : vals) h.h.push_back(v);
    h.n_valid = 0;
    for (auto v : h.h) h.n_valid += v;
    return h;
}

static void test_cdf_construction() {
    std::printf("--- C1: CDF is prefix-sum + monotone flag ---\n");
    Histogram h = mkHist({1, 3, 2, 4});
    Cdf c = makeCdf(h);
    CHECK(c.cum.size() == 4, "C1: 4 CDF entries");
    CHECK(c.cum[0] == 1 && c.cum[1] == 4 && c.cum[2] == 6 && c.cum[3] == 10,
          "C1: CDF = {1,4,6,10}");
    CHECK(c.N == 10, "C1: N = sum(h)");
    CHECK(c.monotone == true, "C1: monotone flag set");
}

static void test_percentile_median() {
    std::printf("--- C2: median (q=0.5) lands in correct bucket ---\n");
    // Histogram: buckets 0..4 with counts {2, 2, 2, 2, 2}, N=10.
    // CDF: {2, 4, 6, 8, 10}. Target for q=0.5: ⌈5⌉ = 5. First cum >= 5 → bucket 2.
    Histogram h = mkHist({2, 2, 2, 2, 2});
    Cdf c = makeCdf(h);
    uint32_t p50 = percentileBucket(c, 0.5);
    CHECK(p50 == 2, "C2: median in bucket 2");
}

static void test_percentile_edges() {
    std::printf("--- C3: q=0 → first non-empty bucket; q=1 → last non-empty ---\n");
    Histogram h = mkHist({0, 0, 5, 3, 0, 2});   // N=10
    Cdf c = makeCdf(h);
    // CDF = {0, 0, 5, 8, 8, 10}
    uint32_t p_low  = percentileBucket(c, 0.001);   // target = ⌈0.01⌉ = 1 → bucket 2
    uint32_t p_high = percentileBucket(c, 1.0);     // target = 10 → bucket 5
    CHECK(p_low == 2, "C3: q≈0 → bucket 2 (first non-empty)");
    CHECK(p_high == 5, "C3: q=1 → bucket 5 (last non-empty)");
}

static void test_standard_percentiles() {
    std::printf("--- C4: standard percentile suite ---\n");
    // Fifty-fifty split around bucket 5.
    Histogram h;
    h.h.assign(10, 0);
    for (int i = 0; i < 10; ++i) h.h[i] = 10;    // uniform, N=100
    h.n_valid = 100;
    Cdf c = makeCdf(h);
    // CDF = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
    // p25 target=25 → bucket 2 (cum=30 ≥ 25)
    // p50 target=50 → bucket 4 (cum=50 ≥ 50)
    // p75 target=75 → bucket 7 (cum=80 ≥ 75)
    // p90 target=90 → bucket 8 (cum=90 ≥ 90)
    // p95 target=95 → bucket 9 (cum=100 ≥ 95)
    // p99 target=99 → bucket 9
    StdPercentiles sp = standardPercentiles(c);
    CHECK(sp.p25 == 2, "C4: p25 = 2");
    CHECK(sp.p50 == 4, "C4: p50 = 4");
    CHECK(sp.p75 == 7, "C4: p75 = 7");
    CHECK(sp.p90 == 8, "C4: p90 = 8");
    CHECK(sp.p95 == 9, "C4: p95 = 9");
    CHECK(sp.p99 == 9, "C4: p99 = 9");
}

static void test_empty_hist() {
    std::printf("--- C5: N=0 → returns 0 without crash ---\n");
    Histogram h;
    h.h.assign(8, 0);
    h.n_valid = 0;
    Cdf c = makeCdf(h);
    CHECK(c.N == 0, "C5: N=0");
    uint32_t p = percentileBucket(c, 0.5);
    CHECK(p == 0, "C5: percentile on empty CDF = 0");
}

static void test_non_monotone_detection() {
    std::printf("--- C6: non-monotone CDF is detected (Gap 11 sentinel) ---\n");
    // Simulate DP noise producing overflow → cum wraps.
    Cdf c;
    c.cum = {5, 10, 15, 12};   // cum[3] < cum[2] → non-monotone
    c.N = 12;
    c.monotone = true;
    // Recompute the flag using our helper by constructing a hist that would
    // NEVER produce this — but our detection is at makeCdf time. Direct
    // synthesis here just checks the flag interpretation.
    // For makeCdf, non-monotone can only occur on integer overflow (u64 wrap).
    // Simulate: h = {UINT64_MAX/2, UINT64_MAX/2, UINT64_MAX/2} would wrap.
    Histogram h;
    h.h = {UINT64_MAX / 2, UINT64_MAX / 2, UINT64_MAX / 2};
    Cdf c2 = makeCdf(h);
    CHECK(c2.monotone == false, "C6: overflow wrap detected as non-monotone");
}

static void test_bucket_midpoint() {
    std::printf("--- C7: bucketMidpoint maps to representative value ---\n");
    auto edges = makeLinearEdges(0, 1000, 10);   // width 100 each
    double m0 = bucketMidpoint(0, edges);
    double m5 = bucketMidpoint(5, edges);
    double m9 = bucketMidpoint(9, edges);
    std::printf("  midpoints: b0=%.1f  b5=%.1f  b9=%.1f\n", m0, m5, m9);
    CHECK(std::abs(m0 - 50.0)  < 1e-6, "C7: bucket 0 midpoint = 50");
    CHECK(std::abs(m5 - 550.0) < 1e-6, "C7: bucket 5 midpoint = 550");
    CHECK(std::abs(m9 - 950.0) < 1e-6, "C7: bucket 9 midpoint = 950");
}

int main() {
    test_cdf_construction();
    test_percentile_median();
    test_percentile_edges();
    test_standard_percentiles();
    test_empty_hist();
    test_non_monotone_detection();
    test_bucket_midpoint();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 10 acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
