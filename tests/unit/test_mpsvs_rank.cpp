// MPSVS Phase 8 acceptance tests — RankViaHistogram + slim-sort.

#include "volePSI/MpsvsRank.h"

#include <cstdio>
#include <vector>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static EntityMetricRow makeRow(uint32_t sector, uint64_t num, uint64_t den,
                                uint8_t incl) {
    EntityMetricRow r{};
    r.sector = sector;
    r.live = 1;
    auto& mp = r.metrics[static_cast<size_t>(Metric::DTI)];
    mp.num = num; mp.den = den; mp.incl = incl;
    return r;
}

static uint32_t bySector(const EntityMetricRow& r) {
    return static_cast<uint32_t>(r.sector);
}

static void test_slim_sort_ordering() {
    std::printf("--- C1: slimSort orders by (popkey, invalid, bucket) ---\n");
    std::vector<SlimRow> s = {
        {0, /*popkey=*/1, 1, /*bucket=*/5, 0},
        {1, 0, 1, 3, 0},
        {2, 1, 0, 7, 0},   // invalid (incl=0)
        {3, 0, 1, 8, 0},
        {4, 1, 1, 2, 0},
    };
    slimSort(s);
    CHECK(s[0].popkey == 0 && s[0].bucket == 3, "C1: (popkey=0, incl=1, bucket=3) first");
    CHECK(s[1].popkey == 0 && s[1].bucket == 8, "C1: (popkey=0, incl=1, bucket=8) second");
    CHECK(s[2].popkey == 1 && s[2].incl == 1 && s[2].bucket == 2, "C1: (popkey=1, incl=1, bucket=2) third");
    CHECK(s[3].popkey == 1 && s[3].incl == 1 && s[3].bucket == 5, "C1: (popkey=1, incl=1, bucket=5) fourth");
    CHECK(s[4].popkey == 1 && s[4].incl == 0, "C1: (popkey=1, invalid) last");
}

static void test_rank_within_popkey() {
    std::printf("--- C2: rank is monotone in bucket within popkey ---\n");
    std::vector<SlimRow> s = {
        {0, 5, 1, /*bucket=*/10, 0},
        {1, 5, 1, 4, 0},
        {2, 5, 1, 7, 0},
        {3, 5, 1, 4, 0},   // duplicate bucket
    };
    SlimSortConfig cfg; cfg.B = 128;
    auto res = rankViaHistogram(s, cfg);
    // After sort: buckets 4, 4, 7, 10 → ranks 0, 1, 2, 3
    CHECK(res.slim.size() == 4, "C2: no rows dropped");
    for (size_t i = 0; i < res.slim.size(); ++i) {
        CHECK(res.slim[i].rank == i, "C2: rank == position within popkey");
        if (i > 0)
            CHECK(res.slim[i].bucket >= res.slim[i-1].bucket, "C2: bucket monotone");
    }
}

static void test_histogram_sum() {
    std::printf("--- C3: histogram sums to n_valid ---\n");
    std::vector<SlimRow> s = {
        {0, 0, 1, 2, 0},
        {1, 0, 1, 5, 0},
        {2, 0, 0, 3, 0},   // excluded
        {3, 0, 1, 5, 0},   // dup bucket 5
    };
    SlimSortConfig cfg; cfg.B = 16;
    auto res = rankViaHistogram(s, cfg);
    CHECK(res.histogram.n_valid == 3, "C3: n_valid = 3 (excluded row skipped)");
    uint64_t sum = 0;
    for (auto v : res.histogram.h) sum += v;
    CHECK(sum == 3, "C3: histogram sum = n_valid");
    CHECK(res.histogram.h[2] == 1, "C3: bucket 2 has 1");
    CHECK(res.histogram.h[5] == 2, "C3: bucket 5 has 2");
    CHECK(res.histogram.h[3] == 0, "C3: excluded row not counted");
}

static void test_excluded_zero_rank() {
    std::printf("--- C4: excluded rows get rank 0 ---\n");
    std::vector<SlimRow> s = {
        {0, 0, 0, 7, 999},
        {1, 0, 1, 3, 0},
    };
    SlimSortConfig cfg; cfg.B = 16;
    auto res = rankViaHistogram(s, cfg);
    for (const auto& r : res.slim) {
        if (!r.incl) {
            CHECK(r.rank == 0, "C4: excluded → rank 0");
        }
    }
}

static void test_multi_popkey() {
    std::printf("--- C5: multi-popkey rank resets per segment ---\n");
    // Build 3 popkeys: sector 1 (2 rows), sector 2 (3 rows), sector 3 (1 row)
    std::vector<EntityMetricRow> rows;
    rows.push_back(makeRow(1, 3000, 100000, 1));   // DTI 3% bp=300
    rows.push_back(makeRow(1, 5000, 100000, 1));   // 5% bp=500
    rows.push_back(makeRow(2, 1000, 100000, 1));   // 1% bp=100
    rows.push_back(makeRow(2, 4000, 100000, 1));   // 4% bp=400
    rows.push_back(makeRow(2, 8000, 100000, 1));   // 8% bp=800
    rows.push_back(makeRow(3, 2000, 100000, 1));   // 2% bp=200

    BucketEdges be = makeDefaultBucketEdges();
    SlimSortConfig cfg; cfg.B = kBucketCount;

    auto ranks = computeMetricRanks(rows, Metric::DTI, be, cfg, &bySector);

    // Ranks within each sector should be 0-indexed and go 0, 1, ...
    uint32_t last_popkey = ranks.front().popkey;
    uint64_t expected_rank = 0;
    for (const auto& r : ranks) {
        if (r.popkey != last_popkey) {
            last_popkey = r.popkey;
            expected_rank = 0;
        }
        if (r.incl) {
            CHECK(r.rank == expected_rank, "C5: rank matches position in popkey segment");
            ++expected_rank;
        }
    }
}

static void test_score_normalization() {
    std::printf("--- C6: score = rank/(n_valid-1) mapped to [0,1] fp ---\n");
    // 5 rows in single sector, buckets producing rank 0..4
    std::vector<EntityMetricRow> rows;
    for (int i = 0; i < 5; ++i) {
        rows.push_back(makeRow(1, static_cast<uint64_t>(1000 + i*2000),
                                100000, 1));
    }
    BucketEdges be = makeDefaultBucketEdges();
    SlimSortConfig cfg; cfg.B = kBucketCount;
    auto ranks = computeMetricRanks(rows, Metric::DTI, be, cfg, &bySector);

    // With 5 included rows, n_valid=5, denom=4. Ranks 0..4 → scores 0, 0.25, 0.5, 0.75, 1.0
    double expected[5] = {0.0, 0.25, 0.5, 0.75, 1.0};
    for (size_t i = 0; i < ranks.size(); ++i) {
        double got = fpToDouble(ranks[i].score_fp);
        double err = std::abs(got - expected[i]);
        std::printf("  rank=%lu got=%.4f want=%.4f\n", ranks[i].rank, got, expected[i]);
        CHECK(err < 1e-6, "C6: score matches rank/(n_valid-1)");
    }
}

static void test_singleton_score() {
    std::printf("--- C7: singleton popkey → score = 0 ---\n");
    std::vector<EntityMetricRow> rows;
    rows.push_back(makeRow(1, 5000, 100000, 1));   // only row in sector 1
    BucketEdges be = makeDefaultBucketEdges();
    SlimSortConfig cfg; cfg.B = kBucketCount;
    auto ranks = computeMetricRanks(rows, Metric::DTI, be, cfg, &bySector);
    CHECK(ranks.size() == 1, "C7: one row out");
    CHECK(ranks[0].rank == 0, "C7: singleton rank = 0");
    // n_valid=1 → denom=1 → score=0/1=0
    double got = fpToDouble(ranks[0].score_fp);
    CHECK(std::abs(got) < 1e-9, "C7: singleton score = 0.0");
}

static void test_segmented_scan() {
    std::printf("--- Extra: segmented inclusive sum ---\n");
    // xs=[1,2,3, 4,5, 6], boundary=[1,0,0, 1,0, 1]
    // Expected: [1,3,6, 4,9, 6]
    std::vector<uint64_t> xs = {1,2,3, 4,5, 6};
    std::vector<uint8_t> b = {1,0,0, 1,0, 1};
    auto ps = segmentedInclusiveSum(xs, b);
    std::vector<uint64_t> want = {1,3,6, 4,9, 6};
    bool ok = true;
    for (size_t i = 0; i < ps.size(); ++i) {
        if (ps[i] != want[i]) { ok = false; break; }
    }
    CHECK(ok, "Extra: segmented sum correct across 3 segments");
}

int main() {
    test_slim_sort_ordering();
    test_rank_within_popkey();
    test_histogram_sum();
    test_excluded_zero_rank();
    test_multi_popkey();
    test_score_normalization();
    test_singleton_score();
    test_segmented_scan();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 8 acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
