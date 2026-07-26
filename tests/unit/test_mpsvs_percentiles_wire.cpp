// MPSVS Phase 10 MPC-wire — percentile query on shared histogram.

#include "volePSI/MpsvsPercentiles.h"
#include "volePSI/MpsvsPercentilesWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// Helpers.
static std::vector<SharedU64Bin> shareBins(std::initializer_list<uint64_t> v,
                                              oc::PRNG& prng) {
    std::vector<SharedU64Bin> out;
    for (auto x : v) out.push_back(shareU64Bin(2, x, prng));
    return out;
}

static void test_prefix_sum() {
    std::printf("--- C1: sharedPrefixSum matches plaintext ---\n");
    oc::PRNG prng(oc::block(0x11, 0x22));
    auto bins = shareBins({3, 7, 2, 5}, prng);
    size_t budget = percentileWireTripleBudget(4);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto cum = sharedPrefixSum(bins, triples, idx);
    uint64_t got0 = cum[0].reconstruct();
    uint64_t got1 = cum[1].reconstruct();
    uint64_t got2 = cum[2].reconstruct();
    uint64_t got3 = cum[3].reconstruct();
    std::printf("  cum = %lu, %lu, %lu, %lu (want 3, 10, 12, 17) triples %zu/%zu\n",
                 got0, got1, got2, got3, idx, budget);
    CHECK(got0 == 3, "C1: cum[0] = bins[0]");
    CHECK(got1 == 10, "C1: cum[1] = 3+7");
    CHECK(got2 == 12, "C1: cum[2] = 10+2");
    CHECK(got3 == 17, "C1: cum[3] = 12+5");
}

static void test_percentile_median() {
    std::printf("--- C2: p50 lands in correct bucket (uniform) ---\n");
    oc::PRNG prng(oc::block(0x33, 0x44));
    // Histogram: {10, 10, 10, 10, 10, 10, 10, 10} (8 bins, N=80)
    // CDF: 10, 20, 30, 40, 50, 60, 70, 80.
    // Target for q=0.5: N/2 = 40. First cum >= 40 is bucket 3 (cum=40).
    auto bins = shareBins({10, 10, 10, 10, 10, 10, 10, 10}, prng);
    size_t budget = percentileWireTripleBudget(8);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto cum = sharedPrefixSum(bins, triples, idx);
    // Total N.
    SharedU64Bin N = shareU64Bin(2, 80, prng);
    SharedU64Bin bucket = percentileBucketWire(cum, N, /*q_num=*/1, /*q_den=*/2,
                                                  triples, idx);
    uint64_t p50 = bucket.reconstruct();
    std::printf("  p50 = %lu (want 3) triples %zu/%zu\n", p50, idx, budget);
    CHECK(p50 == 3, "C2: p50 = bucket 3");
}

static void test_percentile_quartiles() {
    std::printf("--- C3: p25, p75, p90 match plaintext oracle ---\n");
    oc::PRNG prng(oc::block(0x55, 0x66));
    auto bins_plain = std::vector<uint64_t>{10, 10, 10, 10, 10, 10, 10, 10};
    Histogram plain_h;
    plain_h.h = bins_plain;
    plain_h.n_valid = 80;
    Cdf plain_cdf = makeCdf(plain_h);
    uint32_t p25_want = percentileBucket(plain_cdf, 0.25);
    uint32_t p75_want = percentileBucket(plain_cdf, 0.75);
    uint32_t p90_want = percentileBucket(plain_cdf, 0.90);

    auto bins = shareBins({10, 10, 10, 10, 10, 10, 10, 10}, prng);
    size_t budget = percentileWireTripleBudget(8) * 4;
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto cum = sharedPrefixSum(bins, triples, idx);
    SharedU64Bin N = shareU64Bin(2, 80, prng);

    // p25 = q=1/4 (power of 2)
    auto b25 = percentileBucketWire(cum, N, 1, 4, triples, idx).reconstruct();
    // p75 = q=75/100
    auto b75 = percentileBucketWire(cum, N, 75, 100, triples, idx).reconstruct();
    // p90 = q=90/100
    auto b90 = percentileBucketWire(cum, N, 90, 100, triples, idx).reconstruct();
    std::printf("  p25 wire=%lu plain=%u\n", b25, p25_want);
    std::printf("  p75 wire=%lu plain=%u\n", b75, p75_want);
    std::printf("  p90 wire=%lu plain=%u\n", b90, p90_want);
    CHECK(b25 == p25_want, "C3: p25 matches plaintext oracle");
    CHECK(b75 == p75_want, "C3: p75 matches plaintext oracle");
    CHECK(b90 == p90_want, "C3: p90 matches plaintext oracle");
}

static void test_skewed_histogram() {
    std::printf("--- C4: skewed histogram → p50 in dominant bucket ---\n");
    oc::PRNG prng(oc::block(0x77, 0x88));
    // {2, 2, 100, 2, 2, 2}, N=110. p50 target = 55. CDF: 2, 4, 104, 106, 108, 110.
    // First cum >= 55 is bucket 2 (cum=104).
    auto bins = shareBins({2, 2, 100, 2, 2, 2}, prng);
    size_t budget = percentileWireTripleBudget(6);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto cum = sharedPrefixSum(bins, triples, idx);
    SharedU64Bin N = shareU64Bin(2, 110, prng);
    auto p50 = percentileBucketWire(cum, N, 1, 2, triples, idx).reconstruct();
    std::printf("  p50 = %lu (want 2)\n", p50);
    CHECK(p50 == 2, "C4: p50 in dominant bucket");
}

int main() {
    test_prefix_sum();
    test_percentile_median();
    test_percentile_quartiles();
    test_skewed_histogram();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 10 MPC-wire acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
