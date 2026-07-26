// MPSVS Phase 12.1 MPC-wire acceptance tests — output opening from shares.

#include "volePSI/MpsvsOpenWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// Build a shared release row from plaintext (test helper — the real pipeline
// gets shares from Phase 12 upstream).
static SharedReleaseRow mkSharedRow(SectorKey k, Metric m,
                                     const std::vector<uint64_t>& hist_bins,
                                     uint64_t sum_num, uint64_t sum_den,
                                     oc::PRNG& prng) {
    const uint32_t N = 2;
    SharedReleaseRow s;
    s.key = k;
    s.metric = m;
    for (auto v : hist_bins) s.hist.counts.push_back(shareU64(N, v, prng));
    s.sum_num = shareU64(N, sum_num, prng);
    s.sum_den = shareU64(N, sum_den, prng);
    return s;
}

static void test_two_party_open() {
    std::printf("--- C1: two-party open reconstructs plaintext ---\n");
    oc::PRNG prng(oc::block(0x1, 0x2));

    std::vector<SharedReleaseRow> rows;
    std::vector<uint64_t> bins1 = {10, 5, 3, 0, 7};
    rows.push_back(mkSharedRow({1, 202601}, Metric::DTI, bins1, 120, 300, prng));
    std::vector<uint64_t> bins2 = {2, 1, 4};
    rows.push_back(mkSharedRow({2, 202601}, Metric::DTI, bins2, 60, 200, prng));

    auto c0 = extractContribution(0, rows);
    auto c1 = extractContribution(1, rows);
    CHECK(c0.party_id == 0, "C1: party 0 contribution tagged");
    CHECK(c1.party_id == 1, "C1: party 1 contribution tagged");

    auto rel = combineContributions(rows, {c0, c1}, /*rho=*/0.5,
                                     /*query_count=*/2);
    CHECK(rel.rows.size() == 2, "C1: 2 rows reconstructed");
    CHECK(rel.rows[0].hist_clamped == bins1, "C1: row 0 bins match plaintext");
    CHECK(rel.rows[1].hist_clamped == bins2, "C1: row 1 bins match plaintext");
    // ratio-of-sums 120/300 = 0.4, 60/200 = 0.3
    CHECK(std::abs(rel.rows[0].ratio - 0.4) < 1e-9, "C1: row 0 ratio = 0.4");
    CHECK(std::abs(rel.rows[1].ratio - 0.3) < 1e-9, "C1: row 1 ratio = 0.3");
    CHECK(rel.protocol_rev == 7, "C1: protocol_rev = 7");
}

static void test_one_party_hides() {
    std::printf("--- C2: single party's contribution alone does not reveal plaintext ---\n");
    oc::PRNG prng(oc::block(0x3, 0x4));
    std::vector<SharedReleaseRow> rows;
    std::vector<uint64_t> bins = {100, 50, 25, 12, 7};
    rows.push_back(mkSharedRow({1, 202601}, Metric::DTI, bins, 500, 1000, prng));

    std::vector<uint64_t> true_totals = bins;
    true_totals.push_back(500);
    true_totals.push_back(1000);

    bool p0_hides = oneShareDoesNotRevealPlaintext(0, rows, true_totals);
    bool p1_hides = oneShareDoesNotRevealPlaintext(1, rows, true_totals);
    CHECK(p0_hides, "C2: party 0's contribution ≠ plaintext totals (uniform share)");
    CHECK(p1_hides, "C2: party 1's contribution ≠ plaintext totals");
}

static void test_percentiles_computed_from_open() {
    std::printf("--- C3: percentiles derived from opened histogram ---\n");
    oc::PRNG prng(oc::block(0x5, 0x6));
    // Uniform histogram: 10 bins × 10 each, CDF crosses q at expected buckets.
    std::vector<SharedReleaseRow> rows;
    std::vector<uint64_t> bins(10, 10);   // n_valid = 100
    rows.push_back(mkSharedRow({1, 202601}, Metric::DTI, bins, 500, 100, prng));

    auto c0 = extractContribution(0, rows);
    auto c1 = extractContribution(1, rows);
    auto rel = combineContributions(rows, {c0, c1}, 0.1, 1);
    // CDF = {10,20,30,40,50,60,70,80,90,100}
    // p50 target = 50 → bucket 4 (cum=50)
    CHECK(rel.rows[0].percentiles.p50 == 4, "C3: p50 = 4");
    CHECK(rel.rows[0].percentiles.p90 == 8, "C3: p90 = 8");
    CHECK(rel.rows[0].n_valid_noisy == 100, "C3: n_valid = 100");
}

int main() {
    test_two_party_open();
    test_one_party_hides();
    test_percentiles_computed_from_open();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 12.1 MPC-wire acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
