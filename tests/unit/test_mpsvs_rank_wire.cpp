// MPSVS Phase 8 MPC-wire — rank via bitonic sort on shares + segmented scan.

#include "volePSI/MpsvsInclusionWire.h"
#include "volePSI/MpsvsRankWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// Fabricate a SharedEntityMetricRow with only what Phase 8 needs:
// (sector, incl, bucket-as-num).
static SharedEntityMetricRow mkRow(uint16_t sector, uint8_t incl,
                                     uint32_t bucket, oc::PRNG& prng) {
    SharedEntityMetricRow r;
    r.sector = sector;
    r.period = 202601;
    r.live = shareBit(2, 1, prng);
    r.b_MAS = shareBit(2, 1, prng);
    r.b_DOS = shareBit(2, 1, prng);
    r.b_MOM = shareBit(2, 1, prng);
    for (size_t i = 0; i < kMetricCount; ++i) {
        r.metrics[i].num = shareU64Bin(2, 0, prng);
        r.metrics[i].den = shareU64Bin(2, 0, prng);
        r.metrics[i].incl = shareBit(2, 0, prng);
    }
    // Test convention: metrics[DTI].num holds the bucket ID (test-only).
    r.metrics[static_cast<size_t>(Metric::DTI)].num = shareU64Bin(2, bucket, prng);
    r.metrics[static_cast<size_t>(Metric::DTI)].incl = shareBit(2, incl, prng);
    r.incl_vuln = shareBit(2, 0, prng);
    r.avail_core_count = shareU64Bin(2, 0, prng);
    return r;
}

static void test_wire_rank_matches_plain() {
    std::printf("--- C1: wire rank reconstructs to plaintext expected ranks ---\n");
    oc::PRNG prng(oc::block(0x11, 0x22));

    // 4 rows, all in sector 1, buckets 5, 2, 8, 5 (dup) — after sort: 2, 5, 5, 8
    // Ranks: 0, 1, 2, 3 (all included)
    std::vector<SharedEntityMetricRow> rows;
    rows.push_back(mkRow(1, 1, 5, prng));
    rows.push_back(mkRow(1, 1, 2, prng));
    rows.push_back(mkRow(1, 1, 8, prng));
    rows.push_back(mkRow(1, 1, 5, prng));

    size_t budget = rankWireTripleBudget(rows.size(), 128);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto shared_out = rankViaHistogramWire(rows, Metric::DTI, /*B=*/128,
                                             triples, idx, prng);
    auto plain = reconstructRanked(shared_out);
    CHECK(plain.size() == 4, "C1: 4 rows out");

    // Check ranks are 0, 1, 2, 3 in some order matching bucket sort.
    std::printf("  triples: %zu / %zu\n", idx, budget);
    for (const auto& r : plain) {
        std::printf("  entity_idx=%u popkey=%u incl=%u bucket=%u rank=%lu\n",
                     r.entity_idx, r.popkey, r.incl, r.bucket, r.rank);
    }
    // After sort by bucket ascending: rows with buckets 2, 5, 5, 8 → ranks 0,1,2,3
    CHECK(plain[0].bucket == 2 && plain[0].rank == 0, "C1: bucket 2 → rank 0");
    CHECK(plain[1].bucket == 5 && plain[1].rank == 1, "C1: first bucket 5 → rank 1");
    CHECK(plain[2].bucket == 5 && plain[2].rank == 2, "C1: second bucket 5 → rank 2");
    CHECK(plain[3].bucket == 8 && plain[3].rank == 3, "C1: bucket 8 → rank 3");
}

static void test_excluded_rows_at_end() {
    std::printf("--- C2: excluded rows sort to end (invalid=1 higher key) ---\n");
    oc::PRNG prng(oc::block(0xa, 0xb));
    std::vector<SharedEntityMetricRow> rows;
    rows.push_back(mkRow(1, 1, 5, prng));   // included
    rows.push_back(mkRow(1, 0, 3, prng));   // excluded
    rows.push_back(mkRow(1, 1, 7, prng));   // included
    rows.push_back(mkRow(1, 0, 9, prng));   // excluded

    size_t budget = rankWireTripleBudget(rows.size(), 128);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto shared_out = rankViaHistogramWire(rows, Metric::DTI, /*B=*/128,
                                             triples, idx, prng);
    auto plain = reconstructRanked(shared_out);

    // Included rows sort first by bucket: (5, r=0), (7, r=1); then excluded.
    // rank_acc DOES advance on all rows via incl-bit-add, so excluded rows
    // are "rank" of whatever was accumulated at their position, but incl=0
    // means they wouldn't advance the acc.
    for (const auto& r : plain) {
        std::printf("  entity_idx=%u incl=%u bucket=%u rank=%lu\n",
                     r.entity_idx, r.incl, r.bucket, r.rank);
    }
    // Verify: included rows have ranks 0, 1 in bucket order.
    int count_incl = 0;
    for (const auto& r : plain) {
        if (r.incl) {
            CHECK(r.rank == static_cast<uint64_t>(count_incl),
                  "C2: incl row has rank matching its position");
            ++count_incl;
        }
    }
    CHECK(count_incl == 2, "C2: exactly 2 included rows");
}

static void test_multi_popkey() {
    std::printf("--- C3: multi-popkey — rank resets per popkey ---\n");
    oc::PRNG prng(oc::block(0x33, 0x44));
    std::vector<SharedEntityMetricRow> rows;
    // sector 1: 2 rows; sector 2: 2 rows; sector 3: 1 row.
    rows.push_back(mkRow(1, 1, 3, prng));
    rows.push_back(mkRow(1, 1, 7, prng));
    rows.push_back(mkRow(2, 1, 4, prng));
    rows.push_back(mkRow(2, 1, 6, prng));
    rows.push_back(mkRow(3, 1, 5, prng));

    size_t budget = rankWireTripleBudget(rows.size(), 128);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto shared_out = rankViaHistogramWire(rows, Metric::DTI, /*B=*/128,
                                             triples, idx, prng);
    auto plain = reconstructRanked(shared_out);

    for (const auto& r : plain) {
        std::printf("  popkey=%u bucket=%u rank=%lu\n", r.popkey, r.bucket, r.rank);
    }
    // Sector 1: 2 rows sorted by bucket (3, 7) → ranks 0, 1
    // Sector 2: 2 rows (4, 6) → ranks 0, 1
    // Sector 3: 1 row (5) → rank 0
    int expected[5] = {0, 1, 0, 1, 0};
    for (size_t i = 0; i < plain.size(); ++i) {
        CHECK(plain[i].rank == static_cast<uint64_t>(expected[i]),
              "C3: rank matches expected per-popkey position");
    }
}

int main() {
    test_wire_rank_matches_plain();
    test_excluded_rows_at_end();
    test_multi_popkey();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 8 MPC-wire acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
