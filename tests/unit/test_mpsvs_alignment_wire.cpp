// MPSVS Phase 4 MPC-wire — F_PSA alignment (within-bin sort + windowed merge).

#include "volePSI/MpsvsAlignmentWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_within_bin_sort() {
    std::printf("--- C1: within-bin sort orders by shared key ---\n");
    oc::PRNG prng(oc::block(0x11, 0x22));

    std::vector<SharedBinRow> rows;
    rows.push_back(shareBinRow(0, /*src=*/0, /*key=*/50, 1, 1, 111, prng));
    rows.push_back(shareBinRow(0, 0, 10, 1, 1, 222, prng));
    rows.push_back(shareBinRow(0, 0, 30, 1, 2, 333, prng));
    rows.push_back(shareBinRow(0, 0, 40, 1, 3, 444, prng));

    size_t budget = alignmentWireTripleBudget(rows.size());
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    withinBinSortWire(rows, triples, idx);

    std::printf("  triples used: %zu / %zu\n", idx, budget);
    // Verify keys are now in ascending order.
    uint64_t prev = 0;
    bool monotone = true;
    for (const auto& r : rows) {
        uint64_t k = r.key.reconstruct();
        std::printf("  bin=%u src=%u key=%lu memb=%u sector=%lu payload=%lu\n",
                     r.bin, r.source, k, r.memb.reconstruct(),
                     r.sector.reconstruct(), r.payload.reconstruct());
        if (k < prev) monotone = false;
        prev = k;
    }
    CHECK(monotone, "C1: keys reconstruct in ascending order after wire sort");
    CHECK(rows.size() == 4, "C1: 4 rows preserved (no dummy padding needed)");
}

static void test_within_bin_sort_with_padding() {
    std::printf("--- C2: sort pads to power of 2 with dummy (memb=0, key=max) ---\n");
    oc::PRNG prng(oc::block(0x33, 0x44));
    std::vector<SharedBinRow> rows;
    // 3 rows → pad to 4.
    rows.push_back(shareBinRow(0, 0, 100, 1, 1, 111, prng));
    rows.push_back(shareBinRow(0, 0, 50, 1, 1, 222, prng));
    rows.push_back(shareBinRow(0, 0, 200, 1, 2, 333, prng));

    size_t budget = alignmentWireTripleBudget(4);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    withinBinSortWire(rows, triples, idx);
    CHECK(rows.size() == 4, "C2: padded to 4");
    // Last row should be the dummy (memb=0, key=UINT64_MAX).
    uint64_t last_key = rows.back().key.reconstruct();
    uint8_t last_memb = rows.back().memb.reconstruct();
    std::printf("  last row: key=0x%016lx memb=%u\n", last_key, last_memb);
    CHECK(last_key == UINT64_MAX, "C2: dummy at end has key = 2^64-1");
    CHECK(last_memb == 0, "C2: dummy at end has memb=0");
}

static void test_windowed_merge_match() {
    std::printf("--- C3: R16 gate → live=1 for matching keys with both memb=1 ---\n");
    oc::PRNG prng(oc::block(0x55, 0x66));
    // Two sorted rows with the SAME key + both memb=1 → should merge (live=1).
    std::vector<SharedBinRow> sorted;
    sorted.push_back(shareBinRow(0, 0, /*key=*/42, /*memb=*/1, 5, 999, prng));
    sorted.push_back(shareBinRow(0, 1, /*key=*/42, /*memb=*/1, 5, 777, prng));
    size_t budget = alignmentWireTripleBudget(2);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto merged = windowedMergeWire(sorted, triples, idx);
    auto plain = reconstructMerged(merged);
    CHECK(plain.size() == 2, "C3: 2 output rows");
    std::printf("  row 0: live=%u key=%lu payload=%lu\n",
                 plain[0].live, plain[0].key, plain[0].payload);
    std::printf("  row 1: live=%u key=%lu payload=%lu (tail, no successor)\n",
                 plain[1].live, plain[1].key, plain[1].payload);
    CHECK(plain[0].live == 1, "C3: adjacent match with both memb=1 → live=1");
    CHECK(plain[1].live == 0, "C3: tail row has live=0 (no successor)");
}

static void test_r16_defect_a_closure() {
    std::printf("--- C4: R16 defect-A — dummy in adjacent pair → live=0 ---\n");
    oc::PRNG prng(oc::block(0x77, 0x88));
    // Same key, but ONE of the pair is a dummy (memb=0) — R16 must gate out.
    std::vector<SharedBinRow> sorted;
    sorted.push_back(shareBinRow(0, 0, /*key=*/99, /*memb=*/1, 5, 111, prng));
    sorted.push_back(shareBinRow(0, 4, /*key=*/99, /*memb=*/0, 0, 0, prng));
    size_t budget = alignmentWireTripleBudget(2);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto merged = windowedMergeWire(sorted, triples, idx);
    auto plain = reconstructMerged(merged);
    std::printf("  row 0: live=%u (key match but dummy in pair)\n", plain[0].live);
    CHECK(plain[0].live == 0, "C4: R16 gates out dummy-adjacent match");
}

static void test_windowed_merge_no_match() {
    std::printf("--- C5: different keys → live=0 (no false positives) ---\n");
    oc::PRNG prng(oc::block(0x99, 0xaa));
    std::vector<SharedBinRow> sorted;
    sorted.push_back(shareBinRow(0, 0, /*key=*/10, 1, 5, 111, prng));
    sorted.push_back(shareBinRow(0, 1, /*key=*/20, 1, 5, 222, prng));
    size_t budget = alignmentWireTripleBudget(2);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto merged = windowedMergeWire(sorted, triples, idx);
    auto plain = reconstructMerged(merged);
    CHECK(plain[0].live == 0, "C5: different keys → no merge");
    CHECK(plain[1].live == 0, "C5: tail row unaffected");
}

static void test_full_bin_sort_then_merge() {
    std::printf("--- C6: end-to-end bin: sort then merge, multiple entities ---\n");
    oc::PRNG prng(oc::block(0xab, 0xcd));
    // 4 rows: two entities each appearing twice (2 sources per entity).
    // Entity A: key=42 (both real, memb=1) → should merge live
    // Entity B: key=88 (both real, memb=1) → should merge live
    std::vector<SharedBinRow> rows;
    rows.push_back(shareBinRow(0, 0, 88, 1, 3, 4444, prng));
    rows.push_back(shareBinRow(0, 1, 42, 1, 1, 2222, prng));
    rows.push_back(shareBinRow(0, 0, 42, 1, 1, 1111, prng));
    rows.push_back(shareBinRow(0, 1, 88, 1, 3, 3333, prng));

    size_t budget = alignmentWireTripleBudget(4) * 2;
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    withinBinSortWire(rows, triples, idx);
    auto merged = windowedMergeWire(rows, triples, idx);
    auto plain = reconstructMerged(merged);
    int live_count = 0;
    for (const auto& p : plain) {
        std::printf("  live=%u key=%lu payload=%lu\n", p.live, p.key, p.payload);
        if (p.live) ++live_count;
    }
    // 4 rows, 2 pairs of matches: expected 2 live rows (at positions 0 and 2
    // after sort by key: [42_a, 42_b, 88_a, 88_b] → pairs (0,1) and (2,3)).
    CHECK(live_count == 2, "C6: 2 live rows from 2 matched pairs");
    std::printf("  triples: %zu / %zu\n", idx, budget);
}

int main() {
    test_within_bin_sort();
    test_within_bin_sort_with_padding();
    test_windowed_merge_match();
    test_r16_defect_a_closure();
    test_windowed_merge_no_match();
    test_full_bin_sort_then_merge();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 4 MPC-wire acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
