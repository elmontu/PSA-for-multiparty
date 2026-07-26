// MPSVS Phase 9 MPC-wire — composite vuln score on shares.
// Tests both STRICT and RENORMALISED variants + full-protocol scenario.

#include "volePSI/MpsvsCompositeWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cmath>
#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static SharedRankedRow mkRankedRow(uint32_t eid, uint32_t popkey,
                                     uint8_t incl, uint64_t rank,
                                     oc::PRNG& prng) {
    SharedRankedRow r;
    r.entity_idx = eid;
    r.popkey = popkey;
    r.incl = shareBit(2, incl, prng);
    r.bucket = shareU64Bin(2, 0, prng);
    r.rank = shareU64Bin(2, rank, prng);
    return r;
}

// Common triple budget per entity (worst case: 4 core + full renorm path).
static size_t budgetForEntities(size_t n_entities, size_t n_cells) {
    return n_cells * goldschmidtWireTripleBudget(6)              // cell reciprocals (n_valid-1)
         + n_entities * goldschmidtWireTripleBudget(6)            // per-entity renorm denom recip
         + n_entities * 4 * 65536                                  // 4× fpMulShared (rank·recip)
         + n_entities * 4 * 130 * 384                              // 4× mulPublicConst128
         + n_entities * 4 * 4 * 384                                // bitAdds (strict + renorm num + denom + gate)
         + n_entities * 4 * 128                                    // gateFpByBit for renorm num
         + n_entities * (128 + 65536)                              // selectFp + final fpMul(num, recip)
         + n_entities * 20                                          // incl chains (AND + OR × 3 each)
         + 100000;                                                  // slack
}

static void test_strict_all_present() {
    std::printf("--- C1: STRICT — all 4 core present, weighted rank/(n-1) ---\n");
    oc::PRNG prng(oc::block(0xa1, 0xa2));

    // 3 entities, sector 1, all included in all 4 core metrics.
    // Ranks per metric: (0, 1, 2). n_valid=3 → denom=2. score=rank/2.
    // Weights 0.25 each → vuln = Σ 0.25·score = score.
    std::array<std::vector<SharedRankedRow>, kMetricCount> mr{};
    for (Metric mc : kVulnCoreMetrics) {
        size_t m = static_cast<size_t>(mc);
        for (uint32_t eid = 0; eid < 3; ++eid)
            mr[m].push_back(mkRankedRow(eid, 1, 1, eid, prng));
    }
    std::map<std::pair<uint32_t, Metric>, SharedU64Bin> n_valid_by_cell;
    for (Metric mc : kVulnCoreMetrics)
        n_valid_by_cell[{1, mc}] = shareU64Bin(2, 3, prng);

    size_t budget = budgetForEntities(3, 4);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto reciprocals = precomputeCellReciprocals(n_valid_by_cell,
                                                   1ULL << 20, triples, idx);
    CompositeWeightsWire weights;
    auto shared = computeCompositeTwoScoreWire(mr, reciprocals, weights,
                                                 triples, idx, prng);
    auto plain = reconstructComposites(shared);
    std::printf("  triples used: %zu / %zu\n", idx, budget);
    CHECK(plain.size() == 3, "C1: 3 rows");
    double expected[3] = {0.0, 0.5, 1.0};
    for (const auto& p : plain) {
        std::printf("  entity=%u incl_strict=%u vuln_strict=%.4f  incl_renorm=%u vuln_renorm=%.4f  avail=%u\n",
                     p.entity_idx, p.incl_strict, p.vuln_strict,
                     p.incl_renorm, p.vuln_renorm, p.avail_core);
        double want = expected[p.entity_idx];
        CHECK(p.incl_strict == 1, "C1: strict incl=1 for full coverage");
        CHECK(p.incl_renorm == 1, "C1: renorm incl=1");
        CHECK(std::abs(p.vuln_strict - want) < 5e-3,
              "C1: strict vuln matches expected");
        // With all 4 available, renorm should equal strict (same denominator 1.0).
        CHECK(std::abs(p.vuln_renorm - want) < 5e-3,
              "C1: renorm vuln = strict when all core available");
    }
}

static void test_strict_missing_dsi() {
    std::printf("--- C2: STRICT excluded when any core missing; RENORM emits ---\n");
    oc::PRNG prng(oc::block(0xb1, 0xb2));
    // Entity 0: DTI/Delq/NPL included with rank=1; DSI excluded.
    // n_valid = 2 → denom = 1 → recip = 1.
    // score = 1 per available metric.
    // renorm_num = 0.25 · 1 · 3 (three available) = 0.75
    // renorm_denom = 0.25 · 3 = 0.75
    // vuln_renorm = 1.0
    // vuln_strict is computed (contains contributions from all 4) but gated
    // out by incl_strict=0.
    std::array<std::vector<SharedRankedRow>, kMetricCount> mr{};
    mr[static_cast<size_t>(Metric::DTI)] .push_back(mkRankedRow(0, 1, 1, 1, prng));
    mr[static_cast<size_t>(Metric::DSI)] .push_back(mkRankedRow(0, 1, 0, 1, prng));
    mr[static_cast<size_t>(Metric::Delq)].push_back(mkRankedRow(0, 1, 1, 1, prng));
    mr[static_cast<size_t>(Metric::NPL)] .push_back(mkRankedRow(0, 1, 1, 1, prng));

    std::map<std::pair<uint32_t, Metric>, SharedU64Bin> n_valid_by_cell;
    for (Metric mc : kVulnCoreMetrics)
        n_valid_by_cell[{1, mc}] = shareU64Bin(2, 2, prng);

    size_t budget = budgetForEntities(1, 4);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto reciprocals = precomputeCellReciprocals(n_valid_by_cell,
                                                   1ULL << 20, triples, idx);
    CompositeWeightsWire weights;
    auto shared = computeCompositeTwoScoreWire(mr, reciprocals, weights,
                                                 triples, idx, prng);
    auto plain = reconstructComposites(shared);
    CHECK(plain.size() == 1, "C2: 1 row");
    std::printf("  entity=%u incl_strict=%u vuln_strict=%.4f incl_renorm=%u vuln_renorm=%.4f\n",
                 plain[0].entity_idx, plain[0].incl_strict, plain[0].vuln_strict,
                 plain[0].incl_renorm, plain[0].vuln_renorm);
    CHECK(plain[0].incl_strict == 0, "C2: DSI missing → incl_strict = 0");
    CHECK(plain[0].incl_renorm == 1, "C2: DSI missing but 3/4 avail → incl_renorm = 1");
    CHECK(std::abs(plain[0].vuln_renorm - 1.0) < 5e-3,
          "C2: renorm vuln = 1.0 with 3/4 core at rank 1");
    CHECK(plain[0].avail_core == 3, "C2: avail_core = 3");
}

static void test_no_core_available() {
    std::printf("--- C3: no core available → both incl = 0, renorm safe ---\n");
    oc::PRNG prng(oc::block(0xc1, 0xc2));
    // Entity 0: all 4 core excluded.
    std::array<std::vector<SharedRankedRow>, kMetricCount> mr{};
    for (Metric mc : kVulnCoreMetrics) {
        size_t m = static_cast<size_t>(mc);
        mr[m].push_back(mkRankedRow(0, 1, 0, 999, prng));
    }
    std::map<std::pair<uint32_t, Metric>, SharedU64Bin> n_valid_by_cell;
    for (Metric mc : kVulnCoreMetrics)
        n_valid_by_cell[{1, mc}] = shareU64Bin(2, 2, prng);

    size_t budget = budgetForEntities(1, 4);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto reciprocals = precomputeCellReciprocals(n_valid_by_cell,
                                                   1ULL << 20, triples, idx);
    CompositeWeightsWire weights;
    auto shared = computeCompositeTwoScoreWire(mr, reciprocals, weights,
                                                 triples, idx, prng);
    auto plain = reconstructComposites(shared);
    CHECK(plain[0].incl_strict == 0, "C3: no core → incl_strict = 0");
    CHECK(plain[0].incl_renorm == 0, "C3: no core → incl_renorm = 0");
    // Goldschmidt does NOT crash on empty denom thanks to safe-denom Select.
    // Result value is meaningless — consumer gates on incl_renorm.
}

static void test_renorm_asymmetric_ranks() {
    std::printf("--- C4: RENORM with asymmetric ranks per metric ---\n");
    oc::PRNG prng(oc::block(0xd1, 0xd2));
    // Entity 0, sector 1: DTI rank=2, DSI missing, Delq rank=1, NPL rank=0
    // n_valid = 3 per cell → denom = 2 → recip = 0.5.
    // scores: DTI=1.0, Delq=0.5, NPL=0.0 (DSI gated out).
    // renorm_num = 0.25·(1.0 + 0.5 + 0.0) = 0.375
    // renorm_denom = 0.25·3 = 0.75
    // vuln_renorm = 0.375 / 0.75 = 0.5
    std::array<std::vector<SharedRankedRow>, kMetricCount> mr{};
    mr[static_cast<size_t>(Metric::DTI)] .push_back(mkRankedRow(0, 1, 1, 2, prng));
    mr[static_cast<size_t>(Metric::DSI)] .push_back(mkRankedRow(0, 1, 0, 1, prng));
    mr[static_cast<size_t>(Metric::Delq)].push_back(mkRankedRow(0, 1, 1, 1, prng));
    mr[static_cast<size_t>(Metric::NPL)] .push_back(mkRankedRow(0, 1, 1, 0, prng));

    std::map<std::pair<uint32_t, Metric>, SharedU64Bin> n_valid_by_cell;
    for (Metric mc : kVulnCoreMetrics)
        n_valid_by_cell[{1, mc}] = shareU64Bin(2, 3, prng);

    size_t budget = budgetForEntities(1, 4);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto reciprocals = precomputeCellReciprocals(n_valid_by_cell,
                                                   1ULL << 20, triples, idx);
    CompositeWeightsWire weights;
    auto shared = computeCompositeTwoScoreWire(mr, reciprocals, weights,
                                                 triples, idx, prng);
    auto plain = reconstructComposites(shared);
    std::printf("  entity=%u vuln_renorm=%.4f (want 0.5) avail=%u\n",
                 plain[0].entity_idx, plain[0].vuln_renorm, plain[0].avail_core);
    CHECK(plain[0].incl_renorm == 1, "C4: 3/4 avail → incl_renorm = 1");
    CHECK(std::abs(plain[0].vuln_renorm - 0.5) < 5e-3,
          "C4: renorm = 0.375 / 0.75 = 0.5");
    CHECK(plain[0].avail_core == 3, "C4: avail_core = 3");
}

int main() {
    test_strict_all_present();
    test_strict_missing_dsi();
    test_no_core_available();
    test_renorm_asymmetric_ranks();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 9 MPC-wire (strict + renormalised) acceptance met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
