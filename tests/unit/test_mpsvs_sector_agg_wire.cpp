// MPSVS Phase 11 MPC-wire acceptance tests — additive share aggregation.

#include "volePSI/MpsvsInclusion.h"
#include "volePSI/MpsvsInclusionWire.h"
#include "volePSI/MpsvsSectorAgg.h"
#include "volePSI/MpsvsSectorAggWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static UnionRow makePlainRow(uint16_t sector, uint32_t period,
                              uint64_t debt, uint64_t income, uint64_t emp,
                              uint8_t live) {
    UnionRow r{};
    r.bin = 0; r.period = period; r.sector = sector;
    r.live = live;
    r.b_MAS = 1; r.b_DOS = 1; r.b_MOM = 1;
    r.p_MAS.v[fields::MAS_debt]   = debt;   r.p_MAS.valid[fields::MAS_debt] = 1;
    r.p_MAS.v[fields::MAS_dserv]  = debt/12;r.p_MAS.valid[fields::MAS_dserv]= 1;
    r.p_MAS.v[fields::MAS_delq]   = debt/50;r.p_MAS.valid[fields::MAS_delq] = 1;
    r.p_MAS.v[fields::MAS_npl]    = debt/100;r.p_MAS.valid[fields::MAS_npl] = 1;
    r.p_MAS.v[fields::MAS_unsec]  = debt/3; r.p_MAS.valid[fields::MAS_unsec]= 1;
    r.p_MAS.v[fields::MAS_stdebt] = debt/4; r.p_MAS.valid[fields::MAS_stdebt]= 1;
    r.p_MAS.g = 5000; r.p_MAS.v_g = 1;
    r.p_DOS.v[fields::DOS_income] = income; r.p_DOS.valid[fields::DOS_income]= 1;
    r.p_DOS.g = 3000; r.p_DOS.v_g = 1;
    r.p_MOM.v[fields::MOM_emp]    = emp;    r.p_MOM.valid[fields::MOM_emp]  = 1;
    return r;
}

static RangeConfig makeRc() {
    RangeConfig rc;
    rc.income = {1, 10000000ULL};
    rc.debt   = {1, 100000000ULL};
    rc.emp    = {1, 100000};
    return rc;
}

static void test_wire_agg_matches_plaintext() {
    std::printf("--- C1: wire aggregation reconstructs to plaintext totals ---\n");
    oc::PRNG prng(oc::block(0x7, 0x11));
    const uint32_t N = 2;

    std::vector<UnionRow> plain;
    // Sector 1, 3 rows: DTI num = 30k, 50k, 70k; den = 60k, 60k, 60k → sums = 150k / 180k
    plain.push_back(makePlainRow(1, 202601, 30000, 60000, 5, 1));
    plain.push_back(makePlainRow(1, 202601, 50000, 60000, 5, 1));
    plain.push_back(makePlainRow(1, 202601, 70000, 60000, 5, 1));
    // Sector 2, 2 rows: 40k, 60k
    plain.push_back(makePlainRow(2, 202601, 40000, 80000, 4, 1));
    plain.push_back(makePlainRow(2, 202601, 60000, 80000, 4, 1));
    // Dummy row (live=0): should NOT contribute.
    plain.push_back(makePlainRow(1, 202601, 999999, 999999, 999, 0));

    RangeConfig rc = makeRc();

    // Plaintext reference
    auto plain_entities = computeEntityMetrics(plain, rc, CoveragePolicy::STRICT_GATING);
    auto plain_hists = aggregateHistograms(plain_entities, Metric::DTI, makeDefaultBucketEdges());
    auto plain_ratios = aggregateRatios(plain_entities, Metric::DTI);

    // Wire path
    std::vector<SharedUnionRow> shared_in;
    for (const auto& u : plain) shared_in.push_back(shareUnionRow(N, u, prng));

    size_t incl_budget = shared_in.size() * inclusionTripleBudgetPerRow();
    auto incl_triples = generateBeaverTripleBits(N, incl_budget, prng);
    auto shared_entities = computeEntityMetricsWireBatch(
        shared_in, rc, CoveragePolicy::STRICT_GATING, incl_triples);

    size_t agg_budget = shared_in.size() * sectorAggTripleBudgetPerRow();
    auto agg_triples = generateBeaverTripleBits(N, agg_budget, prng);
    size_t idx = 0;
    auto shared_hists = aggregateHistogramsWire(shared_entities, Metric::DTI,
                                                 agg_triples, idx, prng);

    CHECK(shared_hists.size() == 2, "C1: 2 cells (sector 1, sector 2)");
    // Reconstruct and compare against plaintext ratio-of-sums
    for (const auto& sh : shared_hists) {
        auto p = reconstructCell(sh);
        std::printf("  cell (sector=%u, period=%u): sum_num=%lu, sum_den=%lu, n_valid=%lu\n",
                    p.key.sector, p.key.period, p.sum_num, p.sum_den, p.n_valid);
        for (const auto& pr : plain_ratios) {
            if (pr.key == p.key) {
                CHECK(p.sum_num == pr.sum_num,
                      "C1: wire sum_num matches plaintext ratio-of-sums");
                CHECK(p.sum_den == pr.sum_den,
                      "C1: wire sum_den matches plaintext");
            }
        }
        // n_valid is not in the plaintext ratios struct; check by counting.
        // sector 1: 3 included; sector 2: 2 included.
        uint64_t expected_n = (p.key.sector == 1) ? 3 : 2;
        CHECK(p.n_valid == expected_n, "C1: wire n_valid correct");
    }
}

static void test_dummy_row_gated_out() {
    std::printf("--- C2: dummy row (live=0) contributes 0 to sums ---\n");
    oc::PRNG prng(oc::block(0xa, 0xb));
    const uint32_t N = 2;

    std::vector<UnionRow> plain;
    plain.push_back(makePlainRow(1, 202601, 100000, 60000, 5, 1));   // included
    plain.push_back(makePlainRow(1, 202601, 999999, 999999, 999, 0)); // dummy — should contribute 0

    RangeConfig rc = makeRc();
    std::vector<SharedUnionRow> shared_in;
    for (const auto& u : plain) shared_in.push_back(shareUnionRow(N, u, prng));

    size_t incl_budget = shared_in.size() * inclusionTripleBudgetPerRow();
    auto incl_triples = generateBeaverTripleBits(N, incl_budget, prng);
    auto shared_entities = computeEntityMetricsWireBatch(
        shared_in, rc, CoveragePolicy::STRICT_GATING, incl_triples);

    size_t agg_budget = shared_in.size() * sectorAggTripleBudgetPerRow();
    auto agg_triples = generateBeaverTripleBits(N, agg_budget, prng);
    size_t idx = 0;
    auto shared_hists = aggregateHistogramsWire(shared_entities, Metric::DTI,
                                                 agg_triples, idx, prng);
    CHECK(shared_hists.size() == 1, "C2: 1 cell");
    auto p = reconstructCell(shared_hists[0]);
    // sum_num should equal only the included row: 100000
    // sum_den should equal only the included row's denom: 60000
    // n_valid should equal 1
    std::printf("  reconstructed: sum_num=%lu (want 100000), sum_den=%lu (want 60000), n_valid=%lu (want 1)\n",
                p.sum_num, p.sum_den, p.n_valid);
    CHECK(p.sum_num == 100000, "C2: dummy row does not contribute to sum_num");
    CHECK(p.sum_den == 60000, "C2: dummy row does not contribute to sum_den");
    CHECK(p.n_valid == 1, "C2: n_valid excludes dummy");
}

int main() {
    test_wire_agg_matches_plaintext();
    test_dummy_row_gated_out();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 11 MPC-wire acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
