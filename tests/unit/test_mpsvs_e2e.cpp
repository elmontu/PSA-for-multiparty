// MPSVS Phase 15 end-to-end integration test.
//
// Composes Phases 1-12.1 on synthetic data:
//   Phase 4  → binned alignment (F_PSA)
//   Phase 5  → inclusion bits + entity metrics
//   Phase 11 → sector aggregation (histograms + ratio-of-sums)
//   Phase 12 → DP noise + R26 clamp
//   Phase 12.1 → assemble release for GovTech
//   Phase 13 → pipeline-level audit invariants

#include "volePSI/MpsvsAlignment.h"
#include "volePSI/MpsvsAudit.h"
#include "volePSI/MpsvsInclusion.h"
#include "volePSI/MpsvsOpen.h"
#include "volePSI/MpsvsRatioBucket.h"
#include "volePSI/MpsvsSectorAgg.h"
#include "volePSI/MpsvsDp.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <random>
#include <vector>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// ---------------------------------------------------------------------------
// Synthetic fixture — small realistic panel across 3 sectors × 2 periods.
// ---------------------------------------------------------------------------

static std::vector<Row> makeSourceRows(uint32_t source, size_t n,
                                        size_t start_id,
                                        std::mt19937_64& rng) {
    std::vector<Row> rows;
    std::uniform_int_distribution<uint64_t> debt_d(10000, 500000);
    std::uniform_int_distribution<uint64_t> income_d(30000, 200000);
    for (size_t i = 0; i < n; ++i) {
        Row r;
        r.bin = i % 16;                    // β=4 for the test → 16 bins
        r.source = source;
        r.key = start_id + i;              // canonical id
        r.memb = 1;
        r.period = 202601 + (i % 2);
        r.sector = 1 + (i % 3);            // sectors 1..3
        if (source == 0) {                 // MAS
            r.payload.v[fields::MAS_debt]  = debt_d(rng);
            r.payload.v[fields::MAS_dserv] = debt_d(rng) / 12;
            r.payload.v[fields::MAS_delq]  = debt_d(rng) / 50;
            r.payload.v[fields::MAS_npl]   = debt_d(rng) / 100;
            r.payload.v[fields::MAS_unsec] = debt_d(rng) / 3;
            r.payload.v[fields::MAS_stdebt]= debt_d(rng) / 4;
            for (auto& v : r.payload.valid) v = 1;
        } else if (source == 1) {          // DOS
            r.payload.v[fields::DOS_income] = income_d(rng);
            r.payload.valid[fields::DOS_income] = 1;
        } else {                            // MOM
            r.payload.v[fields::MOM_emp] = 1 + (i % 20);
            r.payload.valid[fields::MOM_emp] = 1;
        }
        rows.push_back(r);
    }
    return rows;
}

// Merge alignment output (UnionRow) into EntityMetricRow via Phase 5.
static std::vector<EntityMetricRow>
buildEntityMetrics(const std::vector<UnionRow>& union_rows) {
    RangeConfig rc;
    rc.income = {1, 10000000ULL};
    rc.debt   = {1, 100000000ULL};
    rc.emp    = {1, 100000};
    return computeEntityMetrics(union_rows, rc, CoveragePolicy::RENORMALISED_WEIGHTS);
}

static void test_e2e_pipeline() {
    std::printf("--- E2E: Phase 4 → 5 → 11 → 12 → 12.1 → 13 audit ---\n");

    std::mt19937_64 rng(2026);
    // Overlapping id ranges so a subset intersects across all 3 sources.
    auto mas = makeSourceRows(0, 40, 100, rng);
    auto dos = makeSourceRows(1, 40, 105, rng);   // 5-offset overlap
    auto mom = makeSourceRows(2, 40, 110, rng);   // 10-offset overlap

    BinParams params;
    params.beta = 4; params.tau_bits = 8; params.cap_P = 8;

    oc::PRNG prng(oc::block(0xdeadbeef, 0xf00d));
    auto align = runFPsa(mas, dos, mom, params, prng);
    CHECK(align.table.size() > 0, "E2E: F_PSA produced union table");
    CHECK(!align.restarted, "E2E: no restart (bins fit within cap_P)");

    auto entities = buildEntityMetrics(align.table);
    CHECK(entities.size() == align.table.size(),
          "E2E: entity metrics 1:1 with union rows");

    BucketEdges be = makeDefaultBucketEdges();
    auto agg = aggregateAllMetrics(entities, be);
    size_t dti_cells = agg.hists[static_cast<size_t>(Metric::DTI)].size();
    std::printf("  DTI cells produced: %zu\n", dti_cells);
    CHECK(dti_cells > 0, "E2E: sector aggregation produced cells");

    std::mt19937_64 dp_rng(9999);
    BudgetTracker budget;
    auto noisy = addNoiseToBundle(agg, /*rho_per_cell=*/0.1, dp_rng, budget);
    CHECK(budget.query_count > 0, "E2E: budget spent");

    auto release = assembleRelease(agg, noisy, budget);
    CHECK(release.rows.size() > 0, "E2E: release rows produced");

    // Phase 13 consolidated audit
    auto audit = runPipelineAudit(align, entities, agg, noisy, budget, release);
    std::printf("\n%s\n\n", audit.summary.c_str());
    CHECK(audit.overall_pass, "E2E: consolidated audit PASS");
}

static void test_malicious_upgrade_gaps() {
    std::printf("--- Phase 17: malicious-upgrade gap register present ---\n");
    CHECK(kMaliciousUpgradeGapsCount > 0, "P17: at least one gap listed");
    for (size_t i = 0; i < kMaliciousUpgradeGapsCount; ++i) {
        std::printf("  [%zu] %s → %s (%s)\n", i,
                    kMaliciousUpgradeGaps[i].primitive,
                    kMaliciousUpgradeGaps[i].required_proof,
                    kMaliciousUpgradeGaps[i].rev7_section);
    }
    CHECK(kMaliciousUpgradeGapsCount >= 6, "P17: full primitive set covered");
}

int main() {
    test_e2e_pipeline();
    test_malicious_upgrade_gaps();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 13-17 acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
