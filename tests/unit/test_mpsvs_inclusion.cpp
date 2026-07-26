// Phase 5 acceptance-criteria tests: inclusion masks + entity-level metrics.
// Per docs/DEPLOYMENT_FULL_MPC.md Phase 5 + Protocol §7.

#include "volePSI/MpsvsInclusion.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace volePSI::mpsvs;

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// Build a UnionRow representing an entity present at all three sources with
// specific validity + values. Defaults: all valid.
static UnionRow makeUnionRow(uint8_t live,
                             uint8_t b_MAS, uint8_t b_DOS, uint8_t b_MOM,
                             uint64_t debt = 100'000'00, uint64_t income = 500'000'00,
                             uint64_t emp = 100, uint64_t delq = 10'000'00,
                             uint64_t npl = 5'000'00) {
    UnionRow u{};
    u.live = live;
    u.b_MAS = b_MAS; u.b_DOS = b_DOS; u.b_MOM = b_MOM;
    u.canonical = 1;
    u.period = 20263;
    u.sector = 1;
    // MAS payload
    u.p_MAS.v[fields::MAS_debt] = debt;    u.p_MAS.valid[fields::MAS_debt] = 1;
    u.p_MAS.v[fields::MAS_dserv] = 20'000'00;  u.p_MAS.valid[fields::MAS_dserv] = 1;
    u.p_MAS.v[fields::MAS_delq]  = delq;    u.p_MAS.valid[fields::MAS_delq] = 1;
    u.p_MAS.v[fields::MAS_npl]   = npl;     u.p_MAS.valid[fields::MAS_npl] = 1;
    u.p_MAS.v[fields::MAS_unsec] = 30'000'00; u.p_MAS.valid[fields::MAS_unsec] = 1;
    u.p_MAS.v[fields::MAS_stdebt]= 40'000'00; u.p_MAS.valid[fields::MAS_stdebt] = 1;
    u.p_MAS.g = 100; u.p_MAS.v_g = 1;
    // DOS payload
    u.p_DOS.v[fields::DOS_income] = income; u.p_DOS.valid[fields::DOS_income] = 1;
    u.p_DOS.g = 50; u.p_DOS.v_g = 1;
    // MOM payload
    u.p_MOM.v[fields::MOM_emp] = emp; u.p_MOM.valid[fields::MOM_emp] = 1;
    return u;
}

// ---------------------------------------------------------------------------
// C1: For every ratio, per-entity inclusion bit is produced (all metrics).
// ---------------------------------------------------------------------------

static void test_all_ratios_have_inclusion() {
    UnionRow u = makeUnionRow(1, 1, 1, 1);
    std::vector<UnionRow> rows = {u};
    RangeConfig rc;
    auto out = computeEntityMetrics(rows, rc, CoveragePolicy::STRICT_GATING);
    CHECK(out.size() == 1, "C1: output has one entity row");
    const auto& e = out[0];
    // With a K-way live entity + all-valid + all-in-range → every metric incl=1.
    for (size_t i = 0; i < kMetricCount; ++i) {
        CHECK(e.metrics[i].incl == 1,
              (std::string("C1: metric ") + metricName(static_cast<Metric>(i))
               + " has incl=1 for fully-covered entity").c_str());
    }
}

// ---------------------------------------------------------------------------
// C2: Missing value (validity_bit = 0) → excludes ratio; NOT zero-substituted.
// ---------------------------------------------------------------------------

static void test_missing_excludes_not_substitutes() {
    UnionRow u = makeUnionRow(1, 1, 1, 1);
    // Set income validity=0 (missing) but keep the value non-zero.
    u.p_DOS.valid[fields::DOS_income] = 0;
    RangeConfig rc;
    auto out = computeEntityMetrics({u}, rc, CoveragePolicy::STRICT_GATING);
    const auto& e = out[0];
    // Metrics that depend on income should exclude: DTI, DSI, IPW.
    CHECK(e.metrics[static_cast<size_t>(Metric::DTI)].incl == 0,
          "C2: missing income → DTI excluded");
    CHECK(e.metrics[static_cast<size_t>(Metric::DSI)].incl == 0,
          "C2: missing income → DSI excluded");
    CHECK(e.metrics[static_cast<size_t>(Metric::IPW)].incl == 0,
          "C2: missing income → IPW excluded");
    // But the raw stored value is UNCHANGED (not zeroed) — invariant that the
    // pair carries num/den as observed, gated by the bit.
    CHECK(e.metrics[static_cast<size_t>(Metric::DTI)].den == 500'000'00,
          "C2: (num, den) still carries raw value; bit gates use (not zero-substituted)");
    // Metrics that don't depend on income should still be included.
    CHECK(e.metrics[static_cast<size_t>(Metric::Delq)].incl == 1,
          "C2: Delq unaffected (doesn't depend on income)");
    CHECK(e.metrics[static_cast<size_t>(Metric::NPL)].incl == 1,
          "C2: NPL unaffected");
    CHECK(e.metrics[static_cast<size_t>(Metric::DEmp)].incl == 1,
          "C2: DEmp unaffected");
}

// ---------------------------------------------------------------------------
// C3: Out-of-range denominator → excludes ratio; NOT zero-substituted.
// ---------------------------------------------------------------------------

static void test_out_of_range_excludes() {
    UnionRow u = makeUnionRow(1, 1, 1, 1);
    // Income = 0 (below range min_incl=1)
    u.p_DOS.v[fields::DOS_income] = 0;
    RangeConfig rc;
    auto out = computeEntityMetrics({u}, rc, CoveragePolicy::STRICT_GATING);
    const auto& e = out[0];
    // Income = 0 fails income range check → DTI, DSI excluded (denominator=income).
    // IPW's denominator is EMP not income, so IPW is NOT excluded by income=0
    // — a firm with zero income has IPW = 0/emp = 0, a legitimate value.
    CHECK(e.metrics[static_cast<size_t>(Metric::DTI)].incl == 0,
          "C3: income=0 → DTI excluded (income out of range, DTI's denominator)");
    CHECK(e.metrics[static_cast<size_t>(Metric::DSI)].incl == 0,
          "C3: income=0 → DSI excluded (income out of range)");
    CHECK(e.metrics[static_cast<size_t>(Metric::IPW)].incl == 1,
          "C3: income=0 → IPW STILL INCLUDED (its denominator is emp, not income)");
    // Test very large value beyond max_incl.
    u.p_DOS.v[fields::DOS_income] = 200'000'000'000'000'000ULL;  // > max 100T cents
    auto out2 = computeEntityMetrics({u}, rc, CoveragePolicy::STRICT_GATING);
    CHECK(out2[0].metrics[static_cast<size_t>(Metric::DTI)].incl == 0,
          "C3: income > max → DTI excluded");
}

// ---------------------------------------------------------------------------
// C4: Dummies (live=0) → all inclusion bits = 0.
// ---------------------------------------------------------------------------

static void test_dummies_all_excluded() {
    UnionRow u = makeUnionRow(0, 0, 0, 0);   // dead
    RangeConfig rc;
    auto out = computeEntityMetrics({u}, rc, CoveragePolicy::STRICT_GATING);
    for (size_t i = 0; i < kMetricCount; ++i) {
        CHECK(out[0].metrics[i].incl == 0,
              (std::string("C4: dummy row → metric ") + metricName(static_cast<Metric>(i))
               + " incl=0").c_str());
    }
    CHECK(out[0].incl_vuln == 0, "C4: dummy row → incl_vuln = 0");
}

// ---------------------------------------------------------------------------
// C5: MAS-only entity (no DOS/MOM) — MAS-alone metrics included,
//     cross-source metrics excluded.
// ---------------------------------------------------------------------------

static void test_mas_only_partial_metrics() {
    UnionRow u = makeUnionRow(1, 1, 0, 0);
    RangeConfig rc;
    auto out = computeEntityMetrics({u}, rc, CoveragePolicy::STRICT_GATING);
    const auto& e = out[0];
    // MAS-alone metrics: Delq, NPL, UnsecShare, StDebtShare all included.
    CHECK(e.metrics[static_cast<size_t>(Metric::Delq)].incl == 1,
          "C5: MAS-only → Delq included");
    CHECK(e.metrics[static_cast<size_t>(Metric::NPL)].incl == 1,
          "C5: MAS-only → NPL included");
    CHECK(e.metrics[static_cast<size_t>(Metric::UnsecShare)].incl == 1,
          "C5: MAS-only → UnsecShare included");
    // Cross-source metrics: DTI, DSI, DEmp, IPW, Gap all excluded.
    CHECK(e.metrics[static_cast<size_t>(Metric::DTI)].incl == 0,
          "C5: MAS-only → DTI excluded (needs DOS)");
    CHECK(e.metrics[static_cast<size_t>(Metric::DSI)].incl == 0,
          "C5: MAS-only → DSI excluded");
    CHECK(e.metrics[static_cast<size_t>(Metric::DEmp)].incl == 0,
          "C5: MAS-only → DEmp excluded (needs MOM)");
    CHECK(e.metrics[static_cast<size_t>(Metric::IPW)].incl == 0,
          "C5: MAS-only → IPW excluded (needs DOS+MOM)");
    CHECK(e.metrics[static_cast<size_t>(Metric::Gap)].incl == 0,
          "C5: MAS-only → Gap excluded (needs DOS growth)");
}

// ---------------------------------------------------------------------------
// C6: Downstream sum matches count of incl=1 (not count of members).
// ---------------------------------------------------------------------------

static void test_aggregate_gates_on_inclusion() {
    // 3 entities: two K-way live with all valid, one live but missing income.
    UnionRow u1 = makeUnionRow(1, 1, 1, 1);
    UnionRow u2 = makeUnionRow(1, 1, 1, 1);
    UnionRow u3 = makeUnionRow(1, 1, 1, 1);
    u3.p_DOS.valid[fields::DOS_income] = 0;   // missing income
    // Two dummies live=0.
    UnionRow d1 = makeUnionRow(0, 0, 0, 0);
    UnionRow d2 = makeUnionRow(0, 0, 0, 0);

    std::vector<UnionRow> rows = {u1, u2, u3, d1, d2};
    auto ents = computeEntityMetrics(rows, RangeConfig{}, CoveragePolicy::STRICT_GATING);
    auto agg = aggregateOverAll(ents);
    // DTI: only u1, u2 included (u3 excluded due to missing income; dummies not live).
    CHECK(agg[static_cast<size_t>(Metric::DTI)].n_valid == 2,
          "C6: DTI aggregate counts only the 2 fully-covered entities");
    CHECK(agg[static_cast<size_t>(Metric::DTI)].sum_num == 2 * 100'000'00,
          "C6: DTI sum_num = 2 × debt (bit-gated)");
    CHECK(agg[static_cast<size_t>(Metric::DTI)].sum_den == 2 * 500'000'00,
          "C6: DTI sum_den = 2 × income (bit-gated)");
    // Delq: all 3 live entities included (independent of income).
    CHECK(agg[static_cast<size_t>(Metric::Delq)].n_valid == 3,
          "C6: Delq aggregate counts all 3 live entities");
}

// ---------------------------------------------------------------------------
// C7: Vuln coverage policy — STRICT vs RENORMALISED.
// ---------------------------------------------------------------------------

static void test_vuln_coverage_policy() {
    // Entity covered on Delq + NPL but not on DTI (missing income).
    UnionRow u = makeUnionRow(1, 1, 1, 1);
    u.p_DOS.valid[fields::DOS_income] = 0;
    // With STRICT_GATING (need all 4 core: DTI, DSI, Delq, NPL):
    auto strict = computeEntityMetrics({u}, RangeConfig{}, CoveragePolicy::STRICT_GATING);
    CHECK(strict[0].avail_core_count == 2,   // Delq + NPL
          "C7 strict: avail_core_count = 2 (Delq + NPL only)");
    CHECK(strict[0].incl_vuln == 0,
          "C7 strict: vuln excluded (needs all 4 core available)");
    // With RENORMALISED_WEIGHTS (any core available):
    auto renorm = computeEntityMetrics({u}, RangeConfig{}, CoveragePolicy::RENORMALISED_WEIGHTS);
    CHECK(renorm[0].avail_core_count == 2,
          "C7 renorm: avail_core_count = 2");
    CHECK(renorm[0].incl_vuln == 1,
          "C7 renorm: vuln included (at least one core available)");
}

// ---------------------------------------------------------------------------
// C8: Gap metric — signed encoding for growth difference.
// ---------------------------------------------------------------------------

static void test_gap_signed() {
    UnionRow u = makeUnionRow(1, 1, 1, 1);
    // g_debt = 100, g_income = 50 → gap = +50
    u.p_MAS.g = 100; u.p_MAS.v_g = 1;
    u.p_DOS.g = 50;  u.p_DOS.v_g = 1;
    auto out = computeEntityMetrics({u}, RangeConfig{}, CoveragePolicy::STRICT_GATING);
    const auto& e = out[0];
    int64_t gap = 0;
    std::memcpy(&gap, &e.metrics[static_cast<size_t>(Metric::Gap)].num, sizeof(gap));
    CHECK(gap == 50, "C8: gap = g_debt(100) − g_income(50) = +50");
    CHECK(e.metrics[static_cast<size_t>(Metric::Gap)].incl == 1,
          "C8: gap included with both growth-validity bits");

    // Reverse: g_debt < g_income → negative gap
    u.p_MAS.g = 30; u.p_DOS.g = 80;
    auto out2 = computeEntityMetrics({u}, RangeConfig{}, CoveragePolicy::STRICT_GATING);
    int64_t gap2 = 0;
    std::memcpy(&gap2, &out2[0].metrics[static_cast<size_t>(Metric::Gap)].num, sizeof(gap2));
    CHECK(gap2 == -50, "C8: gap signed can be negative (30 − 80 = −50)");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    if (sodium_init() < 0) { std::printf("FATAL: libsodium init failed\n"); return 2; }
    std::puts("=== MpsvsInclusion — Phase 5 acceptance-criteria tests ===\n");
    test_all_ratios_have_inclusion();       std::puts("");
    test_missing_excludes_not_substitutes();std::puts("");
    test_out_of_range_excludes();           std::puts("");
    test_dummies_all_excluded();            std::puts("");
    test_mas_only_partial_metrics();        std::puts("");
    test_aggregate_gates_on_inclusion();    std::puts("");
    test_vuln_coverage_policy();            std::puts("");
    test_gap_signed();
    std::puts("");
    if (failures) { std::printf("== %d FAILURES ==\n", failures); return 1; }
    std::puts("ALL PASSED — Phase 5 acceptance criteria met");
    return 0;
}
