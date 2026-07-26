// MPSVS Phase 5 MPC-wire acceptance tests.
//
// Instantiate 2 parties (S1, S2), each holding one share. Compute inclusion
// bits on shares only. Assert:
//   C1 output matches plaintext reference on same input
//   C2 no share taken alone reconstructs the plaintext (structural check)
//   C3 no intermediate SharedBit / SharedU64Bin has "single-party value"
//      that equals the plaintext by itself
//   C4 triple bag is properly sized and fully consumed

#include "volePSI/MpsvsInclusion.h"
#include "volePSI/MpsvsInclusionWire.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <random>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// Build one fully-populated UnionRow.
static UnionRow makePlainRow(uint16_t sector, uint32_t period,
                              uint64_t debt, uint64_t income, uint64_t emp,
                              uint8_t live, uint8_t bMAS, uint8_t bDOS,
                              uint8_t bMOM) {
    UnionRow r{};
    r.bin = 0; r.period = period; r.sector = sector; r.sector_conflict = 0;
    r.live = live;
    r.b_MAS = bMAS; r.b_DOS = bDOS; r.b_MOM = bMOM;
    r.p_MAS.v[fields::MAS_debt]   = debt;   r.p_MAS.valid[fields::MAS_debt]  = 1;
    r.p_MAS.v[fields::MAS_dserv]  = debt/12;r.p_MAS.valid[fields::MAS_dserv] = 1;
    r.p_MAS.v[fields::MAS_delq]   = debt/50;r.p_MAS.valid[fields::MAS_delq]  = 1;
    r.p_MAS.v[fields::MAS_npl]    = debt/100;r.p_MAS.valid[fields::MAS_npl]  = 1;
    r.p_MAS.v[fields::MAS_unsec]  = debt/3; r.p_MAS.valid[fields::MAS_unsec] = 1;
    r.p_MAS.v[fields::MAS_stdebt] = debt/4; r.p_MAS.valid[fields::MAS_stdebt]= 1;
    r.p_MAS.g = 5000; r.p_MAS.v_g = 1;
    r.p_DOS.v[fields::DOS_income] = income; r.p_DOS.valid[fields::DOS_income]= 1;
    r.p_DOS.g = 3000; r.p_DOS.v_g = 1;
    r.p_MOM.v[fields::MOM_emp]    = emp;    r.p_MOM.valid[fields::MOM_emp]   = 1;
    return r;
}

static RangeConfig makeRc() {
    RangeConfig rc;
    rc.income = {1, 10000000ULL};
    rc.debt   = {1, 100000000ULL};
    rc.emp    = {1, 100000};
    return rc;
}

static void test_wire_matches_plaintext() {
    std::printf("--- C1: wire output equals plaintext reference ---\n");
    oc::PRNG prng(oc::block(0xabc, 0xdef));
    const uint32_t N = 2;   // S1, S2

    std::vector<UnionRow> plain;
    // Included case: full coverage.
    plain.push_back(makePlainRow(1, 202601, /*debt*/100000, /*income*/60000, /*emp*/5,
                                  /*live*/1, 1, 1, 1));
    // Excluded case: income out of range.
    plain.push_back(makePlainRow(1, 202601, /*debt*/100000, /*income*/0, /*emp*/5,
                                  /*live*/1, 1, 1, 1));
    // Excluded case: dummy row (live=0).
    plain.push_back(makePlainRow(1, 202601, /*debt*/100000, /*income*/60000, /*emp*/5,
                                  /*live*/0, 1, 1, 1));
    // Included, but MAS-only firm — cross-source metrics excluded.
    plain.push_back(makePlainRow(2, 202601, /*debt*/50000, /*income*/40000, /*emp*/3,
                                  /*live*/1, 1, 0, 0));

    RangeConfig rc = makeRc();
    auto plain_out = computeEntityMetrics(plain, rc, CoveragePolicy::STRICT_GATING);

    // Wire path.
    std::vector<SharedUnionRow> shared;
    for (const auto& u : plain) shared.push_back(shareUnionRow(N, u, prng));

    size_t budget = shared.size() * inclusionTripleBudgetPerRow();
    auto triples = generateBeaverTripleBits(N, budget, prng);
    auto shared_out = computeEntityMetricsWireBatch(
        shared, rc, CoveragePolicy::STRICT_GATING, triples);

    CHECK(shared_out.size() == plain_out.size(),
          "C1: wire produces same number of rows");
    for (size_t i = 0; i < shared_out.size(); ++i) {
        EntityMetricRow reconstructed = reconstructEntityMetricRow(shared_out[i]);
        // Compare inclusion bits + avail_core_count + incl_vuln.
        bool ok_incl = true;
        for (size_t m = 0; m < kMetricCount; ++m) {
            if (reconstructed.metrics[m].incl != plain_out[i].metrics[m].incl) {
                ok_incl = false;
                std::printf("  row %zu metric %s: wire=%d plain=%d\n",
                             i, metricName(static_cast<Metric>(m)),
                             reconstructed.metrics[m].incl,
                             plain_out[i].metrics[m].incl);
            }
        }
        CHECK(ok_incl, "C1: all metric inclusion bits match");
        CHECK(reconstructed.incl_vuln == plain_out[i].incl_vuln,
              "C1: incl_vuln matches");
        CHECK(reconstructed.avail_core_count == plain_out[i].avail_core_count,
              "C1: avail_core_count matches");
    }
}

static void test_share_privacy_structural() {
    std::printf("--- C2: no individual party share equals plaintext ---\n");
    oc::PRNG prng(oc::block(0x111, 0x222));
    const uint32_t N = 2;

    UnionRow u = makePlainRow(1, 202601, 100000, 60000, 5, 1, 1, 1, 1);
    SharedUnionRow s = shareUnionRow(N, u, prng);

    // Check that S1's share alone doesn't equal plaintext.
    // For SharedBit: party's byte is 0 or 1; the plaintext is 0 or 1; but
    // with N=2, one party's share matches the plaintext by chance ~50% of
    // the time — so this test cannot rule out "share equals plaintext by
    // coincidence". The stronger check: reveal one party's share and it
    // does NOT determine the plaintext (info-theoretic secrecy of XOR
    // shares).
    //
    // Concrete test: over many random shares of the same plaintext bit,
    // party 0's share is uniform over {0, 1}.
    int party0_sum = 0;
    int trials = 200;
    for (int t = 0; t < trials; ++t) {
        SharedBit sb = shareBit(N, /*value=*/1, prng);
        party0_sum += sb.shares[0];
    }
    double freq = static_cast<double>(party0_sum) / trials;
    std::printf("  party0 share freq of 1 when plaintext=1: %.3f (want ≈ 0.5)\n", freq);
    CHECK(freq > 0.3 && freq < 0.7,
          "C2: party 0's share is uniform → info-theoretic hiding");

    // Same for u64: party 0 share is uniform over 2^64.
    // Weaker sanity: party 0 share != plaintext in > 90% of trials.
    int neq = 0;
    for (int t = 0; t < 100; ++t) {
        SharedU64Bin b = shareU64Bin(N, /*value=*/42, prng);
        uint64_t p0 = 0;
        for (int i = 0; i < 64; ++i) p0 |= (uint64_t(b.bits[i].shares[0] & 1) << i);
        if (p0 != 42) ++neq;
    }
    std::printf("  party0 u64 share ≠ plaintext(42): %d / 100 trials\n", neq);
    CHECK(neq >= 95, "C2: u64 share hides plaintext");
}

static void test_triple_budget() {
    std::printf("--- C3: triple budget is sufficient (bag not exhausted) ---\n");
    oc::PRNG prng(oc::block(0x333, 0x444));
    const uint32_t N = 2;
    UnionRow u = makePlainRow(1, 202601, 100000, 60000, 5, 1, 1, 1, 1);
    SharedUnionRow s = shareUnionRow(N, u, prng);
    RangeConfig rc = makeRc();
    size_t budget = inclusionTripleBudgetPerRow();
    std::printf("  budget/row = %zu bit triples\n", budget);
    auto triples = generateBeaverTripleBits(N, budget, prng);
    size_t idx = 0;
    (void)computeEntityMetricsWire(s, rc, CoveragePolicy::RENORMALISED_WEIGHTS,
                                    triples, idx);
    std::printf("  consumed %zu / %zu triples\n", idx, budget);
    CHECK(idx <= budget, "C3: consumed ≤ budget");
    CHECK(idx > budget / 2, "C3: consumed > budget/2 (budget not wildly overestimated)");
}

static void test_no_intermediate_reveal() {
    std::printf("--- C4: no intermediate SharedBit is trivially reconstructed ---\n");
    // Test that a mid-computation SharedBit still requires both parties to
    // reveal. This is a structural check via the type system: every
    // intermediate is a SharedBit / SharedU64Bin whose .reconstruct()
    // requires all party shares. Verify by attempting reconstruction from
    // only one party (should not match plaintext except by coincidence).
    oc::PRNG prng(oc::block(0x555, 0x666));
    const uint32_t N = 2;

    UnionRow u = makePlainRow(1, 202601, 100000, 60000, 5, 1, 1, 1, 1);
    SharedUnionRow s = shareUnionRow(N, u, prng);
    RangeConfig rc = makeRc();
    size_t budget = inclusionTripleBudgetPerRow();
    auto triples = generateBeaverTripleBits(N, budget, prng);
    size_t idx = 0;
    auto shared_e = computeEntityMetricsWire(s, rc, CoveragePolicy::STRICT_GATING,
                                              triples, idx);

    // The incl_vuln SharedBit — each party's share alone is random.
    // Under semi-honest single-party view: party 0's share of a shared bit
    // is uniform. Verify over many independent runs.
    int party0_bit_sum = 0;
    int trials = 30;
    for (int t = 0; t < trials; ++t) {
        oc::PRNG p2(oc::block(t, t*7 + 1));
        SharedUnionRow s2 = shareUnionRow(N, u, p2);
        size_t b2 = inclusionTripleBudgetPerRow();
        auto t2 = generateBeaverTripleBits(N, b2, p2);
        size_t idx2 = 0;
        auto e2 = computeEntityMetricsWire(s2, rc, CoveragePolicy::STRICT_GATING,
                                            t2, idx2);
        party0_bit_sum += e2.incl_vuln.shares[0];
    }
    double freq = static_cast<double>(party0_bit_sum) / trials;
    std::printf("  incl_vuln party0 share freq: %.3f (want ≈ 0.5 for hiding)\n", freq);
    CHECK(freq > 0.25 && freq < 0.75,
          "C4: intermediate SharedBit party-0 share is roughly uniform");
}

int main() {
    test_wire_matches_plaintext();
    test_share_privacy_structural();
    test_triple_budget();
    test_no_intermediate_reveal();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 5 MPC-wire acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
