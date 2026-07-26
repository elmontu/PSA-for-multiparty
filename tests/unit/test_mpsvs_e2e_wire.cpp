// MPSVS end-to-end MPC-wire integration test.
//
// Chains: Phase 5 inclusion → Phase 11 aggregation → Phase 12.1 opening,
// all on 2-party (N=2) shares. Verifies:
//   (a) reconstructed release matches plaintext oracle
//   (b) each party's contribution alone does NOT reveal plaintext
//   (c) structural invariants (dummy row exclusion, valid-bit gating)
//
// The composite path (Phase 6 bucket + Phase 8 rank + Phase 9 composite +
// Phase 6 Goldschmidt) is exercised in test_mpsvs_composite_wire; here we
// focus on the aggregation-and-open chain which is the operational Rev 7
// release path.

#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpWire.h"
#include "volePSI/MpsvsInclusion.h"
#include "volePSI/MpsvsInclusionWire.h"
#include "volePSI/MpsvsOpenWire.h"
#include "volePSI/MpsvsSectorAgg.h"
#include "volePSI/MpsvsSectorAggWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <random>
#include <vector>

// Named indices into the release row's hist.counts vector (matches the
// packing order used when we construct SharedReleaseRow below).
namespace release_bin {
    constexpr size_t kSumNum  = 0;
    constexpr size_t kSumDen  = 1;
    constexpr size_t kNValid  = 2;
    constexpr size_t kCount   = 3;
}

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// ---------------------------------------------------------------------------
// Plaintext fixture builders
// ---------------------------------------------------------------------------

static UnionRow makePlainRow(uint16_t sector, uint32_t period,
                              uint64_t debt, uint64_t income, uint64_t emp,
                              uint8_t live) {
    UnionRow r{};
    r.bin = 0; r.period = period; r.sector = sector; r.sector_conflict = 0;
    r.live = live;
    r.b_MAS = 1; r.b_DOS = 1; r.b_MOM = 1;
    r.p_MAS.v[fields::MAS_debt]   = debt;    r.p_MAS.valid[fields::MAS_debt]  = 1;
    r.p_MAS.v[fields::MAS_dserv]  = debt/12; r.p_MAS.valid[fields::MAS_dserv] = 1;
    r.p_MAS.v[fields::MAS_delq]   = debt/50; r.p_MAS.valid[fields::MAS_delq]  = 1;
    r.p_MAS.v[fields::MAS_npl]    = debt/100;r.p_MAS.valid[fields::MAS_npl]   = 1;
    r.p_MAS.v[fields::MAS_unsec]  = debt/3;  r.p_MAS.valid[fields::MAS_unsec] = 1;
    r.p_MAS.v[fields::MAS_stdebt] = debt/4;  r.p_MAS.valid[fields::MAS_stdebt]= 1;
    r.p_MAS.g = 5000; r.p_MAS.v_g = 1;
    r.p_DOS.v[fields::DOS_income] = income;  r.p_DOS.valid[fields::DOS_income]= 1;
    r.p_DOS.g = 3000; r.p_DOS.v_g = 1;
    r.p_MOM.v[fields::MOM_emp]    = emp;     r.p_MOM.valid[fields::MOM_emp]   = 1;
    return r;
}

static RangeConfig makeRc() {
    RangeConfig rc;
    rc.income = {1, 10000000ULL};
    rc.debt   = {1, 100000000ULL};
    rc.emp    = {1, 100000};
    return rc;
}

// ---------------------------------------------------------------------------
// Test main
// ---------------------------------------------------------------------------

int main() {
    std::printf("=== MPSVS E2E MPC-wire integration test ===\n\n");

    oc::PRNG prng(oc::block(0xe2e, 0x1234));
    const uint32_t N = 2;

    // -----------------------------------------------------------------------
    // Fixture: 3 included entities in sector 1 + 1 dummy row.
    // -----------------------------------------------------------------------
    std::vector<UnionRow> plain;
    plain.push_back(makePlainRow(1, 202601, /*debt=*/30000, /*income=*/60000, /*emp=*/5, /*live=*/1));
    plain.push_back(makePlainRow(1, 202601, /*debt=*/50000, /*income=*/80000, /*emp=*/6, /*live=*/1));
    plain.push_back(makePlainRow(1, 202601, /*debt=*/70000, /*income=*/100000,/*emp=*/8, /*live=*/1));
    plain.push_back(makePlainRow(1, 202601, /*debt=*/999999,/*income=*/999999,/*emp=*/999,/*live=*/0));  // dummy

    // -----------------------------------------------------------------------
    // Plaintext oracle
    // -----------------------------------------------------------------------
    RangeConfig rc = makeRc();
    auto plain_entities = computeEntityMetrics(plain, rc, CoveragePolicy::STRICT_GATING);
    auto plain_hists    = aggregateHistograms(plain_entities, Metric::DTI,
                                                makeDefaultBucketEdges());
    auto plain_ratios   = aggregateRatios(plain_entities, Metric::DTI);

    // Oracle values derived from the plaintext computation — never hardcoded.
    uint64_t oracle_sum_num = plain_ratios[0].sum_num;
    uint64_t oracle_sum_den = plain_ratios[0].sum_den;
    uint64_t oracle_n_valid = 0;
    for (const auto& e : plain_entities) {
        if (e.metrics[static_cast<size_t>(Metric::DTI)].incl) ++oracle_n_valid;
    }
    std::printf("Plaintext oracle (derived):\n");
    std::printf("  sector=%u period=%u DTI sum_num=%lu sum_den=%lu n_valid=%lu\n\n",
                 plain_ratios[0].key.sector, plain_ratios[0].key.period,
                 oracle_sum_num, oracle_sum_den, oracle_n_valid);

    // -----------------------------------------------------------------------
    // Wire pipeline
    // -----------------------------------------------------------------------
    std::printf("=== Wire pipeline (N=2 parties) ===\n");

    // Share input.
    std::vector<SharedUnionRow> shared_in;
    for (const auto& u : plain) shared_in.push_back(shareUnionRow(N, u, prng));
    std::printf("Sharing: %zu UnionRows shared to %u parties.\n",
                 shared_in.size(), N);

    // Phase 5 wire — inclusion.
    size_t incl_budget = shared_in.size() * inclusionTripleBudgetPerRow();
    auto incl_triples = generateBeaverTripleBits(N, incl_budget, prng);
    auto shared_entities = computeEntityMetricsWireBatch(
        shared_in, rc, CoveragePolicy::STRICT_GATING, incl_triples);
    std::printf("Phase 5 (inclusion): %zu entity rows produced, %zu triples budget.\n",
                 shared_entities.size(), incl_budget);

    // Phase 11 wire — aggregation (DTI only).
    // FOLLOW-UP: aggregateHistogramsWire's (triples, tripleIndex) parameters
    // are historical — the current impl generates its own arithmetic Beaver
    // triples internally over Z_{2^64}. Either drop those params or use them
    // consistently. Tracked as a wire-API cleanup for a future refactor.
    std::vector<BeaverTripleBit> agg_bit_triples;   // intentionally empty per note above
    size_t agg_idx = 0;
    auto shared_hists = aggregateHistogramsWire(shared_entities, Metric::DTI,
                                                  agg_bit_triples, agg_idx, prng);
    std::printf("Phase 11 (aggregation): %zu cells produced.\n",
                 shared_hists.size());

    CHECK(shared_hists.size() == 1, "E2E: 1 cell (sector 1, period 202601)");
    if (shared_hists.empty()) return 1;   // guard downstream access

    // -----------------------------------------------------------------------
    // C1 — Reconstruct cell, compare to oracle
    // -----------------------------------------------------------------------
    std::printf("\n--- C1: reconstructed shared cell matches plaintext oracle ---\n");
    auto cell_recon = reconstructCell(shared_hists[0]);
    std::printf("  reconstructed: sum_num=%lu sum_den=%lu n_valid=%lu\n",
                 cell_recon.sum_num, cell_recon.sum_den, cell_recon.n_valid);
    CHECK(cell_recon.sum_num == oracle_sum_num, "C1: sum_num matches oracle");
    CHECK(cell_recon.sum_den == oracle_sum_den, "C1: sum_den matches oracle");
    CHECK(cell_recon.n_valid == oracle_n_valid, "C1: n_valid = 3 (dummy excluded)");
    CHECK(cell_recon.key.sector == 1,           "C1: sector = 1");
    CHECK(cell_recon.key.period == 202601,      "C1: period = 202601");

    // -----------------------------------------------------------------------
    // Phase 12.1 — assemble release + open via 2-party contribution
    // -----------------------------------------------------------------------
    std::printf("\n--- C2: Phase 12.1 open reconstructs release from party shares ---\n");

    // Phase 12 wire — jointly-generated DP noise on the shared histogram.
    // This makes hist.counts (noisy) DIVERGE from sum_num/sum_den (raw
    // aggregation), matching the production release-row shape where the
    // two fields have different provenance.
    std::mt19937_64 dp_rng1(0xdead), dp_rng2(0xbeef);
    auto noisy = addJointNoise(shared_hists[0], /*rho=*/0.1,
                                dp_rng1, dp_rng2, prng);
    std::printf("Phase 12 (DP noise): joint noise per bin = %ld, %ld, %ld\n",
                 noisy.joint_noise[0], noisy.joint_noise[1], noisy.joint_noise[2]);

    // Assemble release: hist.counts carries the NOISED bins, sum_num/den
    // carry the raw aggregation for ratio computation.
    std::vector<SharedReleaseRow> shared_release;
    {
        SharedReleaseRow row;
        row.key = shared_hists[0].key;
        row.metric = shared_hists[0].metric;
        row.hist.counts = noisy.bins_shared;   // divergent — post-DP-noise
        row.sum_num = shared_hists[0].sum_num;
        row.sum_den = shared_hists[0].sum_den;
        shared_release.push_back(row);
    }

    // Extract each party's contribution (this is what actually goes over wire).
    PartyContribution c0 = extractContribution(0, shared_release);
    PartyContribution c1 = extractContribution(1, shared_release);
    CHECK(c0.party_id == 0, "C2: party 0 contribution tagged");
    CHECK(c1.party_id == 1, "C2: party 1 contribution tagged");

    // GovTech combines both contributions to reconstruct the release.
    ReleaseBundle rel = combineContributions(shared_release, {c0, c1},
                                              /*rho=*/0.0, /*queries=*/1,
                                              /*protocol_rev=*/7);
    CHECK(rel.rows.size() == 1, "C2: 1 release row assembled");
    std::printf("  released row: sector=%u metric=%s n_valid_noisy=%lu\n",
                 rel.rows[0].key.sector, metricName(rel.rows[0].metric),
                 rel.rows[0].n_valid_noisy);
    const auto& hc = rel.rows[0].hist_clamped;
    CHECK(hc.size() == release_bin::kCount, "C2: 3 hist bins in release");
    // Post-DP hist bins = max(0, oracle + joint_noise).
    auto expected_noisy = [&](uint64_t oracle, int64_t noise) -> uint64_t {
        int64_t v = static_cast<int64_t>(oracle) + noise;
        return v < 0 ? 0 : static_cast<uint64_t>(v);
    };
    CHECK(hc[release_bin::kSumNum] == expected_noisy(oracle_sum_num, noisy.joint_noise[0]),
          "C2: hist[sum_num] = max(0, oracle + joint_noise)");
    CHECK(hc[release_bin::kSumDen] == expected_noisy(oracle_sum_den, noisy.joint_noise[1]),
          "C2: hist[sum_den] = max(0, oracle + joint_noise)");
    CHECK(hc[release_bin::kNValid] == expected_noisy(oracle_n_valid, noisy.joint_noise[2]),
          "C2: hist[n_valid] = max(0, oracle + joint_noise)");
    // Raw ratio-of-sums fields (in release.rows[0].ratio) reconstruct WITHOUT noise.
    double expected_ratio = static_cast<double>(oracle_sum_num) / oracle_sum_den;
    CHECK(std::abs(rel.rows[0].ratio - expected_ratio) < 1e-9,
          "C2: ratio-of-sums bypasses DP noise (comes from raw sum_num/sum_den)");
    CHECK(rel.protocol_rev == 7, "C2: protocol_rev = 7 in release");

    // -----------------------------------------------------------------------
    // C3 — Sanity check: no party's contribution accidentally equals plaintext.
    //
    // This is a WEAK sanity check, NOT a security proof. The actual secrecy
    // guarantee comes from the additive-share primitive (each party's share
    // is uniformly random over Z_{2^64}, information-theoretically hiding
    // the plaintext given only one share). This test only catches the
    // degenerate case where sharing accidentally leaked (e.g. if shareU64
    // returned (value, 0) instead of (r, value-r)). For a rigorous
    // statistical secrecy check see the entropy-based tests in
    // test_secret_share.cpp.
    // -----------------------------------------------------------------------
    std::printf("\n--- C3: sanity — no party's share accidentally matches plaintext ---\n");
    std::vector<uint64_t> oracle_flat = {oracle_sum_num, oracle_sum_den, oracle_n_valid,
                                           oracle_sum_num, oracle_sum_den};
    int c0_match = 0, c1_match = 0;
    for (size_t i = 0; i < oracle_flat.size(); ++i) {
        if (c0.flat_shares[i] == oracle_flat[i]) ++c0_match;
        if (c1.flat_shares[i] == oracle_flat[i]) ++c1_match;
    }
    std::printf("  party 0 shares matching oracle: %d / %zu\n", c0_match, oracle_flat.size());
    std::printf("  party 1 shares matching oracle: %d / %zu\n", c1_match, oracle_flat.size());
    CHECK(c0_match == 0, "C3: party 0's shares are uniformly random — never match plaintext");
    CHECK(c1_match == 0, "C3: party 1's shares uniformly random");

    // -----------------------------------------------------------------------
    // C4 — Dummy row (live=0) excluded from shared aggregation
    // -----------------------------------------------------------------------
    std::printf("\n--- C4: dummy row was gated out cryptographically ---\n");
    // If dummy had contributed, sum_num would equal the oracle sum PLUS
    // the dummy's raw debt value, and n_valid would be 4 (real+dummy).
    uint64_t dummy_debt   = plain.back().p_MAS.v[fields::MAS_debt];
    uint64_t would_be_num = oracle_sum_num + dummy_debt;
    CHECK(cell_recon.sum_num != would_be_num,       "C4: dummy debt not summed");
    CHECK(cell_recon.n_valid != plain.size(),       "C4: n_valid excludes dummy");

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    std::printf("\n=== Wire triple budget (Phase 5) / arith-triple usage (Phase 11) ===\n");
    std::printf("  Phase 5 (inclusion): %zu bit triples budget for %zu rows\n",
                 incl_budget, shared_in.size());
    // aggregateHistogramsWire allocates its own arithmetic Beaver triples
    // internally over Z_{2^64}. Per-row cost ≈ 131 arith triples per metric
    // × 9 metrics × #rows. The bit-triples parameter is preserved for
    // interface uniformity but unused; exposing the arith counter is future
    // API work (out of scope for this integration test).
    std::printf("  Phase 11 (aggregation): ≈%zu arith triples × 9 metrics × %zu rows\n",
                 static_cast<size_t>(131), shared_entities.size());

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — MPSVS E2E MPC-wire pipeline works end-to-end\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
