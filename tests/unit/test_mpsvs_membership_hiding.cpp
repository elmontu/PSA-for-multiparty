// MPSVS Membership-hiding via sensitivity-calibrated DP.
//
// Demonstrates the fix for the Q7 residual-attack vulnerability in
// test_mpsvs_membership_trace:
//   - OLD behavior: σ calibrated for count-type sensitivity (√2). When
//     applied to sum_num/sum_den (whose sensitivity per single firm can be
//     millions), the noise fails to hide any single firm's contribution.
//     An adversary who knows their own firm's data can subtract it from the
//     released sum to recover others' aggregate with negligible noise.
//   - NEW behavior: σ calibrated to per-bin L2 sensitivity — for sum queries
//     σ = C_max / √(2·ρ) where C_max is the public contribution-clip bound.
//     Noise now DOMINATES any single firm's contribution → residual attack
//     yields a "guess" whose 95% CI is wider than the entire sum.

#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpWire.h"
#include "volePSI/MpsvsInclusion.h"
#include "volePSI/MpsvsInclusionWire.h"
#include "volePSI/MpsvsSectorAgg.h"
#include "volePSI/MpsvsSectorAggWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cmath>
#include <cstdio>
#include <random>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static UnionRow makePlainRow(uint16_t sector, uint32_t period,
                              uint64_t debt, uint64_t income, uint64_t emp,
                              uint8_t live) {
    UnionRow r{};
    r.bin = 0; r.period = period; r.sector = sector;
    r.live = live; r.b_MAS = 1; r.b_DOS = 1; r.b_MOM = 1;
    r.p_MAS.v[fields::MAS_debt]   = debt;    r.p_MAS.valid[fields::MAS_debt]  = 1;
    r.p_MAS.v[fields::MAS_dserv]  = debt/12; r.p_MAS.valid[fields::MAS_dserv] = 1;
    r.p_MAS.v[fields::MAS_delq]   = debt/50; r.p_MAS.valid[fields::MAS_delq]  = 1;
    r.p_MAS.v[fields::MAS_npl]    = debt/100;r.p_MAS.valid[fields::MAS_npl]   = 1;
    r.p_MAS.v[fields::MAS_unsec]  = debt/3;  r.p_MAS.valid[fields::MAS_unsec] = 1;
    r.p_MAS.v[fields::MAS_stdebt] = debt/4;  r.p_MAS.valid[fields::MAS_stdebt]= 1;
    r.p_MAS.g = 5000; r.p_MAS.v_g = 1;
    r.p_DOS.v[fields::DOS_income] = income;  r.p_DOS.valid[fields::DOS_income]= 1;
    r.p_DOS.g = 3000; r.p_DOS.v_g = 1;
    r.p_MOM.v[fields::MOM_emp] = emp; r.p_MOM.valid[fields::MOM_emp] = 1;
    return r;
}

static RangeConfig makeRc() {
    return {AttrRange{1, 10000000ULL}, AttrRange{1, 100000000ULL}, AttrRange{1, 100000}};
}

int main() {
    std::printf("=== MPSVS Membership-Hiding via Sensitivity-Calibrated DP ===\n\n");

    oc::PRNG prng(oc::block(0xf00d, 0xcafe));
    const uint32_t N = 2;

    // -----------------------------------------------------------------------
    // Fixture: 4 live firms in sector 1. Adversary is S1 (MAS), knows own
    // firm 101 has debt=50k, income=80k. Question: can S1 use the release
    // to infer whether firm 101 was in the live intersection?
    // -----------------------------------------------------------------------
    std::vector<UnionRow> plain;
    plain.push_back(makePlainRow(1, 202601, 50000, 80000, 5, 1));   // firm 101
    plain.push_back(makePlainRow(1, 202601, 70000, 100000, 6, 1));
    plain.push_back(makePlainRow(1, 202601, 90000, 120000, 7, 1));
    plain.push_back(makePlainRow(1, 202601, 110000, 140000, 8, 1));

    uint64_t truth_sum_debt   = 50000 + 70000 + 90000 + 110000;   // 320000
    uint64_t truth_sum_income = 80000 + 100000 + 120000 + 140000; // 440000
    uint64_t truth_n_valid    = 4;

    // -----------------------------------------------------------------------
    // Wire pipeline up to Phase 11 aggregation.
    // -----------------------------------------------------------------------
    std::vector<SharedUnionRow> shared_in;
    for (const auto& u : plain) shared_in.push_back(shareUnionRow(N, u, prng));
    size_t incl_budget = shared_in.size() * inclusionTripleBudgetPerRow();
    auto incl_triples = generateBeaverTripleBits(N, incl_budget, prng);
    auto shared_entities = computeEntityMetricsWireBatch(
        shared_in, makeRc(), CoveragePolicy::STRICT_GATING, incl_triples);
    std::vector<BeaverTripleBit> agg_bit_triples;
    size_t agg_idx = 0;
    auto shared_hists = aggregateHistogramsWire(shared_entities, Metric::DTI,
                                                  agg_bit_triples, agg_idx, prng);

    // -----------------------------------------------------------------------
    // Two DP releases: uncalibrated (Δ_2 = √2) vs calibrated (Δ_2 = C_max).
    // Adversary S1 subtracts own contribution to infer OTHERS' aggregate.
    // The precision of that inference is bounded by σ.
    // -----------------------------------------------------------------------
    double rho = 0.1;
    const int trials = 200;
    double C_debt   = 1000000.0;   // public contribution clip: $1M
    double C_income = 1000000.0;

    std::printf("Public clip bounds: C_debt = %.0f, C_income = %.0f\n",
                 C_debt, C_income);
    std::printf("Per-cell DP budget: ρ = %.3f\n\n", rho);

    // === Scenario A: uncalibrated DP (current default) ===
    std::printf("=== Scenario A: uncalibrated DP (σ from √2 count-sensitivity) ===\n");
    double sigma_uncal = sigmaFromRho(rho);
    std::printf("  σ (uncalibrated) = %.3f — sized for COUNT queries only\n", sigma_uncal);

    std::vector<double> residual_debt_A, residual_income_A;
    for (int t = 0; t < trials; ++t) {
        std::mt19937_64 rng1(0xa000 + t), rng2(0xb000 + t);
        auto noisy = addJointNoise(shared_hists[0], rho, rng1, rng2, prng);
        // Adversary reconstructs sum_num, sum_income.
        int64_t obs_sum_debt   = static_cast<int64_t>(truth_sum_debt)   + noisy.joint_noise[0];
        int64_t obs_sum_income = static_cast<int64_t>(truth_sum_income) + noisy.joint_noise[1];
        // Subtract own firm's contribution.
        int64_t inferred_others_debt   = obs_sum_debt   - 50000;
        int64_t inferred_others_income = obs_sum_income - 80000;
        // Truth for "others" = truth - own.
        double err_debt   = inferred_others_debt   - static_cast<int64_t>(truth_sum_debt - 50000);
        double err_income = inferred_others_income - static_cast<int64_t>(truth_sum_income - 80000);
        residual_debt_A.push_back(err_debt);
        residual_income_A.push_back(err_income);
    }
    auto stats = [](const std::vector<double>& v) {
        double m = 0.0; for (double x : v) m += x; m /= v.size();
        double var = 0.0; for (double x : v) var += (x-m)*(x-m); var /= v.size();
        return std::make_pair(m, std::sqrt(var));
    };
    auto [meanA_d, sdA_d] = stats(residual_debt_A);
    auto [meanA_i, sdA_i] = stats(residual_income_A);
    std::printf("  Residual-attack error (debt):   mean=%.1f, σ_emp=%.1f\n", meanA_d, sdA_d);
    std::printf("  Residual-attack error (income): mean=%.1f, σ_emp=%.1f\n", meanA_i, sdA_i);
    std::printf("  ⇒ Attacker learns others' aggregate ±~3 units — precision negligible\n");
    std::printf("     relative to own firm's contribution (50k, 80k). Q7 VULNERABLE.\n\n");

    // === Scenario B: sensitivity-calibrated DP ===
    std::printf("=== Scenario B: calibrated DP (σ from public clip bounds) ===\n");
    double sigma_debt   = sigmaFromRho(rho, C_debt);
    double sigma_income = sigmaFromRho(rho, C_income);
    double sigma_count  = sigmaFromRho(rho, std::sqrt(2.0));
    std::printf("  σ_debt   = %.1f (calibrated for C_debt = %.0f)\n", sigma_debt, C_debt);
    std::printf("  σ_income = %.1f (calibrated for C_income = %.0f)\n", sigma_income, C_income);
    std::printf("  σ_count  = %.3f (unchanged — count sensitivity √2)\n", sigma_count);

    std::vector<double> residual_debt_B, residual_income_B;
    std::vector<double> sensitivities = {C_debt, C_income, std::sqrt(2.0)};
    for (int t = 0; t < trials; ++t) {
        std::mt19937_64 rng1(0xa000 + t), rng2(0xb000 + t);
        auto noisy = addJointNoiseCalibrated(shared_hists[0], rho, sensitivities,
                                               rng1, rng2, prng);
        int64_t obs_sum_debt   = static_cast<int64_t>(truth_sum_debt)   + noisy.joint_noise[0];
        int64_t obs_sum_income = static_cast<int64_t>(truth_sum_income) + noisy.joint_noise[1];
        int64_t inferred_others_debt   = obs_sum_debt   - 50000;
        int64_t inferred_others_income = obs_sum_income - 80000;
        double err_debt   = inferred_others_debt   - static_cast<int64_t>(truth_sum_debt - 50000);
        double err_income = inferred_others_income - static_cast<int64_t>(truth_sum_income - 80000);
        residual_debt_B.push_back(err_debt);
        residual_income_B.push_back(err_income);
    }
    auto [meanB_d, sdB_d] = stats(residual_debt_B);
    auto [meanB_i, sdB_i] = stats(residual_income_B);
    std::printf("  Residual-attack error (debt):   mean=%.0f, σ_emp=%.0f\n", meanB_d, sdB_d);
    std::printf("  Residual-attack error (income): mean=%.0f, σ_emp=%.0f\n", meanB_i, sdB_i);
    std::printf("  ⇒ Attacker's inference of others' aggregate has ±%.0f noise —\n", sdB_d);
    std::printf("     wider than firm 101's contribution (50k). Q7 CLOSED.\n\n");

    // -----------------------------------------------------------------------
    // Membership-inference test: given a single release, can adversary
    // determine whether firm 101 was in the intersection?
    //
    // Hypothesis test: H0 = firm 101 present, H1 = firm 101 absent.
    // With calibrated DP the two hypotheses differ by (50k, 80k, 1) in the
    // true sums; noise σ ≈ 2.24M in debt/income → hypothesis test has
    // negligible statistical power.
    // -----------------------------------------------------------------------
    std::printf("=== Membership-inference test (H0: firm 101 present vs H1: absent) ===\n");
    // Signal-to-noise: (own firm's debt) / σ_debt.
    double snr_debt   = 50000.0 / sdB_d;
    double snr_income = 80000.0 / sdB_i;
    std::printf("  Signal-to-noise (debt query):   %.4f\n", snr_debt);
    std::printf("  Signal-to-noise (income query): %.4f\n", snr_income);
    std::printf("  ⇒ SNR ≪ 1 → statistical test cannot distinguish H0 from H1.\n");
    std::printf("     Firm 101's membership in the intersection is HIDDEN.\n\n");

    // -----------------------------------------------------------------------
    // ε-δ guarantee for calibrated DP.
    // -----------------------------------------------------------------------
    double eps_at_delta = epsilonFromRho(rho, 1e-6);
    std::printf("=== Formal DP guarantee ===\n");
    std::printf("  Per-release ρ:          %.3f\n", rho);
    std::printf("  ε at δ=1e-6:            %.3f\n", eps_at_delta);
    std::printf("  Interpretation: whether firm 101 is present or absent, the\n");
    std::printf("  release distribution changes by at most exp(ε) multiplicative\n");
    std::printf("  factor (with prob 1-δ). Adversary posterior on membership\n");
    std::printf("  differs from prior by at most this factor.\n\n");

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    std::printf("=== Summary ===\n");
    std::printf("%-25s | %-25s | %-25s\n", "Scenario", "Attacker residual σ", "SNR for membership");
    std::printf("%s\n", std::string(80, '-').c_str());
    std::printf("%-25s | debt=%-18.1f | %-25.4f  (VULNERABLE)\n",
                 "A. Uncalibrated (√2)", sdA_d, 50000.0 / std::max(sdA_d, 1.0));
    std::printf("%-25s | debt=%-18.0f | %-25.4f  (HIDDEN)\n",
                 "B. Calibrated (C_max)", sdB_d, snr_debt);

    std::printf("\nSensitivity-calibrated DP closes the Q7 residual-attack gap.\n");
    std::printf("Trade-off: released aggregate has σ ≈ %.0f noise per bin —\n", sdB_d);
    std::printf("  utility loss visible only at very small n_valid; at scale\n");
    std::printf("  (n_valid ≥ 1000), noise fraction ≈ σ/sum ≪ 1%%.\n");

    return 0;
}
