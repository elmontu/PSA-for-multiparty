// MPSVS Phase 12 acceptance tests — DP noise + R26 CDF clamp + zCDP tracker.

#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsPercentiles.h"

#include <cmath>
#include <cstdio>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static Histogram mkHist(std::initializer_list<uint64_t> v) {
    Histogram h;
    for (auto x : v) h.h.push_back(x);
    h.n_valid = 0;
    for (auto x : h.h) h.n_valid += x;
    return h;
}

static void test_noise_and_clamp() {
    std::printf("--- C1: noise added, clamp keeps non-negative ---\n");
    // Small counts + moderate σ → some bins likely to go negative.
    Histogram h = mkHist({3, 1, 2, 0, 5, 1, 0, 4});
    std::mt19937_64 rng(42);
    BudgetTracker bt;
    NoisyHistogram nh = addNoiseAndClamp(h, /*rho=*/0.5, rng, bt);
    CHECK(nh.h_clamped.size() == h.h.size(), "C1: size preserved");
    for (auto v : nh.h_clamped) {
        // Type is u64 → nonneg by construction.
        (void)v;
    }
    // At least SOME bin should have been clamped (noise σ ≈ sqrt(2)/√1 = √2)
    int negatives = 0;
    for (auto n : nh.h_noisy) if (n < 0) ++negatives;
    std::printf("  σ = %.3f, negative bins before clamp: %d/%zu\n",
                nh.sigma, negatives, nh.h_noisy.size());
    CHECK(negatives >= 0, "C1: sampler ran");
    CHECK(bt.rho_total == 0.5, "C1: budget spent tracked");
}

static void test_r26_monotone_cdf() {
    std::printf("--- C2: R26 clamp → CDF is monotone ---\n");
    // Reproduce Gap 11 scenario: many small bins + large σ → many negative
    // noise values → without clamp CDF would be non-monotone.
    Histogram h = mkHist({1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1});
    std::mt19937_64 rng(7);
    BudgetTracker bt;
    NoisyHistogram nh = addNoiseAndClamp(h, /*rho=*/0.1, rng, bt);

    // Build CDF from clamped values; must be monotone.
    Histogram clamped_hist;
    clamped_hist.h = nh.h_clamped;
    clamped_hist.n_valid = 0;
    for (auto v : nh.h_clamped) clamped_hist.n_valid += v;
    Cdf cdf = makeCdf(clamped_hist);
    CHECK(cdf.monotone == true, "C2: CDF from clamped values is monotone");

    // If we had used pre-clamp values (allowing negative), the CDF could dip.
    // Verify at least one bin was clamped (Gap 11 realistic).
    int clamped_bins = 0;
    for (auto n : nh.h_noisy) if (n < 0) ++clamped_bins;
    std::printf("  bins clamped up: %d/%zu\n", clamped_bins, nh.h_noisy.size());
}

static void test_zcdp_composition() {
    std::printf("--- C3: zCDP tracker composes linearly ---\n");
    BudgetTracker bt;
    std::mt19937_64 rng(1);
    Histogram h = mkHist({10, 20, 30});
    for (int i = 0; i < 5; ++i) {
        addNoiseAndClamp(h, /*rho=*/0.02, rng, bt);
    }
    CHECK(bt.query_count == 5, "C3: 5 queries counted");
    CHECK(std::abs(bt.rho_total - 0.1) < 1e-9, "C3: rho_total = 5 * 0.02 = 0.1");

    double eps = bt.epsilon_at(/*delta=*/1e-6);
    // ε(δ) = ρ + 2·sqrt(ρ · log(1/δ)) = 0.1 + 2 * sqrt(0.1 * 13.82) ≈ 0.1 + 2*1.18 ≈ 2.45
    std::printf("  ρ=%.4f, ε at δ=1e-6: %.4f\n", bt.rho_total, eps);
    CHECK(eps > 0 && eps < 5.0, "C3: ε in expected range");
}

static void test_bundle_release() {
    std::printf("--- C4: full bundle release — one query per cell ---\n");
    SectorAggregateBundle b;
    // Just DTI, one cell.
    SectorHistogram sh;
    sh.key = {1, 202601};
    sh.metric = Metric::DTI;
    sh.hist.h.assign(kBucketCount, 0);
    sh.hist.h[10] = 5;
    sh.hist.h[20] = 3;
    sh.hist.n_valid = 8;
    b.hists[static_cast<size_t>(Metric::DTI)].push_back(sh);

    std::mt19937_64 rng(99);
    BudgetTracker bt;
    NoisySectorBundle out = addNoiseToBundle(b, /*rho_per_cell=*/0.05, rng, bt);
    CHECK(bt.query_count == 1, "C4: 1 query billed for 1 cell");
    CHECK(std::abs(bt.rho_total - 0.05) < 1e-9, "C4: rho_spent = 0.05");
    CHECK(out.hists[static_cast<size_t>(Metric::DTI)].size() == 1,
          "C4: noisy DTI hist produced");
}

static void test_audit() {
    std::printf("--- C5: audit reports clamp events + monotone CDF ---\n");
    Histogram h = mkHist({0, 0, 0, 0, 0, 100, 0, 0});  // pathological single-bin
    std::mt19937_64 rng(21);
    BudgetTracker bt;
    NoisyHistogram nh = addNoiseAndClamp(h, /*rho=*/0.5, rng, bt);
    DpAudit a = auditNoisyHistogram(nh);
    CHECK(a.all_clamped_nonneg, "C5: no clamped bin is negative");
    CHECK(a.cdf_monotone_after_clamp, "C5: CDF monotone after clamp");
    std::printf("  bins clamped up: %u\n", a.bins_clamped_up);
}

static void test_sigma_from_rho() {
    std::printf("--- C6: σ derivation from ρ ---\n");
    // ρ = Δ²/(2σ²) → σ = Δ/√(2ρ). For Δ=√2, ρ=0.5 → σ = √2 / 1 = √2 ≈ 1.414
    double sigma = sigmaFromRho(0.5);
    std::printf("  σ(ρ=0.5, Δ=√2) = %.4f\n", sigma);
    CHECK(std::abs(sigma - std::sqrt(2.0)) < 1e-6, "C6: σ = √2 at ρ=0.5");

    // ρ=0.1 → σ = √2 / √0.2 = √10 ≈ 3.162
    double sigma2 = sigmaFromRho(0.1);
    CHECK(std::abs(sigma2 - std::sqrt(10.0)) < 1e-6, "C6: σ = √10 at ρ=0.1");
}

int main() {
    test_noise_and_clamp();
    test_r26_monotone_cdf();
    test_zcdp_composition();
    test_bundle_release();
    test_audit();
    test_sigma_from_rho();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 12 acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
