// MPSVS Cover-Firm Injection — demonstrates additional MAS-membership
// protection.
//
// Setup:
//   - True intersection: 5 firms per cell
//   - DP noise: σ_count = √2/√(2ρ) ≈ 3.16 at ρ=0.1
//   - Cover config: K ∈ [K_min=3, K_max=15] → E[K]=9, σ_K ≈ 3.46
// Adversary observes released_n_valid = true_n + K + DP_noise.
//   Best estimator: released - E[K] = released - 9.
//   Uncertainty: √(σ_K² + σ_DP²) ≈ √(12 + 10) ≈ 4.7 firms
//
// Without covers: adversary's uncertainty is σ_DP ≈ 3.16.
// With covers:    adversary's uncertainty is √(σ_K² + σ_DP²) ≈ 4.7 firms.
// Additional protection: √(σ_K²) ≈ 3.46 firms — matches theoretical K uncertainty.

#include "volePSI/MpsvsCoverFirms.h"
#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpWire.h"
#include "volePSI/MpsvsSectorAgg.h"
#include "volePSI/MpsvsSectorAggWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cmath>
#include <cstdio>
#include <random>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

int main() {
    std::printf("=== MPSVS Cover-Firm Injection Trace ===\n\n");
    oc::PRNG prng(oc::block(0xabcd, 0x1234));
    const uint32_t N = 2;

    // Build a synthetic cell manually to isolate the cover-firm effect.
    // True n_valid = 5, sum_num = 150000, sum_den = 240000.
    SharedSectorHistogram cell;
    cell.key = {1, 202601};
    cell.metric = Metric::DTI;
    cell.sum_num = shareU64(N, 150000, prng);
    cell.sum_den = shareU64(N, 240000, prng);
    cell.n_valid = shareU64(N, 5, prng);
    uint64_t true_n_valid = 5;

    std::printf("Cell (public):     sector=%u period=%u\n", cell.key.sector, cell.key.period);
    std::printf("True n_valid:      %lu (sensitive — hides |MAS ∩ DOS ∩ MOM|)\n", true_n_valid);
    std::printf("True sum_num:      %lu\n", cell.sum_num.reconstruct());
    std::printf("True sum_den:      %lu\n\n", cell.sum_den.reconstruct());

    // -----------------------------------------------------------------------
    // Configure covers.
    // -----------------------------------------------------------------------
    CoverConfig cc;
    cc.K_min = 3;
    cc.K_max = 15;
    double e_k = cc.expected_K();
    double sd_k = cc.K_uncertainty_sd();
    std::printf("Cover config: K ∈ [%u, %u], E[K]=%.1f, σ_K=%.2f\n\n",
                 cc.K_min, cc.K_max, e_k, sd_k);

    // -----------------------------------------------------------------------
    // Trial: run pipeline over many trials, measure adversary's inference
    // precision on true_n_valid.
    // -----------------------------------------------------------------------
    const int trials = 500;
    double rho = 0.1;
    double sigma_dp = sigmaFromRho(rho);   // √2/√(2·0.1) ≈ 3.16

    std::vector<double> adv_est_no_cover;
    std::vector<double> adv_est_with_cover;

    for (int t = 0; t < trials; ++t) {
        std::mt19937_64 rng1(0x1111 + t), rng2(0x2222 + t);
        std::mt19937_64 dp_rng1(0xa000 + t), dp_rng2(0xb000 + t);

        // === No cover ===
        auto noisy_nc = addJointNoise(cell, rho, dp_rng1, dp_rng2, prng);
        int64_t released_nc = static_cast<int64_t>(true_n_valid) + noisy_nc.joint_noise[2];
        double est_nc = static_cast<double>(released_nc);   // adversary's guess
        adv_est_no_cover.push_back(est_nc - static_cast<double>(true_n_valid));

        // === With cover ===
        auto cell_wc = addCoverFirms(cell, cc, rng1, rng2);
        uint64_t inflated_n = cell_wc.n_valid.reconstruct();
        // Verify inflation is in expected range.
        if (t == 0) {
            std::printf("Trial 0: n_valid before covers = %lu, after = %lu (diff = %ld ∈ [%u, %u])\n\n",
                         true_n_valid, inflated_n, inflated_n - true_n_valid, cc.K_min, cc.K_max);
        }
        auto noisy_wc = addJointNoise(cell_wc, rho, dp_rng1, dp_rng2, prng);
        int64_t released_wc = static_cast<int64_t>(inflated_n) + noisy_wc.joint_noise[2];
        // Adversary's best estimator: released - E[K]
        double est_wc = released_wc - e_k;
        adv_est_with_cover.push_back(est_wc - static_cast<double>(true_n_valid));
    }

    auto stats = [](const std::vector<double>& v) {
        double m = 0.0; for (double x : v) m += x; m /= v.size();
        double var = 0.0; for (double x : v) var += (x-m)*(x-m); var /= v.size();
        return std::make_pair(m, std::sqrt(var));
    };
    auto [bias_nc, sd_nc] = stats(adv_est_no_cover);
    auto [bias_wc, sd_wc] = stats(adv_est_with_cover);

    std::printf("=== Adversary's estimation error on true_n_valid (%d trials) ===\n", trials);
    std::printf("%-25s | %-12s | %-12s | %s\n", "Scenario", "Bias", "σ (empirical)", "σ (theory)");
    std::printf("%s\n", std::string(80, '-').c_str());
    std::printf("%-25s | %-12.2f | %-12.2f | %.2f\n",
                 "A. No cover firms",       bias_nc, sd_nc, sigma_dp);
    double theory_wc = std::sqrt(sd_k * sd_k + sigma_dp * sigma_dp);
    std::printf("%-25s | %-12.2f | %-12.2f | %.2f\n",
                 "B. Cover firms",          bias_wc, sd_wc, theory_wc);

    double protection_gain = sd_wc - sd_nc;
    std::printf("\nAdditional uncertainty from covers: %.2f firms\n", protection_gain);
    std::printf("(theory: √(σ_K² + σ_DP²) - σ_DP = √(%.1f²+%.1f²) - %.1f = %.2f)\n",
                 sd_k, sigma_dp, sigma_dp, theory_wc - sigma_dp);

    // -----------------------------------------------------------------------
    // Membership-inference test with covers.
    // -----------------------------------------------------------------------
    std::printf("\n=== Membership-inference test with covers ===\n");
    std::printf("Question: is a specific firm (contributing 1 to n_valid) in MAS?\n");
    std::printf("Signal   = 1 firm (add/remove for hypothesis test)\n");
    double snr_no_cover = 1.0 / sd_nc;
    double snr_with_cover = 1.0 / sd_wc;
    std::printf("SNR without covers: %.4f\n", snr_no_cover);
    std::printf("SNR with covers:    %.4f\n", snr_with_cover);
    std::printf("Improvement:        %.2fx harder\n", sd_wc / sd_nc);

    // -----------------------------------------------------------------------
    // Ratio-of-sums unbiased? (Covers add 0/0 to sums.)
    // -----------------------------------------------------------------------
    std::printf("\n=== Utility check: ratio-of-sums preserved ===\n");
    // Reconstruct post-cover cell — sum_num and sum_den unchanged.
    std::mt19937_64 rr1(0x77), rr2(0x88);
    auto cell_verify = addCoverFirms(cell, cc, rr1, rr2);
    uint64_t recon_num = cell_verify.sum_num.reconstruct();
    uint64_t recon_den = cell_verify.sum_den.reconstruct();
    double ratio = static_cast<double>(recon_num) / recon_den;
    double true_ratio = 150000.0 / 240000.0;
    std::printf("  Post-cover sum_num:  %lu (want 150000)\n", recon_num);
    std::printf("  Post-cover sum_den:  %lu (want 240000)\n", recon_den);
    std::printf("  Ratio-of-sums:       %.6f (want %.6f)\n", ratio, true_ratio);
    bool utility_preserved = (recon_num == 150000 && recon_den == 240000);
    std::printf("  ⇒ ratio-of-sums metric UNBIASED: %s\n\n",
                 utility_preserved ? "PASS" : "FAIL");

    // -----------------------------------------------------------------------
    // Consumer bias correction.
    // -----------------------------------------------------------------------
    std::printf("=== Consumer bias correction ===\n");
    std::printf("Released n_valid = true_n + K + noise (K in [%u,%u], E[K]=%.1f)\n",
                 cc.K_min, cc.K_max, e_k);
    std::printf("Best point estimate: n_true ≈ released - %.1f\n", e_k);
    std::printf("Confidence interval: n_true ∈ [released - %.1f - 1.96·%.2f, released - %.1f + 1.96·%.2f]\n",
                 e_k, theory_wc, e_k, theory_wc);
    std::printf("                     ≈ ±%.1f firms (vs ±%.1f without covers)\n",
                 1.96 * theory_wc, 1.96 * sigma_dp);

    if (utility_preserved && sd_wc > sd_nc)
        std::printf("\nPASS — cover-firm injection strengthens membership protection.\n");

    return 0;
}
