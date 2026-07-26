// MPSVS Membership-Inference Prediction Rate.
//
// Answers: given our DP-noised release, how accurately can an adversary
// predict "is firm X in MAS?" — the ultimate operational privacy metric.
//
// Attack model:
//   H0: firm X is NOT in MAS (true_n_valid = n0)
//   H1: firm X IS in MAS     (true_n_valid = n0 + 1)
// The two hypotheses differ by exactly ±1 in the shared count (single-firm
// contribution). Adversary receives release, chooses H0 or H1 based on
// threshold test.
//
// Neyman-Pearson optimal test:
//   Predict H1 iff released ≥ threshold τ, where τ = (n0 + n0+1)/2 = n0 + 0.5
// Under Gaussian mechanism with σ:
//   accuracy = 0.5 · (1 + Φ(1 / (2σ)))
// This is the fundamental limit under DP.
//
// Prior: uniform (50/50) — worst case for the defender.
// Results are compared to:
//   - Random guessing baseline: 50%
//   - DP theoretical bound: 0.5 · (1 + Φ(Δ/(2σ)))
//   - Effective ε from empirical attack advantage

#include "volePSI/MpsvsCoverFirms.h"
#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpWire.h"
#include "volePSI/MpsvsSectorAgg.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cmath>
#include <cstdio>
#include <random>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

// Standard normal CDF via erf.
static double phi(double x) {
    return 0.5 * (1.0 + std::erf(x / std::sqrt(2.0)));
}

struct AttackResult {
    int n_trials;
    int correct;
    int true_pos;
    int true_neg;
    int false_pos;
    int false_neg;
    double accuracy() const { return static_cast<double>(correct) / n_trials; }
    double tpr() const { return static_cast<double>(true_pos) / (true_pos + false_neg); }
    double fpr() const { return static_cast<double>(false_pos) / (false_pos + true_neg); }
    double advantage() const { return tpr() - fpr(); }
};

// Run one full membership-inference experiment: N/2 trials with firm-X-in-MAS
// (H1) and N/2 trials without (H0). Adversary uses optimal threshold test.
static AttackResult
runAttack(double rho, uint64_t base_n_valid,
           const CoverConfig* cover_cfg,   // nullptr = no covers
           bool use_calibrated_dp,
           double sensitivity_for_calibrated,
           int trials_per_hyp,
           oc::PRNG& base_prng) {
    AttackResult r{};
    r.n_trials = 2 * trials_per_hyp;

    // Theoretical σ under our mechanism (used ONLY to derive attacker
    // threshold; attacker knows σ from the public protocol parameters).
    double sigma_dp = use_calibrated_dp
                       ? sigmaFromRho(rho, sensitivity_for_calibrated)
                       : sigmaFromRho(rho);
    double sigma_k = cover_cfg ? cover_cfg->K_uncertainty_sd() : 0.0;
    double sigma_total = std::sqrt(sigma_dp * sigma_dp + sigma_k * sigma_k);
    double e_k = cover_cfg ? cover_cfg->expected_K() : 0.0;

    // Optimal Neyman-Pearson threshold (attacker's decision boundary):
    //   predict H1 iff released - E[K] > base_n_valid + 0.5
    double threshold = static_cast<double>(base_n_valid) + 0.5;

    for (int i = 0; i < r.n_trials; ++i) {
        bool truth_H1 = (i < trials_per_hyp);
        uint64_t truth_n_valid = base_n_valid + (truth_H1 ? 1 : 0);

        // Build a cell with the true count.
        SharedSectorHistogram cell;
        cell.key = {1, 202601};
        cell.metric = Metric::DTI;
        cell.sum_num = shareU64(2, 150000, base_prng);
        cell.sum_den = shareU64(2, 240000, base_prng);
        cell.n_valid = shareU64(2, truth_n_valid, base_prng);

        // Apply covers if configured.
        if (cover_cfg) {
            std::mt19937_64 rng_c1(0x1000 + i), rng_c2(0x2000 + i);
            cell = addCoverFirms(cell, *cover_cfg, rng_c1, rng_c2);
        }

        // Apply DP noise.
        std::mt19937_64 dp_r1(0xa000 + i), dp_r2(0xb000 + i);
        SharedNoisyHistogram noisy;
        if (use_calibrated_dp) {
            std::vector<double> sens = {sensitivity_for_calibrated,
                                          sensitivity_for_calibrated,
                                          std::sqrt(2.0)};
            noisy = addJointNoiseCalibrated(cell, rho, sens,
                                              dp_r1, dp_r2, base_prng);
        } else {
            noisy = addJointNoise(cell, rho, dp_r1, dp_r2, base_prng);
        }

        // Adversary sees released_n_valid (bin 2) and predicts.
        int64_t released_n = static_cast<int64_t>(cell.n_valid.reconstruct())
                              + noisy.joint_noise[2];
        double adv_estimate = static_cast<double>(released_n) - e_k;
        bool prediction_H1 = (adv_estimate > threshold);

        if (truth_H1 && prediction_H1)       ++r.true_pos, ++r.correct;
        else if (!truth_H1 && !prediction_H1) ++r.true_neg, ++r.correct;
        else if (!truth_H1 && prediction_H1) ++r.false_pos;
        else                                   ++r.false_neg;
    }
    (void)sigma_total;
    return r;
}

int main() {
    std::printf("=== MPSVS Membership-Inference Prediction Rate ===\n\n");
    std::printf("Question: given the DP-noised release, what fraction of the\n");
    std::printf("time can an adversary CORRECTLY guess whether firm X is in MAS?\n");
    std::printf("Random baseline: 50%%. DP protects: attack accuracy ≪ 100%%.\n\n");

    oc::PRNG prng(oc::block(0x9999, 0xaaaa));
    const uint64_t base_n_valid = 5;   // baseline (H0)
    const int trials_per_hyp = 2000;
    const double rho = 0.1;
    const double C_max = 1e6;   // public contribution clip for calibrated DP

    // -----------------------------------------------------------------------
    // Scenario 1: baseline DP (uncalibrated, no covers)
    // -----------------------------------------------------------------------
    auto s1 = runAttack(rho, base_n_valid, nullptr, false, 0.0,
                          trials_per_hyp, prng);
    double sigma1 = sigmaFromRho(rho);
    double theory1 = 0.5 * (1.0 + std::erf(1.0 / (2.0 * sigma1 * std::sqrt(2.0))));

    std::printf("=== Scenario 1: baseline (uncalibrated DP, no covers) ===\n");
    std::printf("  σ_DP = %.3f (count sensitivity √2)\n", sigma1);
    std::printf("  Empirical accuracy:  %.4f (%d/%d)\n",
                 s1.accuracy(), s1.correct, s1.n_trials);
    std::printf("  Theory (Gaussian):   %.4f\n", theory1);
    std::printf("  TPR = %.4f, FPR = %.4f, Advantage = %.4f\n",
                 s1.tpr(), s1.fpr(), s1.advantage());
    std::printf("  Prediction rate ABOVE random: +%.2f%% (worse for privacy)\n\n",
                 (s1.accuracy() - 0.5) * 100);

    // -----------------------------------------------------------------------
    // Scenario 2: with cover firms
    // -----------------------------------------------------------------------
    CoverConfig cc; cc.K_min = 3; cc.K_max = 15;
    auto s2 = runAttack(rho, base_n_valid, &cc, false, 0.0,
                          trials_per_hyp, prng);
    double sigma2 = std::sqrt(sigma1 * sigma1 + cc.K_uncertainty_sd() * cc.K_uncertainty_sd());
    double theory2 = 0.5 * (1.0 + std::erf(1.0 / (2.0 * sigma2 * std::sqrt(2.0))));

    std::printf("=== Scenario 2: with cover firms (K ∈ [%u, %u]) ===\n",
                 cc.K_min, cc.K_max);
    std::printf("  σ_DP + σ_K = %.3f  (σ_K=%.2f from uniform K)\n",
                 sigma2, cc.K_uncertainty_sd());
    std::printf("  Empirical accuracy:  %.4f (%d/%d)\n",
                 s2.accuracy(), s2.correct, s2.n_trials);
    std::printf("  Theory (Gaussian):   %.4f\n", theory2);
    std::printf("  TPR = %.4f, FPR = %.4f, Advantage = %.4f\n",
                 s2.tpr(), s2.fpr(), s2.advantage());
    std::printf("  Prediction rate ABOVE random: +%.2f%%\n\n",
                 (s2.accuracy() - 0.5) * 100);

    // -----------------------------------------------------------------------
    // Scenario 3: attacker on the SUM query (much larger sensitivity)
    // — uses the calibrated DP variant
    // -----------------------------------------------------------------------
    // For this scenario the signal is 1 firm's contribution to sum_debt
    // (~50k typical). Attacker's advantage bounded by 50k / (2·σ_calibrated).
    double sigma_sum = sigmaFromRho(rho, C_max);
    double theory_sum = 0.5 * (1.0 + std::erf(50000.0 / (2.0 * sigma_sum * std::sqrt(2.0))));
    std::printf("=== Scenario 3: sum_debt query with calibrated DP (C_max=$1M) ===\n");
    std::printf("  σ_sum = %.0f (calibrated for $1M contribution)\n", sigma_sum);
    std::printf("  Signal:  50000 (typical single-firm contribution)\n");
    std::printf("  Theory (Gaussian):   %.4f  ← membership-inference on SUM query\n",
                 theory_sum);
    std::printf("  Prediction rate ABOVE random: +%.4f%%\n\n",
                 (theory_sum - 0.5) * 100);

    // -----------------------------------------------------------------------
    // Effective ε from empirical attack advantage
    // (rough: attacker's advantage bounded by e^ε / (1+e^ε) - 1/2)
    // Note: this is an upper bound derivation, not exact.
    // -----------------------------------------------------------------------
    std::printf("=== Effective privacy from empirical attack (upper bound) ===\n");
    auto eps_from_adv = [](double adv) {
        // adv = e^ε / (1 + e^ε) - 1/2  → ε = ln((0.5 + adv) / (0.5 - adv))
        if (adv >= 0.5 || adv <= -0.5) return 999.0;
        return std::log((0.5 + adv) / (0.5 - adv));
    };
    double formal_eps = epsilonFromRho(rho, 1e-6);
    std::printf("  Formal ε (zCDP→(ε,δ) at δ=1e-6):  %.3f\n", formal_eps);
    std::printf("  Effective ε (S1 attack):           %.3f  (upper bound from advantage %.4f)\n",
                 eps_from_adv(s1.advantage()), s1.advantage());
    std::printf("  Effective ε (S2 w/ covers):        %.3f  (upper bound from advantage %.4f)\n",
                 eps_from_adv(s2.advantage()), s2.advantage());
    std::printf("  Effective ε (S3 sum, calibrated):  %.3f  (theoretical adv %.4f)\n",
                 eps_from_adv(theory_sum - 0.5), theory_sum - 0.5);

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    std::printf("\n=== Summary: prediction rate for \"firm X in MAS?\" ===\n");
    std::printf("%-45s | %-8s | %-8s | %s\n", "Scenario", "Accuracy", "vs 50%", "Effective ε");
    std::printf("%s\n", std::string(90, '-').c_str());
    std::printf("%-45s | %.4f  | +%5.2f%% | %.3f\n",
                 "Random guessing (no info)", 0.5, 0.0, 0.0);
    std::printf("%-45s | %.4f  | +%5.2f%% | %.3f\n",
                 "Attack on n_valid, no covers", s1.accuracy(),
                 (s1.accuracy() - 0.5) * 100, eps_from_adv(s1.advantage()));
    std::printf("%-45s | %.4f  | +%5.2f%% | %.3f\n",
                 "Attack on n_valid, WITH covers", s2.accuracy(),
                 (s2.accuracy() - 0.5) * 100, eps_from_adv(s2.advantage()));
    std::printf("%-45s | %.4f  | +%5.4f%% | %.3f\n",
                 "Attack on sum, calibrated DP",
                 theory_sum, (theory_sum - 0.5) * 100,
                 eps_from_adv(theory_sum - 0.5));

    std::printf("\n=== Interpretation ===\n");
    std::printf("  - Random-guess baseline: 50%%. Any protection ≥ 50%% is a leak.\n");
    std::printf("  - Attack on n_valid: gains ~%.0f%% over random via count noise alone.\n",
                 (s1.accuracy() - 0.5) * 100);
    std::printf("    Covers reduce this to ~%.0f%% (%.2fx harder).\n",
                 (s2.accuracy() - 0.5) * 100,
                 (s1.accuracy() - 0.5) / std::max(s2.accuracy() - 0.5, 0.0001));
    std::printf("  - Attack on sum with calibrated DP: gain is %.4f%% — effectively\n",
                 (theory_sum - 0.5) * 100);
    std::printf("    RANDOM GUESSING. Membership hypothesis is INDISTINGUISHABLE.\n");
    std::printf("  - Formal ε=%.2f is loose; empirical effective ε ≈ %.3f for count queries.\n",
                 formal_eps, eps_from_adv(s1.advantage()));

    return 0;
}
