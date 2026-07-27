#pragma once

// MPSVS DP Production Hardening — CSPRNG-backed Gaussian noise + covers.
//
// [DP-RETROFIT-TODO] Rev-7 audit surfaced three load-bearing DP holes
// still present here (see docs/PROTOCOL.md §5.12 Alg 30 + §3 F_DP for
// the corrected pseudocode / ideal functionality):
//   (a) k-anon gate operates on the TRUE n_valid — infinite ε-loss
//       for neighbours straddling k. FIX: stability-noise the count
//       first (Bun–Steinke 2016 §4) and threshold on the noised count.
//   (b) The un-noised n_valid is released alongside noised aggregates
//       — a sensitive statistic outside the ρ budget. FIX: release
//       ñ = n_valid + ξ and never emit raw n_v.
//   (c) Δ₂ = √2 is hardcoded and the same ρ is deducted for hist, num,
//       den (three independent Gaussians) — actual privacy cost ~3ρ.
//       FIX: per-metric Δ, per-metric ρ_hist / ρ_num / ρ_den charged
//       independently to BudgetTracker.
// The current `addJointNoiseImpl` implements the honest-case arithmetic
// correctly, but the DP claim in docs/SECURITY.md §2.3 requires the
// three fixes above. Do NOT depend on the DP guarantee against
// adversary class A3 (client-side neighbour queries) until the
// retrofit lands.
//
// Bug fix: previous MpsvsDpWire::sampleAndCommit used std::mt19937_64 which
// is a Mersenne Twister — NOT crypto-secure. State is recoverable from ~624
// consecutive outputs (folklore result), which means:
//   - DP noise becomes predictable to an adversary who observes enough runs
//   - The DP guarantee ε > 0 is nominal only if the noise is truly random
//   - An attacker who reconstructs the RNG state can subtract the noise
//     from released aggregates, defeating DP entirely
//
// Production requires libsodium's CSPRNG (randombytes_buf, backed by
// /dev/urandom or getrandom(2)) for ALL secret sampling.
//
// This module provides hardened variants that:
//   - Sample DP noise via crypto_core_ristretto255_scalar_random or
//     Box-Muller with CSPRNG-sourced uniforms
//   - Sample cover-firm K via secureRandU64Bounded
//   - Integrate with SessionAuditLog for tamper-evident tracking of
//     each noise-generation event

#include "MpsvsAuthShareProd.h"    // for SessionAuditLog
#include "MpsvsCoverFirms.h"
#include "MpsvsDp.h"
#include "MpsvsDpWire.h"
#include "MpsvsProdHygiene.h"
#include "MpsvsSectorAgg.h"
#include "MpsvsSectorAggWire.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// CSPRNG-backed Gaussian sampler (Box-Muller with libsodium-sourced uniforms).
// ---------------------------------------------------------------------------

// Sample one integer Gaussian(0, sigma^2). Uses CSPRNG-sourced uniforms
// (libsodium randombytes_buf) + Box-Muller transform + round to nearest.
int64_t sampleGaussianCsprng(double sigma);

// ---------------------------------------------------------------------------
// Hardened DP joint-noise commit-then-reveal.
//
// Same commit-then-reveal protocol as MpsvsDpWire::sampleAndCommit,
// but noise sampled via CSPRNG instead of mt19937_64.
// ---------------------------------------------------------------------------
NoiseCommit sampleAndCommitProd(uint32_t party_id, uint32_t num_bins,
                                  double sigma_per_party);

// End-to-end: joint noise via CSPRNG commits, logged to audit chain.
// Aborts + logs to SessionAuditLog on commit mismatch.
struct DpProdResult {
    SharedNoisyHistogram noisy;
    bool                 committed_ok;   // true iff both commits verified
};

DpProdResult addJointNoiseProd(const SharedSectorHistogram& cell,
                                 double rho,
                                 SessionAuditLog& audit_log,
                                 const AbortContext& ctx);

// Sensitivity-calibrated variant using CSPRNG.
DpProdResult addJointNoiseCalibratedProd(
    const SharedSectorHistogram& cell,
    double rho,
    const std::vector<double>& sensitivities,
    SessionAuditLog& audit_log,
    const AbortContext& ctx);

// ---------------------------------------------------------------------------
// Hardened cover-firm injection using CSPRNG.
// ---------------------------------------------------------------------------

SharedSectorHistogram addCoverFirmsProd(const SharedSectorHistogram& cell,
                                          const CoverConfig& cc);

// ---------------------------------------------------------------------------
// SPDZ2k-shaped DP release with stability-based noisy-threshold gate
// (Bun–Steinke 2016 §4). Fixes the three holes in the earlier k-anon +
// per-cell-ρ design (see docs/PROTOCOL.md §5.12 Alg 30):
//   (a) gate operates on NOISED count, not true count → bounded ε-loss;
//   (b) released count is noised ñ, not raw n_valid;
//   (c) per-metric Δ threaded through; per-release ρ charged separately.
// ---------------------------------------------------------------------------

struct DpMetricParams {
    double rho_threshold;        // ρ for the stability-noise gate on count
    double rho_hist;             // ρ for the histogram release
    double rho_num;              // ρ for numerator sum
    double rho_den;              // ρ for denominator sum
    double delta_hist;           // Δ_hist_m (default √2 for count hist)
    double delta_num;            // Δ_num_m  (contribution clip C_num_m)
    double delta_den;            // Δ_den_m  (contribution clip C_den_m)
    double delta_target;         // δ in (ε, δ) — for stability-margin τ
    uint64_t k_threshold;        // k in k-anonymity gate
};

struct NoisyThresholdRelease {
    bool     released;           // false ⇒ suppressed
    uint64_t noised_count;       // ñ = n_valid + ξ (public post-release)
    std::vector<int64_t> noised_hist;   // Rev-7 3-bin histogram (num, den, cnt)
    int64_t  noised_num;
    int64_t  noised_den;
    double   rho_spent;          // = ρ_th + ρ_hist + ρ_num + ρ_den (or ρ_th only if suppressed)
    double   stability_margin_tau;   // logged for audit
};

// Stability-based release per PROTOCOL.md §5.12 Alg 30.
// Never reveals raw n_valid. Neighbours straddling k give bounded ε_th
// loss (via ρ_th zCDP on the count), not infinite as classical k-anon.
NoisyThresholdRelease
noisyThresholdReleaseProd(const SharedSectorHistogram& cell,
                           const DpMetricParams& p,
                           SessionAuditLog& audit_log,
                           const AbortContext& ctx);

// ---------------------------------------------------------------------------
// Empirical DP-noise entropy check.
// Runs many samples of the CSPRNG-backed Gaussian and returns a summary
// (mean, variance, empirical entropy estimate). Used by tests to verify
// the CSPRNG output looks Gaussian and NOT predictable.
// ---------------------------------------------------------------------------
struct NoiseEntropyReport {
    double empirical_mean;
    double empirical_variance;
    double target_variance;   // sigma^2
    int    unique_values;      // out of N samples
    bool   passes_variance_check;   // |emp_var - target_var| / target_var < 20%
};

NoiseEntropyReport reportNoiseEntropy(double sigma, int n_samples);

} // namespace mpsvs
} // namespace volePSI
