#pragma once

// MPSVS DP Production Hardening — CSPRNG-backed Gaussian noise + covers.
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
