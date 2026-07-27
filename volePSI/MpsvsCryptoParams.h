#pragma once

// MPSVS Cryptographic Parameters — security-proof-derived constants.
//
// Distinct from MpsvsConfig (which is operations-owned: rho budget,
// k-anon threshold, log path, ...). MpsvsCryptoParams is CRYPTO-team-
// owned: fields whose values follow from security-proof requirements,
// not from operational preference. Changing them requires a fresh
// security review, not just a regulator sign-off.
//
// Fields fall into four families:
//
//   1. Security parameters
//      - lambda_bits           : computational security (>= 128)
//      - sigma_stat_bits       : statistical security (>= 40)
//
//   2. Algebraic-field parameters
//      - mac_field_bits        : SPDZ MAC ring width (Z_{2^k}, k ∈ {32,64,128})
//      - oprf_group_name       : "ristretto255" (only supported curve)
//      - oprf_scalar_bits      : 255 (Curve25519 / Ristretto scalar width)
//
//   3. Protocol batch sizes (derived from soundness / statistical bounds)
//      - beaver_triple_batch   : #triples per SPDZ preprocessing batch
//      - sacrifice_batch       : #triples spent on cut-and-choose sacrifice
//      - shuffle_nizk_batch_max: cap on Bayer-Groth CGP shuffle proof size
//      - oprf_query_cap_Q_tilde: Rev 7 §5 metering cap per client per epoch
//
//   4. OT / LPN parameters
//      - silent_ot_regime      : "SD" (Small-Distance) or "EA" (Ext-Additive)
//      - lpn_iterations        : Silent-OT LPN iterations (>= lambda_bits/2)
//
// Cross-parameter constraints validated by validateCryptoParams:
//   - lambda_bits >= 128 (128-bit computational security floor)
//   - sigma_stat_bits >= 40 (40-bit statistical soundness floor)
//   - sacrifice_batch >= ceil(sigma_stat_bits / log2(mac_field_bits))
//     [soundness of cut-and-choose sacrifice test]
//   - beaver_triple_batch > sacrifice_batch (usable triples > sacrificed)
//   - mac_field_bits in {32, 64, 128}
//   - oprf_scalar_bits == 255 (Ristretto255 only)
//
// Cross-config constraints (checked in validateAgainstOperationalConfig,
// against MpsvsConfig fields):
//   - config.bucket_count is *close* to breakEvenBucketCount(n_expected)
//     from math_rev7_r27_break_even — if too far off, warn (not fatal;
//     regulators may legitimately pick a smaller B).
//   - config.dp_delta ≤ 2^{-sigma_stat_bits}  (statistical DP soundness)

#include "MpsvsProdHygiene.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

struct MpsvsConfig;   // forward — validateAgainstOperationalConfig only

struct MpsvsCryptoParams {
    // -----------------------------------------------------------------------
    // 1. Security parameters
    // -----------------------------------------------------------------------
    uint32_t lambda_bits            = 128;
    uint32_t sigma_stat_bits        = 40;

    // -----------------------------------------------------------------------
    // 2. Algebraic-field parameters
    // -----------------------------------------------------------------------
    uint32_t    mac_field_bits      = 64;
    std::string oprf_group_name     = "ristretto255";
    uint32_t    oprf_scalar_bits    = 255;

    // -----------------------------------------------------------------------
    // 3. Protocol batch sizes
    // -----------------------------------------------------------------------
    uint32_t beaver_triple_batch    = 1024;
    uint32_t sacrifice_batch        = 128;
    uint32_t shuffle_nizk_batch_max = 65536;
    uint32_t oprf_query_cap_Q_tilde = 10000;

    // -----------------------------------------------------------------------
    // 4. OT / LPN parameters
    // -----------------------------------------------------------------------
    std::string silent_ot_regime    = "SD";     // "SD" or "EA"
    uint32_t    lpn_iterations      = 128;      // >= lambda_bits/2 typical

    // Deterministic SHA-256 hash of the canonical text form (for the
    // change-control audit chain — mirror of MpsvsConfig::configHash).
    std::array<uint8_t, 32> paramsHash() const;

    // Canonical text serialisation (sorted keys, fixed formatting).
    std::string toCanonicalText() const;
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Returns empty string on success, error message on first violation.
std::string validateCryptoParams(const MpsvsCryptoParams& p);

// Cross-check crypto params against operational config for coherence.
// Returns list of warnings (empty = coherent). Warnings are non-fatal —
// they surface potential misconfigurations for regulator review.
std::vector<std::string> validateAgainstOperationalConfig(
    const MpsvsCryptoParams& cp, const MpsvsConfig& oc);

// ---------------------------------------------------------------------------
// Analytic bounds — pull in the math suite's computed thresholds so
// validation can be quantitative rather than "some conservative constant."
// ---------------------------------------------------------------------------

// Break-even bucket count B*(n) from math_rev7_r27_break_even.
// Solves B / log2(B) = log2(n) by bisection. Config's bucket_count
// should be >= 0.5 · B* and <= 2 · B* for the recommended operating
// regime; anything outside triggers a validation warning.
double breakEvenBucketCount(double n_expected);

// Minimum sacrifice batch size for given statistical security σ over
// Z_{2^k}: ceil(σ / k). E.g., σ=40 over Z_{2^64} → 1 (single sacrifice
// suffices for 40-bit soundness); over Z_{2^32} → 2.
uint32_t minSacrificeBatch(uint32_t sigma_stat_bits, uint32_t mac_field_bits);

// Maximum tolerable dp_delta for a given statistical security parameter:
// delta must not exceed 2^{-σ}. Returns 2^{-sigma_stat_bits} as double.
double maxDpDelta(uint32_t sigma_stat_bits);

} // namespace mpsvs
} // namespace volePSI
