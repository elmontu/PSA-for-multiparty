#include "MpsvsCryptoParams.h"
#include "MpsvsConfig.h"

#include <sodium.h>

#include <cmath>
#include <sstream>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Canonical text + hash
// ---------------------------------------------------------------------------

std::string MpsvsCryptoParams::toCanonicalText() const {
    std::ostringstream o;
    o.setf(std::ios::fixed);
    o.precision(9);
    o << "beaver_triple_batch=" << beaver_triple_batch << "\n"
      << "lambda_bits=" << lambda_bits << "\n"
      << "lpn_iterations=" << lpn_iterations << "\n"
      << "mac_field_bits=" << mac_field_bits << "\n"
      << "oprf_group_name=" << oprf_group_name << "\n"
      << "oprf_query_cap_Q_tilde=" << oprf_query_cap_Q_tilde << "\n"
      << "oprf_scalar_bits=" << oprf_scalar_bits << "\n"
      << "sacrifice_batch=" << sacrifice_batch << "\n"
      << "shuffle_nizk_batch_max=" << shuffle_nizk_batch_max << "\n"
      << "sigma_stat_bits=" << sigma_stat_bits << "\n"
      << "silent_ot_regime=" << silent_ot_regime << "\n";
    return o.str();
}

std::array<uint8_t, 32> MpsvsCryptoParams::paramsHash() const {
    ensureSodiumInit();
    std::string s = toCanonicalText();
    std::array<uint8_t, 32> h;
    crypto_hash_sha256(h.data(),
                        reinterpret_cast<const uint8_t*>(s.data()),
                        s.size());
    return h;
}

// ---------------------------------------------------------------------------
// Analytic bounds
// ---------------------------------------------------------------------------

double breakEvenBucketCount(double n_expected) {
    // Solves B / log2(B) = log2(n) by bisection.
    // Mirror of math_rev7_r27_break_even::break_even_B — reproduced here so
    // volePSI does not depend on the math test binary at link time.
    if (n_expected <= 4.0) return 2.0;
    double log2n = std::log2(n_expected);
    double lo = 2.0, hi = 10000.0;
    for (int i = 0; i < 100; ++i) {
        double mid = 0.5 * (lo + hi);
        double val = mid / std::log2(mid);
        if (val < log2n) lo = mid;
        else              hi = mid;
    }
    return 0.5 * (lo + hi);
}

uint32_t minSacrificeBatch(uint32_t sigma_stat_bits, uint32_t mac_field_bits) {
    // Sacrifice check catches a malicious triple with probability
    // 1 - 1/|F| per sacrificed triple. For σ-bit soundness over Z_{2^k}:
    //   need t sacrifices with 1 - (1/2^k)^t <= 2^{-σ}
    // => t >= ceil(σ / k).
    if (mac_field_bits == 0) return 1;
    uint32_t t = (sigma_stat_bits + mac_field_bits - 1u) / mac_field_bits;
    return (t == 0) ? 1u : t;
}

double maxDpDelta(uint32_t sigma_stat_bits) {
    return std::pow(2.0, -static_cast<double>(sigma_stat_bits));
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

std::string validateCryptoParams(const MpsvsCryptoParams& p) {
    if (p.lambda_bits < 128)
        return "lambda_bits < 128 (128-bit computational security minimum)";
    if (p.lambda_bits > 256)
        return "lambda_bits > 256 (unnecessarily strong; likely typo)";
    if (p.sigma_stat_bits < 40)
        return "sigma_stat_bits < 40 (40-bit statistical minimum)";
    if (p.sigma_stat_bits > 128)
        return "sigma_stat_bits > 128 (unnecessarily strong; likely typo)";

    if (p.mac_field_bits != 32 && p.mac_field_bits != 64 && p.mac_field_bits != 128)
        return "mac_field_bits must be 32, 64, or 128";
    if (p.oprf_group_name != "ristretto255")
        return "oprf_group_name: only 'ristretto255' is supported";
    if (p.oprf_scalar_bits != 255)
        return "oprf_scalar_bits must be 255 for Ristretto255";

    if (p.beaver_triple_batch == 0 || p.beaver_triple_batch > (1u << 20))
        return "beaver_triple_batch must be in (0, 2^20]";
    if (p.sacrifice_batch == 0 || p.sacrifice_batch > (1u << 16))
        return "sacrifice_batch must be in (0, 2^16]";
    if (p.sacrifice_batch >= p.beaver_triple_batch)
        return "sacrifice_batch must be < beaver_triple_batch";

    uint32_t need = minSacrificeBatch(p.sigma_stat_bits, p.mac_field_bits);
    if (p.sacrifice_batch < need) {
        return "sacrifice_batch too small for sigma_stat_bits/mac_field_bits "
                "(need >= " + std::to_string(need) + ")";
    }

    if (p.shuffle_nizk_batch_max == 0 || p.shuffle_nizk_batch_max > (1u << 20))
        return "shuffle_nizk_batch_max must be in (0, 2^20]";
    if (p.oprf_query_cap_Q_tilde == 0 || p.oprf_query_cap_Q_tilde > 10000000u)
        return "oprf_query_cap_Q_tilde must be in (0, 10^7]";

    if (p.silent_ot_regime != "SD" && p.silent_ot_regime != "EA")
        return "silent_ot_regime must be 'SD' or 'EA'";
    if (p.lpn_iterations < p.lambda_bits / 2)
        return "lpn_iterations must be >= lambda_bits / 2";

    return {};
}

std::vector<std::string> validateAgainstOperationalConfig(
    const MpsvsCryptoParams& cp, const MpsvsConfig& oc) {

    std::vector<std::string> warns;

    // Warning W1: DP delta vs statistical soundness.
    double delta_max = maxDpDelta(cp.sigma_stat_bits);
    if (oc.dp_delta > delta_max) {
        std::ostringstream o;
        o.setf(std::ios::scientific);
        o << "dp_delta (" << oc.dp_delta
          << ") exceeds 2^{-sigma_stat_bits} (" << delta_max
          << ") — statistical DP soundness violated";
        warns.push_back(o.str());
    }

    // Warning W2: bucket_count vs break-even bound. We don't know the true
    // input size n at config-load time; use a conservative default n=1e6.
    double B_star = breakEvenBucketCount(1e6);
    double lo = 0.5 * B_star;
    double hi = 2.0 * B_star;
    if (oc.bucket_count < lo || oc.bucket_count > hi) {
        std::ostringstream o;
        o << "bucket_count (" << oc.bucket_count
          << ") outside 0.5·B* … 2·B* range for n≈10^6 (B*≈"
          << static_cast<uint32_t>(B_star)
          << ") — CGP shuffle may be sub-optimal";
        warns.push_back(o.str());
    }

    // Warning W3: OPRF query cap coherence with max_concurrent_sessions.
    // If Q̃ · sessions > 10^8, the aggregate OPRF cost dominates the release
    // budget; regulator likely wants to know.
    uint64_t aggregate = static_cast<uint64_t>(cp.oprf_query_cap_Q_tilde)
                        * oc.max_concurrent_sessions;
    if (aggregate > 100000000ull) {
        std::ostringstream o;
        o << "aggregate OPRF cap (Q_tilde · sessions = " << aggregate
          << ") exceeds 10^8 — review compute budget";
        warns.push_back(o.str());
    }

    // Warning W4: fp fractional bits vs mac field width.
    // We store x·2^f in Z_{2^k}. Multiplying two such values overflows if
    // 2·f + log2(range) > k. Rough check: 2·f + 20 > k → warn.
    if (2u * oc.fp_fractional_bits + 20u > cp.mac_field_bits) {
        std::ostringstream o;
        o << "fp_fractional_bits (" << oc.fp_fractional_bits
          << ") close to mac_field_bits/2 (" << (cp.mac_field_bits / 2)
          << ") — risk of overflow on fixed-point multiply";
        warns.push_back(o.str());
    }

    return warns;
}

} // namespace mpsvs
} // namespace volePSI
