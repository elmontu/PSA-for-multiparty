// MPSVS CryptoParams tests: validation, cross-tool bounds, config coherence.

#include "volePSI/MpsvsConfig.h"
#include "volePSI/MpsvsCryptoParams.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// ==========================================================================
// Defaults + basic validation
// ==========================================================================

static void test_defaults_validate() {
    std::printf("--- C1: default crypto params pass validation ---\n");
    MpsvsCryptoParams p;
    std::string err = validateCryptoParams(p);
    CHECK(err.empty(), "C1: defaults valid");
    if (!err.empty()) std::printf("     err: %s\n", err.c_str());
}

static void test_lambda_floor() {
    std::printf("--- C2: lambda_bits < 128 rejected ---\n");
    MpsvsCryptoParams p;
    p.lambda_bits = 80;
    CHECK(!validateCryptoParams(p).empty(), "C2a: lambda=80 rejected");
    p.lambda_bits = 127;
    CHECK(!validateCryptoParams(p).empty(), "C2b: lambda=127 rejected");
    p.lambda_bits = 128;
    CHECK(validateCryptoParams(p).empty(), "C2c: lambda=128 accepted");
    p.lambda_bits = 256;
    CHECK(validateCryptoParams(p).empty(), "C2d: lambda=256 accepted");
    p.lambda_bits = 257;
    CHECK(!validateCryptoParams(p).empty(), "C2e: lambda=257 rejected (typo)");
}

static void test_sigma_floor() {
    std::printf("--- C3: sigma_stat_bits < 40 rejected ---\n");
    MpsvsCryptoParams p;
    p.sigma_stat_bits = 20;
    CHECK(!validateCryptoParams(p).empty(), "C3a: sigma=20 rejected");
    p.sigma_stat_bits = 40;
    CHECK(validateCryptoParams(p).empty(), "C3b: sigma=40 accepted");
    p.sigma_stat_bits = 80;
    // Need to bump sacrifice_batch to satisfy new soundness need
    p.sacrifice_batch = minSacrificeBatch(80, 64);
    CHECK(validateCryptoParams(p).empty(), "C3c: sigma=80 accepted with matching sacrifice_batch");
}

static void test_mac_field_bits() {
    std::printf("--- C4: mac_field_bits restricted to {32,64,128} ---\n");
    MpsvsCryptoParams p;
    p.mac_field_bits = 63;
    CHECK(!validateCryptoParams(p).empty(), "C4a: 63 rejected");
    p.mac_field_bits = 32;
    p.sacrifice_batch = minSacrificeBatch(40, 32);
    CHECK(validateCryptoParams(p).empty(), "C4b: 32 accepted");
    p.mac_field_bits = 128;
    p.sacrifice_batch = 128;
    CHECK(validateCryptoParams(p).empty(), "C4c: 128 accepted");
}

static void test_oprf_group() {
    std::printf("--- C5: only ristretto255 accepted ---\n");
    MpsvsCryptoParams p;
    p.oprf_group_name = "secp256k1";
    CHECK(!validateCryptoParams(p).empty(), "C5a: secp256k1 rejected");
    p.oprf_group_name = "ristretto255";
    CHECK(validateCryptoParams(p).empty(), "C5b: ristretto255 accepted");
    p.oprf_scalar_bits = 256;
    CHECK(!validateCryptoParams(p).empty(), "C5c: scalar_bits=256 rejected");
}

static void test_sacrifice_bound() {
    std::printf("--- C6: sacrifice_batch enforces soundness bound ---\n");
    MpsvsCryptoParams p;
    p.sigma_stat_bits = 40;
    p.mac_field_bits = 64;
    p.sacrifice_batch = 1;    // enough: ceil(40/64) = 1
    CHECK(validateCryptoParams(p).empty(), "C6a: 1 sacrifice enough for σ=40 over Z_{2^64}");

    p.mac_field_bits = 32;
    p.sacrifice_batch = 1;    // NOT enough: ceil(40/32) = 2
    CHECK(!validateCryptoParams(p).empty(), "C6b: 1 sacrifice too few for σ=40 over Z_{2^32}");
    p.sacrifice_batch = 2;
    CHECK(validateCryptoParams(p).empty(), "C6c: 2 sacrifices enough for σ=40 over Z_{2^32}");

    p.mac_field_bits = 64;
    p.sigma_stat_bits = 80;
    p.sacrifice_batch = 1;    // NOT enough: ceil(80/64) = 2
    CHECK(!validateCryptoParams(p).empty(), "C6d: 1 sacrifice too few for σ=80 over Z_{2^64}");
    p.sacrifice_batch = 2;
    CHECK(validateCryptoParams(p).empty(), "C6e: 2 sacrifices enough for σ=80 over Z_{2^64}");
}

static void test_beaver_gt_sacrifice() {
    std::printf("--- C7: beaver_triple_batch > sacrifice_batch ---\n");
    MpsvsCryptoParams p;
    p.beaver_triple_batch = 100;
    p.sacrifice_batch = 100;
    CHECK(!validateCryptoParams(p).empty(), "C7a: equal rejected");
    p.sacrifice_batch = 99;
    CHECK(validateCryptoParams(p).empty(), "C7b: strictly less accepted");
}

static void test_ot_regime() {
    std::printf("--- C8: silent_ot_regime restricted ---\n");
    MpsvsCryptoParams p;
    p.silent_ot_regime = "SD";
    CHECK(validateCryptoParams(p).empty(), "C8a: SD accepted");
    p.silent_ot_regime = "EA";
    CHECK(validateCryptoParams(p).empty(), "C8b: EA accepted");
    p.silent_ot_regime = "XYZ";
    CHECK(!validateCryptoParams(p).empty(), "C8c: XYZ rejected");
}

// ==========================================================================
// Analytic bounds
// ==========================================================================

static void test_break_even_bucket() {
    std::printf("--- C9: breakEvenBucketCount matches expected ranges ---\n");
    // n = 10^4 → log2(n) ≈ 13.3 → B*/log2(B*) ≈ 13.3 → B* ~ 60-70
    double B10k = breakEvenBucketCount(10000);
    CHECK(B10k > 40.0 && B10k < 120.0, "C9a: B*(10^4) in [40, 120]");
    // n = 10^6 → log2(n) ≈ 20 → B* ~ 100-200
    double B1M = breakEvenBucketCount(1000000);
    CHECK(B1M > 80.0 && B1M < 250.0, "C9b: B*(10^6) in [80, 250]");
    // Monotone in n
    CHECK(B1M > B10k, "C9c: B* increases with n");
    std::printf("     B*(10^4)=%.1f  B*(10^6)=%.1f\n", B10k, B1M);
}

static void test_min_sacrifice_formula() {
    std::printf("--- C10: minSacrificeBatch formula ---\n");
    CHECK(minSacrificeBatch(40, 64) == 1,  "C10a: (40, 64) = 1");
    CHECK(minSacrificeBatch(40, 32) == 2,  "C10b: (40, 32) = 2");
    CHECK(minSacrificeBatch(80, 64) == 2,  "C10c: (80, 64) = 2");
    CHECK(minSacrificeBatch(128, 32) == 4, "C10d: (128, 32) = 4");
    CHECK(minSacrificeBatch(128, 128) == 1, "C10e: (128, 128) = 1");
}

static void test_max_dp_delta() {
    std::printf("--- C11: maxDpDelta = 2^{-σ} ---\n");
    double d40 = maxDpDelta(40);
    double d64 = maxDpDelta(64);
    CHECK(std::fabs(d40 - std::pow(2.0, -40)) < 1e-18, "C11a: d40 = 2^-40");
    CHECK(d64 < d40, "C11b: larger σ → smaller δ");
}

// ==========================================================================
// Hash + canonical form
// ==========================================================================

static void test_hash_deterministic_and_sensitive() {
    std::printf("--- C12: paramsHash deterministic + change-sensitive ---\n");
    MpsvsCryptoParams a, b;
    auto ha = a.paramsHash();
    auto hb = b.paramsHash();
    CHECK(std::memcmp(ha.data(), hb.data(), 32) == 0,
          "C12a: identical params → identical hash");
    b.lambda_bits += 1;
    auto hb2 = b.paramsHash();
    CHECK(std::memcmp(ha.data(), hb2.data(), 32) != 0,
          "C12b: change lambda → hash flips");
}

// ==========================================================================
// Cross-check with MpsvsConfig
// ==========================================================================

static void test_config_coherence_no_spurious_warnings() {
    std::printf("--- C13: minimal-warning setup produces only expected warnings ---\n");
    MpsvsCryptoParams cp;
    // Widen MAC to remove fp-overflow warning (Rev 7 §9 with default f=40
    // needs mac >= 128 for headroom without per-multiply rescaling).
    cp.mac_field_bits = 128;
    MpsvsConfig oc;
    // Tighten delta below 2^{-40} to remove DP soundness warning.
    oc.dp_delta = std::pow(2.0, -45);
    // bucket_count default = 128, B*(10^6) ≈ 143 — within [0.5·B*, 2·B*].
    auto warns = validateAgainstOperationalConfig(cp, oc);
    for (const auto& w : warns) std::printf("     warn: %s\n", w.c_str());
    CHECK(warns.empty(),
          "C13: no warnings once fp/mac ratio and delta/sigma are aligned");
}

static void test_default_config_flags_known_tensions() {
    std::printf("--- C13b: default MpsvsConfig + MpsvsCryptoParams surfaces known Rev 7 tensions ---\n");
    MpsvsCryptoParams cp;   // defaults
    MpsvsConfig oc;         // defaults
    auto warns = validateAgainstOperationalConfig(cp, oc);
    // Expect: dp_delta=1e-6 > 2^-40, and fp=40 with mac=64 requires rescaling.
    bool has_delta = false, has_fp = false;
    for (const auto& w : warns) {
        if (w.find("dp_delta") != std::string::npos) has_delta = true;
        if (w.find("fp_fractional_bits") != std::string::npos) has_fp = true;
    }
    CHECK(has_delta, "C13b-1: default delta triggers soundness warning");
    CHECK(has_fp,    "C13b-2: default fp/mac triggers overflow warning");
}

static void test_config_warns_on_weak_delta() {
    std::printf("--- C14: dp_delta > 2^{-σ} triggers warning ---\n");
    MpsvsCryptoParams cp;
    cp.sigma_stat_bits = 40;
    MpsvsConfig oc;
    oc.dp_delta = 0.01;   // > 2^{-40}
    auto warns = validateAgainstOperationalConfig(cp, oc);
    bool has_delta_warn = false;
    for (const auto& w : warns) if (w.find("dp_delta") != std::string::npos) has_delta_warn = true;
    CHECK(has_delta_warn, "C14: dp_delta warning present");
}

static void test_config_warns_on_bad_bucket() {
    std::printf("--- C15: bucket_count outside break-even range warns ---\n");
    MpsvsCryptoParams cp;
    MpsvsConfig oc;
    oc.dp_delta = std::pow(2.0, -45);   // suppress the delta warning
    oc.bucket_count = 4;   // way below B*(10^6) ≈ 140
    auto warns = validateAgainstOperationalConfig(cp, oc);
    bool has_b_warn = false;
    for (const auto& w : warns)
        if (w.find("bucket_count") != std::string::npos) has_b_warn = true;
    CHECK(has_b_warn, "C15a: too-small bucket_count warns");

    oc.bucket_count = 2048;   // way above 2·B*
    warns = validateAgainstOperationalConfig(cp, oc);
    has_b_warn = false;
    for (const auto& w : warns)
        if (w.find("bucket_count") != std::string::npos) has_b_warn = true;
    CHECK(has_b_warn, "C15b: too-large bucket_count warns");
}

static void test_config_warns_on_fp_overflow() {
    std::printf("--- C16: fp_fractional_bits close to mac/2 warns ---\n");
    MpsvsCryptoParams cp;
    cp.mac_field_bits = 64;
    MpsvsConfig oc;
    oc.dp_delta = std::pow(2.0, -45);
    oc.fp_fractional_bits = 30;   // 2·30 + 20 = 80 > 64 → warn
    auto warns = validateAgainstOperationalConfig(cp, oc);
    bool has_fp_warn = false;
    for (const auto& w : warns)
        if (w.find("fp_fractional_bits") != std::string::npos) has_fp_warn = true;
    CHECK(has_fp_warn, "C16: fp overflow warning present");
}

int main() {
    std::printf("=== MPSVS CryptoParams (security-proof parameters) ===\n\n");
    test_defaults_validate();
    test_lambda_floor();
    test_sigma_floor();
    test_mac_field_bits();
    test_oprf_group();
    test_sacrifice_bound();
    test_beaver_gt_sacrifice();
    test_ot_regime();
    test_break_even_bucket();
    test_min_sacrifice_formula();
    test_max_dp_delta();
    test_hash_deterministic_and_sensitive();
    test_config_coherence_no_spurious_warnings();
    test_default_config_flags_known_tensions();
    test_config_warns_on_weak_delta();
    test_config_warns_on_bad_bucket();
    test_config_warns_on_fp_overflow();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — crypto params bound to math-tool thresholds.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
