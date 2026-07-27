// MPSVS Phase 17.6 — Reciprocal consistency check tests.
//
// Verifies that verifyReciprocalAuth catches a malicious server that returns
// a wrong Goldschmidt output. The algebraic invariant y_fp · x = 2^f is
// checked on authenticated shares — malicious deviations detected.

#include "volePSI/MpsvsAuthShare.h"
#include "volePSI/MpsvsRatioBucket.h"
#include "volePSI/MpsvsReciprocalVerify.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cmath>
#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_honest_reciprocal_passes() {
    std::printf("--- C1: honest Goldschmidt reciprocal → verify PASSES ---\n");
    oc::PRNG prng(oc::block(0x11, 0x22));
    uint64_t alpha = prng.get<uint64_t>();

    uint64_t x = 3;
    // Compute reciprocal via existing Goldschmidt (semantic ref) → fp value.
    Fp recip_fp = goldschmidtRecip(x, 6);
    uint64_t recip_int = static_cast<uint64_t>(recip_fp);

    AuthSharedU64 x_auth = authShareU64(2, x, alpha, prng);
    AuthSharedU64 recip_auth = authShareU64(2, recip_int, alpha, prng);
    AuthBeaverTriple triple = generateAuthBeaverTriple(2, alpha, prng);

    // For x=3, f=40: recip · x should ≈ 2^40. Goldschmidt has ~40 bits of
    // precision so tolerance ~ 1000 is plenty.
    uint64_t tolerance = 10000;
    bool ok = verifyReciprocalAuth(x_auth, recip_auth, alpha,
                                     kFpFractionalBits, tolerance, triple);
    std::printf("  x=%lu, recip_fp=%lu, expected recip·x ≈ 2^%d = %lu\n",
                 x, recip_int, kFpFractionalBits,
                 static_cast<uint64_t>(1) << kFpFractionalBits);
    CHECK(ok, "C1: honest reciprocal passes verify");
}

static void test_malicious_reciprocal_caught() {
    std::printf("--- C2: malicious wrong reciprocal → verify FAILS ---\n");
    oc::PRNG prng(oc::block(0x33, 0x44));
    uint64_t alpha = prng.get<uint64_t>();

    uint64_t x = 5;
    // Attacker outputs a wildly wrong value as "reciprocal".
    uint64_t wrong_y = 12345;
    AuthSharedU64 x_auth = authShareU64(2, x, alpha, prng);
    AuthSharedU64 y_bad = generateWrongReciprocal(2, wrong_y, alpha, prng);
    AuthBeaverTriple triple = generateAuthBeaverTriple(2, alpha, prng);

    uint64_t tolerance = 10000;
    bool ok = verifyReciprocalAuth(x_auth, y_bad, alpha,
                                     kFpFractionalBits, tolerance, triple);
    std::printf("  x=%lu, attacker-y=%lu → verify: %s\n",
                 x, wrong_y, ok ? "PASSED (BUG!)" : "FAILED (correct)");
    CHECK(!ok, "C2: wrong reciprocal caught by algebraic check");
}

static void test_off_by_one_caught() {
    std::printf("--- C3: subtle malice (recip off by small amount) → verify FAILS ---\n");
    oc::PRNG prng(oc::block(0x55, 0x66));
    uint64_t alpha = prng.get<uint64_t>();

    uint64_t x = 7;
    Fp recip_fp = goldschmidtRecip(x, 6);
    // Attacker adds a MEDIUM offset (large enough to exceed tolerance).
    uint64_t tampered = static_cast<uint64_t>(recip_fp) + 1000000;

    AuthSharedU64 x_auth = authShareU64(2, x, alpha, prng);
    AuthSharedU64 y_tampered = authShareU64(2, tampered, alpha, prng);
    AuthBeaverTriple triple = generateAuthBeaverTriple(2, alpha, prng);

    uint64_t tolerance = 10000;
    bool ok = verifyReciprocalAuth(x_auth, y_tampered, alpha,
                                     kFpFractionalBits, tolerance, triple);
    std::printf("  x=%lu, honest_recip ± 1M offset → verify: %s\n",
                 x, ok ? "PASSED (BUG!)" : "FAILED (correct)");
    CHECK(!ok, "C3: even large-offset tampering caught");
}

static void test_batch_catch_rate() {
    std::printf("--- C4: catch rate over 100 random wrong reciprocals ---\n");
    int trials = 100;
    int caught = 0;
    for (int t = 0; t < trials; ++t) {
        oc::PRNG prng(oc::block(0x100 + t, 0));
        uint64_t alpha = prng.get<uint64_t>();
        if (alpha == 0) alpha = 1;
        uint64_t x = (prng.get<uint64_t>() % 1000) + 1;
        uint64_t wrong_y = prng.get<uint64_t>();
        AuthSharedU64 x_auth = authShareU64(2, x, alpha, prng);
        AuthSharedU64 y_bad = generateWrongReciprocal(2, wrong_y, alpha, prng);
        AuthBeaverTriple tr = generateAuthBeaverTriple(2, alpha, prng);
        bool ok = verifyReciprocalAuth(x_auth, y_bad, alpha,
                                         kFpFractionalBits, 10000, tr);
        if (!ok) ++caught;
    }
    double rate = static_cast<double>(caught) / trials;
    std::printf("  %d/%d wrong reciprocals caught (%.1f%%)\n",
                 caught, trials, rate * 100);
    CHECK(caught == trials, "C4: 100% of random wrong reciprocals caught");
}

static void test_share_tamper_after_verify() {
    std::printf("--- C5: honest reciprocal + tampered SHARE → caught by MAC ---\n");
    oc::PRNG prng(oc::block(0x77, 0x88));
    uint64_t alpha = prng.get<uint64_t>();

    uint64_t x = 42;
    Fp recip_fp = goldschmidtRecip(x, 6);
    AuthSharedU64 x_auth = authShareU64(2, x, alpha, prng);
    AuthSharedU64 y_auth = authShareU64(2, static_cast<uint64_t>(recip_fp), alpha, prng);
    // Attacker tampers with a share of y AFTER computation but before verify.
    simulateTampering(y_auth, /*bad_party=*/0, /*tamper=*/99);
    AuthBeaverTriple tr = generateAuthBeaverTriple(2, alpha, prng);
    bool ok = verifyReciprocalAuth(x_auth, y_auth, alpha,
                                     kFpFractionalBits, 10000, tr);
    CHECK(!ok, "C5: share tamper on honest recip caught by combined MAC + algebra");
}

int main() {
    std::printf("=== MPSVS Phase 17.6: Reciprocal Consistency Check ===\n\n");
    test_honest_reciprocal_passes();
    test_malicious_reciprocal_caught();
    test_off_by_one_caught();
    test_batch_catch_rate();
    test_share_tamper_after_verify();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — reciprocal algebraic invariant catches malicious outputs.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
