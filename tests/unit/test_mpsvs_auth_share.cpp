// MPSVS Phase 17.1 — MAC-authenticated shares: correctness + malicious detection.
//
// Two claims tested:
//
//   CLAIM 1 (correctness): honest arithmetic preserves MACs.
//     For every supported op (add, sub, add-const, mul-const, secure-mul),
//     the resulting AuthSharedU64 opens correctly with MAC verification.
//
//   CLAIM 2 (malicious detection): any single-party tampering is caught.
//     Simulate a dishonest party corrupting its share of a value.
//     openWithMacCheck must return FALSE — attack DETECTED.

#include "volePSI/MpsvsAuthShare.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <random>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_honest_add() {
    std::printf("--- C1a: honest add preserves MAC ---\n");
    oc::PRNG prng(oc::block(0x1, 0x2));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 100, alpha, prng);
    AuthSharedU64 y = authShareU64(2, 250, alpha, prng);
    AuthSharedU64 z = authAdd(x, y);
    uint64_t out = 0;
    bool ok = openWithMacCheck(z, alpha, out);
    CHECK(ok, "C1a: add MAC verifies");
    CHECK(out == 350, "C1a: add value correct (100+250=350)");
}

static void test_honest_sub() {
    std::printf("--- C1b: honest sub preserves MAC ---\n");
    oc::PRNG prng(oc::block(0x3, 0x4));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 500, alpha, prng);
    AuthSharedU64 y = authShareU64(2, 200, alpha, prng);
    AuthSharedU64 z = authSub(x, y);
    uint64_t out = 0;
    bool ok = openWithMacCheck(z, alpha, out);
    CHECK(ok, "C1b: sub MAC verifies");
    CHECK(out == 300, "C1b: sub value correct");
}

static void test_honest_add_const() {
    std::printf("--- C1c: honest add-const preserves MAC ---\n");
    oc::PRNG prng(oc::block(0x5, 0x6));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 100, alpha, prng);
    AuthSharedU64 z = authAddConst(x, 42, alpha);
    uint64_t out = 0;
    bool ok = openWithMacCheck(z, alpha, out);
    CHECK(ok, "C1c: add-const MAC verifies");
    CHECK(out == 142, "C1c: add-const value correct");
}

static void test_honest_mul_const() {
    std::printf("--- C1d: honest mul-const preserves MAC ---\n");
    oc::PRNG prng(oc::block(0x7, 0x8));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 100, alpha, prng);
    AuthSharedU64 z = authMulConst(x, 5);
    uint64_t out = 0;
    bool ok = openWithMacCheck(z, alpha, out);
    CHECK(ok, "C1d: mul-const MAC verifies");
    CHECK(out == 500, "C1d: mul-const value correct (100*5=500)");
}

static void test_honest_secure_mul() {
    std::printf("--- C1e: honest secure mul preserves MAC ---\n");
    oc::PRNG prng(oc::block(0x9, 0xa));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 12, alpha, prng);
    AuthSharedU64 y = authShareU64(2, 30, alpha, prng);
    AuthBeaverTriple triple = generateAuthBeaverTriple(2, alpha, prng);
    AuthSharedU64 z = authSecureMultiply(x, y, triple, alpha);
    uint64_t out = 0;
    bool ok = openWithMacCheck(z, alpha, out);
    CHECK(ok, "C1e: secure-mul MAC verifies");
    CHECK(out == 360, "C1e: secure-mul value correct (12*30=360)");
}

// ==========================================================================
// Malicious tests — verify tampering is caught by the MAC check.
// ==========================================================================

static void test_malicious_tamper_value() {
    std::printf("--- C2a: dishonest party tampers with value share → DETECTED ---\n");
    oc::PRNG prng(oc::block(0x11, 0x22));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 1000, alpha, prng);
    // Attacker (party 0) adds 500 to their value share without touching MAC.
    simulateTampering(x, /*bad_party=*/0, /*tamper=*/500);
    uint64_t out = 0;
    bool ok = openWithMacCheck(x, alpha, out);
    std::printf("  attacker added 500 to value share; MAC check: %s\n",
                 ok ? "PASSED (BUG)" : "FAILED (correct)");
    CHECK(!ok, "C2a: MAC check DETECTS value tampering by party 0");
    // The reconstruction gave the wrong value (1500 instead of 1000),
    // but the MAC = α·1000 ≠ α·1500, so the check catches it.
}

static void test_malicious_tamper_after_add() {
    std::printf("--- C2b: tamper after computation → DETECTED ---\n");
    oc::PRNG prng(oc::block(0x33, 0x44));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 100, alpha, prng);
    AuthSharedU64 y = authShareU64(2, 200, alpha, prng);
    AuthSharedU64 z = authAdd(x, y);
    // Attacker tampers with z's share after the add.
    simulateTampering(z, /*bad_party=*/1, /*tamper=*/9999);
    uint64_t out = 0;
    bool ok = openWithMacCheck(z, alpha, out);
    CHECK(!ok, "C2b: MAC check DETECTS post-computation tampering");
}

static void test_malicious_tamper_after_mul() {
    std::printf("--- C2c: tamper after secure-mul → DETECTED ---\n");
    oc::PRNG prng(oc::block(0x55, 0x66));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 7, alpha, prng);
    AuthSharedU64 y = authShareU64(2, 8, alpha, prng);
    AuthBeaverTriple triple = generateAuthBeaverTriple(2, alpha, prng);
    AuthSharedU64 z = authSecureMultiply(x, y, triple, alpha);
    simulateTampering(z, /*bad_party=*/0, /*tamper=*/1);
    uint64_t out = 0;
    bool ok = openWithMacCheck(z, alpha, out);
    CHECK(!ok, "C2c: MAC check catches tampering post-secure-mul");
}

// Note: the "attacker forges a matching MAC" scenario requires knowing α,
// which no single party has (α is additively shared). Any tampering to the
// value without simultaneous consistent MAC tampering FAILS the check.
static void test_malicious_forge_requires_alpha() {
    std::printf("--- C2d: forging valid tamper requires knowing α ---\n");
    oc::PRNG prng(oc::block(0x77, 0x88));
    uint64_t alpha = prng.get<uint64_t>();
    AuthSharedU64 x = authShareU64(2, 100, alpha, prng);
    // Attacker knows α somehow (worst case): can tamper both value and MAC
    // consistently. Verify this succeeds (which is why we NEED to protect α).
    uint64_t tamper = 42;
    x.value.shares[0] += tamper;
    x.mac.shares[0] += alpha * tamper;   // attacker with knowledge of α
    uint64_t out = 0;
    bool ok = openWithMacCheck(x, alpha, out);
    CHECK(ok, "C2d: attacker with α CAN forge (this is why α must stay shared)");
    CHECK(out == 100 + tamper, "C2d: forged value passes MAC check");
    std::printf("  ⇒ Security relies on α being additively shared and never opened.\n");
    std::printf("     In real MPSVS deployment, α is jointly sampled and never revealed.\n");
}

// ==========================================================================
// Statistical: over N runs, verify EVERY tampering attempt is caught.
// ==========================================================================
static void test_batch_malicious_detection() {
    std::printf("--- C3: batch malicious detection — 100%% catch rate ---\n");
    oc::PRNG prng(oc::block(0x99, 0xaa));
    const int N = 500;
    int caught = 0, missed = 0;
    for (int t = 0; t < N; ++t) {
        oc::PRNG p(oc::block(0xc0 + t, 0));
        uint64_t alpha = p.get<uint64_t>();
        if (alpha == 0) alpha = 1;
        uint64_t value = p.get<uint64_t>() & 0xffff;   // small values
        AuthSharedU64 x = authShareU64(2, value, alpha, p);
        // Attacker tampers with a random party's share by a random nonzero amount.
        uint64_t tamper = (p.get<uint64_t>() & 0xff) + 1;   // 1..256
        uint32_t bad = t % 2;
        simulateTampering(x, bad, tamper);
        uint64_t out = 0;
        bool ok = openWithMacCheck(x, alpha, out);
        if (ok) ++missed; else ++caught;
    }
    std::printf("  %d/%d tampering attempts CAUGHT by MAC check\n", caught, N);
    CHECK(caught == N, "C3: 100% of tampering attempts detected");
    CHECK(missed == 0, "C3: 0 false negatives");
}

int main() {
    std::printf("=== MPSVS Phase 17.1: MAC-authenticated shares ===\n\n");
    test_honest_add();
    test_honest_sub();
    test_honest_add_const();
    test_honest_mul_const();
    test_honest_secure_mul();
    test_malicious_tamper_value();
    test_malicious_tamper_after_add();
    test_malicious_tamper_after_mul();
    test_malicious_forge_requires_alpha();
    test_batch_malicious_detection();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — MAC-authenticated shares detect all single-party tampering.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
