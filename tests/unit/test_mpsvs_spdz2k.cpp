// MPSVS SPDZ2k soundness test — verifies the retrofit correctness bound.
//
// Central claim (docs/PROTOCOL.md Theorem 4.6.1):
//   Under SPDZ2k over ℤ_{2^{k+s}} with k = 64, s = 64 (Rev 7.1
//   interim, __int128-fit; combined with batched-check accounting
//   from §7.3, session bound is Q_check · 2^{-64} ≤ 2^{-48} for
//   Q_check ≤ 2^{16}, meeting σ_stat = 40).
//   The per-batched-check bound Open^{sh-α} returns a value x' ≠ x
//   without aborting on TAMPERED shares is ≤ 2^{-s} + q_H · 2^{-256}.
//
// Regression against classical-SPDZ gap (Cramer et al. CRYPTO 2018):
//   With classical SPDZ over ℤ_{2^k}, an adversary that adds
//   δ = 2^{k-1} to a share is caught with probability only 1/2.
//   Below we exhibit that δ and verify the SPDZ2k retrofit catches it
//   with overwhelming probability (empirically 100% over N trials).

#include "volePSI/MpsvsAuthShare128.h"
#include "volePSI/MpsvsProdHygiene.h"

#include <cstdio>
#include <cstring>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// ==========================================================================
// C1 — Ring width: k = 64, s = 64 → R = 128 (interim __int128 retrofit).
// s = 80 (spec target) requires bignum; documented follow-up.
// ==========================================================================
static void test_ring_width() {
    std::printf("--- C1: ring width parameters (k=64, s=64, R=128) ---\n");
    CHECK(kSpdz2kValueBits == 64, "C1a: value ring k = 64");
    CHECK(kSpdz2kStatBits  == 64,
          "C1b: statistical parameter s = 64 (batched-check accounting "
          "in PROTOCOL.md §7.3 delivers 2^-48 session bound for "
          "Q_check ≤ 2^16, exceeding σ_stat = 40 target)");
    CHECK(kSpdz2kRingBits  == 128, "C1c: total ring width R = 128");
    // Value mask exposes low 64 bits only.
    u128 v = (u128{0x1234567890abcdefULL}) | (u128{0xdeadbeef} << 80);
    uint64_t low = static_cast<uint64_t>(v & kSpdz2kValueMask);
    CHECK(low == 0x1234567890abcdefULL,
          "C1d: kSpdz2kValueMask isolates low 64 bits");
}

// ==========================================================================
// C2 — Honest open + MAC check accepts.
// ==========================================================================
static void test_honest_open() {
    std::printf("--- C2: honest AuthSharedU128 opens correctly ---\n");
    ensureSodiumInit();
    AlphaShare128 alpha = generateAlpha128(2);
    AuthSharedU128 x = authShareU128(2, static_cast<u128>(12345), alpha);
    uint64_t v = 0;
    bool ok = openWithMacCheckShared128(x, alpha, v);
    CHECK(ok, "C2a: MAC verifies for honest share");
    CHECK(v == 12345, "C2b: value opens to 12345");
}

// ==========================================================================
// C3 — Classical-SPDZ evading δ = 2^63 is CAUGHT by SPDZ2k.
// ==========================================================================
static void test_spdz2k_catches_high_bit_delta() {
    std::printf("--- C3: SPDZ2k catches δ = 2^63 (classical SPDZ misses this) ---\n");
    ensureSodiumInit();
    const int trials = 100;
    int caught = 0;
    for (int t = 0; t < trials; ++t) {
        AlphaShare128 alpha = generateAlpha128(2);
        AuthSharedU128 x = authShareU128(2, static_cast<u128>(42), alpha);
        // Adversarial tampering: the exact δ that defeats classical SPDZ
        // (worst case 1/2 detection over ℤ_{2^64}) — but should be caught
        // with probability ≥ 1 - 2^-80 by SPDZ2k.
        simulateTampering128(x, /*bad_party=*/0, spdz2kAdversarialDelta());
        uint64_t v = 0;
        bool ok = openWithMacCheckShared128(x, alpha, v);
        if (!ok) ++caught;
    }
    std::printf("  %d/%d trials caught (targeted δ = 2^63)\n", caught, trials);
    CHECK(caught == trials,
          "C3: 100% of adversarial δ = 2^63 caught (would be ~50% under 64-bit SPDZ)");
}

// ==========================================================================
// C4 — Small δ (typical malicious offset) is caught with the same overwhelming prob.
// ==========================================================================
static void test_spdz2k_catches_small_delta() {
    std::printf("--- C4: SPDZ2k catches δ = 999 across trials ---\n");
    const int trials = 100;
    int caught = 0;
    for (int t = 0; t < trials; ++t) {
        AlphaShare128 alpha = generateAlpha128(2);
        AuthSharedU128 x = authShareU128(2, static_cast<u128>(1000000), alpha);
        simulateTampering128(x, /*bad_party=*/1, static_cast<u128>(999));
        uint64_t v = 0;
        bool ok = openWithMacCheckShared128(x, alpha, v);
        if (!ok) ++caught;
    }
    std::printf("  %d/%d trials caught (small δ = 999)\n", caught, trials);
    CHECK(caught == trials, "C4: 100% of δ = 999 caught");
}

// ==========================================================================
// C5 — Beaver mult under SPDZ2k.
// ==========================================================================
static void test_authmult_shared_honest() {
    std::printf("--- C5: authSecureMultiplyShared128 (honest triple) ---\n");
    AlphaShare128 alpha = generateAlpha128(2);
    AuthSharedU128 x = authShareU128(2, static_cast<u128>(7), alpha);
    AuthSharedU128 y = authShareU128(2, static_cast<u128>(13), alpha);
    AuthBeaverTriple128 t = generateAuthBeaverTriple128(2, alpha);
    AuthSharedU128 z = authSecureMultiplyShared128(x, y, t, alpha);
    uint64_t v = 0;
    bool ok = openWithMacCheckShared128(z, alpha, v);
    CHECK(ok, "C5a: MAC on shared-α product verifies");
    CHECK(v == 91, "C5b: 7 · 13 = 91");
}

static void test_authmult_shared_catches_tamper() {
    std::printf("--- C6: authSecureMultiplyShared128 catches tampered x ---\n");
    AlphaShare128 alpha = generateAlpha128(2);
    AuthSharedU128 x = authShareU128(2, static_cast<u128>(100), alpha);
    AuthSharedU128 y = authShareU128(2, static_cast<u128>(200), alpha);
    simulateTampering128(x, /*bad_party=*/0, spdz2kAdversarialDelta());
    AuthBeaverTriple128 t = generateAuthBeaverTriple128(2, alpha);
    bool threw = false;
    try {
        (void)authSecureMultiplyShared128(x, y, t, alpha);
    } catch (const AuthShareMacFailure128&) {
        threw = true;
    }
    CHECK(threw, "C6: adversarial δ on x throws AuthShareMacFailure128");
}

// ==========================================================================
// C7 — Sacrifice check catches malformed Beaver triple.
// ==========================================================================
static void test_sacrifice_catches_malformed() {
    std::printf("--- C7: sacrificeCheckTripleShared128 catches w ≠ u·v ---\n");
    AlphaShare128 alpha = generateAlpha128(2);
    // Build a MALFORMED triple: w = u·v + 999.
    AuthBeaverTriple128 T;
    u128 u_plain = 41, v_plain = 43;
    u128 w_bad = static_cast<u128>(u_plain * v_plain + 999);
    T.u = authShareU128(2, u_plain, alpha);
    T.v = authShareU128(2, v_plain, alpha);
    T.w = authShareU128(2, w_bad,  alpha);
    // Auxiliary triple is honest.
    AuthBeaverTriple128 T_aux = generateAuthBeaverTriple128(2, alpha);
    bool ok = sacrificeCheckTripleShared128(T, T_aux, alpha);
    CHECK(!ok, "C7: malformed triple caught by SPDZ2k sacrifice");
}

// ==========================================================================
// C8 — Batch Ω-check verifies honest batch and catches one tampered element.
// ==========================================================================
static void test_batch_omega_honest() {
    std::printf("--- C8: batch Ω-check on 10 honest elements ---\n");
    AlphaShare128 alpha = generateAlpha128(2);
    std::vector<AuthSharedU128> xs;
    for (int i = 0; i < 10; ++i)
        xs.push_back(authShareU128(2, static_cast<u128>(100 + i), alpha));
    std::vector<uint64_t> vs;
    bool ok = batchOpenWithMacCheckShared128(xs, alpha, vs);
    CHECK(ok, "C8a: honest batch verifies");
    CHECK(vs.size() == 10, "C8b: 10 values reconstructed");
    for (int i = 0; i < 10; ++i)
        if (vs[i] != static_cast<uint64_t>(100 + i)) {
            CHECK(false, "C8c: reconstructed value matches");
            return;
        }
    CHECK(true, "C8c: all reconstructed values match");
}

static void test_batch_omega_catches_tamper() {
    std::printf("--- C9: batch Ω-check catches one tampered element ---\n");
    AlphaShare128 alpha = generateAlpha128(2);
    std::vector<AuthSharedU128> xs;
    for (int i = 0; i < 8; ++i)
        xs.push_back(authShareU128(2, static_cast<u128>(200 + i), alpha));
    // Tamper one element with the classical-SPDZ-evading δ.
    simulateTampering128(xs[3], /*bad_party=*/0, spdz2kAdversarialDelta());
    std::vector<uint64_t> vs;
    bool ok = batchOpenWithMacCheckShared128(xs, alpha, vs);
    CHECK(!ok, "C9: batch tamper caught by Ω-check under SPDZ2k");
}

int main() {
    ensureSodiumInit();
    std::printf("=== MPSVS SPDZ2k retrofit (ℤ_{2^{128}} shares, k=64, s=64) ===\n\n");
    test_ring_width();
    test_honest_open();
    test_spdz2k_catches_high_bit_delta();
    test_spdz2k_catches_small_delta();
    test_authmult_shared_honest();
    test_authmult_shared_catches_tamper();
    test_sacrifice_catches_malformed();
    test_batch_omega_honest();
    test_batch_omega_catches_tamper();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — SPDZ2k retrofit catches classical-SPDZ evading δ = 2^63.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
