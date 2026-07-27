// MPSVS end-to-end shared-α (DPSZ) exercise:
//   - authSecureMultiplyShared: Beaver mult without reconstructing α
//   - sacrificeCheckTripleShared: triple validation without reconstructing α
//   - verifyReciprocalAuthShared: reciprocal invariant check without α
//
// Confirms the malicious-secure primitive is wired all the way through
// the SPDZ operator chain, not just at the open-check boundary.

#include "volePSI/MpsvsAuthShare.h"
#include "volePSI/MpsvsReciprocalVerify.h"
#include "volePSI/MpsvsProdHygiene.h"
#include "volePSI/MpsvsRatioBucket.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <cstring>

using namespace volePSI::mpsvs;
using volePSI::mpstar::SharedU64;
using volePSI::mpstar::shareU64;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// Build an AuthSharedU64 under the shared α (α = α_1 + α_2). This helper
// is what a real preprocessing phase would produce; here we compute MAC
// = α·value locally (reconstructing α *only* for share-construction in the
// test harness — the operators under test never reconstruct it).
static AuthSharedU64 makeAuth(uint64_t value, const AlphaShare& alpha,
                                oc::PRNG& prng) {
    uint64_t alpha_recon = alpha.alpha_share.reconstruct();
    uint64_t mac = alpha_recon * value;
    AuthSharedU64 s;
    s.value = shareU64(2, value, prng);
    s.mac   = shareU64(2, mac,   prng);
    return s;
}

// Build a valid auth Beaver triple under shared α.
static AuthBeaverTriple makeTriple(uint64_t u, uint64_t v,
                                     const AlphaShare& alpha,
                                     oc::PRNG& prng) {
    AuthBeaverTriple t;
    t.u = makeAuth(u,     alpha, prng);
    t.v = makeAuth(v,     alpha, prng);
    t.w = makeAuth(u * v, alpha, prng);
    return t;
}

// ==========================================================================
// authSecureMultiplyShared
// ==========================================================================

static void test_mult_shared_honest() {
    std::printf("--- C1: authSecureMultiplyShared honest x·y verifies ---\n");
    ensureSodiumInit();
    oc::PRNG prng(oc::block(0x1001, 0x2002));
    AlphaShare alpha = generateAlpha(2, prng);
    AuthSharedU64 x = makeAuth(7,  alpha, prng);
    AuthSharedU64 y = makeAuth(13, alpha, prng);
    AuthBeaverTriple t = makeTriple(3, 5, alpha, prng);
    AuthSharedU64 z = authSecureMultiplyShared(x, y, t, alpha);
    uint64_t z_val = 0;
    bool ok = openWithMacCheckShared(z, alpha, z_val);
    CHECK(ok, "C1a: MAC on shared-α product verifies");
    CHECK(z_val == 7ull * 13ull, "C1b: value = 91");
}

static void test_mult_shared_tamper_x() {
    std::printf("--- C2: tamper x → throws AuthShareMacFailure ---\n");
    oc::PRNG prng(oc::block(0x3003, 0x4004));
    AlphaShare alpha = generateAlpha(2, prng);
    AuthSharedU64 x = makeAuth(100, alpha, prng);
    AuthSharedU64 y = makeAuth(200, alpha, prng);
    x.value.shares[0] += 999;   // party 0 tampers with x
    AuthBeaverTriple t = makeTriple(11, 17, alpha, prng);
    bool threw = false;
    try {
        (void)authSecureMultiplyShared(x, y, t, alpha);
    } catch (const AuthShareMacFailure&) {
        threw = true;
    }
    CHECK(threw, "C2: MAC-failure exception fired on tampered x");
}

static void test_mult_shared_chained() {
    std::printf("--- C3: chained mults (a·b·c) via shared-α ---\n");
    oc::PRNG prng(oc::block(0x5005, 0x6006));
    AlphaShare alpha = generateAlpha(2, prng);
    AuthSharedU64 a = makeAuth(2,  alpha, prng);
    AuthSharedU64 b = makeAuth(3,  alpha, prng);
    AuthSharedU64 c = makeAuth(5,  alpha, prng);
    AuthBeaverTriple t1 = makeTriple(11, 13, alpha, prng);
    AuthBeaverTriple t2 = makeTriple(17, 19, alpha, prng);
    AuthSharedU64 ab  = authSecureMultiplyShared(a,  b, t1, alpha);
    AuthSharedU64 abc = authSecureMultiplyShared(ab, c, t2, alpha);
    uint64_t v = 0;
    bool ok = openWithMacCheckShared(abc, alpha, v);
    CHECK(ok, "C3a: chained shared-α product verifies");
    CHECK(v == 30, "C3b: a·b·c = 2·3·5 = 30");
}

// ==========================================================================
// sacrificeCheckTripleShared
// ==========================================================================

static void test_sacrifice_shared_honest() {
    std::printf("--- C4: sacrificeCheckTripleShared accepts honest triples ---\n");
    oc::PRNG prng(oc::block(0x7007, 0x8008));
    AlphaShare alpha = generateAlpha(2, prng);
    AuthBeaverTriple T     = makeTriple(23, 29, alpha, prng);
    AuthBeaverTriple T_aux = makeTriple(31, 37, alpha, prng);
    bool ok = sacrificeCheckTripleShared(T, T_aux, alpha);
    CHECK(ok, "C4: honest triples pass shared-α sacrifice check");
}

static void test_sacrifice_shared_malformed_caught() {
    std::printf("--- C5: sacrificeCheckTripleShared catches w ≠ u·v ---\n");
    oc::PRNG prng(oc::block(0x9009, 0xA00A));
    AlphaShare alpha = generateAlpha(2, prng);
    // Malformed T: w has the wrong value.
    AuthBeaverTriple T;
    T.u = makeAuth(41, alpha, prng);
    T.v = makeAuth(43, alpha, prng);
    T.w = makeAuth(41ull * 43ull + 999, alpha, prng);   // offset by 999
    AuthBeaverTriple T_aux = makeTriple(47, 53, alpha, prng);
    bool ok = sacrificeCheckTripleShared(T, T_aux, alpha);
    CHECK(!ok, "C5: shared-α sacrifice catches malformed triple");
}

// ==========================================================================
// verifyReciprocalAuthShared
// ==========================================================================

static void test_reciprocal_shared_honest() {
    std::printf("--- C6: verifyReciprocalAuthShared accepts honest recip ---\n");
    oc::PRNG prng(oc::block(0xB00B, 0xC00C));
    AlphaShare alpha = generateAlpha(2, prng);
    uint64_t x = 7;
    Fp recip_fp = goldschmidtRecip(x, 6);
    AuthSharedU64 x_auth = makeAuth(x, alpha, prng);
    AuthSharedU64 y_auth = makeAuth(static_cast<uint64_t>(recip_fp), alpha, prng);
    AuthBeaverTriple tr  = makeTriple(101, 103, alpha, prng);
    bool ok = verifyReciprocalAuthShared(x_auth, y_auth, alpha,
                                            kFpFractionalBits, 10000, tr);
    CHECK(ok, "C6: honest reciprocal verified via shared-α");
}

static void test_reciprocal_shared_wrong_caught() {
    std::printf("--- C7: verifyReciprocalAuthShared catches wrong y ---\n");
    oc::PRNG prng(oc::block(0xD00D, 0xE00E));
    AlphaShare alpha = generateAlpha(2, prng);
    uint64_t x = 42;
    AuthSharedU64 x_auth = makeAuth(x, alpha, prng);
    // Wrong y (unrelated to 1/x)
    AuthSharedU64 y_auth = makeAuth(0xDEADBEEFull, alpha, prng);
    AuthBeaverTriple tr  = makeTriple(109, 113, alpha, prng);
    bool ok = verifyReciprocalAuthShared(x_auth, y_auth, alpha,
                                            kFpFractionalBits, 10000, tr);
    CHECK(!ok, "C7: wrong reciprocal caught");
}

static void test_reciprocal_shared_share_tamper() {
    std::printf("--- C8: shared-α reciprocal catches share tamper via MAC ---\n");
    oc::PRNG prng(oc::block(0xF00F, 0x1010));
    AlphaShare alpha = generateAlpha(2, prng);
    uint64_t x = 42;
    Fp recip_fp = goldschmidtRecip(x, 6);
    AuthSharedU64 x_auth = makeAuth(x, alpha, prng);
    AuthSharedU64 y_auth = makeAuth(static_cast<uint64_t>(recip_fp), alpha, prng);
    // Party 1 tampers with y's share.
    y_auth.value.shares[1] += 77;
    AuthBeaverTriple tr = makeTriple(127, 131, alpha, prng);
    bool ok = verifyReciprocalAuthShared(x_auth, y_auth, alpha,
                                            kFpFractionalBits, 10000, tr);
    CHECK(!ok, "C8: share-level tamper caught by shared-α MAC");
}

// ==========================================================================
// α confidentiality end-to-end
// ==========================================================================

static void test_alpha_never_touched_by_operators() {
    std::printf("--- C9: shared-α operators take AlphaShare by const-ref ---\n");
    // Static assertion — enforced at compile time.
    static_assert(std::is_same<
        decltype(&authSecureMultiplyShared),
        AuthSharedU64(*)(const AuthSharedU64&, const AuthSharedU64&,
                          const AuthBeaverTriple&, const AlphaShare&)>::value,
        "authSecureMultiplyShared signature must take AlphaShare, not uint64_t");
    static_assert(std::is_same<
        decltype(&sacrificeCheckTripleShared),
        bool(*)(const AuthBeaverTriple&, const AuthBeaverTriple&,
                 const AlphaShare&)>::value,
        "sacrificeCheckTripleShared signature must take AlphaShare, not uint64_t");
    static_assert(std::is_same<
        decltype(&verifyReciprocalAuthShared),
        bool(*)(const AuthSharedU64&, const AuthSharedU64&, const AlphaShare&,
                 uint32_t, uint64_t, const AuthBeaverTriple&)>::value,
        "verifyReciprocalAuthShared signature must take AlphaShare, not uint64_t");
    CHECK(true, "C9: all three operators bind AlphaShare at type level");
}

int main() {
    ensureSodiumInit();
    std::printf("=== MPSVS shared-α end-to-end (Beaver + sacrifice + reciprocal) ===\n\n");
    test_mult_shared_honest();
    test_mult_shared_tamper_x();
    test_mult_shared_chained();
    test_sacrifice_shared_honest();
    test_sacrifice_shared_malformed_caught();
    test_reciprocal_shared_honest();
    test_reciprocal_shared_wrong_caught();
    test_reciprocal_shared_share_tamper();
    test_alpha_never_touched_by_operators();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — SPDZ operator chain runs end-to-end with α "
                     "never reconstructed.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
