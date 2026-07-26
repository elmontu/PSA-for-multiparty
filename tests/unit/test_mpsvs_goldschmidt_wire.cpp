// MPSVS Phase 6 MPC-wire — Goldschmidt reciprocal on shares.

#include "volePSI/MpsvsGoldschmidtWire.h"
#include "volePSI/MpsvsRatioBucket.h"

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

static void test_wire_matches_plain_recip() {
    std::printf("--- C1: wire Goldschmidt reconstructs to ~1/x ---\n");
    oc::PRNG prng(oc::block(0x333, 0x444));

    struct Case { uint64_t x; double bits_target; };
    std::vector<Case> cases = {
        {2,    30},   // exact fp representation → high precision
        {3,    30},
        {100,  20},   // representation ceiling ~ 33 bits, we allow slack
        {1024, 30},
        {65536, 20},
    };

    for (const auto& c : cases) {
        SharedU64Bin sx = shareU64Bin(2, c.x, prng);
        size_t budget = goldschmidtWireTripleBudget(/*iters=*/6);
        auto triples = generateBeaverTripleBits(2, budget, prng);
        size_t idx = 0;
        SharedU128Bin sy = goldschmidtRecipWire(sx, /*N_max=*/1ULL << 30,
                                                  /*iters=*/6, triples, idx);
        double got = fpToDoubleShared(sy);
        double want = 1.0 / static_cast<double>(c.x);
        double rel_err = std::abs(got - want) / want;
        double bits = (rel_err <= 0.0) ? 60.0 : -std::log2(rel_err);
        std::printf("  x=%lu  wire=%.6e  want=%.6e  rel_err=%.3e  bits=%.1f  triples=%zu/%zu\n",
                     c.x, got, want, rel_err, bits, idx, budget);
        CHECK(bits >= c.bits_target,
              "C1: wire Goldschmidt meets accuracy target");
    }
}

static void test_recip_matches_semantic() {
    std::printf("--- C2: wire result matches semantic-ref Goldschmidt ---\n");
    oc::PRNG prng(oc::block(0x555, 0x666));
    uint64_t x = 42;
    SharedU64Bin sx = shareU64Bin(2, x, prng);
    size_t budget = goldschmidtWireTripleBudget(6);
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    SharedU128Bin sy = goldschmidtRecipWire(sx, 1ULL << 30, 6, triples, idx);
    double wire = fpToDoubleShared(sy);

    // Semantic ref
    Fp ref = goldschmidtRecip(x, 6);
    double semantic = fpToDouble(ref);
    std::printf("  x=%lu wire=%.6e semantic=%.6e diff=%.3e\n",
                 x, wire, semantic, std::abs(wire - semantic));
    CHECK(std::abs(wire - semantic) / semantic < 1e-6,
          "C2: wire and semantic-ref agree to 1e-6 relative");
}

static void test_128bit_prims() {
    std::printf("--- C3: 128-bit add/sub/mul primitives correct ---\n");
    oc::PRNG prng(oc::block(0x777, 0x888));
    auto triples = generateBeaverTripleBits(2, 100000, prng);
    size_t idx = 0;

    __int128 a_val = static_cast<__int128>(123456789012345ULL);
    __int128 b_val = static_cast<__int128>(987654321098765ULL);
    SharedU128Bin a = shareU128Bin(2, a_val, prng);
    SharedU128Bin b = shareU128Bin(2, b_val, prng);

    SharedU128Bin sum = bitAdd128(a, b, triples, idx);
    __int128 sum_r = sum.reconstruct();
    std::printf("  add: reconstructed diff = %lld\n",
                 static_cast<long long>(static_cast<int64_t>(sum_r - (a_val + b_val))));
    CHECK(sum_r == (a_val + b_val), "C3: 128-bit add correct");

    SharedU128Bin diff = bitSub128(a, b, triples, idx);
    __int128 diff_r = diff.reconstruct();
    // Two's-complement 128-bit: (a - b) mod 2^128
    __int128 want_diff = a_val - b_val;   // may be negative, wraps naturally
    CHECK(diff_r == want_diff, "C3: 128-bit sub correct");

    // Mul test — small values so we don't overflow.
    SharedU128Bin smalla = shareU128Bin(2, 12345, prng);
    SharedU128Bin smallb = shareU128Bin(2, 67890, prng);
    SharedU128Bin prod = bitMul128(smalla, smallb, triples, idx);
    __int128 prod_r = prod.reconstruct();
    CHECK(prod_r == static_cast<__int128>(12345LL * 67890LL),
          "C3: 128-bit mul correct on small values");
    std::printf("  mul: 12345 · 67890 = %lld  (want %lld) triples used %zu\n",
                 static_cast<long long>(prod_r), 12345LL * 67890LL, idx);
}

int main() {
    test_128bit_prims();
    test_recip_matches_semantic();
    test_wire_matches_plain_recip();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 6 MPC-wire (Goldschmidt) acceptance met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
