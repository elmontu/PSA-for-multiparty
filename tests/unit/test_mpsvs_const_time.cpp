// MPSVS constant-time primitives tests.

#include "volePSI/MpsvsConstTime.h"
#include "volePSI/MpsvsProdHygiene.h"

#include <cstdint>
#include <cstdio>
#include <random>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_self_check() {
    std::printf("--- C1: ctSelfCheck ---\n");
    const char* err = ctSelfCheck();
    CHECK(err[0] == 0, "C1: self-check passes");
    if (err[0]) std::printf("     err: %s\n", err);
}

static void test_eq_matches_native_across_random() {
    std::printf("--- C2: ctEqU64 vs native == across 10k random pairs ---\n");
    ensureSodiumInit();
    int mismatch = 0;
    for (int i = 0; i < 10000; ++i) {
        uint64_t a = secureRandU64();
        // Half the time force equality:
        uint64_t b = (i & 1) ? a : secureRandU64();
        uint64_t native = (a == b) ? 1 : 0;
        uint64_t ct = ctEqU64(a, b);
        if (native != ct) ++mismatch;
    }
    CHECK(mismatch == 0, "C2: ctEqU64 agrees with native for 10k pairs");
}

static void test_lt_matches_native_across_random() {
    std::printf("--- C3: ctLtU64 vs native < across 10k random pairs ---\n");
    int mismatch = 0;
    for (int i = 0; i < 10000; ++i) {
        uint64_t a = secureRandU64();
        uint64_t b = secureRandU64();
        uint64_t native = (a < b) ? 1 : 0;
        uint64_t ct = ctLtU64(a, b);
        if (native != ct) ++mismatch;
    }
    CHECK(mismatch == 0, "C3: ctLtU64 agrees with native");
}

static void test_lt_signed_matches_native() {
    std::printf("--- C4: ctLtI64 vs native signed < across 10k pairs ---\n");
    int mismatch = 0;
    for (int i = 0; i < 10000; ++i) {
        int64_t a = static_cast<int64_t>(secureRandU64());
        int64_t b = static_cast<int64_t>(secureRandU64());
        uint64_t native = (a < b) ? 1 : 0;
        uint64_t ct = ctLtI64(a, b);
        if (native != ct) ++mismatch;
    }
    CHECK(mismatch == 0, "C4: ctLtI64 agrees with native signed <");
}

static void test_mux_matches_native() {
    std::printf("--- C5: ctMuxU64 vs native ternary ---\n");
    int mismatch = 0;
    for (int i = 0; i < 10000; ++i) {
        uint64_t a = secureRandU64();
        uint64_t b = secureRandU64();
        uint64_t sel = i & 1;
        uint64_t native = sel ? a : b;
        uint64_t ct = ctMuxU64(sel, a, b);
        if (native != ct) ++mismatch;
    }
    CHECK(mismatch == 0, "C5: ctMuxU64 matches ternary for 10k trials");
}

static void test_le_ge_gt() {
    std::printf("--- C6: derived ctLe/Ge/Gt agree with native ---\n");
    int mismatch = 0;
    for (int i = 0; i < 5000; ++i) {
        uint64_t a = secureRandU64();
        uint64_t b = secureRandU64();
        if (ctLeU64(a, b) != ((a <= b) ? 1u : 0u)) ++mismatch;
        if (ctGtU64(a, b) != ((a >  b) ? 1u : 0u)) ++mismatch;
        if (ctGeU64(a, b) != ((a >= b) ? 1u : 0u)) ++mismatch;
        if (ctNeqU64(a, b) != ((a != b) ? 1u : 0u)) ++mismatch;
    }
    CHECK(mismatch == 0, "C6: le/ge/gt/neq all agree");
}

static void test_edge_cases() {
    std::printf("--- C7: edge cases (0, max, msb) ---\n");
    CHECK(ctEqU64(0, 0) == 1, "C7a: eq(0,0)");
    CHECK(ctEqU64(~0ULL, ~0ULL) == 1, "C7b: eq(max, max)");
    CHECK(ctLtU64(0, ~0ULL) == 1, "C7c: 0 < max");
    CHECK(ctLtU64(~0ULL, 0) == 0, "C7d: !(max < 0)");
    CHECK(ctLtU64(1ULL << 63, (1ULL << 63) - 1) == 0,
          "C7e: msb-set is NOT less than msb-cleared in unsigned");
    CHECK(ctLtI64(-(1LL << 62), (1LL << 62)) == 1,
          "C7f: large-negative < large-positive (signed)");
    CHECK(ctMuxU64(1, 0, ~0ULL) == 0, "C7g: mux(1, 0, max) = 0");
    CHECK(ctMuxU64(0, 0, ~0ULL) == ~0ULL, "C7h: mux(0, 0, max) = max");
}

static void test_membuf_compare() {
    std::printf("--- C8: ctMemcmpEq on 32-byte blocks ---\n");
    unsigned char a[32], b[32];
    for (int i = 0; i < 32; ++i) { a[i] = static_cast<unsigned char>(i); b[i] = a[i]; }
    CHECK(ctMemcmpEq(a, b, 32) == 1, "C8a: identical 32B blocks");
    b[31] = 99;
    CHECK(ctMemcmpEq(a, b, 32) == 0, "C8b: last-byte diff detected");
    b[31] = a[31];
    b[0] = 99;
    CHECK(ctMemcmpEq(a, b, 32) == 0, "C8c: first-byte diff detected");
}

int main() {
    std::printf("=== MPSVS constant-time primitives ===\n\n");
    test_self_check();
    test_eq_matches_native_across_random();
    test_lt_matches_native_across_random();
    test_lt_signed_matches_native();
    test_mux_matches_native();
    test_le_ge_gt();
    test_edge_cases();
    test_membuf_compare();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — CT primitives match native semantics.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
