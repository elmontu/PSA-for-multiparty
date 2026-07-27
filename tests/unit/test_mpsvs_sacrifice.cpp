// MPSVS Phase 17.1-ext — SPDZ sacrifice check + batched MAC verification.
//
// Two new malicious-security primitives:
//
//   1. Sacrifice check: given a Beaver triple T claimed to satisfy c = a·b,
//      and auxiliary triple T', verify T without opening its plaintext.
//      Catches a malicious DEALER that distributed a wrong triple (w ≠ u·v).
//      Auth-share MAC check does NOT catch this — the shares are internally
//      consistent, only the algebraic invariant is broken.
//
//   2. Batch MAC check: verify N openings with a single MAC comparison
//      using random public coefficients. O(1) verification for N shares
//      (vs O(N) individual checks). Catches any tampering in the batch.

#include "volePSI/MpsvsAuthShare.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

// ==========================================================================
// Sacrifice check tests
// ==========================================================================

static void test_sacrifice_correct_triples_pass() {
    std::printf("--- C1: two correct Beaver triples → sacrifice check PASSES ---\n");
    oc::PRNG prng(oc::block(0xa1, 0xb2));
    uint64_t alpha = prng.get<uint64_t>();
    AuthBeaverTriple T = generateAuthBeaverTriple(2, alpha, prng);
    AuthBeaverTriple T_aux = generateAuthBeaverTriple(2, alpha, prng);
    bool ok = sacrificeCheckTriple(T, T_aux, alpha, prng);
    CHECK(ok, "C1: sacrifice check passes on correct triples");
}

static void test_sacrifice_catches_malicious_dealer() {
    std::printf("--- C2: malformed triple (w ≠ u·v) → sacrifice check FAILS ---\n");
    oc::PRNG prng(oc::block(0xc3, 0xd4));
    uint64_t alpha = prng.get<uint64_t>();
    // T has w = u·v + 100 (malicious dealer offset).
    AuthBeaverTriple T = generateMalformedBeaverTriple(2, alpha, 100, prng);
    AuthBeaverTriple T_aux = generateAuthBeaverTriple(2, alpha, prng);
    bool ok = sacrificeCheckTriple(T, T_aux, alpha, prng);
    CHECK(!ok, "C2: sacrifice check FAILS on malformed T (as expected)");
}

static void test_sacrifice_catches_malicious_aux() {
    std::printf("--- C3: malformed AUX triple → sacrifice check FAILS ---\n");
    oc::PRNG prng(oc::block(0xe5, 0xf6));
    uint64_t alpha = prng.get<uint64_t>();
    AuthBeaverTriple T = generateAuthBeaverTriple(2, alpha, prng);
    // Malformed auxiliary.
    AuthBeaverTriple T_aux = generateMalformedBeaverTriple(2, alpha, 42, prng);
    bool ok = sacrificeCheckTriple(T, T_aux, alpha, prng);
    CHECK(!ok, "C3: sacrifice check FAILS on malformed T_aux (as expected)");
}

static void test_sacrifice_catch_rate() {
    std::printf("--- C4: sacrifice catch rate over 200 malformed triples ---\n");
    oc::PRNG prng(oc::block(0x11, 0x22));
    int caught = 0;
    int trials = 200;
    for (int t = 0; t < trials; ++t) {
        oc::PRNG p(oc::block(0xa0 + t, 0));
        uint64_t alpha = p.get<uint64_t>();
        if (alpha == 0) alpha = 1;
        // Random malformation offset (nonzero) — guaranteed to be wrong.
        uint64_t offset = (p.get<uint64_t>() & 0xffff) + 1;
        AuthBeaverTriple T = generateMalformedBeaverTriple(2, alpha, offset, p);
        AuthBeaverTriple T_aux = generateAuthBeaverTriple(2, alpha, p);
        bool ok = sacrificeCheckTriple(T, T_aux, alpha, p);
        if (!ok) ++caught;
    }
    double rate = static_cast<double>(caught) / trials;
    std::printf("  %d / %d malformed triples caught (%.1f%%)\n",
                 caught, trials, rate * 100);
    CHECK(caught == trials, "C4: 100% of malformed triples detected");
}

// ==========================================================================
// Batch MAC check tests
// ==========================================================================

static void test_batch_honest_pass() {
    std::printf("--- C5: batch of honest shares → MAC verifies ---\n");
    oc::PRNG prng(oc::block(0x33, 0x44));
    uint64_t alpha = prng.get<uint64_t>();
    std::vector<AuthSharedU64> xs;
    std::vector<uint64_t> plaintexts;
    for (int i = 1; i <= 10; ++i) {
        uint64_t v = i * 100;
        plaintexts.push_back(v);
        xs.push_back(authShareU64(2, v, alpha, prng));
    }
    std::vector<uint64_t> out;
    bool ok = batchOpenWithMacCheck(xs, alpha, out, prng);
    CHECK(ok, "C5: batch MAC check passes on honest shares");
    CHECK(out.size() == 10, "C5: 10 values reconstructed");
    for (size_t i = 0; i < 10; ++i) {
        if (out[i] != plaintexts[i]) {
            CHECK(false, "C5: reconstructed value matches plaintext");
            return;
        }
    }
    CHECK(true, "C5: all 10 reconstructions correct");
}

static void test_batch_tamper_detected() {
    std::printf("--- C6: tampering in batch → detected ---\n");
    oc::PRNG prng(oc::block(0x55, 0x66));
    uint64_t alpha = prng.get<uint64_t>();
    std::vector<AuthSharedU64> xs;
    for (int i = 1; i <= 20; ++i) {
        xs.push_back(authShareU64(2, i * 100, alpha, prng));
    }
    // Attacker tampers with just ONE share out of 20.
    simulateTampering(xs[7], /*bad_party=*/0, /*tamper=*/999);
    std::vector<uint64_t> out;
    bool ok = batchOpenWithMacCheck(xs, alpha, out, prng);
    CHECK(!ok, "C6: batch MAC check FAILS when one share tampered");
}

static void test_batch_efficiency() {
    std::printf("--- C7: batch vs individual — same detection, single MAC compare ---\n");
    oc::PRNG prng(oc::block(0x77, 0x88));
    uint64_t alpha = prng.get<uint64_t>();
    // Large batch to demonstrate scaling.
    std::vector<AuthSharedU64> xs;
    for (int i = 1; i <= 1000; ++i) {
        xs.push_back(authShareU64(2, i, alpha, prng));
    }
    // Tamper with random one.
    simulateTampering(xs[500], /*bad_party=*/1, /*tamper=*/1);
    std::vector<uint64_t> out;
    bool ok = batchOpenWithMacCheck(xs, alpha, out, prng);
    std::printf("  1000 shares batched; MAC check: %s\n",
                 ok ? "PASSED (BUG)" : "FAILED (correct)");
    CHECK(!ok, "C7: batch MAC catches single tamper in 1000-share batch");
}

int main() {
    std::printf("=== MPSVS Phase 17.1-ext: Sacrifice + Batch MAC ===\n\n");
    test_sacrifice_correct_triples_pass();
    test_sacrifice_catches_malicious_dealer();
    test_sacrifice_catches_malicious_aux();
    test_sacrifice_catch_rate();
    test_batch_honest_pass();
    test_batch_tamper_detected();
    test_batch_efficiency();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — sacrifice check + batch MAC catch malicious dealer + tampering.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
