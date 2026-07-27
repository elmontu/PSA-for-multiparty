// MPSVS Phase 17.5 — Bit membership proof (Chaum-Pedersen OR proof) tests.

#include "volePSI/MpPedersen.h"
#include "volePSI/MpRistretto.h"
#include "volePSI/MpsvsBitProof.h"

#include <cstdio>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_prove_bit_0() {
    std::printf("--- C1: proveBit(0) → verify accepts ---\n");
    R255Scalar r = R255Scalar::random();
    PedersenCommitment C = commitBit(0, r);
    BitProof pi = proveBit(0, r, C);
    bool ok = verifyBit(pi, C);
    CHECK(ok, "C1: honest proof for b=0 verifies");
}

static void test_prove_bit_1() {
    std::printf("--- C2: proveBit(1) → verify accepts ---\n");
    R255Scalar r = R255Scalar::random();
    PedersenCommitment C = commitBit(1, r);
    BitProof pi = proveBit(1, r, C);
    bool ok = verifyBit(pi, C);
    CHECK(ok, "C2: honest proof for b=1 verifies");
}

static void test_bit_2_rejected() {
    std::printf("--- C3: commitBit(2) rejected AT COMMIT TIME (stronger than "
                 "rejecting at verify) ---\n");
    R255Scalar r = R255Scalar::random();
    bool threw = false;
    try { (void)commitBit(2, r); }
    catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw, "C3: commitBit(2) throws — attacker cannot even construct "
                    "a non-boolean commitment");
}

static void test_bit_42_rejected() {
    std::printf("--- C4: commitBit(42) rejected at commit time ---\n");
    R255Scalar r = R255Scalar::random();
    bool threw = false;
    try { (void)commitBit(42, r); }
    catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw, "C4: commitBit(42) throws");
}

static void test_swap_c_rejects() {
    std::printf("--- C5: honest proof for one C rejected against different C' ---\n");
    R255Scalar r0 = R255Scalar::random();
    PedersenCommitment C0 = commitBit(0, r0);
    BitProof pi = proveBit(0, r0, C0);
    // Use a DIFFERENT commitment for verify (different randomness).
    R255Scalar r1 = R255Scalar::random();
    PedersenCommitment C_other = commitBit(0, r1);
    bool ok = verifyBit(pi, C_other);
    CHECK(!ok, "C5: proof bound to C0 does not verify against different C");
}

static void test_tampered_proof_rejected() {
    std::printf("--- C6: tampered proof (modified s0) → REJECTED ---\n");
    R255Scalar r = R255Scalar::random();
    PedersenCommitment C = commitBit(1, r);
    BitProof pi = proveBit(1, r, C);
    // Tamper with s0.
    pi.s0 = scalarAdd(pi.s0, R255Scalar::one());
    bool ok = verifyBit(pi, C);
    CHECK(!ok, "C6: tampered response (s0) causes verify to reject");
}

static void test_batch_catch_rate() {
    std::printf("--- C7: batch of 100 non-boolean commitBit attempts → all "
                 "rejected AT COMMIT TIME ---\n");
    int trials = 100;
    int caught = 0;
    for (int t = 0; t < trials; ++t) {
        R255Scalar r = R255Scalar::random();
        int fake = 2 + (t % 100);
        try {
            (void)commitBit(fake, r);   // must throw
        } catch (const std::invalid_argument&) {
            ++caught;
        }
    }
    std::printf("  %d/%d non-boolean commitBit calls rejected (%.1f%%)\n",
                 caught, trials, 100.0 * caught / trials);
    CHECK(caught == trials,
          "C7: 100% of non-boolean commitBit attempts rejected");
}

int main() {
    std::printf("=== MPSVS Phase 17.5: Bit Membership Proof (Chaum-Pedersen OR) ===\n\n");
    test_prove_bit_0();
    test_prove_bit_1();
    test_bit_2_rejected();
    test_bit_42_rejected();
    test_swap_c_rejects();
    test_tampered_proof_rejected();
    test_batch_catch_rate();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — bit-membership proof accepts b ∈ {0, 1}, rejects everything else.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
