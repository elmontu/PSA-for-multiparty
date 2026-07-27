// MPSVS Phase 17.7 — Malicious Adversary Catalog.
//
// Comprehensive test of the malicious-security mechanisms deployed in the
// MPSVS wire pipeline. For each attack vector, simulates a semi-honest+
// (malicious deviating from prescribed protocol at a single step) attacker,
// and verifies the corresponding detection mechanism catches it.
//
// Attack catalog:
//
//   A1. Value-share tampering during open
//       Party P modifies its share of a value before broadcasting.
//       Detection: SPDZ MAC check (openWithMacCheck).
//
//   A2. Batched tampering
//       Party P tampers with 1 share out of a large batch.
//       Detection: batched MAC check (batchOpenWithMacCheck).
//
//   A3. Malformed Beaver triple
//       Dealer distributes (u, v, w') where w' ≠ u·v.
//       Detection: sacrifice check (sacrificeCheckTriple).
//
//   A4. DP joint-noise commit-reveal deviation
//       Party P commits to eta_P, then reveals a DIFFERENT eta'_P.
//       Detection: SHA-256 commit verification (verifyCommit).
//
//   A5. Multi-step cross-hop attack
//       Party tampers with both a value share AND a computed downstream value.
//       Detection: MAC check catches all tampered opens.
//
// For each: attack simulation + detection verification + summary catch rate.

#include "volePSI/MpsvsAuthShare.h"
#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

struct AttackResult {
    const char* attack_id;
    const char* description;
    int         trials;
    int         detected;
    double      catch_rate;
    const char* mechanism;
};

// ==========================================================================
// A1: Value-share tampering
// ==========================================================================
static AttackResult attack_A1_value_tamper(int trials) {
    AttackResult r{"A1", "value-share tampering during open",
                    trials, 0, 0.0,
                    "SPDZ MAC check (openWithMacCheck)"};
    for (int t = 0; t < trials; ++t) {
        oc::PRNG prng(oc::block(0x1000 + t, 0));
        uint64_t alpha = prng.get<uint64_t>();
        if (alpha == 0) alpha = 1;
        AuthSharedU64 x = authShareU64(2, 10000 + t, alpha, prng);
        // Attacker adds a random non-zero tamper.
        uint64_t tamper = (prng.get<uint64_t>() & 0xffff) + 1;
        simulateTampering(x, /*bad_party=*/t & 1, tamper);
        uint64_t out = 0;
        bool ok = openWithMacCheck(x, alpha, out);
        if (!ok) ++r.detected;
    }
    r.catch_rate = static_cast<double>(r.detected) / trials;
    return r;
}

// ==========================================================================
// A2: Batched tampering
// ==========================================================================
static AttackResult attack_A2_batch_tamper(int trials) {
    AttackResult r{"A2", "batched tampering (1 of N shares)",
                    trials, 0, 0.0,
                    "Batched MAC check (batchOpenWithMacCheck)"};
    for (int t = 0; t < trials; ++t) {
        oc::PRNG prng(oc::block(0x2000 + t, 0));
        uint64_t alpha = prng.get<uint64_t>();
        if (alpha == 0) alpha = 1;
        std::vector<AuthSharedU64> xs;
        const int N = 50;
        for (int i = 0; i < N; ++i) {
            xs.push_back(authShareU64(2, 1000 + i, alpha, prng));
        }
        // Tamper with a random share.
        int tampered_idx = prng.get<uint32_t>() % N;
        uint64_t tamper = (prng.get<uint64_t>() & 0xff) + 1;
        simulateTampering(xs[tampered_idx], /*bad_party=*/t & 1, tamper);
        std::vector<uint64_t> out;
        bool ok = batchOpenWithMacCheck(xs, alpha, out, prng);
        if (!ok) ++r.detected;
    }
    r.catch_rate = static_cast<double>(r.detected) / trials;
    return r;
}

// ==========================================================================
// A3: Malformed Beaver triple
// ==========================================================================
static AttackResult attack_A3_malformed_triple(int trials) {
    AttackResult r{"A3", "malformed Beaver triple (dealer attack)",
                    trials, 0, 0.0,
                    "SPDZ sacrifice check (sacrificeCheckTriple)"};
    for (int t = 0; t < trials; ++t) {
        oc::PRNG prng(oc::block(0x3000 + t, 0));
        uint64_t alpha = prng.get<uint64_t>();
        if (alpha == 0) alpha = 1;
        uint64_t offset = (prng.get<uint64_t>() & 0xffff) + 1;
        AuthBeaverTriple T = generateMalformedBeaverTriple(2, alpha, offset, prng);
        AuthBeaverTriple T_aux = generateAuthBeaverTriple(2, alpha, prng);
        bool ok = sacrificeCheckTriple(T, T_aux, alpha, prng);
        if (!ok) ++r.detected;
    }
    r.catch_rate = static_cast<double>(r.detected) / trials;
    return r;
}

// ==========================================================================
// A4: DP joint-noise commit-reveal deviation
// ==========================================================================
static AttackResult attack_A4_dp_commit_reveal_deviation(int trials) {
    AttackResult r{"A4", "DP commit-reveal deviation (reveal ≠ commit)",
                    trials, 0, 0.0,
                    "SHA-256 commit hash verification (verifyCommit)"};
    for (int t = 0; t < trials; ++t) {
        std::mt19937_64 rng(0x4000 + t);
        // Honest commit.
        NoiseCommit c = sampleAndCommit(0, 3, 2.0, rng);
        // Attacker tampers with revealed eta (attempts to bias joint noise).
        NoiseCommit tampered = c;
        int idx = static_cast<int>(rng() % 3);
        int64_t tamper = 100 + (rng() % 1000);
        tampered.eta[idx] += tamper;
        // The verify step recomputes commit hash and compares.
        bool valid = verifyCommit(tampered);
        if (!valid) ++r.detected;   // tampering caught
    }
    r.catch_rate = static_cast<double>(r.detected) / trials;
    return r;
}

// ==========================================================================
// A5: Multi-step cross-hop attack
// ==========================================================================
static AttackResult attack_A5_multi_step(int trials) {
    AttackResult r{"A5", "multi-step: tamper across two computation stages",
                    trials, 0, 0.0,
                    "MAC check propagates through all operations"};
    for (int t = 0; t < trials; ++t) {
        oc::PRNG prng(oc::block(0x5000 + t, 0));
        uint64_t alpha = prng.get<uint64_t>();
        if (alpha == 0) alpha = 1;

        AuthSharedU64 x = authShareU64(2, 100, alpha, prng);
        AuthSharedU64 y = authShareU64(2, 200, alpha, prng);

        // Stage 1: add and multiply.
        AuthSharedU64 sum = authAdd(x, y);
        AuthBeaverTriple tr = generateAuthBeaverTriple(2, alpha, prng);
        AuthSharedU64 prod = authSecureMultiply(x, y, tr, alpha);

        // Attacker tampers with BOTH sum and prod at different stages.
        simulateTampering(sum, 0, 111);
        simulateTampering(prod, 1, 222);

        uint64_t out_sum = 0, out_prod = 0;
        bool ok_sum  = openWithMacCheck(sum, alpha, out_sum);
        bool ok_prod = openWithMacCheck(prod, alpha, out_prod);
        // Detected if EITHER open fails.
        if (!ok_sum || !ok_prod) ++r.detected;
    }
    r.catch_rate = static_cast<double>(r.detected) / trials;
    return r;
}

static void printResult(const AttackResult& r) {
    std::printf("  %-4s | %-52s | %d/%d (%.1f%%) | %s\n",
                 r.attack_id, r.description,
                 r.detected, r.trials, r.catch_rate * 100,
                 r.mechanism);
}

int main() {
    std::printf("=== MPSVS Phase 17.7: Malicious Adversary Catalog ===\n\n");
    std::printf("For each attack vector, %d trials of the attack are simulated.\n", 200);
    std::printf("Detection rate = fraction of attacks caught by the deployed defense.\n\n");

    const int TRIALS = 200;

    auto a1 = attack_A1_value_tamper(TRIALS);
    auto a2 = attack_A2_batch_tamper(TRIALS);
    auto a3 = attack_A3_malformed_triple(TRIALS);
    auto a4 = attack_A4_dp_commit_reveal_deviation(TRIALS);
    auto a5 = attack_A5_multi_step(TRIALS);

    std::printf("Results:\n");
    std::printf("%-4s | %-52s | %-15s | %s\n", "ID", "Attack description", "Detected", "Mechanism");
    std::printf("%s\n", std::string(120, '-').c_str());
    printResult(a1);
    printResult(a2);
    printResult(a3);
    printResult(a4);
    printResult(a5);

    // Overall.
    int total_trials = 5 * TRIALS;
    int total_caught = a1.detected + a2.detected + a3.detected + a4.detected + a5.detected;
    double overall = static_cast<double>(total_caught) / total_trials;
    std::printf("\nOverall detection rate: %d / %d = %.2f%%\n",
                 total_caught, total_trials, overall * 100);

    CHECK(a1.catch_rate == 1.0, "A1: 100% value-tamper detection");
    CHECK(a2.catch_rate == 1.0, "A2: 100% batched-tamper detection");
    CHECK(a3.catch_rate == 1.0, "A3: 100% malformed-triple detection");
    CHECK(a4.catch_rate == 1.0, "A4: 100% DP commit-reveal deviation detection");
    CHECK(a5.catch_rate == 1.0, "A5: 100% multi-step tamper detection");

    std::printf("\n=== Coverage summary ===\n");
    std::printf("Attack surface                              | Defense                        | Status\n");
    std::printf("%s\n", std::string(110, '-').c_str());
    std::printf("Share broadcast (single-party corruption)   | SPDZ MAC (Phase 17.1)         | COVERED\n");
    std::printf("Batched-share broadcast                     | Batched MAC (Phase 17.1-ext)  | COVERED\n");
    std::printf("Beaver triple correctness                   | Sacrifice check (Phase 17.1-ext) | COVERED\n");
    std::printf("DP joint noise commit-reveal                | SHA-256 hash verify (Phase 12) | COVERED\n");
    std::printf("Multi-value / multi-stage tampering         | MAC propagates through ops    | COVERED\n");
    std::printf("OPRF partial evaluation (DLEQ check)        | dleqVerify (Phase 2)           | COVERED (existing)\n");
    std::printf("Threshold DKG (Schnorr + DLEQ)              | dkgS1Finalize verifies         | COVERED (existing)\n");
    std::printf("CGP shuffle correctness                     | Bayer-Groth NIZK              | PENDING (17.4)\n");
    std::printf("Membership bit range proof                  | Bulletproofs range proof       | PENDING (17.5)\n");
    std::printf("Goldschmidt convergence                     | Algebraic consistency proof    | PENDING (17.6)\n");

    if (g_fail == 0) {
        std::printf("\n✓ ALL PASSED — deployed malicious defenses catch 100%% of tested attacks\n");
        std::printf("  across 5 attack vectors, %d total trials.\n", total_trials);
        return 0;
    }
    std::printf("\nFAILED — %d assertion(s)\n", g_fail);
    return 1;
}
