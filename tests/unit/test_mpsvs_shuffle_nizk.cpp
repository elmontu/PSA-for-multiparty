// MPSVS Phase 17.4 — Bayer-Groth CGP shuffle NIZK tests.

#include "volePSI/MpsvsShuffleWire.h"

#include <algorithm>
#include <cstdio>
#include <numeric>
#include <random>
#include <vector>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static std::vector<int> randomPermutation(size_t n, std::mt19937& rng) {
    std::vector<int> p(n);
    std::iota(p.begin(), p.end(), 0);
    std::shuffle(p.begin(), p.end(), rng);
    return p;
}

static void test_honest_shuffle_passes() {
    std::printf("--- C1: honest shuffle → verify PASSES ---\n");
    std::mt19937 rng(0xa1);
    std::vector<uint64_t> keys = {100, 200, 300, 400, 500, 600, 700, 800};
    auto perm = randomPermutation(keys.size(), rng);
    auto t = shuffleAndProve(keys, perm);
    bool ok = verifyShuffleTranscript(t);
    CHECK(ok, "C1: BG shuffle NIZK verifies for honest permutation");
}

static void test_malicious_substitute() {
    std::printf("--- C2: substitute one shuffled key → verify FAILS ---\n");
    std::mt19937 rng(0xb2);
    std::vector<uint64_t> keys = {100, 200, 300, 400, 500, 600, 700, 800};
    auto perm = randomPermutation(keys.size(), rng);
    auto honest = shuffleAndProve(keys, perm);
    auto bad = maliciousSubstitute(honest, /*shuf_idx=*/3, /*new_key=*/9999);
    bool ok = verifyShuffleTranscript(bad);
    CHECK(!ok, "C2: substituted key detected by BG shuffle NIZK");
}

static void test_malicious_drop() {
    std::printf("--- C3: drop one shuffled key → verify FAILS ---\n");
    std::mt19937 rng(0xc3);
    std::vector<uint64_t> keys = {100, 200, 300, 400, 500, 600, 700, 800};
    auto perm = randomPermutation(keys.size(), rng);
    auto honest = shuffleAndProve(keys, perm);
    auto bad = maliciousDrop(honest, /*shuf_idx=*/2);
    bool ok = verifyShuffleTranscript(bad);
    CHECK(!ok, "C3: dropped row detected by BG shuffle NIZK");
}

static void test_malicious_insert() {
    std::printf("--- C4: insert extra key → verify FAILS ---\n");
    std::mt19937 rng(0xd4);
    std::vector<uint64_t> keys = {100, 200, 300, 400, 500, 600, 700, 800};
    auto perm = randomPermutation(keys.size(), rng);
    auto honest = shuffleAndProve(keys, perm);
    auto bad = maliciousInsert(honest, /*new_key=*/11111);
    bool ok = verifyShuffleTranscript(bad);
    CHECK(!ok, "C4: inserted extra row detected");
}

static void test_batch_catch_rate() {
    std::printf("--- C5: batch of 100 malicious substitutions → catch rate ---\n");
    std::mt19937 rng(0xe5);
    int trials = 100;
    int caught = 0;
    for (int t = 0; t < trials; ++t) {
        std::vector<uint64_t> keys;
        for (int i = 0; i < 16; ++i) keys.push_back((rng() % 100000) + 100);
        auto perm = randomPermutation(keys.size(), rng);
        auto honest = shuffleAndProve(keys, perm);
        int idx = rng() % 16;
        uint64_t new_key = (rng() % 100000) + 200000;   // outside original range
        auto bad = maliciousSubstitute(honest, idx, new_key);
        if (!verifyShuffleTranscript(bad)) ++caught;
    }
    std::printf("  %d/%d malicious substitutions caught (%.1f%%)\n",
                 caught, trials, 100.0 * caught / trials);
    CHECK(caught == trials, "C5: 100% of substitutions caught");
}

static void test_identity_permutation() {
    std::printf("--- C6: identity permutation is a valid shuffle → PASSES ---\n");
    std::vector<uint64_t> keys = {100, 200, 300, 400};
    std::vector<int> perm = {0, 1, 2, 3};   // identity
    auto t = shuffleAndProve(keys, perm);
    bool ok = verifyShuffleTranscript(t);
    CHECK(ok, "C6: identity permutation verifies (valid multiset preservation)");
}

int main() {
    std::printf("=== MPSVS Phase 17.4: Bayer-Groth CGP shuffle NIZK ===\n\n");
    test_honest_shuffle_passes();
    test_malicious_substitute();
    test_malicious_drop();
    test_malicious_insert();
    test_batch_catch_rate();
    test_identity_permutation();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — BG shuffle NIZK catches substitute / drop / insert attacks.\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
