// Unit tests for volePSI/MpCgpShuffle.h — Chase-Ghosh-Poburinnaya
// Secret-Shared Shuffle (Asiacrypt'20) simulation, WIDE-ROW variant
// (R26b/step-1). Verifies:
//   1. The dealer correlation satisfies α = π(a) ⊕ b row-wise
//   2. Online correctness: y_A ⊕ y_B == π(x_A ⊕ x_B), per row, per block
//   3. Online message blinds A's input
//   4. Multi-round cascade composes permutations correctly
//   5. Malicious mode catches a bad dealer correlation
//   6. Permutation is uniformly distributed (sanity check)
//   7. NEW: wide rows (W=4) carry payload through the protocol intact
//   8. NEW: wide-row cascade with payload composes correctly
//   9. NEW: width mismatch between correlation and input throws cleanly

#include "volePSI/MpCgpShuffle.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <numeric>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using oc::block;

static bool blocksEq(const block& a, const block& b) {
    return std::memcmp(&a, &b, sizeof(block)) == 0;
}

static bool rowsEq(const mp::Row& a, const mp::Row& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) if (!blocksEq(a[i], b[i])) return false;
    return true;
}

static block makeSeed(uint8_t b) {
    block out;
    std::memset(&out, b, sizeof(out));
    return out;
}

// Random RowVec of n rows, each W blocks wide.
static mp::RowVec randomRows(oc::PRNG& prng, uint32_t n, uint32_t W) {
    mp::RowVec rv(n);
    for (auto& r : rv) {
        r.resize(W);
        for (auto& b : r) b = prng.get<block>();
    }
    return rv;
}

// Apply π row-wise: out[i] = in[pi[i]].
static mp::RowVec applyPiRows(const mp::RowVec& in,
                              const std::vector<int>& pi) {
    mp::RowVec out(in.size());
    for (size_t i = 0; i < in.size(); ++i) out[i] = in[pi[i]];
    return out;
}

// --------------------------------------------------------------

bool test_dealer_correlation_consistent() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xC0));

    const uint32_t n = 32, W = 1;
    mp::CgpCorrelationA cA;
    mp::CgpCorrelationB cB;
    mp::cgpDealerGenerate(n, W, prng, cA, cB);

    if (cA.a.size() != n || cA.alpha.size() != n) return false;
    if (cB.pi.size() != n || cB.b.size() != n) return false;
    for (uint32_t i = 0; i < n; ++i) {
        if (cA.a[i].size() != W) return false;
        if (cA.alpha[i].size() != W) return false;
        if (cB.b[i].size() != W) return false;
    }

    // Sanity: π is a valid permutation of [0, n).
    std::vector<int> sorted = cB.pi;
    std::sort(sorted.begin(), sorted.end());
    for (uint32_t i = 0; i < n; ++i)
        if (sorted[i] != static_cast<int>(i)) return false;

    // Invariant: α = π(a) ⊕ b row-wise.
    auto pi_a = applyPiRows(cA.a, cB.pi);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < W; ++j) {
            block expected = pi_a[i][j] ^ cB.b[i][j];
            if (!blocksEq(expected, cA.alpha[i][j])) return false;
        }
    }
    return true;
}

bool test_online_correctness_W1() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xC1));

    const uint32_t n = 64, W = 1;
    mp::CgpCorrelationA cA;
    mp::CgpCorrelationB cB;
    mp::cgpDealerGenerate(n, W, prng, cA, cB);

    auto x_A = randomRows(prng, n, W);
    auto x_B = randomRows(prng, n, W);

    auto result = mp::cgpRunInMemory(x_A, x_B, cA, cB);

    // Joint x = x_A ⊕ x_B; expected output = π(x) row-wise.
    mp::RowVec joint_in(n);
    for (uint32_t i = 0; i < n; ++i) {
        joint_in[i].resize(W);
        for (uint32_t j = 0; j < W; ++j)
            joint_in[i][j] = x_A[i][j] ^ x_B[i][j];
    }
    auto expected = applyPiRows(joint_in, cB.pi);

    if (result.y_A.size() != n || result.y_B.size() != n) return false;
    for (uint32_t i = 0; i < n; ++i) {
        mp::Row actual(W);
        for (uint32_t j = 0; j < W; ++j)
            actual[j] = result.y_A[i][j] ^ result.y_B[i][j];
        if (!rowsEq(actual, expected[i])) return false;
    }
    return true;
}

bool test_message_blinds_input() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xC2));
    const uint32_t n = 16, W = 1;
    mp::CgpCorrelationA cA;
    mp::CgpCorrelationB cB;
    mp::cgpDealerGenerate(n, W, prng, cA, cB);

    auto x_A = randomRows(prng, n, W);
    mp::RowVec m, y_A;
    mp::cgpOnlineA(x_A, cA, m, y_A);

    bool all_equal = true;
    for (uint32_t i = 0; i < n; ++i) {
        if (!rowsEq(m[i], x_A[i])) { all_equal = false; break; }
    }
    return !all_equal;
}

bool test_cascade_three_rounds_W1() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xC3));

    const uint32_t n = 24, W = 1;
    const uint32_t senderCount = 4;

    auto plain = randomRows(prng, n, W);
    auto spInit = randomRows(prng, n, W);
    mp::RowVec peerInit(n);
    for (uint32_t i = 0; i < n; ++i) {
        peerInit[i].resize(W);
        for (uint32_t j = 0; j < W; ++j)
            peerInit[i][j] = spInit[i][j] ^ plain[i][j];
    }

    mp::CascadeStateCgp state{spInit, peerInit};
    std::vector<int> composite(n);
    std::iota(composite.begin(), composite.end(), 0);

    for (uint32_t k = 0; k < senderCount - 1; ++k) {
        mp::CgpCorrelationA cA;
        mp::CgpCorrelationB cB;
        mp::cgpDealerGenerate(n, W, prng, cA, cB);
        mp::CascadeStateCgp out;
        if (!mp::cgpCascadeRound(state, cA, cB, mp::MaliciousMode::SemiHonest, out))
            return false;
        state = std::move(out);
        std::vector<int> next(n);
        for (uint32_t i = 0; i < n; ++i) next[i] = composite[cB.pi[i]];
        composite = std::move(next);
    }

    auto revealed = mp::cgpFinalReveal(state);
    for (uint32_t i = 0; i < n; ++i) {
        if (!rowsEq(revealed[i], plain[composite[i]])) return false;
    }
    return true;
}

bool test_malicious_mode_catches_bad_dealer() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xC4));

    const uint32_t n = 16, W = 1;
    mp::CgpCorrelationA cA;
    mp::CgpCorrelationB cB;
    mp::cgpDealerGenerate(n, W, prng, cA, cB);

    // Tamper with the dealer's α.
    auto* p = reinterpret_cast<uint8_t*>(&cA.alpha[5][0]);
    p[3] ^= 0x08;

    auto x_A = randomRows(prng, n, W);
    auto x_B = randomRows(prng, n, W);
    mp::CascadeStateCgp incoming{x_A, x_B};
    mp::CascadeStateCgp out;

    bool semi_ok = mp::cgpCascadeRound(incoming, cA, cB,
                                       mp::MaliciousMode::SemiHonest, out);
    if (!semi_ok) return false;

    bool malic_ok = mp::cgpCascadeRound(incoming, cA, cB,
                                        mp::MaliciousMode::Malicious, out);
    if (malic_ok) return false;
    if (!out.spShare.empty() || !out.peerShare.empty()) return false;
    return true;
}

bool test_permutation_is_random() {
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xC5));
    const uint32_t n = 16, W = 1;
    mp::CgpCorrelationA cA;
    mp::CgpCorrelationB cB;
    mp::cgpDealerGenerate(n, W, prng, cA, cB);

    bool is_identity = true;
    for (uint32_t i = 0; i < n; ++i) {
        if (cB.pi[i] != static_cast<int>(i)) { is_identity = false; break; }
    }
    return !is_identity;
}

// --------------------------------------------------------------
// NEW (R26b/step-1): wide-row tests

bool test_wide_row_online_correctness() {
    // W=4 blocks per row = 64 bytes of payload per row. The shuffle must
    // carry the full payload intact and consistent with the permutation.
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xD0));

    const uint32_t n = 32, W = 4;
    mp::CgpCorrelationA cA;
    mp::CgpCorrelationB cB;
    mp::cgpDealerGenerate(n, W, prng, cA, cB);

    auto x_A = randomRows(prng, n, W);
    auto x_B = randomRows(prng, n, W);

    auto result = mp::cgpRunInMemory(x_A, x_B, cA, cB);

    // y_A[i] ⊕ y_B[i] must equal (x_A[π[i]] ⊕ x_B[π[i]]) block-by-block.
    for (uint32_t i = 0; i < n; ++i) {
        int s = cB.pi[i];
        for (uint32_t j = 0; j < W; ++j) {
            block actual   = result.y_A[i][j] ^ result.y_B[i][j];
            block expected = x_A[s][j] ^ x_B[s][j];
            if (!blocksEq(actual, expected)) return false;
        }
    }
    return true;
}

bool test_wide_row_cascade_with_payload() {
    // Simulate the PSA-with-payload scenario: each row carries a wide
    // payload, the cascade must shuffle whole rows.
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xD1));

    const uint32_t n = 24, W = 8;  // 128 bytes of payload per row
    const uint32_t senderCount = 4;

    auto plain  = randomRows(prng, n, W);
    auto spInit = randomRows(prng, n, W);
    mp::RowVec peerInit(n);
    for (uint32_t i = 0; i < n; ++i) {
        peerInit[i].resize(W);
        for (uint32_t j = 0; j < W; ++j)
            peerInit[i][j] = spInit[i][j] ^ plain[i][j];
    }

    mp::CascadeStateCgp state{spInit, peerInit};
    std::vector<int> composite(n);
    std::iota(composite.begin(), composite.end(), 0);

    for (uint32_t k = 0; k < senderCount - 1; ++k) {
        mp::CgpCorrelationA cA;
        mp::CgpCorrelationB cB;
        mp::cgpDealerGenerate(n, W, prng, cA, cB);
        mp::CascadeStateCgp out;
        if (!mp::cgpCascadeRound(state, cA, cB, mp::MaliciousMode::Malicious, out))
            return false;
        state = std::move(out);
        std::vector<int> next(n);
        for (uint32_t i = 0; i < n; ++i) next[i] = composite[cB.pi[i]];
        composite = std::move(next);
    }

    auto revealed = mp::cgpFinalReveal(state);
    for (uint32_t i = 0; i < n; ++i) {
        if (!rowsEq(revealed[i], plain[composite[i]])) return false;
    }
    return true;
}

bool test_width_mismatch_throws() {
    // If A's input rows don't match the correlation's a width, we want a
    // clean exception rather than corrupt output.
    oc::PRNG prng;
    prng.SetSeed(makeSeed(0xD2));

    mp::CgpCorrelationA cA;
    mp::CgpCorrelationB cB;
    mp::cgpDealerGenerate(8, 4, prng, cA, cB);

    // x_A with the WRONG width (W=2 instead of 4).
    auto x_A = randomRows(prng, 8, 2);
    mp::RowVec m, y_A;
    try {
        mp::cgpOnlineA(x_A, cA, m, y_A);
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"dealer_correlation_consistent",     test_dealer_correlation_consistent},
        {"online_correctness_W1",             test_online_correctness_W1},
        {"message_blinds_input",              test_message_blinds_input},
        {"cascade_three_rounds_W1",           test_cascade_three_rounds_W1},
        {"malicious_mode_catches_bad_dealer", test_malicious_mode_catches_bad_dealer},
        {"permutation_is_random",             test_permutation_is_random},
        {"wide_row_online_correctness",       test_wide_row_online_correctness},
        {"wide_row_cascade_with_payload",     test_wide_row_cascade_with_payload},
        {"width_mismatch_throws",             test_width_mismatch_throws},
    };

    int failures = 0;
    for (const auto& [name, fn] : tests) {
        std::cout << name << ": ";
        try {
            if (fn()) std::cout << "PASS\n";
            else { std::cout << "FAIL\n"; ++failures; }
        } catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")\n";
            ++failures;
        } catch (...) {
            std::cout << "FAIL (unknown exception)\n";
            ++failures;
        }
    }
    std::cout << (failures ? "FAILURES: " : "ALL PASSED. failures=") << failures << "\n";
    return failures ? 1 : 0;
}
