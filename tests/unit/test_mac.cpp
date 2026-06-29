// Unit tests for volePSI/MpMac.h — information-theoretic MAC under
// GF(2^128) used by the malicious-secure cascade (T1 production).
//
// Verifies:
//   1. tagVector(α, plain): tags are correctly computed
//   2. randomAuthShare: shares are random AND tag invariant holds
//   3. xorAuth: homomorphism preserves invariant
//   4. permuteAuth: invariant preserved through permutation
//   5. verifyAuthShares: accepts honest, rejects tampered
//   6. verifyAuthSharesBatched: same with batched random-linear-combo check
//   7. xorConstAuth: constant-injection updates tag correctly

#include "volePSI/MpMac.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <numeric>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using oc::block;

static std::mt19937_64 rng_meta(0xC0FFEE);

static block randomBlock(oc::PRNG& prng) { return prng.get<block>(); }

static std::vector<block> randomVec(oc::PRNG& prng, size_t n) {
    std::vector<block> v(n);
    for (auto& b : v) b = prng.get<block>();
    return v;
}

static bool blocksEq(const block& a, const block& b) {
    return std::memcmp(&a, &b, sizeof(block)) == 0;
}

// --------------------------------------------------------------

bool test_tagVector_correct() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x42, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 16);
    auto tag = mp::tagVector(alpha, plain);

    if (tag.size() != plain.size()) return false;
    for (size_t i = 0; i < plain.size(); ++i) {
        block expected = alpha.gf128Mul(plain[i]);
        if (!blocksEq(tag[i], expected)) return false;
    }
    return true;
}

bool test_randomAuthShare_invariant() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x11, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 32);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);

    // Joint reconstruction returns plain.
    for (size_t i = 0; i < plain.size(); ++i) {
        block joint_data = s1.data[i] ^ s2.data[i];
        if (!blocksEq(joint_data, plain[i])) return false;
    }
    // Tag invariant.
    return mp::verifyAuthShares(s1, s2, alpha);
}

bool test_randomAuthShare_unique() {
    // Sharing the same plain twice should produce different shares (PRNG).
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x22, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 8);
    auto [a1, a2] = mp::randomAuthShare(plain, alpha, prng);
    auto [b1, b2] = mp::randomAuthShare(plain, alpha, prng);

    // Each set must independently verify.
    if (!mp::verifyAuthShares(a1, a2, alpha)) return false;
    if (!mp::verifyAuthShares(b1, b2, alpha)) return false;

    // Shares should differ (extremely high prob).
    bool same = true;
    for (size_t i = 0; i < a1.size(); ++i) {
        if (!blocksEq(a1.data[i], b1.data[i])) { same = false; break; }
    }
    return !same;
}

bool test_xorAuth_preserves_invariant() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x33, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto p_x = randomVec(prng, 10);
    auto p_y = randomVec(prng, 10);

    auto [x1, x2] = mp::randomAuthShare(p_x, alpha, prng);
    auto [y1, y2] = mp::randomAuthShare(p_y, alpha, prng);

    // Compute z = x ⊕ y locally on each party.
    auto z1 = mp::xorAuth(x1, y1);
    auto z2 = mp::xorAuth(x2, y2);

    // The reconstructed z = p_x ⊕ p_y, and invariant holds.
    for (size_t i = 0; i < p_x.size(); ++i) {
        block joint = z1.data[i] ^ z2.data[i];
        block expected = p_x[i] ^ p_y[i];
        if (!blocksEq(joint, expected)) return false;
    }
    return mp::verifyAuthShares(z1, z2, alpha);
}

bool test_permuteAuth_preserves_invariant() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x44, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 16);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);

    std::vector<int> dest(16);
    std::iota(dest.begin(), dest.end(), 0);
    std::mt19937 g(0xABC);
    std::shuffle(dest.begin(), dest.end(), g);

    auto p1 = mp::permuteAuth(s1, dest);
    auto p2 = mp::permuteAuth(s2, dest);

    // Invariant still holds.
    if (!mp::verifyAuthShares(p1, p2, alpha)) return false;

    // Joint reconstruction = plain[dest[i]].
    for (size_t i = 0; i < plain.size(); ++i) {
        block joint = p1.data[i] ^ p2.data[i];
        block expected = plain[dest[i]];
        if (!blocksEq(joint, expected)) return false;
    }
    return true;
}

bool test_verifyAuth_rejects_tampered_data() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x55, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 8);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);

    // Flip a bit in s1's data — the joint reconstruction is wrong, but
    // since the tag wasn't updated, the verifier should reject.
    auto* bytes = reinterpret_cast<uint8_t*>(&s1.data[3]);
    bytes[0] ^= 1;

    return !mp::verifyAuthShares(s1, s2, alpha);
}

bool test_verifyAuth_rejects_tampered_tag() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x66, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 8);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);

    auto* bytes = reinterpret_cast<uint8_t*>(&s1.tag[5]);
    bytes[3] ^= 0x10;

    return !mp::verifyAuthShares(s1, s2, alpha);
}

bool test_batched_verify_accepts_honest() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x77, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 64);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);
    auto challenge = randomVec(prng, 64);

    return mp::verifyAuthSharesBatched(s1, s2, alpha, challenge);
}

bool test_batched_verify_rejects_tampered() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x88, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 64);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);
    auto challenge = randomVec(prng, 64);

    // Tamper with a single element.
    auto* bytes = reinterpret_cast<uint8_t*>(&s2.data[30]);
    bytes[5] ^= 0xAA;

    // Soundness is 2^{-128} per check, so with random challenge this
    // virtually-always rejects.
    return !mp::verifyAuthSharesBatched(s1, s2, alpha, challenge);
}

bool test_xorConstAuth_updates_tag() {
    oc::PRNG prng;
    block seed; std::memset(&seed, 0x99, 16);
    prng.SetSeed(seed);

    block alpha = randomBlock(prng);
    auto plain = randomVec(prng, 8);
    auto c = randomVec(prng, 8);
    auto [s1, s2] = mp::randomAuthShare(plain, alpha, prng);

    // Only ONE party applies the public constant; tag is updated by them.
    // The other party doesn't change. The joint reconstruction becomes
    // plain ⊕ c.
    auto s1_prime = mp::xorConstAuth(s1, c, alpha);

    for (size_t i = 0; i < plain.size(); ++i) {
        block joint = s1_prime.data[i] ^ s2.data[i];
        block expected = plain[i] ^ c[i];
        if (!blocksEq(joint, expected)) return false;
    }
    // Invariant should still hold under alpha.
    return mp::verifyAuthShares(s1_prime, s2, alpha);
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"tagVector_correct",                test_tagVector_correct},
        {"randomAuthShare_invariant",        test_randomAuthShare_invariant},
        {"randomAuthShare_unique",           test_randomAuthShare_unique},
        {"xorAuth_preserves_invariant",      test_xorAuth_preserves_invariant},
        {"permuteAuth_preserves_invariant",  test_permuteAuth_preserves_invariant},
        {"verifyAuth_rejects_tampered_data", test_verifyAuth_rejects_tampered_data},
        {"verifyAuth_rejects_tampered_tag",  test_verifyAuth_rejects_tampered_tag},
        {"batched_verify_accepts_honest",    test_batched_verify_accepts_honest},
        {"batched_verify_rejects_tampered",  test_batched_verify_rejects_tampered},
        {"xorConstAuth_updates_tag",         test_xorConstAuth_updates_tag},
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
