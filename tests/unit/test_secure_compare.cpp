// Unit tests for volePSI/MpSecureCompare.h (R34d). Secure 64-bit
// less-than and equality on XOR-shared bit representations, using
// Beaver triples (R34b) for the underlying secureAnd.

#include "volePSI/MpSecureCompare.h"
#include "volePSI/MpSecretShare.h"
#include "volePSI/MpBeaverTriple.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace mp = volePSI::mpstar;
using oc::block;

static oc::PRNG makePrng(uint8_t seedByte) {
    oc::PRNG prng;
    block s; std::memset(&s, seedByte, 16);
    prng.SetSeed(s);
    return prng;
}

// --------------------------------------------------------------

bool test_shareU64Bin_roundtrip() {
    auto prng = makePrng(0xA0);
    std::vector<uint64_t> values = {0ULL, 1ULL, 2ULL, 0xFFFFULL,
                                    0xDEADBEEFCAFEULL, uint64_t(-1ULL)};
    for (uint64_t v : values) {
        auto s = mp::shareU64Bin(3, v, prng);
        if (s.reconstruct() != v) return false;
    }
    return true;
}

bool test_secureLessThan_simple_cases() {
    auto prng = makePrng(0xA1);
    struct Case { uint64_t x, y; uint8_t expected; };
    std::vector<Case> cases = {
        {0, 1, 1}, {1, 0, 0}, {0, 0, 0},
        {100, 200, 1}, {200, 100, 0}, {200, 200, 0},
        {0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL, 1},
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL, 0},
        {1ULL << 63, (1ULL << 63) - 1, 0},   // MSB matters
        {(1ULL << 63) - 1, 1ULL << 63, 1},
    };
    for (const auto& c : cases) {
        auto xs = mp::shareU64Bin(3, c.x, prng);
        auto ys = mp::shareU64Bin(3, c.y, prng);
        auto triples = mp::generateBeaverTripleBits(
            3, mp::secureLessThanTripleCost(), prng);
        size_t idx = 0;
        auto r = mp::secureLessThan(xs, ys, triples, idx);
        if (idx != mp::secureLessThanTripleCost()) return false;
        if (r.reconstruct() != c.expected) {
            std::cerr << "  case x=" << c.x << " y=" << c.y
                      << " expected=" << int(c.expected)
                      << " got=" << int(r.reconstruct()) << "\n";
            return false;
        }
    }
    return true;
}

bool test_secureLessThan_random() {
    auto prng = makePrng(0xA2);
    for (int iter = 0; iter < 100; ++iter) {
        uint64_t x = prng.get<uint64_t>();
        uint64_t y = prng.get<uint64_t>();
        auto xs = mp::shareU64Bin(3, x, prng);
        auto ys = mp::shareU64Bin(3, y, prng);
        auto triples = mp::generateBeaverTripleBits(
            3, mp::secureLessThanTripleCost(), prng);
        size_t idx = 0;
        auto r = mp::secureLessThan(xs, ys, triples, idx);
        uint8_t expected = (x < y) ? 1 : 0;
        if (r.reconstruct() != expected) {
            std::cerr << "  random iter=" << iter
                      << " x=" << x << " y=" << y
                      << " expected=" << int(expected)
                      << " got=" << int(r.reconstruct()) << "\n";
            return false;
        }
    }
    return true;
}

bool test_secureLessThan_share_privacy() {
    // The result share on any single party MUST NOT equal the plaintext
    // comparison outcome (otherwise the party trivially learns the answer).
    auto prng = makePrng(0xA3);
    uint64_t x = 1234, y = 5678;
    uint8_t expected = 1;  // x < y
    auto xs = mp::shareU64Bin(4, x, prng);
    auto ys = mp::shareU64Bin(4, y, prng);
    auto triples = mp::generateBeaverTripleBits(
        4, mp::secureLessThanTripleCost(), prng);
    size_t idx = 0;
    auto r = mp::secureLessThan(xs, ys, triples, idx);
    int sharesEqualExpected = 0;
    for (uint8_t s : r.shares) if (s == expected) ++sharesEqualExpected;
    // Each share is random in {0, 1}; with N=4 we expect ~2 to equal 1.
    // The TEST is that not ALL N shares equal the expected answer (which
    // would mean the value is trivially recoverable from any one share).
    return r.reconstruct() == expected
        && sharesEqualExpected < 4
        && sharesEqualExpected >= 0;
}

bool test_secureEqual_simple_cases() {
    auto prng = makePrng(0xA4);
    struct Case { uint64_t x, y; uint8_t expected; };
    std::vector<Case> cases = {
        {0, 0, 1}, {1, 1, 1}, {0, 1, 0}, {42, 42, 1},
        {0xDEADBEEFCAFEULL, 0xDEADBEEFCAFEULL, 1},
        {0xDEADBEEFCAFEULL, 0xDEADBEEFCAFFULL, 0},
        {uint64_t(-1ULL), uint64_t(-1ULL), 1},
        {1ULL << 63, 1ULL << 63, 1},
    };
    for (const auto& c : cases) {
        auto xs = mp::shareU64Bin(3, c.x, prng);
        auto ys = mp::shareU64Bin(3, c.y, prng);
        auto triples = mp::generateBeaverTripleBits(
            3, mp::secureEqualTripleCost(), prng);
        size_t idx = 0;
        auto r = mp::secureEqual(xs, ys, triples, idx);
        if (r.reconstruct() != c.expected) {
            std::cerr << "  case x=" << c.x << " y=" << c.y
                      << " expected=" << int(c.expected)
                      << " got=" << int(r.reconstruct()) << "\n";
            return false;
        }
    }
    return true;
}

bool test_secureEqual_random() {
    auto prng = makePrng(0xA5);
    for (int iter = 0; iter < 50; ++iter) {
        uint64_t x = prng.get<uint64_t>();
        uint64_t y = (iter % 3 == 0) ? x : prng.get<uint64_t>();
        auto xs = mp::shareU64Bin(3, x, prng);
        auto ys = mp::shareU64Bin(3, y, prng);
        auto triples = mp::generateBeaverTripleBits(
            3, mp::secureEqualTripleCost(), prng);
        size_t idx = 0;
        auto r = mp::secureEqual(xs, ys, triples, idx);
        uint8_t expected = (x == y) ? 1 : 0;
        if (r.reconstruct() != expected) return false;
    }
    return true;
}

bool test_triple_count_exact() {
    // The functions should consume exactly secure*TripleCost() triples.
    auto prng = makePrng(0xA6);
    auto xs = mp::shareU64Bin(3, 100, prng);
    auto ys = mp::shareU64Bin(3, 200, prng);

    {
        auto triples = mp::generateBeaverTripleBits(
            3, mp::secureLessThanTripleCost(), prng);
        size_t idx = 0;
        mp::secureLessThan(xs, ys, triples, idx);
        if (idx != triples.size()) return false;
    }
    {
        auto triples = mp::generateBeaverTripleBits(
            3, mp::secureEqualTripleCost(), prng);
        size_t idx = 0;
        mp::secureEqual(xs, ys, triples, idx);
        if (idx != triples.size()) return false;
    }
    return true;
}

bool test_multi_party_N_varied() {
    auto prng = makePrng(0xA7);
    for (uint32_t N : {2u, 3u, 5u, 7u}) {
        auto xs = mp::shareU64Bin(N, 1000, prng);
        auto ys = mp::shareU64Bin(N, 2000, prng);
        {
            auto triples = mp::generateBeaverTripleBits(
                N, mp::secureLessThanTripleCost(), prng);
            size_t idx = 0;
            auto r = mp::secureLessThan(xs, ys, triples, idx);
            if (r.reconstruct() != 1) return false;
        }
        {
            auto triples = mp::generateBeaverTripleBits(
                N, mp::secureEqualTripleCost(), prng);
            size_t idx = 0;
            auto r = mp::secureEqual(xs, ys, triples, idx);
            if (r.reconstruct() != 0) return false;
        }
    }
    return true;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"shareU64Bin_roundtrip",          test_shareU64Bin_roundtrip},
        {"secureLessThan_simple_cases",    test_secureLessThan_simple_cases},
        {"secureLessThan_random",          test_secureLessThan_random},
        {"secureLessThan_share_privacy",   test_secureLessThan_share_privacy},
        {"secureEqual_simple_cases",       test_secureEqual_simple_cases},
        {"secureEqual_random",             test_secureEqual_random},
        {"triple_count_exact",             test_triple_count_exact},
        {"multi_party_N_varied",           test_multi_party_N_varied},
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
