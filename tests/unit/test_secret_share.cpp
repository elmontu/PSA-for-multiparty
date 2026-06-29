// Unit tests for volePSI/MpSecretShare.h + MpBeaverTriple.h (R34a-c).
// Foundation MPC primitives for the SP-blind private join.
//
// Verifies:
//   1. shareU64: reconstruct returns the original value
//   2. shareU64: shares are uniformly random (each share != value)
//   3. addShared, subShared, addConst, mulConst: arithmetic correctness
//   4. shareBit: reconstruct returns the original bit
//   5. xorShared, xorConst: bit arithmetic correctness
//   6. Beaver triple invariant: w = u * v (mod 2^64)
//   7. secureMultiply: result reconstructs to x * y
//   8. secureMultiply: shares remain hidden (any single share is not x*y)
//   9. Beaver triple bit invariant: w = u AND v
//  10. secureAnd: result reconstructs to x AND y
//  11. Multi-party (N=3, 5) sharing works the same

#include "volePSI/MpSecretShare.h"
#include "volePSI/MpBeaverTriple.h"
#include "cryptoTools/Crypto/PRNG.h"

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

bool test_shareU64_roundtrip() {
    auto prng = makePrng(0x01);
    for (uint32_t N : {2u, 3u, 5u, 10u}) {
        std::vector<uint64_t> values = {0ULL, 1ULL, 42ULL, 0xDEADBEEFCAFEULL,
                                        uint64_t(-1ULL)};
        for (uint64_t v : values) {
            auto s = mp::shareU64(N, v, prng);
            if (s.reconstruct() != v) return false;
            if (s.shares.size() != N) return false;
        }
    }
    return true;
}

bool test_shareU64_shares_random() {
    auto prng = makePrng(0x02);
    uint64_t v = 0xCAFEBABE12345678ULL;
    auto s = mp::shareU64(/*N=*/3, v, prng);
    // With high probability, no share equals v (each is random).
    int sharesEqualV = 0;
    for (uint64_t sh : s.shares) if (sh == v) ++sharesEqualV;
    return sharesEqualV <= 1;  // tolerate astronomically unlikely collision
}

bool test_addShared_correct() {
    auto prng = makePrng(0x03);
    auto a = mp::shareU64(3, 123, prng);
    auto b = mp::shareU64(3, 456, prng);
    auto c = mp::addShared(a, b);
    return c.reconstruct() == 579ULL;
}

bool test_subShared_correct() {
    auto prng = makePrng(0x04);
    auto a = mp::shareU64(3, 1000, prng);
    auto b = mp::shareU64(3, 300, prng);
    auto c = mp::subShared(a, b);
    return c.reconstruct() == 700ULL;
}

bool test_addConst_mulConst_correct() {
    auto prng = makePrng(0x05);
    auto a = mp::shareU64(3, 10, prng);
    auto b = mp::addConst(a, 5);
    if (b.reconstruct() != 15) return false;
    auto c = mp::mulConst(a, 7);
    if (c.reconstruct() != 70) return false;
    return true;
}

bool test_shareBit_roundtrip() {
    auto prng = makePrng(0x06);
    for (uint32_t N : {2u, 3u, 5u}) {
        for (uint8_t v : {uint8_t{0}, uint8_t{1}}) {
            auto s = mp::shareBit(N, v, prng);
            if (s.reconstruct() != v) return false;
        }
    }
    return true;
}

bool test_xorShared_xorConst() {
    auto prng = makePrng(0x07);
    auto a = mp::shareBit(3, 1, prng);
    auto b = mp::shareBit(3, 0, prng);
    auto c = mp::xorShared(a, b);
    if (c.reconstruct() != 1) return false;
    auto d = mp::xorConst(a, 1);
    return d.reconstruct() == 0;
}

bool test_beaver_triple_invariant() {
    auto prng = makePrng(0x08);
    for (int iter = 0; iter < 20; ++iter) {
        auto t = mp::generateBeaverTriple(3, prng);
        uint64_t u = t.u.reconstruct();
        uint64_t v = t.v.reconstruct();
        uint64_t w = t.w.reconstruct();
        if (w != u * v) return false;
    }
    return true;
}

bool test_secureMultiply_correctness() {
    auto prng = makePrng(0x09);
    for (int iter = 0; iter < 50; ++iter) {
        uint64_t x = prng.get<uint64_t>();
        uint64_t y = prng.get<uint64_t>();
        auto xs = mp::shareU64(3, x, prng);
        auto ys = mp::shareU64(3, y, prng);
        auto triple = mp::generateBeaverTriple(3, prng);
        auto zs = mp::secureMultiply(xs, ys, triple);
        if (zs.reconstruct() != x * y) return false;
    }
    return true;
}

bool test_secureMultiply_shares_hidden() {
    // Each share of the result must NOT be the plaintext product.
    auto prng = makePrng(0x0A);
    uint64_t x = 1234567ULL, y = 9876543ULL;
    auto xs = mp::shareU64(4, x, prng);
    auto ys = mp::shareU64(4, y, prng);
    auto triple = mp::generateBeaverTriple(4, prng);
    auto zs = mp::secureMultiply(xs, ys, triple);
    uint64_t target = x * y;
    for (uint64_t s : zs.shares) {
        if (s == target) return false;
    }
    return zs.reconstruct() == target;
}

bool test_beaver_triple_bit_invariant() {
    auto prng = makePrng(0x0B);
    for (int iter = 0; iter < 30; ++iter) {
        auto t = mp::generateBeaverTripleBit(3, prng);
        uint8_t u = t.u.reconstruct();
        uint8_t v = t.v.reconstruct();
        uint8_t w = t.w.reconstruct();
        if (w != (u & v)) return false;
    }
    return true;
}

bool test_secureAnd_correctness() {
    auto prng = makePrng(0x0C);
    for (uint8_t x : {uint8_t{0}, uint8_t{1}}) {
        for (uint8_t y : {uint8_t{0}, uint8_t{1}}) {
            auto xs = mp::shareBit(3, x, prng);
            auto ys = mp::shareBit(3, y, prng);
            auto t  = mp::generateBeaverTripleBit(3, prng);
            auto zs = mp::secureAnd(xs, ys, t);
            if (zs.reconstruct() != (x & y)) return false;
        }
    }
    return true;
}

bool test_multi_party_N_varied() {
    auto prng = makePrng(0x0D);
    for (uint32_t N : {2u, 4u, 7u}) {
        auto xs = mp::shareU64(N, 0xAAAA, prng);
        auto ys = mp::shareU64(N, 0xBBBB, prng);
        auto t  = mp::generateBeaverTriple(N, prng);
        auto zs = mp::secureMultiply(xs, ys, t);
        if (zs.reconstruct() != 0xAAAAULL * 0xBBBBULL) return false;
    }
    return true;
}

bool test_chain_of_multiplications() {
    // (a * b) * c via two sequential secure multiplications.
    auto prng = makePrng(0x0E);
    uint64_t a = 123, b = 7, c = 5;
    auto as = mp::shareU64(3, a, prng);
    auto bs = mp::shareU64(3, b, prng);
    auto cs = mp::shareU64(3, c, prng);
    auto t1 = mp::generateBeaverTriple(3, prng);
    auto t2 = mp::generateBeaverTriple(3, prng);
    auto abs = mp::secureMultiply(as, bs, t1);
    auto abcs = mp::secureMultiply(abs, cs, t2);
    return abcs.reconstruct() == a * b * c;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"shareU64_roundtrip",            test_shareU64_roundtrip},
        {"shareU64_shares_random",        test_shareU64_shares_random},
        {"addShared_correct",             test_addShared_correct},
        {"subShared_correct",             test_subShared_correct},
        {"addConst_mulConst_correct",     test_addConst_mulConst_correct},
        {"shareBit_roundtrip",            test_shareBit_roundtrip},
        {"xorShared_xorConst",            test_xorShared_xorConst},
        {"beaver_triple_invariant",       test_beaver_triple_invariant},
        {"secureMultiply_correctness",    test_secureMultiply_correctness},
        {"secureMultiply_shares_hidden",  test_secureMultiply_shares_hidden},
        {"beaver_triple_bit_invariant",   test_beaver_triple_bit_invariant},
        {"secureAnd_correctness",         test_secureAnd_correctness},
        {"multi_party_N_varied",          test_multi_party_N_varied},
        {"chain_of_multiplications",      test_chain_of_multiplications},
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
