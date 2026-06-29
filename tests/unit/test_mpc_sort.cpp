// Unit tests for volePSI/MpMpcSort.h (R34e + R34f). MPC bitonic sort on
// secret-shared elements, composing R34d secureLessThan + R34a/b/c
// primitives.

#include "volePSI/MpMpcSort.h"
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

static oc::PRNG makePrng(uint8_t b) {
    oc::PRNG p;
    block s; std::memset(&s, b, 16);
    p.SetSeed(s);
    return p;
}

// Build a SharedSortElement from plaintext key + payload bits.
static mp::SharedSortElement makeElem(uint32_t N, uint64_t key,
                                      uint64_t payloadTag,
                                      uint32_t payloadBits,
                                      oc::PRNG& prng)
{
    mp::SharedSortElement e;
    e.key = mp::shareU64Bin(N, key, prng);
    e.payload.resize(payloadBits);
    for (uint32_t i = 0; i < payloadBits; ++i) {
        uint8_t bit = (i < 64) ? ((payloadTag >> i) & 1) : 0;
        e.payload[i] = mp::shareBit(N, bit, prng);
    }
    return e;
}

static uint64_t reconstructPayload(const mp::SharedSortElement& e) {
    uint64_t v = 0;
    for (uint32_t i = 0; i < std::min<uint32_t>(64, e.payload.size()); ++i) {
        v |= (uint64_t(e.payload[i].reconstruct() & 1) << i);
    }
    return v;
}

// --------------------------------------------------------------

bool test_conditional_swap_selector_zero() {
    auto prng = makePrng(0xB0);
    const uint32_t N = 3, B = 16;  // 16-bit payload
    auto a = makeElem(N, 100, 0xAAAA, B, prng);
    auto b = makeElem(N, 200, 0xBBBB, B, prng);

    auto sel = mp::shareBit(N, 0, prng);
    auto triples = mp::generateBeaverTripleBits(
        N, mp::conditionalSwapTripleCost(B), prng);
    size_t idx = 0;
    mp::conditionalSwap(a, b, sel, triples, idx);

    if (a.key.reconstruct() != 100) return false;
    if (b.key.reconstruct() != 200) return false;
    if (reconstructPayload(a) != 0xAAAA) return false;
    if (reconstructPayload(b) != 0xBBBB) return false;
    return true;
}

bool test_conditional_swap_selector_one() {
    auto prng = makePrng(0xB1);
    const uint32_t N = 3, B = 16;
    auto a = makeElem(N, 100, 0xAAAA, B, prng);
    auto b = makeElem(N, 200, 0xBBBB, B, prng);

    auto sel = mp::shareBit(N, 1, prng);
    auto triples = mp::generateBeaverTripleBits(
        N, mp::conditionalSwapTripleCost(B), prng);
    size_t idx = 0;
    mp::conditionalSwap(a, b, sel, triples, idx);

    if (a.key.reconstruct() != 200) return false;
    if (b.key.reconstruct() != 100) return false;
    if (reconstructPayload(a) != 0xBBBB) return false;
    if (reconstructPayload(b) != 0xAAAA) return false;
    return true;
}

bool test_mpc_sort_small() {
    auto prng = makePrng(0xB2);
    const uint32_t N = 3, B = 32;
    // 4 elements, descending → must sort ascending.
    std::vector<mp::SharedSortElement> xs;
    xs.push_back(makeElem(N, 40, 4, B, prng));
    xs.push_back(makeElem(N, 30, 3, B, prng));
    xs.push_back(makeElem(N, 20, 2, B, prng));
    xs.push_back(makeElem(N, 10, 1, B, prng));

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcBitonicSortTripleCost(xs.size(), B), prng);
    size_t idx = 0;
    mp::mpcBitonicSort(xs, triples, idx);

    // Verify ascending.
    uint64_t last = 0;
    for (const auto& e : xs) {
        uint64_t k = e.key.reconstruct();
        if (k < last) return false;
        last = k;
    }
    // Verify payloads tracked their keys.
    std::vector<std::pair<uint64_t, uint64_t>> kp;
    for (const auto& e : xs) kp.push_back({e.key.reconstruct(), reconstructPayload(e)});
    std::vector<std::pair<uint64_t, uint64_t>> expected = {
        {10, 1}, {20, 2}, {30, 3}, {40, 4}};
    return kp == expected;
}

bool test_mpc_sort_random() {
    auto prng = makePrng(0xB3);
    const uint32_t N = 3, B = 16;
    const size_t n = 16;

    std::vector<uint64_t> originalKeys;
    std::vector<uint64_t> originalPayloads;
    std::vector<mp::SharedSortElement> xs;
    std::mt19937 g(123);
    for (size_t i = 0; i < n; ++i) {
        uint64_t k = g() % 10000;
        uint64_t p = k;  // payload = key for traceability
        originalKeys.push_back(k);
        originalPayloads.push_back(p);
        xs.push_back(makeElem(N, k, p, B, prng));
    }

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcBitonicSortTripleCost(n, B), prng);
    size_t idx = 0;
    mp::mpcBitonicSort(xs, triples, idx);

    // Verify ascending + payload-key consistency.
    uint64_t last = 0;
    for (const auto& e : xs) {
        uint64_t k = e.key.reconstruct();
        uint64_t p = reconstructPayload(e);
        if (k < last) return false;
        if (k != p) return false;  // payload == key by construction
        last = k;
    }
    // Multiset of keys preserved.
    std::sort(originalKeys.begin(), originalKeys.end());
    std::vector<uint64_t> outKeys;
    for (const auto& e : xs) outKeys.push_back(e.key.reconstruct());
    return outKeys == originalKeys;
}

bool test_mpc_sort_non_power_of_two() {
    auto prng = makePrng(0xB4);
    const uint32_t N = 3, B = 8;
    const size_t n = 7;  // non-power-of-two

    std::vector<uint64_t> originalKeys;
    std::vector<mp::SharedSortElement> xs;
    std::mt19937 g(456);
    for (size_t i = 0; i < n; ++i) {
        uint64_t k = g() % 1000;
        originalKeys.push_back(k);
        xs.push_back(makeElem(N, k, k, B, prng));
    }

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcBitonicSortTripleCost(n, B), prng);
    size_t idx = 0;
    mp::mpcBitonicSort(xs, triples, idx);

    if (xs.size() != n) return false;
    uint64_t last = 0;
    for (const auto& e : xs) {
        uint64_t k = e.key.reconstruct();
        if (k < last) return false;
        last = k;
    }
    return true;
}

bool test_triple_cost_exact() {
    // mpcBitonicSort should consume exactly mpcBitonicSortTripleCost(n, B)
    // triples (no off-by-one).
    auto prng = makePrng(0xB5);
    const uint32_t N = 3, B = 16;
    const size_t n = 8;
    std::vector<mp::SharedSortElement> xs;
    std::mt19937 g(789);
    for (size_t i = 0; i < n; ++i) {
        xs.push_back(makeElem(N, g() % 100, 0, B, prng));
    }
    const size_t expected = mp::mpcBitonicSortTripleCost(n, B);
    auto triples = mp::generateBeaverTripleBits(N, expected, prng);
    size_t idx = 0;
    mp::mpcBitonicSort(xs, triples, idx);
    return idx == expected;
}

bool test_share_privacy_individual_party() {
    // After the sort, no individual party should be able to reconstruct
    // a key from its OWN share alone. We test this loosely: each
    // individual share of a key bit should NOT equal the plaintext bit.
    auto prng = makePrng(0xB6);
    const uint32_t N = 3, B = 8;
    auto a = makeElem(N, 0x1234, 0x42, B, prng);

    // The 0-th bit of key 0x1234 is 0. Verify that not ALL party shares
    // equal 0 for that bit position (otherwise the bit is trivially
    // recoverable).
    int zeroCount = 0;
    for (uint32_t i = 0; i < N; ++i) {
        if (a.key.bits[0].shares[i] == 0) ++zeroCount;
    }
    return zeroCount < int(N);
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"conditional_swap_selector_zero",  test_conditional_swap_selector_zero},
        {"conditional_swap_selector_one",   test_conditional_swap_selector_one},
        {"mpc_sort_small",                  test_mpc_sort_small},
        {"mpc_sort_random",                 test_mpc_sort_random},
        {"mpc_sort_non_power_of_two",       test_mpc_sort_non_power_of_two},
        {"triple_cost_exact",               test_triple_cost_exact},
        {"share_privacy_individual_party",  test_share_privacy_individual_party},
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
