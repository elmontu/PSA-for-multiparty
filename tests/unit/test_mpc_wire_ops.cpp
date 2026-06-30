// R36b: wire conditional swap + wire MPC bitonic sort.

#include "volePSI/MpMpcWireOps.h"
#include "volePSI/MpMpcWire.h"
#include "volePSI/MpSecretShare.h"
#include "volePSI/MpBeaverTriple.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "macoro/task.h"

#include <algorithm>
#include <array>
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

static std::pair<uint8_t, uint8_t> splitBit(uint8_t v, oc::PRNG& prng) {
    uint8_t s0 = prng.get<uint8_t>() & 1;
    uint8_t s1 = (v ^ s0) & 1;
    return {s0, s1};
}

static std::pair<std::array<uint8_t, 64>, std::array<uint8_t, 64>>
splitU64Bin(uint64_t v, oc::PRNG& prng) {
    std::array<uint8_t, 64> s0{}, s1{};
    for (int i = 0; i < 64; ++i) {
        uint8_t bit = static_cast<uint8_t>((v >> i) & 1);
        auto [a, b] = splitBit(bit, prng);
        s0[i] = a;
        s1[i] = b;
    }
    return {s0, s1};
}

static uint64_t joinU64Bin(const std::array<uint8_t, 64>& a,
                           const std::array<uint8_t, 64>& b) {
    uint64_t v = 0;
    for (int i = 0; i < 64; ++i) {
        uint8_t bit = (a[i] ^ b[i]) & 1;
        v |= (uint64_t(bit) << i);
    }
    return v;
}

// Helper: create a (party-0 share, party-1 share) WireSortElement pair
// for given plaintext key + payload.
static std::pair<mp::WireSortElement, mp::WireSortElement>
splitElement(uint64_t key, const std::vector<uint8_t>& payload, oc::PRNG& prng) {
    mp::WireSortElement e0, e1;
    auto [k0, k1] = splitU64Bin(key, prng);
    e0.key = k0; e1.key = k1;
    e0.payload.resize(payload.size());
    e1.payload.resize(payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        auto [a, b] = splitBit(payload[i], prng);
        e0.payload[i] = a;
        e1.payload[i] = b;
    }
    return {e0, e1};
}

// --------------------------------------------------------------

bool test_wire_conditional_swap_selector_0() {
    auto prng = makePrng(0x40);
    auto [a0, a1] = splitElement(100, {1,0,1,0}, prng);
    auto [b0, b1] = splitElement(200, {0,1,0,1}, prng);
    auto [s0, s1] = splitBit(0, prng);  // selector = 0 → no swap

    const size_t W = 4;
    // wireConditionalSwap consumes 64 (key bits) + W (payload bits) triples.
    auto triples = mp::generateBeaverTripleBits(2, 64 + W, prng);

    auto socks = coproto::LocalAsyncSocket::makePair();
    size_t i0 = 0, i1 = 0;
    auto t0 = [&]() -> macoro::task<void> {
        co_await mp::wireConditionalSwap(a0, b0, s0, triples, i0, 0, socks[0]);
    };
    auto t1 = [&]() -> macoro::task<void> {
        co_await mp::wireConditionalSwap(a1, b1, s1, triples, i1, 1, socks[1]);
    };
    macoro::sync_wait(macoro::when_all_ready(t0(), t1()));

    if (joinU64Bin(a0.key, a1.key) != 100) return false;
    if (joinU64Bin(b0.key, b1.key) != 200) return false;
    for (size_t i = 0; i < W; ++i) {
        if (((a0.payload[i] ^ a1.payload[i]) & 1) != ((std::vector<uint8_t>{1,0,1,0})[i])) return false;
        if (((b0.payload[i] ^ b1.payload[i]) & 1) != ((std::vector<uint8_t>{0,1,0,1})[i])) return false;
    }
    return true;
}

bool test_wire_conditional_swap_selector_1() {
    auto prng = makePrng(0x41);
    auto [a0, a1] = splitElement(100, {1,1,0,0}, prng);
    auto [b0, b1] = splitElement(200, {0,0,1,1}, prng);
    auto [s0, s1] = splitBit(1, prng);  // selector = 1 → swap

    const size_t W = 4;
    auto triples = mp::generateBeaverTripleBits(2, 64 + W, prng);

    auto socks = coproto::LocalAsyncSocket::makePair();
    size_t i0 = 0, i1 = 0;
    auto t0 = [&]() -> macoro::task<void> {
        co_await mp::wireConditionalSwap(a0, b0, s0, triples, i0, 0, socks[0]);
    };
    auto t1 = [&]() -> macoro::task<void> {
        co_await mp::wireConditionalSwap(a1, b1, s1, triples, i1, 1, socks[1]);
    };
    macoro::sync_wait(macoro::when_all_ready(t0(), t1()));

    // After swap: a holds 200/{0,0,1,1}; b holds 100/{1,1,0,0}.
    if (joinU64Bin(a0.key, a1.key) != 200) return false;
    if (joinU64Bin(b0.key, b1.key) != 100) return false;
    for (size_t i = 0; i < W; ++i) {
        if (((a0.payload[i] ^ a1.payload[i]) & 1) != ((std::vector<uint8_t>{0,0,1,1})[i])) return false;
        if (((b0.payload[i] ^ b1.payload[i]) & 1) != ((std::vector<uint8_t>{1,1,0,0})[i])) return false;
    }
    return true;
}

bool test_wire_mpc_bitonic_sort_small() {
    auto prng = makePrng(0x42);
    // 4 elements, descending keys → must sort ascending. Payload tracks key.
    std::vector<uint64_t> plainKeys = {40, 30, 20, 10};
    const size_t W = 0;  // no payload for the simplest test

    std::vector<mp::WireSortElement> p0elts, p1elts;
    for (uint64_t k : plainKeys) {
        auto [e0, e1] = splitElement(k, {}, prng);
        p0elts.push_back(std::move(e0));
        p1elts.push_back(std::move(e1));
    }

    auto triples = mp::generateBeaverTripleBits(
        2, mp::wireMpcBitonicSortTripleCost(plainKeys.size(), W), prng);

    auto socks = coproto::LocalAsyncSocket::makePair();
    size_t i0 = 0, i1 = 0;
    auto t0 = [&]() -> macoro::task<void> {
        co_await mp::wireMpcBitonicSort(p0elts, triples, i0, 0, socks[0]);
    };
    auto t1 = [&]() -> macoro::task<void> {
        co_await mp::wireMpcBitonicSort(p1elts, triples, i1, 1, socks[1]);
    };
    macoro::sync_wait(macoro::when_all_ready(t0(), t1()));

    // Check sorted ascending.
    uint64_t last = 0;
    for (size_t i = 0; i < p0elts.size(); ++i) {
        uint64_t k = joinU64Bin(p0elts[i].key, p1elts[i].key);
        if (k < last) {
            std::cerr << "  not sorted at " << i << ": last=" << last << " current=" << k << "\n";
            return false;
        }
        last = k;
    }
    return true;
}

// --------------------------------------------------------------

// Helper: build a WireSortElement for the cross-product expander.
// Composite key (id << partyIdxBits) | party_idx; payload = [is_real bit][rowDataBits].
static std::pair<mp::WireSortElement, mp::WireSortElement>
makeCpTuple(uint64_t id, uint32_t partyIdxBits, uint32_t party_idx,
            uint8_t isReal, uint32_t rowDataBits, uint64_t dataTag,
            oc::PRNG& prng) {
    uint64_t composite = (id << partyIdxBits) | party_idx;
    auto [k0, k1] = splitU64Bin(composite, prng);
    mp::WireSortElement e0, e1;
    e0.key = k0; e1.key = k1;
    e0.payload.resize(1 + rowDataBits);
    e1.payload.resize(1 + rowDataBits);
    auto [r0, r1] = splitBit(isReal, prng);
    e0.payload[0] = r0; e1.payload[0] = r1;
    for (uint32_t b = 0; b < rowDataBits; ++b) {
        uint8_t bit = static_cast<uint8_t>((dataTag >> (b % 64)) & 1);
        auto [a, c] = splitBit(bit, prng);
        e0.payload[1 + b] = a;
        e1.payload[1 + b] = c;
    }
    return {e0, e1};
}

bool test_wire_cross_product_full_intersection() {
    // N=2, M=2, 1 window. M^N=4 expanded rows, all is_intersection=1.
    auto prng = makePrng(0x50);
    const uint32_t N = 2, M = 2, partyIdxBits = 1, rowDataBits = 4;
    uint64_t id = 42;

    std::vector<mp::WireSortElement> bag0, bag1;
    for (uint32_t p = 0; p < N; ++p) {
        for (uint32_t r = 0; r < M; ++r) {
            auto [e0, e1] = makeCpTuple(id, partyIdxBits, p, 1, rowDataBits,
                                        0xA0 + (p << 4) + r, prng);
            bag0.push_back(std::move(e0));
            bag1.push_back(std::move(e1));
        }
    }

    auto triples = mp::generateBeaverTripleBits(
        2, mp::wireMpcCrossProductExpandTripleCost(1, N, M), prng);

    auto socks = coproto::LocalAsyncSocket::makePair();
    size_t i0 = 0, i1 = 0;
    auto t0 = [&]() -> macoro::task<std::vector<mp::WireMpcJoinRow>> {
        co_return co_await mp::wireMpcCrossProductExpand(
            bag0, N, M, partyIdxBits, rowDataBits, triples, i0, 0, socks[0]);
    };
    auto t1 = [&]() -> macoro::task<std::vector<mp::WireMpcJoinRow>> {
        co_return co_await mp::wireMpcCrossProductExpand(
            bag1, N, M, partyIdxBits, rowDataBits, triples, i1, 1, socks[1]);
    };
    auto r = macoro::sync_wait(macoro::when_all_ready(t0(), t1()));
    auto out0 = std::move(std::get<0>(r)).result();
    auto out1 = std::move(std::get<1>(r)).result();

    if (out0.size() != 4 || out1.size() != 4) return false;
    for (size_t i = 0; i < 4; ++i) {
        uint8_t joint = (out0[i].isIntersection ^ out1[i].isIntersection) & 1;
        if (joint != 1) return false;
        // Joint id should equal 42.
        if (joinU64Bin(out0[i].id, out1[i].id) != 42) return false;
    }
    return true;
}

bool test_wire_filter_pushes_intersection_to_front() {
    // 4 rows, alternating is_intersection=1/0. After wire filter, first
    // 2 should reconstruct to 1, last 2 to 0.
    auto prng = makePrng(0x51);
    const uint32_t N = 2, rowDataBits = 4;

    std::vector<mp::WireMpcJoinRow> rows0, rows1;
    for (int i = 0; i < 4; ++i) {
        mp::WireMpcJoinRow r0, r1;
        auto [k0, k1] = splitU64Bin(100 + i, prng);
        r0.id = k0; r1.id = k1;
        r0.joinedPayload.resize(N * rowDataBits, 0);
        r1.joinedPayload.resize(N * rowDataBits, 0);
        for (auto& b : r0.joinedPayload) b = prng.get<uint8_t>() & 1;
        for (size_t j = 0; j < r0.joinedPayload.size(); ++j)
            r1.joinedPayload[j] = r0.joinedPayload[j];  // both shares zero-joint payload doesn't matter
        auto [s0, s1] = splitBit((i % 2 == 0) ? 1 : 0, prng);
        r0.isIntersection = s0; r1.isIntersection = s1;
        rows0.push_back(r0); rows1.push_back(r1);
    }

    auto triples = mp::generateBeaverTripleBits(
        2, mp::wireMpcFilterIntersectionTripleCost(rows0.size(), N, rowDataBits), prng);

    auto socks = coproto::LocalAsyncSocket::makePair();
    size_t i0 = 0, i1 = 0;
    auto t0 = [&]() -> macoro::task<void> {
        co_await mp::wireMpcFilterIntersection(rows0, N, rowDataBits, triples, i0, 0, socks[0]);
    };
    auto t1 = [&]() -> macoro::task<void> {
        co_await mp::wireMpcFilterIntersection(rows1, N, rowDataBits, triples, i1, 1, socks[1]);
    };
    macoro::sync_wait(macoro::when_all_ready(t0(), t1()));

    // First 2 should have is_intersection=1; last 2 = 0.
    int trueAtFront = 0;
    int falseAtBack = 0;
    for (int i = 0; i < 4; ++i) {
        uint8_t joint = (rows0[i].isIntersection ^ rows1[i].isIntersection) & 1;
        if (i < 2 && joint == 1) ++trueAtFront;
        if (i >= 2 && joint == 0) ++falseAtBack;
    }
    return trueAtFront == 2 && falseAtBack == 2;
}

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"wire_conditional_swap_selector_0",     test_wire_conditional_swap_selector_0},
        {"wire_conditional_swap_selector_1",     test_wire_conditional_swap_selector_1},
        {"wire_mpc_bitonic_sort_small",          test_wire_mpc_bitonic_sort_small},
        {"wire_cross_product_full_intersection", test_wire_cross_product_full_intersection},
        {"wire_filter_pushes_intersection_to_front", test_wire_filter_pushes_intersection_to_front},
    };
    int failures = 0;
    for (const auto& [name, fn] : tests) {
        std::cout << name << ": ";
        try { std::cout << (fn() ? "PASS" : "FAIL") << "\n"; if (!fn()) ++failures; }
        catch (const std::exception& e) { std::cout << "FAIL (" << e.what() << ")\n"; ++failures; }
    }
    std::cout << (failures ? "FAILURES: " : "ALL PASSED. failures=") << failures << "\n";
    return failures ? 1 : 0;
}
