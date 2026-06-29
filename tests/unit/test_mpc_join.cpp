// Unit tests for volePSI/MpMpcJoin.h (R34g + R34h + R34i + R34j). End-
// to-end SP-blind private join in-memory, composing MPC sort + cross-
// product expansion + filter. Uses trusted-dealer Beaver triples.

#include "volePSI/MpMpcJoin.h"
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
#include <set>
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

// Reconstruct a vector of SharedBits into a uint64 (low bits first).
static uint64_t reconstructBitsToU64(const std::vector<mp::SharedBit>& bits) {
    uint64_t v = 0;
    for (size_t i = 0; i < std::min<size_t>(64, bits.size()); ++i) {
        v |= (uint64_t(bits[i].reconstruct() & 1) << i);
    }
    return v;
}

static mp::JoinInputRowShared makeInputRow(
    uint32_t N, uint64_t id, bool isReal,
    uint64_t rowDataTag, uint32_t rowDataBits,
    oc::PRNG& prng)
{
    mp::JoinInputRowShared r;
    r.id = mp::shareU64Bin(N, id, prng);
    r.isReal = mp::shareBit(N, isReal ? 1 : 0, prng);
    r.rowData.resize(rowDataBits);
    for (uint32_t i = 0; i < rowDataBits; ++i) {
        uint8_t bit = (i < 64) ? ((rowDataTag >> i) & 1) : 0;
        r.rowData[i] = mp::shareBit(N, bit, prng);
    }
    return r;
}

// --------------------------------------------------------------

bool test_window_ends_simple() {
    auto prng = makePrng(0xC0);
    const uint32_t N = 3, partyIdxBits = 2;

    // Build 3 windows of (id=10 || party), (id=20 || party), (id=30 || party)
    std::vector<mp::SharedSortElement> bag;
    for (uint64_t id : {10ULL, 10ULL, 20ULL, 20ULL, 30ULL}) {
        mp::SharedSortElement e;
        uint64_t composite = (id << partyIdxBits) | 0;
        e.key = mp::shareU64Bin(N, composite, prng);
        e.payload.push_back(mp::shareBit(N, 0, prng));  // dummy payload
        bag.push_back(std::move(e));
    }

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcWindowEndsTripleCost(bag.size()), prng);
    size_t idx = 0;
    auto ends = mp::mpcWindowEnds(bag, partyIdxBits, triples, idx);

    if (ends.size() != bag.size()) return false;
    // Boundaries: position 1 (id 10→10 not boundary), 2 (10→20 yes), 3 (20→20 no), 4 (last).
    if (ends[0].reconstruct() != 0) return false;
    if (ends[1].reconstruct() != 1) return false;
    if (ends[2].reconstruct() != 0) return false;
    if (ends[3].reconstruct() != 1) return false;
    if (ends[4].reconstruct() != 1) return false;
    return true;
}

bool test_cross_product_full_intersection() {
    // 2 parties, M=2, 1 id-window. All real → all 4 outputs have
    // is_intersection=1.
    auto prng = makePrng(0xC1);
    const uint32_t N = 2, M = 2, partyIdxBits = 1, rowDataBits = 4;

    std::vector<mp::SharedSortElement> bag;
    uint64_t id = 42;
    // Party 0, row 0 & 1
    for (uint32_t r = 0; r < M; ++r) {
        mp::SharedSortElement e;
        uint64_t composite = (id << partyIdxBits) | 0;
        e.key = mp::shareU64Bin(N, composite, prng);
        e.payload.push_back(mp::shareBit(N, 1, prng));  // is_real
        for (uint32_t b = 0; b < rowDataBits; ++b) {
            uint64_t tag = 0xA0 + (r * 16);
            e.payload.push_back(mp::shareBit(N, (tag >> b) & 1, prng));
        }
        bag.push_back(std::move(e));
    }
    // Party 1, row 0 & 1
    for (uint32_t r = 0; r < M; ++r) {
        mp::SharedSortElement e;
        uint64_t composite = (id << partyIdxBits) | 1;
        e.key = mp::shareU64Bin(N, composite, prng);
        e.payload.push_back(mp::shareBit(N, 1, prng));  // is_real
        for (uint32_t b = 0; b < rowDataBits; ++b) {
            uint64_t tag = 0xB0 + (r * 16);
            e.payload.push_back(mp::shareBit(N, (tag >> b) & 1, prng));
        }
        bag.push_back(std::move(e));
    }

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcCrossProductExpandTripleCost(1, N, M), prng);
    size_t idx = 0;
    auto out = mp::mpcCrossProductExpand(
        bag, N, M, partyIdxBits, rowDataBits, triples, idx);

    if (out.size() != M * M) return false;
    for (const auto& row : out) {
        if (row.isIntersection.reconstruct() != 1) return false;
        if (row.id.reconstruct() != id) return false;
        if (row.joinedPayload.size() != N * rowDataBits) return false;
    }
    return true;
}

bool test_cross_product_mixed_dummies() {
    // 2 parties, M=2. Party 1's row 1 is a dummy (is_real=0).
    // Combinations: (p0_0, p1_0)=real, (p0_0, p1_1)=dummy,
    //               (p0_1, p1_0)=real, (p0_1, p1_1)=dummy → 2 real outputs.
    auto prng = makePrng(0xC2);
    const uint32_t N = 2, M = 2, partyIdxBits = 1, rowDataBits = 2;

    std::vector<mp::SharedSortElement> bag;
    uint64_t id = 7;
    for (uint32_t r = 0; r < M; ++r) {
        mp::SharedSortElement e;
        e.key = mp::shareU64Bin(N, (id << partyIdxBits) | 0, prng);
        e.payload.push_back(mp::shareBit(N, 1, prng));
        for (uint32_t b = 0; b < rowDataBits; ++b)
            e.payload.push_back(mp::shareBit(N, 0, prng));
        bag.push_back(std::move(e));
    }
    for (uint32_t r = 0; r < M; ++r) {
        mp::SharedSortElement e;
        e.key = mp::shareU64Bin(N, (id << partyIdxBits) | 1, prng);
        bool real = (r == 0);  // row 0 real, row 1 dummy
        e.payload.push_back(mp::shareBit(N, real ? 1 : 0, prng));
        for (uint32_t b = 0; b < rowDataBits; ++b)
            e.payload.push_back(mp::shareBit(N, 0, prng));
        bag.push_back(std::move(e));
    }

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcCrossProductExpandTripleCost(1, N, M), prng);
    size_t idx = 0;
    auto out = mp::mpcCrossProductExpand(
        bag, N, M, partyIdxBits, rowDataBits, triples, idx);

    if (out.size() != 4) return false;
    int realCount = 0;
    for (const auto& row : out) {
        if (row.isIntersection.reconstruct() == 1) ++realCount;
    }
    return realCount == 2;
}

bool test_filter_pushes_intersection_to_front() {
    auto prng = makePrng(0xC3);
    const uint32_t N = 2, rowDataBits = 4;

    std::vector<mp::MpcJoinRow> rows;
    for (int i = 0; i < 6; ++i) {
        mp::MpcJoinRow r;
        r.id = mp::shareU64Bin(N, 100 + i, prng);
        r.joinedPayload.resize(N * rowDataBits);
        for (auto& b : r.joinedPayload) b = mp::shareBit(N, 0, prng);
        r.isIntersection = mp::shareBit(N, (i % 2 == 0) ? 1 : 0, prng);
        rows.push_back(std::move(r));
    }

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcFilterIntersectionTripleCost(rows.size(), N, rowDataBits), prng);
    size_t idx = 0;
    mp::mpcFilterIntersection(rows, N, rowDataBits, triples, idx);

    // First 3 should all be is_intersection=1; last 3 = 0.
    for (int i = 0; i < 6; ++i) {
        uint8_t v = rows[i].isIntersection.reconstruct();
        if (i < 3 && v != 1) return false;
        if (i >= 3 && v != 0) return false;
    }
    return true;
}

bool test_end_to_end_2party_M2_full_intersection() {
    // N=2 parties, M=2, partyIdxBits=1, rowDataBits=8, 1 shared id.
    // Each party has 2 real rows for the shared id.
    // Expected output: 4 intersection rows (M^N), 0 non-intersection.
    auto prng = makePrng(0xC4);
    const uint32_t N = 2, M = 2, partyIdxBits = 1, rowDataBits = 8;
    uint64_t sharedId = 42;

    std::vector<std::vector<mp::JoinInputRowShared>> perParty(N);
    for (uint32_t p = 0; p < N; ++p) {
        for (uint32_t r = 0; r < M; ++r) {
            uint64_t tag = (uint64_t(p) << 4) | r;
            perParty[p].push_back(makeInputRow(N, sharedId, true, tag, rowDataBits, prng));
        }
    }
    // universeSize = M / M = 1 (assuming perParty[i].size() = N*M / N = M)
    // Wait — pad-contract: perParty[i].size() should be M * universeSize. For
    // 1 id in universe and M=2 rows, perParty[i].size() = 2. universeSize = 2/2 = 1.

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcExecutePrivateJoinInMemoryTripleCost(N, M, partyIdxBits, rowDataBits, 1),
        prng);
    size_t idx = 0;
    auto out = mp::mpcExecutePrivateJoinInMemory(
        N, M, partyIdxBits, rowDataBits, perParty, triples, idx);

    // Output has M^N = 4 rows total. The first 4 should be the
    // intersection rows (all sorted-to-front by filter).
    if (out.size() != M * M) return false;
    int realCount = 0;
    for (const auto& row : out) {
        if (row.isIntersection.reconstruct() == 1) ++realCount;
        if (row.id.reconstruct() != sharedId) return false;
    }
    return realCount == 4;
}

bool test_end_to_end_with_dummies() {
    // N=2 parties, M=2, partyIdxBits=1, rowDataBits=4, 1 shared id.
    // Party 0: both real. Party 1: row 0 real, row 1 dummy.
    // Expected: 4 output rows, 2 with is_intersection=1.
    auto prng = makePrng(0xC5);
    const uint32_t N = 2, M = 2, partyIdxBits = 1, rowDataBits = 4;
    uint64_t sharedId = 7;

    std::vector<std::vector<mp::JoinInputRowShared>> perParty(N);
    for (uint32_t r = 0; r < M; ++r) {
        perParty[0].push_back(makeInputRow(N, sharedId, true, 0xA0 + r, rowDataBits, prng));
    }
    perParty[1].push_back(makeInputRow(N, sharedId, true,  0xB0, rowDataBits, prng));
    perParty[1].push_back(makeInputRow(N, sharedId, false, 0,    rowDataBits, prng));

    auto triples = mp::generateBeaverTripleBits(
        N, mp::mpcExecutePrivateJoinInMemoryTripleCost(N, M, partyIdxBits, rowDataBits, 1),
        prng);
    size_t idx = 0;
    auto out = mp::mpcExecutePrivateJoinInMemory(
        N, M, partyIdxBits, rowDataBits, perParty, triples, idx);

    if (out.size() != 4) return false;
    int realCount = 0;
    for (const auto& row : out) {
        if (row.isIntersection.reconstruct() == 1) ++realCount;
    }
    return realCount == 2;
}

bool test_triple_count_exact() {
    auto prng = makePrng(0xC6);
    const uint32_t N = 2, M = 2, partyIdxBits = 1, rowDataBits = 4;
    uint64_t sharedId = 1;

    std::vector<std::vector<mp::JoinInputRowShared>> perParty(N);
    for (uint32_t p = 0; p < N; ++p) {
        for (uint32_t r = 0; r < M; ++r) {
            perParty[p].push_back(makeInputRow(N, sharedId, true, p * 10 + r, rowDataBits, prng));
        }
    }
    const size_t expected = mp::mpcExecutePrivateJoinInMemoryTripleCost(
        N, M, partyIdxBits, rowDataBits, 1);
    auto triples = mp::generateBeaverTripleBits(N, expected, prng);
    size_t idx = 0;
    mp::mpcExecutePrivateJoinInMemory(
        N, M, partyIdxBits, rowDataBits, perParty, triples, idx);
    return idx == expected;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"window_ends_simple",                        test_window_ends_simple},
        {"cross_product_full_intersection",           test_cross_product_full_intersection},
        {"cross_product_mixed_dummies",               test_cross_product_mixed_dummies},
        {"filter_pushes_intersection_to_front",       test_filter_pushes_intersection_to_front},
        {"end_to_end_2party_M2_full_intersection",    test_end_to_end_2party_M2_full_intersection},
        {"end_to_end_with_dummies",                   test_end_to_end_with_dummies},
        {"triple_count_exact",                        test_triple_count_exact},
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
