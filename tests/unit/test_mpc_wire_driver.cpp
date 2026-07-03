// R36c: end-to-end wire MPC private join driver.

#include "volePSI/MpMpcWireDriver.h"
#include "volePSI/MpMpcWire.h"
#include "volePSI/MpBeaverTriple.h"
#include "volePSI/MpSecretShare.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "macoro/sync_wait.h"
#include "macoro/when_all.h"
#include "macoro/task.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
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

// Build party 0 and party 1 views of a padded input table.
// realRows[p][id] = # real rows for that (party, id) pair (rest padded dummies).
// rowDataBits: shared payload width per row.
// Returns (party0_table, party1_table).
static std::pair<std::vector<std::vector<mp::WireJoinInputRow>>,
                 std::vector<std::vector<mp::WireJoinInputRow>>>
buildTables(uint32_t N, uint32_t M, uint32_t rowDataBits,
            const std::vector<uint64_t>& universe,
            oc::PRNG& prng)
{
    std::vector<std::vector<mp::WireJoinInputRow>> t0(N), t1(N);
    for (uint32_t p = 0; p < N; ++p) {
        for (uint64_t id : universe) {
            for (uint32_t r = 0; r < M; ++r) {
                mp::WireJoinInputRow r0, r1;
                auto [i0, i1] = splitU64Bin(id, prng);
                r0.id = i0; r1.id = i1;
                // All rows real for this test.
                auto [s0, s1] = splitBit(1, prng);
                r0.isReal = s0; r1.isReal = s1;
                r0.rowData.resize(rowDataBits);
                r1.rowData.resize(rowDataBits);
                for (uint32_t b = 0; b < rowDataBits; ++b) {
                    uint8_t bit = static_cast<uint8_t>(((id + p * 100 + r) >> (b % 64)) & 1);
                    auto [a, c] = splitBit(bit, prng);
                    r0.rowData[b] = a;
                    r1.rowData[b] = c;
                }
                t0[p].push_back(r0);
                t1[p].push_back(r1);
            }
        }
    }
    return {t0, t1};
}

// --------------------------------------------------------------

bool test_wire_end_to_end_single_id() {
    // N=2 parties, M=2 rows per (party, id), 1 shared id → M^N=4 real
    // outputs. Small rowDataBits to keep runtime reasonable.
    auto prng = makePrng(0x60);
    const uint32_t N = 2, M = 2, partyIdxBits = 1, rowDataBits = 4;
    std::vector<uint64_t> universe = {42};

    auto [t0, t1] = buildTables(N, M, rowDataBits, universe, prng);

    size_t tripleCount = mp::wireMpcExecutePrivateJoinTripleCost(
        N, M, partyIdxBits, rowDataBits, universe.size());
    auto triples = mp::generateBeaverTripleBits(2, tripleCount, prng);

    auto socks = coproto::LocalAsyncSocket::makePair();
    auto p0 = [&]() -> macoro::task<std::vector<mp::WireMpcJoinRow>> {
        co_return co_await mp::wireMpcExecutePrivateJoin(
            N, M, partyIdxBits, rowDataBits, t0, triples, 0, socks[0]);
    };
    auto p1 = [&]() -> macoro::task<std::vector<mp::WireMpcJoinRow>> {
        co_return co_await mp::wireMpcExecutePrivateJoin(
            N, M, partyIdxBits, rowDataBits, t1, triples, 1, socks[1]);
    };
    auto r = macoro::sync_wait(macoro::when_all_ready(p0(), p1()));
    auto out0 = std::move(std::get<0>(r)).result();
    auto out1 = std::move(std::get<1>(r)).result();

    if (out0.size() != M * M || out1.size() != M * M) return false;

    // First M^N rows after filter should be intersection rows.
    int realCount = 0;
    for (size_t i = 0; i < M * M; ++i) {
        uint8_t joint = (out0[i].isIntersection ^ out1[i].isIntersection) & 1;
        if (joint == 1) ++realCount;
    }
    return realCount == M * M;
}

// --------------------------------------------------------------

int main() {
    const std::vector<std::pair<std::string, std::function<bool()>>> tests = {
        {"wire_end_to_end_single_id",  test_wire_end_to_end_single_id},
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
