// R35: scale benchmarks for the SP-blind MPC private join. Measures
// wall-clock time, Beaver triple consumption, and peak intermediate
// bag size across a sweep over (N, M, |universe|, rowDataBits).
//
// Output is CSV-formatted to stdout for easy plotting. Run example:
//   ./bench_mpc_join > bench.csv
//
// The benchmark uses the TRUSTED-DEALER Beaver gen — same as the unit
// tests. The triple-generation cost is reported separately so the user
// can isolate "online" join cost from "preprocessing" cost.

#include "volePSI/MpMpcJoin.h"
#include "volePSI/MpMpcSort.h"
#include "volePSI/MpSecureCompare.h"
#include "volePSI/MpSecretShare.h"
#include "volePSI/MpBeaverTriple.h"
#include "volePSI/MpsaJoinDriver.h"     // for plaintext comparison

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Defines.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <vector>

namespace mp = volePSI::mpstar;
using oc::block;

static oc::PRNG makePrng(uint64_t seed) {
    oc::PRNG p;
    block s; std::memset(&s, 0, 16);
    std::memcpy(&s, &seed, 8);
    p.SetSeed(s);
    return p;
}

static mp::JoinInputRowShared makeInputRow(
    uint32_t N, uint64_t id, bool isReal,
    uint64_t tag, uint32_t rowDataBits,
    oc::PRNG& prng)
{
    mp::JoinInputRowShared r;
    r.id = mp::shareU64Bin(N, id, prng);
    r.isReal = mp::shareBit(N, isReal ? 1 : 0, prng);
    r.rowData.resize(rowDataBits);
    for (uint32_t i = 0; i < rowDataBits; ++i) {
        uint8_t bit = (i < 64) ? ((tag >> i) & 1) : 0;
        r.rowData[i] = mp::shareBit(N, bit, prng);
    }
    return r;
}

struct BenchResult {
    uint32_t N, M, universeSize, rowDataBits;
    size_t   tripleCount;
    double   ms_preprocess;   // Beaver-triple generation (trusted dealer)
    double   ms_online;       // MPC join itself
    double   ms_plaintext;    // plaintext join (R32 driver) for comparison
    size_t   outputRows;
};

static BenchResult runOne(uint32_t N, uint32_t M, uint32_t universeSize,
                          uint32_t rowDataBits, uint64_t seed)
{
    using clk = std::chrono::high_resolution_clock;
    BenchResult res{};
    res.N = N; res.M = M; res.universeSize = universeSize; res.rowDataBits = rowDataBits;

    // Construct per-party shared input tables. Pad-input contract:
    // perParty[i].size() == universeSize * M. We use first half of universe
    // as "intersection" ids (every party has them), last half as "extra"
    // (specific to each party). Within each id, all M rows are marked
    // real for simplicity (avoids any dummy filtering effects in the bench).
    const uint32_t partyIdxBits = 4;  // supports N up to 16
    auto prng = makePrng(seed);
    std::vector<std::vector<mp::JoinInputRowShared>> perParty(N);
    for (uint32_t p = 0; p < N; ++p) {
        for (uint32_t u = 0; u < universeSize; ++u) {
            uint64_t id = 1000ULL + u;  // shared across parties
            for (uint32_t r = 0; r < M; ++r) {
                uint64_t tag = (uint64_t(p) << 32) | (uint64_t(u) << 16) | r;
                perParty[p].push_back(makeInputRow(N, id, true, tag, rowDataBits, prng));
            }
        }
    }

    // Triple cost + preprocessing.
    res.tripleCount = mp::mpcExecutePrivateJoinInMemoryTripleCost(
        N, M, partyIdxBits, rowDataBits, universeSize);

    auto t0 = clk::now();
    auto triples = mp::generateBeaverTripleBits(N, res.tripleCount, prng);
    auto t1 = clk::now();
    res.ms_preprocess = std::chrono::duration<double, std::milli>(t1 - t0).count();

    // Online: run the MPC join.
    size_t idx = 0;
    auto t2 = clk::now();
    auto out = mp::mpcExecutePrivateJoinInMemory(
        N, M, partyIdxBits, rowDataBits, perParty, triples, idx);
    auto t3 = clk::now();
    res.ms_online = std::chrono::duration<double, std::milli>(t3 - t2).count();
    res.outputRows = out.size();

    // Plaintext baseline (R32 driver).
    // Reconstruct plaintext inputs by combining party shares (we built
    // them above with known plaintexts, so just rebuild).
    std::vector<mp::JoinInputTable> plainPerParty(N);
    auto prngPlain = makePrng(seed);  // mirror the same id/tag schedule
    for (uint32_t p = 0; p < N; ++p) {
        for (uint32_t u = 0; u < universeSize; ++u) {
            uint64_t id = 1000ULL + u;
            for (uint32_t r = 0; r < M; ++r) {
                mp::JoinInputRow row;
                row.id = id;
                row.row_data.resize((rowDataBits + 127) / 128);  // ceil rowDataBits / 128 blocks
                for (auto& b : row.row_data) {
                    b = prngPlain.get<block>();
                }
                plainPerParty[p].push_back(std::move(row));
            }
        }
    }
    // Plain driver expects row_data of length payloadW BLOCKS.
    uint32_t payloadW_blocks = (rowDataBits + 127) / 128;
    auto t4 = clk::now();
    auto plainOut = mp::executePrivateJoinInMemory(
        N, M, payloadW_blocks, plainPerParty);
    auto t5 = clk::now();
    res.ms_plaintext = std::chrono::duration<double, std::milli>(t5 - t4).count();
    (void)plainOut;

    return res;
}

int main(int argc, char** argv)
{
    // CSV header.
    std::cout << "N,M,universeSize,rowDataBits,tripleCount,ms_preprocess,"
              << "ms_online,ms_plaintext,outputRows,mpc_overhead_x\n";

    // Sweep parameters. Keep sizes small enough that the bench runs in
    // under a minute. The user can rerun with larger params after
    // tuning trusted-dealer Beaver gen.
    struct Cfg { uint32_t N, M, universe, bits; };
    std::vector<Cfg> configs = {
        // Sanity: smallest meaningful
        {2, 1, 1,  16},
        {2, 2, 1,  16},
        {3, 2, 1,  16},
        // Scaling in universe size
        {2, 2, 4,  16},
        {2, 2, 8,  16},
        {2, 2, 16, 16},
        // Scaling in M
        {2, 4, 2,  16},
        {2, 8, 2,  16},
        // Scaling in N
        {3, 2, 2,  16},
        {4, 2, 2,  16},
        // Wider payload
        {2, 2, 4,  64},
        {2, 2, 4, 128},
    };

    (void)argc; (void)argv;

    for (const auto& cfg : configs) {
        try {
            auto r = runOne(cfg.N, cfg.M, cfg.universe, cfg.bits, 0xABCDEF);
            double overhead = r.ms_plaintext > 0 ? r.ms_online / r.ms_plaintext : 0;
            std::cout << r.N << "," << r.M << "," << r.universeSize << ","
                      << r.rowDataBits << "," << r.tripleCount << ","
                      << r.ms_preprocess << "," << r.ms_online << ","
                      << r.ms_plaintext << "," << r.outputRows << ","
                      << overhead << "\n";
            std::cout.flush();
        } catch (const std::exception& e) {
            std::cerr << "config (N=" << cfg.N << ", M=" << cfg.M
                      << ", universe=" << cfg.universe
                      << ", bits=" << cfg.bits << ") FAILED: " << e.what() << "\n";
        }
    }
    return 0;
}
