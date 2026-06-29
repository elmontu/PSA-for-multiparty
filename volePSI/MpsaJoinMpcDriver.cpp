#include "MpsaJoinMpcDriver.h"

#include "MpMpcJoin.h"
#include "MpSecureCompare.h"
#include "MpSecretShare.h"
#include "MpBeaverTriple.h"
#include "MpsaJoinDriver.h"   // for JoinInputRow type
#include "fileBased.h"

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace osuCrypto;

namespace volePSI {

namespace {

bool gVerbose = false;
#define LOG if (gVerbose) std::cerr

constexpr uint32_t kBitsPerBlock = 128;

// Hash a 16-byte id block to a 64-bit key for the sort.
uint64_t blockToU64(const oc::block& b) {
    uint64_t v = 0;
    std::memcpy(&v, &b, 8);
    return v;
}

// Parse a multi-row-per-id CSV. Returns (ids_as_u64, payload_blocks).
std::pair<std::vector<uint64_t>, std::vector<std::vector<oc::block>>>
parseCsvForMpcJoin(const std::string& path, uint32_t W)
{
    auto data = readSet(path, FileType::Csv, false, false);
    if (W == 0)
        throw std::runtime_error("parseCsvForMpcJoin: W must be >= 1");
    if (data.size() < 1 + W) {
        throw std::runtime_error(
            "parseCsvForMpcJoin: CSV needs at least 1+W columns; got "
            + std::to_string(data.size()));
    }
    const size_t n = data[0].size();
    std::vector<uint64_t> ids(n);
    std::vector<std::vector<oc::block>> payloads(n);
    for (size_t i = 0; i < n; ++i) {
        ids[i] = blockToU64(data[0][i]);
        payloads[i].resize(W);
        for (uint32_t w = 0; w < W; ++w) {
            payloads[i][w] = data[1 + w][i];
        }
    }
    return {std::move(ids), std::move(payloads)};
}

// Convert N parties' CSV inputs into padded JoinInputRowShared tables.
// Pad each (party, id-in-universe) to M tuples; missing slots become
// dummies (is_real=0, zero rowData).
std::vector<std::vector<volePSI::mpstar::JoinInputRowShared>>
buildSharedTables(uint32_t N, uint32_t M, uint32_t rowDataBits,
                  const std::vector<std::pair<std::vector<uint64_t>,
                                              std::vector<std::vector<oc::block>>>>& perPartyRaw,
                  oc::PRNG& prng)
{
    namespace mp = volePSI::mpstar;

    // Universe of ids.
    std::set<uint64_t> universe;
    for (const auto& pr : perPartyRaw) {
        for (uint64_t u : pr.first) universe.insert(u);
    }

    // Group each party's rows by id.
    std::vector<std::map<uint64_t, std::vector<const std::vector<oc::block>*>>> byId(N);
    for (uint32_t i = 0; i < N; ++i) {
        const auto& ids = perPartyRaw[i].first;
        const auto& pys = perPartyRaw[i].second;
        for (size_t k = 0; k < ids.size(); ++k) {
            auto& v = byId[i][ids[k]];
            if (v.size() >= M)
                throw std::runtime_error(
                    "buildSharedTables: party " + std::to_string(i)
                    + " over M=" + std::to_string(M));
            v.push_back(&pys[k]);
        }
    }

    std::vector<std::vector<mp::JoinInputRowShared>> out(N);
    for (uint32_t i = 0; i < N; ++i) {
        out[i].reserve(universe.size() * M);
        for (uint64_t u : universe) {
            auto it = byId[i].find(u);
            const std::vector<const std::vector<oc::block>*>* rows =
                (it != byId[i].end()) ? &it->second : nullptr;
            uint32_t realCount = rows ? static_cast<uint32_t>(rows->size()) : 0;
            for (uint32_t r = 0; r < M; ++r) {
                mp::JoinInputRowShared shared;
                shared.id = mp::shareU64Bin(N, u, prng);
                bool isReal = (r < realCount);
                shared.isReal = mp::shareBit(N, isReal ? 1 : 0, prng);
                shared.rowData.resize(rowDataBits);
                if (isReal) {
                    // Encode payload blocks bit-by-bit into rowData.
                    const auto& payload = *(*rows)[r];
                    for (uint32_t bit = 0; bit < rowDataBits; ++bit) {
                        uint32_t blkIdx = bit / kBitsPerBlock;
                        uint32_t blkBit = bit % kBitsPerBlock;
                        uint8_t b = 0;
                        if (blkIdx < payload.size()) {
                            const auto* p = reinterpret_cast<const uint8_t*>(&payload[blkIdx]);
                            b = (p[blkBit / 8] >> (blkBit % 8)) & 1;
                        }
                        shared.rowData[bit] = mp::shareBit(N, b, prng);
                    }
                } else {
                    // Dummy: zero rowData.
                    for (auto& b : shared.rowData) b = mp::shareBit(N, 0, prng);
                }
                out[i].push_back(std::move(shared));
            }
        }
    }
    return out;
}

// Write MPC-join output to CSV. Reconstructs the bit-shared id and payload,
// formats as one hex block for id followed by ceil(rowDataBits / 128) blocks
// per party. The simulation reconstructs locally — in the wire protocol
// this would be a multi-party reveal phase.
void writeMpcJoinCsv(const std::string& path,
                     const std::vector<volePSI::mpstar::MpcJoinRow>& rows,
                     uint32_t N, uint32_t rowDataBits)
{
    namespace mp = volePSI::mpstar;
    std::ofstream out(path);
    const uint32_t blocksPerParty = (rowDataBits + kBitsPerBlock - 1) / kBitsPerBlock;
    for (const auto& row : rows) {
        // Only write intersection rows (is_intersection = 1).
        if (row.isIntersection.reconstruct() == 0) continue;

        for (uint32_t p = 0; p < N; ++p) {
            for (uint32_t blk = 0; blk < blocksPerParty; ++blk) {
                if (p > 0 || blk > 0) out << ",";
                // Reconstruct the block from per-bit shares.
                oc::block b;
                std::memset(&b, 0, 16);
                auto* bp = reinterpret_cast<uint8_t*>(&b);
                for (uint32_t bit = 0; bit < kBitsPerBlock; ++bit) {
                    uint32_t globalBit = blk * kBitsPerBlock + bit;
                    if (globalBit >= rowDataBits) break;
                    size_t srcIdx = static_cast<size_t>(p) * rowDataBits + globalBit;
                    if (srcIdx >= row.joinedPayload.size()) break;
                    uint8_t v = row.joinedPayload[srcIdx].reconstruct() & 1;
                    bp[bit / 8] |= (v << (bit % 8));
                }
                out << b;
            }
        }
        out << "\n";
    }
}

void printUsage(std::ostream& os)
{
    os <<
        "MPSA-Join MPC mode (in-process SP-blind private join simulation)\n\n"
        "Usage:\n"
        "  frontend -mpsa-join-mpc -N <N> -M <M> -pw <W> -out <csv> \\\n"
        "           -in0 <csv0> -in1 <csv1> ... -in<N-1> <csv_{N-1}>\n\n"
        "All N parties + SP run in the same process. Inputs are bit-\n"
        "shared, MPC primitives (sort, expand, filter) are exercised end-\n"
        "to-end, output is reconstructed only for CSV writeout. This is\n"
        "a DEMONSTRATION + BENCHMARK harness, NOT a deployable wire\n"
        "protocol (that's R34k, deferred).\n\n"
        "Flags:\n"
        "    -N <N>     number of parties (each must supply -in<idx>)\n"
        "    -M <M>     max rows per (party, id); over-cap → abort\n"
        "    -pw <W>    payload width in 16-byte blocks per row (default 1)\n"
        "    -out       output CSV path (default out_mpc_join.csv)\n"
        "    -v         verbose debug logs\n";
}

} // namespace

void doFileMpsaJoinMpc(CLP& cmd)
{
    namespace mp = volePSI::mpstar;
    if (cmd.isSet("h") || cmd.isSet("help")) {
        printUsage(std::cout);
        return;
    }

    if (sodium_init() < 0)
        throw std::runtime_error("MpsaJoinMpcDriver: sodium_init failed");

    gVerbose = cmd.isSet("v") || cmd.isSet("verbose");
    uint32_t N = cmd.getOr<uint32_t>("N", 2);
    uint32_t M = cmd.getOr<uint32_t>("M", 4);
    uint32_t W = cmd.getOr<uint32_t>("pw", 1);
    std::string outPath = cmd.getOr<std::string>("out", "out_mpc_join.csv");

    if (N < 2 || N > 8) {
        printUsage(std::cerr);
        throw std::runtime_error("MpsaJoinMpcDriver: -N must be in [2, 8]");
    }
    if (M < 1 || M > 16) {
        printUsage(std::cerr);
        throw std::runtime_error("MpsaJoinMpcDriver: -M must be in [1, 16]");
    }
    if (W < 1 || W > 16) {
        printUsage(std::cerr);
        throw std::runtime_error("MpsaJoinMpcDriver: -pw must be in [1, 16]");
    }

    // Load each party's CSV.
    std::vector<std::pair<std::vector<uint64_t>,
                          std::vector<std::vector<oc::block>>>> perPartyRaw(N);
    for (uint32_t i = 0; i < N; ++i) {
        std::string flag = "in" + std::to_string(i);
        std::string path = cmd.getOr<std::string>(flag, "");
        if (path.empty()) {
            printUsage(std::cerr);
            throw std::runtime_error("MpsaJoinMpcDriver: missing -" + flag);
        }
        perPartyRaw[i] = parseCsvForMpcJoin(path, W);
        LOG << "[MPC-join] loaded party " << i << ": "
            << perPartyRaw[i].first.size() << " rows\n";
    }

    // Build shared input tables.
    oc::PRNG prng;
    oc::block seed;
    std::memset(&seed, 0xC0, 16);
    prng.SetSeed(seed);

    const uint32_t partyIdxBits = 4;
    const uint32_t rowDataBits  = W * kBitsPerBlock;

    auto perPartyShared = buildSharedTables(N, M, rowDataBits, perPartyRaw, prng);

    // Universe size from the constructed shared tables.
    if (perPartyShared[0].size() % M != 0)
        throw std::runtime_error("MpsaJoinMpcDriver: pad count not divisible by M");
    const size_t universeSize = perPartyShared[0].size() / M;
    LOG << "[MPC-join] universe size: " << universeSize
        << ", M=" << M << ", rowDataBits=" << rowDataBits << "\n";

    // Generate Beaver triples.
    size_t tripleCount = mp::mpcExecutePrivateJoinInMemoryTripleCost(
        N, M, partyIdxBits, rowDataBits, universeSize);
    LOG << "[MPC-join] need " << tripleCount << " Beaver triple bits\n";
    auto triples = mp::generateBeaverTripleBits(N, tripleCount, prng);
    LOG << "[MPC-join] Beaver triples generated\n";

    // Run MPC join.
    size_t idx = 0;
    auto out = mp::mpcExecutePrivateJoinInMemory(
        N, M, partyIdxBits, rowDataBits, perPartyShared, triples, idx);
    LOG << "[MPC-join] MPC executed; consumed " << idx << " triples\n";
    LOG << "[MPC-join] " << out.size() << " expanded rows (pre-truncation)\n";

    writeMpcJoinCsv(outPath, out, N, rowDataBits);

    // Count intersection rows for reporting.
    size_t k = 0;
    for (const auto& row : out) if (row.isIntersection.reconstruct() == 1) ++k;
    LOG << "[MPC-join] wrote " << k << " intersection rows to " << outPath << "\n";
}

} // namespace volePSI
