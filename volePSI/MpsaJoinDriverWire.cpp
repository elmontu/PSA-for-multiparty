// Wire protocol for N-party table-valued private join (R33). See
// docs/PRIVATE_JOIN_DESIGN.md. Trusted-SP threat model.
//
// Protocol flow (all messages AEAD-encrypted under the SP↔sender
// pairwise session key, derived via X25519 ECDH):
//
//   SP                                        Sender i
//   ──────────                                ─────────
//   accept N sockets
//   broadcast sessionId (32 B)        →
//                                             dial SP socket
//                                             recv sessionId
//   X25519 handshake (MpSpHandshake)
//                                             parse CSV → list of
//                                                 (id, row_data) rows
//                                             AEAD-encrypt as length-
//                                                 prefixed blob
//                                  ←          send blob
//   collect N blobs, decrypt
//   group by (party, id), pad to M
//       per slot with dummies
//   bag = full padded bag
//   bitonic sort by id (R29)
//   cross-product expand (R30)
//   filter is_intersection (R31)
//   local random shuffle
//   write output CSV
//
// Output CSV format: one row per intersection-join row. Each row has
// N · W comma-separated hex blocks (one party's payload of W blocks at
// a time, parties concatenated in order 0..N-1).

#include "MpsaJoinDriverWire.h"

#include "MpStarCrypto.h"
#include "MpSpHandshake.h"
#include "MpsaJoinDriver.h"       // for JoinInputRow, JoinInputTable
#include "MpObliviousSort.h"
#include "MpJoinExpander.h"
#include "MpJoinFilter.h"
#include "MpCgpShuffle.h"         // for the Row alias
#include "fileBased.h"            // readSet

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "macoro/task.h"
#include "macoro/sync_wait.h"

#include <sodium.h>
#include <algorithm>
#include <array>
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

constexpr size_t kBlockSize = sizeof(oc::block);

// Parse a CSV into (ids, payload-rows) where multiple rows with the same
// id are allowed. CSV layout matches the cascade MPSA wide-payload
// format: col 0 = id, cols 1..W = payload blocks per row.
std::pair<std::vector<oc::block>, std::vector<volePSI::mpstar::Row>>
parseCsvForJoin(const std::string& path, uint32_t W)
{
    auto data = readSet(path, FileType::Csv, false, false);
    if (W == 0) throw std::runtime_error("parseCsvForJoin: W must be >= 1");
    if (data.size() < 1 + W) {
        throw std::runtime_error(
            "parseCsvForJoin: CSV needs at least 1+W columns; got "
            + std::to_string(data.size()));
    }
    auto ids = std::move(data[0]);
    const size_t n = ids.size();
    std::vector<volePSI::mpstar::Row> rows(n);
    for (size_t i = 0; i < n; ++i) {
        rows[i].resize(W);
        for (uint32_t w = 0; w < W; ++w) {
            if (data[1 + w].size() != n) {
                throw std::runtime_error(
                    "parseCsvForJoin: payload column " + std::to_string(1 + w)
                    + " has " + std::to_string(data[1 + w].size())
                    + " entries, expected " + std::to_string(n));
            }
            rows[i][w] = data[1 + w][i];
        }
    }
    return {std::move(ids), std::move(rows)};
}

// Serialize a sender's input tuples for wire transmission. Each tuple is
// just (id_block, W payload blocks) = 1 + W blocks. Total bytes:
//   4 (uint32 N rows) + n_rows · (1 + W) · 16 bytes
//
// The sender does NOT do padding — SP does it after collecting from all
// senders (so each sender doesn't have to know the union of ids).
std::vector<uint8_t> serializeSenderRows(const std::vector<oc::block>& ids,
                                         const std::vector<volePSI::mpstar::Row>& payloads,
                                         uint32_t W)
{
    if (ids.size() != payloads.size())
        throw std::runtime_error("serializeSenderRows: id/payload count mismatch");
    const uint32_t n = static_cast<uint32_t>(ids.size());
    std::vector<uint8_t> out;
    out.reserve(4 + static_cast<size_t>(n) * (1 + W) * kBlockSize);

    auto pushU32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    };
    auto pushBlock = [&](const oc::block& b) {
        const auto* p = reinterpret_cast<const uint8_t*>(&b);
        out.insert(out.end(), p, p + kBlockSize);
    };

    pushU32(n);
    for (uint32_t i = 0; i < n; ++i) {
        pushBlock(ids[i]);
        if (payloads[i].size() != W)
            throw std::runtime_error("serializeSenderRows: row width mismatch");
        for (uint32_t w = 0; w < W; ++w) pushBlock(payloads[i][w]);
    }
    return out;
}

// Inverse: parse a sender-serialized blob into (ids, payloads).
std::pair<std::vector<oc::block>, std::vector<volePSI::mpstar::Row>>
deserializeSenderRows(const std::vector<uint8_t>& buf, uint32_t W)
{
    if (buf.size() < 4)
        throw std::runtime_error("deserializeSenderRows: blob too short");
    uint32_t n = 0;
    for (int i = 0; i < 4; ++i) n |= uint32_t(buf[i]) << (i * 8);

    const size_t expectedBytes = 4 + static_cast<size_t>(n) * (1 + W) * kBlockSize;
    if (buf.size() != expectedBytes) {
        throw std::runtime_error(
            "deserializeSenderRows: bad blob size; got "
            + std::to_string(buf.size()) + " want " + std::to_string(expectedBytes));
    }

    std::vector<oc::block> ids(n);
    std::vector<volePSI::mpstar::Row> payloads(n);
    size_t off = 4;
    for (uint32_t i = 0; i < n; ++i) {
        std::memcpy(&ids[i], buf.data() + off, kBlockSize);
        off += kBlockSize;
        payloads[i].resize(W);
        for (uint32_t w = 0; w < W; ++w) {
            std::memcpy(&payloads[i][w], buf.data() + off, kBlockSize);
            off += kBlockSize;
        }
    }
    return {std::move(ids), std::move(payloads)};
}

// Hash a 16-byte id block down to a uint64_t for the bitonic sort. Using
// the low 64 bits of the block is fine: ids are already hash outputs
// from CSV ingest (RandomOracle hash via readSet) so the low bits are
// uniformly distributed.
uint64_t blockToUint64(const oc::block& b) {
    uint64_t out = 0;
    std::memcpy(&out, &b, sizeof(out));
    return out;
}

// SP-side: assemble the padded bag from per-sender (id_block, payload)
// lists. Each (party_idx, distinct id) gets exactly M tuples; missing
// slots become dummies (is_real=0, zero payload).
std::vector<volePSI::mpstar::SortElement>
spAssemblePaddedBag(
    uint32_t N, uint32_t M, uint32_t W,
    const std::vector<std::pair<std::vector<oc::block>, std::vector<volePSI::mpstar::Row>>>& perParty)
{
    using volePSI::mpstar::SortElement;
    using volePSI::mpstar::packTupleMeta;

    // For each party, group by id-as-uint64 → ordered list of payload Rows.
    // (Use uint64 as the canonical id since the sort works on uint64.)
    std::vector<std::map<uint64_t, std::vector<const volePSI::mpstar::Row*>>> byId(N);
    std::set<uint64_t> universe;
    for (uint32_t i = 0; i < N; ++i) {
        const auto& ids      = perParty[i].first;
        const auto& payloads = perParty[i].second;
        for (size_t k = 0; k < ids.size(); ++k) {
            uint64_t u = blockToUint64(ids[k]);
            universe.insert(u);
            auto& v = byId[i][u];
            if (v.size() >= M) {
                throw std::runtime_error(
                    "spAssemblePaddedBag: party " + std::to_string(i)
                    + " sent > M=" + std::to_string(M)
                    + " rows for id 0x" + std::to_string(u));
            }
            v.push_back(&payloads[k]);
        }
    }

    // Emit N · |universe| · M tuples.
    std::vector<SortElement> bag;
    bag.reserve(static_cast<size_t>(N) * universe.size() * M);
    for (uint64_t u : universe) {
        for (uint32_t i = 0; i < N; ++i) {
            auto it = byId[i].find(u);
            const std::vector<const volePSI::mpstar::Row*>* myRows =
                (it != byId[i].end()) ? &it->second : nullptr;
            uint32_t realCount = myRows ? static_cast<uint32_t>(myRows->size()) : 0;
            for (uint32_t r = 0; r < M; ++r) {
                SortElement e;
                e.key = u;
                e.payload.resize(1 + W);
                bool isReal = (r < realCount);
                e.payload[0] = packTupleMeta(i, r, isReal);
                if (isReal) {
                    for (uint32_t w = 0; w < W; ++w) {
                        e.payload[1 + w] = (*(*myRows)[r])[w];
                    }
                } else {
                    for (uint32_t w = 0; w < W; ++w) {
                        std::memset(&e.payload[1 + w], 0, kBlockSize);
                    }
                }
                bag.push_back(std::move(e));
            }
        }
    }
    return bag;
}

// Write joined output to CSV. Each output row: N·W comma-separated hex
// blocks. id is NOT included (it's part of the join key, not payload).
void writeJoinOutputCsv(const std::string& path,
                        const std::vector<volePSI::mpstar::JoinExpandedRow>& rows)
{
    std::ofstream out(path);
    for (const auto& row : rows) {
        for (size_t i = 0; i < row.joinedPayload.size(); ++i) {
            if (i > 0) out << ",";
            out << row.joinedPayload[i];
        }
        out << "\n";
    }
}

static coproto::Socket spAccept(int port)
{
#ifdef COPROTO_ENABLE_BOOST
    return coproto::asioConnect("localhost:" + std::to_string(port), /*isServer=*/true);
#else
    throw std::runtime_error("MpsaJoinDriverWire: COPROTO_ENABLE_BOOST required");
#endif
}

static coproto::Socket senderConnect(const std::string& host, int port)
{
#ifdef COPROTO_ENABLE_BOOST
    return coproto::asioConnect(host + ":" + std::to_string(port), /*isServer=*/false);
#else
    throw std::runtime_error("MpsaJoinDriverWire: COPROTO_ENABLE_BOOST required");
#endif
}

macoro::task<void> runSpRoleJoin(uint32_t N, int basePort,
                                 const std::string& outPath,
                                 uint32_t W, uint32_t M)
{
    std::vector<coproto::Socket> senderSocks(N);
    for (uint32_t i = 0; i < N; ++i) {
        senderSocks[i] = spAccept(basePort + i);
    }
    LOG << "[SP-join] accepted " << N << " sender sockets\n";

    std::array<uint8_t, 32> sessionId;
    randombytes_buf(sessionId.data(), sessionId.size());
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].send(coproto::span<const uint8_t>(sessionId.data(), sessionId.size()));
    }
    LOG << "[SP-join] sessionId broadcast done\n";

    auto spKeysRaw = co_await MpSpHandshake::runSp(senderSocks);
    std::vector<std::array<uint8_t, 32>> spKeys(N);
    for (uint32_t i = 0; i < N; ++i) {
        spKeys[i] = volePSI::mpstar::deriveSessionKey(
            spKeysRaw[i], sessionId, "sp_session");
    }
    LOG << "[SP-join] handshake done\n";

    // Receive each sender's encrypted row blob.
    std::vector<std::pair<std::vector<oc::block>, std::vector<volePSI::mpstar::Row>>> perParty(N);
    for (uint32_t i = 0; i < N; ++i) {
        uint64_t ctLen = 0;
        co_await senderSocks[i].recv(ctLen);
        std::vector<uint8_t> ct(ctLen);
        co_await senderSocks[i].recv(ct);
        auto plain = volePSI::mpstar::aeadDecrypt(ct, spKeys[i]);
        perParty[i] = deserializeSenderRows(plain, W);
        LOG << "[SP-join] received " << perParty[i].first.size()
            << " rows from sender " << i << "\n";
    }

    // Phase 1+2: assemble padded bag.
    auto bag = spAssemblePaddedBag(N, M, W, perParty);
    LOG << "[SP-join] padded bag size: " << bag.size() << "\n";

    // Phase 3: oblivious sort by id.
    volePSI::mpstar::obliviousBitonicSort(bag);
    LOG << "[SP-join] sort done\n";

    // Phase 4+5: window detect + cross-product expand.
    auto expanded = volePSI::mpstar::crossProductExpand(bag, N, M, W);
    LOG << "[SP-join] expander produced " << expanded.size() << " rows\n";

    // Phase 6: oblivious filter + truncate to actual intersection rows.
    size_t k = volePSI::mpstar::filterAndTruncate(expanded, W);
    LOG << "[SP-join] post-filter row count: " << k << "\n";

    // Output randomization: SP locally permutes the rows so output
    // position doesn't leak structural info from the sort.
    {
        std::mt19937_64 rng;
        std::array<uint8_t, 8> seed_bytes;
        randombytes_buf(seed_bytes.data(), seed_bytes.size());
        uint64_t seed = 0;
        for (int s = 0; s < 8; ++s) seed |= uint64_t(seed_bytes[s]) << (s * 8);
        rng.seed(seed);
        std::shuffle(expanded.begin(), expanded.end(), rng);
    }

    writeJoinOutputCsv(outPath, expanded);
    LOG << "[SP-join] wrote " << expanded.size() << " joined rows to " << outPath << "\n";

    // Flush + close sender sockets.
    for (auto& s : senderSocks) co_await s.flush();
    co_return;
}

macoro::task<void> runSenderRoleJoin(uint32_t N, uint32_t selfIdx, int basePort,
                                     const std::string& inputPath,
                                     const std::string& spHost,
                                     uint32_t W)
{
    (void)N;
    coproto::Socket spSock = senderConnect(spHost, basePort + selfIdx);
    LOG << "[S" << selfIdx << "-join] spSock connected\n";

    std::array<uint8_t, 32> sessionId;
    co_await spSock.recv(coproto::span<uint8_t>(sessionId.data(), sessionId.size()));
    LOG << "[S" << selfIdx << "-join] got sessionId\n";

    auto spKeyRaw = co_await MpSpHandshake::runSender(spSock, selfIdx);
    auto spKey = volePSI::mpstar::deriveSessionKey(spKeyRaw, sessionId, "sp_session");
    LOG << "[S" << selfIdx << "-join] handshake done\n";

    auto [ids, payloads] = parseCsvForJoin(inputPath, W);
    LOG << "[S" << selfIdx << "-join] parsed " << ids.size() << " rows (W=" << W << ")\n";

    auto plain = serializeSenderRows(ids, payloads, W);
    auto ct    = volePSI::mpstar::aeadEncrypt(plain, spKey);
    uint64_t ctLen = ct.size();
    co_await spSock.send(ctLen);
    co_await spSock.send(std::move(ct));
    LOG << "[S" << selfIdx << "-join] sent " << ctLen << " bytes\n";

    co_await spSock.flush();
    co_return;
}

void printMpsaJoinUsage(std::ostream& os)
{
    os <<
        "MPSA-Join mode (N-party table-valued private join)\n\n"
        "Usage:\n"
        "  frontend -mpsa-join -N <senderCount> -r <role> [options]\n\n"
        "Role 0 (Service Provider):\n"
        "  frontend -mpsa-join -N <N> -r 0 [-port <p>] [-out <csv>] [-pw <W>] [-M <M>]\n\n"
        "Role 1 (Sender i):\n"
        "  frontend -mpsa-join -N <N> -r 1 -i <senderIdx> -in <csv> "
        "[-port <p>] [-host <h>] [-pw <W>] [-M <M>]\n"
        "    Input CSV: col 0 = ID, cols 1..W = payload (W blocks per row).\n"
        "    Multiple rows with the same ID are allowed (table payload per id).\n\n"
        "Flags:\n"
        "    -pw <W>    payload width in blocks per row (default 1)\n"
        "    -M  <M>    max rows per id per party (default 4); over-cap → abort\n"
        "    -v         verbose debug logs\n\n"
        "Threat model: trusted SP (SP sees plaintext sender inputs).\n"
        "See docs/PRIVATE_JOIN_DESIGN.md for full architecture.\n";
}

} // namespace

void doFileMpsaJoin(CLP& cmd)
{
    if (cmd.isSet("h") || cmd.isSet("help")) {
        printMpsaJoinUsage(std::cout);
        return;
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("MpsaJoinDriverWire: sodium_init failed");
    }

    gVerbose = cmd.isSet("v") || cmd.isSet("verbose");

    uint32_t N         = cmd.getOr<uint32_t>("N", 3);
    int      role      = cmd.getOr<int>("r", 0);
    int      basePort  = cmd.getOr<int>("port", 17500);
    std::string spHost = cmd.getOr<std::string>("host", "localhost");
    uint32_t W         = cmd.getOr<uint32_t>("pw", 1);
    uint32_t M         = cmd.getOr<uint32_t>("M",  4);

    if (N < 2) {
        printMpsaJoinUsage(std::cerr);
        throw std::runtime_error("MpsaJoinDriverWire: -N must be >= 2");
    }
    if (W < 1 || W > 256) {
        printMpsaJoinUsage(std::cerr);
        throw std::runtime_error("MpsaJoinDriverWire: -pw must be in [1, 256]");
    }
    if (M < 1 || M > 64) {
        printMpsaJoinUsage(std::cerr);
        throw std::runtime_error("MpsaJoinDriverWire: -M must be in [1, 64]");
    }
    if (basePort <= 0 || basePort + static_cast<int>(N) > 65535) {
        printMpsaJoinUsage(std::cerr);
        throw std::runtime_error("MpsaJoinDriverWire: -port out of range");
    }
    if (spHost.empty()) {
        throw std::runtime_error("MpsaJoinDriverWire: -host cannot be empty");
    }

    if (role == 0) {
        std::string out = cmd.getOr<std::string>("out", "out_join.csv");
        macoro::sync_wait(runSpRoleJoin(N, basePort, out, W, M));
    } else if (role == 1) {
        uint32_t idx = cmd.getOr<uint32_t>("i", 0);
        std::string in = cmd.getOr<std::string>("in", "");
        if (in.empty() || idx >= N) {
            printMpsaJoinUsage(std::cerr);
            throw std::runtime_error("MpsaJoinDriverWire: sender requires -in <csv> and -i in [0, N)");
        }
        macoro::sync_wait(runSenderRoleJoin(N, idx, basePort, in, spHost, W));
    } else {
        printMpsaJoinUsage(std::cerr);
        throw std::runtime_error("MpsaJoinDriverWire: invalid -r (0=SP, 1=sender)");
    }
}

} // namespace volePSI
