// MpsaDriver.cpp — end-to-end N-party Private Set Alignment driver.
//
// IMPLEMENTATION NOTES:
//   - coproto::asioConnect(addr, isServer) — same pattern as the existing
//     2-party doFileSpHshPSIwithOSN in fileBased.cpp. Both sides call
//     asioConnect; server side passes isServer=true (accepts), client side
//     passes isServer=false (connects). Requires COPROTO_ENABLE_BOOST.
//   - Peer mesh (sender↔sender): for each pair (i,j) with i<j, sender i
//     ACCEPTS on a dedicated port and sender j CONNECTS. SP plays no role
//     in sender↔sender traffic. Earlier designs tried a star-with-relay
//     where SP forwarded; that deadlocked on coproto's single-thread
//     io_context. Direct mesh removes the relay.
//   - coproto requires Socket::flush() before destruction or terminate()
//     fires — see flushes at runSpRole and runSenderRole exits.

#include "MpsaDriver.h"

#include "RsMpsi.h"
#include "MpStarChannel.h"
#include "MpStarSetup.h"
#include "MpStarCrypto.h"
#include "MpSpHandshake.h"
#include "MpShuffleDriver.h"
#include "fileBased.h"

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "macoro/task.h"
#include "macoro/sync_wait.h"

#include <sodium.h>
#include <fstream>
#include <iostream>
#include <ostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace osuCrypto;

namespace volePSI {

namespace {

// Set by doFileMpsa from the -v CLI flag. When false, all the per-step
// debug logs are suppressed.
bool gVerbose = false;
#define LOG if (gVerbose) std::cerr

std::pair<std::vector<block>, std::vector<block>> parseCsv(const std::string& path)
{
    auto data = readSet(path, FileType::Csv, false, false);
    if (data.size() < 2) {
        throw std::runtime_error("MpsaDriver: CSV must have at least 2 columns (id, payload)");
    }
    return {std::move(data[0]), std::move(data[1])};
}

// Write N parallel shuffled columns as a CSV: each row is N comma-separated
// hex-encoded 16-byte blocks (one per sender's payload at that intersection
// row, all permuted by the same secret pi).
void writeColumnsAsCsv(const std::string& path,
                       const std::vector<std::vector<block>>& columns,
                       uint64_t C)
{
    std::ofstream out(path);
    for (uint64_t i = 0; i < C; ++i) {
        for (size_t c = 0; c < columns.size(); ++c) {
            if (c > 0) out << ",";
            out << columns[c][i];
        }
        out << "\n";
    }
}

// coproto::asioConnect is the real upstream API. Both sides call it; the
// server side passes isServer=true (accept), client side passes false.
// host:port is "address:port" string form.
static coproto::Socket spAccept(int port)
{
#ifdef COPROTO_ENABLE_BOOST
    return coproto::asioConnect("localhost:" + std::to_string(port), /*isServer=*/true);
#else
    throw std::runtime_error("MpsaDriver: COPROTO_ENABLE_BOOST required for tcp sockets");
#endif
}

static coproto::Socket senderConnect(const std::string& host, int port)
{
#ifdef COPROTO_ENABLE_BOOST
    return coproto::asioConnect(host + ":" + std::to_string(port), /*isServer=*/false);
#else
    throw std::runtime_error("MpsaDriver: COPROTO_ENABLE_BOOST required for tcp sockets");
#endif
}

macoro::task<void> runSpRole(uint32_t N, int basePort, const std::string& outPath,
                             uint64_t padCmax)
{
    std::vector<coproto::Socket> senderSocks(N);
    for (uint32_t i = 0; i < N; ++i) {
        senderSocks[i] = spAccept(basePort + i);
    }

    // New port layout (Round 11 two-OSN-per-round):
    //   basePort + i           (i = 0..N-1): per-sender star/MPSI socket
    //   basePort + N + 2k      (k = 0..N-2): OSN call A socket with sender k
    //   basePort + N + 2k + 1  (k = 0..N-2): OSN call B socket with sender k
    //   basePort + N + 2*(N-1): reveal socket from last sender
    // Total ports used: 3N - 1.
    LOG << "[SP] accepting sender sockets...\n";
    // Port layout (Round 13 — peer-mesh design, SP no longer relays):
    //   basePort + i        (i = 0..N-1):   per-sender SP socket
    //   basePort + N + 2k   (k = 0..N-2):   OSN call A socket with sender k
    //   basePort + N + 2k+1 (k = 0..N-2):   OSN call B socket with sender k
    //   basePort + N + 2(N-1):              reveal socket from last sender
    // Sender-sender mesh ports are at basePort + 3N + (i*N + j) for pair (i,j)
    // with i<j; senders i ACCEPT, senders j CONNECT. SP plays no part.
    std::vector<coproto::Socket> osnSocksA(N - 1), osnSocksB(N - 1);
    for (uint32_t k = 0; k < N - 1; ++k) {
        osnSocksA[k] = spAccept(basePort + N + 2 * k);
        osnSocksB[k] = spAccept(basePort + N + 2 * k + 1);
    }
    coproto::Socket revealSock = spAccept(basePort + N + 2 * (N - 1));
    LOG << "[SP] all SP-side sockets accepted\n";

    std::array<uint8_t, 32> sessionId;
    randombytes_buf(sessionId.data(), sessionId.size());
    LOG << "[SP] broadcasting sessionId\n";
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].send(coproto::span<const uint8_t>(sessionId.data(), sessionId.size()));
    }
    LOG << "[SP] sessionId broadcast done; running MpSpHandshake\n";
    auto spKeysRaw = co_await MpSpHandshake::runSp(senderSocks);
    LOG << "[SP] MpSpHandshake done\n";
    std::vector<std::array<uint8_t, 32>> spKeys(N);
    for (uint32_t i = 0; i < N; ++i) {
        spKeys[i] = volePSI::mpstar::deriveSessionKey(spKeysRaw[i], sessionId, "sp_session");
    }

    std::vector<size_t> perSenderSetSize(N);
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].recv(perSenderSetSize[i]);
    }
    LOG << "[SP] set sizes received\n";

    RsMpsi3rdPReceiver mpsi;
    mpsi.init(perSenderSetSize[0], perSenderSetSize[0], 40, sysRandomSeed(), false, 1);
    LOG << "[SP] MPSI starting\n";
    uint64_t C = co_await mpsi.runIntersection(senderSocks, N, perSenderSetSize);
    LOG << "[SP] MPSI done; C=" << C << "\n";

    // Apply the same C_max padding the senders will. After this point
    // SP processes Ceff rows; C is the real intersection (still leaked
    // by MPSI to SP — full hiding needs oblivious MPSI, see design doc).
    uint64_t Ceff = std::max(C, padCmax);
    LOG << "[SP] effective row count Ceff=" << Ceff << " (pad from C=" << C << ")\n";
    C = Ceff;

    // Receive AEAD-wrapped masked columns m_i. SP keeps each sender's
    // column SEPARATELY (no XOR-aggregation) so it can shuffle N parallel
    // streams. initialMasked[c] is sender c's column.
    std::vector<std::vector<block>> initialMasked(N);
    for (uint32_t i = 0; i < N; ++i) {
        uint64_t ctLen = 0;
        co_await senderSocks[i].recv(ctLen);
        std::vector<uint8_t> ct(ctLen);
        co_await senderSocks[i].recv(ct);
        auto plain = volePSI::mpstar::aeadDecrypt(ct, spKeys[i]);
        initialMasked[i] = volePSI::mpstar::deserializeBlocks(plain, C);
    }
    LOG << "[SP] N masked columns received\n";

    // Senders talk to each other directly via the peer mesh; SP only
    // orchestrates the OSN cascade. No MpStarChannel needed on the SP side.
    LOG << "[SP] running MpShuffleDriver::runSp\n";
    auto shuffled = co_await MpShuffleDriver::runSp(
        osnSocksA, osnSocksB, revealSock,
        N, C, std::move(initialMasked), spKeys, sessionId);
    LOG << "[SP] runSp done\n";

    // Flush all SP sockets before destruction to keep coproto happy.
    for (auto& sock : osnSocksA) co_await sock.flush();
    for (auto& sock : osnSocksB) co_await sock.flush();
    co_await revealSock.flush();

    writeColumnsAsCsv(outPath, shuffled, C);
}

macoro::task<void> runSenderRole(uint32_t N, uint32_t selfIdx, int basePort,
                                 const std::string& inputPath, const std::string& spHost,
                                 uint64_t padCmax)
{
    LOG << "[S" << selfIdx << "] connecting spSock\n";
    coproto::Socket spSock = senderConnect(spHost, basePort + selfIdx);
    LOG << "[S" << selfIdx << "] spSock connected\n";

    // Peer-mesh sockets (Round 13): direct sender↔sender. For each pair
    // (i,j) with i<j, sender i ACCEPTS at port (basePort + 3N + i*N + j),
    // sender j CONNECTS. Avoid deadlock by iterating pairs in CANONICAL
    // order across all senders — each step has exactly one (accept,
    // connect) pair so they meet up.
    auto peerPort = [&](uint32_t i, uint32_t j) {
        return basePort + 3 * N + i * N + j;
    };
    std::vector<coproto::Socket> peerSocks(N);
    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t j = i + 1; j < N; ++j) {
            if (selfIdx == i) {
                LOG << "[S" << selfIdx << "] accepting peer " << j << "\n";
                peerSocks[j] = coproto::asioConnect(
                    "localhost:" + std::to_string(peerPort(i, j)), true);
            } else if (selfIdx == j) {
                LOG << "[S" << selfIdx << "] connecting peer " << i << "\n";
                peerSocks[i] = senderConnect(spHost, peerPort(i, j));
            }
            // else: this sender sits this pair out.
        }
    }
    LOG << "[S" << selfIdx << "] peer mesh established\n";

    // Sockets for the two-OSN-per-round cascade design.
    // - Sender k = selfIdx in [0, N-1) connects two OSN sockets to SP
    //   (call A and call B) for the round it drives.
    // - Sender N-1 connects only the reveal socket.
    coproto::Socket osnSocketA, osnSocketB, revealSocket;
    if (selfIdx < N - 1) {
        osnSocketA = senderConnect(spHost, basePort + N + 2 * selfIdx);
        osnSocketB = senderConnect(spHost, basePort + N + 2 * selfIdx + 1);
    } else {
        revealSocket = senderConnect(spHost, basePort + N + 2 * (N - 1));
    }
    LOG << "[S" << selfIdx << "] all sockets connected; recv sessionId\n";

    // Receive session_id broadcast by SP. Binds all this-session AEAD to
    // this run; defeats cross-session replay.
    std::array<uint8_t, 32> sessionId;
    co_await spSock.recv(coproto::span<uint8_t>(sessionId.data(), sessionId.size()));
    LOG << "[S" << selfIdx << "] sessionId received; running MpSpHandshake\n";

    auto spKeyRaw = co_await MpSpHandshake::runSender(spSock, selfIdx);
    LOG << "[S" << selfIdx << "] MpSpHandshake done\n";
    auto spKey = volePSI::mpstar::deriveSessionKey(spKeyRaw, sessionId, "sp_session");

    LOG << "[S" << selfIdx << "] parsing CSV " << inputPath << "\n";
    auto [ids, payloads] = parseCsv(inputPath);
    LOG << "[S" << selfIdx << "] CSV parsed: " << ids.size() << " ids, "
              << payloads.size() << " payloads\n";
    if (ids.size() != payloads.size()) {
        throw std::runtime_error("MpsaDriver: ID / payload size mismatch");
    }

    co_await spSock.send(ids.size());
    LOG << "[S" << selfIdx << "] sent set size; running MPSI\n";

    RsMpsi3rdPSender mpsi;
    mpsi.init(ids.size(), ids.size(), 40, sysRandomSeed(), false, 1);
    auto bitvec = co_await mpsi.runIntersection(span<block>(ids), spSock, selfIdx, N);
    uint64_t C = mpsi.getCardinality();
    LOG << "[S" << selfIdx << "] MPSI done; C=" << C << "\n";

    // Cardinality-hiding via output padding (Round 17). If -cmax is set
    // and > real C, the sender pads c_i with PRNG-random blocks. After the
    // cascade these padded "dummy" rows are mixed with real intersection
    // rows in the output. SP still learns C from MPSI itself (residual
    // leak — see docs/CARDINALITY_HIDING_DESIGN.md for full-hiding plan).
    uint64_t Ceff = std::max(C, padCmax);
    LOG << "[S" << selfIdx << "] padding C=" << C << " to Ceff=" << Ceff
        << " (cardinality-hiding from downstream)\n";

    LOG << "[S" << selfIdx << "] building c_i (Ceff=" << Ceff << ", ids=" << ids.size()
              << ", bitvec=" << bitvec.size() << ")\n";
    std::vector<block> c_i(Ceff, ZeroBlock);
    {
        uint64_t k = 0;
        for (uint64_t j = 0; j < ids.size() && k < C; ++j) {
            if (bitvec[j]) c_i[k++] = payloads[j];
        }
        // Fill remaining (Ceff - C) entries with PRNG-random "dummies".
        if (Ceff > C) {
            PRNG dprng;
            dprng.SetSeed(sysRandomSeed());
            dprng.get<block>(c_i.data() + C, Ceff - C);
        }
    }
    LOG << "[S" << selfIdx << "] building r_i (Ceff=" << Ceff << ")\n";
    std::vector<block> r_i(Ceff);
    LOG << "[S" << selfIdx << "] r_i allocated at " << (void*)r_i.data() << "; seeding PRNG\n";
    {
        PRNG prng;
        prng.SetSeed(sysRandomSeed());
        LOG << "[S" << selfIdx << "] PRNG seeded; calling get<block>(ptr, " << Ceff << ")\n";
        prng.get<block>(r_i.data(), Ceff);
    }
    LOG << "[S" << selfIdx << "] r_i filled\n";
    std::vector<block> m_i(Ceff);
    LOG << "[S" << selfIdx << "] m_i allocated at " << (void*)m_i.data() << "; XOR loop\n";
    for (uint64_t j = 0; j < Ceff; ++j) {
        m_i[j] = c_i[j] ^ r_i[j];
    }

    // Rest of the protocol uses Ceff instead of C.
    C = Ceff;
    LOG << "[S" << selfIdx << "] m_i built; AEAD-encrypting\n";
    // AEAD-wrap m_i under the SP key; length-prefixed send so SP's recv can
    // size its vector correctly.
    auto m_i_plain = volePSI::mpstar::serializeBlocks(m_i);
    auto m_i_ct = volePSI::mpstar::aeadEncrypt(m_i_plain, spKey);
    uint64_t ctLen = m_i_ct.size();
    co_await spSock.send(ctLen);
    co_await spSock.send(std::move(m_i_ct));
    LOG << "[S" << selfIdx << "] m_i sent (" << ctLen << " bytes)\n";

    LOG << "[S" << selfIdx << "] making star (peer-mesh) channel\n";
    MpStarChannel chan(std::move(peerSocks), selfIdx, N);
    LOG << "[S" << selfIdx << "] running MpStarSetup::runSender\n";
    auto setup = co_await MpStarSetup::runSender(chan, selfIdx, N);
    LOG << "[S" << selfIdx << "] MpStarSetup done\n";

    // Phase 0 (N-column + commit-and-open hardening):
    //
    // 1) Every sender j>0 picks a fresh 16-byte nonce_j, computes
    //    commit_j = H("mpstar.commit.v1" || serialize(r_j) || nonce_j),
    //    and BROADCASTS commit_j to ALL peers (every k != j).
    // 2) Every sender k receives commit_j from every peer j (k will also
    //    receive its own commit echoed back from sender 0 — discard).
    // 3) Sender 0 receives (serialize(r_j) || nonce_j) AEAD'd from each
    //    sender j>0 and VERIFIES commit_j opens correctly. Mismatch ⇒ abort.
    // 4) Other senders (k != 0) hold their commits for later challenge.
    //
    // Catches: sender j providing different r_j values to different recipients
    // (in the current single-recipient topology this can't happen; but
    // commitments still bind sender j to the value, enabling non-repudiation
    // if a dispute arises after the protocol). With T1's full info-theoretic
    // MAC layer (see docs/MALICIOUS_CASCADE_DESIGN.md) this generalizes to
    // catching wrong-r in the cascade too.
    using volePSI::mpstar::serializeBlocks;
    using volePSI::mpstar::deserializeBlocks;
    using volePSI::mpstar::aeadEncrypt;
    using volePSI::mpstar::aeadDecrypt;
    using volePSI::mpstar::deriveSessionKey;
    using volePSI::mpstar::commit;
    using volePSI::mpstar::verifyCommit;

    // ---- compute my own commitment + nonce ----
    std::array<uint8_t, 16> nonce_i;
    randombytes_buf(nonce_i.data(), nonce_i.size());
    auto r_i_bytes = serializeBlocks(r_i);
    auto commit_i  = commit(r_i_bytes, nonce_i);

    // ---- broadcast commit_i to every peer (32 bytes opaque) ----
    if (selfIdx > 0) {
        std::vector<uint8_t> commitBytes(commit_i.begin(), commit_i.end());
        for (uint32_t k = 0; k < N; ++k) {
            if (k == selfIdx) continue;
            co_await chan.sendTo(k, commitBytes);  // sender j>0 ships its commit
        }
    }
    LOG << "[S" << selfIdx << "] commit phase: broadcast done\n";

    // ---- receive commit_j from every peer j (only j>0 actually broadcast) ----
    std::vector<std::array<uint8_t, 32>> peerCommits(N);  // peerCommits[j] for j>0
    for (uint32_t j = 1; j < N; ++j) {
        if (j == selfIdx) continue;
        auto cb = co_await chan.recvFrom(j);
        if (cb.size() != 32) {
            throw std::runtime_error("MpsaDriver: bad commit size from peer " + std::to_string(j));
        }
        std::copy(cb.begin(), cb.end(), peerCommits[j].begin());
    }
    LOG << "[S" << selfIdx << "] commit phase: peer commits received\n";

    // ---- Phase 0 open: senders j>0 ship (r_j || nonce_j) to sender 0 ----
    std::vector<std::vector<block>> ownMasks(N);
    if (selfIdx == 0) {
        ownMasks[0] = r_i;
        for (uint32_t j = 1; j < N; ++j) {
            auto sessionKey = deriveSessionKey(setup.key(j), sessionId, "pair_session");
            auto ct    = co_await chan.recvFrom(j);
            auto plain = aeadDecrypt(ct, sessionKey);
            if (plain.size() != C * sizeof(block) + 16) {
                throw std::runtime_error("MpsaDriver: bad opened-message size from sender "
                                         + std::to_string(j));
            }
            std::vector<uint8_t> r_j_bytes(plain.begin(), plain.begin() + C * sizeof(block));
            std::array<uint8_t, 16> nonce_j;
            std::copy(plain.end() - 16, plain.end(), nonce_j.begin());

            if (!verifyCommit(r_j_bytes, nonce_j, peerCommits[j])) {
                throw std::runtime_error("MpsaDriver: commitment mismatch from sender "
                                         + std::to_string(j) + " — abort");
            }
            ownMasks[j] = deserializeBlocks(r_j_bytes, C);
        }
        LOG << "[S0] commit phase: all peer opens verified ✓\n";
    } else {
        auto sessionKey = deriveSessionKey(setup.key(0), sessionId, "pair_session");
        std::vector<uint8_t> opened;
        opened.reserve(r_i_bytes.size() + 16);
        opened.insert(opened.end(), r_i_bytes.begin(), r_i_bytes.end());
        opened.insert(opened.end(), nonce_i.begin(), nonce_i.end());
        auto ct = aeadEncrypt(opened, sessionKey);
        co_await chan.sendTo(0, std::move(ct));
        for (uint32_t c = 0; c < N; ++c) {
            ownMasks[c] = std::vector<block>(C, ZeroBlock);
        }
    }

    co_await MpShuffleDriver::runSender(
        chan, setup, selfIdx, N, C, std::move(ownMasks),
        osnSocketA, osnSocketB, revealSocket, spKey, sessionId);

    // coproto requires all sockets to be flushed before destruction or
    // terminate() fires. Flush every socket we held.
    // (spSock was moved into chan; the chan's peer sockets get flushed via
    // sendTo's own flush. Phase-0 sender 0 holds peerSocks for inbound but
    // never sends after MpStarSetup, so no pending outbound there.)
    if (selfIdx < N - 1) {
        co_await osnSocketA.flush();
        co_await osnSocketB.flush();
    } else {
        co_await revealSocket.flush();
    }
    LOG << "[S" << selfIdx << "] done\n";
}

} // anonymous namespace

static void printMpsaUsage(std::ostream& os)
{
    os <<
        "MPSA mode (N-party Private Set Alignment)\n"
        "\n"
        "Usage:\n"
        "  frontend -mpsa -N <senderCount> -r <role> [options]\n"
        "\n"
        "Role 0 (Service Provider):\n"
        "  frontend -mpsa -N <N> -r 0 [-port <basePort>] [-out <csv>]\n"
        "    -port      SP listens on basePort..basePort+2N (default 17500)\n"
        "    -out       Output CSV path (default out_cleartext.csv)\n"
        "\n"
        "Role 1 (Sender i):\n"
        "  frontend -mpsa -N <N> -r 1 -i <senderIdx> -in <csv> [-port <p>] [-host <h>]\n"
        "    -i         Sender index in [0, N)\n"
        "    -in        Input CSV (col 0 = ID, col 1 = payload)\n"
        "    -port      Base port to dial SP (default 17500)\n"
        "    -host      SP hostname (default localhost)\n"
        "\n"
        "Common flags:\n"
        "    -v         print per-step debug logs to stderr\n"
        "    -cmax <n>  cardinality-hiding: pad output to >= n rows\n"
        "               (dummies are PRNG-random and shuffled with reals;\n"
        "                hides the exact intersection size from any party\n"
        "                that observes only the output file; SP still learns\n"
        "                C via MPSI itself — see CARDINALITY_HIDING_DESIGN)\n"
        "\n"
        "Examples:\n"
        "  frontend -mpsa -N 3 -r 0\n"
        "  frontend -mpsa -N 3 -r 1 -i 0 -in dataset/sender_0.csv\n"
        "\n"
        "See README.md and docs/RESEARCH_MPSI.md for protocol details.\n";
}

void doFileMpsa(CLP& cmd)
{
    if (cmd.isSet("h") || cmd.isSet("help")) {
        printMpsaUsage(std::cout);
        return;
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("MpsaDriver: sodium_init failed");
    }

    gVerbose = cmd.isSet("v") || cmd.isSet("verbose");

    uint32_t N    = cmd.getOr<uint32_t>("N", 3);
    int role      = cmd.getOr<int>("r", 0);
    int basePort  = cmd.getOr<int>("port", 17500);
    std::string spHost = cmd.getOr<std::string>("host", "localhost");
    uint64_t padCmax = cmd.getOr<uint64_t>("cmax", 0);  // 0 = no padding

    if (N < 2) {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: -N must be >= 2");
    }
    if (basePort <= 0 || basePort + static_cast<int>(2 * N) > 65535) {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: -port out of range; must be in [1, 65535-2N]");
    }
    if (spHost.empty()) {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: -host cannot be empty");
    }

    if (role == 0) {
        std::string out = cmd.getOr<std::string>("out", "out_cleartext.csv");
        macoro::sync_wait(runSpRole(N, basePort, out, padCmax));
    } else if (role == 1) {
        uint32_t idx = cmd.getOr<uint32_t>("i", 0);
        std::string in = cmd.getOr<std::string>("in", "");
        if (in.empty() || idx >= N) {
            printMpsaUsage(std::cerr);
            throw std::runtime_error("MpsaDriver: sender requires -in <csv> and -i in [0, N)");
        }
        macoro::sync_wait(runSenderRole(N, idx, basePort, in, spHost, padCmax));
    } else {
        printMpsaUsage(std::cerr);
        throw std::runtime_error("MpsaDriver: invalid -r role (use 0 for SP, 1 for sender)");
    }
}

} // namespace volePSI
