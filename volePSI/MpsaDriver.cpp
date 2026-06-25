// MpsaDriver.cpp — end-to-end N-party Private Set Alignment driver.
//
// IMPLEMENTATION NOTES:
//   - Uses coproto::asioConnect(addr, isServer) — same pattern as the
//     existing 2-party doFileSpHshPSIwithOSN in fileBased.cpp. Both sides
//     call asioConnect; the server side passes isServer=true (accepts),
//     the client side passes isServer=false (connects).
//   - Requires COPROTO_ENABLE_BOOST at compile time (CMake flag).
//   - relayLoop concurrency: relayLoop is run in a std::thread because
//     macoro doesn't expose a when_any primitive that lets us return when
//     the first task completes while leaving the other live. The shuffle
//     coroutine drives the foreground; when it returns, we detach the
//     relay thread and let process exit reclaim it (the underlying TCP
//     sockets are closed by destructors).

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
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace osuCrypto;

namespace volePSI {

namespace {

std::pair<std::vector<block>, std::vector<block>> parseCsv(const std::string& path)
{
    auto data = readSet(path, FileType::Csv, false, false);
    if (data.size() < 2) {
        throw std::runtime_error("MpsaDriver: CSV must have at least 2 columns (id, payload)");
    }
    return {std::move(data[0]), std::move(data[1])};
}

void writeBlocksAsHex(const std::string& path, const std::vector<block>& data)
{
    std::ofstream out(path);
    for (const auto& b : data) {
        out << b << "\n";
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

macoro::task<void> runSpRole(uint32_t N, int basePort, const std::string& outPath)
{
    std::vector<coproto::Socket> senderSocks(N);
    for (uint32_t i = 0; i < N; ++i) {
        senderSocks[i] = spAccept(basePort + i);
    }

    std::vector<coproto::Socket> osnSocks(N - 1);
    for (uint32_t i = 0; i < N - 1; ++i) {
        osnSocks[i] = spAccept(basePort + N + i);
    }

    // Accept the last sender's reveal channel (Phase 4 fix).
    coproto::Socket revealSock = spAccept(basePort + 2 * N);

    // SP picks a per-session random ID and broadcasts it. This binds every
    // AEAD ciphertext in this MPSA invocation to this session, defeating
    // cross-session replay attacks even when long-term DH keys are reused.
    std::array<uint8_t, 32> sessionId;
    randombytes_buf(sessionId.data(), sessionId.size());
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].send(coproto::span<const uint8_t>(sessionId.data(), sessionId.size()));
    }

    // SP↔sender DH first: derives an authentication key per sender. Used
    // below to AEAD-decrypt the masked-column m_i so a tampering sender or
    // network attacker is detected before XOR'ing into M_0.
    auto spKeysRaw = co_await MpSpHandshake::runSp(senderSocks);
    std::vector<std::array<uint8_t, 32>> spKeys(N);
    for (uint32_t i = 0; i < N; ++i) {
        spKeys[i] = volePSI::mpstar::deriveSessionKey(spKeysRaw[i], sessionId, "sp_session");
    }

    std::vector<size_t> perSenderSetSize(N);
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].recv(perSenderSetSize[i]);
    }

    RsMpsi3rdPReceiver mpsi;
    mpsi.init(perSenderSetSize[0], perSenderSetSize[0], 40, sysRandomSeed(), false, 1);
    uint64_t C = co_await mpsi.runIntersection(senderSocks, N, perSenderSetSize);

    // Receive AEAD-wrapped masked columns m_i. Decrypt with each sender's
    // SP key; XOR into M_0. aeadDecrypt throws on MAC mismatch.
    std::vector<block> initialMasked(C, ZeroBlock);
    for (uint32_t i = 0; i < N; ++i) {
        std::vector<uint8_t> ct;
        co_await senderSocks[i].recv(ct);
        auto plain = volePSI::mpstar::aeadDecrypt(ct, spKeys[i]);
        auto m_i = volePSI::mpstar::deserializeBlocks(plain, C);
        for (uint64_t j = 0; j < C; ++j) {
            initialMasked[j] = initialMasked[j] ^ m_i[j];
        }
    }

    MpStarChannel spChan = MpStarChannel::makeSp(std::move(senderSocks));

    // Drive relayLoop in a worker thread; macoro doesn't expose a when_any
    // that lets us return when shuffle completes while leaving relay live.
    // The relay sockets get closed by spChan's destructor when this scope
    // unwinds, which terminates the worker via recv-throwing-EOF.
    std::thread relayThread([&spChan]() {
        try { macoro::sync_wait(spChan.relayLoop()); } catch (...) {}
    });

    // Push the reveal socket onto the OSN-rounds vector since MpShuffleDriver
    // uses osnSocksPerRound.back() for the final reveal.
    osnSocks.push_back(std::move(revealSock));
    auto shuffled = co_await MpShuffleDriver::runSp(spChan, osnSocks, N, C, std::move(initialMasked));

    relayThread.detach();
    writeBlocksAsHex(outPath, shuffled);
}

macoro::task<void> runSenderRole(uint32_t N, uint32_t selfIdx, int basePort, const std::string& inputPath)
{
    coproto::Socket spSock = senderConnect("localhost", basePort + selfIdx);

    coproto::Socket osnSock;
    if (selfIdx < N - 1) {
        osnSock = senderConnect("localhost", basePort + N + selfIdx);
    }
    if (selfIdx == N - 1) {
        // SP-side accept on basePort+2*N added in Phase 4 fix.
        osnSock = senderConnect("localhost", basePort + 2 * N);
    }

    // Receive session_id broadcast by SP. Binds all this-session AEAD to
    // this run; defeats cross-session replay.
    std::array<uint8_t, 32> sessionId;
    co_await spSock.recv(coproto::span<uint8_t>(sessionId.data(), sessionId.size()));

    // SP↔sender DH: must happen before sending anything authenticated.
    auto spKeyRaw = co_await MpSpHandshake::runSender(spSock, selfIdx);
    auto spKey = volePSI::mpstar::deriveSessionKey(spKeyRaw, sessionId, "sp_session");

    auto [ids, payloads] = parseCsv(inputPath);
    if (ids.size() != payloads.size()) {
        throw std::runtime_error("MpsaDriver: ID / payload size mismatch");
    }

    co_await spSock.send(ids.size());

    RsMpsi3rdPSender mpsi;
    mpsi.init(ids.size(), ids.size(), 40, sysRandomSeed(), false, 1);
    auto bitvec = co_await mpsi.runIntersection(span<block>(ids), spSock, selfIdx, N);
    uint64_t C = mpsi.getCardinality();

    std::vector<block> c_i(C, ZeroBlock);
    {
        uint64_t k = 0;
        for (uint64_t j = 0; j < ids.size() && k < C; ++j) {
            if (bitvec[j]) c_i[k++] = payloads[j];
        }
    }
    std::vector<block> r_i(C);
    PRNG(sysRandomSeed()).get(r_i.data(), C * sizeof(block));
    std::vector<block> m_i(C);
    for (uint64_t j = 0; j < C; ++j) {
        m_i[j] = c_i[j] ^ r_i[j];
    }
    // AEAD-wrap m_i under the SP key so SP can detect tampering / forgery.
    auto m_i_plain = volePSI::mpstar::serializeBlocks(m_i);
    auto m_i_ct = volePSI::mpstar::aeadEncrypt(m_i_plain, spKey);
    co_await spSock.send(std::move(m_i_ct));

    MpStarChannel chan(std::move(spSock), selfIdx, N);
    auto setup = co_await MpStarSetup::runSender(chan, selfIdx, N);

    // Phase 0: sender 0 collects every other sender's r_i (encrypted under
    // session-bound pairwise key); other senders ship r_i to sender 0.
    using volePSI::mpstar::serializeBlocks;
    using volePSI::mpstar::deserializeBlocks;
    using volePSI::mpstar::aeadEncrypt;
    using volePSI::mpstar::aeadDecrypt;
    using volePSI::mpstar::deriveSessionKey;

    std::vector<block> ownMasks;
    if (selfIdx == 0) {
        ownMasks = r_i;
        for (uint32_t j = 1; j < N; ++j) {
            auto sessionKey = deriveSessionKey(setup.key(j), sessionId, "pair_session");
            auto ct    = co_await chan.recvFrom(j);
            auto plain = aeadDecrypt(ct, sessionKey);
            auto r_j   = deserializeBlocks(plain, C);
            for (uint64_t b = 0; b < C; ++b)
                ownMasks[b] = ownMasks[b] ^ r_j[b];
        }
    } else {
        auto sessionKey = deriveSessionKey(setup.key(0), sessionId, "pair_session");
        auto plain = serializeBlocks(r_i);
        auto ct    = aeadEncrypt(plain, sessionKey);
        co_await chan.sendTo(0, std::move(ct));
        ownMasks = std::vector<block>(C, ZeroBlock);
    }

    co_await MpShuffleDriver::runSender(chan, setup, selfIdx, N, C, std::move(ownMasks), osnSock);
}

} // anonymous namespace

void doFileMpsa(CLP& cmd)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("MpsaDriver: sodium_init failed");
    }

    uint32_t N    = cmd.getOr<uint32_t>("N", 3);
    int role      = cmd.getOr<int>("r", 0);
    int basePort  = cmd.getOr<int>("port", 17500);

    if (role == 0) {
        std::string out = cmd.getOr<std::string>("out", "out_cleartext.csv");
        macoro::sync_wait(runSpRole(N, basePort, out));
    } else if (role == 1) {
        uint32_t idx = cmd.getOr<uint32_t>("i", 0);
        std::string in = cmd.getOr<std::string>("in", "");
        if (in.empty()) throw std::runtime_error("MpsaDriver: -in required for sender");
        macoro::sync_wait(runSenderRole(N, idx, basePort, in));
    } else {
        throw std::runtime_error("MpsaDriver: invalid -r role (0=SP, 1=sender)");
    }
}

} // namespace volePSI
