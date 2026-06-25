// SCAFFOLDING — multiple TODOs require human fill-in. See DEFERRED_AUDITS.md.
//
// What works (or should work) end-to-end:
//   - CLI parsing + role dispatch
//   - MPSI intersection (RsMpsi3rdPSender/Receiver)
//   - sodium_init
//   - MpStarSetup pairwise DH (via MpStarChannel)
//
// What's stubbed / TODO:
//   - coproto AsioAcceptor / AsioSocket call sites (actual API names need
//     verification against the coproto release pulled by the build)
//   - CSV parser (must reuse the helpers already in fileBased.cpp, which
//     are not currently exported in fileBased.h)
//   - Phase 0 mask aggregation (sender 0 collects all r_i via star unicast)
//   - OSN socket for the last sender (final-reveal channel)

#include "MpsaDriver.h"

#include "RsMpsi.h"
#include "MpStarChannel.h"
#include "MpStarSetup.h"
#include "MpShuffleDriver.h"

#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "macoro/task.h"
#include "macoro/sync_wait.h"

#include <sodium.h>
#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace osuCrypto;

namespace volePSI {

namespace {

// TODO: replace with existing CSV reader from fileBased.cpp. Currently a stub.
std::pair<std::vector<block>, std::vector<block>> parseCsv(const std::string& /*path*/)
{
    return {};
}

// TODO: confirm block has stream operator that emits hex.
void writeBlocksAsHex(const std::string& path, const std::vector<block>& data)
{
    std::ofstream out(path);
    for (const auto& b : data) {
        out << b << "\n";
    }
}

// TODO: coproto's actual TCP accept / connect API. The names below are
// placeholders. The real calls in this codebase look like
//   `coproto::AsioAcceptor acc(io, port); auto sock = co_await acc.accept();`
// or similar. Verify against coproto release used at build time.
coproto::Socket asioAccept(int /*port*/)  { return coproto::Socket{}; }
coproto::Socket asioConnect(const std::string& /*host*/, int /*port*/) { return coproto::Socket{}; }

macoro::task<void> runSpRole(uint32_t N, int basePort, const std::string& outPath)
{
    std::vector<coproto::Socket> senderSocks(N);
    for (uint32_t i = 0; i < N; ++i) {
        senderSocks[i] = asioAccept(basePort + i);
    }

    std::vector<coproto::Socket> osnSocks(N - 1);
    for (uint32_t i = 0; i < N - 1; ++i) {
        osnSocks[i] = asioAccept(basePort + N + i);
    }

    // Receive per-sender set sizes.
    std::vector<size_t> perSenderSetSize(N);
    for (uint32_t i = 0; i < N; ++i) {
        co_await senderSocks[i].recv(perSenderSetSize[i]);
    }

    // MPSI.
    RsMpsi3rdPReceiver mpsi;
    mpsi.init(perSenderSetSize[0], perSenderSetSize[0], 40, sysRandomSeed(), false, 1);
    uint64_t C = co_await mpsi.runIntersection(senderSocks, N, perSenderSetSize);

    // Receive each sender's masked column m_i; XOR into M_0.
    std::vector<block> initialMasked(C, ZeroBlock);
    for (uint32_t i = 0; i < N; ++i) {
        std::vector<block> m_i(C);
        co_await senderSocks[i].recv(span<block>(m_i));
        for (uint64_t j = 0; j < C; ++j) {
            initialMasked[j] = initialMasked[j] ^ m_i[j];
        }
    }

    // SP-side MpStarChannel (relayer between senders).
    MpStarChannel spChan = MpStarChannel::makeSp(std::move(senderSocks));
    // TODO: relayLoop must run concurrently with runSp. For prototype, omit and
    // assume sender-side aggregation does not require relay (Phase 0 path
    // currently bypassed by senderwise direct sends).

    auto shuffled = co_await MpShuffleDriver::runSp(spChan, osnSocks, N, C, std::move(initialMasked));

    writeBlocksAsHex(outPath, shuffled);
}

macoro::task<void> runSenderRole(uint32_t N, uint32_t selfIdx, int basePort, const std::string& inputPath)
{
    coproto::Socket spSock = asioConnect("127.0.0.1", basePort + selfIdx);

    coproto::Socket osnSock;
    if (selfIdx < N - 1) {
        osnSock = asioConnect("127.0.0.1", basePort + N + selfIdx);
    }
    // TODO: last sender (selfIdx == N-1) also needs a socket for the final reveal.
    // For now reuses asioConnect to a designated reveal port (basePort + 2N).
    if (selfIdx == N - 1) {
        osnSock = asioConnect("127.0.0.1", basePort + 2 * N);
    }

    auto [ids, payloads] = parseCsv(inputPath);
    if (ids.size() != payloads.size()) {
        throw std::runtime_error("MpsaDriver: ID / payload size mismatch");
    }

    co_await spSock.send(ids.size());

    RsMpsi3rdPSender mpsi;
    mpsi.init(ids.size(), ids.size(), 40, sysRandomSeed(), false, 1);
    auto bitvec = co_await mpsi.runIntersection(span<block>(ids), spSock, selfIdx, N);
    uint64_t C = mpsi.getCardinality();

    // Build c_i then m_i = c_i XOR r_i.
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
    co_await spSock.send(span<block>(m_i));

    // Star setup for pairwise keys.
    MpStarChannel chan(std::move(spSock), selfIdx, N);
    auto setup = co_await MpStarSetup::runSender(chan, selfIdx, N);

    // Phase 0: sender 0 aggregates all r_i. Sketched, not wired (uses chan.sendTo/recvFrom).
    std::vector<block> ownMasks;
    if (selfIdx == 0) {
        ownMasks = r_i;
        for (uint32_t j = 1; j < N; ++j) {
            // TODO: receive r_j via chan.recvFrom(j) (decrypt under setup.key(j))
            // For now, leave ownMasks = r_i only.
        }
    } else {
        // TODO: send r_i to sender 0 via chan.sendTo(0, encrypted_r_i)
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
