#include "MpShuffleDriver.h"
#include "MpStarChannel.h"
#include "MpStarSetup.h"
#include "MpStarCrypto.h"
#include "osn/OSNSender.h"
#include "osn/OSNReceiver.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <sodium.h>
#include <cstring>
#include <map>
#include <random>
#include <algorithm>
#include <numeric>
#include <stdexcept>
#include <string>
#include <array>

// Round-k cascade design (two-OSN-per-round):
//
//   Sender k holds R_k, SP holds M_k. Invariant: M_k XOR R_k = the
//   table after rounds 0..k-1.
//
//   1) Both derive seed_k from sender↔SP session key + sessionId +
//      "shuffle_round_<k>". OSNSender::init_wj_seeded ensures both ends
//      bake the same Benes routing dest_k.
//
//   2) OSN call A: SP = receiver provides M_k, sender k = sender.
//      After: SP has m_sender_share, sender k has m_receiver_share.
//      m_sender_share[j] XOR m_receiver_share[j] = M_k[dest_k[j]]
//
//   3) OSN call B: sender k = receiver provides R_k, SP = sender, SAME seed_k.
//      After: sender k has r_sender_share, SP has r_receiver_share.
//      r_sender_share[j] XOR r_receiver_share[j] = R_k[dest_k[j]]
//
//   4) New state:
//      M_{k+1} (SP)         = m_sender_share XOR r_receiver_share
//      R_{k+1} (sender k)   = m_receiver_share XOR r_sender_share
//
//      M_{k+1} XOR R_{k+1} = (M_k XOR R_k)[dest_k[j]] = dest_k(table)
//
//   5) Sender k hands R_{k+1} to sender k+1 via MpStarChannel (AEAD under
//      MpStarSetup pairwise key + session id).
//
//   6) After N-1 rounds, sender N-1 sends final R to SP over revealSocket
//      (AEAD under SP key). SP reconstructs table = M_final XOR R_final.

namespace volePSI {

namespace {

constexpr size_t kBlockSize = sizeof(oc::block);

// Note: serializeBlocks/deserializeBlocks live in volePSI::mpstar
// (MpStarCrypto.h) and are reused below.

// Derive a 16-byte per-round seed from the 32-byte session-bound SP key
// and the round index. Both SP and sender k call this with the same
// inputs and get the same result.
oc::block deriveRoundSeed(const std::array<uint8_t, 32>& spKey,
                          const std::array<uint8_t, 32>& sessionId,
                          uint32_t roundIdx)
{
    std::string purpose = "shuffle_round_" + std::to_string(roundIdx);
    auto k = volePSI::mpstar::deriveSessionKey(spKey, sessionId, purpose);
    oc::block out;
    std::memcpy(&out, k.data(), kBlockSize);  // first 16 of 32 bytes
    return out;
}

// AEAD over a vector<block> sent on a raw socket, length-prefixed.
macoro::task<void> sendBlocksAead(coproto::Socket& sock,
                                  std::vector<oc::block> blocks,
                                  const std::array<uint8_t, 32>& key)
{
    auto plain = volePSI::mpstar::serializeBlocks(blocks);
    auto ct = volePSI::mpstar::aeadEncrypt(plain, key);
    uint32_t len = static_cast<uint32_t>(ct.size());
    std::array<uint8_t, 4> hdr;
    hdr[0] = static_cast<uint8_t>(len >> 24);
    hdr[1] = static_cast<uint8_t>(len >> 16);
    hdr[2] = static_cast<uint8_t>(len >> 8);
    hdr[3] = static_cast<uint8_t>(len);
    co_await sock.send(coproto::span<const uint8_t>(hdr.data(), hdr.size()));
    co_await sock.send(std::move(ct));
}

macoro::task<std::vector<oc::block>> recvBlocksAead(coproto::Socket& sock,
                                                    size_t count,
                                                    const std::array<uint8_t, 32>& key)
{
    std::array<uint8_t, 4> hdr;
    co_await sock.recv(coproto::span<uint8_t>(hdr.data(), hdr.size()));

    uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16)
                 | (uint32_t(hdr[2]) << 8)  |  uint32_t(hdr[3]);
    if (len > 64ULL * 1024 * 1024)
        throw std::runtime_error("MpShuffleDriver: AEAD payload exceeds limit");
    std::vector<uint8_t> ct(len);
    co_await sock.recv(coproto::span<uint8_t>(ct.data(), ct.size()));

    auto plain = volePSI::mpstar::aeadDecrypt(ct, key);
    co_return volePSI::mpstar::deserializeBlocks(plain, count);
}

} // anonymous namespace

macoro::task<std::vector<oc::block>> MpShuffleDriver::runSender(
    MpStarChannel& chan,
    const MpStarSetup& setup,
    uint32_t selfIdx,
    uint32_t senderCount,
    uint64_t C,
    std::vector<oc::block> ownMasks,
    coproto::Socket& osnSocketA,
    coproto::Socket& osnSocketB,
    coproto::Socket& revealSocket,
    const std::array<uint8_t, 32>& spKey,
    const std::array<uint8_t, 32>& sessionId)
{
    if (senderCount < 2)
        throw std::runtime_error("MpShuffleDriver::runSender: senderCount must be >= 2");

    std::vector<oc::block> R = std::move(ownMasks);
    const size_t c = static_cast<size_t>(C);

    for (uint32_t k = 0; k < senderCount - 1; ++k) {
        if (k == selfIdx) {
            // I'm the round-k driver.

            oc::block seed = deriveRoundSeed(spKey, sessionId, k);

            // ---- OSN call A: I'm the OSN SENDER. SP provides M_k ----
            OSNSender osnSA;
            std::map<int, int> i2locA;
            osnSA.init_wj_seeded(c, 1, "", i2locA, seed);
            std::vector<oc::block> m_receiver_share;
            co_await osnSA.run_osn(osnSocketA, m_receiver_share);
            if (m_receiver_share.size() != c)
                throw std::runtime_error("MpShuffleDriver: OSN-A returned wrong size");

            // ---- OSN call B: I'm the OSN RECEIVER providing R_k ----
            OSNReceiver osnRB;
            osnRB.init(c, 1);
            std::vector<oc::block> r_sender_share;
            co_await osnRB.run_osn(oc::span<oc::block>(R.data(), R.size()),
                                   osnSocketB, r_sender_share);
            if (r_sender_share.size() != c)
                throw std::runtime_error("MpShuffleDriver: OSN-B returned wrong size");

            // My new R for the next holder.
            std::vector<oc::block> R_next(c);
            for (size_t j = 0; j < c; ++j)
                R_next[j] = m_receiver_share[j] ^ r_sender_share[j];

            R.clear();  // I'm done with my old R.

            // Handoff R_next to sender k+1 via star, AEAD under pairwise key.
            uint32_t nextIdx = k + 1;
            namespace mp = volePSI::mpstar;
            auto pairKey = mp::deriveSessionKey(setup.key(nextIdx), sessionId, "pair_session");
            auto plain = mp::serializeBlocks(R_next);
            auto ct = mp::aeadEncrypt(plain, pairKey);
            co_await chan.sendTo(nextIdx, std::move(ct));

            // I have no further role until protocol exit.
            // (Don't break — fall through to let other rounds idle for me.)
        }
        else if (k + 1 == selfIdx) {
            // I receive R from sender k via the star channel.
            namespace mp = volePSI::mpstar;
            auto pairKey = mp::deriveSessionKey(setup.key(k), sessionId, "pair_session");
            auto ct = co_await chan.recvFrom(k);
            auto plain = mp::aeadDecrypt(ct, pairKey);
            R = mp::deserializeBlocks(plain, c);
        }
        // else: idle this round
    }

    // Final reveal: the last sender ships R to SP under SP key.
    if (selfIdx == senderCount - 1) {
        co_await sendBlocksAead(revealSocket, R, spKey);
    }

    co_return R;
}

macoro::task<std::vector<oc::block>> MpShuffleDriver::runSp(
    MpStarChannel& /*spChan*/,
    std::vector<coproto::Socket>& osnSocksA,
    std::vector<coproto::Socket>& osnSocksB,
    coproto::Socket& revealSocket,
    uint32_t senderCount,
    uint64_t C,
    std::vector<oc::block> initialMasked,
    const std::vector<std::array<uint8_t, 32>>& spKeys,
    const std::array<uint8_t, 32>& sessionId)
{
    if (senderCount < 2)
        throw std::runtime_error("MpShuffleDriver::runSp: senderCount must be >= 2");
    if (osnSocksA.size() != senderCount - 1 || osnSocksB.size() != senderCount - 1)
        throw std::runtime_error("MpShuffleDriver::runSp: osnSocks size mismatch");
    if (spKeys.size() != senderCount)
        throw std::runtime_error("MpShuffleDriver::runSp: spKeys size mismatch");

    std::vector<oc::block> M = std::move(initialMasked);
    const size_t c = static_cast<size_t>(C);
    if (M.size() != c)
        throw std::runtime_error("MpShuffleDriver::runSp: initialMasked size mismatch");

    for (uint32_t k = 0; k < senderCount - 1u; ++k) {
        oc::block seed = deriveRoundSeed(spKeys[k], sessionId, k);

        // ---- OSN call A: I'm the OSN RECEIVER providing M_k ----
        OSNReceiver osnRA;
        osnRA.init(c, 1);
        std::vector<oc::block> m_sender_share;
        co_await osnRA.run_osn(oc::span<oc::block>(M.data(), M.size()),
                               osnSocksA[k], m_sender_share);
        if (m_sender_share.size() != c)
            throw std::runtime_error("MpShuffleDriver: OSN-A returned wrong size");

        // ---- OSN call B: I'm the OSN SENDER ----
        OSNSender osnSB;
        std::map<int, int> i2locB;
        osnSB.init_wj_seeded(c, 1, "", i2locB, seed);
        std::vector<oc::block> r_receiver_share;
        co_await osnSB.run_osn(osnSocksB[k], r_receiver_share);
        if (r_receiver_share.size() != c)
            throw std::runtime_error("MpShuffleDriver: OSN-B returned wrong size");

        // New M for the next round.
        std::vector<oc::block> M_next(c);
        for (size_t j = 0; j < c; ++j)
            M_next[j] = m_sender_share[j] ^ r_receiver_share[j];
        M = std::move(M_next);
    }

    // Final reveal: receive R from the last sender, AEAD-verified.
    auto finalR = co_await recvBlocksAead(revealSocket, c, spKeys[senderCount - 1]);

    std::vector<oc::block> table(c);
    for (size_t i = 0; i < c; ++i)
        table[i] = M[i] ^ finalR[i];

    co_return table;
}

} // namespace volePSI
