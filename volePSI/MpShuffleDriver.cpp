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

// Round 15 — N-column joined-table cascade:
//
//   SP holds M_k as N parallel masked vectors (M_k[c], one per sender c).
//   The mask holder (initially sender 0, then sender 1 after round 0, ...
//   sender N-1 after round N-2) holds R_k as N parallel R vectors.
//
//   Invariant: M_k[c] XOR R_k[c] = composed-shuffle-so-far applied to c_c.
//
//   Round k (driver = sender k):
//     1) Both ends derive seed_k from sender↔SP session key + sessionId
//        + "shuffle_round_<k>".
//     2) For each column c in 0..N-1:
//        OSN call A (M-side):  SP=receiver provides M_k[c], sender k=sender.
//            → SP holds m_sender_share_c,  sender k holds m_receiver_share_c
//            (XOR = M_k[c] permuted by dest_k).
//        OSN call B (R-side):  sender k=receiver provides R_k[c], SP=sender.
//            → sender k holds r_sender_share_c,  SP holds r_receiver_share_c
//            (XOR = R_k[c] permuted by dest_k).
//        Both calls reuse the SAME init_wj_seeded(C, ..., seed_k) so they
//        bake the same Benes routing dest_k.
//     3) New state:
//        M_{k+1}[c] (SP)         = m_sender_share_c   XOR r_receiver_share_c
//        R_{k+1}[c] (sender k)   = m_receiver_share_c XOR r_sender_share_c
//        ⇒ M_{k+1}[c] XOR R_{k+1}[c] = dest_k applied to (M_k[c] XOR R_k[c]).
//     4) Sender k AEAD-handoffs R_{k+1} (all N columns) to sender k+1 via
//        peer-mesh chan.sendTo(k+1, ...).
//
//   Final reveal: sender N-1 ships its N R columns to SP under SP key.
//   SP outputs N parallel shuffled columns: result[c] = dest applied to c_c.

namespace volePSI {

namespace {

constexpr size_t kBlockSize = sizeof(oc::block);

oc::block deriveRoundSeed(const std::array<uint8_t, 32>& spKey,
                          const std::array<uint8_t, 32>& sessionId,
                          uint32_t roundIdx)
{
    std::string purpose = "shuffle_round_" + std::to_string(roundIdx);
    auto k = volePSI::mpstar::deriveSessionKey(spKey, sessionId, purpose);
    oc::block out;
    std::memcpy(&out, k.data(), kBlockSize);
    return out;
}

// Serialize N parallel block vectors into one byte buffer:
// [column 0 blocks][column 1 blocks]...[column N-1 blocks].
// All columns have the same length C.
std::vector<uint8_t> serializeColumns(
    const std::vector<std::vector<oc::block>>& columns, uint64_t C)
{
    std::vector<uint8_t> out(columns.size() * C * kBlockSize);
    for (size_t c = 0; c < columns.size(); ++c) {
        if (columns[c].size() != C)
            throw std::runtime_error("serializeColumns: column size mismatch");
        std::memcpy(out.data() + c * C * kBlockSize,
                    columns[c].data(),
                    C * kBlockSize);
    }
    return out;
}

std::vector<std::vector<oc::block>> deserializeColumns(
    const std::vector<uint8_t>& data, uint32_t numCols, uint64_t C)
{
    if (data.size() != numCols * C * kBlockSize)
        throw std::runtime_error("deserializeColumns: data size mismatch");
    std::vector<std::vector<oc::block>> out(numCols);
    for (uint32_t c = 0; c < numCols; ++c) {
        out[c].resize(C);
        std::memcpy(out[c].data(),
                    data.data() + c * C * kBlockSize,
                    C * kBlockSize);
    }
    return out;
}

// Send N columns AEAD-wrapped under the SP key, length-prefixed.
macoro::task<void> sendColumnsAead(coproto::Socket& sock,
                                   const std::vector<std::vector<oc::block>>& columns,
                                   uint64_t C,
                                   const std::array<uint8_t, 32>& key)
{
    auto plain = serializeColumns(columns, C);
    auto ct = volePSI::mpstar::aeadEncrypt(plain, key);
    uint32_t len = static_cast<uint32_t>(ct.size());
    std::array<uint8_t, 4> hdr;
    hdr[0] = uint8_t(len >> 24);
    hdr[1] = uint8_t(len >> 16);
    hdr[2] = uint8_t(len >> 8);
    hdr[3] = uint8_t(len);
    co_await sock.send(coproto::span<const uint8_t>(hdr.data(), hdr.size()));
    co_await sock.send(std::move(ct));
    co_await sock.flush();
}

macoro::task<std::vector<std::vector<oc::block>>> recvColumnsAead(
    coproto::Socket& sock, uint32_t numCols, uint64_t C,
    const std::array<uint8_t, 32>& key)
{
    std::array<uint8_t, 4> hdr;
    co_await sock.recv(coproto::span<uint8_t>(hdr.data(), hdr.size()));
    uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16)
                 | (uint32_t(hdr[2]) << 8)  |  uint32_t(hdr[3]);
    if (len > 256ULL * 1024 * 1024)
        throw std::runtime_error("MpShuffleDriver: AEAD payload exceeds limit");
    std::vector<uint8_t> ct(len);
    co_await sock.recv(coproto::span<uint8_t>(ct.data(), ct.size()));
    auto plain = volePSI::mpstar::aeadDecrypt(ct, key);
    co_return deserializeColumns(plain, numCols, C);
}

} // anonymous namespace

macoro::task<std::vector<std::vector<oc::block>>> MpShuffleDriver::runSender(
    MpStarChannel& chan,
    const MpStarSetup& setup,
    uint32_t selfIdx,
    uint32_t senderCount,
    uint64_t C,
    std::vector<std::vector<oc::block>> ownMasks,
    coproto::Socket& osnSocketA,
    coproto::Socket& osnSocketB,
    coproto::Socket& revealSocket,
    const std::array<uint8_t, 32>& spKey,
    const std::array<uint8_t, 32>& sessionId)
{
    if (senderCount < 2)
        throw std::runtime_error("MpShuffleDriver::runSender: senderCount must be >= 2");
    if (ownMasks.size() != senderCount)
        throw std::runtime_error("MpShuffleDriver::runSender: ownMasks size mismatch");

    auto R = std::move(ownMasks);  // N columns
    const size_t c_size = static_cast<size_t>(C);

    for (uint32_t k = 0; k < senderCount - 1; ++k) {
        if (k == selfIdx) {
            oc::block seed = deriveRoundSeed(spKey, sessionId, k);

            std::vector<std::vector<oc::block>> R_next(senderCount);

            for (uint32_t col = 0; col < senderCount; ++col) {
                // ---- OSN call A: I'm the OSN SENDER ----
                OSNSender osnSA;
                std::map<int, int> i2locA;
                osnSA.init_wj_seeded(c_size, 1, "", i2locA, seed);
                std::vector<oc::block> m_receiver_share;
                co_await osnSA.run_osn(osnSocketA, m_receiver_share);
                if (m_receiver_share.size() != c_size)
                    throw std::runtime_error("MpShuffleDriver: OSN-A returned wrong size");

                // ---- OSN call B: I'm the OSN RECEIVER providing R[col] ----
                OSNReceiver osnRB;
                osnRB.init(c_size, 1);
                std::vector<oc::block> r_sender_share;
                co_await osnRB.run_osn(oc::span<oc::block>(R[col].data(), R[col].size()),
                                       osnSocketB, r_sender_share);
                if (r_sender_share.size() != c_size)
                    throw std::runtime_error("MpShuffleDriver: OSN-B returned wrong size");

                std::vector<oc::block> R_next_col(c_size);
                for (size_t j = 0; j < c_size; ++j)
                    R_next_col[j] = m_receiver_share[j] ^ r_sender_share[j];
                R_next[col] = std::move(R_next_col);
            }

            R.clear();
            R.assign(senderCount, std::vector<oc::block>());  // empty per-column

            // Handoff R_next (all N columns) to sender k+1 via peer mesh.
            uint32_t nextIdx = k + 1;
            namespace mp = volePSI::mpstar;
            auto pairKey = mp::deriveSessionKey(setup.key(nextIdx), sessionId, "pair_session");
            auto plain = serializeColumns(R_next, C);
            auto ct = mp::aeadEncrypt(plain, pairKey);
            co_await chan.sendTo(nextIdx, std::move(ct));
        }
        else if (k + 1 == selfIdx) {
            namespace mp = volePSI::mpstar;
            auto pairKey = mp::deriveSessionKey(setup.key(k), sessionId, "pair_session");
            auto ct = co_await chan.recvFrom(k);
            auto plain = mp::aeadDecrypt(ct, pairKey);
            R = deserializeColumns(plain, senderCount, C);
        }
        // else: idle this round
    }

    // Final reveal: the last sender ships all N R columns to SP under SP key.
    if (selfIdx == senderCount - 1) {
        co_await sendColumnsAead(revealSocket, R, C, spKey);
    }

    co_return R;
}

macoro::task<std::vector<std::vector<oc::block>>> MpShuffleDriver::runSp(
    std::vector<coproto::Socket>& osnSocksA,
    std::vector<coproto::Socket>& osnSocksB,
    coproto::Socket& revealSocket,
    uint32_t senderCount,
    uint64_t C,
    std::vector<std::vector<oc::block>> initialMasked,
    const std::vector<std::array<uint8_t, 32>>& spKeys,
    const std::array<uint8_t, 32>& sessionId)
{
    if (senderCount < 2)
        throw std::runtime_error("MpShuffleDriver::runSp: senderCount must be >= 2");
    if (osnSocksA.size() != senderCount - 1 || osnSocksB.size() != senderCount - 1)
        throw std::runtime_error("MpShuffleDriver::runSp: osnSocks size mismatch");
    if (spKeys.size() != senderCount)
        throw std::runtime_error("MpShuffleDriver::runSp: spKeys size mismatch");
    if (initialMasked.size() != senderCount)
        throw std::runtime_error("MpShuffleDriver::runSp: initialMasked size mismatch");

    auto M = std::move(initialMasked);
    const size_t c_size = static_cast<size_t>(C);

    for (uint32_t k = 0; k < senderCount - 1u; ++k) {
        oc::block seed = deriveRoundSeed(spKeys[k], sessionId, k);

        std::vector<std::vector<oc::block>> M_next(senderCount);

        for (uint32_t col = 0; col < senderCount; ++col) {
            // ---- OSN call A: I'm the OSN RECEIVER providing M[col] ----
            OSNReceiver osnRA;
            osnRA.init(c_size, 1);
            std::vector<oc::block> m_sender_share;
            co_await osnRA.run_osn(oc::span<oc::block>(M[col].data(), M[col].size()),
                                   osnSocksA[k], m_sender_share);
            if (m_sender_share.size() != c_size)
                throw std::runtime_error("MpShuffleDriver: OSN-A returned wrong size");

            // ---- OSN call B: I'm the OSN SENDER ----
            OSNSender osnSB;
            std::map<int, int> i2locB;
            osnSB.init_wj_seeded(c_size, 1, "", i2locB, seed);
            std::vector<oc::block> r_receiver_share;
            co_await osnSB.run_osn(osnSocksB[k], r_receiver_share);
            if (r_receiver_share.size() != c_size)
                throw std::runtime_error("MpShuffleDriver: OSN-B returned wrong size");

            std::vector<oc::block> M_next_col(c_size);
            for (size_t j = 0; j < c_size; ++j)
                M_next_col[j] = m_sender_share[j] ^ r_receiver_share[j];
            M_next[col] = std::move(M_next_col);
        }
        M = std::move(M_next);
    }

    // Final reveal: receive N R columns from the last sender, AEAD-verified.
    auto finalR = co_await recvColumnsAead(revealSocket, senderCount, C,
                                           spKeys[senderCount - 1]);

    std::vector<std::vector<oc::block>> table(senderCount);
    for (uint32_t col = 0; col < senderCount; ++col) {
        table[col].resize(c_size);
        for (size_t i = 0; i < c_size; ++i)
            table[col][i] = M[col][i] ^ finalR[col][i];
    }
    co_return table;
}

} // namespace volePSI
