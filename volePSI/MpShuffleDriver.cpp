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
//     1) Sender k picks a FRESH RANDOM routing seed locally (never shared
//        with the SP). This is the fix for the R37/A1 finding: previously
//        the seed was deriveRoundSeed(spKey_k, sessionId, k), which the SP
//        can recompute for every k (it holds every spKey_k), letting it
//        reconstruct the whole composed permutation and de-shuffle the
//        output. With a sender-private seed the SP never learns dest_k.
//     2) For each column c:
//        OSN call (M-side):  SP=receiver provides M_k[c], sender k=OSN sender
//            (holds routing dest_k from the private seed).
//            → SP holds m_sender_share_c, sender k holds m_receiver_share_c,
//              with m_sender_share_c XOR m_receiver_share_c = dest_k(M_k[c]).
//        Sender k permutes its OWN R_k[c] locally by the same dest_k via
//        OSNSender::permuteBlocks (no OSN, no seed disclosure).
//     3) New state:
//        M_{k+1}[c] (SP)       = m_sender_share_c
//        R_{k+1}[c] (sender k) = m_receiver_share_c XOR dest_k(R_k[c])
//        ⇒ M_{k+1}[c] XOR R_{k+1}[c]
//            = m_sender_share_c XOR m_receiver_share_c XOR dest_k(R_k[c])
//            = dest_k(M_k[c]) XOR dest_k(R_k[c])
//            = dest_k applied to (M_k[c] XOR R_k[c]).
//        The second OSN call (R-side), which forced the SP to hold dest_k,
//        is eliminated — sender k applies dest_k to its own plaintext share.
//     4) Sender k AEAD-handoffs R_{k+1} (all N columns) to sender k+1 via
//        peer-mesh chan.sendTo(k+1, ...).
//
//   Final reveal: sender N-1 ships its N R columns to SP under SP key.
//   SP outputs N parallel shuffled columns: result[c] = dest applied to c_c.

namespace volePSI {

namespace {

constexpr size_t kBlockSize = sizeof(oc::block);

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
    // colCount is decoupled from senderCount: it is the number of parallel
    // single-block columns being shuffled, which equals senderCount when
    // payload width W=1 (the legacy case) but equals senderCount*W when
    // wide payload is in use (the caller flattens its N senders × W blocks
    // into N*W cascade columns).
    const uint32_t colCount = static_cast<uint32_t>(ownMasks.size());
    if (colCount == 0)
        throw std::runtime_error("MpShuffleDriver::runSender: ownMasks empty");
    if (colCount % senderCount != 0)
        throw std::runtime_error("MpShuffleDriver::runSender: colCount must be multiple of senderCount");

    auto R = std::move(ownMasks);  // colCount columns
    const size_t c_size = static_cast<size_t>(C);

    // A1 fix: the R-side OSN call (which used osnSocketB) is gone — sender k
    // permutes its own R share locally. The socket param is retained so the
    // caller's topology setup is unchanged; it simply carries no traffic now.
    (void)osnSocketB;

    for (uint32_t k = 0; k < senderCount - 1; ++k) {
        if (k == selfIdx) {
            // A1 fix: fresh per-round routing seed generated locally and NEVER
            // sent to the SP, so the SP cannot reconstruct dest_k. (Previously
            // seed = deriveRoundSeed(spKey, sessionId, k), recomputable by the
            // SP from spKey.)
            oc::block seed;
            randombytes_buf(&seed, sizeof(seed));

            std::vector<std::vector<oc::block>> R_next(colCount);

            for (uint32_t col = 0; col < colCount; ++col) {
                // ---- Single OSN call: I'm the OSN SENDER (routing holder) ----
                OSNSender osnSA;
                std::map<int, int> i2locA;
                osnSA.init_wj_seeded(c_size, 1, "", i2locA, seed);
                std::vector<oc::block> m_receiver_share;
                co_await osnSA.run_osn(osnSocketA, m_receiver_share);
                if (m_receiver_share.size() != c_size)
                    throw std::runtime_error("MpShuffleDriver: OSN returned wrong size");

                // Permute my own R[col] by the SAME dest_k, locally. This
                // replaces the former OSN call B, whose R-side required the SP
                // to hold dest_k and was the source of the permutation leak.
                std::vector<oc::block> permR = R[col];
                osnSA.permuteBlocks(permR);

                std::vector<oc::block> R_next_col(c_size);
                for (size_t j = 0; j < c_size; ++j)
                    R_next_col[j] = m_receiver_share[j] ^ permR[j];
                R_next[col] = std::move(R_next_col);
            }

            R.clear();
            R.assign(colCount, std::vector<oc::block>());  // empty per-column

            // Handoff R_next (all colCount columns) to sender k+1 via peer mesh.
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
            R = deserializeColumns(plain, colCount, C);
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
    const uint32_t colCount = static_cast<uint32_t>(initialMasked.size());
    if (colCount == 0)
        throw std::runtime_error("MpShuffleDriver::runSp: initialMasked empty");
    if (colCount % senderCount != 0)
        throw std::runtime_error("MpShuffleDriver::runSp: colCount must be multiple of senderCount");

    auto M = std::move(initialMasked);
    const size_t c_size = static_cast<size_t>(C);

    // A1 fix: the SP no longer derives any routing seed and no longer acts as
    // an OSN SENDER (the former call B). It is only ever the OSN RECEIVER, so
    // it never holds dest_k and cannot reconstruct the cascade permutation.
    (void)sessionId;
    (void)osnSocksB;

    for (uint32_t k = 0; k < senderCount - 1u; ++k) {
        std::vector<std::vector<oc::block>> M_next(colCount);

        for (uint32_t col = 0; col < colCount; ++col) {
            // ---- Single OSN call: I'm the OSN RECEIVER providing M[col] ----
            OSNReceiver osnRA;
            osnRA.init(c_size, 1);
            std::vector<oc::block> m_sender_share;
            co_await osnRA.run_osn(oc::span<oc::block>(M[col].data(), M[col].size()),
                                   osnSocksA[k], m_sender_share);
            if (m_sender_share.size() != c_size)
                throw std::runtime_error("MpShuffleDriver: OSN returned wrong size");

            // New M share is simply the OSN receiver output. The matching
            // dest_k(R_k[col]) term is folded into R_{k+1} by sender k locally.
            M_next[col] = std::move(m_sender_share);
        }
        M = std::move(M_next);
    }

    // Final reveal: receive all colCount R columns from the last sender,
    // AEAD-verified.
    auto finalR = co_await recvColumnsAead(revealSocket, colCount, C,
                                           spKeys[senderCount - 1]);

    std::vector<std::vector<oc::block>> table(colCount);
    for (uint32_t col = 0; col < colCount; ++col) {
        table[col].resize(c_size);
        for (size_t i = 0; i < c_size; ++i)
            table[col][i] = M[col][i] ^ finalR[col][i];
    }
    co_return table;
}

} // namespace volePSI
