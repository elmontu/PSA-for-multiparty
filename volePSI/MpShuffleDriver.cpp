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
#include <array>

// TODOs surfaced by audit:
//   1) OSN semantics: this driver assumes OSNSender::run_osn(sock, input_vec) overwrites
//      input_vec with the sender's new share = pi(input) XOR correlation, and
//      OSNReceiver::run_osn(span, sock, output_masks) fills output_masks with the
//      receiver's new share. Invariant: sender_share XOR receiver_share = pi(original).
//      Verify against actual osn/OSNSender.cpp behavior before relying.
//   2) recvBlocksOnSocket uses a single coproto::Socket::recv; replace with a
//      loop-until-full helper if coproto can short-read on TCP.

namespace volePSI {

namespace {

constexpr size_t kBlockSize = sizeof(oc::block);

std::vector<uint8_t> serializeBlocks(const std::vector<oc::block>& blocks)
{
    std::vector<uint8_t> out(blocks.size() * kBlockSize);
    std::memcpy(out.data(), blocks.data(), out.size());
    return out;
}

std::vector<oc::block> deserializeBlocks(const std::vector<uint8_t>& data, size_t count)
{
    if (data.size() != count * kBlockSize)
        throw std::runtime_error("MpShuffleDriver: invalid serialized block length");
    std::vector<oc::block> out(count);
    std::memcpy(out.data(), data.data(), data.size());
    return out;
}

std::vector<int> randomPermutation(size_t n)
{
    std::vector<int> pi(n);
    std::iota(pi.begin(), pi.end(), 0);
    std::random_device rd;
    std::mt19937_64 g(((uint64_t)rd() << 32) | rd());
    std::shuffle(pi.begin(), pi.end(), g);
    return pi;
}

macoro::task<void> sendBlocksOnSocket(coproto::Socket& sock, std::vector<oc::block> blocks)
{
    auto data = serializeBlocks(blocks);
    co_await sock.send(data);
}

macoro::task<std::vector<oc::block>> recvBlocksOnSocket(coproto::Socket& sock, size_t count)
{
    const std::size_t total = count * kBlockSize;
    std::vector<uint8_t> buf(total);
    co_await sock.recv(coproto::span<uint8_t>(buf.data(), buf.size()));
    co_return deserializeBlocks(buf, count);
}

// AEAD-wrap blocks under the SP key and send length-prefixed ciphertext.
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
    if (len > 64ULL * 1024 * 1024) {
        throw std::runtime_error("MpShuffleDriver: AEAD payload exceeds limit");
    }
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
    coproto::Socket& myOsnSocket,
    const std::array<uint8_t, 32>& spKey)
{
    if (senderCount < 2)
        throw std::runtime_error("MpShuffleDriver::runSender: senderCount must be >= 2");

    std::vector<oc::block> R = std::move(ownMasks);
    const size_t c = static_cast<size_t>(C);

    for (uint32_t k = 0; k < senderCount - 1; ++k) {
        if (k == selfIdx) {
            // Drive OSN round k.
            auto pi = randomPermutation(c);

            OSNSender osnS;
            // OSNSender::init is declared-only; init_wj is the actually-defined
            // initializer in osn/OSNSender.cpp. We pass an identity i2loc map
            // since the cascade shuffles C blocks without an intersection
            // structure, so position-i in the OSN corresponds to row-i.
            std::map<int, int> i2loc;
            for (size_t k = 0; k < c; ++k) {
                i2loc[static_cast<int>(k)] = static_cast<int>(k);
            }
            osnS.init_wj(c, 1, "", i2loc);
            osnS.setPi(std::move(pi));

            // R is in/out: after run_osn, R holds sender's new share = pi(R) XOR correlation.
            co_await osnS.run_osn(myOsnSocket, R);
            if (R.size() != c)
                throw std::runtime_error("MpShuffleDriver: OSN sender returned wrong size");

            // Re-randomizer rho.
            std::vector<oc::block> rho(c);
            oc::PRNG(oc::sysRandomSeed()).get(rho.data(), rho.size() * kBlockSize);

            // payload = R XOR rho; encrypt for sender k+1.
            std::vector<oc::block> payload(c);
            for (size_t i = 0; i < c; ++i)
                payload[i] = R[i] ^ rho[i];

            auto plain = serializeBlocks(payload);
            std::array<uint8_t, crypto_secretbox_NONCEBYTES> nonce;
            randombytes_buf(nonce.data(), nonce.size());

            const auto& key = setup.key(k + 1);
            std::vector<uint8_t> cipher(plain.size() + crypto_secretbox_MACBYTES);
            if (crypto_secretbox_easy(cipher.data(), plain.data(), plain.size(),
                                      nonce.data(), key.data()) != 0)
                throw std::runtime_error("MpShuffleDriver: secretbox encryption failed");

            std::vector<uint8_t> msg;
            msg.reserve(nonce.size() + cipher.size());
            msg.insert(msg.end(), nonce.begin(), nonce.end());
            msg.insert(msg.end(), cipher.begin(), cipher.end());
            co_await chan.sendTo(k + 1, std::move(msg));

            // Send rho to SP via the OSN socket, AEAD-wrapped under the
            // session-bound SP key. SP rejects any forged/tampered rho.
            co_await sendBlocksAead(myOsnSocket, rho, spKey);

            R.clear();
            break; // this sender has no further role until final reveal (only the LAST sender does that)
        }
        else if (k + 1 == selfIdx) {
            // Receive re-randomized mask from sender k.
            auto msg = co_await chan.recvFrom(k);
            if (msg.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
                throw std::runtime_error("MpShuffleDriver: handoff message too short");

            const uint8_t* nonce_ptr = msg.data();
            const uint8_t* cipher_ptr = nonce_ptr + crypto_secretbox_NONCEBYTES;
            size_t cipher_len = msg.size() - crypto_secretbox_NONCEBYTES;

            const auto& key = setup.key(k);
            std::vector<uint8_t> plain(cipher_len - crypto_secretbox_MACBYTES);
            if (crypto_secretbox_open_easy(plain.data(), cipher_ptr, cipher_len,
                                           nonce_ptr, key.data()) != 0)
                throw std::runtime_error("MpShuffleDriver: secretbox decryption failed");

            R = deserializeBlocks(plain, c);
        }
        // else: idle this round
    }

    // Final reveal: the last sender ships its R to SP, AEAD-wrapped.
    if (selfIdx == senderCount - 1) {
        co_await sendBlocksAead(myOsnSocket, R, spKey);
    }

    co_return R;
}

macoro::task<std::vector<oc::block>> MpShuffleDriver::runSp(
    MpStarChannel& /*spChan*/,
    std::vector<coproto::Socket>& osnSocksPerRound,
    uint32_t senderCount,
    uint64_t C,
    std::vector<oc::block> initialMasked,
    const std::vector<std::array<uint8_t, 32>>& spKeys)
{
    if (senderCount < 2)
        throw std::runtime_error("MpShuffleDriver::runSp: senderCount must be >= 2");
    if (osnSocksPerRound.size() != senderCount - 1)
        throw std::runtime_error("MpShuffleDriver::runSp: osnSocksPerRound size mismatch");
    if (spKeys.size() != senderCount)
        throw std::runtime_error("MpShuffleDriver::runSp: spKeys size mismatch");

    std::vector<oc::block> M = std::move(initialMasked);
    const size_t c = static_cast<size_t>(C);
    if (M.size() != c)
        throw std::runtime_error("MpShuffleDriver::runSp: initialMasked size mismatch");

    for (size_t k = 0; k < senderCount - 1u; ++k) {
        OSNReceiver osnR;
        osnR.init(c, 1);

        std::vector<oc::block> newM;
        co_await osnR.run_osn(oc::span<oc::block>(M.data(), M.size()),
                              osnSocksPerRound[k], newM);
        if (newM.size() != c)
            throw std::runtime_error("MpShuffleDriver: OSN receiver returned wrong size");

        // Receive rho from sender k AEAD-verified under their SP key.
        // Tampered/forged rho throws here.
        auto rho = co_await recvBlocksAead(osnSocksPerRound[k], c, spKeys[k]);

        // M_{k+1} = newM XOR rho.
        for (size_t i = 0; i < c; ++i)
            newM[i] ^= rho[i];

        M = std::move(newM);
    }

    // Final reveal: receive R from the last sender on the last socket,
    // AEAD-verified under that sender's SP key.
    auto finalR = co_await recvBlocksAead(osnSocksPerRound.back(), c,
                                          spKeys[senderCount - 1]);

    std::vector<oc::block> table(c);
    for (size_t i = 0; i < c; ++i)
        table[i] = M[i] ^ finalR[i];

    co_return table;
}

} // namespace volePSI
