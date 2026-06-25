#include "MpShuffleDriver.h"
#include "MpStarChannel.h"
#include "MpStarSetup.h"
#include "osn/OSNSender.h"
#include "osn/OSNReceiver.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <sodium.h>
#include <cstring>
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
    std::vector<uint8_t> buf(count * kBlockSize);
    // TODO: loop if coproto::Socket::recv can short-read
    co_await sock.recv(buf);
    co_return deserializeBlocks(buf, count);
}

} // anonymous namespace

macoro::task<std::vector<oc::block>> MpShuffleDriver::runSender(
    MpStarChannel& chan,
    const MpStarSetup& setup,
    uint32_t selfIdx,
    uint32_t senderCount,
    uint64_t C,
    std::vector<oc::block> ownMasks,
    coproto::Socket& myOsnSocket)
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
            osnS.init(c);
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

            // Send rho cleartext to SP via the OSN socket.
            co_await sendBlocksOnSocket(myOsnSocket, rho);

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

    // Final reveal: the last sender ships its R to SP.
    if (selfIdx == senderCount - 1) {
        co_await sendBlocksOnSocket(myOsnSocket, R);
    }

    co_return R;
}

macoro::task<std::vector<oc::block>> MpShuffleDriver::runSp(
    MpStarChannel& /*spChan*/,
    std::vector<coproto::Socket>& osnSocksPerRound,
    uint32_t senderCount,
    uint64_t C,
    std::vector<oc::block> initialMasked)
{
    if (senderCount < 2)
        throw std::runtime_error("MpShuffleDriver::runSp: senderCount must be >= 2");
    if (osnSocksPerRound.size() != senderCount - 1)
        throw std::runtime_error("MpShuffleDriver::runSp: osnSocksPerRound size mismatch");

    std::vector<oc::block> M = std::move(initialMasked);
    const size_t c = static_cast<size_t>(C);
    if (M.size() != c)
        throw std::runtime_error("MpShuffleDriver::runSp: initialMasked size mismatch");

    for (size_t k = 0; k < senderCount - 1u; ++k) {
        OSNReceiver osnR;
        osnR.init(c);

        std::vector<oc::block> newM;
        co_await osnR.run_osn(oc::span<oc::block>(M.data(), M.size()),
                              osnSocksPerRound[k], newM);
        if (newM.size() != c)
            throw std::runtime_error("MpShuffleDriver: OSN receiver returned wrong size");

        // Receive rho from sender k.
        auto rho = co_await recvBlocksOnSocket(osnSocksPerRound[k], c);

        // M_{k+1} = newM XOR rho.
        for (size_t i = 0; i < c; ++i)
            newM[i] ^= rho[i];

        M = std::move(newM);
    }

    // Final reveal: receive R from the last sender on the last socket.
    auto finalR = co_await recvBlocksOnSocket(osnSocksPerRound.back(), c);

    std::vector<oc::block> table(c);
    for (size_t i = 0; i < c; ++i)
        table[i] = M[i] ^ finalR[i];

    co_return table;
}

} // namespace volePSI
