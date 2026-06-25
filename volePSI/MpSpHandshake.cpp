#include "MpSpHandshake.h"

#include <sodium.h>
#include <stdexcept>

#include "cryptoTools/Crypto/RandomOracle.h"

namespace volePSI {

static void writeBigEndian(uint32_t value, uint8_t* out) {
    out[0] = static_cast<uint8_t>(value >> 24);
    out[1] = static_cast<uint8_t>(value >> 16);
    out[2] = static_cast<uint8_t>(value >> 8);
    out[3] = static_cast<uint8_t>(value);
}

static void deriveSpKey(const std::array<uint8_t, 32>& shared,
                        uint32_t senderIdx,
                        std::array<uint8_t, 32>& out)
{
    oc::RandomOracle ro(32);
    ro.Update(shared.data(), shared.size());
    ro.Update(reinterpret_cast<const uint8_t*>("sp"), 2);
    uint8_t idx_be[4];
    writeBigEndian(senderIdx, idx_be);
    ro.Update(idx_be, sizeof(idx_be));
    ro.Final(out.data());
}

macoro::task<std::vector<std::array<uint8_t, 32>>> MpSpHandshake::runSp(
    std::vector<coproto::Socket>& senderSocks)
{
    const size_t numSenders = senderSocks.size();

    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> pk_sp{};
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> sk_sp{};
    if (crypto_box_keypair(pk_sp.data(), sk_sp.data()) != 0)
        throw std::runtime_error("MpSpHandshake: crypto_box_keypair failed");

    // SP sends pk first to avoid deadlock.
    for (size_t i = 0; i < numSenders; ++i) {
        co_await senderSocks[i].send(
            coproto::span<const uint8_t>(pk_sp.data(), pk_sp.size()));
    }

    std::vector<std::array<uint8_t, crypto_box_PUBLICKEYBYTES>> pk_sender(numSenders);
    for (size_t i = 0; i < numSenders; ++i) {
        co_await senderSocks[i].recv(
            coproto::span<uint8_t>(pk_sender[i].data(), pk_sender[i].size()));
    }

    std::vector<std::array<uint8_t, 32>> keys;
    keys.reserve(numSenders);

    for (size_t i = 0; i < numSenders; ++i) {
        std::array<uint8_t, crypto_scalarmult_BYTES> shared{};
        if (crypto_scalarmult(shared.data(), sk_sp.data(), pk_sender[i].data()) != 0)
            throw std::runtime_error("MpSpHandshake: scalarmult failed (small-subgroup?)");

        std::array<uint8_t, 32> key;
        deriveSpKey(shared, static_cast<uint32_t>(i), key);
        keys.push_back(key);
    }

    co_return keys;
}

macoro::task<std::array<uint8_t, 32>> MpSpHandshake::runSender(
    coproto::Socket& spSock,
    uint32_t selfIdx)
{
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> pk_sender{};
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> sk_sender{};
    if (crypto_box_keypair(pk_sender.data(), sk_sender.data()) != 0)
        throw std::runtime_error("MpSpHandshake: crypto_box_keypair failed");

    // Sender recvs first (SP sent first, per protocol).
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> pk_sp{};
    co_await spSock.recv(coproto::span<uint8_t>(pk_sp.data(), pk_sp.size()));

    co_await spSock.send(coproto::span<const uint8_t>(pk_sender.data(), pk_sender.size()));

    std::array<uint8_t, crypto_scalarmult_BYTES> shared{};
    if (crypto_scalarmult(shared.data(), sk_sender.data(), pk_sp.data()) != 0)
        throw std::runtime_error("MpSpHandshake: scalarmult failed (small-subgroup?)");

    std::array<uint8_t, 32> key;
    deriveSpKey(shared, selfIdx, key);
    co_return key;
}

} // namespace volePSI
