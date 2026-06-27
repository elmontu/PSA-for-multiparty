#include "MpHybridHandshake.h"
#include "MpKem.h"

#include <sodium.h>
#include <stdexcept>

#include "cryptoTools/Crypto/RandomOracle.h"

namespace volePSI {

namespace {

static void writeBigEndian(uint32_t value, uint8_t* out) {
    out[0] = uint8_t(value >> 24);
    out[1] = uint8_t(value >> 16);
    out[2] = uint8_t(value >> 8);
    out[3] = uint8_t(value);
}

// Combine the two shared secrets into a 32-byte session key. The static
// tag and senderIdx provide domain separation so each (SP, sender_i) pair
// gets a distinct key even with identical secret material.
static std::array<uint8_t, 32> combineSecrets(
    const std::array<uint8_t, 32>& x25519_ss,
    const std::vector<uint8_t>& kem_ss,
    uint32_t senderIdx)
{
    std::array<uint8_t, 32> out;
    oc::RandomOracle ro(32);
    static const uint8_t kTag[] = "mphybrid.v1";
    ro.Update(kTag, sizeof(kTag) - 1);
    ro.Update(x25519_ss.data(), x25519_ss.size());
    ro.Update(kem_ss.data(), static_cast<uint32_t>(kem_ss.size()));
    uint8_t idx_be[4];
    writeBigEndian(senderIdx, idx_be);
    ro.Update(idx_be, sizeof(idx_be));
    ro.Final(out.data());
    return out;
}

} // anonymous namespace

macoro::task<std::vector<std::array<uint8_t, 32>>> MpHybridHandshake::runSp(
    std::vector<coproto::Socket>& senderSocks,
    const mpstar::Kem& kem)
{
    const size_t N = senderSocks.size();

    // SP X25519 keypair (one for all senders).
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> x25519_pk_sp;
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> x25519_sk_sp;
    if (crypto_box_keypair(x25519_pk_sp.data(), x25519_sk_sp.data()) != 0)
        throw std::runtime_error("MpHybridHandshake::runSp: x25519 keypair failed");

    // SP KEM keypair (one for all senders — for prototype; per-sender for
    // forward secrecy is a separate design knob).
    std::vector<uint8_t> kem_pk_sp, kem_sk_sp;
    kem.keypair(kem_pk_sp, kem_sk_sp);

    // Send X25519 pk + KEM pk to every sender (SP sends first to avoid deadlock).
    for (size_t i = 0; i < N; ++i) {
        co_await senderSocks[i].send(
            coproto::span<const uint8_t>(x25519_pk_sp.data(), x25519_pk_sp.size()));
        co_await senderSocks[i].send(
            coproto::span<const uint8_t>(kem_pk_sp.data(), kem_pk_sp.size()));
    }

    // Receive X25519 pk + KEM ciphertext from each sender.
    std::vector<std::array<uint8_t, 32>> keys(N);
    for (size_t i = 0; i < N; ++i) {
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES> x25519_pk_sender;
        co_await senderSocks[i].recv(
            coproto::span<uint8_t>(x25519_pk_sender.data(), x25519_pk_sender.size()));

        std::vector<uint8_t> kem_ct(kem.ciphertextBytes());
        co_await senderSocks[i].recv(coproto::span<uint8_t>(kem_ct.data(), kem_ct.size()));

        // Compute X25519 shared secret.
        std::array<uint8_t, crypto_scalarmult_BYTES> x25519_ss{};
        if (crypto_scalarmult(x25519_ss.data(), x25519_sk_sp.data(), x25519_pk_sender.data()) != 0)
            throw std::runtime_error("MpHybridHandshake::runSp: scalarmult failed");

        // Decapsulate KEM shared secret.
        std::vector<uint8_t> kem_ss;
        kem.decap(kem_ct, kem_sk_sp, kem_ss);

        keys[i] = combineSecrets(x25519_ss, kem_ss, static_cast<uint32_t>(i));
    }

    co_return keys;
}

macoro::task<std::array<uint8_t, 32>> MpHybridHandshake::runSender(
    coproto::Socket& spSock,
    uint32_t selfIdx,
    const mpstar::Kem& kem)
{
    // Sender X25519 keypair.
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> x25519_pk_sender;
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> x25519_sk_sender;
    if (crypto_box_keypair(x25519_pk_sender.data(), x25519_sk_sender.data()) != 0)
        throw std::runtime_error("MpHybridHandshake::runSender: x25519 keypair failed");

    // Recv SP's X25519 pk + KEM pk.
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> x25519_pk_sp;
    co_await spSock.recv(coproto::span<uint8_t>(x25519_pk_sp.data(), x25519_pk_sp.size()));

    std::vector<uint8_t> kem_pk_sp(kem.publicKeyBytes());
    co_await spSock.recv(coproto::span<uint8_t>(kem_pk_sp.data(), kem_pk_sp.size()));

    // Send our X25519 pk.
    co_await spSock.send(
        coproto::span<const uint8_t>(x25519_pk_sender.data(), x25519_pk_sender.size()));

    // Encapsulate to SP's KEM pk.
    std::vector<uint8_t> kem_ct, kem_ss;
    kem.encap(kem_pk_sp, kem_ct, kem_ss);
    co_await spSock.send(coproto::span<const uint8_t>(kem_ct.data(), kem_ct.size()));

    // Compute X25519 shared secret.
    std::array<uint8_t, crypto_scalarmult_BYTES> x25519_ss{};
    if (crypto_scalarmult(x25519_ss.data(), x25519_sk_sender.data(), x25519_pk_sp.data()) != 0)
        throw std::runtime_error("MpHybridHandshake::runSender: scalarmult failed");

    co_return combineSecrets(x25519_ss, kem_ss, selfIdx);
}

} // namespace volePSI
