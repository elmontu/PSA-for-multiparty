#include "MpStarCrypto.h"

#include "cryptoTools/Crypto/RandomOracle.h"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

namespace volePSI {
namespace mpstar {

std::vector<uint8_t> serializeBlocks(const std::vector<oc::block>& blocks)
{
    std::vector<uint8_t> out(blocks.size() * sizeof(oc::block));
    for (size_t i = 0; i < blocks.size(); ++i)
        std::memcpy(out.data() + i * sizeof(oc::block), &blocks[i], sizeof(oc::block));
    return out;
}

std::vector<oc::block> deserializeBlocks(const std::vector<uint8_t>& data, size_t count)
{
    if (data.size() < count * sizeof(oc::block))
        throw std::runtime_error("deserializeBlocks: data too short");

    std::vector<oc::block> out(count);
    for (size_t i = 0; i < count; ++i)
        std::memcpy(&out[i], data.data() + i * sizeof(oc::block), sizeof(oc::block));
    return out;
}

std::vector<uint8_t> aeadEncrypt(const std::vector<uint8_t>& plain,
                                 const std::array<uint8_t, 32>& key)
{
    std::vector<uint8_t> out(crypto_secretbox_NONCEBYTES + plain.size() + crypto_secretbox_MACBYTES);
    randombytes_buf(out.data(), crypto_secretbox_NONCEBYTES);

    int r = crypto_secretbox_easy(out.data() + crypto_secretbox_NONCEBYTES,
                                  plain.data(), plain.size(),
                                  out.data(), key.data());
    if (r != 0)
        throw std::runtime_error("aeadEncrypt: encryption failed");
    return out;
}

std::vector<uint8_t> aeadDecrypt(const std::vector<uint8_t>& ct,
                                 const std::array<uint8_t, 32>& key)
{
    if (ct.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
        throw std::runtime_error("aeadDecrypt: ciphertext too short");

    size_t plainLen = ct.size() - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
    std::vector<uint8_t> plain(plainLen);

    int r = crypto_secretbox_open_easy(plain.data(),
                                       ct.data() + crypto_secretbox_NONCEBYTES,
                                       ct.size() - crypto_secretbox_NONCEBYTES,
                                       ct.data(),
                                       key.data());
    if (r != 0)
        throw std::runtime_error("aeadDecrypt: decryption failed");
    return plain;
}

std::array<uint8_t, 32> deriveSessionKey(
    const std::array<uint8_t, 32>& baseKey,
    const std::array<uint8_t, 32>& sessionId,
    const std::string& purpose)
{
    std::array<uint8_t, 32> out;
    oc::RandomOracle ro(32);
    ro.Update(baseKey.data(), baseKey.size());
    ro.Update(sessionId.data(), sessionId.size());
    ro.Update(reinterpret_cast<const uint8_t*>(purpose.data()),
              static_cast<uint32_t>(purpose.size()));
    ro.Final(out.data());
    return out;
}

std::array<uint8_t, 32> commit(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 16>& nonce)
{
    std::array<uint8_t, 32> out;
    oc::RandomOracle ro(32);
    // Domain separation: prevent commitment collision with deriveSessionKey
    // or any other RO use that happens to feed the same bytes.
    static const uint8_t kCommitTag[] = "mpstar.commit.v1";
    ro.Update(kCommitTag, sizeof(kCommitTag) - 1);
    ro.Update(message.data(), static_cast<uint32_t>(message.size()));
    ro.Update(nonce.data(), nonce.size());
    ro.Final(out.data());
    return out;
}

bool verifyCommit(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, 16>& nonce,
    const std::array<uint8_t, 32>& expected)
{
    auto got = commit(message, nonce);
    // Constant-time compare via sodium.
    return sodium_memcmp(got.data(), expected.data(), got.size()) == 0;
}

} // namespace mpstar
} // namespace volePSI
