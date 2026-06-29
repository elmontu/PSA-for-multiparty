#include "MpTranscript.h"

#include <sodium.h>
#include <stdexcept>

#include "cryptoTools/Crypto/RandomOracle.h"

namespace volePSI {
namespace mpstar {

MpTranscript::MpTranscript() = default;

void MpTranscript::record(const std::string& label,
                          const std::vector<uint8_t>& data)
{
    recordSpan(label, data.data(), data.size());
}

void MpTranscript::recordSpan(const std::string& label,
                              const uint8_t* data, size_t len)
{
    // Wire format per record: u32_be(label_len) | label | u32_be(data_len) | data.
    // Append-only; the final digest is computed by hashing mAcc.
    auto pushU32 = [&](uint32_t v) {
        mAcc.push_back(uint8_t(v >> 24));
        mAcc.push_back(uint8_t(v >> 16));
        mAcc.push_back(uint8_t(v >> 8));
        mAcc.push_back(uint8_t(v));
    };
    pushU32(static_cast<uint32_t>(label.size()));
    mAcc.insert(mAcc.end(), label.begin(), label.end());
    pushU32(static_cast<uint32_t>(len));
    mAcc.insert(mAcc.end(), data, data + len);
}

std::array<uint8_t, 32> MpTranscript::digest() const
{
    std::array<uint8_t, 32> out;
    oc::RandomOracle ro(32);
    static const uint8_t kTag[] = "mptranscript.v1";
    ro.Update(kTag, sizeof(kTag) - 1);
    ro.Update(mAcc.data(), static_cast<uint32_t>(mAcc.size()));
    ro.Final(out.data());
    return out;
}

std::array<uint8_t, 64> MpTranscript::sign(
    const std::array<uint8_t, 64>& ed25519_sk) const
{
    auto d = digest();
    std::array<uint8_t, 64> sig;
    unsigned long long siglen = 0;
    if (crypto_sign_detached(sig.data(), &siglen,
                             d.data(), d.size(),
                             ed25519_sk.data()) != 0) {
        throw std::runtime_error("MpTranscript: crypto_sign_detached failed");
    }
    if (siglen != sig.size()) {
        throw std::runtime_error("MpTranscript: unexpected signature length");
    }
    return sig;
}

bool MpTranscript::verify(
    const std::array<uint8_t, 32>& digest_value,
    const std::array<uint8_t, 64>& signature,
    const std::array<uint8_t, 32>& ed25519_pk)
{
    return crypto_sign_verify_detached(
               signature.data(),
               digest_value.data(), digest_value.size(),
               ed25519_pk.data()) == 0;
}

void ed25519Keypair(std::array<uint8_t, 32>& pk,
                    std::array<uint8_t, 64>& sk)
{
    if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
        throw std::runtime_error("ed25519Keypair: crypto_sign_keypair failed");
    }
}

} // namespace mpstar
} // namespace volePSI
