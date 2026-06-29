#include "MpIdentity.h"

#include <sodium.h>
#include <fstream>
#include <stdexcept>

namespace volePSI {
namespace mpstar {

namespace {

void writeFile(const std::string& path, const uint8_t* data, size_t len) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("MpIdentity: cannot write " + path);
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
}

void readFile(const std::string& path, uint8_t* data, size_t len) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("MpIdentity: cannot open " + path);
    f.read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(len));
    if (static_cast<size_t>(f.gcount()) != len) {
        throw std::runtime_error("MpIdentity: short read for " + path);
    }
}

} // anonymous

void MpIdentity::genkey(const std::string& authDir,
                        const std::string& selfId,
                        const std::string& authSkFile)
{
    std::array<uint8_t, 32> pk;
    std::array<uint8_t, 64> sk;
    if (crypto_sign_keypair(pk.data(), sk.data()) != 0)
        throw std::runtime_error("MpIdentity::genkey: crypto_sign_keypair failed");

    writeFile(authDir + "/" + selfId + ".pk", pk.data(), pk.size());
    writeFile(authDir + "/" + authSkFile, sk.data(), sk.size());
}

MpIdentity::MpIdentity(const std::string& authDir,
                       const std::string& selfId,
                       const std::string& authSkFile)
    : mAuthDir(authDir)
{
    readFile(authDir + "/" + selfId + ".pk", mPk.data(), mPk.size());
    readFile(authDir + "/" + authSkFile, mSk.data(), mSk.size());
}

const std::array<uint8_t, 32>& MpIdentity::peerPubKey(const std::string& peerId)
{
    auto it = mPeerCache.find(peerId);
    if (it != mPeerCache.end()) return it->second;
    std::array<uint8_t, 32> pk;
    readFile(mAuthDir + "/" + peerId + ".pk", pk.data(), pk.size());
    auto [ins, _] = mPeerCache.insert({peerId, pk});
    return ins->second;
}

std::array<uint8_t, 64> MpIdentity::sign(const std::vector<uint8_t>& message) const
{
    std::array<uint8_t, 64> sig;
    unsigned long long siglen = 0;
    if (crypto_sign_detached(sig.data(), &siglen,
                             message.data(), message.size(),
                             mSk.data()) != 0) {
        throw std::runtime_error("MpIdentity::sign: crypto_sign_detached failed");
    }
    if (siglen != sig.size())
        throw std::runtime_error("MpIdentity::sign: unexpected sig length");
    return sig;
}

bool MpIdentity::verify(const std::string& peerId,
                        const std::vector<uint8_t>& message,
                        const std::array<uint8_t, 64>& signature)
{
    const auto& pk = peerPubKey(peerId);
    return crypto_sign_verify_detached(
               signature.data(),
               message.data(), message.size(),
               pk.data()) == 0;
}

} // namespace mpstar
} // namespace volePSI
