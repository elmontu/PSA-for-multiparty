#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace volePSI {
namespace mpstar {

// Long-term Ed25519 identity for a protocol party. Lets the handshake
// AUTHENTICATE the peer (not just establish a shared secret), defeating
// MITM attackers who relay pubkeys but cannot forge signatures.
//
// On-disk layout (under <auth-dir>):
//   sp.pk            32 bytes — SP's long-term Ed25519 public key
//   sender_<i>.pk    32 bytes — sender i's long-term Ed25519 public key
//   <role>.sk        64 bytes — the calling party's own secret key
//
// `genkey` produces a fresh keypair and writes .pk/.sk. The .pk files MUST
// be distributed out of band (registry, cert pinning, manual exchange).
// In production this is the PKI bootstrap; the prototype assumes all
// parties share a filesystem directory.
class MpIdentity {
public:
    // Generate a fresh Ed25519 keypair and write to:
    //   <authDir>/<selfId>.pk   (32B)
    //   <authDir>/<authSk>      (64B)
    // selfId examples: "sp", "sender_0", "sender_1".
    static void genkey(const std::string& authDir,
                       const std::string& selfId,
                       const std::string& authSkFile);

    // Load this party's own pk + sk. Throws if files missing.
    MpIdentity(const std::string& authDir,
               const std::string& selfId,
               const std::string& authSkFile);

    // Load a peer's public key from <authDir>/<peerId>.pk. Cached on first
    // load. Throws if file missing.
    const std::array<uint8_t, 32>& peerPubKey(const std::string& peerId);

    // Sign a message under this party's long-term sk. Returns 64-byte
    // Ed25519 detached signature.
    std::array<uint8_t, 64> sign(const std::vector<uint8_t>& message) const;

    // Verify a peer's signature.
    bool verify(const std::string& peerId,
                const std::vector<uint8_t>& message,
                const std::array<uint8_t, 64>& signature);

    const std::array<uint8_t, 32>& selfPubKey() const { return mPk; }

private:
    std::string mAuthDir;
    std::array<uint8_t, 32> mPk;
    std::array<uint8_t, 64> mSk;
    std::map<std::string, std::array<uint8_t, 32>> mPeerCache;
};

} // namespace mpstar
} // namespace volePSI
