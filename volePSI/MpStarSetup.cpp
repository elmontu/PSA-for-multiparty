#include "MpStarSetup.h"
#include "MpStarChannel.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "macoro/task.h"
#include <sodium.h>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

// NOTE: callers must invoke sodium_init() exactly once before any MpStarSetup
// instance runs. Suggested call site: main() in frontend, before any volePSI
// API call.

namespace volePSI {

macoro::task<MpStarSetup> MpStarSetup::runSender(MpStarChannel& chan, uint32_t selfIdx, uint32_t senderCount)
{
    // 1. Generate X25519 key pair (libsodium, pk-first ordering).
    std::array<uint8_t, 32> pk, sk;
    crypto_box_keypair(pk.data(), sk.data());

    for (uint32_t j = 0; j < senderCount; ++j)
    {
        if (j == selfIdx) continue;
        co_await chan.sendTo(j, std::vector<uint8_t>(pk.begin(), pk.end()));
    }

    // 3. Receive public keys and derive pairwise keys.
    MpStarSetup setup;
    setup.mSelfIdx     = selfIdx;
    setup.mSenderCount = senderCount;

    for (uint32_t j = 0; j < senderCount; ++j)
    {
        if (j == selfIdx) continue;

        auto remoteBytes = co_await chan.recvFrom(j);
        if (remoteBytes.size() != 32)
        {
            throw std::runtime_error(
                "MpStarSetup: invalid public key size from peer " + std::to_string(j));
        }

        // 4. X25519 shared secret. crypto_scalarmult returns 0 on success;
        //    non-zero indicates a small-subgroup or otherwise invalid peer key.
        std::array<uint8_t, 32> sharedSecret;
        int ret = crypto_scalarmult(sharedSecret.data(), sk.data(), remoteBytes.data());
        if (ret != 0)
        {
            throw std::runtime_error(
                "MpStarSetup: crypto_scalarmult failed (small-subgroup key?) from peer " + std::to_string(j));
        }

        // 5. KDF: oc::RandomOracle over shared || min(i,j) || max(i,j) (BE u32 pair).
        oc::RandomOracle oracle(32);
        oracle.Update(sharedSecret.data(), static_cast<uint32_t>(sharedSecret.size()));

        uint32_t a = std::min(selfIdx, j);
        uint32_t b = std::max(selfIdx, j);
        std::array<uint8_t, 8> info;
        info[0] = static_cast<uint8_t>(a >> 24);
        info[1] = static_cast<uint8_t>(a >> 16);
        info[2] = static_cast<uint8_t>(a >> 8);
        info[3] = static_cast<uint8_t>(a);
        info[4] = static_cast<uint8_t>(b >> 24);
        info[5] = static_cast<uint8_t>(b >> 16);
        info[6] = static_cast<uint8_t>(b >> 8);
        info[7] = static_cast<uint8_t>(b);
        oracle.Update(info.data(), static_cast<uint32_t>(info.size()));

        oracle.Final(setup.mPairKeys[j].data());
    }

    co_return setup;
}

const std::array<uint8_t, 32>& MpStarSetup::key(uint32_t peer) const
{
    if (peer == mSelfIdx)
        throw std::runtime_error("MpStarSetup::key: peer cannot be self");
    if (peer >= mSenderCount)
        throw std::runtime_error("MpStarSetup::key: peer index out of range");
    return mPairKeys.at(peer);
}

} // namespace volePSI
