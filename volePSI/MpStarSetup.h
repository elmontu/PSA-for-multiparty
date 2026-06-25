#pragma once

#include <array>
#include <cstdint>
#include <map>
#include "macoro/task.h"

namespace volePSI {

class MpStarChannel; // forward declaration

class MpStarSetup {
public:
    // Run pairwise X25519 key exchange among all senders via MpStarChannel.
    // Returns a populated MpStarSetup containing k_{selfIdx,peer} for every peer.
    static macoro::task<MpStarSetup> runSender(MpStarChannel& chan, uint32_t selfIdx, uint32_t senderCount);

    // Lookup k_{selfIdx,peer}. Throws on self or out-of-range.
    const std::array<uint8_t, 32>& key(uint32_t peer) const;

private:
    uint32_t mSelfIdx = 0;
    uint32_t mSenderCount = 0;
    std::map<uint32_t, std::array<uint8_t, 32>> mPairKeys;
};

} // namespace volePSI
