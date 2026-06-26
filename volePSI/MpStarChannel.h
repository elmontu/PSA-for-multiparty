#pragma once

#include <cstdint>
#include <vector>
#include <stdexcept>

#include "coproto/coproto.h"
#include "macoro/task.h"

namespace volePSI {

// Direct point-to-point sender↔sender mesh for use by MpStarSetup and the
// Phase 0 mask handoff. SP plays NO role in this channel.
//
// Earlier versions tried a star-relayed design (every sender talks only to
// SP, SP forwards frames between senders). That deadlocked on the coproto
// io_context single-thread assumption when the relay was driven from a
// separate std::thread. The mesh removes the relay entirely.
//
// Wire format on each peer socket: uint32_t lenBytes (big-endian), then
// lenBytes of payload. No fromIdx/toIdx needed — the socket identity is
// the source identity.
class MpStarChannel {
public:
    // Sender-side constructor.
    // peerSocks: vector of N coproto::Sockets. peerSocks[selfIdx] is unused
    // (kept default-constructed) — every other peerSocks[j] is the socket
    // to sender j.
    MpStarChannel(std::vector<coproto::Socket> peerSocks,
                  uint32_t selfIdx,
                  uint32_t senderCount);

    // Send opaque bytes to peer toIdx. Length-prefixed on the wire.
    macoro::task<> sendTo(uint32_t toIdx, std::vector<uint8_t> data);

    // Receive opaque bytes from peer fromIdx. Returns whatever the peer
    // sent (variable length).
    macoro::task<std::vector<uint8_t>> recvFrom(uint32_t fromIdx);

private:
    uint32_t mSelfIdx = 0;
    uint32_t mSenderCount = 0;
    std::vector<coproto::Socket> mPeerSocks;
};

} // namespace volePSI
