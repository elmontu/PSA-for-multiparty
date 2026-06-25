#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "coproto/coproto.h"
#include "macoro/task.h"

namespace volePSI {

// X25519 DH key establishment between SP and every sender, conducted
// over each sender's raw socket BEFORE any MpStarChannel relay is set up.
// Produces a 32-byte symmetric key per (SP, sender) pair, suitable for
// AEAD-tagging the masked-column transmission and any other sender→SP
// integrity-critical message.
class MpSpHandshake {
public:
    // SP side. Generates one keypair, sends pk to every sender, recvs each
    // sender's pk, derives per-sender shared key via X25519 + RandomOracle KDF.
    // Returns one 32-byte key per sender, indexed by sender id.
    static macoro::task<std::vector<std::array<uint8_t, 32>>> runSp(
        std::vector<coproto::Socket>& senderSocks);

    // Sender side. Exchanges pk with SP over spSock, derives the matching key.
    static macoro::task<std::array<uint8_t, 32>> runSender(
        coproto::Socket& spSock,
        uint32_t selfIdx);
};

} // namespace volePSI
