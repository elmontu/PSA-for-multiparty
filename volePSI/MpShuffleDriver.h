#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include "cryptoTools/Common/Defines.h"
#include "coproto/coproto.h"
#include "macoro/task.h"

namespace volePSI {

class MpStarChannel;
class MpStarSetup;

// N-party oblivious shuffle in star topology via N-1 sequential 2-party OSN rounds.
// Invariant maintained: SP's M XOR the unique-mask-holder's R = pi_0 o ... o pi_k (initial table).
class MpShuffleDriver {
public:
    // Sender participant in the cascade.
    // myOsnSocket: direct socket to SP, used (a) by sender k as the OSN channel when k == selfIdx,
    //              and (b) by the last sender for the final-reveal send to SP.
    // spKey: sender↔SP session key (from MpSpHandshake + deriveSessionKey).
    //        Used to AEAD-wrap rho_k and the final-reveal R so SP detects
    //        tampering / forgery of these messages.
    static macoro::task<std::vector<oc::block>> runSender(
        MpStarChannel& chan,
        const MpStarSetup& setup,
        uint32_t selfIdx,
        uint32_t senderCount,
        uint64_t C,
        std::vector<oc::block> ownMasks,
        coproto::Socket& myOsnSocket,
        const std::array<uint8_t, 32>& spKey);

    // SP role.
    // osnSocksPerRound[k]: OSN socket with sender k, used for round k AND (if k = senderCount-2) for the
    //   final-reveal recv from the last sender.
    // spKeys: per-sender session keys (size = senderCount).
    // Requires senderCount >= 2.
    static macoro::task<std::vector<oc::block>> runSp(
        MpStarChannel& spChan,
        std::vector<coproto::Socket>& osnSocksPerRound,
        uint32_t senderCount,
        uint64_t C,
        std::vector<oc::block> initialMasked,
        const std::vector<std::array<uint8_t, 32>>& spKeys);
};

} // namespace volePSI
