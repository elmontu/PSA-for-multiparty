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

// N-party oblivious shuffle in star topology via N-1 sequential rounds.
// Each round runs TWO OSN calls (one for M, one for R) with the SAME
// seeded Benes routing, so the joint shared (M ⊕ R) is permuted by a
// single per-round random dest_k. Composing N-1 rounds gives a random
// permutation no single party knows.
//
// Per-round random dest_k is derived from the sender↔SP session key + a
// "shuffle_round_k" domain tag, so SP and sender k agree on it but no
// other party does.
class MpShuffleDriver {
public:
    // Sender side.
    //
    // For sender index k in [0, N-1):
    //   - osnSocksA and osnSocksB MUST be non-default; they are the two
    //     sockets to SP used for the M-side and R-side OSN calls when this
    //     sender drives round k. (Sender k drives round k.)
    //   - revealSocket is ignored (unused).
    //
    // For sender index k == N-1:
    //   - osnSocksA / osnSocksB are ignored.
    //   - revealSocket is used to ship final R to SP after the last round's
    //     handoff completes.
    //
    // spKey: sender↔SP session key (from MpSpHandshake + deriveSessionKey).
    //        Per-round seeds derived from this + sessionId + "shuffle_round_k".
    static macoro::task<std::vector<oc::block>> runSender(
        MpStarChannel& chan,
        const MpStarSetup& setup,
        uint32_t selfIdx,
        uint32_t senderCount,
        uint64_t C,
        std::vector<oc::block> ownMasks,
        coproto::Socket& osnSocketA,
        coproto::Socket& osnSocketB,
        coproto::Socket& revealSocket,
        const std::array<uint8_t, 32>& spKey,
        const std::array<uint8_t, 32>& sessionId);

    // SP side.
    //
    // osnSocksA[k] / osnSocksB[k]: the two OSN sockets with sender k.
    //                              Both arrays size = senderCount - 1.
    // revealSocket: socket to the last sender (senderCount-1) for final R.
    // spKeys: per-sender session keys (size = senderCount).
    static macoro::task<std::vector<oc::block>> runSp(
        MpStarChannel& spChan,
        std::vector<coproto::Socket>& osnSocksA,
        std::vector<coproto::Socket>& osnSocksB,
        coproto::Socket& revealSocket,
        uint32_t senderCount,
        uint64_t C,
        std::vector<oc::block> initialMasked,
        const std::vector<std::array<uint8_t, 32>>& spKeys,
        const std::array<uint8_t, 32>& sessionId);
};

} // namespace volePSI
