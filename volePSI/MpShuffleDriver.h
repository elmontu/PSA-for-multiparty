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

// N-party oblivious shuffle of N PARALLEL payload columns in star topology.
//
// Each cascade round k applies the same secret permutation pi_k to all N
// columns. Composing N-1 rounds yields a random permutation no single party
// learns. Each (M[c], R[c]) pair is shuffled by two OSN calls per round
// (M-side and R-side, sharing seeded init_wj_seeded).
//
// Per-round seed derived from sender↔SP session key + sessionId +
// "shuffle_round_<k>", so SP and sender k agree without leaking it.
class MpShuffleDriver {
public:
    // Sender side.
    //
    // ownMasks: per-column R vectors. ownMasks.size() == senderCount.
    //   Each ownMasks[c] is the current R-share for column c. Initially:
    //     sender 0:    ownMasks[c] = r_c (collected from peers in Phase 0)
    //     sender i>0:  ownMasks[c] = zero vector (length C)
    //   After cascade rounds, only the LAST sender holds non-trivial state.
    //
    // osnSocketA/B: see runSp; per-round OSN sockets to SP, used only when
    //   selfIdx == k for some round k < senderCount-1.
    // revealSocket: used only by selfIdx == senderCount-1 for final reveal.
    static macoro::task<std::vector<std::vector<oc::block>>> runSender(
        MpStarChannel& chan,
        const MpStarSetup& setup,
        uint32_t selfIdx,
        uint32_t senderCount,
        uint64_t C,
        std::vector<std::vector<oc::block>> ownMasks,
        coproto::Socket& osnSocketA,
        coproto::Socket& osnSocketB,
        coproto::Socket& revealSocket,
        const std::array<uint8_t, 32>& spKey,
        const std::array<uint8_t, 32>& sessionId);

    // SP side.
    //
    // initialMasked: per-column M vectors. initialMasked.size() == senderCount.
    //   initialMasked[c] is sender c's masked payload column = c_c XOR r_c.
    // osnSocksA/B[k]: per-cascade-round OSN sockets with sender k.
    // revealSocket: socket to last sender for final R reveal (N parallel R).
    // spKeys: per-sender session keys.
    //
    // Returns N parallel shuffled columns: result[c] = pi(c_c) for all c
    // (where pi is the composite per-round dest_k).
    static macoro::task<std::vector<std::vector<oc::block>>> runSp(
        std::vector<coproto::Socket>& osnSocksA,
        std::vector<coproto::Socket>& osnSocksB,
        coproto::Socket& revealSocket,
        uint32_t senderCount,
        uint64_t C,
        std::vector<std::vector<oc::block>> initialMasked,
        const std::vector<std::array<uint8_t, 32>>& spKeys,
        const std::array<uint8_t, 32>& sessionId);
};

} // namespace volePSI
