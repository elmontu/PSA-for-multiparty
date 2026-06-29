#pragma once

// In-memory simulation of the N-party MAC-propagating cascade shuffle.
//
// This module is NOT a wire protocol — it operates on plain `AuthShare`
// state held by simulated parties. The purpose is to validate the MAC
// arithmetic across (a) inter-round XOR of shares, (b) round-by-round
// permutation, and (c) end-of-protocol verification — independently of the
// OSN and coproto-socket layers.
//
// Once this passes its unit tests, the same logic ports into
// MpShuffleDriver: each OSN-twice call is replaced by an OSN-quadruple
// (data + tag, with shared init_wj_seeded) and the per-round MAC keys are
// derived from spKey ⊕ sessionId via deriveSessionKey (already in use).
//
// Threat model bound by this simulation:
//   - We assume SP and active sender k both derive the per-round MAC key
//     α_k from a shared session secret. Either party can compute α_k · v
//     for any value they hold. This catches tampering by network attackers
//     and by ANY single party that deviates AFTER its round (e.g. lies
//     about handed-off R_{k+1}).
//   - It does NOT prevent collusion: if SP and one sender share α, they
//     can jointly forge consistent (data, tag) pairs. Full SPDZ-style
//     active security needs OLE-based α-shares; see docs/MALICIOUS_CASCADE_DESIGN.md.

#include "MpMac.h"

#include <array>
#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// One column of cascade state. The cascade operates on N parallel columns
// independently — the same permutation is applied across columns. The
// invariant is per-column:
//   sp.data ⊕ peer.data == plain_after_perm
//   sp.tag  ⊕ peer.tag  == α_round · plain_after_perm
struct CascadeColumn {
    AuthShare sp;    // SP-side authenticated share
    AuthShare peer;  // active sender-side authenticated share
};

// Result of one cascade round. `peerHandoff` is what the active sender
// hands off to the next sender (peer mesh AEAD). `spState` is what SP
// keeps for the next round.
struct CascadeRoundOutput {
    std::vector<AuthShare> spState;        // size = N columns
    std::vector<AuthShare> peerHandoff;    // size = N columns
};

// Apply a single cascade round in-memory.
//
//   - permutation: dest[i] = source index that lands at position i after π
//                  (matches OSN init_wj_seeded semantics).
//   - alphaOld: MAC key used to authenticate the INCOMING state.
//   - alphaNew: MAC key the OUTGOING state should be re-MACed under.
//
// Verifies the incoming invariant under alphaOld, applies the permutation
// in lockstep to data and tag, and re-MACs under alphaNew. Returns false
// (with outputs cleared) if the incoming invariant is broken (tampering
// detected).
bool cascadeRound(const std::vector<CascadeColumn>& incoming,
                  const std::vector<int>& permutation,
                  const oc::block& alphaOld,
                  const oc::block& alphaNew,
                  oc::PRNG& sharingPrng,
                  CascadeRoundOutput& out);

// Final verification: SP has accumulated (M, tag_M) across all rounds and
// the last sender hands off (R, tag_R). Recompute the joint plaintext
// (M ⊕ R) and the joint MAC (tag_M ⊕ tag_R), check invariant under the
// LAST round's α.
bool finalVerify(const std::vector<AuthShare>& spState,
                 const std::vector<AuthShare>& lastPeerState,
                 const oc::block& alphaFinal,
                 std::vector<std::vector<oc::block>>& outPlain);

// Derive per-round MAC key from a base session key + round index. Uses
// the existing KDF (deriveSessionKey) under purpose "mac_round_<k>".
oc::block deriveMacKey(const std::array<uint8_t, 32>& spKey,
                       const std::array<uint8_t, 32>& sessionId,
                       uint32_t roundIdx);

// Generate a uniformly-random permutation of [0..n) from a block seed.
// Same Fisher-Yates routine used in OSN init_wj_seeded so the simulation
// matches what the live cascade will produce.
std::vector<int> randomPermutation(uint32_t n, const oc::block& seed);

} // namespace mpstar
} // namespace volePSI
