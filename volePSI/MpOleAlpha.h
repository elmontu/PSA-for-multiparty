#pragma once

// R28: OLE-based α-sharing for the malicious cascade.
//
// In R25's MAC-propagating cascade, the per-round MAC key α is a SHARED
// SECRET between SP and the active sender — either party can locally
// compute α·v. This is the documented privacy gap: SP-vs-active-sender
// collusion can forge consistent (data, tag) perturbations.
//
// R28 closes the gap by SPDZ-style additively sharing α between the two
// parties: α = α_0 XOR α_1 (GF(2^128) addition). Neither party knows α
// alone. Multiplying a shared value by α is done via OLE: each party
// inputs its (α_i, x_i) shares; outputs are additive shares of α·x.
//
// For this prototype:
//   - α-shares: each party picks a uniform random GF(2^128) element.
//   - OLE: ideal trusted-dealer simulation (one-shot dealer outputs
//     (a, b, c) such that c = α·x where α from one party, x from the
//     other; party A holds (α, a), party B holds (x, c) with the
//     invariant α·x XOR a == c).
//   - Authenticated sharing: combine local α·own_data with OLE outputs.
//   - Verification: at protocol end, parties reveal α-shares and MAC
//     tags, recompute and check.
//
// The trusted-dealer simulation IS the part that needs replacement with
// real OLE for production. With R34k delivering libOTe SilentOtTriple
// (over Z_2), the OLE for GF(2^128) is the natural next extension —
// SilentVole would provide it directly. See docs/R28_DESIGN.md.

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "coproto/Socket/Socket.h"
#include "macoro/task.h"

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace volePSI {
namespace mpstar {

// Each party's α-share. 128 bits = one oc::block.
using MyShareAlpha = oc::block;

// Each party's authenticated share of an underlying value.
struct AuthShareMine {
    oc::block data;   // my share of plaintext x  (x = data_0 XOR data_1)
    oc::block tag;    // my share of MAC tag      (α·x = tag_0 XOR tag_1)
};

// Generate THIS party's α-share. The joint α = α_0 XOR α_1 is uniform
// random and is NEVER reconstructed until the verification phase.
MyShareAlpha generateMyAlphaShare(oc::PRNG& prng);

// Trusted-dealer OLE correlation for a single GF(2^128) multiplication
// of (α from one party) × (x from the other party).
//
// Output to party A: (αA, aA) with aA uniform random.
// Output to party B: (xB, cB) with cB = αA·xB XOR aA.
// Invariant: αA · xB == aA XOR cB.
//
// In production this comes from libOTe's SilentVole or equivalent OLE
// protocol. The two parties never directly see each other's inputs.
struct OleGf128Correlation {
    oc::block myValue;   // αA on party A; xB on party B
    oc::block myMask;    // aA on party A; cB on party B
};

struct OleGf128Result {
    OleGf128Correlation forPartyA;   // (αA, aA)
    OleGf128Correlation forPartyB;   // (xB, cB)
};

// Dealer-emulated OLE on a single (α, x) pair.
OleGf128Result dealerOleGf128(oc::block alphaA, oc::block xB, oc::PRNG& prng);

// Authenticate an input held by one party. After this, both parties
// hold an AuthShareMine:
//   - input party (iAmInputParty=true): data = plain, tag = own
//     contribution + OLE result.
//   - non-input party: data = 0, tag = its OLE mask.
//
// Joint reconstruction: data_0 XOR data_1 = plain;
//                       tag_0  XOR tag_1  = (α_0 XOR α_1) · plain = α · plain.
//
// Requires two OLE correlations (one in each direction: I-need-α-other ·
// my-x, and other-needs-α-mine · their-x = 0). For inputs where the
// non-input party's x = 0, only one OLE is needed (the cross term
// α_other · plain). Returns this party's share.
//
// PRECONDITION: myOleAcross must be the dealer output for OLE on
// (α_other, plain) — i.e., the non-input party's α-share times the
// input party's plain value. Caller wires this up via dealerOleGf128.
AuthShareMine authShareInput(
    oc::block plain,                            // valid only if iAmInputParty
    bool iAmInputParty,
    MyShareAlpha myAlpha,
    const OleGf128Correlation& myOleAcross,
    uint64_t partyIdx);

// Verify a batch of (auth-share-A, auth-share-B) pairs satisfies the
// MAC invariant under the JOINT α. Used by the final verify phase
// where both parties reveal their α-shares to a verifier (or to each
// other via a MAC-check subprotocol). Uses constant-time comparison
// per-position to avoid early-termination side channel on the tag.
bool verifyAuthBatchJoint(
    const std::vector<AuthShareMine>& sharesA,
    const std::vector<AuthShareMine>& sharesB,
    oc::block jointAlpha);

// SPDZ-style MAC check WITHOUT revealing α: each party computes a
// random linear combination of its data shares + tag shares (using a
// public challenge r); reveals only the LINEAR-COMBINED shares; the
// linear combination is verified to satisfy the invariant under the
// random challenge. If any individual tag was bogus, the random LC
// catches it with probability 1 - 2^{-128}.
//
// For this in-memory prototype the function takes both parties' shares
// and the joint α as input; in a wire protocol α stays secret and the
// check is done via a small interactive subprotocol. Returns true iff
// the batched check passes.
bool macCheckBatched(
    const std::vector<AuthShareMine>& sharesA,
    const std::vector<AuthShareMine>& sharesB,
    oc::block jointAlpha,
    oc::PRNG& challengePrng);

// R37: Wire-protocol variant of the OLE correlation generator.
// Follows the same handshake-then-seeded-PRNG scaffold as
// cgpPreprocessOverWire (see MpCgpPreprocess.h) so both parties derive
// consistent (a, c) values from a shared random seed. The libOTe
// SilentVole substitution slots into this function.
//
// partyIdx == 0 plays the "A" role (holds alphaA, receives aA)
// partyIdx == 1 plays the "B" role (holds b,      receives cB)
//
// Callers on party 0 pass `alphaA` (their own α-share); party 1's
// value is derived from the shared seed. Callers on party 1 pass
// their input `b` (their x value being MAC'd).
//
// Returns THIS party's OLE correlation (the other party's half is
// held only by the peer, matching the security invariant).
struct OleGf128CorrelationOverWire {
    oc::block myValue;
    oc::block myMask;
};

macoro::task<OleGf128CorrelationOverWire> oleGf128OverWire(
    uint64_t partyIdx,
    oc::block myInputValue,  // alphaA for party 0; b for party 1
    oc::PRNG& prng,
    coproto::Socket& sock);

} // namespace mpstar
} // namespace volePSI
