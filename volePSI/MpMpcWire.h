#pragma once

// 2-party wire-protocol MPC primitives (R34k-remain). Each party holds
// ONLY ITS OWN share (single uint8_t for bits, single uint64_t for u64s);
// every "open" is a 1-round-trip share exchange with the peer over a
// coproto::Socket. Composes on top of R34k MpOleTriple for triple gen.
//
// 2-party only. Higher-level building blocks (mpcBitonicSort, MPC join
// driver) use these primitives. See docs/MPC_WIRE_DESIGN.md for the
// architecture and the path to N>2.

#include "MpBeaverTriple.h"   // for BeaverTripleBit (re-used as triple-share container)

#include "coproto/Socket/Socket.h"
#include "macoro/task.h"

#include <array>
#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

using MyShareBit = uint8_t;

// ----------------------------------------------------------------------
// Building blocks: open, NOT, AND, OR

// One round-trip share exchange: send myShare to peer, receive theirs,
// return XOR (joint plaintext bit). Both parties call this with their
// own share; the call order is symmetric.
macoro::task<uint8_t> wireOpenBit(
    uint8_t myShare,
    uint64_t partyIdx,
    coproto::Socket& sock);

// Local-only NOT: only party 0 flips its share (the joint XOR flips,
// satisfying NOT semantics). partyIdx > 0 returns unchanged.
inline uint8_t wireNotBit(uint8_t myShare, uint64_t partyIdx) {
    return (partyIdx == 0) ? static_cast<uint8_t>(myShare ^ 1) : myShare;
}

// Wire AND of two XOR-shared bits using one Beaver triple bit. Two opens
// (d and e) batched in one round-trip. Each "myTriple*" arg is THIS
// party's share of the corresponding triple component.
macoro::task<uint8_t> wireSecureAnd(
    uint8_t myX,
    uint8_t myY,
    uint8_t myTripleU,
    uint8_t myTripleV,
    uint8_t myTripleW,
    uint64_t partyIdx,
    coproto::Socket& sock);

// Convenience: wireSecureAnd taking a BeaverTripleBit and partyIdx
// (extracts the right share automatically).
macoro::task<uint8_t> wireSecureAndT(
    uint8_t myX,
    uint8_t myY,
    const BeaverTripleBit& triple,
    uint64_t partyIdx,
    coproto::Socket& sock);

// Wire OR via De Morgan: a OR b = NOT (NOT a AND NOT b).
// Consumes one triple bit.
macoro::task<uint8_t> wireSecureOr(
    uint8_t myA,
    uint8_t myB,
    const BeaverTripleBit& triple,
    uint64_t partyIdx,
    coproto::Socket& sock);

// ----------------------------------------------------------------------
// 64-bit secure comparison + equality

// 64-bit less-than: each my* is the party's bit-shares (LSB at index 0,
// MSB at index 63). Consumes secureLessThanTripleCost() = 256 triples.
macoro::task<uint8_t> wireSecureLessThan(
    const std::array<uint8_t, 64>& myX,
    const std::array<uint8_t, 64>& myY,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock);

// 64-bit equality. AND-tree on per-bit NOT-XOR. Consumes 63 triples.
macoro::task<uint8_t> wireSecureEqual(
    const std::array<uint8_t, 64>& myX,
    const std::array<uint8_t, 64>& myY,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock);

size_t wireSecureLessThanTripleCost();
size_t wireSecureEqualTripleCost();

} // namespace mpstar
} // namespace volePSI
