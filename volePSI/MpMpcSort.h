#pragma once

// MPC bitonic sort on secret-shared (key, payload) pairs (R34e + R34f).
// Composes R34d (secureLessThan) + R34a/b/c primitives into a fully
// SP-blind sort: no party sees plaintext keys or payloads during the
// sort; the access pattern is structurally oblivious (same compare-swap
// network as MpObliviousSort, but each comparator and swap is an MPC
// subprotocol).
//
// Cost per compare-and-swap on n-element bitonic network:
//   - 1 secureLessThan        → secureLessThanTripleCost() = 256 triples
//   - 1 conditional swap      → conditionalSwapTripleCost(payloadBits)
//                              = (64 + payloadBits) triples
//
// Total triples for sort of n elements with payload width B bits each:
//   bitonicCompareSwapCount(n) · (256 + 64 + B)

#include "MpSecretShare.h"
#include "MpBeaverTriple.h"
#include "MpSecureCompare.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// One element in the MPC-sortable bag: 64-bit XOR-shared key plus a
// payload of arbitrary length, also XOR-shared bit by bit.
struct SharedSortElement {
    SharedU64Bin key;
    std::vector<SharedBit> payload;
};

// Conditionally swap two SharedSortElements based on a SharedBit selector.
// If selector reconstructs to 1, swap is applied; if 0, leave alone.
// Per-bit oblivious: the structural access pattern is identical regardless
// of the selector value.
//
// payloadBits = a.payload.size() (must match b.payload.size()).
// Consumes (64 + payloadBits) Beaver triple bits from `triples`.
void conditionalSwap(SharedSortElement& a,
                     SharedSortElement& b,
                     const SharedBit& selector,
                     const std::vector<BeaverTripleBit>& triples,
                     size_t& tripleIndex);

size_t conditionalSwapTripleCost(size_t payloadBits);

// MPC bitonic sort. Sorts `xs` in ascending key order, in place.
// Pre-generated Beaver triples must satisfy:
//   triples.size() >= mpcBitonicSortTripleCost(n, payloadBits)
size_t mpcBitonicSortTripleCost(size_t n, size_t payloadBits);

void mpcBitonicSort(std::vector<SharedSortElement>& xs,
                    const std::vector<BeaverTripleBit>& triples,
                    size_t& tripleIndex);

} // namespace mpstar
} // namespace volePSI
