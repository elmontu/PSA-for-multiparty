#pragma once

// R36b: higher-level wire MPC ops composing on top of MpMpcWire's
// primitives (R34k-remain). 2-party wire-protocol versions of
// conditional swap, bitonic sort, cross-product expansion, and the
// is_intersection filter — enough to run the full SP-blind MPC private
// join over the wire.

#include "MpMpcWire.h"
#include "MpBeaverTriple.h"

#include "coproto/Socket/Socket.h"
#include "macoro/task.h"

#include <array>
#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// 2-party wire conditional swap on a pair of (key, payload) elements.
// key is a 64-bit XOR-shared value (one bit per array entry); payload
// is an arbitrary-length XOR-shared bit vector. If `selector` reconstructs
// to 1, the elements swap; if 0, they don't. Triple cost: 64 + payloadBits.
struct WireSortElement {
    std::array<uint8_t, 64> key;      // bit-shared 64-bit key
    std::vector<uint8_t> payload;     // bit-shared payload bits
};

macoro::task<void> wireConditionalSwap(
    WireSortElement& a,
    WireSortElement& b,
    uint8_t selector,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock);

// Wire MPC bitonic sort on a vector of WireSortElement. Sorts in
// ascending key order in place. Each compare-and-swap consumes
// secureLessThanTripleCost() + (64 + payloadBits) triples.
macoro::task<void> wireMpcBitonicSort(
    std::vector<WireSortElement>& xs,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock);

size_t wireMpcBitonicSortTripleCost(size_t n, size_t payloadBits);

// One MPC-join output row: (id, joined payload, is_intersection bit).
// All bit-shared. Length conventions match MpcJoinRow but stored as
// per-party uint8_t shares for the wire variant.
struct WireMpcJoinRow {
    std::array<uint8_t, 64> id;             // bit-shared 64-bit id
    std::vector<uint8_t> joinedPayload;     // N * rowDataBits bits
    uint8_t isIntersection;                 // 1 bit
};

// Wire cross-product expansion. Input bag is laid out so that within
// each window of N*M consecutive elements:
//   positions [0, M)   = party 0's M tuples for the window's id
//   positions [M, 2M)  = party 1's M tuples
//   ... etc.
// Each input element's payload = [is_real bit][row data bits ...].
// Output: |windows| * M^N rows.
//
// Each output row consumes (N-1) wireSecureAnd calls (for is_intersection
// AND-aggregation chain). All other work is local bit copying.
macoro::task<std::vector<WireMpcJoinRow>> wireMpcCrossProductExpand(
    const std::vector<WireSortElement>& sortedBag,
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits,
    uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock);

size_t wireMpcCrossProductExpandTripleCost(
    size_t windowCount, uint32_t N, uint32_t M);

// Wire oblivious filter on is_intersection: sorts rows so true-rows come
// first, via wireMpcBitonicSort using a derived key. Reuses sort cost.
macoro::task<void> wireMpcFilterIntersection(
    std::vector<WireMpcJoinRow>& rows,
    uint32_t N, uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIdx,
    uint64_t partyIdx,
    coproto::Socket& sock);

size_t wireMpcFilterIntersectionTripleCost(
    size_t numRows, uint32_t N, uint32_t rowDataBits);

} // namespace mpstar
} // namespace volePSI
