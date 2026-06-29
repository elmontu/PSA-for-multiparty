#pragma once

// MPC variants of join Phases 4-6 (R34g + R34h + R34i) + end-to-end
// in-memory driver (R34j) for the SP-blind private join. See
// docs/PRIVATE_JOIN_DESIGN.md.
//
// All operations work on secret-shared data (XOR-shared bits or
// arithmetic-shared u64). No party — including SP — reconstructs any
// plaintext id or payload until the final reveal phase.
//
// Composite-key trick to avoid in-protocol window detection:
//   Each tuple's sort key is COMPOSITE: (id << partyIdxBits) | party_idx.
//   After MPC bitonic sort by this composite, tuples are grouped by id
//   AND ordered by party_idx WITHIN each id-group. The structural layout
//   then is: positions [w·N·M, w·N·M + M) are party 0's M tuples for
//   window w's id, positions [w·N·M + M, w·N·M + 2M) are party 1's, etc.
//
// This makes cross-product expansion an INDEX-BASED data-movement step
// (no MPC math beyond the is_intersection AND-aggregation).

#include "MpSecretShare.h"
#include "MpBeaverTriple.h"
#include "MpSecureCompare.h"
#include "MpMpcSort.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// ----------------------------------------------------------------------
// R34g — MPC window detection (general-purpose; not required by the join
// pipeline since composite-key sort gives the window layout
// structurally, but useful for other use cases like SP-blind aggregate
// queries).

// Returns one SharedBit per position. bit[i].reconstruct() = 1 iff
// position i is the LAST in its id-window (either i == n-1 or
// keys[i] != keys[i+1]).
//
// Compares ONLY the high (id) bits of the sort key. The low
// (party_idx) bits are masked out before comparison.
std::vector<SharedBit> mpcWindowEnds(
    const std::vector<SharedSortElement>& sorted,
    uint32_t partyIdxBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex);

size_t mpcWindowEndsTripleCost(size_t n);

// ----------------------------------------------------------------------
// R34h — MPC cross-product expander.
//
// Input bag must be sorted by composite key as described in the file
// header. Each input element's payload is:
//   payload[0]               = is_real (SharedBit)
//   payload[1 .. 1+rowDataBits) = row data bits (SharedBit each)

// One output row of the MPC join. Same shape as JoinExpandedRow but
// fully bit-shared.
struct MpcJoinRow {
    SharedU64Bin id;                       // pure id (extracted from composite key)
    std::vector<SharedBit> joinedPayload;  // N * rowDataBits, party-major
    SharedBit isIntersection;              // AND of picked is_reals
};

std::vector<MpcJoinRow> mpcCrossProductExpand(
    const std::vector<SharedSortElement>& sortedBag,
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits,
    uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex);

size_t mpcCrossProductExpandTripleCost(
    size_t windowCount, uint32_t N, uint32_t M);

// ----------------------------------------------------------------------
// R34i — MPC oblivious filter on is_intersection.
//
// Pushes is_intersection=true rows to the front via MPC bitonic sort
// using is_intersection (negated) as the sort key. Caller-visible
// truncation leaks the actual K; pad to a public ceiling for full
// cardinality hiding.
void mpcFilterIntersection(
    std::vector<MpcJoinRow>& rows,
    uint32_t N, uint32_t rowDataBits,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex);

size_t mpcFilterIntersectionTripleCost(
    size_t numRows, uint32_t N, uint32_t rowDataBits);

// ----------------------------------------------------------------------
// R34j — end-to-end in-memory SP-blind private join driver.
//
// Per-party input: each party's table as a list of (id, is_real,
// row_data) shared tuples. The CALLER is responsible for Phase 1
// (per-party padding to M-per-id and dummy generation); this driver
// runs Phases 3 (sort) + 5 (expand) + 6 (filter).
//
// Returns the joined rows still bit-shared. Reconstruction is the
// caller's choice (typically only after a Phase 7 random shuffle).

struct JoinInputRowShared {
    SharedU64Bin id;
    SharedBit isReal;
    std::vector<SharedBit> rowData;  // length rowDataBits
};

std::vector<MpcJoinRow> mpcExecutePrivateJoinInMemory(
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits, uint32_t rowDataBits,
    const std::vector<std::vector<JoinInputRowShared>>& perParty,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex);

// Total triple cost for the end-to-end driver. The caller pre-generates
// this many triples before invoking the driver.
size_t mpcExecutePrivateJoinInMemoryTripleCost(
    uint32_t N, uint32_t M,
    uint32_t partyIdxBits, uint32_t rowDataBits,
    size_t universeSize);

} // namespace mpstar
} // namespace volePSI
