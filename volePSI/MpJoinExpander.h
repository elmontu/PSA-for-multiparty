#pragma once

// Phases 4 + 5 of the N-party private-join protocol (R30). See
// docs/PRIVATE_JOIN_DESIGN.md.
//
//   Phase 4 — window detection: after oblivious sort by id (R29), tuples
//   sharing the same id are contiguous. This module identifies window
//   boundaries.
//
//   Phase 5 — cross-product expansion: for each window, emit all M^N
//   combinations of one-tuple-per-party. Each output row carries an
//   is_intersection bit that is the AND of the picked tuples' is_real
//   bits — true iff every party contributed a real (not padding) row.
//
// Encoding contract: each input SortElement (from MpObliviousSort) has
//   - key  = id hash (uint64_t)
//   - payload[0]  = metadata block packed as:
//       bytes 0..3   : party_idx (uint32_t, little-endian)
//       bytes 4..7   : row_idx_in_id (uint32_t, little-endian)
//       bytes 8      : is_real (uint8_t, 0 or 1)
//       bytes 9..15  : reserved / zero
//   - payload[1..W] : payload_data (W blocks of actual row data)
//
// Pad-input contract: each (party_idx, id) pair must appear EXACTLY M
// times in the sorted input. If a party doesn't have this id at all,
// Phase 1 (per-party pad+commit, not yet implemented) emits M all-dummy
// tuples for that party with is_real = 0. The expander asserts the
// per-window structural invariant.

#include "MpObliviousSort.h"

#include "cryptoTools/Common/Defines.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// Phase 4 output: a vector of window-end flags. windowEnds[i] is true iff
// position i is the LAST in its id-window (i.e., either it's the final
// element or sorted[i+1].key != sorted[i].key).
std::vector<bool> detectWindowEnds(const std::vector<SortElement>& sorted);

// Phase 4 helper: window start indices (one per distinct id).
std::vector<size_t> windowStartIndices(const std::vector<SortElement>& sorted);

// One output row from the cross-product expansion.
struct JoinExpandedRow {
    uint64_t id;                          // shared across all picks
    std::vector<oc::block> joinedPayload; // length = N * payloadW
    bool isIntersection;                  // AND of picked is_real bits
};

// Phase 5: cross-product expander. Input must satisfy the pad-input
// contract (see header). Returns |windows| * M^N output rows.
//
// payloadW is the per-party payload width in blocks (matches R26b/step-5
// terminology). The joinedPayload is laid out as concat over parties:
//   joinedPayload[party_idx * payloadW + w] for party in [0, N), w in [0, payloadW).
std::vector<JoinExpandedRow> crossProductExpand(
    const std::vector<SortElement>& sorted,
    uint32_t N, uint32_t M, uint32_t payloadW);

// Encode the (party_idx, row_idx_in_id, is_real) metadata into one block,
// matching the contract above. Used by tests and by the future Phase 1
// per-party pad+commit module.
oc::block packTupleMeta(uint32_t party_idx, uint32_t row_idx, bool is_real);

// Inverse: decode the metadata block.
void unpackTupleMeta(const oc::block& meta,
                     uint32_t& out_party_idx,
                     uint32_t& out_row_idx,
                     bool& out_is_real);

} // namespace mpstar
} // namespace volePSI
