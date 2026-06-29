#pragma once

// In-memory end-to-end driver for the N-party private-join protocol
// (R32). Composes Phases 1, 2, 3, 4, 5, 6 from the modular building
// blocks (MpObliviousSort, MpJoinExpander, MpJoinFilter). Phase 7
// (cascade shuffle) and Phase 8 (CSV writeout) are existing volePSI
// infrastructure — left out of the in-memory driver for separation of
// concerns; the wire-protocol driver (R33) glues them on.
//
// This module is a correctness oracle: it computes what the wire
// protocol should produce, end-to-end, against plaintext inputs. Tests
// can compare the wire-protocol output against this oracle.

#include "MpJoinExpander.h"   // for JoinExpandedRow

#include "cryptoTools/Common/Defines.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpstar {

// One row of a party's input table: (id, row_data). id is a uint64_t
// (typically a hash of the application-level identifier). row_data is W
// blocks wide; W is a global parameter.
struct JoinInputRow {
    uint64_t id;
    std::vector<oc::block> row_data;   // length must equal W
};

// One party's input table: a flat list of (id, row_data) tuples; ids
// can repeat (multi-row per id is the whole point of table-valued PSA).
using JoinInputTable = std::vector<JoinInputRow>;

// Run the in-memory N-party private join.
//
//   N          : number of parties (≥ 2)
//   M          : per-party-per-id row-count cap (Phase 1 padding target)
//   payloadW   : row_data width in blocks per row
//   perParty   : perParty[i] is party i's input table
//
// Returns the joined intersection table: each output row is the
// cross-product of one row from each party for an id present in ALL
// parties' tables. Dummy expansions are filtered out (Phase 6).
//
// Throws if:
//   - any input row has row_data.size() != payloadW
//   - any party has more than M rows for some id (over-cap)
//   - the bag size cannot fit (Phase 5 cross-product guard fires)
std::vector<JoinExpandedRow> executePrivateJoinInMemory(
    uint32_t N, uint32_t M, uint32_t payloadW,
    const std::vector<JoinInputTable>& perParty);

} // namespace mpstar
} // namespace volePSI
