#pragma once

// MPSVS Phase 4 — MPC-wire F_PSA alignment (sort + windowed merge on shares).
//
// Bit-shared row shape: `bin` and `source` are public post-OPRF (§3);
// `key`, `memb`, `sector`, and payload are secret-shared. Within-bin sort
// uses `MpMpcSort::mpcBitonicSort` on a composite key. Windowed merge
// implements the Rev 7 §5.4 R16 defect-A closure: two adjacent same-key
// rows merge into one live output only if BOTH have memb=1.
//
// This wire implements Phase 4's compute half — the parallel-partition sort
// and the K-way merge. CGP shuffle (§5.5) uses the existing
// `volePSI::mpstar::MpCgpShuffle` module, which has an independent shape
// (RowVec of plaintext blocks with per-party rerandomisation) and is
// integrated at a separate seam.
//
// Payload width kept to a single u64 slot for tests; the pattern extends
// linearly to the full 6-field Rev 7 §5.2 schema (each field is an
// independent SharedU64Bin, gated by a shared valid bit).
//
// Cost profile (n rows per bin, single u64 payload):
//   - Sort: mpcBitonicSortTripleCost(n, 64+8+3 payload bits)
//   - Merge: n × [1 secureEqual (192 triples) + 3 × 64 secureAnd for MUXes]

#include "MpBeaverTriple.h"
#include "MpMpcSort.h"
#include "MpSecretShare.h"
#include "MpSecureCompare.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::SharedBit;
using mpstar::SharedU64Bin;

// Row entering Phase 4 alignment. Bin + source are public; the rest shared.
struct SharedBinRow {
    uint32_t     bin = 0;       // public post-OPRF
    uint8_t      source = 0;    // public (0=MAS, 1=DOS, 2=MOM)
    SharedU64Bin key;           // OPRF-derived τ-bit tag suffix, shared
    SharedBit    memb;          // 1 = real, 0 = dummy padding
    SharedU64Bin sector;        // canonical sector code
    SharedU64Bin payload;       // single u64 slot for the test scope
};

// Output of windowed merge: fewer or equal rows compared to input; some
// carry a "live" bit indicating a successful cross-source match.
struct SharedMergedRow {
    uint32_t     bin;
    SharedBit    live;          // 1 iff K-way match succeeded with all memb=1
    SharedU64Bin key;
    SharedU64Bin sector;
    SharedU64Bin payload;
};

// Sort the rows within a bin by shared key. Rows are padded (by caller)
// to a power of 2. Sort key is the shared u64 key. Payload carried through.
void withinBinSortWire(std::vector<SharedBinRow>& rows,
                        const std::vector<BeaverTripleBit>& triples,
                        size_t& tripleIndex);

// R16-gated windowed merge over a SORTED bin. For each adjacent pair
// (rows[i], rows[i+1]) with the SAME shared key AND both memb bits = 1,
// produce a "live" merged row that combines their payloads (single-source
// test: pick either — same by construction). Rows without a match have
// live=0 in the output (they are still emitted so downstream shape is
// public-fixed).
//
// R16 defect-A closure: if either row has memb=0 (i.e., is a dummy pad),
// the merge produces live=0 even if keys "match" (dummies have random key).
std::vector<SharedMergedRow>
windowedMergeWire(const std::vector<SharedBinRow>& sorted,
                    const std::vector<BeaverTripleBit>& triples,
                    size_t& tripleIndex);

// Triple budget estimator.
size_t alignmentWireTripleBudget(size_t bin_size);

// Test helper: reconstruct a merged row to plaintext.
struct PlainMergedRow {
    uint32_t bin;
    uint8_t  live;
    uint64_t key;
    uint64_t sector;
    uint64_t payload;
};
std::vector<PlainMergedRow>
reconstructMerged(const std::vector<SharedMergedRow>& shared);

// Test helper: share a plaintext (bin, key, memb, sector, payload, source).
SharedBinRow shareBinRow(uint32_t bin, uint8_t source, uint64_t key,
                          uint8_t memb, uint64_t sector, uint64_t payload,
                          oc::PRNG& prng);

} // namespace mpsvs
} // namespace volePSI
