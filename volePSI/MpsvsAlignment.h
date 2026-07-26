#pragma once

// MPSVS Phase 4 — Binned oblivious alignment realising F_PSA.
//
// Per docs/PROTOCOL_PI_SECTORVULN_R7.md §5.0 (F_PSA ideal functionality) and
// its instantiation in §5.1 (secret-share bins), §5.2 (payload schema),
// §5.3 (within-bin bitonic sort), §5.4 (WindowedMerge, R16 membership-gated),
// §5.5 (LiveMark + CGP ComposedShuffle).
//
// This module is the SEMANTIC REFERENCE. Row fields are stored in plaintext
// uint64_t (representing "reconstructed shares" — the semantic value each
// party would jointly recover if their shares were combined). All operations
// are STRUCTURALLY OBLIVIOUS: the access pattern depends only on public
// parameters (n, β, cap_P, bin_id), never on secret values. MPC wire upgrade
// (2-of-2 additive shares over Z_{2^k} + Beaver-triple multiplication) is
// a straight substitution of the primitive layer — the alignment algorithm
// is unchanged.
//
// Invariants (verified by tests/unit/test_mpsvs_alignment.cpp):
//   * R16 defect-A closure: dummy rows (memb=0) NEVER become live post-merge,
//     even under a key collision with a real row.
//   * Determinism: same input → same output up to composed shuffle permutation.
//   * F_PSA correctness: output row for each K-way-intersection entity has
//     all K membership bits set and each source's payload; single-source
//     entities have exactly their source's membership bit set.
//   * Duplicate detection: (canonical_id, period) collision within one source
//     triggers a generic abort with no per-entity leakage.

#include "MpsvsOprf.h"
#include "MpsvsTopology.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace volePSI {
namespace mpsvs {

// ---------------------------------------------------------------------------
// Row schema (fixed length; Rev 7 §5.2)
// ---------------------------------------------------------------------------

// Payload columns per source. Aligned with MpsvsLocalPrep.h payload schemas
// but flattened for the alignment layer. Six numeric fields per source is
// enough for the pipeline; caller composes richer schemas by chaining rows.
constexpr size_t kPayloadNumFields = 6;

struct PayloadPerSource {
    // Numeric fields (SGD cents for MAS/DOS; counts for MOM).
    std::array<uint64_t, kPayloadNumFields> v{};
    // Validity bits (one per field).
    std::array<uint8_t, kPayloadNumFields> valid{};
    // Growth fields (Rev 7 §4.1 local growth): fp-encoded growth + validity.
    uint64_t g = 0;
    uint8_t  v_g = 0;
    uint64_t contraction = 0;
};

// A single row entering F_PSA. Pre-Phase-4 layout: one row per (source,
// canonical_id, period) with the OPRF-derived (bin, key) tag from Phase 2 §3.
struct Row {
    // PUBLIC bookkeeping.
    uint64_t  bin = 0;       // 2^β bin index (public post OPRF)
    uint32_t  source = 0;    // 0=MAS, 1=DOS, 2=MOM; small enum

    // SECRET (would be shared in MPC; here in plaintext for reference).
    uint64_t  key = 0;       // τ-bit tag suffix from Phase 2 §3
    uint8_t   memb = 0;      // 1 = real, 0 = dummy
    uint64_t  period = 0;    // canonical period tag
    uint64_t  sector = 0;    // canonical sector code (may conflict across sources)
    PayloadPerSource payload{};

    // Convenience: is this a real row (not a dummy padding)?
    bool isReal() const { return memb == 1; }
};

// Post-merge union row: one output row per candidate key. Membership bits
// per source; payload per source; live flag; canonical flag.
struct UnionRow {
    // PUBLIC bookkeeping (post-shuffle, becomes public position only).
    uint64_t bin = 0;

    // SECRET (would be shared).
    uint64_t period = 0;
    uint64_t sector = 0;   // reconciled per §5.4 (authoritative source rule)
    uint8_t  b_MAS = 0;    // presence bit — Rev 7 R16 membership-gated
    uint8_t  b_DOS = 0;
    uint8_t  b_MOM = 0;
    PayloadPerSource p_MAS{};
    PayloadPerSource p_DOS{};
    PayloadPerSource p_MOM{};
    uint8_t canonical = 0; // set only on the first row of a same-key run
    uint8_t live = 0;      // = canonical AND (b_MAS OR b_DOS OR b_MOM)
    uint8_t sector_conflict = 0;  // shared exception flag (§5.4)
};

// ---------------------------------------------------------------------------
// Bin packing (Rev 7 §4.3 + §5.1)
// ---------------------------------------------------------------------------

// Per-party per-bin capacity. Rev 7 §9 sizing gives cap_P via Chernoff.
struct BinParams {
    uint32_t beta      = 13;     // 2^β bins
    uint32_t tau_bits  = 71;     // key width (β + τ ≥ collision bound)
    uint32_t cap_P     = 256;    // per-party per-bin capacity
};

// Aggregate over one party's rows: bin them, pad each bin to cap_P with
// dummies (memb=0, random key). Overflow (any bin count > cap_P) throws
// RestartSession per §4.3.
struct BinnedTable {
    uint32_t beta;
    uint32_t cap_P;
    // rows[b] holds exactly cap_P rows for bin b (real + dummies).
    std::vector<std::vector<Row>> rows;
};

class RestartSession : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

BinnedTable packBins(uint32_t source,
                     const std::vector<Row>& real_rows,
                     const BinParams& params,
                     oc::PRNG& prng);

// ---------------------------------------------------------------------------
// Duplicate detection (Rev 7 §5.4 guard)
// ---------------------------------------------------------------------------

// Check that within one source's rows, (canonical_id_key, period) is unique.
// If any duplicate, throw with a generic message (no per-entity leakage in
// external logs).
class DuplicateEntityPeriod : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
void assertNoDuplicateEntityPeriod(const std::vector<Row>& rows);

// ---------------------------------------------------------------------------
// Within-bin sort + WindowedMerge + LiveMark + Shuffle
// ---------------------------------------------------------------------------

// Sort a bin's rows in-place by (key, source) using a data-oblivious bitonic
// network. Requires n a power of two — pad with public dead rows keyed to
// sort last (Rev 7 §5.3 padding). This function does that padding.
void withinBinSort(std::vector<Row>& bin);

// R16 membership-gated windowed merge (Rev 7 §5.4). Consumes a sorted bin;
// produces at most cap_P canonical union rows (one per distinct key in the
// bin). Non-canonical rows are set to live=0.
std::vector<UnionRow> windowedMerge(const std::vector<Row>& sorted_bin);

// Mark live = canonical AND (b_MAS OR b_DOS OR b_MOM). Rev 7 §5.5.
void markLive(std::vector<UnionRow>& rows);

// CGP-style composed shuffle (Rev 7 §5.6): S1 permutes with π1, then S2
// permutes with π2. Composed π = π2 ∘ π1 unknown to either party. Semantic
// reference just applies π2∘π1 as a single pass on plaintext rows.
void composedShuffle(std::vector<UnionRow>& rows, oc::PRNG& prng);

// ---------------------------------------------------------------------------
// F_PSA runner
// ---------------------------------------------------------------------------

// Given three per-party row streams (already tagged by Phase 2 §3), run the
// full alignment pipeline. Returns the final union table of size
// N̂ = 2^β · Σ_P cap_P, in uniformly random order.
//
// Sector reconciliation (§5.4 authoritative-source rule): default = MAS
// wins if MAS present, else DOS, else MOM. Sets sector_conflict flag if
// sources disagreed. Never leaks per-entity conflict externally.
struct AlignmentResult {
    std::vector<UnionRow> table;
    bool restarted = false;
    // Public metadata: bin params.
    BinParams params;
};

AlignmentResult runFPsa(const std::vector<Row>& mas_rows,
                        const std::vector<Row>& dos_rows,
                        const std::vector<Row>& mom_rows,
                        const BinParams& params,
                        oc::PRNG& prng);

// ---------------------------------------------------------------------------
// F_PSA leakage audit (verifies output shape matches §5.0)
// ---------------------------------------------------------------------------

struct FPsaAudit {
    size_t total_rows;        // must equal N̂ = 2^β · Σ_P cap_P
    size_t live_rows;         // number of live=1 rows
    size_t canonical_rows;    // number of canonical=1 rows
    size_t sector_conflicts;  // rows with sector_conflict=1
    bool   all_shapes_public; // structural fixed-shape check
};

FPsaAudit auditAlignment(const AlignmentResult& r);

} // namespace mpsvs
} // namespace volePSI
