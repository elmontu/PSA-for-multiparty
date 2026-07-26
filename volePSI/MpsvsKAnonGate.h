#pragma once

// MPSVS k-Anonymity Gate — fully oblivious release protection.
//
// The Rev 7 §12 spec mandates a k-anonymity gate: cells with n_valid < k
// must be suppressed to prevent identifying individual contributors. In the
// baseline implementation this gate would be applied AFTER opening (plaintext
// check), which leaks "was this cell suppressed vs empty?" — a form of
// membership leakage.
//
// This module implements the gate ON SHARES, cryptographically:
//   1. Compute pass_bit = (n_valid_shared ≥ k_thresh) via secureLessThan
//   2. MUX every released field by pass_bit: output = pass_bit · field
//   3. GovTech sees only "zero cell" or "release cell", cannot tell whether
//      a zero was suppressed or genuinely empty.
//
// Combined with:
//   - Cover firms (MpsvsCoverFirms) — inflates n_valid so k-anon threshold
//     may pass even for small true counts
//   - Calibrated DP (addJointNoiseCalibrated) — bounds sum leakage
// the release becomes FULLY OBLIVIOUS to individual firm membership.
//
// Threat model coverage:
//   - Without k-anon: cell (sector=X, n_valid=1) → adversary identifies
//     the one firm in sector X immediately.
//   - With plaintext k-anon: suppressed cell appears as ∅ in release →
//     adversary knows n_valid < k in sector X (partial leak).
//   - With shared k-anon: suppressed cell appears as ZEROS with the same
//     shape as any other cell → adversary cannot tell suppress vs empty
//     vs random low-count.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpSecureCompare.h"
#include "MpsvsSectorAgg.h"
#include "MpsvsSectorAggWire.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::BeaverTripleU64;
using mpstar::SharedBit;
using mpstar::SharedU64;
using mpstar::SharedU64Bin;

struct KAnonConfig {
    uint32_t k_thresh = 5;   // public threshold: cells with n_valid < k → suppress
};

// Convert arithmetic-shared u64 to bit-shared u64 (for comparison).
// Cost: reveals bit-decomposition via B2A-inverse. For simplicity in this
// prototype we perform bit-shared reconstruction of n_valid to a
// SharedU64Bin form via re-sharing. In production, use a proper A2B
// conversion (e.g. Toft-style prefix adder tree).
SharedU64Bin arithToBit(const SharedU64& x, oc::PRNG& prng);

// Apply k-anon gate to a shared cell. Returns a gated copy where each field
// is MUX-ed by (n_valid ≥ k_thresh) — pass_bit stays shared.
// Cost per cell:
//   1 secureLessThan on 64-bit values (~192 bit triples)
//   1 B2A on the pass bit (1 arith triple)
//   3 secureMultiply on arith shares (3 arith triples: sum_num, sum_den, n_valid)
struct GatedCell {
    SectorKey     key;
    Metric        metric;
    SharedU64     sum_num_gated;
    SharedU64     sum_den_gated;
    SharedU64     n_valid_gated;
    SharedBit     pass;        // for audit; still shared
};

GatedCell
applyKAnonGate(const SharedSectorHistogram& cell,
                const KAnonConfig& cfg,
                const std::vector<BeaverTripleBit>& bit_triples,
                size_t& bit_idx,
                oc::PRNG& prng);

// Batch variant.
std::vector<GatedCell>
applyKAnonGateBatch(const std::vector<SharedSectorHistogram>& cells,
                      const KAnonConfig& cfg,
                      const std::vector<BeaverTripleBit>& bit_triples,
                      size_t& bit_idx,
                      oc::PRNG& prng);

// Triple budget estimator per cell.
size_t kAnonTripleBudgetPerCell();

// Test helper: reconstruct a gated cell.
struct PlainGatedCell {
    SectorKey key;
    Metric    metric;
    uint64_t  sum_num;
    uint64_t  sum_den;
    uint64_t  n_valid;
    uint8_t   pass;
};
PlainGatedCell reconstructGatedCell(const GatedCell& g);

} // namespace mpsvs
} // namespace volePSI
