#pragma once

// MPSVS Phase 9 — MPC-wire composite vulnerability score.
//
// vuln_strict = Σ_{m ∈ core} w_m · (rank_{entity, m} / (n_valid_{popkey, m} − 1))
// incl_strict = AND of 4 core inclusion bits (per entity)
//
// Cost breakdown per (popkey × core-metric) reciprocal:
//   - 1 goldschmidtRecipWire call: ~692K bit triples (Phase 6 wire)
// Cost per entity:
//   - 4 fpMulShared (rank_fp · reciprocal_fp): 4 × ~65K = ~260K triples
//   - 4 mulPublicConst128 (score · w_fp): 4 × 128 × 512 ≈ ~260K triples
//   - 3 bitAdd128 (accumulate weighted scores): 3 × 384 = 1152 triples
//   - 3 secureAnd (AND-chain of 4 incl bits): 3 triples
//
// For 3 entities × 1 popkey × 4 core metrics test:
//   4 reciprocals + 3·4 = 12 fpMul + 3·4 = 12 pub-const mul + rest ≈
//   4·692K + 12·65K + 12·65K + small ≈ 4.3M triples for the test.
//
// Deferred: renormalised composite variant — requires ONE Goldschmidt per
// entity (per-entity available-weight denominator), an extra ~692K triples
// per entity. Not implemented in this first-pass wire.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpsvsComposite.h"
#include "MpsvsGoldschmidtWire.h"
#include "MpsvsRankWire.h"

#include <array>
#include <cstdint>
#include <map>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::BeaverTripleBit;
using mpstar::SharedBit;

// Public weights encoded as 128-bit fp (from CompositeWeights doubles).
struct CompositeWeightsWire {
    std::array<__int128, kMetricCount> w_fp{};
    CompositeWeightsWire() {
        w_fp.fill(0);
        __int128 quarter_fp = (static_cast<__int128>(1) << (kFpFractionalBits - 2));
        w_fp[static_cast<size_t>(Metric::DTI)]  = quarter_fp;
        w_fp[static_cast<size_t>(Metric::DSI)]  = quarter_fp;
        w_fp[static_cast<size_t>(Metric::Delq)] = quarter_fp;
        w_fp[static_cast<size_t>(Metric::NPL)]  = quarter_fp;
    }
};

// Per-entity shared composite output.
struct SharedCompositeRow {
    uint32_t      entity_idx;
    uint32_t      popkey;
    // STRICT variant.
    SharedBit     incl_strict;      // AND of 4 core incl bits
    SharedU128Bin vuln_strict_fp;   // Σ w_m · score_m
    // RENORMALISED variant.
    SharedBit     incl_renorm;      // OR of 4 core incl bits
    SharedU128Bin vuln_renorm_fp;   // Σ (incl_m · w_m · score_m) / Σ (incl_m · w_m)
    uint8_t       avail_core;       // reconstructed count for audit (0..4)
};

// Public multiplication by a __int128 constant on a bit-shared 128-bit value.
// Uses shift-and-conditional-add on the constant's bits (public shifts) —
// no secureAnd needed since the constant is public. Only the additions
// consume Beaver triples (~384 per set bit of the constant).
SharedU128Bin mulPublicConst128(const SharedU128Bin& x, __int128 c,
                                  const std::vector<BeaverTripleBit>& triples,
                                  size_t& tripleIndex);

// Per-cell shared reciprocal cache: precomputed once per (popkey, metric).
struct SharedCellReciprocal {
    uint32_t       popkey;
    Metric         metric;
    SharedU128Bin  recip_fp;    // 1 / (n_valid_popkey_m - 1) as fp
};

// Precompute reciprocals — one per (popkey, metric) cell.
// n_valid_by_cell must contain a shared u64 value per (popkey, metric).
std::vector<SharedCellReciprocal>
precomputeCellReciprocals(
    const std::map<std::pair<uint32_t, Metric>, SharedU64Bin>& n_valid_by_cell,
    uint64_t N_max,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex);

// Compute BOTH strict + renormalised composites per entity.
// Inputs:
//   - metric_ranks[m] : shared ranked rows for metric m (from Phase 8 wire)
//   - reciprocals     : precomputed 1/(n_valid-1) per (popkey, metric)
//   - weights         : public weights per metric (fp-encoded)
// Output:
//   - one SharedCompositeRow per unique entity_idx (populates both strict
//     and renorm fields; consumer gates on incl_strict / incl_renorm)
//
// Documented controlled leak: goldschmidtRecipWire on the per-entity
// renorm-denominator reveals its integer magnitude (via range-reduction).
// The safe-denom Select ensures entities with 0 available core see a
// dummy plaintext '1' — real Σincl_m·w_m only leaked for entities with
// at least one available core (which is a small set of possibilities
// bounded by 2^4=16 combinations of the 4 core-incl bits × 4 possible
// weight assignments = 16 magnitudes). Full-oblivious range reduction
// is Phase 17 malicious-upgrade work.
std::vector<SharedCompositeRow>
computeCompositeTwoScoreWire(
    const std::array<std::vector<SharedRankedRow>, kMetricCount>& metric_ranks,
    const std::vector<SharedCellReciprocal>& reciprocals,
    const CompositeWeightsWire& weights,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex,
    oc::PRNG& prng);

// Deprecated alias — same as computeCompositeTwoScoreWire, kept for the
// existing test binary. New code should call the TwoScore variant.
std::vector<SharedCompositeRow>
computeCompositeStrictWire(
    const std::array<std::vector<SharedRankedRow>, kMetricCount>& metric_ranks,
    const std::vector<SharedCellReciprocal>& reciprocals,
    const CompositeWeightsWire& weights,
    const std::vector<BeaverTripleBit>& triples,
    size_t& tripleIndex,
    oc::PRNG& prng);

// Reconstruct a shared composite row (test helper).
struct PlainCompositeRow {
    uint32_t entity_idx;
    uint32_t popkey;
    uint8_t  incl_strict;
    double   vuln_strict;
    uint8_t  incl_renorm;
    double   vuln_renorm;
    uint8_t  avail_core;
};
std::vector<PlainCompositeRow>
reconstructComposites(const std::vector<SharedCompositeRow>& shared);

} // namespace mpsvs
} // namespace volePSI
