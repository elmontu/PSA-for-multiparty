#pragma once

// MPSVS Phase 12.1 — MPC-wire output opening to GovTech.
//
// The only plaintext boundary in the protocol: reveal DP-clamped noisy
// histogram + derived percentiles + ratio-of-sums to GovTech. Before this
// point, all values are on shares. After this point, GovTech sees plaintext
// (which is what the protocol demands — the DP-noised output IS the release).
//
// Wire protocol: both parties broadcast their share of each opened value to
// GovTech; GovTech sums.
//
// Structural invariant enforced by types: only `SharedU64::reconstruct()`
// can produce plaintext — all preceding pipeline outputs are shared, so a
// "GovTech" who only receives one party's share cannot reveal anything.

#include "MpSecretShare.h"
#include "MpsvsOpen.h"
#include "MpsvsSectorAggWire.h"

#include <cstdint>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::SharedU64;

// Shared histogram bin (one shared u64 per bin), pre-noise or post-noise.
struct SharedHistBin {
    std::vector<SharedU64> counts;   // size = kBucketCount
};

// A shared release row before opening.
struct SharedReleaseRow {
    SectorKey key;
    Metric    metric;
    SharedHistBin  hist;         // clamped noisy histogram bins
    SharedU64      sum_num;      // ratio-of-sums numerator
    SharedU64      sum_den;      // denominator
};

// Party's contribution to the release opening. Each party sends its share
// vector to GovTech; GovTech sums.
struct PartyContribution {
    uint32_t party_id;
    std::vector<uint64_t> flat_shares;   // flattened bin counts + sum_num + sum_den
};

// Extract party p's contribution — this is what actually goes over the wire.
PartyContribution extractContribution(uint32_t party_id,
                                       const std::vector<SharedReleaseRow>& rows);

// GovTech: combine both parties' contributions to reconstruct the plaintext
// release. This is the ONLY function that can produce plaintext output.
ReleaseBundle
combineContributions(const std::vector<SharedReleaseRow>& shape,
                      const std::vector<PartyContribution>& contribs,
                      double rho_total,
                      uint32_t query_count,
                      uint32_t protocol_rev = 7);

// Structural check: verify that a single party's contribution alone
// reconstructs to random-looking values (info-theoretic hiding).
bool oneShareDoesNotRevealPlaintext(uint32_t party_id,
                                     const std::vector<SharedReleaseRow>& rows,
                                     const std::vector<uint64_t>& true_totals);

} // namespace mpsvs
} // namespace volePSI
