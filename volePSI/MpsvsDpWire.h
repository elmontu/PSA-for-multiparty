#pragma once

// MPSVS Phase 12 — MPC-wire DP noise via commit-then-reveal joint sampling.
//
// Neither S1 nor S2 alone knows the noise added to the histogram. Each party
// samples an independent noise value; parties commit-then-reveal their
// samples so neither can bias after seeing the other. The joint noise is
// the sum, which is Gaussian (sum of independent Gaussians).
//
// Given σ_target, each party samples η_i ~ N(0, σ_target² / N) so the sum
// is N(0, σ_target²).
//
// Protocol:
//   1. Each party i draws η_i ~ N(0, σ²/N), computes hash commit(η_i).
//   2. Parties exchange commits.
//   3. Parties reveal η_i; verify commit.
//   4. Joint noise = Σ η_i. Adds noise to histogram bin (each party
//      holds an arithmetic share of the bin; joint noise added as
//      additive share).
//   5. R26 clamp: max(0, noisy_share). Applied per bin via secureLessThan
//      + secureAnd on bit-shared form (or opened at clamp — see spec).
//
// This wire module implements the joint noise + arithmetic-share add.
// R26 clamp requires bit-shared arithmetic (SharedU64Bin) which we haven't
// yet reached; we defer the shared clamp to the mid-protocol boundary and
// perform it at open time (Phase 12.1). This is acceptable because R26
// only affects percentiles derived from the CDF — the sums themselves
// don't need clamping.

#include "MpBeaverTriple.h"
#include "MpSecretShare.h"
#include "MpsvsOpenWire.h"
#include "MpsvsSectorAggWire.h"

#include "cryptoTools/Crypto/Blake2.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <cstdint>
#include <random>
#include <vector>

namespace volePSI {
namespace mpsvs {

using mpstar::SharedU64;

// Per-party noise sample + commit.
struct NoiseCommit {
    uint32_t party_id;
    oc::block commit;      // 128-bit hash of (party_id || η_bytes || salt)
    // Held privately until reveal:
    std::vector<int64_t> eta;    // one per bin
    oc::block salt;
};

// Sample noise + commit for one party. σ_per_party = σ_target / √N.
NoiseCommit sampleAndCommit(uint32_t party_id, uint32_t num_bins,
                             double sigma_per_party, std::mt19937_64& rng);

// Verify commit against revealed values.
bool verifyCommit(const NoiseCommit& c);

// Combine both parties' revealed noise into joint noise per bin.
std::vector<int64_t> jointNoise(const std::vector<NoiseCommit>& revealed);

// Add joint noise to a shared histogram bin — each party locally adds the
// joint noise to its share. Since (jointNoise) is now known to both parties
// after reveal, this is deterministic post-reveal.
//
// After this, R26 clamp is deferred to open time (each party sends its
// share; the reconstructed noisy count is clamped max(0, ·) before use).
struct SharedNoisyHistogram {
    std::vector<SharedU64> bins_shared;    // post-noise arithmetic shares
    double sigma_target;
    double rho;
    // For audit: which party contributed which noise (revealed).
    std::vector<int64_t> joint_noise;
};

SharedNoisyHistogram addJointNoise(const SharedSectorHistogram& cell,
                                    double rho,
                                    std::mt19937_64& rng1,
                                    std::mt19937_64& rng2,
                                    oc::PRNG& share_prng);

// Sensitivity-calibrated variant: per-bin L2 sensitivity Δ_2 given by
// `sensitivities`. σ per bin = Δ_2 / sqrt(2·ρ). Use this when the release
// contains SUMS (whose sensitivity is the public contribution-clip bound
// per firm) rather than COUNTS (sensitivity ~ √2).
//
// Example — for a release row of {sum_num, sum_den, n_valid} with per-firm
// clip C_debt=1e6, C_income=1e6, and count sensitivity √2:
//   sensitivities = {1e6, 1e6, √2}
// This produces DP noise that dominates any single firm's contribution to
// the sum, so the "residual attack" (adversary knows own record + release
// → subtracts to learn others' aggregate) yields noise no more precise than
// σ. This closes the membership-inference gap flagged in the membership
// trace's Q7.
SharedNoisyHistogram addJointNoiseCalibrated(
    const SharedSectorHistogram& cell,
    double rho,
    const std::vector<double>& sensitivities,   // must have 3 entries: {num, den, count}
    std::mt19937_64& rng1, std::mt19937_64& rng2,
    oc::PRNG& share_prng);

// R26 clamp at open time: reconstruct each bin (joint reveal), max(0, ·),
// return clamped u64 histogram. This is the only "plaintext" point for the
// histogram — matches Phase 12.1's release boundary.
struct ClampedRelease {
    std::vector<uint64_t> h_clamped;
    uint64_t              n_valid;
    uint32_t              bins_clamped_up;
};
ClampedRelease openAndClamp(const SharedNoisyHistogram& nh);

// Audit: verify commits, verify no party's individual noise ≈ joint noise.
struct DpWireAudit {
    bool all_commits_verified;
    bool no_single_party_biased;
};
DpWireAudit auditDpWire(const std::vector<NoiseCommit>& reveals);

} // namespace mpsvs
} // namespace volePSI
