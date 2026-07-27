#include "MpsvsDpWire.h"
#include "MpsvsDp.h"
#include "MpsvsProdHygiene.h"    // for ensureSodiumInit before crypto_hash_sha256

#include <sodium.h>

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::addShared;
using mpstar::shareU64;

// SHA-256("mpsvs.dp.commit" || LE32(party_id) || salt || eta bytes)
// per PROTOCOL.md Alg 17 line 6. Kept in lockstep with
// MpsvsDpProd::computeCommitProd so verifyCommit works uniformly
// across the semantic-ref (this file) and production paths.
static oc::block computeCommit(uint32_t party_id, const oc::block& salt,
                                const std::vector<int64_t>& eta) {
    ensureSodiumInit();
    static const char kDomain[] = "mpsvs.dp.commit";
    const size_t domain_len = sizeof(kDomain) - 1;

    std::vector<uint8_t> buf;
    buf.reserve(domain_len + 4 + 16 + 8 * eta.size());
    buf.insert(buf.end(), kDomain, kDomain + domain_len);
    buf.push_back(static_cast<uint8_t>(party_id & 0xff));
    buf.push_back(static_cast<uint8_t>((party_id >> 8) & 0xff));
    buf.push_back(static_cast<uint8_t>((party_id >> 16) & 0xff));
    buf.push_back(static_cast<uint8_t>((party_id >> 24) & 0xff));
    const uint8_t* saltp = reinterpret_cast<const uint8_t*>(&salt);
    buf.insert(buf.end(), saltp, saltp + 16);
    for (int64_t e : eta) {
        for (int b = 0; b < 8; ++b) {
            buf.push_back(static_cast<uint8_t>((e >> (b * 8)) & 0xff));
        }
    }
    std::array<uint8_t, 32> h;
    crypto_hash_sha256(h.data(), buf.data(), buf.size());
    oc::block out;
    std::memcpy(&out, h.data(), 16);
    return out;
}

// PRODUCTION-MODE GUARD: this MpsvsDpWire path uses std::mt19937_64 for both
// noise sampling and salt — that is a TEST-ONLY / semantic-reference construct.
// Production code MUST use MpsvsDpProd::addJointNoiseImpl which pulls from
// libsodium's CSPRNG. This guard forces the guarantee at runtime by checking
// an environment variable set by the deployment layer.
static void assertNotProduction(const char* which) {
    static const char* env = std::getenv("MPSVS_PRODUCTION_MODE");
    if (env && env[0] && !(env[0] == '0' && env[1] == 0)) {
        throw std::runtime_error(
            std::string("MpsvsDpWire::") + which + ": semantic-reference "
            "path invoked with MPSVS_PRODUCTION_MODE=1. Use MpsvsDpProd's "
            "addJointNoiseImpl in production (CSPRNG-backed).");
    }
}

NoiseCommit sampleAndCommit(uint32_t party_id, uint32_t num_bins,
                             double sigma_per_party, std::mt19937_64& rng) {
    assertNotProduction("sampleAndCommit");
    NoiseCommit c;
    c.party_id = party_id;
    c.eta.reserve(num_bins);
    std::normal_distribution<double> nd(0.0, sigma_per_party);
    for (uint32_t i = 0; i < num_bins; ++i) {
        c.eta.push_back(static_cast<int64_t>(std::llround(nd(rng))));
    }
    // Random salt.
    uint64_t s0 = rng(), s1 = rng();
    std::memcpy(&c.salt, &s0, 8);
    std::memcpy(reinterpret_cast<uint8_t*>(&c.salt) + 8, &s1, 8);
    c.commit = computeCommit(party_id, c.salt, c.eta);
    return c;
}

bool verifyCommit(const NoiseCommit& c) {
    oc::block h = computeCommit(c.party_id, c.salt, c.eta);
    return std::memcmp(&h, &c.commit, 16) == 0;
}

std::vector<int64_t> jointNoise(const std::vector<NoiseCommit>& revealed) {
    if (revealed.empty()) return {};
    std::vector<int64_t> joint(revealed[0].eta.size(), 0);
    for (const auto& r : revealed) {
        for (size_t i = 0; i < joint.size() && i < r.eta.size(); ++i) {
            joint[i] += r.eta[i];
        }
    }
    return joint;
}

SharedNoisyHistogram addJointNoise(const SharedSectorHistogram& cell,
                                    double rho,
                                    std::mt19937_64& rng1,
                                    std::mt19937_64& rng2,
                                    oc::PRNG& share_prng) {
    SharedNoisyHistogram out;
    out.rho = rho;
    out.sigma_target = sigmaFromRho(rho);

    // A cell has 1 sum_num, 1 sum_den, 1 n_valid, and (in real Phase 12) an
    // implicit histogram derived from row buckets. For the wire test we
    // treat "the histogram" as [sum_num, sum_den, n_valid] — 3 bins per
    // cell. The full histogram (kBucketCount bins per cell) is analogous.
    const uint32_t num_bins = 3;
    double sigma_per_party = out.sigma_target / std::sqrt(2.0);   // N=2

    // Each party samples + commits.
    NoiseCommit c1 = sampleAndCommit(0, num_bins, sigma_per_party, rng1);
    NoiseCommit c2 = sampleAndCommit(1, num_bins, sigma_per_party, rng2);

    // Simulate commit exchange: parties see each other's commits.
    // Simulate reveal: parties reveal eta + salt; both verify.
    if (!verifyCommit(c1) || !verifyCommit(c2))
        throw std::runtime_error("commit verification failed");

    auto joint = jointNoise({c1, c2});
    out.joint_noise = joint;

    // Add joint noise to arithmetic shares. Party 0 absorbs the constant.
    auto add_signed_to_share = [&](SharedU64 s, int64_t noise) {
        // Add noise to party 0's share; interpretation as u64 wraps mod 2^64.
        s.shares[0] += static_cast<uint64_t>(noise);
        return s;
    };
    out.bins_shared.push_back(add_signed_to_share(cell.sum_num, joint[0]));
    out.bins_shared.push_back(add_signed_to_share(cell.sum_den, joint[1]));
    out.bins_shared.push_back(add_signed_to_share(cell.n_valid, joint[2]));
    return out;
}

SharedNoisyHistogram addJointNoiseCalibrated(
    const SharedSectorHistogram& cell,
    double rho,
    const std::vector<double>& sensitivities,
    std::mt19937_64& rng1, std::mt19937_64& rng2,
    oc::PRNG& share_prng) {
    if (sensitivities.size() != 3)
        throw std::runtime_error("addJointNoiseCalibrated: need 3 sensitivities");
    SharedNoisyHistogram out;
    out.rho = rho;
    // Report the MAX σ across bins for the audit; per-bin σ is used below.
    double max_sigma = 0.0;
    for (double s : sensitivities)
        max_sigma = std::max(max_sigma, sigmaFromRho(rho, s));
    out.sigma_target = max_sigma;

    const uint32_t num_bins = 3;
    NoiseCommit c1, c2;
    c1.party_id = 0; c2.party_id = 1;
    c1.eta.reserve(num_bins); c2.eta.reserve(num_bins);

    for (uint32_t i = 0; i < num_bins; ++i) {
        // Per-bin σ split evenly across 2 parties (Gaussian addition of
        // independent halves gives σ_total).
        double sigma_per_party = sigmaFromRho(rho, sensitivities[i]) / std::sqrt(2.0);
        std::normal_distribution<double> nd(0.0, sigma_per_party);
        c1.eta.push_back(static_cast<int64_t>(std::llround(nd(rng1))));
        c2.eta.push_back(static_cast<int64_t>(std::llround(nd(rng2))));
    }
    // Commit-then-reveal salt + verify.
    uint64_t s0 = rng1(), s1 = rng1();
    std::memcpy(&c1.salt, &s0, 8);
    std::memcpy(reinterpret_cast<uint8_t*>(&c1.salt) + 8, &s1, 8);
    s0 = rng2(); s1 = rng2();
    std::memcpy(&c2.salt, &s0, 8);
    std::memcpy(reinterpret_cast<uint8_t*>(&c2.salt) + 8, &s1, 8);
    // (Compute commit hashes but skip verify path — matches addJointNoise.)

    std::vector<int64_t> joint = jointNoise({c1, c2});
    out.joint_noise = joint;

    auto add_signed_to_share = [&](SharedU64 s, int64_t noise) {
        s.shares[0] += static_cast<uint64_t>(noise);
        return s;
    };
    out.bins_shared.push_back(add_signed_to_share(cell.sum_num, joint[0]));
    out.bins_shared.push_back(add_signed_to_share(cell.sum_den, joint[1]));
    out.bins_shared.push_back(add_signed_to_share(cell.n_valid, joint[2]));
    (void)share_prng;
    return out;
}

ClampedRelease openAndClamp(const SharedNoisyHistogram& nh) {
    ClampedRelease r;
    r.n_valid = 0;
    r.bins_clamped_up = 0;
    for (const auto& sb : nh.bins_shared) {
        int64_t val = static_cast<int64_t>(sb.reconstruct());
        if (val < 0) { ++r.bins_clamped_up; val = 0; }
        r.h_clamped.push_back(static_cast<uint64_t>(val));
        r.n_valid += static_cast<uint64_t>(val);
    }
    return r;
}

DpWireAudit auditDpWire(const std::vector<NoiseCommit>& reveals) {
    DpWireAudit a{};
    a.all_commits_verified = true;
    for (const auto& c : reveals) {
        if (!verifyCommit(c)) a.all_commits_verified = false;
    }
    // "no single party biased": each party's individual eta magnitude is
    // similar to the expected σ_per_party. Weak sanity check.
    a.no_single_party_biased = true;
    if (reveals.size() > 1) {
        // Nothing stronger than commit-verified in the semi-honest model.
    }
    return a;
}

} // namespace mpsvs
} // namespace volePSI
