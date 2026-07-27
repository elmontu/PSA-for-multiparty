#include "MpsvsDpProd.h"

#include <sodium.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <set>
#include <stdexcept>

namespace volePSI {
namespace mpsvs {

using mpstar::shareU64;

// ---------------------------------------------------------------------------
// Uniform (0, 1] via CSPRNG. Rejects 0.
// ---------------------------------------------------------------------------
static double secureUniform01() {
    uint64_t r = 0;
    do {
        r = secureRandU64();
    } while (r == 0);
    // Take 53 high bits for double mantissa precision.
    uint64_t bits = r >> (64 - 53);
    return static_cast<double>(bits) / static_cast<double>(1ULL << 53);
}

// ---------------------------------------------------------------------------
// Box-Muller with CSPRNG-sourced uniforms.
// Returns one integer draw from N(0, sigma^2), rounded to nearest.
// ---------------------------------------------------------------------------
int64_t sampleGaussianCsprng(double sigma) {
    if (sigma <= 0.0) return 0;
    double u1 = secureUniform01();
    double u2 = secureUniform01();
    // z0 ~ N(0, 1); scale by sigma; round.
    double z0 = std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * M_PI * u2);
    double x = z0 * sigma;
    return static_cast<int64_t>(std::llround(x));
}

// ---------------------------------------------------------------------------
// SHA-256("mpsvs.dp.commit" || LE32(party_id) || salt || eta bytes)
// per PROTOCOL.md Alg 17 line 6. Domain-separated + party-tagged so a
// commit from party 1 cannot be replayed as party 2, and cannot be reused
// across protocols. Output truncated to oc::block (16 bytes) for storage
// compatibility with the semantic-ref path; the full 32-byte SHA-256 is
// computed and truncated.
// ---------------------------------------------------------------------------
static oc::block computeCommitProd(uint32_t party_id, const oc::block& salt,
                                     const std::vector<int64_t>& eta) {
    static const char kDomain[] = "mpsvs.dp.commit";
    const size_t domain_len = sizeof(kDomain) - 1;

    std::vector<uint8_t> buf;
    buf.reserve(domain_len + 4 + 16 + 8 * eta.size());
    buf.insert(buf.end(), kDomain, kDomain + domain_len);
    // LE32 party id (matches format in PROTOCOL.md).
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

NoiseCommit sampleAndCommitProd(uint32_t party_id, uint32_t num_bins,
                                  double sigma_per_party) {
    NoiseCommit c;
    c.party_id = party_id;
    c.eta.reserve(num_bins);
    for (uint32_t i = 0; i < num_bins; ++i) {
        c.eta.push_back(sampleGaussianCsprng(sigma_per_party));
    }
    // Salt from CSPRNG.
    secureRandBytes(&c.salt, 16);
    c.commit = computeCommitProd(party_id, c.salt, c.eta);
    return c;
}

// ---------------------------------------------------------------------------
// Hardened joint noise + audit log.
// ---------------------------------------------------------------------------

static SharedNoisyHistogram addJointNoiseImpl(
    const SharedSectorHistogram& cell, double rho,
    const std::vector<double>& sensitivities,
    bool use_calibrated,
    SessionAuditLog& audit_log, const AbortContext& ctx) {

    SharedNoisyHistogram out;
    out.rho = rho;
    double max_sigma = 0.0;
    if (use_calibrated) {
        if (sensitivities.size() != 3)
            throw std::invalid_argument("addJointNoiseImpl: expected 3 sensitivities");
        for (double s : sensitivities)
            max_sigma = std::max(max_sigma, sigmaFromRho(rho, s));
    } else {
        max_sigma = sigmaFromRho(rho);
    }
    out.sigma_target = max_sigma;

    const uint32_t num_bins = 3;
    NoiseCommit c1, c2;
    if (use_calibrated) {
        // Per-bin sigma using per-bin sensitivity, split across parties by √2.
        c1.party_id = 0; c2.party_id = 1;
        c1.eta.reserve(num_bins); c2.eta.reserve(num_bins);
        for (uint32_t i = 0; i < num_bins; ++i) {
            double sigma_pp = sigmaFromRho(rho, sensitivities[i]) / std::sqrt(2.0);
            c1.eta.push_back(sampleGaussianCsprng(sigma_pp));
            c2.eta.push_back(sampleGaussianCsprng(sigma_pp));
        }
        secureRandBytes(&c1.salt, 16);
        secureRandBytes(&c2.salt, 16);
        c1.commit = computeCommitProd(0, c1.salt, c1.eta);
        c2.commit = computeCommitProd(1, c2.salt, c2.eta);
    } else {
        double sigma_pp = max_sigma / std::sqrt(2.0);
        c1 = sampleAndCommitProd(0, num_bins, sigma_pp);
        c2 = sampleAndCommitProd(1, num_bins, sigma_pp);
    }

    // ─── Phase B: commit-exchange ────────────────────────────────────────
    // Snapshot both commits BEFORE any (η, salt) is exchanged, matching
    // the two-phase pattern of openWithMacCheckShared (see PROTOCOL.md
    // Alg 17 rounds 7–9). A wire-level impl replicates this ordering by
    // physically not sending (η, salt) until both `commit` values are on
    // the wire; the semantic reference enforces it by copying `commit`
    // into an immutable snapshot here.
    const oc::block commit_of_1 = c1.commit;
    const oc::block commit_of_2 = c2.commit;

    // ─── Phase C: reveal + verify peer's commit ──────────────────────────
    // On reveal, each side receives peer's (η, salt) and recomputes the
    // commit hash to compare against the earlier snapshot. sodium_memcmp
    // gives CT byte comparison (defence-in-depth against timing signals).
    auto verify_or_log = [&](const NoiseCommit& c, const oc::block& snapshot) {
        auto expected = computeCommitProd(c.party_id, c.salt, c.eta);
        if (sodium_memcmp(&expected, &snapshot, 16) != 0) {
            audit_log.append(AbortReason::DP_COMMIT_MISMATCH, ctx);
            return false;
        }
        return true;
    };
    if (!verify_or_log(c1, commit_of_1) || !verify_or_log(c2, commit_of_2)) {
        // CRITICAL: DP failure must NOT return un-noised data. Attacker
        // triggering commit mismatch would otherwise obtain raw plaintext.
        // Throw + rely on caller's transaction rollback / abort protocol.
        // Audit log entry was already written by verify_or_log for
        // tamper-evident record.
        throw std::runtime_error(
            "MpsvsDpProd: DP commit mismatch — release aborted "
            "(see SessionAuditLog for details)");
    }

    auto joint = jointNoise({c1, c2});
    out.joint_noise = joint;

    auto add_signed = [&](SharedU64 s, int64_t noise) {
        s.shares[0] += static_cast<uint64_t>(noise);
        return s;
    };
    out.bins_shared.push_back(add_signed(cell.sum_num, joint[0]));
    out.bins_shared.push_back(add_signed(cell.sum_den, joint[1]));
    out.bins_shared.push_back(add_signed(cell.n_valid, joint[2]));
    return out;
}

DpProdResult addJointNoiseProd(const SharedSectorHistogram& cell,
                                 double rho,
                                 SessionAuditLog& audit_log,
                                 const AbortContext& ctx) {
    DpProdResult r;
    size_t log_before = audit_log.size();
    r.noisy = addJointNoiseImpl(cell, rho, {}, /*use_calibrated=*/false,
                                  audit_log, ctx);
    r.committed_ok = (audit_log.size() == log_before);   // no new abort entries
    return r;
}

DpProdResult addJointNoiseCalibratedProd(
    const SharedSectorHistogram& cell,
    double rho,
    const std::vector<double>& sensitivities,
    SessionAuditLog& audit_log,
    const AbortContext& ctx) {
    DpProdResult r;
    size_t log_before = audit_log.size();
    r.noisy = addJointNoiseImpl(cell, rho, sensitivities,
                                  /*use_calibrated=*/true, audit_log, ctx);
    r.committed_ok = (audit_log.size() == log_before);
    return r;
}

// ---------------------------------------------------------------------------
// Hardened cover firms with CSPRNG.
// ---------------------------------------------------------------------------
SharedSectorHistogram addCoverFirmsProd(const SharedSectorHistogram& cell,
                                          const CoverConfig& cc) {
    if (cc.K_max < cc.K_min)
        throw std::invalid_argument("addCoverFirmsProd: K_max < K_min");
    uint64_t half_range = (static_cast<uint64_t>(cc.K_max) - cc.K_min) / 2;
    uint64_t k1 = (half_range == 0) ? 0 : secureRandU64Bounded(half_range + 1);
    uint64_t k2 = (half_range == 0) ? 0 : secureRandU64Bounded(half_range + 1);
    SharedSectorHistogram out = cell;
    out.n_valid.shares[0] += static_cast<uint64_t>(cc.K_min) + k1;
    out.n_valid.shares[1] += k2;
    return out;
}

// ---------------------------------------------------------------------------
// Entropy report
// ---------------------------------------------------------------------------

NoiseEntropyReport reportNoiseEntropy(double sigma, int n_samples) {
    std::vector<int64_t> samples;
    samples.reserve(n_samples);
    std::set<int64_t> unique;
    double sum = 0.0;
    for (int i = 0; i < n_samples; ++i) {
        int64_t x = sampleGaussianCsprng(sigma);
        samples.push_back(x);
        unique.insert(x);
        sum += x;
    }
    double mean = sum / n_samples;
    double var = 0.0;
    for (int64_t x : samples) var += (x - mean) * (x - mean);
    var /= n_samples;

    NoiseEntropyReport r;
    r.empirical_mean = mean;
    r.empirical_variance = var;
    r.target_variance = sigma * sigma;
    r.unique_values = static_cast<int>(unique.size());
    double rel_err = std::abs(var - sigma * sigma) / (sigma * sigma);
    r.passes_variance_check = rel_err < 0.20;
    return r;
}

} // namespace mpsvs
} // namespace volePSI
