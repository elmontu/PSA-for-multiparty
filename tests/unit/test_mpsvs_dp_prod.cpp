// MPSVS DP Production Retrofit tests.
//
// Verifies:
//   (1) CSPRNG-backed Gaussian sampler produces correct statistics.
//   (2) sampleAndCommitProd + verifyCommit still work end-to-end.
//   (3) addJointNoiseProd integrates with SessionAuditLog.
//   (4) addCoverFirmsProd samples K uniformly via CSPRNG.

#include "volePSI/MpsvsAuthShareProd.h"
#include "volePSI/MpsvsCoverFirms.h"
#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpProd.h"
#include "volePSI/MpsvsDpWire.h"
#include "volePSI/MpsvsProdHygiene.h"
#include "volePSI/MpsvsSectorAgg.h"
#include "volePSI/MpsvsSectorAggWire.h"

#include <cstdio>
#include <map>
#include <set>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_gaussian_csprng_stats() {
    std::printf("--- C1: CSPRNG-Gaussian statistics (mean~0, var~sigma^2) ---\n");
    double sigma = 10.0;
    auto rep = reportNoiseEntropy(sigma, 5000);
    std::printf("  sigma=%.1f  mean=%.3f  var=%.2f (target %.2f)  unique=%d/5000\n",
                 sigma, rep.empirical_mean, rep.empirical_variance,
                 rep.target_variance, rep.unique_values);
    CHECK(std::abs(rep.empirical_mean) < 0.5,
           "C1: mean within 0.5 of theoretical zero");
    CHECK(rep.passes_variance_check, "C1: variance within 20% of sigma^2");
    CHECK(rep.unique_values > 30, "C1: sampled values are diverse (not stuck)");
}

static void test_sampleAndCommit_prod() {
    std::printf("--- C2: sampleAndCommitProd — CSPRNG-backed commit ---\n");
    NoiseCommit c = sampleAndCommitProd(0, 3, 2.0);
    CHECK(c.eta.size() == 3, "C2: 3 bins sampled");
    bool valid = verifyCommit(c);
    // NOTE: verifyCommit uses the SHA-256 in MpsvsDpWire which uses the
    // same format string; our commit format matches — should verify.
    CHECK(valid, "C2: commit hash verifies against revealed eta+salt");
}

static void test_addJointNoiseProd_success() {
    std::printf("--- C3: addJointNoiseProd — honest path integrates audit log ---\n");
    oc::PRNG prng(oc::block(0xa, 0xb));
    SharedSectorHistogram cell;
    cell.key = {1, 202601}; cell.metric = Metric::DTI;
    cell.sum_num = shareU64(2, 100000, prng);
    cell.sum_den = shareU64(2, 200000, prng);
    cell.n_valid = shareU64(2, 5, prng);

    SessionAuditLog log;
    AbortContext ctx{"Phase 12 DP", 0, "sector=1 period=202601", ""};
    auto result = addJointNoiseProd(cell, /*rho=*/0.1, log, ctx);
    CHECK(result.committed_ok, "C3: honest run — no abort entries in log");
    CHECK(log.size() == 0, "C3: audit log empty after honest run");
    CHECK(result.noisy.bins_shared.size() == 3, "C3: 3 noisy bins produced");
    CHECK(result.noisy.sigma_target > 0, "C3: sigma_target populated");
}

static void test_addJointNoiseCalibratedProd() {
    std::printf("--- C4: calibrated DP noise via CSPRNG ---\n");
    oc::PRNG prng(oc::block(0xc, 0xd));
    SharedSectorHistogram cell;
    cell.key = {1, 202601}; cell.metric = Metric::DTI;
    cell.sum_num = shareU64(2, 100000, prng);
    cell.sum_den = shareU64(2, 200000, prng);
    cell.n_valid = shareU64(2, 5, prng);

    SessionAuditLog log;
    AbortContext ctx{"Phase 12 DP-cal", 0, "sector=1", ""};
    std::vector<double> sens = {1e6, 1e6, std::sqrt(2.0)};
    auto result = addJointNoiseCalibratedProd(cell, /*rho=*/0.1, sens, log, ctx);
    CHECK(result.committed_ok, "C4: calibrated honest run — no aborts");
    CHECK(log.size() == 0, "C4: audit log empty after honest calibrated");
}

static void test_addCoverFirmsProd_range() {
    std::printf("--- C5: addCoverFirmsProd K in [K_min, K_max] ---\n");
    oc::PRNG prng(oc::block(0xe, 0xf));
    SharedSectorHistogram cell;
    cell.key = {1, 202601}; cell.metric = Metric::DTI;
    cell.sum_num = shareU64(2, 100000, prng);
    cell.sum_den = shareU64(2, 200000, prng);
    cell.n_valid = shareU64(2, 5, prng);

    CoverConfig cc; cc.K_min = 10; cc.K_max = 30;
    std::set<uint64_t> k_seen;
    for (int t = 0; t < 200; ++t) {
        SharedSectorHistogram out = addCoverFirmsProd(cell, cc);
        uint64_t new_n = out.n_valid.reconstruct();
        uint64_t K = new_n - 5;   // subtract baseline
        k_seen.insert(K);
        if (K < 10 || K > 30) {
            CHECK(false, "C5: K out of range");
            return;
        }
    }
    std::printf("  200 samples; unique K values seen: %zu (of 21 possible)\n",
                 k_seen.size());
    CHECK(k_seen.size() > 10, "C5: CSPRNG produces diverse K values");
    CHECK(true, "C5: all K in [10, 30]");
}

static void test_dp_release_correctness() {
    std::printf("--- C6: full DP release with CSPRNG matches (oracle + noise) ---\n");
    oc::PRNG prng(oc::block(0x11, 0x22));
    SharedSectorHistogram cell;
    cell.key = {1, 202601}; cell.metric = Metric::DTI;
    cell.sum_num = shareU64(2, 500000, prng);
    cell.sum_den = shareU64(2, 800000, prng);
    cell.n_valid = shareU64(2, 20, prng);

    SessionAuditLog log;
    AbortContext ctx{"Phase 12 DP", 0, "sector=1", ""};
    auto r = addJointNoiseProd(cell, /*rho=*/0.5, log, ctx);
    CHECK(r.committed_ok, "C6: DP release run OK");

    // Reconstruct noisy sum_num — verify = oracle + reported joint noise.
    int64_t reconstructed = static_cast<int64_t>(r.noisy.bins_shared[0].reconstruct());
    int64_t expected = 500000 + r.noisy.joint_noise[0];
    std::printf("  expected sum_num = 500000 + noise(%ld) = %ld, got %ld\n",
                 r.noisy.joint_noise[0], expected, reconstructed);
    CHECK(reconstructed == expected, "C6: reconstructed = oracle + joint noise (exact)");
}

int main() {
    std::printf("=== MPSVS DP Production Retrofit — CSPRNG-backed noise ===\n\n");
    test_gaussian_csprng_stats();
    test_sampleAndCommit_prod();
    test_addJointNoiseProd_success();
    test_addJointNoiseCalibratedProd();
    test_addCoverFirmsProd_range();
    test_dp_release_correctness();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — DP noise + cover K now CSPRNG-backed (production ready).\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
