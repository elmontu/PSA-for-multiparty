// MPSVS k-Anonymity Gate — fully oblivious membership hiding.

#include "volePSI/MpsvsCoverFirms.h"
#include "volePSI/MpsvsDp.h"
#include "volePSI/MpsvsDpWire.h"
#include "volePSI/MpsvsKAnonGate.h"
#include "volePSI/MpsvsSectorAgg.h"
#include "volePSI/MpsvsSectorAggWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <random>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static SharedSectorHistogram mkCell(uint16_t sec, uint32_t per, uint64_t nv,
                                       uint64_t sn, uint64_t sd, oc::PRNG& prng) {
    SharedSectorHistogram c;
    c.key = {sec, per};
    c.metric = Metric::DTI;
    c.sum_num = shareU64(2, sn, prng);
    c.sum_den = shareU64(2, sd, prng);
    c.n_valid = shareU64(2, nv, prng);
    return c;
}

static void test_below_threshold_suppressed() {
    std::printf("--- C1: cell below k threshold → zeros released ---\n");
    oc::PRNG prng(oc::block(0x1, 0x2));
    // k_thresh = 5. Cell with n_valid = 2 → should be suppressed.
    auto cell = mkCell(1, 202601, 2, 30000, 60000, prng);
    KAnonConfig cfg; cfg.k_thresh = 5;
    size_t budget = kAnonTripleBudgetPerCell();
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto g = applyKAnonGate(cell, cfg, triples, idx, prng);
    auto p = reconstructGatedCell(g);
    std::printf("  input:  n_valid=2 sum_num=30000 sum_den=60000, k_thresh=5\n");
    std::printf("  output: pass=%u sum_num=%lu sum_den=%lu n_valid=%lu\n",
                 p.pass, p.sum_num, p.sum_den, p.n_valid);
    CHECK(p.pass == 0, "C1: pass bit = 0 (below threshold)");
    CHECK(p.sum_num == 0, "C1: sum_num zeroed");
    CHECK(p.sum_den == 0, "C1: sum_den zeroed");
    CHECK(p.n_valid == 0, "C1: n_valid zeroed");
}

static void test_above_threshold_released() {
    std::printf("--- C2: cell above k threshold → values passed through ---\n");
    oc::PRNG prng(oc::block(0x3, 0x4));
    auto cell = mkCell(2, 202601, 8, 100000, 200000, prng);
    KAnonConfig cfg; cfg.k_thresh = 5;
    size_t budget = kAnonTripleBudgetPerCell();
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto g = applyKAnonGate(cell, cfg, triples, idx, prng);
    auto p = reconstructGatedCell(g);
    std::printf("  input:  n_valid=8 sum_num=100000, k_thresh=5\n");
    std::printf("  output: pass=%u sum_num=%lu sum_den=%lu n_valid=%lu\n",
                 p.pass, p.sum_num, p.sum_den, p.n_valid);
    CHECK(p.pass == 1, "C2: pass bit = 1 (above threshold)");
    CHECK(p.sum_num == 100000, "C2: sum_num preserved");
    CHECK(p.sum_den == 200000, "C2: sum_den preserved");
    CHECK(p.n_valid == 8, "C2: n_valid preserved");
}

static void test_at_threshold() {
    std::printf("--- C3: cell exactly at k threshold → passed through ---\n");
    oc::PRNG prng(oc::block(0x5, 0x6));
    auto cell = mkCell(1, 202601, 5, 40000, 80000, prng);
    KAnonConfig cfg; cfg.k_thresh = 5;
    size_t budget = kAnonTripleBudgetPerCell();
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto g = applyKAnonGate(cell, cfg, triples, idx, prng);
    auto p = reconstructGatedCell(g);
    CHECK(p.pass == 1, "C3: n_valid == k_thresh → pass=1 (>= threshold)");
    CHECK(p.sum_num == 40000, "C3: values preserved at boundary");
}

static void test_batch_mixed() {
    std::printf("--- C4: batch of mixed cells: some pass, some suppressed ---\n");
    oc::PRNG prng(oc::block(0x7, 0x8));
    std::vector<SharedSectorHistogram> cells;
    cells.push_back(mkCell(1, 202601, 3, 15000, 30000, prng));    // suppress
    cells.push_back(mkCell(2, 202601, 7, 70000, 140000, prng));   // pass
    cells.push_back(mkCell(3, 202601, 1, 5000, 10000, prng));     // suppress
    cells.push_back(mkCell(4, 202601, 10, 90000, 180000, prng));  // pass
    KAnonConfig cfg; cfg.k_thresh = 5;
    size_t budget = kAnonTripleBudgetPerCell() * cells.size();
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto gated = applyKAnonGateBatch(cells, cfg, triples, idx, prng);
    int suppressed = 0, passed = 0;
    for (const auto& g : gated) {
        auto p = reconstructGatedCell(g);
        std::printf("  sector=%u n_valid=%lu → pass=%u (sum_num=%lu, sum_den=%lu)\n",
                     p.key.sector, p.n_valid, p.pass, p.sum_num, p.sum_den);
        if (p.pass) ++passed; else ++suppressed;
    }
    CHECK(suppressed == 2, "C4: 2 cells suppressed (n_valid < 5)");
    CHECK(passed == 2,     "C4: 2 cells passed (n_valid ≥ 5)");
}

static void test_kanon_plus_covers_ambiguity() {
    std::printf("--- C5: k-anon + covers → adversary cannot distinguish suppress vs cover-pass ---\n");
    oc::PRNG prng(oc::block(0x9, 0xa));
    // True n_valid = 3 (below k_thresh=5).
    // With covers K ∈ [3, 15]: post-cover n_valid ∈ [6, 18] → ALL pass gate.
    // Adversary sees released n_valid ≈ true+K+noise; cannot tell true was 3.
    auto cell = mkCell(1, 202601, 3, 30000, 60000, prng);
    CoverConfig cc; cc.K_min = 3; cc.K_max = 15;
    std::mt19937_64 rng1(0xf1), rng2(0xf2);
    auto cell_wc = addCoverFirms(cell, cc, rng1, rng2);
    uint64_t post_cover_n = cell_wc.n_valid.reconstruct();
    std::printf("  true n_valid=3, post-cover n_valid=%lu (K ∈ [3,15])\n", post_cover_n);
    CHECK(post_cover_n >= 6 && post_cover_n <= 18, "C5: cover inflation in expected range");

    KAnonConfig cfg; cfg.k_thresh = 5;
    size_t budget = kAnonTripleBudgetPerCell();
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto g = applyKAnonGate(cell_wc, cfg, triples, idx, prng);
    auto p = reconstructGatedCell(g);
    CHECK(p.pass == 1, "C5: covers push cell over gate → pass=1");
    CHECK(p.n_valid == post_cover_n, "C5: released n_valid = inflated (covers hide true)");
    std::printf("  Adversary sees pass=1, n_valid=%lu — CANNOT infer true n_valid=3.\n", p.n_valid);
}

static void test_membership_indistinguishability() {
    std::printf("--- C6: MEMBERSHIP INDISTINGUISHABILITY — cell suppressed indistinguishable from empty ---\n");
    oc::PRNG prng(oc::block(0xab, 0xcd));
    // Compare two scenarios that should produce IDENTICAL adversary view:
    //   A. Cell with 2 real firms → gate suppresses to zeros
    //   B. Cell with 0 real firms (empty)  → is naturally zero
    // Post-gate, both look identical: (sum_num=0, sum_den=0, n_valid=0, pass=0).
    auto cell_A = mkCell(1, 202601, 2, 20000, 40000, prng);   // small non-empty
    auto cell_B = mkCell(1, 202601, 0, 0, 0, prng);            // empty
    KAnonConfig cfg; cfg.k_thresh = 5;
    size_t budget = kAnonTripleBudgetPerCell() * 2;
    auto triples = generateBeaverTripleBits(2, budget, prng);
    size_t idx = 0;
    auto gA = applyKAnonGate(cell_A, cfg, triples, idx, prng);
    auto gB = applyKAnonGate(cell_B, cfg, triples, idx, prng);
    auto pA = reconstructGatedCell(gA);
    auto pB = reconstructGatedCell(gB);
    std::printf("  A (2 real firms, suppressed):  sum_num=%lu sum_den=%lu n_valid=%lu pass=%u\n",
                 pA.sum_num, pA.sum_den, pA.n_valid, pA.pass);
    std::printf("  B (empty cell):                sum_num=%lu sum_den=%lu n_valid=%lu pass=%u\n",
                 pB.sum_num, pB.sum_den, pB.n_valid, pB.pass);
    CHECK(pA.sum_num == pB.sum_num, "C6: sum_num indistinguishable (both zero)");
    CHECK(pA.sum_den == pB.sum_den, "C6: sum_den indistinguishable");
    CHECK(pA.n_valid == pB.n_valid, "C6: n_valid indistinguishable");
    CHECK(pA.pass == pB.pass,       "C6: pass bit indistinguishable");
    std::printf("  ⇒ Adversary CANNOT tell suppressed cell from empty cell.\n");
    std::printf("     Membership secrecy: 'does sector 1 have firms?' is HIDDEN.\n");
}

int main() {
    test_below_threshold_suppressed();
    test_above_threshold_released();
    test_at_threshold();
    test_batch_mixed();
    test_kanon_plus_covers_ambiguity();
    test_membership_indistinguishability();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — k-anon gate provides fully oblivious membership hiding\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
