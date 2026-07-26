// MPSVS Phase 9 acceptance tests — TwoScore composite vuln score.

#include "volePSI/MpsvsComposite.h"

#include <cmath>
#include <cstdio>

using namespace volePSI::mpsvs;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static EntityRankRow mkR(uint32_t eid, uint32_t popkey, uint8_t incl,
                          double score) {
    EntityRankRow r;
    r.entity_idx = eid;
    r.popkey = popkey;
    r.incl = incl;
    r.bucket = 0;
    r.rank = 0;
    long double scale = static_cast<long double>(1ULL << kFpFractionalBits);
    r.score_fp = static_cast<Fp>(score * scale);
    return r;
}

static void test_strict_all_present() {
    std::printf("--- C1: STRICT → include when all 4 core metrics present ---\n");
    std::array<std::vector<EntityRankRow>, kMetricCount> mr{};
    mr[static_cast<size_t>(Metric::DTI)]  = {mkR(0, 1, 1, 0.2)};
    mr[static_cast<size_t>(Metric::DSI)]  = {mkR(0, 1, 1, 0.4)};
    mr[static_cast<size_t>(Metric::Delq)] = {mkR(0, 1, 1, 0.6)};
    mr[static_cast<size_t>(Metric::NPL)]  = {mkR(0, 1, 1, 0.8)};
    auto out = computeCompositeTwoScore(mr);
    CHECK(out.size() == 1, "C1: 1 composite row");
    CHECK(out[0].incl_strict == 1, "C1: incl_strict = 1");
    double got = fpToDouble(out[0].vuln_strict_fp);
    double want = 0.25 * (0.2 + 0.4 + 0.6 + 0.8);   // = 0.5
    std::printf("  got=%.4f want=%.4f\n", got, want);
    CHECK(std::abs(got - want) < 1e-6, "C1: composite = Σ w·s");
    CHECK(out[0].avail_core == 4, "C1: avail_core = 4");
}

static void test_strict_missing_excludes() {
    std::printf("--- C2: STRICT → exclude when any core missing ---\n");
    std::array<std::vector<EntityRankRow>, kMetricCount> mr{};
    mr[static_cast<size_t>(Metric::DTI)]  = {mkR(0, 1, 1, 0.5)};
    mr[static_cast<size_t>(Metric::DSI)]  = {mkR(0, 1, 0, 0.5)};   // excluded
    mr[static_cast<size_t>(Metric::Delq)] = {mkR(0, 1, 1, 0.5)};
    mr[static_cast<size_t>(Metric::NPL)]  = {mkR(0, 1, 1, 0.5)};
    auto out = computeCompositeTwoScore(mr);
    CHECK(out[0].incl_strict == 0, "C2: DSI missing → incl_strict = 0");
    CHECK(out[0].avail_core == 3, "C2: avail_core = 3");
}

static void test_renormalised_partial() {
    std::printf("--- C3: RENORMALISED → emit + renormalise on partial core ---\n");
    std::array<std::vector<EntityRankRow>, kMetricCount> mr{};
    mr[static_cast<size_t>(Metric::DTI)]  = {mkR(0, 1, 1, 0.4)};
    mr[static_cast<size_t>(Metric::DSI)]  = {mkR(0, 1, 0, 0.5)};    // excluded
    mr[static_cast<size_t>(Metric::Delq)] = {mkR(0, 1, 0, 0.5)};    // excluded
    mr[static_cast<size_t>(Metric::NPL)]  = {mkR(0, 1, 1, 0.8)};
    auto out = computeCompositeTwoScore(mr);
    CHECK(out[0].incl_renorm == 1, "C3: renorm emitted with 2/4 core");
    double got = fpToDouble(out[0].vuln_renorm_fp);
    // Available: DTI (w=0.25, s=0.4), NPL (w=0.25, s=0.8).
    //   num  = 0.25*0.4 + 0.25*0.8 = 0.3
    //   denom_orig = 0.5
    //   vuln_renorm = 0.3 / 0.5 = 0.6
    double want = 0.6;
    std::printf("  got=%.4f want=%.4f\n", got, want);
    CHECK(std::abs(got - want) < 1e-4, "C3: renorm = 0.6");
}

static void test_none_available() {
    std::printf("--- C4: no core available → both incl = 0 ---\n");
    std::array<std::vector<EntityRankRow>, kMetricCount> mr{};
    mr[static_cast<size_t>(Metric::DTI)]  = {mkR(0, 1, 0, 0.5)};
    mr[static_cast<size_t>(Metric::DSI)]  = {mkR(0, 1, 0, 0.5)};
    mr[static_cast<size_t>(Metric::Delq)] = {mkR(0, 1, 0, 0.5)};
    mr[static_cast<size_t>(Metric::NPL)]  = {mkR(0, 1, 0, 0.5)};
    auto out = computeCompositeTwoScore(mr);
    CHECK(out[0].incl_strict == 0, "C4: incl_strict = 0");
    CHECK(out[0].incl_renorm == 0, "C4: incl_renorm = 0");
    CHECK(out[0].avail_core == 0, "C4: avail_core = 0");
}

static void test_multi_entity() {
    std::printf("--- C5: multi-entity — each computed independently ---\n");
    std::array<std::vector<EntityRankRow>, kMetricCount> mr{};
    // Entity 0: all present, vuln = 0.5.
    // Entity 1: DTI+DSI only, vuln_strict=excluded, vuln_renorm=(0.25*0.3+0.25*0.7)/0.5=0.5
    mr[static_cast<size_t>(Metric::DTI)]  = {mkR(0, 1, 1, 0.5), mkR(1, 1, 1, 0.3)};
    mr[static_cast<size_t>(Metric::DSI)]  = {mkR(0, 1, 1, 0.5), mkR(1, 1, 1, 0.7)};
    mr[static_cast<size_t>(Metric::Delq)] = {mkR(0, 1, 1, 0.5), mkR(1, 1, 0, 0.0)};
    mr[static_cast<size_t>(Metric::NPL)]  = {mkR(0, 1, 1, 0.5), mkR(1, 1, 0, 0.0)};
    auto out = computeCompositeTwoScore(mr);
    CHECK(out.size() == 2, "C5: 2 entities out");
    for (const auto& c : out) {
        if (c.entity_idx == 0) {
            CHECK(c.incl_strict == 1 &&
                  std::abs(fpToDouble(c.vuln_strict_fp) - 0.5) < 1e-6,
                  "C5: entity 0 strict = 0.5");
        } else {
            CHECK(c.incl_strict == 0, "C5: entity 1 strict excluded (only 2 core avail)");
            double got = fpToDouble(c.vuln_renorm_fp);
            std::printf("  entity 1 renorm = %.4f\n", got);
            CHECK(std::abs(got - 0.5) < 1e-4, "C5: entity 1 renorm = 0.5");
        }
    }
}

int main() {
    test_strict_all_present();
    test_strict_missing_excludes();
    test_renormalised_partial();
    test_none_available();
    test_multi_entity();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 9 acceptance criteria met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
