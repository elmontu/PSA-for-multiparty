// MPSVS Phase 6 MPC-wire — bucketIndex on shares via secureLessThan.

#include "volePSI/MpsvsRatioBucket.h"
#include "volePSI/MpsvsRatioBucketWire.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <cstdio>
#include <vector>

using namespace volePSI::mpsvs;
using namespace volePSI::mpstar;

static int g_fail = 0;
#define CHECK(cond, msg) do {                                            \
    if (cond) { std::printf("ok:   %s\n", msg); }                        \
    else       { std::printf("FAIL: %s\n", msg); ++g_fail; }             \
} while (0)

static void test_bucket_wire_matches_plain() {
    std::printf("--- C1: wire bucketIndex reconstructs to plaintext bucket ---\n");
    oc::PRNG prng(oc::block(0x88, 0x99));
    const uint32_t N = 2;

    // Very small B for tractable triple count.
    auto edges = makeLinearEdges(0, 1000, 8);   // B=8

    struct Case { uint64_t num; uint64_t den; uint32_t expect; };
    std::vector<Case> cases = {
        {250,  1, 2},   // ratio 250 → bucket 2 (edges: 0,125,250,375,...)
        {500,  1, 4},
        {50,   1, 0},   // below all → bucket 0
        {900,  1, 7},   // last bucket
    };

    for (const auto& c : cases) {
        SharedU64Bin sn = shareU64Bin(N, c.num, prng);
        SharedU64Bin sd = shareU64Bin(N, c.den, prng);
        SharedBit    si = shareBit(N, 1, prng);
        size_t budget = bucketWireTripleBudget(8);
        auto triples = generateBeaverTripleBits(N, budget, prng);
        size_t idx = 0;
        auto r = bucketIndexWire(sn, sd, edges, si, /*ratio_scale=*/1,
                                   triples, idx);
        uint32_t got = reconstructBucket(r);
        std::printf("  num=%lu den=%lu → wire bucket=%u  (want %u, triples %zu/%zu)\n",
                     c.num, c.den, got, c.expect, idx, budget);
        CHECK(got == c.expect, "C1: wire bucket matches plaintext");
    }
}

static void test_bucket_wire_incl_zero() {
    std::printf("--- C2: incl=0 → all-zero one-hot (no bucket selected) ---\n");
    oc::PRNG prng(oc::block(0xaa, 0xbb));
    const uint32_t N = 2;
    auto edges = makeLinearEdges(0, 1000, 8);

    SharedU64Bin sn = shareU64Bin(N, 500, prng);
    SharedU64Bin sd = shareU64Bin(N, 1, prng);
    SharedBit    si = shareBit(N, 0, prng);   // excluded
    size_t budget = bucketWireTripleBudget(8);
    auto triples = generateBeaverTripleBits(N, budget, prng);
    size_t idx = 0;
    auto r = bucketIndexWire(sn, sd, edges, si, /*ratio_scale=*/1,
                               triples, idx);
    bool any = false;
    for (auto& b : r.one_hot) if (b.reconstruct()) any = true;
    CHECK(!any, "C2: incl=0 → no bucket bit set");
}

int main() {
    test_bucket_wire_matches_plain();
    test_bucket_wire_incl_zero();

    std::printf("\n");
    if (g_fail == 0) {
        std::printf("ALL PASSED — Phase 6 MPC-wire (bucketIndex) acceptance met\n");
        return 0;
    }
    std::printf("FAILED — %d assertion(s)\n", g_fail);
    return 1;
}
