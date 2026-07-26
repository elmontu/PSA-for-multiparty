// Regression test for the A1 fix (docs/PRIVACY_AUDIT_R37 shuffle finding):
// the Service Provider must NOT be able to reconstruct the cascade
// permutation.
//
// Root cause that was fixed: MpShuffleDriver derived each round's OSN routing
// seed as deriveRoundSeed(spKey_k, sessionId, k). Because the SP holds every
// spKey_k, it recomputed every dest_k and de-shuffled the output. The fix makes
// the round's permutation holder (sender k) pick a FRESH LOCAL random seed that
// is never sent to the SP, and apply that same permutation to its own R share
// locally via the new OSNSender::permuteBlocks — eliminating the R-side OSN call
// that forced the SP to hold dest_k.
//
// This test exercises the load-bearing new primitive (permuteBlocks) entirely
// offline. The end-to-end direction-match between permuteBlocks and run_osn is
// covered by tests/run_mpsa_smoke.sh (the reconstructed join must equal the
// plaintext join). See that script for the network-level check.

#include "volePSI/osn/OSNSender.h"
#include "cryptoTools/Common/block.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <vector>

namespace {

// Fill v with the distinct "labels" 0..C-1 so we can track where each element
// lands under the permutation.
std::vector<oc::block> labelBlocks(size_t C) {
    std::vector<oc::block> v(C);
    for (size_t i = 0; i < C; ++i) {
        uint64_t lo = static_cast<uint64_t>(i), hi = 0;
        std::memcpy(reinterpret_cast<uint8_t*>(&v[i]),     &lo, 8);
        std::memcpy(reinterpret_cast<uint8_t*>(&v[i]) + 8, &hi, 8);
    }
    return v;
}

uint64_t low64(const oc::block& b) {
    uint64_t lo;
    std::memcpy(&lo, reinterpret_cast<const uint8_t*>(&b), 8);
    return lo;
}

oc::block seedFromBytes(uint8_t fill) {
    oc::block s;
    std::memset(&s, fill, sizeof(s));
    return s;
}

// Apply permuteBlocks under a given seed and return the resulting label order.
std::vector<uint64_t> permOrder(size_t C, oc::block seed) {
    OSNSender s;
    std::map<int, int> i2loc;
    s.init_wj_seeded(C, 1, "", i2loc, seed);
    auto v = labelBlocks(C);
    s.permuteBlocks(v);
    std::vector<uint64_t> order(C);
    for (size_t i = 0; i < C; ++i) order[i] = low64(v[i]);
    return order;
}

bool isPermutationOf0toN(const std::vector<uint64_t>& order) {
    std::vector<uint64_t> sorted = order;
    std::sort(sorted.begin(), sorted.end());
    for (size_t i = 0; i < sorted.size(); ++i)
        if (sorted[i] != i) return false;
    return true;
}

} // namespace

int main() {
    const size_t C = 16;
    int failures = 0;

    // Check 1: permuteBlocks is a genuine bijection (a permutation of its
    // input). If the local R-side permutation were not a true permutation,
    // the cascade would corrupt payloads.
    {
        auto order = permOrder(C, seedFromBytes(0xA5));
        bool ok = isPermutationOf0toN(order);
        std::cout << "[1] permuteBlocks is a bijection: " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // Check 2: determinism given a fixed seed. The permutation is a function of
    // the local seed ALONE — so nothing an SP holds (spKey, sessionId) can
    // determine it. Same seed twice => identical order.
    {
        auto a = permOrder(C, seedFromBytes(0x3C));
        auto b = permOrder(C, seedFromBytes(0x3C));
        bool ok = (a == b);
        std::cout << "[2] deterministic in the local seed: " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // Check 3 (the A1 property): different seeds => different permutations.
    // Because the round seed is now fresh local randomness rather than a KDF of
    // an SP-held key, the SP cannot predict or recompute dest_k. We assert seed
    // sensitivity across several seeds as a proxy: the permutation genuinely
    // varies with the secret the SP does not have.
    {
        auto base = permOrder(C, seedFromBytes(0x11));
        int distinct = 0;
        for (uint8_t f : {0x22, 0x44, 0x77, 0x99, 0xEE}) {
            if (permOrder(C, seedFromBytes(f)) != base) ++distinct;
        }
        bool ok = (distinct == 5);
        std::cout << "[3] permutation varies with the secret seed ("
                  << distinct << "/5 distinct): " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    // Check 4: a range of sizes stays a bijection (Benes network handles
    // non-power-of-two and odd sizes).
    {
        bool ok = true;
        for (size_t n : {2u, 3u, 5u, 8u, 13u, 32u}) {
            if (!isPermutationOf0toN(permOrder(n, seedFromBytes(0x5A)))) { ok = false; break; }
        }
        std::cout << "[4] bijection across sizes {2,3,5,8,13,32}: " << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    if (failures == 0) {
        std::cout << "PASS: permuteBlocks is a sound, seed-private permutation.\n";
        std::cout << "NOTE: end-to-end reconstruction (permuteBlocks direction "
                     "matches run_osn) is validated by tests/run_mpsa_smoke.sh.\n";
        return 0;
    }
    std::cerr << "FAIL: " << failures << " check(s) failed.\n";
    return 1;
}
