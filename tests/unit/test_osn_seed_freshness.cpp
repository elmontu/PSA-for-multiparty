// Regression test for the C4 fix (docs/PRIVACY_AUDIT_R37):
// OSN internals must not use hardcoded PRNG seeds. Before the fix, every
// call to OSNSender::init_wj(...) at the same size produced the SAME
// permutation (Fisher-Yates seeded by _mm_set_epi32(4253233465,334565,0,235))
// -- so any adversary with source access knew every dest[] a priori.
//
// This is the OFFLINE component of the C4 check: we exercise init_wj (which
// no longer takes a seed argument -- it seeds itself from sysRandomSeed())
// and assert the permutations differ across independent calls.
//
// The WIRE-side component of C4 (OSN receiver masks + OT base messages no
// longer deterministic) is exercised by tests/unit/test_osn_semantics.cpp
// running the real OSN protocol over an in-process socket pair.

#include "volePSI/osn/OSNSender.h"

#include <iostream>
#include <map>
#include <vector>

int main() {
    const size_t C = 32;
    int failures = 0;

    // Check 1: init_wj at the same size produces DIFFERENT dest[] across
    // independent OSNSender instances. This is the pre-vs-post C4 signal:
    // pre-fix these were identical (constant seed), post-fix they differ
    // with overwhelming probability.
    {
        OSNSender a, b;
        std::map<int, int> mapA, mapB;
        a.init_wj(C, 1, "", mapA);
        b.init_wj(C, 1, "", mapB);

        // dest is public on the OSNSender object after init_wj.
        std::vector<int> destA = a.dest;
        std::vector<int> destB = b.dest;
        bool differ = (destA != destB);
        std::cout << "[1] init_wj produces different dest across calls: "
                  << (differ ? "PASS" : "FAIL (still constant-seeded!)") << "\n";
        if (!differ) ++failures;
    }

    // Check 2: repeat with a larger size to make coincidence effectively
    // impossible (32! is ~10^35, so two random draws matching is negligible).
    {
        OSNSender a, b, c;
        std::map<int, int> ma, mb, mc;
        a.init_wj(64, 1, "", ma);
        b.init_wj(64, 1, "", mb);
        c.init_wj(64, 1, "", mc);
        bool allDifferent = (a.dest != b.dest) && (b.dest != c.dest) && (a.dest != c.dest);
        std::cout << "[2] three independent init_wj calls all distinct (size 64): "
                  << (allDifferent ? "PASS" : "FAIL") << "\n";
        if (!allDifferent) ++failures;
    }

    // Check 3: sanity -- each dest is still a valid permutation of 0..N-1.
    {
        OSNSender a;
        std::map<int, int> m;
        a.init_wj(C, 1, "", m);
        std::vector<int> sorted = a.dest;
        std::sort(sorted.begin(), sorted.end());
        bool ok = true;
        for (size_t i = 0; i < C; ++i)
            if (sorted[i] != static_cast<int>(i)) { ok = false; break; }
        std::cout << "[3] dest is a valid permutation of 0..C-1: "
                  << (ok ? "PASS" : "FAIL") << "\n";
        if (!ok) ++failures;
    }

    if (failures == 0) {
        std::cout << "PASS: init_wj is seed-fresh (C4 Fisher-Yates hole closed).\n";
        std::cout << "NOTE: OSN wire-mask and OT-base freshness are additionally\n";
        std::cout << "      exercised by tests/unit/test_osn_semantics.cpp.\n";
        return 0;
    }
    std::cerr << "FAIL: " << failures << " check(s) failed.\n";
    return 1;
}
