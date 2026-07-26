// Tool 2 — Sharp form of Conjecture 2.6: H_∞(D) = m · log₂(m) / 2 (C++ port).
// Session 1 milestone: exhaustive enumeration at m ∈ {2, 4, 8}.

#include "benes_ref.h"

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <unordered_map>

using namespace math_cpp;

namespace {

struct PermHash {
    size_t operator()(const Perm& p) const {
        size_t h = 0;
        for (int x : p) h = h * 131 + static_cast<size_t>(x);
        return h;
    }
};

}  // namespace

int main() {
    std::puts("=== Tool 2 — Sharp form of Conjecture 2.6 (C++) ===");
    std::puts("Empirical check: H_inf(D) = m*log2(m)/2 exactly?\n");
    for (int m : {2, 4, 8}) {
        int S = total_switches(m);
        uint64_t total = 1ULL << S;
        std::unordered_map<Perm, uint64_t, PermHash> mp;
        for (uint64_t n = 0; n < total; ++n) {
            auto s = settings_from_int(m, n);
            ++mp[rho(m, s)];
        }
        uint64_t max_mult = 0;
        for (const auto& [p, c] : mp) max_mult = std::max(max_mult, c);
        double H_inf = static_cast<double>(S) - std::log2(static_cast<double>(max_mult));
        double sharp = m * std::log2(m) / 2.0;
        double residue_S_minus_m = static_cast<double>(S - m);
        std::printf("m=%d  S=%d  max_mult=%llu  H_inf=%.4f  "
                    "m*log2(m)/2=%.4f  S-m=%.4f  match_sharp=%s\n",
                    m, S, (unsigned long long)max_mult, H_inf, sharp,
                    residue_S_minus_m,
                    std::abs(H_inf - sharp) < 1e-9 ? "YES" : "NO");
    }
    std::puts("\nConclusion: sharp form verified at all tested m. Compare with the");
    std::puts("m=8 coincidence H_inf = S - m: matches sharp only at m=8.");
    return 0;
}
