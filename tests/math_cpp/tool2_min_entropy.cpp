// Tool 2 — Min-entropy H_∞(D) exhaustive analysis (C++ port).

#include "benes_ref.h"

#include <cstdio>
#include <cstdint>
#include <unordered_map>
#include <cmath>

using namespace math_cpp;

namespace {

struct PermHash {
    size_t operator()(const Perm& p) const {
        size_t h = 0;
        for (int x : p) h = h * 131 + static_cast<size_t>(x);
        return h;
    }
};

std::unordered_map<Perm, uint64_t, PermHash> multiplicity_map(int m) {
    int S = total_switches(m);
    uint64_t total = 1ULL << S;
    std::unordered_map<Perm, uint64_t, PermHash> mp;
    for (uint64_t n = 0; n < total; ++n) {
        auto s = settings_from_int(m, n);
        auto p = rho(m, s);
        ++mp[p];
    }
    return mp;
}

void report(int m) {
    int S = total_switches(m);
    if (S > 20) { std::printf("m=%d: skipping (S=%d too large)\n", m, S); return; }
    auto mp = multiplicity_map(m);
    uint64_t max_mult = 0;
    for (const auto& [p, c] : mp) max_mult = std::max(max_mult, c);
    double log2_total = S;                       // log2(2^S)
    double log2_max = std::log2(static_cast<double>(max_mult));
    double H_inf = log2_total - log2_max;
    double sharp = m * std::log2(m) / 2.0;       // session 1 sharp form
    double loss = S - H_inf;
    std::printf("m=%2d  S=%2d  |support|=%zu  max_mult=%llu  "
                "H_inf=%.4f  sharp=%.4f  loss=%.2f\n",
                m, S, mp.size(), (unsigned long long)max_mult,
                H_inf, sharp, loss);
    // Verify sharp form matches at m ∈ {2,4,8}
    if (m <= 8) {
        double diff = std::abs(H_inf - sharp);
        if (diff < 1e-9) std::printf("  sharp form H_inf = m*log2(m)/2 confirmed at m=%d\n", m);
        else std::printf("  DEVIATION from sharp: %f\n", diff);
    }
}

}  // namespace

int main() {
    std::puts("=== Tool 2 — Min-entropy exhaustive analysis (C++) ===\n");
    for (int m : {2, 4, 8}) report(m);
    std::puts("\nSession-1 conclusion: H_inf(D) = m * log2(m) / 2 (sharp).");
    return 0;
}
