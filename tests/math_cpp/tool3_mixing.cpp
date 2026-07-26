// Tool 3 — Path A: exact convolution D^{*k} on S_m for small m (C++ port).

#include "benes_ref.h"

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <map>

using namespace math_cpp;

namespace {

using DistMap = std::map<Perm, double>;

DistMap enumerate_D(int m) {
    int S = total_switches(m);
    uint64_t total = 1ULL << S;
    DistMap d;
    for (uint64_t n = 0; n < total; ++n) {
        auto s = settings_from_int(m, n);
        d[rho(m, s)] += 1.0;
    }
    for (auto& [_, v] : d) v /= static_cast<double>(total);
    return d;
}

DistMap convolve(const DistMap& D, int k) {
    DistMap cur = D;
    for (int step = 1; step < k; ++step) {
        DistMap nxt;
        for (const auto& [p, pp] : cur)
            for (const auto& [q, qp] : D)
                nxt[perm_mul(p, q)] += pp * qp;
        cur = std::move(nxt);
    }
    return cur;
}

double tv_to_uniform(const DistMap& d, int m) {
    double u = 1.0 / std::tgamma(m + 1);   // 1 / m!
    // Iterate over all perms (including those with 0 prob)
    auto perms = all_perms(m);
    double tv = 0.0;
    for (const auto& p : perms) {
        auto it = d.find(p);
        double prob = (it == d.end()) ? 0.0 : it->second;
        tv += std::abs(prob - u);
    }
    return 0.5 * tv;
}

}  // namespace

int main() {
    std::puts("=== Tool 3 — Path A: convolution D^{*k} at small m (C++) ===\n");
    for (int m : {2, 4}) {
        auto D = enumerate_D(m);
        std::printf("--- m=%d, |S_m|=%zu ---\n", m, all_perms(m).size());
        double tv1 = tv_to_uniform(D, m);
        std::printf("  k=1: TV(D, Unif) = %.6f\n", tv1);
        int max_k = (m == 2) ? 8 : 4;
        DistMap cur = D;
        for (int k = 2; k <= max_k; ++k) {
            cur = convolve(D, k);
            std::printf("  k=%d: TV(D^*%d, Unif) = %.6f\n", k, k, tv_to_uniform(cur, m));
        }
        std::puts("");
    }
    std::puts("Path B (Fourier / Friedrichs) — see tool3_friedrichs.cpp");
    return 0;
}
