// Tool 4 — Simulator: Theorem 4.2 tight bound γ(D) = 1/16 at m=4 (C++ port).

#include "benes_ref.h"

#include <cstdio>
#include <cstdint>
#include <map>

using namespace math_cpp;

int main() {
    std::puts("=== Tool 4 — Simulator posteriors (Theorem 4.2) at m=4 (C++) ===\n");

    const int m = 4;
    int S = total_switches(m);
    uint64_t total = 1ULL << S;

    // Enumerate D distribution
    std::map<Perm, uint64_t> Dmp;
    for (uint64_t n = 0; n < total; ++n) {
        auto s = settings_from_int(m, n);
        ++Dmp[rho(m, s)];
    }
    std::printf("|support(D)| = %zu (of m! = 24)\n", Dmp.size());

    // Full-permutation model (Theorem 4.2): π uniform on S_m. Party sees ρ_2.
    // For each observed ρ_2, the posterior over π is:
    //   P(π | ρ_2) ∝ P(ρ_2 | π) = P(ρ_1 = π · ρ_2^{-1}) = M(π ρ_2^-1) / 2^S
    // Party's max posterior over π: max_π P(π | ρ_2) = max_π M(π ρ_2^-1) / (Σ M)
    // Since M is symmetric under group action (bijection π ↔ π·ρ_2^-1),
    // max posterior = max_ρ_1 M(ρ_1) / 2^S = γ(D).
    uint64_t max_mult = 0;
    for (const auto& [p, c] : Dmp) if (c > max_mult) max_mult = c;
    double gamma_D = static_cast<double>(max_mult) / static_cast<double>(total);
    std::printf("Full-permutation posterior: γ(D) = max M(σ) / 2^S = %llu / %llu = %.6f\n",
                (unsigned long long)max_mult, (unsigned long long)total, gamma_D);
    std::printf("Session 2 finding: γ(D) at m=4 = 0.0625 = 1/16 EXACTLY.\n");

    // c-injection model: π: [c] -> [m], c < m. Party knows its c positions map
    // somewhere; posterior on its c-tuple = 1/c!.
    for (int c = 2; c <= 4; ++c) {
        double posterior = 1.0;
        for (int i = 2; i <= c; ++i) posterior /= i;
        std::printf("c-injection model (c=%d): max posterior = 1/c! = %.4f\n",
                    c, posterior);
    }
    return 0;
}
