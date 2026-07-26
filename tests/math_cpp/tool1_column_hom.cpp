// Tool 1 — Column homomorphism verification (C++ port of tool1_column_hom.py).
// Verifies Prop 1.2 (i) exhaustively at m ≤ 8 and (iii) the XOR-split identity.

#include "benes_ref.h"

#include <cstdio>
#include <random>

using namespace math_cpp;

static void test_all_settings_produce_permutations(int m) {
    int S = total_switches(m);
    if (S > 20) { std::printf("  m=%d: skipping exhaustive (S=%d > 20)\n", m, S); return; }
    uint64_t total = 1ULL << S;
    for (uint64_t n = 0; n < total; ++n) {
        auto s = settings_from_int(m, n);
        auto p = rho(m, s);
        if (!is_permutation(p)) {
            std::printf("[Prop 1.2 i] m=%d: FAIL at settings int %llu\n",
                        m, (unsigned long long)n);
            std::exit(1);
        }
    }
    std::printf("[Prop 1.2 i] m=%d: all 2^%d=%llu settings produce valid perms — PASS\n",
                m, S, (unsigned long long)total);
}

static void test_random_settings_produce_permutations(int m, int trials, uint64_t seed) {
    std::mt19937_64 rng(seed);
    for (int i = 0; i < trials; ++i) {
        auto s = random_settings(m, rng);
        auto p = rho(m, s);
        if (!is_permutation(p)) {
            std::printf("[Prop 1.2 i] m=%d random FAIL at trial %d\n", m, i);
            std::exit(1);
        }
    }
    std::printf("[Prop 1.2 i] m=%d: %d random settings all valid perms — PASS\n",
                m, trials);
}

static void test_prop_1_2_iii_xor_split(int m, uint64_t seed) {
    // κ_t(a XOR b) = κ_t(a) · κ_t(b). Equivalently: ρ(a xor b) = ρ_both_blind(a, b)
    // where the both-blind eval applies a-column then b-column separately per layer.
    auto ws = wirings(m);
    int S = total_switches(m);

    // Exhaustive at m=4 (S=6, 4096 pairs)
    if (S <= 6) {
        uint64_t total = 1ULL << S;
        uint64_t checked = 0;
        for (uint64_t an = 0; an < total; ++an)
        for (uint64_t bn = 0; bn < total; ++bn) {
            auto a = settings_from_int(m, an);
            auto b = settings_from_int(m, bn);
            auto s = xor_settings(a, b);
            auto p1 = rho(m, s, &ws);

            // both-blind eval
            int D = num_columns(m);
            Perm p2(m); for (int i = 0; i < m; ++i) p2[i] = i;
            p2 = apply_wiring(p2, ws[0]);
            for (int t = 0; t < D; ++t) {
                p2 = apply_column(p2, a[t]);
                p2 = apply_column(p2, b[t]);
                p2 = apply_wiring(p2, ws[t + 1]);
            }
            if (p1 != p2) {
                std::printf("[Prop 1.2 iii] m=%d: XOR-split FAIL at (an=%llu, bn=%llu)\n",
                            m, (unsigned long long)an, (unsigned long long)bn);
                std::exit(1);
            }
            ++checked;
        }
        std::printf("[Prop 1.2 iii] m=%d: exhaustive %llu (a,b) pairs — PASS\n",
                    m, (unsigned long long)checked);
    } else {
        // Random sample
        std::mt19937_64 rng(seed);
        int trials = 5000;
        for (int i = 0; i < trials; ++i) {
            auto a = random_settings(m, rng);
            auto b = random_settings(m, rng);
            auto s = xor_settings(a, b);
            auto p1 = rho(m, s, &ws);

            int D = num_columns(m);
            Perm p2(m); for (int i = 0; i < m; ++i) p2[i] = i;
            p2 = apply_wiring(p2, ws[0]);
            for (int t = 0; t < D; ++t) {
                p2 = apply_column(p2, a[t]);
                p2 = apply_column(p2, b[t]);
                p2 = apply_wiring(p2, ws[t + 1]);
            }
            if (p1 != p2) {
                std::printf("[Prop 1.2 iii] m=%d random FAIL at trial %d\n", m, i);
                std::exit(1);
            }
        }
        std::printf("[Prop 1.2 iii] m=%d: %d random (a,b) pairs — PASS\n", m, trials);
    }
}

int main() {
    std::puts("=== Tool 1 — Column homomorphism verification (C++) ===\n");
    for (int m : {2, 4, 8}) test_all_settings_produce_permutations(m);
    for (int m : {16, 32}) test_random_settings_produce_permutations(m, 200, 0xC0DE);
    std::puts("");
    for (int m : {2, 4}) test_prop_1_2_iii_xor_split(m, 0xE1);
    for (int m : {8, 16, 32}) test_prop_1_2_iii_xor_split(m, 0xE1);
    std::puts("\nALL PASSED");
    return 0;
}
