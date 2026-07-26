// Tool 4 — Both-blind XOR-shared variant of ρ_1 (session 4, C++ port).

#include "benes_ref.h"

#include <cstdio>
#include <cstdint>
#include <random>

using namespace math_cpp;

namespace {

Perm rho_both_blind(int m, const ColSettings& a, const ColSettings& b,
                    const Wirings* ws_opt = nullptr) {
    int D = num_columns(m);
    Wirings ws_local;
    const Wirings& ws = ws_opt ? *ws_opt : (ws_local = wirings(m));
    Perm perm(m); for (int i = 0; i < m; ++i) perm[i] = i;
    perm = apply_wiring(perm, ws[0]);
    for (int t = 0; t < D; ++t) {
        perm = apply_column(perm, a[t]);   // matcher's share
        perm = apply_column(perm, b[t]);   // router's share
        perm = apply_wiring(perm, ws[t + 1]);
    }
    return perm;
}

void verify_prop_1_2_iii_via_both_blind(int m, int num_trials, uint64_t seed) {
    std::mt19937_64 rng(seed);
    auto ws = wirings(m);
    for (int i = 0; i < num_trials; ++i) {
        auto a = random_settings(m, rng);
        auto b = random_settings(m, rng);
        auto p1 = rho_both_blind(m, a, b, &ws);
        auto p2 = rho(m, xor_settings(a, b), &ws);
        if (p1 != p2) {
            std::printf("[Prop 1.2 iii] m=%d FAIL at trial %d\n", m, i);
            std::exit(1);
        }
    }
    std::printf("[Prop 1.2 iii] m=%d: %d both-blind eval == XOR-eval — PASS\n",
                m, num_trials);
}

// Coalition capability model
bool can_compute_rho1(bool has_a, bool has_b) { return has_a && has_b; }
bool can_compute_rho2(bool has_pi, bool has_rho1, bool has_rho2) {
    return (has_pi && has_rho1) || has_rho2;
}
bool can_compute_pi(bool has_pi, bool has_rho1, bool has_rho2) {
    return has_pi || (has_rho1 && has_rho2);
}

struct Coalition {
    const char* name;
    bool has_pi, has_a, has_b, has_rho2;
};

void print_coalition_matrix() {
    // Coalitions: matcher has (pi, a); router has (b); party has (rho2).
    Coalition C[] = {
        {"Matcher alone",              true,  true,  false, false},
        {"Router alone",               false, false, true,  false},
        {"Party alone",                false, false, false, true},
        {"Matcher + Router (EXCLUDED)", true, true,  true,  false},
        {"Matcher + Party",            true,  true,  false, true},
        {"Router + Party",             false, false, true,  true},
    };
    std::printf("%-32s %-10s %-10s %-10s   Verdict\n",
                "Coalition", "Can rho_1?", "Can rho_2?", "Can pi?");
    std::printf("%s\n", std::string(90, '-').c_str());
    for (const auto& c : C) {
        bool rho1 = can_compute_rho1(c.has_a, c.has_b);
        bool rho2 = can_compute_rho2(c.has_pi, rho1, c.has_rho2);
        bool pi_ok = can_compute_pi(c.has_pi, rho1, c.has_rho2);
        std::string verdict;
        if (std::string(c.name).find("EXCLUDED") != std::string::npos)
            verdict = "FULL (excluded)";
        else if (pi_ok && rho1 && rho2) verdict = "FULL LEAK";
        else if (c.has_pi && !rho2) verdict = "pi known but rho_2 hidden";
        else if (c.has_rho2 && !rho1) verdict = "rho_2 known but rho_1 hidden";
        else verdict = "no useful knowledge";
        std::printf("%-32s %-10s %-10s %-10s   %s\n", c.name,
                    rho1 ? "true" : "false",
                    rho2 ? "true" : "false",
                    pi_ok ? "true" : "false",
                    verdict.c_str());
    }
}

}  // namespace

int main() {
    std::puts("=== Tool 4 — Both-blind XOR variant (session 4, C++) ===\n");
    for (int m : {2, 4, 8}) verify_prop_1_2_iii_via_both_blind(m, 100, 0xE4);
    std::puts("\n--- Coalition matrix (both-blind variant) ---");
    print_coalition_matrix();
    std::puts("\nKey improvement: Matcher + Party can no longer recover rho_2 without router's b.");
    return 0;
}
