// Composite SVS security bound — C++ port of tests/math/composite_bound.py.
// Sessions 1-6 sharpenings folded in (see Python source for full commentary).
//
// Self-contained: no external deps beyond libc++.

#include <cmath>
#include <cstdio>
#include <string>

namespace {

struct Result {
    double T1, T2, T3, T4;
    double T5_kb;
    double T_crypto, total;
    int m, N, k, Q, num_sectors;
    double eps_agg, eps_card, eps_cell;
    std::string composition;
    bool include_dp;
};

double T1_crypto(int m) {
    double lg = std::log2(m);
    double H_inf = m * lg / 2.0;
    return std::pow(2.0, -H_inf);
}

double T2_incidence(int k, int /*N*/, double eps_cell) {
    double padding_per_cell = 1.0 / (std::exp(eps_cell) - 1.0);
    return 1.0 / (k + padding_per_cell);
}

double T3_dp_composition(int Q, int num_sectors,
                         double eps_agg, double eps_card,
                         const std::string& composition) {
    double per_query = eps_agg + eps_card;
    double total_queries = static_cast<double>(Q) * num_sectors;
    if (composition == "basic") {
        return total_queries * per_query;
    } else if (composition == "renyi_alpha2") {
        // δ = 2^-40; ln(1/δ) ≈ 27.7
        return std::sqrt(2.0 * total_queries * 27.7) * per_query
             + total_queries * per_query * per_query;
    }
    return -1.0;
}

double T4_single_benes_dist(int m, double friedrichs_cos = 0.5) {
    int D = 2 * static_cast<int>(std::log2(m)) - 1;
    return std::pow(friedrichs_cos, D - 1);
}

double T5_comm_cost_kbytes(int m) {
    int D = 2 * static_cast<int>(std::log2(m)) - 1;
    int osn_calls = 2 * D + 1;
    int kappa = 128;
    double per_osn_bits = 2.0 * kappa * m * static_cast<int>(std::log2(m));
    return osn_calls * per_osn_bits / 8.0 / 1024.0;
}

Result composite_bound(int m, int N, int k, int Q, int num_sectors,
                       double eps_agg, double eps_card, double eps_cell,
                       const std::string& composition = "basic",
                       bool include_dp = true) {
    Result r{};
    r.T1 = T1_crypto(m);
    r.T2 = T2_incidence(k, N, eps_cell);
    r.T3 = include_dp
        ? T3_dp_composition(Q, num_sectors, eps_agg, eps_card, composition)
        : 0.0;
    r.T4 = T4_single_benes_dist(m);
    r.T5_kb = T5_comm_cost_kbytes(m);
    r.T_crypto = std::max(r.T1, r.T4);
    r.total = r.T_crypto + r.T2 + r.T3;
    r.m = m; r.N = N; r.k = k; r.Q = Q; r.num_sectors = num_sectors;
    r.eps_agg = eps_agg; r.eps_card = eps_card; r.eps_cell = eps_cell;
    r.composition = composition; r.include_dp = include_dp;
    return r;
}

std::string fmt_sci(double x, int sig = 3) {
    char buf[64];
    if (x == 0.0)     { std::snprintf(buf, sizeof(buf), "0");            return buf; }
    if (x < 1e-30)    { std::snprintf(buf, sizeof(buf), "< 2^-100");     return buf; }
    if (x < 0.001)    { std::snprintf(buf, sizeof(buf), "%.*e", sig, x); return buf; }
    std::snprintf(buf, sizeof(buf), "%.*f", sig, x);
    return buf;
}

void print_scenario(const std::string& label, const Result& r) {
    std::printf("--- %s ---\n", label.c_str());
    std::printf("  Params: m=%d, N=%d, k=%d, Q=%d, sectors=%d, "
                "eps_agg=%g, eps_card=%g, eps_cell=%g, composition=%s, DP=%s\n",
                r.m, r.N, r.k, r.Q, r.num_sectors,
                r.eps_agg, r.eps_card, r.eps_cell,
                r.composition.c_str(), r.include_dp ? "true" : "false");
    std::printf("  T1 (crypto guess):     %s\n", fmt_sci(r.T1).c_str());
    std::printf("  T4 (single-Benes TV):  %s   [session 6]\n", fmt_sci(r.T4).c_str());
    std::printf("  T_crypto = max(T1,T4): %s\n", fmt_sci(r.T_crypto).c_str());
    std::printf("  T2 (incidence):        %s\n", fmt_sci(r.T2).c_str());
    std::printf("  T3 (DP output):        %s%s\n", fmt_sci(r.T3).c_str(),
                r.include_dp ? "" : "   [DISABLED]");
    std::printf("  Total advantage:       %s\n", fmt_sci(r.total).c_str());
    std::printf("  T5 comms per query:    %.0f KB   [session 5, not Adv]\n", r.T5_kb);

    struct Term { const char* name; double val; };
    Term ts[] = { {"T_crypto", r.T_crypto}, {"T2", r.T2}, {"T3", r.T3} };
    Term* binding = &ts[0];
    for (int i = 1; i < 3; ++i) if (ts[i].val > binding->val) binding = &ts[i];
    std::printf("  BINDING TERM: %s  (%s)\n\n",
                binding->name, fmt_sci(binding->val).c_str());
}

}  // namespace

int main() {
    std::puts("======================================================================");
    std::puts("Composite SVS security bound - numerical evaluator (C++ port)");
    std::puts("(Sessions 1-6 sharpenings folded in.)");
    std::puts("======================================================================");
    std::puts("");
    std::puts("Coalition scope for T_crypto: post-sessions-4/5 (both-blind + two-server)");
    std::puts("  -> covers 5 non-trivial coalitions (vs 1 in single-server)");
    std::puts("  -> same gamma(D) bound, ~5x broader threat model");
    std::puts("");
    std::printf("Session 6 addition:\n");
    std::printf("  T4_dist(4)     = %s  (verified concretely, cos theta' = 0.5)\n",
                fmt_sci(T4_single_benes_dist(4)).c_str());
    std::printf("  T4_dist(1024)  = %s  (optimistic conjecture)\n",
                fmt_sci(T4_single_benes_dist(1024)).c_str());
    std::printf("  T4_dist(16384) = %s  (optimistic conjecture)\n\n",
                fmt_sci(T4_single_benes_dist(16384)).c_str());
    std::printf("Session 5 comms cost:\n");
    std::printf("  T5 at m=1024:  %.0f KB per query\n", T5_comm_cost_kbytes(1024));
    std::printf("  T5 at m=16384: %.0f KB per query\n\n", T5_comm_cost_kbytes(16384));

    print_scenario("A. MAS default (basic DP composition)",
                   composite_bound(1024, 4, 25, 4, 20, 0.5, 0.1, 1.0, "basic"));
    print_scenario("B. MAS default (Renyi alpha=2 composition)",
                   composite_bound(1024, 4, 25, 4, 20, 0.5, 0.1, 1.0, "renyi_alpha2"));
    print_scenario("C. Reduced granularity: 5 sectors",
                   composite_bound(1024, 4, 25, 4, 5, 0.5, 0.1, 1.0, "basic"));
    print_scenario("D. Small per-query eps (0.01 each)",
                   composite_bound(1024, 4, 25, 4, 20, 0.01, 0.01, 1.0, "basic"));
    print_scenario("E. Annual release only (Q=1)",
                   composite_bound(1024, 4, 25, 1, 20, 0.5, 0.1, 1.0, "basic"));
    print_scenario("F. Sweet spot: annual, 5 sectors, small eps",
                   composite_bound(1024, 4, 25, 1, 5, 0.1, 0.05, 1.0, "basic"));
    print_scenario("G. Large-population (m=16K, N=6)",
                   composite_bound(16384, 6, 50, 4, 20, 0.5, 0.1, 1.0, "basic"));
    print_scenario("H. Sub-unity sweet spot: Q=1, 5 sectors, eps=0.02",
                   composite_bound(1024, 4, 25, 1, 5, 0.02, 0.01, 1.0, "basic"));
    print_scenario("I. Single-scalar release, semi-annual",
                   composite_bound(1024, 4, 25, 2, 1, 0.05, 0.02, 1.0, "basic"));

    std::puts("======================================================================");
    std::puts("CURRENT DEPLOYMENT (DP disabled, both-blind + two-server enabled)");
    std::puts("======================================================================\n");
    print_scenario("J. Current deployment (MAS quarterly, DP off)",
                   composite_bound(1024, 4, 25, 4, 20, 0.0, 0.0, 1.0, "basic", false));
    print_scenario("K. Current deployment, large population (m=16K)",
                   composite_bound(16384, 6, 50, 4, 20, 0.0, 0.0, 1.0, "basic", false));
    print_scenario("L. Current deployment, k=1 (no k-anon padding)",
                   composite_bound(1024, 4, 1, 4, 20, 0.0, 0.0, 1.0, "basic", false));

    std::puts("======================================================================");
    std::puts("KEY FINDINGS (see composite_bound.py for full narrative)");
    std::puts("======================================================================");
    std::puts("Regime 2 (DP off) headline numbers:");
    std::puts("  J. Adv = 0.039 at MAS default (k=25)");
    std::puts("  K. Adv = 0.020 at m=16K, k=50");
    std::puts("  L. Adv = 0.632 at k=1 (k-anon is load-bearing)");
    std::puts("");
    std::puts("Session 4/5/6 coalition/comms/mixing overlays as summarized in .py.");
    return 0;
}
