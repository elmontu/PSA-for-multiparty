// Tool 5 — Möbius / zeta incidence analysis on Boolean lattice (C++ port).

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <map>
#include <random>
#include <vector>
#include <cassert>

namespace {

using Subset = uint32_t;  // bitmask over [N] with N ≤ 30
using CellMap = std::map<Subset, int>;

std::vector<Subset> all_nonempty_subsets(int N) {
    std::vector<Subset> out;
    for (uint32_t s = 1; s < (1u << N); ++s) out.push_back(s);
    return out;
}

CellMap zeta_transform(const CellMap& n, int N) {
    auto subs = all_nonempty_subsets(N);
    CellMap I;
    for (auto B : subs) {
        int s = 0;
        for (auto A : subs) if ((A & B) == B) s += n.count(A) ? n.at(A) : 0;
        I[B] = s;
    }
    return I;
}

CellMap mobius_inverse(const CellMap& I, int N) {
    auto subs = all_nonempty_subsets(N);
    CellMap n;
    for (auto A : subs) {
        int s = 0;
        for (auto B : subs) if ((A & B) == A) {
            int sz = __builtin_popcount(B ^ A);
            s += (sz % 2 == 0 ? 1 : -1) * (I.count(B) ? I.at(B) : 0);
        }
        n[A] = s;
    }
    return n;
}

std::vector<Subset> simulate_membership(int N, int num_items, double avg_membership,
                                        std::mt19937_64& rng) {
    std::uniform_real_distribution<double> u(0.0, 1.0);
    double p = avg_membership / N;
    std::vector<Subset> out;
    while ((int)out.size() < num_items) {
        Subset s = 0;
        for (int i = 0; i < N; ++i) if (u(rng) < p) s |= (1u << i);
        if (s != 0) out.push_back(s);
    }
    return out;
}

CellMap cell_counts(const std::vector<Subset>& memb, int N) {
    CellMap n;
    for (auto s : memb) n[s]++;
    // Ensure all keys present as 0
    for (auto s : all_nonempty_subsets(N)) if (!n.count(s)) n[s] = 0;
    return n;
}

void test_zeta_identity(int N) {
    std::mt19937_64 rng(0xC5);
    auto memb = simulate_membership(N, 200, 2.0, rng);
    auto n = cell_counts(memb, N);
    auto I = zeta_transform(n, N);

    // Cross-check against direct definition
    for (auto B : all_nonempty_subsets(N)) {
        int direct = 0;
        for (auto s : memb) if ((s & B) == B) ++direct;
        assert(I[B] == direct);
    }
    auto n_back = mobius_inverse(I, N);
    for (auto A : all_nonempty_subsets(N)) assert(n[A] == n_back[A]);
    std::printf("[zeta/mobius] N=%d: zn matches direct, mu(zn)=n exactly — PASS\n", N);
}

void test_lemma_5_2(int N) {
    std::mt19937_64 rng(0xD5);
    auto memb = simulate_membership(N, 100, 2.0, rng);
    auto n = cell_counts(memb, N);
    auto I = zeta_transform(n, N);

    int max_ell1 = 0;
    for (auto Aw : all_nonempty_subsets(N)) {
        auto np = n;
        np[Aw] += 1;
        auto Ip = zeta_transform(np, N);
        int dI = 0, dn = 0;
        for (auto B : all_nonempty_subsets(N)) dI += std::abs(Ip[B] - I[B]);
        for (auto A : all_nonempty_subsets(N)) dn += std::abs(np[A] - n[A]);
        assert(dn == 1);
        max_ell1 = std::max(max_ell1, dI);
        int expected = (1 << __builtin_popcount(Aw)) - 1;
        assert(dI == expected);
    }
    std::printf("[Lemma 5.2] N=%d: max l1(dI) = %d (= 2^N - 1 = %d) — PASS\n",
                N, max_ell1, (1 << N) - 1);
}

int geometric_sample(double scale, std::mt19937_64& rng) {
    double p = 1.0 / (scale + 1.0);
    if (p >= 1.0) return 0;
    std::uniform_real_distribution<double> u(0.0, 1.0);
    double x = u(rng);
    return (int)(std::log(1 - x) / std::log(1 - p));
}

void test_mechanism_5_3(int N, double eps, int trials) {
    double scale = 1.0 / (std::exp(eps) - 1.0);
    double theoretical = ((1 << N) - 1) * scale;
    std::mt19937_64 rng(0xE5);
    double emp = 0.0;
    for (int t = 0; t < trials; ++t) {
        double s = 0.0;
        auto subs = all_nonempty_subsets(N);
        for (size_t k = 0; k < subs.size(); ++k) s += geometric_sample(scale, rng);
        emp += s;
    }
    emp /= trials;
    std::printf("[Mech 5.3] N=%d, eps=%.2f: theoretical=%.3f, empirical=%.3f\n",
                N, eps, theoretical, emp);
}

}  // namespace

int main() {
    std::puts("=== Tool 5 — Mobius/zeta incidence analysis (C++) ===\n");
    for (int N : {3, 4, 5}) {
        test_zeta_identity(N);
        test_lemma_5_2(N);
        test_mechanism_5_3(N, 1.0, 1000);
        test_mechanism_5_3(N, 0.1, 1000);
        std::puts("");
    }
    std::puts("ALL PASSED");
    return 0;
}
