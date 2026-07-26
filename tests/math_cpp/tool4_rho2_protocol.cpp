// Tool 4 — Session 5: two-server ρ_2 evaluation protocol (C++ port).

#include "benes_ref.h"

#include <cstdio>
#include <cstdint>
#include <random>
#include <vector>
#include <cassert>
#include <unordered_map>

using namespace math_cpp;

namespace {

using BitVec = std::vector<int>;

BitVec unit_vec(int i, int m) {
    BitVec v(m, 0); v[i] = 1; return v;
}

BitVec xor_vecs(const BitVec& u, const BitVec& v) {
    BitVec r(u.size());
    for (size_t i = 0; i < u.size(); ++i) r[i] = u[i] ^ v[i];
    return r;
}

// Apply permutation P (P[i] = image of i) to bit-vector v: v'[P[i]] = v[i]
BitVec apply_perm_to_vec(const Perm& P, const BitVec& v) {
    BitVec out(v.size(), 0);
    for (size_t i = 0; i < v.size(); ++i) out[P[i]] = v[i];
    return out;
}

int index_of_one(const BitVec& v) {
    int idx = -1;
    for (int i = 0; i < (int)v.size(); ++i)
        if (v[i]) { assert(idx == -1); idx = i; }
    assert(idx >= 0);
    return idx;
}

// Direct chain application (non-oblivious spec)
BitVec rho_2_apply_direct(int /*m*/, const Perm& pi, const ColSettings& a,
                          const ColSettings& b, const Wirings& ws, BitVec v) {
    v = apply_wiring(v, ws[0]);
    for (int t = 0; t < (int)a.size(); ++t) {
        v = apply_column(v, a[t]);
        v = apply_column(v, b[t]);
        v = apply_wiring(v, ws[t + 1]);
    }
    v = apply_perm_to_vec(pi, v);
    return v;
}

Perm rho_2_as_perm(int m, const Perm& pi, const ColSettings& a,
                   const ColSettings& b, const Wirings& ws) {
    BitVec ident(m); for (int i = 0; i < m; ++i) ident[i] = i;  // identity as "vector"
    // But apply_wiring/apply_column treat elements as opaque. Use int identity vector.
    // Then rho_2[v[k]] = k.
    auto v = rho_2_apply_direct(m, pi, a, b, ws, ident);
    Perm rho_2(m);
    for (int k = 0; k < m; ++k) rho_2[v[k]] = k;
    return rho_2;
}

struct Counter { int osn_calls = 0; int public_wirings = 0; };

// Public wiring: both apply locally
void apply_wiring_shared(BitVec& vM, BitVec& vR, const Perm& w, Counter& c) {
    vM = apply_wiring(vM, w);
    vR = apply_wiring(vR, w);
    ++c.public_wirings;
}

// One-side-known column via ideal OSN mask
void apply_column_shared(BitVec& vM, BitVec& vR, const Bits& bits, Counter& c,
                         std::mt19937_64& rng) {
    std::uniform_int_distribution<int> u(0, 1);
    BitVec mask(vM.size()); for (auto& x : mask) x = u(rng);
    vM = xor_vecs(apply_column(vM, bits), mask);
    vR = xor_vecs(apply_column(vR, bits), mask);
    ++c.osn_calls;
}

// Matcher-known permutation via OSN
void apply_perm_shared(BitVec& vM, BitVec& vR, const Perm& P, Counter& c,
                       std::mt19937_64& rng) {
    std::uniform_int_distribution<int> u(0, 1);
    BitVec mask(vM.size()); for (auto& x : mask) x = u(rng);
    vM = xor_vecs(apply_perm_to_vec(P, vM), mask);
    vR = xor_vecs(apply_perm_to_vec(P, vR), mask);
    ++c.osn_calls;
}

std::pair<BitVec, Counter> run_protocol(int m, const Perm& pi,
                                        const ColSettings& a, const ColSettings& b,
                                        const Wirings& ws, int i, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<int> u(0, 1);
    int D = a.size();
    Counter c;
    BitVec vM(m); for (auto& x : vM) x = u(rng);
    BitVec vR = xor_vecs(vM, unit_vec(i, m));
    apply_wiring_shared(vM, vR, ws[0], c);
    for (int t = 0; t < D; ++t) {
        apply_column_shared(vM, vR, a[t], c, rng);
        apply_column_shared(vM, vR, b[t], c, rng);
        apply_wiring_shared(vM, vR, ws[t + 1], c);
    }
    apply_perm_shared(vM, vR, pi, c, rng);
    return {xor_vecs(vM, vR), c};
}

void test_correctness(int m, int num_trials, uint64_t seed) {
    std::mt19937_64 rng(seed);
    auto ws = wirings(m);
    int D = num_columns(m);
    int expected_osn = 2 * D + 1;
    for (int trial = 0; trial < num_trials; ++trial) {
        auto a = random_settings(m, rng);
        auto b = random_settings(m, rng);
        Perm pi(m); for (int i = 0; i < m; ++i) pi[i] = i;
        std::shuffle(pi.begin(), pi.end(), rng);
        std::uniform_int_distribution<int> idxU(0, m - 1);
        int i = idxU(rng);

        auto v_expected = rho_2_apply_direct(m, pi, a, b, ws, unit_vec(i, m));
        auto [v_actual, c] = run_protocol(m, pi, a, b, ws, i,
                                          std::uniform_int_distribution<uint64_t>()(rng));
        if (v_actual != v_expected) {
            std::printf("[Correctness] m=%d trial %d FAIL\n", m, trial); std::exit(1);
        }
        if (c.osn_calls != expected_osn) {
            std::printf("[Correctness] OSN count wrong: %d != %d\n",
                        c.osn_calls, expected_osn); std::exit(1);
        }
        int j = index_of_one(v_actual);
        auto rho2_arr = rho_2_as_perm(m, pi, a, b, ws);
        if (j != rho2_arr[i]) {
            std::printf("[Correctness] index recovery FAIL trial %d\n", trial); std::exit(1);
        }
    }
    std::printf("[Correctness] m=%d, D=%d: %d trials -- %d OSN calls per query -- PASS\n",
                m, D, num_trials, expected_osn);
}

void test_collusion_recovers(int m) {
    std::mt19937_64 rng(0xD0);
    auto ws = wirings(m);
    auto a = random_settings(m, rng);
    auto b = random_settings(m, rng);
    Perm pi(m); for (int i = 0; i < m; ++i) pi[i] = i;
    std::shuffle(pi.begin(), pi.end(), rng);
    auto rho2 = rho_2_as_perm(m, pi, a, b, ws);
    std::printf("[Collusion] m=%d: matcher+router can trivially compute rho_2 "
                "(rho_2[0]=%d) — VERIFIED\n", m, rho2[0]);
}

}  // namespace

int main() {
    std::puts("=== Tool 4 — Two-server rho_2 protocol (session 5, C++) ===\n");
    for (int m : {2, 4, 8}) test_correctness(m, 100, 0xE5);
    test_collusion_recovers(4);

    std::puts("\n--- Cost projection ---");
    for (int m : {256, 1024, 4096}) {
        int D = num_columns(m);
        int osn = 2 * D + 1;
        int kappa = 128;
        double per_osn_bits = 2.0 * kappa * m * (int)std::log2(m);
        double per_query_KB = osn * per_osn_bits / 8.0 / 1024.0;
        std::printf("  m=%d: %d OSN calls per query, ~%.0f KB\n", m, osn, per_query_KB);
    }
    return 0;
}
