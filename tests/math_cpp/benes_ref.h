// Beneš switching network — C++ reference implementation.
// Mirrors tests/math/benes.py exactly (same wiring convention, same κ_t action).
// Header-only.

#pragma once

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstddef>
#include <random>
#include <vector>

namespace math_cpp {

using Perm = std::vector<int>;
using Bits = std::vector<int>;
using ColSettings = std::vector<Bits>;
using Wirings = std::vector<Perm>;

inline int num_switches_per_column(int m) { return m / 2; }

inline int num_columns(int m) {
    assert(m >= 2 && (m & (m - 1)) == 0);
    return 2 * static_cast<int>(std::log2(m)) - 1;
}

inline int total_switches(int m) {
    return num_switches_per_column(m) * num_columns(m);
}

inline Perm apply_column(const Perm& perm, const Bits& bits) {
    assert(static_cast<int>(bits.size()) == static_cast<int>(perm.size()) / 2);
    Perm out = perm;
    for (int j = 0; j < static_cast<int>(bits.size()); ++j) {
        if (bits[j]) std::swap(out[2 * j], out[2 * j + 1]);
    }
    return out;
}

inline Perm perfect_shuffle(int m) {
    Perm out(m, 0);
    for (int i = 0; i < m; ++i) {
        if (i % 2 == 0) out[i / 2] = i;
        else            out[m / 2 + i / 2] = i;
    }
    return out;
}

inline Perm inverse_perfect_shuffle(int m) {
    Perm out(m, 0);
    for (int i = 0; i < m; ++i) {
        if (i < m / 2) out[2 * i] = i;
        else           out[2 * (i - m / 2) + 1] = i;
    }
    return out;
}

inline Perm compose(const Perm& p, const Perm& q) {
    Perm r(q.size());
    for (size_t i = 0; i < q.size(); ++i) r[i] = p[q[i]];
    return r;
}

inline Perm apply_wiring(const Perm& perm, const Perm& w) {
    Perm out(w.size());
    for (size_t i = 0; i < w.size(); ++i) out[i] = perm[w[i]];
    return out;
}

inline Wirings wirings(int m) {
    int D = num_columns(m);
    Wirings ws;
    Perm identity(m); for (int i = 0; i < m; ++i) identity[i] = i;
    ws.push_back(identity);
    for (int t = 0; t < D; ++t) {
        if (t < D / 2) ws.push_back(perfect_shuffle(m));
        else           ws.push_back(inverse_perfect_shuffle(m));
    }
    return ws;
}

inline Perm rho(int m, const ColSettings& s, const Wirings* ws_opt = nullptr) {
    int D = num_columns(m);
    assert(static_cast<int>(s.size()) == D);
    Wirings ws_local;
    const Wirings& ws = ws_opt ? *ws_opt : (ws_local = wirings(m));
    Perm perm(m); for (int i = 0; i < m; ++i) perm[i] = i;
    perm = apply_wiring(perm, ws[0]);
    for (int t = 0; t < D; ++t) {
        perm = apply_column(perm, s[t]);
        perm = apply_wiring(perm, ws[t + 1]);
    }
    return perm;
}

inline Bits bits_from_int(uint64_t x, int width) {
    Bits b(width);
    for (int i = 0; i < width; ++i) b[i] = static_cast<int>((x >> i) & 1ULL);
    return b;
}

inline ColSettings settings_from_int(int m, uint64_t n) {
    int D = num_columns(m);
    int per_col = m / 2;
    int total = D * per_col;
    Bits bits = bits_from_int(n, total);
    ColSettings out(D);
    for (int t = 0; t < D; ++t) {
        out[t].assign(bits.begin() + t * per_col, bits.begin() + (t + 1) * per_col);
    }
    return out;
}

inline ColSettings random_settings(int m, std::mt19937_64& rng) {
    int D = num_columns(m);
    int per_col = m / 2;
    ColSettings s(D, Bits(per_col));
    std::uniform_int_distribution<int> u(0, 1);
    for (int t = 0; t < D; ++t)
        for (int j = 0; j < per_col; ++j)
            s[t][j] = u(rng);
    return s;
}

inline bool is_permutation(const Perm& p) {
    Perm sorted_p = p;
    std::sort(sorted_p.begin(), sorted_p.end());
    for (int i = 0; i < static_cast<int>(p.size()); ++i)
        if (sorted_p[i] != i) return false;
    return true;
}

inline Perm perm_inv(const Perm& p) {
    Perm inv(p.size());
    for (int i = 0; i < static_cast<int>(p.size()); ++i) inv[p[i]] = i;
    return inv;
}

inline Perm perm_mul(const Perm& p, const Perm& q) {
    Perm r(q.size());
    for (size_t i = 0; i < q.size(); ++i) r[i] = p[q[i]];
    return r;
}

inline ColSettings xor_settings(const ColSettings& a, const ColSettings& b) {
    ColSettings out(a.size());
    for (size_t t = 0; t < a.size(); ++t) {
        out[t].resize(a[t].size());
        for (size_t j = 0; j < a[t].size(); ++j) out[t][j] = a[t][j] ^ b[t][j];
    }
    return out;
}

// Enumerate all permutations of [0..m-1] (feasible for m ≤ 8).
inline std::vector<Perm> all_perms(int m) {
    Perm base(m); for (int i = 0; i < m; ++i) base[i] = i;
    std::vector<Perm> out;
    do { out.push_back(base); } while (std::next_permutation(base.begin(), base.end()));
    return out;
}

}  // namespace math_cpp
