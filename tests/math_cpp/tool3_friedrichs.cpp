// Tool 3 — Path B: spectral / Friedrichs-angle analysis (C++ port, uses Eigen).

#include "benes_ref.h"

#include <Eigen/Dense>

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <unordered_map>
#include <map>
#include <vector>

using namespace math_cpp;

namespace {

using DistMap = std::map<Perm, double>;
using Mat = Eigen::MatrixXd;

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
    double u = 1.0 / std::tgamma(m + 1);
    auto perms = all_perms(m);
    double tv = 0.0;
    for (const auto& p : perms) {
        auto it = d.find(p);
        double prob = (it == d.end()) ? 0.0 : it->second;
        tv += std::abs(prob - u);
    }
    return 0.5 * tv;
}

struct PermIdx {
    std::vector<Perm> perms;
    std::map<Perm, int> idx;
    explicit PermIdx(int m) {
        perms = all_perms(m);
        for (int i = 0; i < (int)perms.size(); ++i) idx[perms[i]] = i;
    }
    int operator()(const Perm& p) const { return idx.at(p); }
};

Mat convolution_matrix(const DistMap& D, const PermIdx& pi) {
    int n = pi.perms.size();
    Mat M = Mat::Zero(n, n);
    for (int i = 0; i < n; ++i) {
        Perm pi_i = pi.perms[i];
        for (int j = 0; j < n; ++j) {
            Perm inv_pj = perm_inv(pi.perms[j]);
            Perm key = perm_mul(pi_i, inv_pj);
            auto it = D.find(key);
            if (it != D.end()) M(i, j) = it->second;
        }
    }
    return M;
}

Mat perm_matrix(const Perm& sigma, const PermIdx& pi) {
    int n = pi.perms.size();
    Mat M = Mat::Zero(n, n);
    for (int j = 0; j < n; ++j) {
        Perm target = perm_mul(sigma, pi.perms[j]);
        M(pi(target), j) = 1.0;
    }
    return M;
}

std::vector<Perm> column_stabilizer(int m) {
    int per_col = m / 2;
    std::vector<Perm> out;
    for (int mask = 0; mask < (1 << per_col); ++mask) {
        Perm p(m); for (int i = 0; i < m; ++i) p[i] = i;
        for (int j = 0; j < per_col; ++j)
            if ((mask >> j) & 1) std::swap(p[2*j], p[2*j+1]);
        out.push_back(p);
    }
    return out;
}

Mat averaging_projection(const std::vector<Perm>& K, const PermIdx& pi) {
    int n = pi.perms.size();
    Mat E = Mat::Zero(n, n);
    for (const auto& p : K) E += perm_matrix(p, pi);
    return E / static_cast<double>(K.size());
}

std::vector<double> sorted_singular_values_desc(const Mat& M) {
    Eigen::JacobiSVD<Mat> svd(M);
    auto sv = svd.singularValues();
    std::vector<double> out(sv.data(), sv.data() + sv.size());
    std::sort(out.begin(), out.end(), std::greater<double>());
    return out;
}

double diaconis_shahshahani_bound(const std::vector<double>& svs, int k) {
    double s = 0.0;
    for (double sv : svs) if (sv < 1.0 - 1e-9) s += std::pow(sv, 2 * k);
    return 0.5 * std::sqrt(s);
}

double friedrichs_cos(const Mat& E1, const Mat& E2) {
    Mat prod = E1 * E2;
    Eigen::JacobiSVD<Mat> svd(prod);
    auto sv = svd.singularValues();
    double best = 0.0;
    for (int i = 0; i < sv.size(); ++i)
        if (sv[i] < 1.0 - 1e-9 && sv[i] > best) best = sv[i];
    return best;
}

void group_by_multiplicity(const std::vector<double>& svs, double tol = 1e-8) {
    std::vector<std::pair<double, int>> groups;
    for (double s : svs) {
        bool placed = false;
        for (auto& g : groups) if (std::abs(g.first - s) < tol) { g.second++; placed = true; break; }
        if (!placed) groups.emplace_back(s, 1);
    }
    for (auto& [val, mult] : groups) std::printf("    SV = %.6f, mult = %d\n", val, mult);
}

void analyze(int m) {
    PermIdx pi(m);
    auto D = enumerate_D(m);
    auto M = convolution_matrix(D, pi);
    auto svs = sorted_singular_values_desc(M);

    std::printf("--- Spectral analysis at m=%d ---\n", m);
    std::printf("  |S_m| = %d\n", (int)pi.perms.size());
    std::printf("  Top 6 SVs: ");
    for (int i = 0; i < std::min<int>(6, svs.size()); ++i) std::printf("%.4f ", svs[i]);
    std::printf("\n  sigma_2 = %.6f\n", svs[1]);

    std::printf("  SV multiplicity spectrum:\n");
    group_by_multiplicity(svs);

    // Diaconis-Shahshahani bound vs exact TV
    for (int k = 1; k <= 6; ++k) {
        double tv_exact = tv_to_uniform(convolve(D, k), m);
        double tv_bound = diaconis_shahshahani_bound(svs, k);
        std::printf("  k=%d: TV_exact = %.6f, DS_bound = %.6f  %s\n",
                    k, tv_exact, tv_bound, tv_exact <= tv_bound + 1e-10 ? "OK" : "FAIL");
    }

    // Friedrichs angles between column stabilizers
    int D_cols = num_columns(m);
    auto ws = wirings(m);
    auto K = column_stabilizer(m);
    std::vector<Mat> E;
    for (int t = 0; t < D_cols; ++t) E.push_back(averaging_projection(K, pi));

    std::printf("  Friedrichs angles between consecutive columns (with wirings):\n");
    for (int t = 0; t < D_cols - 1; ++t) {
        Mat w_mat = perm_matrix(ws[t + 1], pi);
        Mat conj = w_mat.transpose() * E[t + 1] * w_mat;
        double c = friedrichs_cos(E[t], conj);
        double theta_deg = std::acos(std::min(1.0, std::max(-1.0, c))) * 180.0 / M_PI;
        std::printf("    cos(theta'_%d) = %.6f, theta' = %.1f deg\n", t, c, theta_deg);
    }
    std::puts("");
}

}  // namespace

int main() {
    std::puts("=== Tool 3 — Path B: spectral / Friedrichs analysis (C++, Eigen) ===\n");
    analyze(2);
    analyze(4);
    std::puts("Session 6 finding: at m=4, cos(theta')=0.5, sigma_2 = 0.5^(D-1) = 0.25 exactly.");
    return 0;
}
