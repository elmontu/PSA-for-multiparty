"""
Tool 2 — Min-Entropy of Pre-Colored Sampling (distribution D).

Tests (all empirical or exhaustive for small m):

  Lemma 2.2 (single-column injectivity):  γ(D) ≤ 2^{-m/2}
    Empirical multiplicity check: enumerate settings, compute M(σ),
    verify max_σ M(σ) / 2^S ≤ 2^{-m/2}.

  Lemma 2.4 (exact marginal uniformity): for every input i,
    Pr_{ρ~D}[ρ(i) = j] = 1/m for every j.
    Verified two ways:
      (a) exhaustive over settings (small m only)
      (b) doubly-stochastic matrix-product argument, per the sketch's
          "repair": columnwise averaged action is doubly stochastic,
          composition preserves the uniform vector.

  Prop 2.5 (multiplicity recursion): sanity-check by counting M(σ)
    exhaustively at small m and confirming the sum ΣM(σ) = 2^S.

  Conjecture 2.6: empirical H_∞(D) at small m to check the
    m log m - Θ(m) scaling claim. Numerical support only.
"""

import math
import random
import sys
import os
from collections import Counter
sys.path.insert(0, os.path.dirname(__file__))

from benes import (
    num_columns, num_switches_per_column, total_switches,
    rho, apply_column, apply_wiring, wirings, settings_from_int,
    random_settings, is_permutation,
)


# ---------------------------------------------------------------------------
# Exhaustive enumeration → multiplicity distribution M(σ)
# ---------------------------------------------------------------------------

def multiplicity_map(m):
    """
    For each realizable σ, count how many s ∈ {0,1}^S map to it.
    Returns dict[tuple[int]] = M(σ). Feasible up to S ≈ 22 (~ 4M enum).
    """
    S = total_switches(m)
    counts = Counter()
    for n in range(1 << S):
        s = settings_from_int(m, n)
        p = tuple(rho(m, s))
        counts[p] += 1
    return counts


def test_lemma_2_2_multiplicity_bound(m):
    """
    Lemma 2.2: γ(D) ≤ 2^{-m/2}.

    γ(D) = max_σ M(σ) / 2^S.
    Equivalently: max M(σ) ≤ 2^{S - m/2}.
    """
    S = total_switches(m)
    if S > 22:
        print(f"[Lemma 2.2] m={m}: S={S} too large for enumeration — SKIP")
        return
    mult = multiplicity_map(m)
    max_M = max(mult.values())
    bound = 1 << (S - m // 2)          # 2^{S - m/2}
    gamma = max_M / (1 << S)           # max_σ Pr[ρ = σ]
    theoretical_gamma = 1.0 / (1 << (m // 2))   # 2^{-m/2}
    print(f"[Lemma 2.2] m={m}: max M(σ) = {max_M}, bound 2^(S-m/2) = {bound},"
          f" γ = {gamma:.6g}, theoretical γ ≤ 2^(-m/2) = {theoretical_gamma:.6g}")
    assert max_M <= bound, f"Lemma 2.2 violated at m={m}: {max_M} > {bound}"
    assert gamma <= theoretical_gamma + 1e-12
    print(f"  PASS (bound holds; ratio actual/theoretical = {gamma/theoretical_gamma:.4f})")


def test_prop_2_5_settings_sum(m):
    """
    Prop 2.5: sanity — Σ_σ M(σ) = 2^S (every setting counted exactly once).
    """
    S = total_switches(m)
    if S > 22:
        print(f"[Prop 2.5] m={m}: S={S} too large — SKIP")
        return
    mult = multiplicity_map(m)
    total = sum(mult.values())
    assert total == (1 << S), f"sum mismatch at m={m}: {total} != 2^{S}"
    print(f"[Prop 2.5] m={m}: Σ M(σ) = {total} = 2^{S} — PASS")


def test_conjecture_2_6_empirical_h_infty(m):
    """
    Conjecture 2.6: H_∞(D) = m log m - Θ(m).
    m log m - m/2 = S (total switches), so H_∞ ≤ S.
    The lower bound Lemma 2.2 says H_∞ ≥ m/2.
    The conjecture: H_∞ ~ S - Θ(m), which is m log m - O(m).

    We compute empirical H_∞ and report where it sits.
    """
    S = total_switches(m)
    if S > 22:
        print(f"[Conj 2.6] m={m}: S={S} too large for exact enumeration — SKIP")
        return
    mult = multiplicity_map(m)
    max_M = max(mult.values())
    h_infty = math.log2((1 << S) / max_M)
    lower = m // 2                       # Lemma 2.2 lower bound
    upper = S                            # trivial upper (uniform on 2^S)
    conjectured = S - m                  # ~ conjecture midpoint (θ(m) slack)
    perms_realized = len(mult)
    print(f"[Conj 2.6] m={m}: S={S}, empirical H_∞(D) = {h_infty:.4f} bits, "
          f"Lemma 2.2 lower = m/2 = {lower}, S = {S}, "
          f"conjecture region S-Θ(m) ≈ {conjectured}, "
          f"|supp(D)| = {perms_realized}/{math.factorial(m)}")


# ---------------------------------------------------------------------------
# Lemma 2.4 — exact marginal uniformity via doubly stochastic matrix product
# ---------------------------------------------------------------------------
# Proof completion: each averaged column action A_t is a m×m doubly
# stochastic matrix. Composition of doubly stochastic matrices is doubly
# stochastic. The averaged network M = W_D · A_D · W_{D-1} · ... · A_1 · W_0
# maps the uniform vector u = (1/m,...,1/m) to itself, so E_{s}[ρ(s)(i) = j]
# = 1/m for every i, j.
#
# We verify:
#   (a) Each averaged column matrix A_t is doubly stochastic.
#   (b) The full averaged product M is doubly stochastic AND all its rows
#       and columns are the uniform vector (i.e., M(i,j) = 1/m for all i, j).
#   (c) For small m, cross-check against exhaustive enumeration of Pr[ρ(i)=j].

def averaged_column_matrix(m):
    """
    A_t = (1/2^{m/2}) Σ_{b ∈ {0,1}^{m/2}} P_{κ_t(b)}
    where P_{κ_t(b)} is the m×m permutation matrix for κ_t(b).

    Since the m/2 switches are disjoint and each swap acts on a 2-cycle
    independently, A_t factors as a Kronecker sum: for each pair (2j, 2j+1),
    A_t restricted to those two rows/cols is (1/2)*(I + [[0,1],[1,0]])
    which is (1/2) * (all-ones on the 2x2 block). Off-block entries: 0.

    So A_t is block-diagonal with m/2 identical 2x2 blocks = 0.5 * [[1,1],[1,1]].
    """
    per_col = num_switches_per_column(m)
    A = [[0.0] * m for _ in range(m)]
    for j in range(per_col):
        # 2x2 uniform mixing on rows/cols {2j, 2j+1}
        A[2*j][2*j] = 0.5
        A[2*j][2*j+1] = 0.5
        A[2*j+1][2*j] = 0.5
        A[2*j+1][2*j+1] = 0.5
    return A


def wiring_matrix(w):
    """Permutation matrix for wiring w."""
    m = len(w)
    W = [[0.0] * m for _ in range(m)]
    for i in range(m):
        W[i][w[i]] = 1.0
    return W


def matmul(A, B):
    n = len(A)
    m = len(B[0])
    inner = len(B)
    C = [[0.0] * m for _ in range(n)]
    for i in range(n):
        for k in range(inner):
            if A[i][k] == 0.0:
                continue
            for j in range(m):
                C[i][j] += A[i][k] * B[k][j]
    return C


def is_doubly_stochastic(M, tol=1e-9):
    n = len(M)
    for i in range(n):
        rs = sum(M[i])
        if abs(rs - 1.0) > tol:
            return False
    for j in range(n):
        cs = sum(M[i][j] for i in range(n))
        if abs(cs - 1.0) > tol:
            return False
    return True


def is_uniform_matrix(M, tol=1e-9):
    n = len(M)
    target = 1.0 / n
    for i in range(n):
        for j in range(n):
            if abs(M[i][j] - target) > tol:
                return False
    return True


def test_lemma_2_4_matrix_argument(m):
    """
    Compute the full averaged network matrix M and verify:
      - each A_t doubly stochastic
      - product is doubly stochastic
      - product is UNIFORM (every entry = 1/m)
    """
    A = averaged_column_matrix(m)
    assert is_doubly_stochastic(A), f"averaged column not doubly stochastic at m={m}"

    D = num_columns(m)
    ws = wirings(m)
    # M = W_D · A · W_{D-1} · A · ... · W_1 · A · W_0
    # (each column contributes A; wirings interleaved.)
    M = wiring_matrix(ws[0])
    for t in range(D):
        M = matmul(A, M)
        M = matmul(wiring_matrix(ws[t + 1]), M)
    assert is_doubly_stochastic(M), f"product not doubly stochastic at m={m}"
    assert is_uniform_matrix(M), f"product not uniform at m={m}: e.g. M[0]={M[0]}"
    print(f"[Lemma 2.4-matrix] m={m}: averaged network matrix is exactly uniform (1/m in every cell) — PASS")


def test_lemma_2_4_exhaustive(m):
    """Cross-check by enumerating all settings and computing marginal Pr[ρ(i)=j]."""
    S = total_switches(m)
    if S > 20:
        print(f"[Lemma 2.4-exh] m={m}: S={S} too large — SKIP")
        return
    counts = [[0] * m for _ in range(m)]
    for n in range(1 << S):
        s = settings_from_int(m, n)
        p = rho(m, s)
        for i in range(m):
            counts[i][p[i]] += 1
    # Every counts[i][j] should equal 2^S / m
    expected = (1 << S) // m
    ok = True
    for i in range(m):
        for j in range(m):
            if counts[i][j] != expected:
                ok = False
                print(f"  MISMATCH i={i} j={j}: counts={counts[i][j]} expected={expected}")
                break
        if not ok: break
    assert ok, f"exhaustive marginal not uniform at m={m}"
    print(f"[Lemma 2.4-exh] m={m}: exhaustive enumeration confirms every marginal is exactly 1/m — PASS")


def main():
    print("=== Tool 2 — Min-Entropy of D ===\n")
    for m in (2, 4, 8):
        print(f"--- m = {m} ---")
        test_lemma_2_2_multiplicity_bound(m)
        test_prop_2_5_settings_sum(m)
        test_conjecture_2_6_empirical_h_infty(m)
        test_lemma_2_4_matrix_argument(m)
        test_lemma_2_4_exhaustive(m)
        print()
    for m in (16, 32):
        print(f"--- m = {m} (matrix-only; enumeration too large) ---")
        test_lemma_2_4_matrix_argument(m)
        print()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
