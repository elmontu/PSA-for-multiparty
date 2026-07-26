"""
Tool 3 — Mixing Amplification via Products of Projections (SKELETON).

Target: TV(D^{*k}, Unif) ≤ ε for k = O(log m + log(1/ε)).

Two paths for empirical validation at small m:

  Path A (direct): compute exact D^{*k} distribution over S_m for small m.
    D itself is computable from tool2's multiplicity_map (each σ has probability
    M(σ)/2^S). D^{*k} = convolution on the group. Feasible for m ∈ {2, 4}
    where |S_m| = 2, 24; up to m=4 we can convolve exactly a few times.

  Path B (Fourier): compute Fourier transform D̂(λ) for each irrep λ of S_m
    using SymPy or direct character-table access. Norms of D̂(λ) give
    Diaconis-Shahshahani upper bound on TV. Cleanest per the doc but
    requires representation-theory machinery.

  Path C (Monte Carlo): sample many k-fold compositions and estimate TV
    to uniform via chi-square. Cheap; only gives loose estimates.

THIS FILE currently: Path A implemented for m ∈ {2, 4}; Paths B and C flagged
for next-session work.

Open items from the theory doc (Tool 3):
  - Compute Friedrichs angle between Fix(K_t) and Fix(K_{t+1}) in each irrep
    of S_m via domino tableaux. Requires SymPy + character tables + branching
    rule S_m ↓ S_2 ≀ S_{m/2}. Multi-hour SymPy work.
  - Verify conjectured k = O(log m + log 1/ε) rate.
"""

import math
import sys
import os
from collections import Counter
sys.path.insert(0, os.path.dirname(__file__))

from benes import (
    num_columns, total_switches, rho, settings_from_int,
)
from itertools import permutations


def all_perms(m):
    return list(permutations(range(m)))


def enumerate_D(m):
    """
    Enumerate the pre-colored distribution D on S_m.
    Returns dict[tuple_perm] → probability. Feasible for m up to 8
    (S=20 → 2^20 ≈ 1M enumerations).
    """
    S = total_switches(m)
    counts = Counter()
    for n in range(1 << S):
        s = settings_from_int(m, n)
        counts[tuple(rho(m, s))] += 1
    total = 1 << S
    return {perm: c / total for perm, c in counts.items()}


def perm_mul(p, q):
    """(p·q)[i] = p[q[i]] — permutation composition, standard convention."""
    return tuple(p[q[i]] for i in range(len(p)))


def convolve_D(D_dist, k, m):
    """
    D^{*k}: k-fold convolution of D on S_m.
    Sparse dictionary convolution; feasible only for small m.
    """
    cur = D_dist
    for _ in range(k - 1):
        nxt = Counter()
        for p, pp in cur.items():
            for q, qp in D_dist.items():
                nxt[perm_mul(p, q)] += pp * qp
        cur = dict(nxt)
    return cur


def tv_to_uniform(dist, m):
    """Total variation distance to uniform on S_m."""
    mfact = math.factorial(m)
    u = 1.0 / mfact
    perms = all_perms(m)
    tv = 0.0
    for perm in perms:
        tv += abs(dist.get(perm, 0.0) - u)
    return 0.5 * tv


def main():
    print("=== Tool 3 — Mixing amplification (SKELETON, path A) ===\n")

    for m in (2, 4):
        print(f"--- m = {m}, |S_m| = {math.factorial(m)} ---")
        D = enumerate_D(m)
        tv1 = tv_to_uniform(D, m)
        print(f"  k=1 (single Beneš):  TV(D, Unif) = {tv1:.6f}")

        max_k = 3 if m == 4 else 8   # convolution cost grows fast
        for k in range(2, max_k + 1):
            Dk = convolve_D(D, k, m)
            tvk = tv_to_uniform(Dk, m)
            print(f"  k={k}:                 TV(D^*{k}, Unif) = {tvk:.6f}")
        print()

    print("NOTES:")
    print("  - Path A limited to m ≤ 4 due to convolution cost.")
    print("  - Paths B (Fourier via SymPy) and C (Monte Carlo) deferred.")
    print("  - Friedrichs-angle analysis deferred (needs domino tableaux).")


if __name__ == "__main__":
    main()
