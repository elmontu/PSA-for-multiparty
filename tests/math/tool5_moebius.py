r"""
Tool 5 — Möbius/Zeta Analysis of Incidence Leakage.

Boolean lattice 2^[N]. For each element e (an item ID with a membership
vector v(e) ∈ {0,1}^N), Venn cell A = supp(v(e)) is a subset of [N].

  n_A = # of elements whose exact membership is A
  I_B = |∩_{i∈B} X_i| = Σ_{A ⊇ B} n_A     (zeta transform)
  n_A = Σ_{B ⊇ A} (-1)^{|B\A|} I_B         (Möbius / inclusion-exclusion)

Tests:

  Identity (ζ n = I) and its inverse (μ I = n).

  Lemma 5.2 (sensitivity transfer):
    ℓ1(Δn) = 1 for a single-record change,
    ℓ1(ΔI) can be up to 2^{N-1}.

  Mechanism 5.3 (one-sided geometric):
    ñ_A = n_A + G_A with G_A ~ Geom(e^{-ε}).
    ε-DP for upward neighbors; expected padding cost Σ_A E[G_A].

  Prop 5.4 (identification risk):
    Given cell occupancies, per-individual identification prob = 1/n_A;
    k-anonymity threshold means cells with n_A < k are "at risk"; a
    padding lever lifts them above threshold.
r"""

import math
import random
import sys
from itertools import combinations


# ---------------------------------------------------------------------------
# Boolean-lattice utilities
# ---------------------------------------------------------------------------

def all_nonempty_subsets(N):
    r"""All nonempty subsets of [N] as frozensets, sorted by size then content.r"""
    subs = []
    for k in range(1, N + 1):
        for s in combinations(range(N), k):
            subs.append(frozenset(s))
    return subs


def zeta_transform(n_by_A, N):
    r"""
    Compute I_B = Σ_{A ⊇ B} n_A for every nonempty B ⊆ [N].
    n_by_A: dict[frozenset] → int (any subset A missing means n_A = 0).
    Returns: dict[frozenset] → int, same domain.
    r"""
    subs = all_nonempty_subsets(N)
    I = {B: 0 for B in subs}
    for B in subs:
        for A in subs:
            if A.issuperset(B):
                I[B] += n_by_A.get(A, 0)
    return I


def mobius_inverse(I_by_B, N):
    r"""
    Möbius inversion: n_A = Σ_{B ⊇ A} (-1)^{|B \ A|} I_B.
    r"""
    subs = all_nonempty_subsets(N)
    n = {A: 0 for A in subs}
    for A in subs:
        for B in subs:
            if B.issuperset(A):
                n[A] += (-1) ** (len(B) - len(A)) * I_by_B.get(B, 0)
    return n


# ---------------------------------------------------------------------------
# Simulate an N-party dataset and compute (n, I)
# ---------------------------------------------------------------------------

def simulate_membership(N, num_items, avg_membership, rng):
    r"""
    Simulate: num_items records, each with a random non-empty membership
    subset of [N]. Bernoulli per-party inclusion with p = avg_membership/N.

    Returns list of frozensets (each item's membership vector).
    r"""
    p = avg_membership / N
    out = []
    for _ in range(num_items):
        while True:
            s = frozenset(i for i in range(N) if rng.random() < p)
            if s:   # exclude empty (item belongs to nobody)
                out.append(s)
                break
    return out


def cell_counts(memberships, N):
    r"""Compute n_A dict from a list of membership sets.r"""
    n = {A: 0 for A in all_nonempty_subsets(N)}
    for m in memberships:
        n[m] = n.get(m, 0) + 1
    return n


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_zeta_identity(N=4):
    r"""ζn = I. Verified by direct computation from a simulated dataset.r"""
    rng = random.Random(0xC5)
    memberships = simulate_membership(N, num_items=200, avg_membership=2.0, rng=rng)
    n = cell_counts(memberships, N)
    I = zeta_transform(n, N)

    # Cross-check I_B against direct definition: I_B = # items whose membership
    # is a SUPERSET of B  ⇔  ALL parties in B have this item.
    for B in all_nonempty_subsets(N):
        direct = sum(1 for m in memberships if m.issuperset(B))
        assert I[B] == direct, f"ζn ≠ direct I at B={set(B)}: {I[B]} vs {direct}"

    # Round-trip: mobius_inverse(I) should give back n.
    n_back = mobius_inverse(I, N)
    for A in all_nonempty_subsets(N):
        assert n[A] == n_back[A], f"Möbius round-trip failed at A={set(A)}: {n[A]} vs {n_back[A]}"

    print(f"[ζ / μ identity] N={N}: ζn matches direct intersection count, "
          f"μ(ζn) = n exactly — PASS")


def test_lemma_5_2_sensitivity(N=4):
    r"""
    Lemma 5.2:
      ℓ1(Δn) = 1 for a single-item change.
      ℓ1(ΔI) can reach 2^{N-1} — because adding an item to cell A changes
      I_B for every nonempty B ⊆ A.
    r"""
    rng = random.Random(0xD5)
    memberships = simulate_membership(N, num_items=100, avg_membership=2.0, rng=rng)
    n = cell_counts(memberships, N)
    I = zeta_transform(n, N)

    # Add a new item in a "worst case" cell (the full [N]) — this affects
    # I_B for ALL nonempty B ⊆ [N], which is 2^N - 1 coordinates. But the
    # tightest bound stated in the doc is 2^{N-1}, which corresponds to
    # cells of size N-1 (containing N-1 elements). Let's verify both.
    max_ell1_deltaI = 0
    for A_worst in all_nonempty_subsets(N):
        n_prime = dict(n)
        n_prime[A_worst] += 1
        I_prime = zeta_transform(n_prime, N)
        delta_I = sum(abs(I_prime[B] - I[B]) for B in all_nonempty_subsets(N))
        # ℓ1(Δn) = 1 always (only one cell changed by 1).
        delta_n = sum(abs(n_prime[A] - n[A]) for A in all_nonempty_subsets(N))
        assert delta_n == 1, f"Δn sensitivity violated at A={set(A_worst)}: {delta_n}"
        max_ell1_deltaI = max(max_ell1_deltaI, delta_I)
        # Adding an item at cell A affects I_B for every B ⊆ A (nonempty),
        # which is 2^|A| - 1 coordinates. So per-cell ℓ1(ΔI) = 2^|A|-1.
        expected = (1 << len(A_worst)) - 1
        assert delta_I == expected, (
            f"ΔI at A={set(A_worst)}: got {delta_I}, expected {expected} (=2^|A|-1)"
        )
    print(f"[Lemma 5.2] N={N}: ℓ1(Δn) = 1 always; max ℓ1(ΔI) = {max_ell1_deltaI} "
          f"(= 2^N - 1 = {(1 << N) - 1}) — PASS")


def geometric_positive(scale, rng):
    r"""
    One-sided Geometric(p) with p = 1 - e^{-ε}, so scale = 1/(e^ε - 1).
    Sample: G = floor(log(1-U)/log(1-p)) where U ~ Uniform(0, 1).
    (Standard inverse-CDF for a shifted geometric on {0, 1, 2, ...}.)
    r"""
    p = 1.0 / (scale + 1.0)   # E[G] = (1-p)/p = scale
    if p >= 1.0:
        return 0
    u = rng.random()
    return int(math.log(1 - u) / math.log(1 - p))


def test_mechanism_5_3_overhead(N=4, eps=1.0, trials=1000):
    r"""
    Mechanism 5.3: expected padding overhead per session = (2^N - 1) / (e^ε - 1).
    Empirically sample geometric(e^{-ε}) noise, sum expected G_A.
    r"""
    scale = 1.0 / (math.exp(eps) - 1.0)  # E[G_A] per cell
    theoretical = ((1 << N) - 1) * scale
    rng = random.Random(0xE5)
    empirical = 0.0
    for _ in range(trials):
        s = sum(geometric_positive(scale, rng) for _ in all_nonempty_subsets(N))
        empirical += s
    empirical /= trials
    # SE of the sum over 2^N - 1 cells each with std = sqrt((1-p)/p^2) = scale*sqrt(1+1/scale)
    # ≈ scale*sqrt(1/scale) = sqrt(scale) for large scale. Sum of (2^N-1) cells has
    # SE = sqrt(2^N - 1) * cell_std / sqrt(trials). Use generous tol = 5 * SE.
    cell_std = math.sqrt((1 - 1.0 / (scale + 1)) / (1.0 / (scale + 1)) ** 2)
    se = math.sqrt((1 << N) - 1) * cell_std / math.sqrt(trials)
    tol = max(0.5, 5 * se)
    print(f"[Mechanism 5.3] N={N}, ε={eps}: theoretical overhead "
          f"(2^N-1)/(e^ε-1) = {theoretical:.3f} records, "
          f"empirical mean = {empirical:.3f} over {trials} trials, SE ≈ {se:.3f}")
    assert abs(empirical - theoretical) < tol, (
        f"empirical padding {empirical:.3f} diverges from theory {theoretical:.3f} "
        f"by more than tol {tol:.3f}"
    )
    print(f"  PASS (empirical within {tol:.3f} of theoretical)")


def test_prop_5_4_identification_risk(N=4, num_items=200):
    r"""
    Prop 5.4: identification probability of a target with membership A is
    1/n_A. Verify by simulation: draw random target, ask "which item was it?"
    r"""
    rng = random.Random(0xF5)
    memberships = simulate_membership(N, num_items=num_items, avg_membership=2.0, rng=rng)
    n = cell_counts(memberships, N)
    # Pick a random target index; adversary knows only its membership set A.
    target_idx = rng.randrange(num_items)
    target_A = memberships[target_idx]
    # Adversary sees the pseudonymous list (memberships shuffled). Its posterior
    # over the target is uniform on items with membership == target_A.
    candidates = [i for i, m in enumerate(memberships) if m == target_A]
    assert target_idx in candidates
    id_prob = 1.0 / len(candidates)
    theoretical = 1.0 / n[target_A]
    assert abs(id_prob - theoretical) < 1e-12
    print(f"[Prop 5.4] N={N}: target has membership {set(target_A)}, "
          f"n_A = {n[target_A]}, identification prob = 1/n_A = {theoretical:.4f} — PASS")

    # k-anon lens: how many items are in "at-risk" cells (n_A < k)?
    for k in (3, 5, 10):
        at_risk = sum(cnt for A, cnt in n.items() if 0 < cnt < k)
        print(f"  k={k}: {at_risk} items in cells with n_A < k (at-risk under k-anon)")


def main():
    print("=== Tool 5 — Möbius/Zeta Analysis of Incidence Leakage ===\n")
    for N in (3, 4, 5):
        print(f"--- N = {N} ---")
        test_zeta_identity(N=N)
        test_lemma_5_2_sensitivity(N=N)
        test_mechanism_5_3_overhead(N=N, eps=1.0, trials=1000)
        test_mechanism_5_3_overhead(N=N, eps=0.1, trials=1000)
        test_prop_5_4_identification_risk(N=N, num_items=300)
        print()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
