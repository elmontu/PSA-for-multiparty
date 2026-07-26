"""
Tool 1 — Column-Homomorphism Structure of Switching Networks.

Verifies Proposition 1.2 computationally:
  (i)  Every setting yields a valid permutation.
  (ii) [structural, verified by construction of benes.py]
  (iii) XOR-splitting identity:
        ρ(a ⊕ b) = w_0 · κ_1(a_1) κ_1(b_1) · w_1 · ... · κ_D(a_D) κ_D(b_D) · w_D
        i.e., the network with additively shared control equals a 2D-layer
        alternating product of two shares' effects.

For (iii), we need to be careful about the equivalence claim. The doc says
this is "identically" a 2D-layer alternating product. The verification is:
   ρ(a XOR b)   ==   w_0 · κ_1(a_1) · κ_1(b_1) · w_1 · κ_2(a_2) · κ_2(b_2) · w_2 · ... · w_D
That is, INSIDE each column, replace κ_t(a_t XOR b_t) with the composed
pair κ_t(a_t)κ_t(b_t). Because κ_t is a homomorphism into an ABELIAN
subgroup (K_t ≅ (Z/2)^{m/2}), κ_t(a XOR b) = κ_t(a) · κ_t(b) as a group
element, so the WHOLE network's output is unchanged when we substitute
this equality columnwise.

Test: for random (a, b) pairs, compute both sides and check equality.
"""

import random
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from benes import (
    num_columns, total_switches, rho, apply_column, apply_wiring,
    random_settings, settings_from_int, wirings, is_permutation,
)


def xor_settings(a, b):
    """Elementwise XOR of two switch-setting bundles."""
    return [[ai ^ bi for ai, bi in zip(ac, bc)] for ac, bc in zip(a, b)]


def rho_via_split(m, a, b, ws=None):
    """
    Compute the RHS of Prop 1.2 (iii): apply w_0, then κ_1(a_1) then κ_1(b_1),
    then w_1, then κ_2(a_2) then κ_2(b_2), then w_2, ..., then w_D.

    This differs from rho(m, a XOR b) only structurally — the group-theoretic
    result must be identical by the abelian-homomorphism property of κ_t.
    """
    D = num_columns(m)
    if ws is None:
        ws = wirings(m)
    perm = list(range(m))
    perm = apply_wiring(perm, ws[0])
    for t in range(D):
        perm = apply_column(perm, a[t])   # κ_t(a_t)
        perm = apply_column(perm, b[t])   # κ_t(b_t)
        perm = apply_wiring(perm, ws[t + 1])
    return perm


def test_prop_1_2_i_bijection(m, num_trials=200, seed=0xA1):
    """Every setting → bijection."""
    rng = random.Random(seed)
    for _ in range(num_trials):
        s = random_settings(m, rng)
        p = rho(m, s)
        assert is_permutation(p), f"non-bijection at m={m}: rho={p}"
    print(f"[Tool 1.i] m={m}: {num_trials} random settings all bijections — PASS")


def test_prop_1_2_i_bijection_exhaustive(m):
    """Enumerate ALL settings and check bijectivity (only feasible for small m)."""
    S = total_switches(m)
    if S > 20:
        print(f"[Tool 1.i-exh] m={m}: S={S} too large to enumerate — SKIP")
        return
    for n in range(1 << S):
        s = settings_from_int(m, n)
        p = rho(m, s)
        assert is_permutation(p), f"non-bijection at m={m}, s(int)={n}: {p}"
    print(f"[Tool 1.i-exh] m={m}: all 2^{S} settings are bijections — PASS")


def test_prop_1_2_iii_xor_split(m, num_trials=200, seed=0xB2):
    """
    XOR-split identity: rho(a XOR b) == rho_via_split(a, b).
    """
    rng = random.Random(seed)
    for trial in range(num_trials):
        a = random_settings(m, rng)
        b = random_settings(m, rng)
        left  = rho(m, xor_settings(a, b))
        right = rho_via_split(m, a, b)
        assert left == right, (
            f"XOR-split failed at m={m} trial {trial}:\n"
            f"  a={a}\n  b={b}\n"
            f"  rho(a XOR b) = {left}\n"
            f"  split         = {right}"
        )
    print(f"[Tool 1.iii] m={m}: {num_trials} random (a,b) pairs — XOR-split identity holds — PASS")


def test_prop_1_2_iii_exhaustive(m):
    """Exhaustive XOR-split check (only for very small m)."""
    S = total_switches(m)
    if S > 12:
        print(f"[Tool 1.iii-exh] m={m}: S={S} too large — SKIP")
        return
    for an in range(1 << S):
        a = settings_from_int(m, an)
        for bn in range(1 << S):
            b = settings_from_int(m, bn)
            left  = rho(m, xor_settings(a, b))
            right = rho_via_split(m, a, b)
            assert left == right, f"failed at m={m}, a={an}, b={bn}"
    print(f"[Tool 1.iii-exh] m={m}: all 2^{S}·2^{S} = 2^{2*S} (a,b) pairs — PASS")


def main():
    print("=== Tool 1 — Column-Homomorphism verification ===\n")
    for m in (2, 4, 8, 16, 32):
        print(f"--- m = {m} ---")
        test_prop_1_2_i_bijection(m, num_trials=200)
        test_prop_1_2_i_bijection_exhaustive(m)
        test_prop_1_2_iii_xor_split(m, num_trials=200)
        test_prop_1_2_iii_exhaustive(m)
        print()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
