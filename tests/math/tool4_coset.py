"""
Tool 4 — Coset Factorization Calculus (SKELETON).

Theorem 4.2 (hiding characterization) is a knowledge-state theorem: given
which subset of {π, ρ_1, ρ_2, s} a party knows, its posterior on π is one
of:
  - if knows ρ_2 but neither ρ_1 nor s: guessing prob ≤ γ(D)
  - if knows ρ_1 (or s) but not ρ_2:      posterior = prior (perfect hiding)

This file simulates the knowledge-state machinery empirically at small m by
enumerating the derivation closure over F = {π, ρ_1, ρ_2, s} and computing
each party role's posterior on π.

Verification target for this session (partial):
  - Enumeration of all "knowledge states" and their closure under
    derivation rules.
  - For each state, compute the posterior distribution of π given that
    state and check against Theorem 4.2's claimed classification.

Corollary 4.3 (coalition matrix) skeleton also below: for each pair of
parties, compute their JOINT knowledge state and derive coalition capabilities.

Fully implementing Theorem 4.2 requires:
  - A model of π (target injection [c] → [m]) — small m, small c makes this
    trivially enumerable.
  - ρ_1 ← D (from Tool 2).
  - ρ_2 = π · ρ_1^{-1} — derivable computation.

DEFERRED to next session:
  - The both-blind XOR-shared variant proof (Prop 1.2 iii applied to ρ_1).
  - Formal simulator specification for the UC treatment.
"""

import math
from itertools import combinations


# ---------------------------------------------------------------------------
# Knowledge-state closure
# ---------------------------------------------------------------------------

FACTORS = ["pi", "rho1", "rho2", "s"]

# Derivation rules: (subset of factors known → factor derived).
# From the theory doc:
#   {pi, rho1}    → rho2  (since rho2 = pi * rho1^-1)
#   {pi, rho2}    → rho1
#   {rho1, rho2}  → pi
#   {s}           → rho1
DERIVATION_RULES = [
    ({"pi", "rho1"}, "rho2"),
    ({"pi", "rho2"}, "rho1"),
    ({"rho1", "rho2"}, "pi"),
    ({"s"}, "rho1"),
]


def closure(initial_set):
    """Repeatedly apply derivation rules until no new factor added."""
    known = set(initial_set)
    changed = True
    while changed:
        changed = False
        for prereqs, out in DERIVATION_RULES:
            if prereqs.issubset(known) and out not in known:
                known.add(out)
                changed = True
    return known


def hiding_classification(state):
    """
    Given a closed knowledge state, classify per Theorem 4.2:
      "full"      — state contains pi (or can derive it) → no hiding
      "gamma_D"   — state has rho2 but neither rho1 nor s → guessing bounded by γ(D)
      "perfect"   — state has rho1 (or s) but not rho2 → posterior = prior
      "trivial"   — state has neither rho1 nor rho2 → posterior = prior (also perfect)
    """
    closed = closure(state)
    if "pi" in closed:
        return "full_leak"
    if "rho2" in closed and "rho1" not in closed and "s" not in closed:
        return "gamma_D"
    if ("rho1" in closed or "s" in closed) and "rho2" not in closed:
        return "perfect"
    return "trivial"


def print_all_knowledge_states():
    """Enumerate all 2^4 = 16 knowledge states, show closure + classification."""
    print(f"{'state':<28} {'closure':<38} {'classification'}")
    print("-" * 90)
    for k in range(5):
        for state in combinations(FACTORS, k):
            state_set = set(state)
            closed = closure(state_set)
            cls = hiding_classification(state_set)
            state_str = "{" + ", ".join(sorted(state_set)) + "}" if state_set else "{}"
            closed_str = "{" + ", ".join(sorted(closed)) + "}"
            print(f"{state_str:<28} {closed_str:<38} {cls}")


# ---------------------------------------------------------------------------
# Party role assignments per the theory doc (§4, "The split, derived rather
# than designed"): each party's initial knowledge state.
# ---------------------------------------------------------------------------

PARTY_ROLES = {
    "Router":      {"s"},         # knows s hence rho1; never receives rho2
    "Matcher":     {"pi", "rho2"}, # holds pi and derived rho2 (matcher role)
    "Party P_i":   {"rho2"},       # receives rho2 from matcher only
}


def show_party_classifications():
    print("\n--- Per-role hiding classification (Theorem 4.2) ---")
    for role, state in PARTY_ROLES.items():
        cls = hiding_classification(state)
        closed = closure(state)
        print(f"  {role:<15} initial={sorted(state)}  closure={sorted(closed)}  → {cls}")


def show_coalitions():
    """Corollary 4.3 — coalition matrix by union of knowledge states."""
    print("\n--- Coalition matrix (Corollary 4.3) ---")
    roles = list(PARTY_ROLES.keys())
    for i, r1 in enumerate(roles):
        for r2 in roles[i:]:
            joined = PARTY_ROLES[r1] | PARTY_ROLES[r2]
            cls = hiding_classification(joined)
            closed = closure(joined)
            print(f"  {r1} + {r2:<15} joined={sorted(joined)}  "
                  f"closure={sorted(closed)}  → {cls}")


def main():
    print("=== Tool 4 — Coset factorization (SKELETON) ===\n")
    print("Enumeration of all 2^4 = 16 knowledge states, with closure and")
    print("Theorem-4.2 hiding classification.\n")
    print_all_knowledge_states()
    show_party_classifications()
    show_coalitions()
    print("\nDEFERRED:")
    print("  - Explicit simulator computations of posterior distributions (needs")
    print("    Tool 2 D-distribution + small-m π enumeration; feasible next session).")
    print("  - Both-blind XOR-shared-control variant (Prop 1.2(iii) applied to ρ_1).")
    print("  - Formal UC composition of the coset factorization.")


if __name__ == "__main__":
    main()
