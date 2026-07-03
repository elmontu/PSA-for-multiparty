#!/usr/bin/env python3
"""
Test harness for demos/vfl_xgboost_double_blind.py.

Validates FOUR properties:

  1. CORRECTNESS: the VFL-mock accuracy equals the plaintext-baseline
     accuracy across multiple seeds and hyperparameter settings.
     The mock Paillier is arithmetically exact, so any deviation means
     the code paths diverge on structural (non-arithmetic) grounds.

  2. SECURITY INVARIANT: Party A cannot decrypt ciphertext handles —
     they can only add and pass them around. Any decrypt attempt on
     the A side would violate the double-blind property.

  3. CROSS-PARTY UTILITY: split candidates from BOTH parties get
     chosen. If the VFL protocol only ever picks Party B's features
     (which are trivially free), it would degenerate to a single-party
     model even though the API supports both.

  4. NONTRIVIAL SIGNAL: model accuracy is meaningfully above a
     50%-guess baseline. Rules out silent regressions where the model
     always predicts one class.

Run:
    python3 tests/test_vfl_xgboost_demo.py
Exit code 0 iff all checks pass.
"""

import importlib.util
import os
import sys
import traceback
from typing import List, Tuple

import numpy as np

# Import the demo as a module so we can call its functions directly.
DEMO_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "demos", "vfl_xgboost_double_blind.py",
)
spec = importlib.util.spec_from_file_location("vfl_demo", DEMO_PATH)
vfl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vfl)


# =====================================================================
# Test infrastructure
# =====================================================================
def _report(name: str, ok: bool, detail: str = "") -> Tuple[str, bool]:
    marker = "PASS" if ok else "FAIL"
    print(f"  {marker}  {name}{('  — ' + detail) if detail else ''}")
    return name, ok


def _accuracy(trees, pa, pb) -> float:
    raw = vfl.ensemble_predict(trees, pa, pb)
    pred = (vfl.sigmoid(raw) > 0.5).astype(int)
    return float((pred == pb.labels).mean())


def _combined_view(pa, pb):
    """Match the demo's combined-features baseline eval trick."""
    combined_A = vfl.PartyA(
        name="aggregator",
        features=np.concatenate([pa.features, pb.features], axis=1),
        feature_names=list(pa.feature_names) + list(pb.feature_names),
    )
    null_B = vfl.PartyB(
        name="null_B",
        features=np.zeros((pb.features.shape[0], 0)),
        feature_names=[],
        labels=pb.labels,
    )
    return combined_A, null_B


def _train_pair(seed: int, n_train=300, n_test=150, rounds=6, depth=3,
                lr=0.3, lam=1.0, min_gain=0.0):
    """Train BOTH the VFL model and the plaintext baseline, return
    (vfl_trees, baseline_trees, parties, paillier)."""
    X_A, X_B, y = vfl.make_synthetic_data(n_train + n_test, seed=seed)
    X_A_tr, X_A_te = X_A[:n_train], X_A[n_train:]
    X_B_tr, X_B_te = X_B[:n_train], X_B[n_train:]
    y_tr, y_te = y[:n_train], y[n_train:]

    pa_tr = vfl.PartyA(name="pa", features=X_A_tr,
                       feature_names=["A0", "A1"])
    pb_tr = vfl.PartyB(name="pb", features=X_B_tr,
                       feature_names=["B0", "B1"], labels=y_tr)
    pa_te = vfl.PartyA(name="pa", features=X_A_te,
                       feature_names=["A0", "A1"])
    pb_te = vfl.PartyB(name="pb", features=X_B_te,
                       feature_names=["B0", "B1"], labels=y_te)

    vfl_trees, paillier = vfl.train_boosted_vfl(
        pa_tr, pb_tr,
        n_rounds=rounds, learning_rate=lr,
        max_depth=depth, lam=lam, min_gain=min_gain)

    baseline_trees = vfl.train_plaintext_baseline(
        pa_tr, pb_tr,
        n_rounds=rounds, learning_rate=lr,
        max_depth=depth, lam=lam, min_gain=min_gain)

    return (vfl_trees, baseline_trees,
            (pa_tr, pb_tr, pa_te, pb_te), paillier)


# =====================================================================
# Individual test cases
# =====================================================================
def test_correctness_matches_baseline_across_seeds() -> Tuple[str, bool]:
    """Test 1: VFL accuracy == baseline accuracy across 5 seeds and 2
    depth settings.

    Since the mock Paillier is exact-arithmetic, any accuracy deviation
    signals a structural divergence between the code paths.
    """
    configs = [(seed, depth) for seed in [1, 7, 13, 42, 99] for depth in [2, 3]]
    mismatches: List[str] = []
    for seed, depth in configs:
        vfl_trees, base_trees, (pa_tr, pb_tr, pa_te, pb_te), _ = \
            _train_pair(seed=seed, depth=depth, rounds=5)

        # VFL uses native (pa, pb); baseline needs combined view.
        vfl_test_acc = _accuracy(vfl_trees, pa_te, pb_te)
        base_pa_te, base_pb_te = _combined_view(pa_te, pb_te)
        base_test_acc = _accuracy(base_trees, base_pa_te, base_pb_te)

        if abs(vfl_test_acc - base_test_acc) > 1e-9:
            mismatches.append(
                f"seed={seed} depth={depth}: "
                f"vfl={vfl_test_acc:.6f} base={base_test_acc:.6f}")
    ok = (len(mismatches) == 0)
    detail = "" if ok else (f"{len(mismatches)}/{len(configs)} configs diverged: "
                             + "; ".join(mismatches[:3]))
    return _report("correctness_matches_baseline_across_seeds", ok, detail)


def test_party_A_cannot_decrypt() -> Tuple[str, bool]:
    """Test 2: Enforce API discipline — Party A can only add/scale;
    only Party B has decrypt_B. Attempt any decrypt from an "A context"
    should raise / not exist.

    Since Python doesn't enforce access control natively, we verify by
    inspecting the MockPaillier class shape.
    """
    p = vfl.MockPaillier()
    a_methods = {"add_A", "scale_A"}
    b_methods = {"encrypt_B", "decrypt_B"}
    # A methods should exist; A should NOT be able to see plaintext.
    for m in a_methods:
        if not hasattr(p, m):
            return _report("party_A_cannot_decrypt", False,
                           f"A method {m} missing")
    for m in b_methods:
        if not hasattr(p, m):
            return _report("party_A_cannot_decrypt", False,
                           f"B method {m} missing")

    # Enforce naming discipline: any method ending in "_A" must not
    # return floats/ints — only int handles.
    handles = p.encrypt_B([1.5, -2.0, 3.25])
    add_result = p.add_A(handles)
    scale_result = p.scale_A(handles[0], 2.0)
    if not isinstance(add_result, int) or not isinstance(scale_result, int):
        return _report("party_A_cannot_decrypt", False,
                       "A ops returned plaintext")

    # decrypt_B must be the ONLY way to read plaintext.
    plain = p.decrypt_B(add_result)
    if abs(plain - 2.75) > 1e-9:
        return _report("party_A_cannot_decrypt", False,
                       f"decrypt returned wrong value: {plain}")
    return _report("party_A_cannot_decrypt", True)


def test_cross_party_utility() -> Tuple[str, bool]:
    """Test 3: over the ensemble, splits use features from BOTH parties.

    If Party A features are never picked, the protocol degenerates and
    the demo is a lie about its cross-party utility.
    """
    vfl_trees, _, _, _ = _train_pair(seed=42, depth=3, rounds=8)

    def collect_split_parties(node) -> List[str]:
        if node.is_leaf:
            return []
        return ([node.split_party]
                + collect_split_parties(node.left)
                + collect_split_parties(node.right))

    all_splits: List[str] = []
    for tree, _ in vfl_trees:
        all_splits.extend(collect_split_parties(tree))

    a_count = all_splits.count("A")
    b_count = all_splits.count("B")
    total = len(all_splits)
    if total == 0:
        return _report("cross_party_utility", False,
                       "no splits found across ensemble")

    a_frac = a_count / total
    b_frac = b_count / total
    ok = (a_count > 0 and b_count > 0
          and a_frac >= 0.15 and b_frac >= 0.15)
    detail = f"A={a_count}/{total} ({a_frac:.1%}), B={b_count}/{total} ({b_frac:.1%})"
    return _report("cross_party_utility", ok, detail)


def test_nontrivial_accuracy() -> Tuple[str, bool]:
    """Test 4: test accuracy meaningfully above 50%-guess."""
    vfl_trees, _, (pa_tr, pb_tr, pa_te, pb_te), _ = \
        _train_pair(seed=42, depth=3, rounds=10)
    train_acc = _accuracy(vfl_trees, pa_tr, pb_tr)
    test_acc = _accuracy(vfl_trees, pa_te, pb_te)
    # Synthetic dataset is designed to be learnable; expect > 0.65
    # even at n=300, 10 rounds.
    ok = (train_acc >= 0.75 and test_acc >= 0.65)
    detail = f"train={train_acc:.3f} test={test_acc:.3f}"
    return _report("nontrivial_accuracy", ok, detail)


def test_paillier_addition_correctness() -> Tuple[str, bool]:
    """Sanity: mock Paillier addition is arithmetically exact."""
    p = vfl.MockPaillier()
    values = [1.1, -2.2, 3.3, 4.4, -5.5]
    handles = p.encrypt_B(values)
    sum_handle = p.add_A(handles)
    expected = sum(values)
    got = p.decrypt_B(sum_handle)
    ok = abs(got - expected) < 1e-9
    detail = "" if ok else f"expected {expected}, got {got}"
    return _report("paillier_addition_correctness", ok, detail)


def test_paillier_op_count_grows_with_rounds() -> Tuple[str, bool]:
    """Sanity: op counts scale with rounds (encrypt is n*rounds*2)."""
    _, _, _, paillier_2r = _train_pair(seed=1, rounds=2, depth=2)
    _, _, _, paillier_6r = _train_pair(seed=1, rounds=6, depth=2)
    ops_2 = paillier_2r.op_counts()
    ops_6 = paillier_6r.op_counts()
    # 3x rounds → ~3x encrypts.
    ratio = ops_6["encrypt"] / max(1, ops_2["encrypt"])
    ok = 2.5 < ratio < 3.5
    detail = f"encrypts: 2r={ops_2['encrypt']} 6r={ops_6['encrypt']} ratio={ratio:.2f}"
    return _report("paillier_op_count_grows_with_rounds", ok, detail)


def test_gradient_hessian_formula() -> Tuple[str, bool]:
    """Sanity: logistic-loss grad/hess formula is correct."""
    y_pred = np.array([-2.0, -0.5, 0.0, 0.5, 2.0])
    y = np.array([0.0, 1.0, 0.0, 1.0, 1.0])
    g, h = vfl.logistic_grads_and_hess(y_pred, y)
    p = vfl.sigmoid(y_pred)
    expected_g = p - y
    expected_h = p * (1 - p)
    ok = (np.allclose(g, expected_g) and np.allclose(h, expected_h))
    detail = "" if ok else f"g={g} exp={expected_g}, h={h} exp={expected_h}"
    return _report("gradient_hessian_formula", ok, detail)


def test_leaf_value_and_gain_formula() -> Tuple[str, bool]:
    """Sanity: leaf value and gain formulas match XGBoost math."""
    # leaf_value(-2, 3, lam=1) = -(-2) / (3 + 1) = 0.5
    lv = vfl.leaf_value(-2.0, 3.0, lam=1.0)
    if abs(lv - 0.5) > 1e-9:
        return _report("leaf_value_and_gain_formula", False,
                       f"leaf_value wrong: got {lv}")
    # gain: G_L=1, H_L=2, G_R=-1, H_R=2, lam=1
    # 0.5 * (1/(2+1) + 1/(2+1) - 0/(4+1)) = 0.5 * (0.333 + 0.333 - 0) = 0.333
    g = vfl.split_gain(1.0, 2.0, -1.0, 2.0, lam=1.0)
    expected = 0.5 * (1.0 / 3.0 + 1.0 / 3.0 - 0.0)
    ok = abs(g - expected) < 1e-9
    detail = "" if ok else f"expected {expected}, got {g}"
    return _report("leaf_value_and_gain_formula", ok, detail)


def test_predictions_deterministic() -> Tuple[str, bool]:
    """Training with the same seed twice produces identical models."""
    vfl_1, _, (pa_tr, pb_tr, _, _), _ = _train_pair(seed=42, rounds=4, depth=2)
    vfl_2, _, _, _ = _train_pair(seed=42, rounds=4, depth=2)
    raw_1 = vfl.ensemble_predict(vfl_1, pa_tr, pb_tr)
    raw_2 = vfl.ensemble_predict(vfl_2, pa_tr, pb_tr)
    ok = np.allclose(raw_1, raw_2)
    return _report("predictions_deterministic", ok)


# =====================================================================
# Runner
# =====================================================================
def main() -> int:
    print("VFL-XGB demo test harness")
    print("-" * 74)

    tests = [
        test_paillier_addition_correctness,
        test_gradient_hessian_formula,
        test_leaf_value_and_gain_formula,
        test_party_A_cannot_decrypt,
        test_predictions_deterministic,
        test_paillier_op_count_grows_with_rounds,
        test_nontrivial_accuracy,
        test_cross_party_utility,
        test_correctness_matches_baseline_across_seeds,
    ]
    results = []
    for t in tests:
        try:
            results.append(t())
        except Exception as e:
            print(f"  FAIL  {t.__name__}  — exception: {e}")
            traceback.print_exc()
            results.append((t.__name__, False))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print("-" * 74)
    print(f"Result: {passed}/{total} PASS")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
