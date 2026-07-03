#!/usr/bin/env python3
"""
Double-blind XGBoost VFL training — end-to-end mock demonstrating how the
MPSA/MPC primitives in this repo (MpMpcWire + MpMpcWireOps + MpOleTriple)
compose into a working vertical federated XGBoost training loop.

Setup
-----
Two parties:
  * Party A (feature provider): holds features X_A (subset of columns)
    for a set of sample IDs. Does NOT hold labels.
  * Party B (label + feature provider): holds features X_B (other columns)
    AND labels y for the same set of sample IDs.

"Double-blind" means:
  * Party A never sees any label, any X_B value, or any per-sample
    gradient/hessian in plaintext.
  * Party B never sees any X_A value in plaintext.
  * Party B does learn AGGREGATE gradient/hessian sums per split
    candidate — this is the standard VFL threat model (matches
    SecureBoost / HeteroSecureBoost / FATE).

The demo uses a mock Paillier-style additively-homomorphic ciphertext to
faithfully model the cryptographic constraints: Party A only interacts
with opaque HANDLES; only Party B can decrypt. In the C++ codebase, this
would be replaced by either:
  * Real Paillier (add a dependency; not currently in libOTe), OR
  * Additive secret sharing over Z_p with wire MPC primitives
    (MpMpcWire.wireSecureAnd + reveal). The wire cost model is
    printed at the end.

Protocol phases
---------------
1. Sample alignment: assumed done via MPSA (`frontend -mpsa` in this repo).
   This demo starts from aligned samples.
2. Party B computes gradients + hessians for the current model on the
   labels it privately holds.
3. Party B homomorphically encrypts g_i, h_i for each sample i and sends
   the ciphertexts to Party A.
4. Tree growth: for each split candidate on each party's features:
   * If split is on Party A's feature: A determines the partition (they
     know their own X_A), sums encrypted grads/hessians for the left set
     via homomorphic addition, sends the aggregate ciphertext to B for
     decryption. B learns G_L, H_L, computes gain, replies.
   * If split is on Party B's feature: B does everything locally, then
     reveals G_L, H_L, gain to A.
5. Best split selected, tree grown, model updated, repeat.

Compare against a PLAINTEXT baseline (both parties reveal all data to a
trusted aggregator) to show correctness of the MPC-mocked training.
"""

import argparse
import math
import random
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict

import numpy as np


# =====================================================================
# Mock cryptographic layer: Paillier-style additive homomorphic encryption
# =====================================================================
class MockPaillier:
    """Simulates additively-homomorphic ciphertexts.

    Party A never sees plaintext values — only opaque handles.
    Party B holds the "secret key" and is the only one who can decrypt.
    The API DISCIPLINE (which methods each party is allowed to call)
    enforces the security invariant.

    Realized in the C++ codebase via either:
      * A Paillier library (Pyfhel/Pypbc bindings, or libOTe extension)
      * OR additive shares over a large prime with wire MPC (MpMpcWire)
    """
    def __init__(self):
        self._plaintexts: Dict[int, float] = {}
        self._next: int = 0
        self._ops: Dict[str, int] = {"encrypt": 0, "add": 0, "decrypt": 0}

    # --- Party B API ------------------------------------------------
    def encrypt_B(self, values: List[float]) -> List[int]:
        """Party B: encrypt a list of plaintexts, return ciphertext handles."""
        handles = []
        for v in values:
            self._plaintexts[self._next] = float(v)
            handles.append(self._next)
            self._next += 1
        self._ops["encrypt"] += len(values)
        return handles

    def decrypt_B(self, handle: int) -> float:
        """Party B: decrypt one ciphertext handle to plaintext."""
        self._ops["decrypt"] += 1
        return self._plaintexts[handle]

    # --- Party A API ------------------------------------------------
    def add_A(self, handles: List[int]) -> int:
        """Party A: homomorphically add ciphertext handles → new handle.

        Party A sees only handles, never the underlying plaintexts.
        """
        new_handle = self._next
        self._next += 1
        self._plaintexts[new_handle] = sum(self._plaintexts[h] for h in handles)
        self._ops["add"] += len(handles)
        return new_handle

    def scale_A(self, handle: int, factor: float) -> int:
        """Party A: homomorphically scale a ciphertext by a public factor."""
        new_handle = self._next
        self._next += 1
        self._plaintexts[new_handle] = self._plaintexts[handle] * float(factor)
        self._ops["add"] += 1
        return new_handle

    # --- Metrics ----------------------------------------------------
    def op_counts(self) -> Dict[str, int]:
        return dict(self._ops)


# =====================================================================
# Party representation
# =====================================================================
@dataclass
class PartyA:
    """Feature holder, no labels."""
    name: str
    features: np.ndarray  # shape (n_samples, d_A)
    feature_names: List[str]

    @property
    def n_features(self) -> int:
        return self.features.shape[1]


@dataclass
class PartyB:
    """Feature + label holder."""
    name: str
    features: np.ndarray  # shape (n_samples, d_B)
    feature_names: List[str]
    labels: np.ndarray  # shape (n_samples,)

    @property
    def n_features(self) -> int:
        return self.features.shape[1]


# =====================================================================
# Gradient boosting arithmetic (logistic loss, binary classification)
# =====================================================================
def sigmoid(x: np.ndarray) -> np.ndarray:
    """Numerically stable logistic."""
    return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))


def logistic_grads_and_hess(y_pred: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Per-sample gradient (∂L/∂ŷ) and hessian for logistic loss.

    L = y * log(1 + e^{-ŷ}) + (1 - y) * log(1 + e^{ŷ})
    g_i = p_i - y_i,  h_i = p_i * (1 - p_i)
    where p_i = sigmoid(ŷ_i).
    """
    p = sigmoid(y_pred)
    grads = p - y
    hess = p * (1.0 - p)
    return grads, hess


def split_gain(G_L: float, H_L: float, G_R: float, H_R: float, lam: float) -> float:
    """XGBoost split gain (parent term dropped since it's constant across
    candidate splits on the same node)."""
    def leaf_score(G, H):
        return (G * G) / (H + lam) if (H + lam) > 0 else 0.0
    G_total = G_L + G_R
    H_total = H_L + H_R
    return 0.5 * (leaf_score(G_L, H_L) + leaf_score(G_R, H_R) - leaf_score(G_total, H_total))


def leaf_value(G: float, H: float, lam: float) -> float:
    """XGBoost leaf output = -G / (H + λ)."""
    return -G / (H + lam) if (H + lam) > 0 else 0.0


# =====================================================================
# Tree node representation
# =====================================================================
@dataclass
class TreeNode:
    is_leaf: bool = False
    value: float = 0.0
    # Split info (populated when not leaf):
    split_party: str = ""       # "A" or "B"
    split_feature: int = -1     # index into that party's features
    split_threshold: float = 0.0
    left: Optional["TreeNode"] = None
    right: Optional["TreeNode"] = None


# =====================================================================
# Double-blind split search
# =====================================================================
def find_best_split_on_A_feature(
    feature_idx: int,
    party_A: PartyA,
    node_mask: np.ndarray,          # which samples are at this node
    grad_ciphertexts: List[int],    # per-sample encrypted grads (all samples)
    hess_ciphertexts: List[int],    # per-sample encrypted hess (all samples)
    paillier: MockPaillier,
    lam: float,
    G_total_at_node: float,
    H_total_at_node: float,
    max_candidates: int = 16,
) -> Tuple[float, Optional[float]]:
    """Party A explores split candidates on ONE of their features.

    Returns (best_gain, best_threshold). If no valid split, best_threshold
    is None and best_gain <= 0.

    Cryptographic constraint: Party A never sees plaintext grads/hessians.
    They only see the encrypted handles, homomorphically add them for
    each candidate partition, and receive back the sum from Party B via
    decrypt. Party B learns G_L and H_L for each candidate split.
    """
    values = party_A.features[node_mask, feature_idx]
    unique_values = np.unique(values)
    if unique_values.size < 2:
        return -math.inf, None

    # Down-sample candidate thresholds if too many (typical XGBoost
    # optimization).
    if unique_values.size > max_candidates:
        step = unique_values.size // max_candidates
        candidates = unique_values[::step][:-1]
    else:
        candidates = unique_values[:-1]

    node_indices = np.where(node_mask)[0]
    best_gain = -math.inf
    best_threshold = None

    for t in candidates:
        left_local_mask = party_A.features[node_indices, feature_idx] <= t
        left_indices = node_indices[left_local_mask]
        right_indices = node_indices[~left_local_mask]
        if left_indices.size == 0 or right_indices.size == 0:
            continue

        # Party A homomorphically sums encrypted grads/hessians for the
        # left partition. Never sees plaintext values.
        grad_L_handle = paillier.add_A([grad_ciphertexts[i] for i in left_indices])
        hess_L_handle = paillier.add_A([hess_ciphertexts[i] for i in left_indices])

        # Party B receives the aggregate ciphertexts and decrypts.
        # B now knows G_L and H_L for this candidate — matches the
        # SecureBoost threat model.
        G_L = paillier.decrypt_B(grad_L_handle)
        H_L = paillier.decrypt_B(hess_L_handle)
        G_R = G_total_at_node - G_L
        H_R = H_total_at_node - H_L
        gain = split_gain(G_L, H_L, G_R, H_R, lam)
        if gain > best_gain:
            best_gain = gain
            best_threshold = float(t)

    return best_gain, best_threshold


def find_best_split_on_B_feature(
    feature_idx: int,
    party_B: PartyB,
    node_mask: np.ndarray,
    grads: np.ndarray,  # B holds these in plaintext
    hess: np.ndarray,
    lam: float,
    G_total_at_node: float,
    H_total_at_node: float,
    max_candidates: int = 16,
) -> Tuple[float, Optional[float]]:
    """Party B splits on their own feature — trivial case, all in plaintext
    on B's side. B only reveals G_L, H_L, gain (aggregate) to A."""
    values = party_B.features[node_mask, feature_idx]
    unique_values = np.unique(values)
    if unique_values.size < 2:
        return -math.inf, None
    if unique_values.size > max_candidates:
        step = unique_values.size // max_candidates
        candidates = unique_values[::step][:-1]
    else:
        candidates = unique_values[:-1]

    node_indices = np.where(node_mask)[0]
    best_gain = -math.inf
    best_threshold = None
    for t in candidates:
        left_local_mask = party_B.features[node_indices, feature_idx] <= t
        left_indices = node_indices[left_local_mask]
        right_indices = node_indices[~left_local_mask]
        if left_indices.size == 0 or right_indices.size == 0:
            continue
        G_L = float(grads[left_indices].sum())
        H_L = float(hess[left_indices].sum())
        G_R = G_total_at_node - G_L
        H_R = H_total_at_node - H_L
        gain = split_gain(G_L, H_L, G_R, H_R, lam)
        if gain > best_gain:
            best_gain = gain
            best_threshold = float(t)
    return best_gain, best_threshold


# =====================================================================
# Tree building
# =====================================================================
def grow_tree(
    party_A: PartyA,
    party_B: PartyB,
    grads: np.ndarray,
    hess: np.ndarray,
    grad_ciphertexts: List[int],
    hess_ciphertexts: List[int],
    paillier: MockPaillier,
    max_depth: int,
    min_gain: float,
    lam: float,
    node_mask: Optional[np.ndarray] = None,
    depth: int = 0,
) -> TreeNode:
    n = grads.shape[0]
    if node_mask is None:
        node_mask = np.ones(n, dtype=bool)

    node_indices = np.where(node_mask)[0]
    G_node = float(grads[node_indices].sum())
    H_node = float(hess[node_indices].sum())

    # Terminate: max depth or too few samples.
    if depth >= max_depth or node_indices.size < 2:
        return TreeNode(is_leaf=True, value=leaf_value(G_node, H_node, lam))

    best_gain = -math.inf
    best_split = None  # (party, feature_idx, threshold)

    # Search Party A's features.
    for f in range(party_A.n_features):
        gain, thresh = find_best_split_on_A_feature(
            f, party_A, node_mask, grad_ciphertexts, hess_ciphertexts,
            paillier, lam, G_node, H_node)
        if thresh is not None and gain > best_gain:
            best_gain = gain
            best_split = ("A", f, thresh)

    # Search Party B's features.
    for f in range(party_B.n_features):
        gain, thresh = find_best_split_on_B_feature(
            f, party_B, node_mask, grads, hess, lam, G_node, H_node)
        if thresh is not None and gain > best_gain:
            best_gain = gain
            best_split = ("B", f, thresh)

    # No good split → leaf.
    if best_split is None or best_gain < min_gain:
        return TreeNode(is_leaf=True, value=leaf_value(G_node, H_node, lam))

    party, feature_idx, threshold = best_split
    node = TreeNode(is_leaf=False, split_party=party,
                    split_feature=feature_idx, split_threshold=threshold)

    # Compute masks for children. Both parties know the split (structure
    # of the tree is public); only the FEATURE VALUES stay private on
    # each party's side.
    if party == "A":
        left_mask = node_mask & (party_A.features[:, feature_idx] <= threshold)
    else:
        left_mask = node_mask & (party_B.features[:, feature_idx] <= threshold)
    right_mask = node_mask & (~left_mask & node_mask)

    node.left = grow_tree(party_A, party_B, grads, hess,
                          grad_ciphertexts, hess_ciphertexts, paillier,
                          max_depth, min_gain, lam, left_mask, depth + 1)
    node.right = grow_tree(party_A, party_B, grads, hess,
                           grad_ciphertexts, hess_ciphertexts, paillier,
                           max_depth, min_gain, lam, right_mask, depth + 1)
    return node


def predict_tree(tree: TreeNode, party_A: PartyA, party_B: PartyB) -> np.ndarray:
    n = party_A.features.shape[0]
    preds = np.zeros(n)

    def descend(node: TreeNode, mask: np.ndarray):
        if node.is_leaf:
            preds[mask] += node.value
            return
        if node.split_party == "A":
            feat = party_A.features[:, node.split_feature]
        else:
            feat = party_B.features[:, node.split_feature]
        left = mask & (feat <= node.split_threshold)
        right = mask & ~left
        descend(node.left, left)
        descend(node.right, right)

    descend(tree, np.ones(n, dtype=bool))
    return preds


# =====================================================================
# Boosted ensemble training
# =====================================================================
def train_boosted_vfl(
    party_A: PartyA,
    party_B: PartyB,
    n_rounds: int,
    learning_rate: float,
    max_depth: int,
    lam: float,
    min_gain: float,
) -> Tuple[List[Tuple[TreeNode, float]], MockPaillier]:
    """Trains a boosted ensemble under the double-blind VFL protocol.

    Returns (list of (tree, lr) pairs, mock-Paillier oracle for cost report).
    """
    n = party_B.labels.shape[0]
    y = party_B.labels.astype(np.float64)
    y_pred = np.zeros(n)  # raw score (pre-sigmoid)

    paillier = MockPaillier()
    trees = []

    for r in range(n_rounds):
        grads, hess = logistic_grads_and_hess(y_pred, y)
        # Party B encrypts once per round and sends handles to A.
        grad_ciphertexts = paillier.encrypt_B(grads.tolist())
        hess_ciphertexts = paillier.encrypt_B(hess.tolist())

        tree = grow_tree(party_A, party_B, grads, hess,
                         grad_ciphertexts, hess_ciphertexts, paillier,
                         max_depth, min_gain, lam)
        tree_pred = predict_tree(tree, party_A, party_B)
        y_pred = y_pred + learning_rate * tree_pred
        trees.append((tree, learning_rate))

    return trees, paillier


def ensemble_predict(trees, party_A: PartyA, party_B: PartyB) -> np.ndarray:
    """Return raw scores; caller can sigmoid + threshold."""
    n = party_A.features.shape[0]
    total = np.zeros(n)
    for tree, lr in trees:
        total += lr * predict_tree(tree, party_A, party_B)
    return total


# =====================================================================
# Plaintext baseline (for correctness check)
# =====================================================================
def train_plaintext_baseline(
    party_A: PartyA,
    party_B: PartyB,
    n_rounds: int,
    learning_rate: float,
    max_depth: int,
    lam: float,
    min_gain: float,
) -> List[Tuple[TreeNode, float]]:
    """Reveal all features to both parties (aggregator model); same tree
    structure otherwise."""

    # Combined feature-view party A' that has ALL features (violates VFL).
    combined_features = np.concatenate([party_A.features, party_B.features], axis=1)
    combined_names = list(party_A.feature_names) + list(party_B.feature_names)
    party_all = PartyA(name="aggregator", features=combined_features,
                       feature_names=combined_names)

    # Trivial null-B (labels only, no features), so tree only grows on A'.
    party_null_B = PartyB(name="null_B",
                          features=np.zeros((party_B.features.shape[0], 0)),
                          feature_names=[], labels=party_B.labels)

    # Baseline uses no Paillier — feed dummy MockPaillier with encrypted
    # values in the same operations, but this is not evaluated against
    # security — just correctness.
    return train_boosted_vfl(party_all, party_null_B, n_rounds, learning_rate,
                             max_depth, lam, min_gain)[0]


# =====================================================================
# Synthetic data generation
# =====================================================================
def make_synthetic_data(n_samples: int, seed: int = 0
                         ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Synthetic binary classification.

    Features 0..3 (X_A gets 0-1, X_B gets 2-3). Labels depend on features
    in both parties so BOTH must contribute to good splits.
    """
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n_samples, 4))
    # A label rule using features from BOTH parties:
    logits = (
        1.3 * X[:, 0]   # A feature 0
        - 0.9 * X[:, 1]  # A feature 1
        + 1.1 * X[:, 2]  # B feature 0
        + 0.8 * X[:, 3]  # B feature 1
        + 0.7 * (X[:, 0] * X[:, 2])   # interaction across parties
        - 0.5 * (X[:, 1] * X[:, 3])
    )
    p = 1.0 / (1.0 + np.exp(-logits))
    y = (rng.uniform(size=n_samples) < p).astype(int)
    X_A = X[:, :2].copy()
    X_B = X[:, 2:].copy()
    return X_A, X_B, y


# =====================================================================
# Main
# =====================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-train", type=int, default=400)
    parser.add_argument("--n-test", type=int, default=200)
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--lr", type=float, default=0.3)
    parser.add_argument("--lambda-reg", type=float, default=1.0)
    parser.add_argument("--min-gain", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print("=" * 74)
    print("VFL XGBoost — Double-Blind Training Mock")
    print("=" * 74)
    print(f"  n_train={args.n_train}  n_test={args.n_test}")
    print(f"  rounds={args.rounds}  depth={args.depth}  lr={args.lr}")

    # Generate data.
    X_A, X_B, y = make_synthetic_data(args.n_train + args.n_test, args.seed)
    X_A_train, X_A_test = X_A[:args.n_train], X_A[args.n_train:]
    X_B_train, X_B_test = X_B[:args.n_train], X_B[args.n_train:]
    y_train, y_test = y[:args.n_train], y[args.n_train:]

    party_A_train = PartyA(
        name="party_A", features=X_A_train,
        feature_names=["A_feat_0", "A_feat_1"])
    party_B_train = PartyB(
        name="party_B", features=X_B_train,
        feature_names=["B_feat_0", "B_feat_1"], labels=y_train)
    party_A_test = PartyA(
        name="party_A", features=X_A_test,
        feature_names=["A_feat_0", "A_feat_1"])
    party_B_test = PartyB(
        name="party_B", features=X_B_test,
        feature_names=["B_feat_0", "B_feat_1"], labels=y_test)

    print(f"  Party A features:  {party_A_train.feature_names}   (private to A)")
    print(f"  Party B features:  {party_B_train.feature_names}   (private to B)")
    print(f"  Labels:            private to Party B only")
    print()

    # Double-blind VFL training.
    print("--- Double-blind VFL training (mock) ---")
    vfl_trees, paillier = train_boosted_vfl(
        party_A_train, party_B_train,
        n_rounds=args.rounds, learning_rate=args.lr,
        max_depth=args.depth, lam=args.lambda_reg, min_gain=args.min_gain)

    # Plaintext baseline.
    print("--- Plaintext baseline (both parties reveal all data) ---")
    baseline_trees = train_plaintext_baseline(
        party_A_train, party_B_train,
        n_rounds=args.rounds, learning_rate=args.lr,
        max_depth=args.depth, lam=args.lambda_reg, min_gain=args.min_gain)

    # Evaluate on holdout.
    def accuracy(trees, pa, pb):
        raw = ensemble_predict(trees, pa, pb)
        pred = (sigmoid(raw) > 0.5).astype(int)
        return (pred == pb.labels).mean()

    # For the baseline, we passed a combined-features party during
    # training. Predict via a matching combined party for eval too.
    def combined_party(pa, pb):
        combined_A = PartyA(
            name="aggregator",
            features=np.concatenate([pa.features, pb.features], axis=1),
            feature_names=list(pa.feature_names) + list(pb.feature_names))
        null_B = PartyB(name="null_B",
                        features=np.zeros((pb.features.shape[0], 0)),
                        feature_names=[], labels=pb.labels)
        return combined_A, null_B

    vfl_train_acc = accuracy(vfl_trees, party_A_train, party_B_train)
    vfl_test_acc = accuracy(vfl_trees, party_A_test, party_B_test)
    base_train_pa, base_train_pb = combined_party(party_A_train, party_B_train)
    base_test_pa,  base_test_pb  = combined_party(party_A_test,  party_B_test)
    base_train_acc = accuracy(baseline_trees, base_train_pa, base_train_pb)
    base_test_acc  = accuracy(baseline_trees, base_test_pa,  base_test_pb)

    print()
    print("=" * 74)
    print("RESULTS")
    print("=" * 74)
    print(f"  VFL train acc:      {vfl_train_acc:.4f}")
    print(f"  VFL test  acc:      {vfl_test_acc:.4f}")
    print(f"  Baseline train acc: {base_train_acc:.4f}")
    print(f"  Baseline test  acc: {base_test_acc:.4f}")
    print(f"  Accuracy delta (VFL - baseline, test): "
          f"{vfl_test_acc - base_test_acc:+.4f}")

    # Cost report.
    ops = paillier.op_counts()
    print()
    print("--- MPC cost report (mock Paillier ops) ---")
    print(f"  Ciphertext encrypts (Party B → Party A):   {ops['encrypt']}")
    print(f"  Homomorphic additions (Party A local):     {ops['add']}")
    print(f"  Decryption requests (Party A → Party B):   {ops['decrypt']}")

    # Estimate wire-MPC cost if we backend-swap Paillier for additive
    # secret sharing over the C++ MpMpcWire stack:
    per_open = 2 * 8  # 2 bytes per open (send + recv), 8 bytes per share sum (uint64_t)
    est_bytes = ops['decrypt'] * per_open
    print(f"  Estimated wire bandwidth (if additive-shared over MpMpcWire):")
    print(f"    ~ {est_bytes} B ({est_bytes/1024:.2f} KB) per training run")

    # Also report tree structure sample (first tree of VFL model).
    def tree_summary(node, depth=0):
        if node.is_leaf:
            return f"{'  '*depth}leaf: value={node.value:.4f}"
        return "\n".join([
            f"{'  '*depth}[{node.split_party}] "
            f"feat_{node.split_feature} <= {node.split_threshold:.3f}",
            tree_summary(node.left, depth + 1),
            tree_summary(node.right, depth + 1),
        ])

    print()
    print("--- First VFL tree structure ---")
    print(tree_summary(vfl_trees[0][0]))

    # Compare tree structures: they SHOULD be very similar since the
    # split-gain arithmetic is identical (up to plaintext-vs-Paillier
    # numerical equivalence for our mock).
    def collect_splits(node, path=""):
        if node.is_leaf:
            return [(path, "leaf", node.value)]
        left_desc = collect_splits(node.left, path + "L")
        right_desc = collect_splits(node.right, path + "R")
        return [(path, node.split_party + str(node.split_feature),
                 node.split_threshold)] + left_desc + right_desc

    vfl_splits = collect_splits(vfl_trees[0][0])
    baseline_splits = collect_splits(baseline_trees[0][0])
    # Baseline used feature indices 0..3 in the "combined" view; adjust
    # nothing here — just report the top-level split feature indices.
    vfl_root_feature = vfl_trees[0][0].split_feature if not vfl_trees[0][0].is_leaf else -1
    vfl_root_party = vfl_trees[0][0].split_party if not vfl_trees[0][0].is_leaf else "?"
    print(f"\n  VFL first-tree root split:      party={vfl_root_party} feature={vfl_root_feature}")
    base_root_feature = baseline_trees[0][0].split_feature if not baseline_trees[0][0].is_leaf else -1
    print(f"  Baseline first-tree root split: (combined feature index) {base_root_feature}")

    print()
    print("=" * 74)
    print("The double-blind VFL demo produced a working model without either")
    print("party learning the other's raw feature values or per-sample")
    print("gradients. The Party B → Party A leakage is bounded to per-split")
    print("aggregate (G_L, H_L) which matches the SecureBoost threat model.")
    print("=" * 74)


if __name__ == "__main__":
    main()
