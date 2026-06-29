#!/usr/bin/env python3
"""
DP-FL composition demo (T12).

Reads `dataset/out_mpsa.csv` (produced by `frontend -mpsa -dp <eps>`),
treats the per-row joined payloads as a tiny synthetic feature matrix,
and runs ONE FedAvg + DP-SGD round across the N senders' contributions.

The point isn't a real ML pipeline — it's to demonstrate end-to-end
PRIVACY BUDGET COMPOSITION between MPSA's `-dp` cardinality release and
a downstream FL step's per-update DP noise.

Usage:
  ./tests/dp_fl_compose_demo.py [--in dataset/out_mpsa.csv]
                                [--mpsa-eps 0.5]
                                [--fl-eps 1.0]
                                [--fl-clip 1.0]

The script reports:
  - dataset shape inferred from the CSV
  - MPSA privacy cost (the user-supplied --mpsa-eps)
  - per-round FL DP-SGD privacy cost (per the Gaussian mechanism + RDP)
  - composed total epsilon for the whole pipeline (basic + RDP composition)

This is documentation-grade; not a substitute for a real DP-FL stack.
"""
import argparse
import csv
import math
import os
import sys


def read_mpsa_output(path):
    """Each row = N hex-encoded 16-byte blocks separated by commas."""
    with open(path) as f:
        rows = [line.strip().split(',') for line in f if line.strip()]
    if not rows:
        return [], 0
    N = len(rows[0])
    return rows, N


def hex_block_to_float(hex_str):
    """Trivial feature extraction: hash the 16-byte block to a float in [0, 1).
    Real applications would parse the payload format here."""
    val = int(hex_str, 16)
    return (val & 0xFFFFFFFFFFFFFFFF) / 2**64


def basic_dp_compose(eps_list):
    """Basic composition theorem (Dwork et al. 2006): total eps is the sum."""
    return sum(eps_list)


def rdp_gauss_compose(noise_multipliers, T):
    """Crude RDP composition for repeated Gaussian mechanisms.
    Returns approximate epsilon at delta = 1e-5.
    Real composition needs the moments accountant (Abadi et al. 2016) or
    Mironov's RDP -> (eps, delta) conversion. This is a rough upper bound."""
    delta = 1e-5
    # For Gaussian mechanism at noise multiplier sigma, per-step RDP at order
    # alpha is alpha / (2 * sigma^2). Composition: sum across T steps.
    # Convert to (eps, delta) at order alpha:
    #   eps = T * alpha / (2 * sigma^2) - log(delta) / (alpha - 1)
    # Optimize over alpha (here just try a few).
    best = float('inf')
    for alpha in [1.5, 2, 4, 8, 16, 32, 64]:
        if all(sigma > 0 for sigma in noise_multipliers):
            avg_sigma = sum(noise_multipliers) / len(noise_multipliers)
            try:
                eps = T * alpha / (2 * avg_sigma**2) - math.log(delta) / (alpha - 1)
                best = min(best, eps)
            except (ValueError, ZeroDivisionError):
                pass
    return best


def fl_round_dp(features, sender_idx, clip_norm, noise_sigma):
    """One FedAvg + DP-SGD round for sender_idx's column.

    Simplest possible "model": mean(features). Per-record gradient = (feature - mean).
    DP-SGD: clip per-record gradient to L2 norm clip_norm, add Gaussian noise
    scaled by noise_sigma * clip_norm.
    """
    if not features:
        return 0.0
    mean = sum(features) / len(features)
    grads = [f - mean for f in features]
    # Per-record clipping (L2 norm in 1-D is just absolute value).
    clipped = [max(-clip_norm, min(clip_norm, g)) for g in grads]
    summed = sum(clipped)
    # Add Gaussian noise.
    sigma = noise_sigma * clip_norm
    import random
    noise = random.gauss(0.0, sigma)
    noisy_grad = (summed + noise) / len(features)
    return mean + noisy_grad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="dataset/out_mpsa.csv",
                    help="Path to MPSA output CSV.")
    ap.add_argument("--mpsa-eps", type=float, default=0.5,
                    help="Epsilon spent on MPSA's -dp cardinality release.")
    ap.add_argument("--fl-eps", type=float, default=1.0,
                    help="Target epsilon for the FL DP-SGD step.")
    ap.add_argument("--fl-clip", type=float, default=1.0,
                    help="Per-record gradient clipping norm for DP-SGD.")
    ap.add_argument("--fl-rounds", type=int, default=10,
                    help="Number of FL rounds (for composition).")
    args = ap.parse_args()

    if not os.path.exists(args.inp):
        print(f"ERROR: {args.inp} does not exist. Run ./tests/run_mpsa_smoke.sh first.",
              file=sys.stderr)
        sys.exit(1)

    rows, N = read_mpsa_output(args.inp)
    print(f"=== MPSA → DP-FL composition demo ===")
    print(f"Input: {args.inp}")
    print(f"Rows  (= |intersection|): {len(rows)}")
    print(f"N     (= senders): {N}")
    print()

    # Parse each column into a feature vector.
    columns = [[] for _ in range(N)]
    for row in rows:
        for c in range(N):
            columns[c].append(hex_block_to_float(row[c]))

    # MPSA's eps: spent on the cardinality release.
    eps_mpsa = args.mpsa_eps

    # Map FL-eps target to a noise multiplier (very rough: sigma = sqrt(2 ln(1.25/delta)) / eps).
    delta = 1e-5
    eps_per_round = args.fl_eps
    noise_mult = math.sqrt(2 * math.log(1.25 / delta)) / eps_per_round
    print(f"MPSA privacy cost:  epsilon = {eps_mpsa}")
    print(f"FL per-round target: epsilon = {eps_per_round}, => noise multiplier sigma = {noise_mult:.3f}")
    print()

    # Run one FL round per sender column.
    print(f"=== FL round (FedAvg + DP-SGD, T={args.fl_rounds} rounds simulated) ===")
    for c in range(N):
        noisy_aggregate = fl_round_dp(columns[c], c, args.fl_clip, noise_mult)
        print(f"  sender {c}: column mean (with DP noise) = {noisy_aggregate:.6f}")
    print()

    # Composition: MPSA-eps + T rounds of FL-eps (basic + RDP-style).
    basic_total = basic_dp_compose([eps_mpsa] + [eps_per_round] * args.fl_rounds)
    rdp_total = eps_mpsa + rdp_gauss_compose([noise_mult] * args.fl_rounds, args.fl_rounds)
    print(f"=== Privacy budget composition ===")
    print(f"Basic composition (Dwork+McSherry+Nissim+Smith TCC'06):")
    print(f"  total epsilon  = MPSA-eps + T * FL-eps = {basic_total:.3f}")
    print(f"RDP composition (Mironov CSF'17):")
    print(f"  total epsilon  (at delta=1e-5) ~ {rdp_total:.3f}")
    print()
    print("Note: this is a documentation-grade demo. Real DP-FL requires:")
    print("  - the moments accountant (Abadi+Chu+Goodfellow+...+Zhang CCS'16)")
    print("  - a real FL framework (NVIDIA FLARE, Flower, etc.)")
    print("  - careful per-organization budget tracking across queries")
    print("See docs/ARCHITECTURE.md and your ~/fl/ FL deployment guide.")


if __name__ == "__main__":
    main()
