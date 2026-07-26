#!/usr/bin/env python3
"""Generate 3 sender CSVs with numeric payloads for the (x+y)/z end-to-end
test.

Sender 0 contributes x, sender 1 contributes y, sender 2 contributes z, all
aligned by intersection ID. Values are stored as fixed-point uint64
(multiplied by --scale, default 1_000_000).

CSV row format (one payload block, W=1):
    <id_hex_32chars>,<payload_hex_32chars>

Each column parses as an oc::block. hexToBlock reads 32 hex chars big-endian
and stores byte[15-i] = strtol(hex[2i:2i+2], 16), so the low 64 bits of the
block equal int(hex[16:32], 16). We use that: the ID is 32 hex chars of true
randomness, and the payload is 16 zeros followed by 16 hex chars of the
fixed-point uint64.

Writes ground_truth.json alongside the CSVs so the verifier can check the
shuffled output multiset against the expected multiset.
"""
import argparse
import json
import os
import random
import secrets
import sys


def uint64_hex_block(v: int) -> str:
    """Encode a uint64 as an oc::block (32 hex chars, low64 == v)."""
    if v < 0 or v >= (1 << 64):
        raise ValueError(f"payload {v} does not fit in uint64")
    return "0" * 16 + f"{v:016x}"


def random_id_hex() -> str:
    return secrets.token_hex(16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--intersect", type=int, required=True,
                    help="Number of common IDs (== output row count).")
    ap.add_argument("--total", type=int, default=None,
                    help="Rows per sender (default: intersect + 20 filler rows).")
    ap.add_argument("--outdir", type=str, required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--scale", type=int, default=1_000_000,
                    help="Fixed-point scale. Values stored as int(v * scale).")
    args = ap.parse_args()

    N_SENDERS = 3  # x, y, z
    if args.intersect < 1:
        sys.exit("--intersect must be >= 1")
    if args.total is None:
        args.total = args.intersect + 20
    if args.total < args.intersect:
        sys.exit("--total must be >= --intersect")

    random.seed(args.seed)
    os.makedirs(args.outdir, exist_ok=True)

    # Pick intersection IDs (shared across all senders).
    intersect_ids = [random_id_hex() for _ in range(args.intersect)]

    # Pick per-intersection values: x in [1, 100), y in [1, 100), z in [1, 50).
    # Scaled to fixed-point uint64 for on-wire.
    #
    # For each intersection ID, ground_truth[id_hex] = {x, y, z, ratio}
    # where ratio = (x + y) * scale // z (fixed-point division).
    ground_truth = {}
    x_values, y_values, z_values = [], [], []
    for uid in intersect_ids:
        # Draw as floats then convert; keeps the test data varied but exact.
        x_f = random.uniform(0.5, 100.0)
        y_f = random.uniform(0.5, 100.0)
        z_f = random.uniform(0.5, 50.0)
        x_i = int(round(x_f * args.scale))
        y_i = int(round(y_f * args.scale))
        z_i = int(round(z_f * args.scale))
        # Fixed-point ratio: (x+y)/z in FP means (x_fp + y_fp) * scale / z_fp.
        ratio = ((x_i + y_i) * args.scale) // z_i
        ground_truth[uid] = {
            "x": x_i, "y": y_i, "z": z_i, "ratio": ratio,
        }
        x_values.append(x_i)
        y_values.append(y_i)
        z_values.append(z_i)

    # Fillers: unique random IDs per sender, filler payload = 0 (won't be
    # in intersection so never appears in MPSA output).
    per_sender_values = [x_values, y_values, z_values]
    all_generated_ids = set(intersect_ids)
    for sender_idx in range(N_SENDERS):
        path = os.path.join(args.outdir, f"sender_{sender_idx}.csv")
        with open(path, "w") as f:
            for j, uid in enumerate(intersect_ids):
                f.write(f"{uid},{uint64_hex_block(per_sender_values[sender_idx][j])}\n")
            for _ in range(args.total - args.intersect):
                while True:
                    uid = random_id_hex()
                    if uid not in all_generated_ids:
                        all_generated_ids.add(uid)
                        break
                f.write(f"{uid},{uint64_hex_block(0)}\n")

    gt_path = os.path.join(args.outdir, "ground_truth.json")
    with open(gt_path, "w") as f:
        json.dump({
            "scale": args.scale,
            "intersect": args.intersect,
            "N": N_SENDERS,
            "ground_truth": ground_truth,
        }, f, indent=2)

    print(f"Wrote {N_SENDERS} sender CSVs to {args.outdir}; "
          f"intersect={args.intersect}, scale={args.scale}. "
          f"Ground truth in {gt_path}")


if __name__ == "__main__":
    main()
