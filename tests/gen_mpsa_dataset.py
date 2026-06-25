#!/usr/bin/env python3
"""Generate N CSVs with a controlled intersection size for MPSA smoke tests."""
import argparse
import os
import random
import string
import sys


def generate_id():
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--N", type=int, required=True, help="Number of senders")
    parser.add_argument("--total", type=int, required=True, help="Rows per file")
    parser.add_argument("--intersect", type=int, required=True,
                        help="Rows sharing the same ID across all senders")
    parser.add_argument("--outdir", type=str, required=True, help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    if args.intersect > args.total:
        sys.exit(f"intersect ({args.intersect}) cannot exceed total ({args.total})")

    random.seed(args.seed)
    os.makedirs(args.outdir, exist_ok=True)

    intersect_ids = []
    intersect_set = set()
    while len(intersect_ids) < args.intersect:
        uid = generate_id()
        if uid not in intersect_set:
            intersect_ids.append(uid)
            intersect_set.add(uid)

    all_unique_ids = set()

    for i in range(args.N):
        filepath = os.path.join(args.outdir, f"sender_{i}.csv")
        with open(filepath, "w") as f:
            for j, uid in enumerate(intersect_ids):
                payload = f"val{i}_{j}"
                f.write(f"{uid},{payload}\n")

            for k in range(args.total - args.intersect):
                while True:
                    uid = generate_id()
                    if uid not in intersect_set and uid not in all_unique_ids:
                        break
                all_unique_ids.add(uid)
                payload = f"val{i}_{args.intersect + k}"
                f.write(f"{uid},{payload}\n")

    print(f"Wrote {args.N} files to {args.outdir}; intersection size = {args.intersect}")


if __name__ == "__main__":
    main()
