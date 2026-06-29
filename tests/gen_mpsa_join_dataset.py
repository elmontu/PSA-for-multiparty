#!/usr/bin/env python3
"""Generate N CSVs for the MPSA-join (table-valued payload) smoke test.

Each party has a set of distinct IDs; for each ID, the party has between
1 and M rows. IDs in the "shared" subset are present in all N parties'
files; non-shared IDs are unique to one party.
"""
import argparse
import os
import random
import string
import sys


def generate_id():
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


def payload_cols(W, sender_idx, id_idx, row_idx):
    return ",".join(f"s{sender_idx}_id{id_idx}_r{row_idx}_b{w}" for w in range(W))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--N", type=int, required=True, help="Number of senders")
    parser.add_argument("--intersect", type=int, required=True,
                        help="IDs shared across all senders")
    parser.add_argument("--extra", type=int, default=10,
                        help="Per-sender extra (non-shared) IDs (default 10)")
    parser.add_argument("--M", type=int, default=2,
                        help="Max rows per ID per party (default 2)")
    parser.add_argument("--W", type=int, default=1,
                        help="Payload width in blocks per row (default 1)")
    parser.add_argument("--outdir", type=str, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.M < 1 or args.W < 1:
        sys.exit("--M and --W must be >= 1")

    random.seed(args.seed)
    os.makedirs(args.outdir, exist_ok=True)

    intersect_ids = []
    seen = set()
    while len(intersect_ids) < args.intersect:
        u = generate_id()
        if u not in seen:
            intersect_ids.append(u)
            seen.add(u)

    rows_per_party_per_id = {}  # (party, id_str) -> int (1..M)

    for i in range(args.N):
        path = os.path.join(args.outdir, f"sender_{i}.csv")
        with open(path, "w") as f:
            # Shared IDs: each gets 1..M rows for this party.
            for id_idx, uid in enumerate(intersect_ids):
                k = random.randint(1, args.M)
                rows_per_party_per_id[(i, uid)] = k
                for r in range(k):
                    f.write(f"{uid},{payload_cols(args.W, i, id_idx, r)}\n")

            # Extra (non-shared) IDs.
            for e in range(args.extra):
                while True:
                    u = generate_id()
                    if u not in seen:
                        seen.add(u)
                        break
                k = random.randint(1, args.M)
                for r in range(k):
                    f.write(f"{u},{payload_cols(args.W, i, args.intersect + e, r)}\n")

    # Compute expected joined output size for the smoke test.
    expected_rows = 0
    for uid in intersect_ids:
        prod = 1
        for i in range(args.N):
            prod *= rows_per_party_per_id[(i, uid)]
        expected_rows += prod

    print(f"Wrote {args.N} files to {args.outdir}")
    print(f"  intersection IDs       : {args.intersect}")
    print(f"  per-sender extra IDs   : {args.extra}")
    print(f"  M (max rows/id/party)  : {args.M}")
    print(f"  W (payload width)      : {args.W}")
    print(f"  expected joined rows   : {expected_rows}")
    # Write the expectation to a sidecar so the smoke test can assert on it.
    with open(os.path.join(args.outdir, "expected_rows.txt"), "w") as f:
        f.write(str(expected_rows) + "\n")


if __name__ == "__main__":
    main()
