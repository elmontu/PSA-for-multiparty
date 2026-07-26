#!/usr/bin/env python3
"""Verify a (x+y)/z computation on shuffled MPSA output.

Reads the shuffled CSV produced by frontend -mpsa (each row is N=3
hex-encoded oc::blocks concatenated by commas) and ground_truth.json from
the generator. For each output row:
  - unpack 3 hex blocks -> (x_i, y_i, z_i) uint64 values (fixed-point)
  - compute observed_ratio = (x + y) * scale // z
  - additionally: check the (x, y, z) triple exists in ground truth
    (i.e., no output row has "mixed provenance" values from different IDs).
Then verify multiset(observed_ratios) == multiset(expected_ratios).

Exit 0 iff all checks pass.
"""
import argparse
import json
import os
import sys


def hex_block_to_uint64(hex_block: str) -> int:
    """Extract the low 64 bits of an oc::block encoded as 32 hex chars.

    hexToBlock in fileBased.cpp reads chars big-endian into byte[15-i], so
    the last 16 hex chars encode the low 8 bytes of the block, i.e., the
    low 64-bit word.
    """
    hex_block = hex_block.strip()
    if len(hex_block) != 32:
        raise ValueError(f"expected 32 hex chars, got {len(hex_block)}: {hex_block!r}")
    return int(hex_block[16:32], 16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-csv", required=True, help="MPSA output CSV")
    ap.add_argument("--ground-truth", required=True, help="ground_truth.json from generator")
    args = ap.parse_args()

    with open(args.ground_truth) as f:
        meta = json.load(f)
    scale = meta["scale"]
    expected_gt = meta["ground_truth"]         # {id_hex: {x,y,z,ratio}}
    expected_intersect = meta["intersect"]

    # Build the expected sets.
    expected_ratios = sorted(v["ratio"] for v in expected_gt.values())
    expected_triples = sorted((v["x"], v["y"], v["z"]) for v in expected_gt.values())

    # Parse output CSV.
    if not os.path.exists(args.out_csv):
        print(f"FAIL: output CSV missing: {args.out_csv}", file=sys.stderr)
        return 1
    with open(args.out_csv) as f:
        raw_rows = [ln.strip() for ln in f if ln.strip()]

    if len(raw_rows) != expected_intersect:
        print(f"FAIL: expected {expected_intersect} output rows, got {len(raw_rows)}",
              file=sys.stderr)
        return 1

    observed_ratios = []
    observed_triples = []
    for r_idx, row in enumerate(raw_rows):
        cols = [c.strip() for c in row.split(",")]
        if len(cols) != 3:
            print(f"FAIL: row {r_idx} has {len(cols)} columns, expected 3",
                  file=sys.stderr)
            return 1
        try:
            x = hex_block_to_uint64(cols[0])
            y = hex_block_to_uint64(cols[1])
            z = hex_block_to_uint64(cols[2])
        except ValueError as e:
            print(f"FAIL: row {r_idx} parse error: {e}", file=sys.stderr)
            return 1
        if z == 0:
            print(f"FAIL: row {r_idx} has z=0, division undefined", file=sys.stderr)
            return 1
        ratio = ((x + y) * scale) // z
        observed_ratios.append(ratio)
        observed_triples.append((x, y, z))

    observed_ratios.sort()
    observed_triples.sort()

    # Print evidence.
    print(f"scale = {scale}")
    print(f"|intersection| observed = {len(raw_rows)}, expected = {expected_intersect}")
    print("First 3 output rows [x, y, z, (x+y)/z] (fixed-point):")
    for i in range(min(3, len(observed_triples))):
        x, y, z = observed_triples[i]
        r = ((x + y) * scale) // z
        print(f"  row {i}: x={x} y={y} z={z} -> (x+y)/z = {r} (== {r/scale:.6f} real)")

    # Check triple multiset equality: every output triple must be a legitimate
    # (x_i, y_i, z_i) for some intersection ID. Sum-preserving mixes across
    # senders would break this because the wrong (x, y, z) grouping would
    # not appear in expected_triples.
    if observed_triples != expected_triples:
        print("FAIL: observed (x,y,z) triple multiset != expected", file=sys.stderr)
        # Show first mismatch to help debug.
        for i, (obs, exp) in enumerate(zip(observed_triples, expected_triples)):
            if obs != exp:
                print(f"  first diff at sorted index {i}: obs={obs} exp={exp}",
                      file=sys.stderr)
                break
        return 1

    if observed_ratios != expected_ratios:
        # This is redundant given the triple check passed, but keep it as a
        # sanity assertion on the arithmetic itself.
        print("FAIL: observed ratio multiset != expected", file=sys.stderr)
        return 1

    print(f"PASS: {len(observed_ratios)} rows all match ground-truth (x+y)/z.")
    print("      (triple-multiset also matched: no cross-sender payload mixing.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
