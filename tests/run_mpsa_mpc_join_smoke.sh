#!/bin/bash
# R34/MPC-mode smoke test: in-process SP-blind MPC join via -mpsa-join-mpc.
set -euo pipefail

N=${N:-2}
M=${M:-2}
W=${W:-1}
INTERSECT=${INTERSECT:-3}
EXTRA=${EXTRA:-1}
BUILD=./out/build/linux/frontend/frontend
OUTDIR=${OUTDIR:-dataset_mpc_join}

if [ ! -x "$BUILD" ]; then
    echo "FAIL: frontend binary not found at $BUILD"; exit 1
fi

echo "Generating dataset (N=$N, M=$M, W=$W, intersect=$INTERSECT, extra=$EXTRA)..."
python3 tests/gen_mpsa_join_dataset.py --N "$N" --M "$M" --W "$W" \
        --intersect "$INTERSECT" --extra "$EXTRA" \
        --outdir "$OUTDIR"

EXPECTED=$(cat "$OUTDIR/expected_rows.txt")
echo "Expected joined rows: $EXPECTED"

ARGS=("-mpsa-join-mpc" "-N" "$N" "-M" "$M" "-pw" "$W"
      "-out" "$OUTDIR/out_mpc_join.csv" "-v")
for i in $(seq 0 $((N-1))); do
    ARGS+=("-in$i" "$OUTDIR/sender_${i}.csv")
done

echo "Running: $BUILD ${ARGS[*]}"
"$BUILD" "${ARGS[@]}" 2>&1 | tail -20

ACTUAL=$(wc -l < "$OUTDIR/out_mpc_join.csv")
if [ "$ACTUAL" -ne "$EXPECTED" ]; then
    echo "FAIL: expected $EXPECTED intersection rows, got $ACTUAL"
    exit 1
fi

EXPECTED_FIELDS=$((N * W))
ACTUAL_FIELDS=$(head -n 1 "$OUTDIR/out_mpc_join.csv" | awk -F',' '{print NF}')
if [ "$ACTUAL_FIELDS" -ne "$EXPECTED_FIELDS" ]; then
    echo "FAIL: expected $EXPECTED_FIELDS blocks/row, got $ACTUAL_FIELDS"
    head -n 1 "$OUTDIR/out_mpc_join.csv"
    exit 1
fi

echo "PASS: $ACTUAL intersection rows × $ACTUAL_FIELDS hex blocks (N=$N, W=$W) — SP-blind MPC join"
